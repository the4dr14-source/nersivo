"""Tests UNITARIOS de `backend/client_ip.py` (corrección de A3).

Son funciones puras: no hay red, ni Starlette, ni Uvicorn. Demuestran la lógica
del modelo de confianza, NO que Render envíe la cadena que se supone; eso solo
se comprueba con el procedimiento de verificación en producción.
"""

import logging
import random
import time

import pytest

from backend.client_ip import (
    MAX_TRUSTED_HOPS,
    TRUSTED_HOPS_ENV,
    UNKNOWN_CLIENT_KEY,
    UNTRUSTED_CHAIN_KEY,
    normalize_ip,
    resolve_client,
    trusted_hops_from_env,
    validate_trusted_hops,
    warn_if_proxy_headers_untrusted,
)

REAL = "198.51.100.9"  # IP real del cliente (la añade el proxy de confianza)
HOP = "10.1.2.3"  # IP de un segundo salto de infraestructura


# ------------------------------------------------------------ normalize_ip
@pytest.mark.parametrize(
    "value,expected",
    [
        ("198.51.100.9", "198.51.100.9"),
        ("  198.51.100.9  ", "198.51.100.9"),
        ("198.51.100.9:54321", "198.51.100.9"),
        ("2001:DB8::1", "2001:db8::1"),
        ("2001:db8:0:0:0:0:0:1", "2001:db8::1"),
        ("[2001:db8::1]", "2001:db8::1"),
        ("[2001:db8::1]:443", "2001:db8::1"),
        ("::ffff:198.51.100.9", "198.51.100.9"),
        ("::1", "::1"),
    ],
)
def test_normalize_ip_acepta_formas_validas_y_las_canoniza(value, expected):
    assert normalize_ip(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "",
        "   ",
        "unknown",
        "example.com",
        "1.2.3",
        "1.2.3.4.5",
        "1.2.3.04",  # ceros a la izquierda: ambiguo (octal)
        "999.1.1.1",
        "2130706433",  # IPv4 como entero
        "0x7f.0.0.1",
        "1.2.3.4:abc",
        "1.2.3.4:99999",
        "1.2.3.4:",
        "[2001:db8::1",
        "[2001:db8::1]x",
        "[2001:db8::1]:abc",
        "fe80::1%eth0",  # identificador de zona
        "1.2.3.4, 5.6.7.8",
        "1.2.3.4;rm -rf /",
        "１.２.３.４",  # dígitos de anchura completa
        "1.2.3.4\n5.6.7.8",
        "a" * 5000,
        "1" * 100,
    ],
)
def test_normalize_ip_rechaza_valores_malformados_o_inesperados(value):
    assert normalize_ip(value) is None


# ------------------------------------------------------- configuración env
@pytest.mark.parametrize(
    "env,expected",
    [({}, 0), ({TRUSTED_HOPS_ENV: ""}, 0), ({TRUSTED_HOPS_ENV: "  "}, 0),
     ({TRUSTED_HOPS_ENV: "0"}, 0), ({TRUSTED_HOPS_ENV: "1"}, 1),
     ({TRUSTED_HOPS_ENV: " 2 "}, 2), ({TRUSTED_HOPS_ENV: str(MAX_TRUSTED_HOPS)}, MAX_TRUSTED_HOPS)],
)
def test_trusted_hops_from_env_valores_validos(env, expected):
    assert trusted_hops_from_env(env) == expected


@pytest.mark.parametrize("bad", ["abc", "-1", "6", "1.5", "uno", "1,2", "*", "True"])
def test_trusted_hops_valor_invalido_es_un_error_y_no_se_ignora(bad):
    with pytest.raises(ValueError):
        trusted_hops_from_env({TRUSTED_HOPS_ENV: bad})


@pytest.mark.parametrize("bad", [-1, MAX_TRUSTED_HOPS + 1, "x"])
def test_validate_trusted_hops_rechaza_fuera_de_rango(bad):
    with pytest.raises(ValueError):
        validate_trusted_hops(bad)


# ------------------------------------------------- modo 0: no se confía nada
def test_hops_0_usa_la_direccion_tcp_e_ignora_x_forwarded_for():
    ident = resolve_client("10.0.0.5", ["203.0.113.77, 198.51.100.9"], 0)
    assert ident.key == "10.0.0.5"
    assert ident.source == "peer"


def test_hops_0_ausencia_de_cliente_no_desactiva_el_limite():
    assert resolve_client(None, [], 0).key == UNKNOWN_CLIENT_KEY
    assert resolve_client("", [], 0).key == UNKNOWN_CLIENT_KEY


def test_hops_0_peer_no_ip_se_conserva_tal_cual():
    # El TestClient de Starlette usa el host "testclient".
    assert resolve_client("testclient", [], 0).key == "testclient"


# ---------------------------------------- modo 1: un proxy de confianza
def test_hops_1_cliente_legitimo_se_identifica_por_la_ultima_entrada():
    ident = resolve_client("10.0.0.5", [REAL], 1)
    assert (ident.key, ident.source) == (REAL, "forwarded-for")


def test_hops_1_cliente_que_falsifica_la_cabecera_no_cambia_su_identidad():
    """El cliente escribe a la izquierda; el proxy añade la IP real al final."""
    forged = ["203.0.113.77", "1.1.1.1, 2.2.2.2", "8.8.8.8, 9.9.9.9, 203.0.113.1"]
    for prefix in forged:
        assert resolve_client("10.0.0.5", [f"{prefix}, {REAL}"], 1).key == REAL


def test_hops_1_cabecera_con_multiples_ips_usa_la_anadida_por_el_proxy():
    chain = f"203.0.113.1, 203.0.113.2, 203.0.113.3, {REAL}"
    assert resolve_client("10.0.0.5", [chain], 1).key == REAL


def test_hops_1_varias_lineas_de_cabecera_se_unen_en_orden():
    ident = resolve_client("10.0.0.5", ["203.0.113.77", REAL], 1)
    assert ident.key == REAL


def test_hops_1_espacios_y_puerto_en_la_entrada_confiable():
    assert resolve_client("10.0.0.5", [f"1.1.1.1 ,   {REAL}:5555  "], 1).key == REAL


def test_hops_1_ipv6_en_distintas_formas_textuales_comparte_cubo():
    a = resolve_client("10.0.0.5", ["1.1.1.1, 2001:DB8::1"], 1).key
    b = resolve_client("10.0.0.5", ["1.1.1.1, 2001:db8:0:0:0:0:0:1"], 1).key
    c = resolve_client("10.0.0.5", ["1.1.1.1, [2001:db8::1]:443"], 1).key
    assert a == b == c == "2001:db8::1"


# ------------------------------------------------ modo 2: dos saltos
def test_hops_2_usa_la_penultima_entrada():
    ident = resolve_client("10.0.0.5", [f"203.0.113.77, {REAL}, {HOP}"], 2)
    assert (ident.key, ident.source) == (REAL, "forwarded-for")


def test_hops_2_con_exactamente_dos_entradas():
    assert resolve_client("10.0.0.5", [f"{REAL}, {HOP}"], 2).key == REAL


def test_hops_2_falsificar_la_izquierda_no_cambia_el_resultado():
    rng = random.Random(1234)
    for _ in range(500):
        junk = ", ".join(
            f"{rng.randint(1, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
            for _ in range(rng.randint(0, 6))
        )
        chain = f"{junk}, {REAL}, {HOP}" if junk else f"{REAL}, {HOP}"
        assert resolve_client("10.0.0.5", [chain], 2).key == REAL


# ------------------------------------------- cadenas anómalas: nunca se
# desactiva el limitador y el cubo no depende de lo que envíe el cliente
@pytest.mark.parametrize(
    "hops,values",
    [
        (1, []),  # sin cabecera
        (1, [""]),  # cabecera vacía
        (1, ["   "]),
        (1, [","]),
        (1, [f"{REAL},"]),  # entrada final vacía
        (1, ["no-es-una-ip"]),
        (1, ["203.0.113.1, <script>"]),
        (1, ["1.2.3"]),
        (1, ["203.0.113.1, 1.2.3.04"]),
        (2, [REAL]),  # cadena más corta que los saltos de confianza
        (3, [f"{REAL}, {HOP}"]),
    ],
)
def test_cadena_anomala_cae_en_el_cubo_compartido_constante(hops, values):
    ident = resolve_client("10.0.0.5", values, hops)
    assert ident.key == UNTRUSTED_CHAIN_KEY
    assert ident.source == "fallback"


def test_el_cubo_de_fallback_no_depende_de_la_basura_enviada():
    keys = {
        resolve_client("10.0.0.5", [junk], 1).key
        for junk in ("x", "y" * 50, "<>", "999.999.999.999", "1.2.3.4.5", ";;;", "é")
    }
    assert keys == {UNTRUSTED_CHAIN_KEY}


def test_la_direccion_tcp_no_influye_cuando_se_confia_en_la_cabecera():
    assert resolve_client("10.0.0.5", [REAL], 1).key == resolve_client("10.9.9.9", [REAL], 1).key


def test_cabecera_gigante_se_resuelve_rapido():
    huge = ", ".join(["203.0.113.1"] * 200_000) + f", {REAL}"
    start = time.perf_counter()
    assert resolve_client("10.0.0.5", [huge], 1).key == REAL
    assert time.perf_counter() - start < 0.5


# ------------------------------------------------------- aviso de arranque
def _warnings(caplog):
    return [r for r in caplog.records if r.levelno == logging.WARNING and "A3" in r.getMessage()]


def test_avisa_con_comodin_y_sin_saltos_configurados(caplog):
    with caplog.at_level(logging.WARNING, logger="backend.client_ip"):
        warn_if_proxy_headers_untrusted(0, {"FORWARDED_ALLOW_IPS": "*"})
    assert len(_warnings(caplog)) == 1


@pytest.mark.parametrize(
    "hops,env",
    [(1, {"FORWARDED_ALLOW_IPS": "*"}), (0, {}), (0, {"FORWARDED_ALLOW_IPS": "127.0.0.1,::1"})],
)
def test_no_avisa_si_la_combinacion_no_es_la_vulnerable(caplog, hops, env):
    with caplog.at_level(logging.WARNING, logger="backend.client_ip"):
        warn_if_proxy_headers_untrusted(hops, env)
    assert _warnings(caplog) == []


# ---------------------------------------- verificación opcional del peer TCP
def test_sin_redes_no_se_comprueba_el_peer():
    assert resolve_client("203.0.113.9", [REAL], 1).key == REAL  # peer público, sin redes


def test_con_redes_un_peer_fuera_de_ellas_ignora_la_cabecera():
    from backend.client_ip import UNTRUSTED_PEER_KEY, validate_trusted_networks

    nets = validate_trusted_networks(["10.0.0.0/8"])
    ident = resolve_client("203.0.113.9", [REAL], 1, nets)
    assert (ident.key, ident.source) == (UNTRUSTED_PEER_KEY, "fallback")
    assert resolve_client("10.1.2.3", [REAL], 1, nets).key == REAL


def test_con_redes_y_cero_saltos_se_sigue_usando_el_peer():
    from backend.client_ip import validate_trusted_networks

    nets = validate_trusted_networks(["10.0.0.0/8"])
    assert resolve_client("203.0.113.9", [REAL], 0, nets).key == "203.0.113.9"


def test_redes_desde_el_entorno():
    from backend.client_ip import TRUSTED_CIDRS_ENV, trusted_networks_from_env

    assert trusted_networks_from_env({}) is None
    assert trusted_networks_from_env({TRUSTED_CIDRS_ENV: "  "}) is None
    assert len(trusted_networks_from_env({TRUSTED_CIDRS_ENV: "10.0.0.0/8, fd00::/8"})) == 2
    for bad in ("nope", "10.0.0.0/8,", "10.0.0.0/99", ","):
        with pytest.raises(ValueError):
            trusted_networks_from_env({TRUSTED_CIDRS_ENV: bad})


# --------------------------------------------- aviso de cubo de respaldo
def test_el_aviso_de_cubo_de_respaldo_se_limita_en_el_tiempo(caplog):
    from backend.client_ip import ClientIdentity, FallbackReporter

    now = [0.0]
    reporter = FallbackReporter(interval=60, clock=lambda: now[0])
    fallback = ClientIdentity("untrusted-proxy-chain", "fallback", "chain-too-short")
    normal = ClientIdentity(REAL, "forwarded-for")
    with caplog.at_level(logging.WARNING, logger="backend.client_ip"):
        assert reporter.report("10.0.0.5", normal) is False
        assert reporter.report("10.0.0.5", fallback) is True
        now[0] = 30
        assert reporter.report("10.0.0.5", fallback) is False
        now[0] = 61
        assert reporter.report("10.0.0.5", fallback) is True
    assert len(_warnings(caplog)) == 2
    assert "1 mas" in _warnings(caplog)[1].getMessage()
