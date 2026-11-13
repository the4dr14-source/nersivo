"""Regresiones del cierre de A3 (evidencia reproducida con Uvicorn real).

Cubren dos fallos demostrados con pruebas HTTP reales contra Uvicorn 0.53:

1. IPv6: la clave del limitador era la dirección completa. Un cliente con un
   /64 (2**64 direcciones) rotaba la parte baja y no se le limitaba nunca (40
   direcciones distintas, 40 respuestas aceptadas), además de llenar la tabla
   del limitador (interacción con el tope de claves de A2/M2). Ahora la clave
   de una dirección IPv6 es su /64.
2. ``NERSIVO_TRUSTED_PROXY_CIDRS`` con ``FORWARDED_ALLOW_IPS`` que incluye al
   proxy: Uvicorn reescribe ``scope["client"]`` con la IP del usuario final, el
   chequeo de peer falla para TODOS y todos los usuarios comparten un cubo. Ahora
   es un error de arranque (antes el docstring lo recomendaba).

Qué NO demuestran: cuántas entradas añade Render a ``X-Forwarded-For``. Eso solo
se verifica en producción (ver ``docs/A3_CLIENT_IP.md``, §5).
"""

import asyncio
import logging

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.client_ip import (
    IPV6_RATE_LIMIT_PREFIX,
    TRUSTED_CIDRS_ENV,
    TRUSTED_HOPS_ENV,
    UNTRUSTED_PEER_KEY,
    rate_limit_key,
    resolve_client,
)
from backend.rate_limit import AnalyzeRateLimitMiddleware
from backend.tests.test_rate_limit_a3 import (
    LIMIT,
    PROXY,
    PROXY_NETS,
    behind_uvicorn,
    burst,
    limiter_keys,
    make_app,
    no_proxy_headers,
    xff,
)

REAL6 = "2001:db8:aaaa:bbbb"  # /64 de documentación (RFC 3849)


# ------------------------------------------------------------ 1. IPv6 / 64
def test_rate_limit_key_ipv4_no_se_agrega():
    assert rate_limit_key("198.51.100.9") == "198.51.100.9"
    assert rate_limit_key("198.51.100.10") != rate_limit_key("198.51.100.9")


def test_rate_limit_key_ipv6_es_el_prefijo_64():
    assert IPV6_RATE_LIMIT_PREFIX == 64
    assert rate_limit_key("2001:db8:aaaa:bbbb::1") == "2001:db8:aaaa:bbbb::/64"
    assert rate_limit_key("2001:db8:aaaa:bbbb:ffff:ffff:ffff:ffff") == "2001:db8:aaaa:bbbb::/64"
    assert rate_limit_key("2001:db8:aaaa:cccc::1") == "2001:db8:aaaa:cccc::/64"


def test_resolve_client_rotar_la_parte_baja_de_un_64_no_crea_cubos():
    keys = {
        resolve_client("10.0.0.5", [f"1.1.1.1, {REAL6}::{i:x}, 10.1.1.1"], 2).key
        for i in range(1, 500)
    }
    assert keys == {f"{REAL6}::/64"}


def test_resolve_client_64_distintos_no_comparten_cubo():
    a = resolve_client("10.0.0.5", [f"2001:db8:aaaa:1::5"], 1).key
    b = resolve_client("10.0.0.5", [f"2001:db8:aaaa:2::5"], 1).key
    assert a != b


def test_resolve_client_ipv4_mapeada_en_ipv6_sigue_siendo_ipv4():
    assert resolve_client("10.0.0.5", ["::ffff:198.51.100.9"], 1).key == "198.51.100.9"


def test_sin_saltos_el_peer_ipv6_tambien_se_agrega():
    a = resolve_client("2001:db8:5:6::1", [], 0).key
    b = resolve_client("2001:db8:5:6:ffff::2", [], 0).key
    assert a == b == "2001:db8:5:6::/64"


def test_sin_saltos_un_peer_no_ip_conserva_su_texto():
    # `testclient` (Starlette) o un literal: no es IP, no se transforma.
    assert resolve_client("testclient", [], 0).key == "testclient"


def test_app_real_rotar_ipv6_dentro_de_un_64_no_recupera_cuota():
    """Reproduce el fallo: antes 40/40 aceptadas, ahora LIMIT y 429."""
    app = make_app(hops=1)
    c = TestClient(behind_uvicorn(app, "*"), client=PROXY)
    codes = burst(c, [xff("203.0.113.1", f"{REAL6}::{i:x}") for i in range(1, 41)])
    assert codes.count(200) == LIMIT
    assert codes.count(429) == 40 - LIMIT
    assert list(limiter_keys(app)) == [f"{REAL6}::/64"]


def test_app_real_rotar_ipv6_no_llena_la_tabla_del_limitador():
    """Interacción A3 x A2/M2: antes cada dirección era una clave y 10 000
    direcciones llenaban la tabla, empujando a los clientes NUEVOS legítimos al
    cubo de desbordamiento compartido."""
    fastapi_app = make_app(hops=1)
    c = TestClient(behind_uvicorn(fastapi_app, "*"), client=PROXY)
    burst(c, [xff(f"{REAL6}::{i:x}") for i in range(1, 300)])
    assert len(limiter_keys(fastapi_app)) == 1
    # Un cliente legítimo nuevo conserva su cuota completa y su propia clave.
    assert burst(c, [xff("198.51.100.200")] * LIMIT) == [200] * LIMIT
    assert len(limiter_keys(fastapi_app)) == 2


def test_app_real_dos_64_distintos_conservan_cuota_independiente():
    app = make_app(hops=1)
    c = TestClient(behind_uvicorn(app, "*"), client=PROXY)
    assert burst(c, [xff("2001:db8:1:1::9")] * (LIMIT + 1)).count(429) == 1
    assert burst(c, [xff("2001:db8:1:2::9")] * LIMIT) == [200] * LIMIT


def test_app_real_formas_textuales_y_puerto_ipv6_comparten_el_64():
    app = make_app(hops=1)
    c = TestClient(behind_uvicorn(app, "*"), client=PROXY)
    forms = [f"{REAL6}::1", f"[{REAL6}::2]:443", f"{REAL6.upper()}:0:0:0:3", f"{REAL6}:0:0:0:4"]
    assert burst(c, [xff(f) for f in forms]) == [200, 200, 200, 429]


# --------------------------- 2. CIDRS x FORWARDED_ALLOW_IPS (Uvicorn reescribe)
def test_CARACTERIZACION_uvicorn_reescribe_el_cliente_si_el_proxy_esta_en_su_lista():
    """Motivo del chequeo de arranque: con el proxy en FORWARDED_ALLOW_IPS,
    Uvicorn sustituye el peer por la IP del usuario y el chequeo de peer de la
    app falla para TODOS (cubo único), aunque `FORWARDED_ALLOW_IPS` no sea `*`."""
    app = make_app(hops=1, networks=PROXY_NETS)
    c = TestClient(behind_uvicorn(app, "10.0.0.5"), client=PROXY)
    burst(c, [xff("198.51.100.1")])
    burst(c, [xff("198.51.100.2")])
    assert list(limiter_keys(app)) == [UNTRUSTED_PEER_KEY]


def test_CARACTERIZACION_con_la_lista_sin_el_proxy_el_peer_se_comprueba_bien():
    app = make_app(hops=1, networks=PROXY_NETS)
    c = TestClient(behind_uvicorn(app, "192.0.2.77"), client=PROXY)
    burst(c, [xff("198.51.100.1")])
    burst(c, [xff("198.51.100.2")])
    assert sorted(limiter_keys(app)) == ["198.51.100.1", "198.51.100.2"]


@pytest.mark.parametrize(
    "allow",
    [
        "10.0.0.5",  # IP dentro de la red de confianza
        "10.0.0.0/8",  # la misma red
        "10.1.0.0/16",  # subred de la red de confianza
        "10.0.0.0/7",  # red que contiene a la de confianza
        "192.0.2.1, 10.0.0.5",  # varias entradas, una solapa
        " 10.0.0.5 ",  # con espacios
    ],
)
def test_redes_que_solapan_con_forwarded_allow_ips_impiden_arrancar(monkeypatch, allow):
    monkeypatch.setenv("FORWARDED_ALLOW_IPS", allow)
    with pytest.raises(ValueError, match="solapa"):
        AnalyzeRateLimitMiddleware(
            FastAPI(), trusted_proxy_hops=1, trusted_proxy_networks=PROXY_NETS
        )


def test_solape_ipv6_impide_arrancar(monkeypatch):
    monkeypatch.setenv("FORWARDED_ALLOW_IPS", "fd00::5")
    with pytest.raises(ValueError, match="solapa"):
        AnalyzeRateLimitMiddleware(
            FastAPI(), trusted_proxy_hops=1, trusted_proxy_networks=["fd00::/8"]
        )


@pytest.mark.parametrize(
    "allow",
    [
        "127.0.0.1,::1",  # valor por defecto de Uvicorn
        "192.0.2.0/24",  # otra red
        "fd00::5",  # otra familia que no solapa con la IPv4
        "unix-socket-literal",  # literal: no es IP, Uvicorn lo trata aparte
        "",
    ],
)
def test_redes_sin_solape_con_forwarded_allow_ips_arrancan(monkeypatch, allow):
    monkeypatch.setenv("FORWARDED_ALLOW_IPS", allow)
    AnalyzeRateLimitMiddleware(FastAPI(), trusted_proxy_hops=1, trusted_proxy_networks=PROXY_NETS)


def test_sin_redes_o_sin_saltos_el_solape_no_aplica(monkeypatch):
    monkeypatch.setenv("FORWARDED_ALLOW_IPS", "10.0.0.5")
    # Sin redes: modo "cadena sin verificar" (avisa, no falla).
    AnalyzeRateLimitMiddleware(FastAPI(), trusted_proxy_hops=1)
    # Sin saltos las redes no se usan.
    AnalyzeRateLimitMiddleware(FastAPI(), trusted_proxy_hops=0, trusted_proxy_networks=PROXY_NETS)


def test_el_solape_se_detecta_al_importar_la_app():
    import os
    import subprocess
    import sys

    clean = {k: v for k, v in os.environ.items() if not k.startswith("NERSIVO_") and k != "FORWARDED_ALLOW_IPS"}
    env = {**clean, TRUSTED_HOPS_ENV: "1", TRUSTED_CIDRS_ENV: "10.0.0.0/8", "FORWARDED_ALLOW_IPS": "10.0.0.5"}
    result = subprocess.run(
        [sys.executable, "-c", "import backend.main"], env=env, capture_output=True, text=True, timeout=60
    )
    assert result.returncode != 0
    assert "ValueError" in result.stderr and "solapa" in result.stderr


# ------------------------------------------------------ 3. limites conocidos
def test_CARACTERIZACION_si_la_plataforma_anade_menos_entradas_que_los_saltos_el_cliente_elige_su_clave():
    """LIMITE NO CORREGIBLE EN CODIGO (necesita verificación en producción).

    Con HOPS=3 y una plataforma que añadiese solo 2 entradas, la 3ª por la
    derecha la escribe el cliente (relleno a la izquierda) y puede rotarla. Con
    una cadena MÁS LARGA que HOPS el efecto es el contrario (cubo compartido,
    fallo cerrado). Reproducido con Uvicorn real: 40/40 aceptadas con 2 entradas
    añadidas y HOPS=3. La mitigación es verificar los saltos reales en Render
    (``docs/A3_CLIENT_IP.md``, §5) y vigilar los avisos de cubo de respaldo."""
    keys = {
        resolve_client("10.0.0.5", [f"203.0.113.{i}, 203.0.114.{i}, 198.51.100.9, 10.1.1.1"], 3).key
        for i in range(1, 30)
    }
    assert len(keys) == 29  # la clave la elige el cliente: configuración incorrecta
    # Con cadena de la longitud correcta (3 entradas propias del proxy) no ocurre:
    keys_ok = {
        resolve_client("10.0.0.5", [f"203.0.113.{i}, 198.51.100.9, 162.158.0.1, 10.1.1.1"], 3).key
        for i in range(1, 30)
    }
    assert keys_ok == {"198.51.100.9"}


# --------------------------------------------------------------- concurrencia
def test_concurrencia_cada_cliente_recibe_exactamente_su_cuota():
    """200 peticiones simultáneas de 20 clientes (10 cada uno, LIMIT=3): cada
    cliente consigue exactamente LIMIT 200, nadie comparte cuota y no hay carreras."""
    app = make_app(hops=1)
    stack = behind_uvicorn(app, "*")
    clients = [f"198.51.100.{i}" for i in range(1, 21)] + [f"2001:db8:aaaa:{i:x}::1" for i in range(1, 6)]  # 5 /64 distintos

    async def run():
        transport = httpx.ASGITransport(app=stack, client=PROXY)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
            jobs = [
                client.get("/analyze/example.com", headers=xff("203.0.113.9", ip))
                for ip in clients
                for _ in range(10)
            ]
            responses = await asyncio.gather(*jobs)
        return [r.status_code for r in responses]

    codes = asyncio.run(run())
    per_client = [codes[i * 10 : (i + 1) * 10] for i in range(len(clients))]
    for statuses in per_client:
        assert statuses.count(200) == LIMIT
        assert statuses.count(429) == 10 - LIMIT
    assert len(limiter_keys(app)) == len(clients)


def test_no_se_registra_aviso_de_respaldo_con_clientes_validos(caplog):
    app = make_app(hops=1)
    c = TestClient(behind_uvicorn(app, "*"), client=PROXY)
    with caplog.at_level(logging.WARNING, logger="backend.client_ip"):
        burst(c, [xff(f"{REAL6}::1"), xff("198.51.100.1")])
    assert not [r for r in caplog.records if "respaldo" in r.getMessage()]
