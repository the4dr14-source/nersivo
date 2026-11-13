"""Regresión de A3: evasión del rate limiter manipulando `X-Forwarded-For`.

QUÉ SON ESTOS TESTS
-------------------
Pruebas a nivel ASGI en local. Envuelven la app con el `ProxyHeadersMiddleware`
REAL de Uvicorn (la misma clase que Uvicorn aplica en producción) y simulan lo
que hace un proxy: el peer TCP es el proxy y este AÑADE la IP del cliente al
final de `X-Forwarded-For`.

QUÉ NO DEMUESTRAN
-----------------
Que Render entregue esa cadena. Eso depende de la plataforma y solo se
comprueba en producción con el procedimiento de verificación (diagnóstico
`NERSIVO_LOG_CLIENT_IP_RESOLUTION=1`). Un TestClient no prueba el proxy real.

Direcciones: 203.0.113.0/24 y 198.51.100.0/24 son rangos de documentación
(RFC 5737); 10.0.0.5 representa al proxy interno.
"""

import logging

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

from backend import analyzer, main
from backend.client_ip import TRUSTED_HOPS_ENV, UNTRUSTED_CHAIN_KEY
from backend.models import Status
from backend.rate_limit import AnalyzeRateLimitMiddleware
from backend.tests.helpers import make_check

PROXY = ("10.0.0.5", 4000)
CLIENT_A = "198.51.100.9"
CLIENT_B = "198.51.100.10"
LIMIT = 3
OFFICIAL_ORIGIN = "https://nersivo-frontend.onrender.com"


def make_app(hops=None, networks=None):
    app = FastAPI()
    app.add_middleware(
        AnalyzeRateLimitMiddleware,
        max_requests=LIMIT,
        window_seconds=60,
        trusted_proxy_hops=hops,
        trusted_proxy_networks=networks,
    )

    @app.get("/analyze/{domain}")
    def analyze(domain: str):
        return {"ok": True}

    @app.get("/health")
    def health():
        return {"ok": True}

    return app


def behind_uvicorn(app, forwarded_allow_ips):
    """Aplica el middleware real de Uvicorn, como hace `uvicorn.run`."""
    return ProxyHeadersMiddleware(app, trusted_hosts=forwarded_allow_ips)


def no_proxy_headers(app):
    """Uvicorn con ``--no-proxy-headers``: ``scope["client"]`` sigue siendo el
    peer TCP real (el proxy) y la app lee ella misma ``X-Forwarded-For``."""
    return app


def burst(client, headers_list):
    return [client.get("/analyze/example.com", headers=h).status_code for h in headers_list]


def xff(*chain):
    return {"X-Forwarded-For": ", ".join(chain)}


# Render hoy: Uvicorn confía en todos los orígenes (FORWARDED_ALLOW_IPS=*).
RENDER_DEFAULT = "*"
# Valor por defecto de Uvicorn (equivale a no confiar en el proxy de Render).
UVICORN_DEFAULT = "127.0.0.1,::1"


# ------------------------------------------------------------ caracterización
def test_CARACTERIZACION_sin_saltos_y_con_comodin_el_limite_se_evade():
    """Documenta A3: el código solo con valores por defecto NO basta.

    Con `FORWARDED_ALLOW_IPS=*` (valor por defecto de Render) y
    `NERSIVO_TRUSTED_PROXY_HOPS=0`, Uvicorn deja `request.client.host` en manos
    del cliente. Este test existe para que nadie crea que el despliegue del
    código por sí solo cierra A3: hace falta configurar los saltos (o
    `--no-proxy-headers`).
    """
    c = TestClient(behind_uvicorn(make_app(hops=0), RENDER_DEFAULT), client=PROXY)
    headers = [xff(f"203.0.113.{i}", CLIENT_A) for i in range(1, 8)]
    assert burst(c, headers) == [200] * 7  # el límite (3) nunca se aplica


# ----------------------------------------------------- corrección con 1 salto
def test_con_un_salto_la_cabecera_falsificada_no_recupera_cuota():
    c = TestClient(no_proxy_headers(make_app(hops=1)), client=PROXY)
    headers = [xff(f"203.0.113.{i}", CLIENT_A) for i in range(1, 8)]
    assert burst(c, headers) == [200, 200, 200, 429, 429, 429, 429]


def test_con_un_salto_la_cadena_con_muchas_ips_falsas_tampoco_funciona():
    c = TestClient(no_proxy_headers(make_app(hops=1)), client=PROXY)
    headers = [
        xff(*[f"203.0.113.{i}" for i in range(1, 30)], CLIENT_A) for _ in range(5)
    ]
    assert burst(c, headers) == [200, 200, 200, 429, 429]


def test_con_un_salto_cambiar_solo_la_cabecera_no_devuelve_la_cuota():
    c = TestClient(no_proxy_headers(make_app(hops=1)), client=PROXY)
    assert burst(c, [xff(CLIENT_A)] * 3) == [200, 200, 200]
    assert c.get("/analyze/example.com", headers=xff(CLIENT_A)).status_code == 429
    # Mismas condiciones salvo una cabecera falsificada a la izquierda.
    for forged in ("203.0.113.77", "1.1.1.1, 2.2.2.2", "::1", "unknown", ""):
        r = c.get("/analyze/example.com", headers=xff(forged, CLIENT_A) if forged else xff(CLIENT_A))
        assert r.status_code == 429, f"falsificar {forged!r} no debería devolver cuota"


def test_con_un_salto_dos_clientes_distintos_no_comparten_cuota():
    c = TestClient(no_proxy_headers(make_app(hops=1)), client=PROXY)
    assert burst(c, [xff(CLIENT_A)] * 4) == [200, 200, 200, 429]
    assert burst(c, [xff(CLIENT_B)] * 4) == [200, 200, 200, 429]


def test_el_cliente_legitimo_se_identifica_con_la_ip_anadida_por_el_proxy():
    app = make_app(hops=1)
    c = TestClient(no_proxy_headers(app), client=PROXY)
    c.get("/analyze/example.com", headers=xff("203.0.113.77", CLIENT_A))
    assert list(limiter_keys(app)) == [CLIENT_A]


def test_con_dos_saltos_se_usa_la_penultima_entrada():
    app = make_app(hops=2)
    c = TestClient(no_proxy_headers(app), client=PROXY)
    headers = [xff(f"203.0.113.{i}", CLIENT_A, "10.9.9.9") for i in range(1, 6)]
    assert burst(c, headers) == [200, 200, 200, 429, 429]
    assert list(limiter_keys(app)) == [CLIENT_A]


def test_varias_lineas_x_forwarded_for_no_permiten_evadir():
    c = TestClient(no_proxy_headers(make_app(hops=1)), client=PROXY)
    codes = []
    for i in range(1, 6):
        r = c.get(
            "/analyze/example.com",
            headers=[("x-forwarded-for", f"203.0.113.{i}"), ("x-forwarded-for", CLIENT_A)],
        )
        codes.append(r.status_code)
    assert codes == [200, 200, 200, 429, 429]


# --------------------------------- ausencia / cabecera inválida: sigue limitando
@pytest.mark.parametrize("hops", [1, 2])
def test_sin_cabecera_el_limitador_no_se_desactiva(hops):
    app = make_app(hops=hops)
    c = TestClient(no_proxy_headers(app), client=PROXY)
    assert burst(c, [{}] * 5) == [200, 200, 200, 429, 429]
    assert list(limiter_keys(app)) == [UNTRUSTED_CHAIN_KEY]


@pytest.mark.parametrize(
    "bad",
    # b"\xe9" es un byte latin-1 (no ASCII) tal como lo enviaría un cliente real.
    ["", " ", ",", "no-es-ip", "1.2.3", "1.2.3.4.5", "999.1.1.1", "'; DROP TABLE x;--", b"\xe9", "a" * 3000],
)
def test_cabecera_vacia_o_malformada_no_permite_recuperar_cuota(bad):
    app = make_app(hops=1)
    c = TestClient(no_proxy_headers(app), client=PROXY)
    codes = [c.get("/analyze/example.com", headers={"X-Forwarded-For": bad}).status_code for _ in range(5)]
    assert codes == [200, 200, 200, 429, 429]
    assert list(limiter_keys(app)) == [UNTRUSTED_CHAIN_KEY]


def test_cambiar_el_contenido_malformado_no_crea_cubos_nuevos():
    app = make_app(hops=1)
    c = TestClient(no_proxy_headers(app), client=PROXY)
    codes = [
        c.get("/analyze/example.com", headers={"X-Forwarded-For": f"basura-{i}"}).status_code
        for i in range(6)
    ]
    assert codes == [200, 200, 200, 429, 429, 429]
    assert len(limiter_keys(app)) == 1


def test_formas_textuales_distintas_de_la_misma_ipv6_comparten_cubo():
    app = make_app(hops=1)
    c = TestClient(no_proxy_headers(app), client=PROXY)
    forms = ["2001:DB8::1", "2001:db8:0:0:0:0:0:1", "[2001:db8::1]:443", "2001:db8::0:1"]
    assert burst(c, [xff("1.1.1.1", f) for f in forms]) == [200, 200, 200, 429]
    assert list(limiter_keys(app)) == ["2001:db8::/64"]  # IPv6 se agrega por /64


# ------------------------------------------- 0 saltos con Uvicorn sin comodín
def test_sin_saltos_y_con_uvicorn_sin_comodin_la_cabecera_se_ignora():
    """Proxy NO confiable: Uvicorn ignora XFF y se limita por dirección TCP."""
    app = make_app(hops=0)
    c = TestClient(behind_uvicorn(app, UVICORN_DEFAULT), client=PROXY)
    headers = [xff(f"203.0.113.{i}", CLIENT_A) for i in range(1, 8)]
    assert burst(c, headers) == [200, 200, 200, 429, 429, 429, 429]
    assert list(limiter_keys(app)) == [PROXY[0]]


def test_sin_saltos_dos_peers_tcp_distintos_no_comparten_cuota():
    app = make_app(hops=0)
    wrapped = behind_uvicorn(app, UVICORN_DEFAULT)
    a = TestClient(wrapped, client=("192.0.2.1", 1000))
    b = TestClient(wrapped, client=("192.0.2.2", 1000))
    assert burst(a, [{}] * 4) == [200, 200, 200, 429]
    assert burst(b, [{}] * 4) == [200, 200, 200, 429]


# --------------------- otras cabeceras de IP: nunca se leen (no verificadas)
@pytest.mark.parametrize("hops", [0, 1])
@pytest.mark.parametrize(
    "header", ["X-Real-IP", "Forwarded", "CF-Connecting-IP", "True-Client-IP", "X-Client-IP"]
)
def test_otras_cabeceras_de_ip_no_influyen_en_la_clave(hops, header):
    app = make_app(hops=hops)
    c = TestClient(behind_uvicorn(app, UVICORN_DEFAULT), client=PROXY)
    base = xff(CLIENT_A)
    headers = [{**base, header: f"203.0.113.{i}"} for i in range(1, 7)]
    codes = burst(c, headers)
    assert codes[:3] == [200, 200, 200] and set(codes[3:]) == {429}


# ----------------------------------------------------------------- configuración
@pytest.mark.parametrize("bad", [-1, 6, "abc"])
def test_saltos_invalidos_impiden_arrancar_el_middleware(bad):
    with pytest.raises(ValueError):
        AnalyzeRateLimitMiddleware(FastAPI(), trusted_proxy_hops=bad)


@pytest.mark.parametrize("bad", ["abc", "-1", "9", "1.5"])
def test_variable_de_entorno_invalida_impide_arrancar_el_middleware(monkeypatch, bad):
    monkeypatch.setenv(TRUSTED_HOPS_ENV, bad)
    with pytest.raises(ValueError):
        AnalyzeRateLimitMiddleware(FastAPI())


def test_la_variable_de_entorno_se_aplica_al_construir_el_middleware(monkeypatch):
    monkeypatch.setenv(TRUSTED_HOPS_ENV, "2")
    assert AnalyzeRateLimitMiddleware(FastAPI()).trusted_proxy_hops == 2
    monkeypatch.delenv(TRUSTED_HOPS_ENV)
    assert AnalyzeRateLimitMiddleware(FastAPI()).trusted_proxy_hops == 0


def test_aviso_de_arranque_en_la_combinacion_vulnerable(monkeypatch, caplog):
    monkeypatch.setenv("FORWARDED_ALLOW_IPS", "*")
    monkeypatch.delenv(TRUSTED_HOPS_ENV, raising=False)
    with caplog.at_level(logging.WARNING, logger="backend.client_ip"):
        AnalyzeRateLimitMiddleware(FastAPI())
    assert any("A3" in r.getMessage() for r in caplog.records)


def test_con_saltos_configurados_desaparece_el_aviso_de_evasion(monkeypatch, caplog):
    monkeypatch.setenv("FORWARDED_ALLOW_IPS", "*")
    monkeypatch.setenv(TRUSTED_HOPS_ENV, "1")
    with caplog.at_level(logging.WARNING, logger="backend.client_ip"):
        AnalyzeRateLimitMiddleware(FastAPI())
    messages = [r.getMessage() for r in caplog.records if "A3" in r.getMessage()]
    assert not [m for m in messages if "puede evadirse" in m]
    # En su lugar avisa, sin ocultarlo, de que la cadena no está verificada.
    assert any("no se verifica" in m for m in messages)


# ------------------------------------------------------------- diagnóstico opcional
def test_el_diagnostico_esta_apagado_por_defecto(monkeypatch, caplog):
    monkeypatch.delenv("NERSIVO_LOG_CLIENT_IP_RESOLUTION", raising=False)
    c = TestClient(no_proxy_headers(make_app(hops=1)), client=PROXY)
    with caplog.at_level(logging.WARNING, logger="backend.client_ip"):
        c.get("/analyze/example.com", headers=xff(CLIENT_A))
    assert not [r for r in caplog.records if "A3-diagnostico" in r.getMessage()]


def test_el_diagnostico_muestra_cadena_y_clave_y_no_permite_inyectar_lineas(monkeypatch, caplog):
    monkeypatch.setenv("NERSIVO_LOG_CLIENT_IP_RESOLUTION", "1")
    c = TestClient(no_proxy_headers(make_app(hops=1)), client=PROXY)
    with caplog.at_level(logging.WARNING, logger="backend.client_ip"):
        c.get("/analyze/example.com", headers=xff("203.0.113.77", CLIENT_A))
        c.get("/analyze/example.com", headers={"X-Forwarded-For": "x\tFAKE-LINE"})
    lines = [r.getMessage() for r in caplog.records if "A3-diagnostico" in r.getMessage()]
    assert len(lines) == 2
    assert "key=198.51.100.9" in lines[0] and "203.0.113.77" in lines[0]
    assert all("\n" not in line and "\t" not in line for line in lines)
    assert f"key={UNTRUSTED_CHAIN_KEY}" in lines[1]


# ------------------------------------------ app real: contrato 429 y CORS
@pytest.fixture
def real_app_client(monkeypatch):
    """`main.app` real con 1 salto de confianza detrás del Uvicorn de Render."""
    monkeypatch.setenv(TRUSTED_HOPS_ENV, "1")
    for name in ("web", "https", "dns", "mx", "spf", "dmarc"):
        monkeypatch.setattr(analyzer, f"check_{name}", lambda d: make_check(Status.OK))
    main.app.middleware_stack = None  # reconstruye leyendo la variable
    yield TestClient(no_proxy_headers(main.app), client=PROXY)
    main.app.middleware_stack = None


def test_app_real_30_peticiones_y_429_con_retry_after_y_cors(real_app_client):
    c = real_app_client
    for i in range(30):
        r = c.get("/analyze/example.com", headers=xff(f"203.0.113.{i % 250 + 1}", CLIENT_A))
        assert r.status_code == 200, f"la petición {i + 1} debería ser 200"

    r = c.get(
        "/analyze/example.com",
        headers={**xff("203.0.113.200", CLIENT_A), "Origin": OFFICIAL_ORIGIN},
    )
    assert r.status_code == 429
    assert "Demasiadas solicitudes" in r.json()["detail"]
    assert r.headers["retry-after"].isdigit() and 1 <= int(r.headers["retry-after"]) <= 60
    assert r.headers["access-control-allow-origin"] == OFFICIAL_ORIGIN

    # Cambiar solo la cabecera falsificada no devuelve cuota.
    for forged in ("1.1.1.1", "9.9.9.9, 8.8.8.8", "::1"):
        r = c.get("/analyze/example.com", headers=xff(forged, CLIENT_A))
        assert r.status_code == 429
        assert "retry-after" in r.headers


def test_app_real_otro_cliente_conserva_su_cuota_y_otros_endpoints_siguen(real_app_client):
    c = real_app_client
    for _ in range(30):
        assert c.get("/analyze/example.com", headers=xff(CLIENT_A)).status_code == 200
    assert c.get("/analyze/example.com", headers=xff(CLIENT_A)).status_code == 429
    assert c.get("/analyze/example.com", headers=xff(CLIENT_B)).status_code == 200
    assert c.get("/health", headers=xff(CLIENT_A)).status_code == 200


# -------------------------------------------------------------------- helpers
def limiter_keys(app):
    """Claves vistas por el limitador real de la pila ya construida."""
    layer = app.middleware_stack
    assert layer is not None, "haz al menos una petición para construir la pila"
    while layer is not None:
        if isinstance(layer, AnalyzeRateLimitMiddleware):
            return list(layer.limiter._requests.keys())
        layer = getattr(layer, "app", None)
    pytest.fail("AnalyzeRateLimitMiddleware no está en la pila")


# =====================================================================
# Segunda ronda de A3: (1) confianza en la cadena de proxies y
# (2) cubos de respaldo. Todo esto es ASGI local; NO demuestra qué cadena
# entrega Render (eso solo se comprueba en producción con el diagnóstico).
# =====================================================================
from backend.client_ip import (  # noqa: E402
    TRUSTED_CIDRS_ENV,
    UNTRUSTED_PEER_KEY,
)

PROXY_NETS = ["10.0.0.0/8"]
DIRECT_ATTACKER = ("203.0.113.50", 5555)  # llega al contenedor SIN pasar por el proxy


# --- Render hoy (FORWARDED_ALLOW_IPS=*) con un salto: debe seguir funcionando.
# La iteración anterior perdió esta cobertura y, con `*`, metía a todos los
# usuarios en un único cubo.
def test_render_actual_con_comodin_falsificar_la_izquierda_no_recupera_cuota():
    c = TestClient(behind_uvicorn(make_app(hops=1), RENDER_DEFAULT), client=PROXY)
    headers = [xff(f"203.0.113.{i}", CLIENT_A) for i in range(1, 8)]
    assert burst(c, headers) == [200, 200, 200, 429, 429, 429, 429]


def test_render_actual_con_comodin_dos_usuarios_legitimos_no_comparten_cuota():
    app = make_app(hops=1)
    c = TestClient(behind_uvicorn(app, RENDER_DEFAULT), client=PROXY)
    assert burst(c, [xff(CLIENT_A)] * 4) == [200, 200, 200, 429]
    assert burst(c, [xff(CLIENT_B)] * 4) == [200, 200, 200, 429]
    assert set(limiter_keys(app)) == {CLIENT_A, CLIENT_B}


# --- (1) verificación opcional del peer TCP
def test_con_redes_el_cliente_detras_de_un_proxy_de_confianza_se_identifica():
    app = make_app(hops=1, networks=PROXY_NETS)
    c = TestClient(no_proxy_headers(app), client=PROXY)
    assert burst(c, [xff("203.0.113.77", CLIENT_A)] * 4) == [200, 200, 200, 429]
    assert list(limiter_keys(app)) == [CLIENT_A]


def test_con_redes_un_peer_no_confiable_no_puede_elegir_su_ip_con_la_cabecera():
    """Alcanza el contenedor sin proxy y escribe la cadena que quiere."""
    app = make_app(hops=1, networks=PROXY_NETS)
    c = TestClient(no_proxy_headers(app), client=DIRECT_ATTACKER)
    headers = [xff(f"192.0.2.{i}") for i in range(1, 8)]
    assert burst(c, headers) == [200, 200, 200, 429, 429, 429, 429]
    assert list(limiter_keys(app)) == [UNTRUSTED_PEER_KEY]


@pytest.mark.parametrize("peer", ["testclient", "2001:db8::1", "999.1.1.1"])
def test_con_redes_un_peer_ilegible_o_de_otra_familia_no_es_de_confianza(peer):
    app = make_app(hops=1, networks=PROXY_NETS)
    c = TestClient(no_proxy_headers(app), client=(peer, 1))
    c.get("/analyze/example.com", headers=xff(CLIENT_A))
    assert list(limiter_keys(app)) == [UNTRUSTED_PEER_KEY]


def test_con_redes_ipv6_el_peer_de_confianza_se_acepta():
    app = make_app(hops=1, networks=["fd00::/8", "10.0.0.0/8"])
    c = TestClient(no_proxy_headers(app), client=("fd00::5", 1))
    c.get("/analyze/example.com", headers=xff(CLIENT_A))
    assert list(limiter_keys(app)) == [CLIENT_A]


# --- (2) los cubos de respaldo no perjudican a clientes con cadena válida
def test_un_atacante_con_basura_a_la_izquierda_solo_agota_su_propia_cuota():
    """Por el proxy, la basura queda a la izquierda de la IP que añade el proxy."""
    app = make_app(hops=1, networks=PROXY_NETS)
    c = TestClient(no_proxy_headers(app), client=PROXY)
    attacker = [xff("basura", "<script>", "1.2.3", "198.51.100.66")] * 10
    assert burst(c, attacker).count(429) == 7
    assert burst(c, [xff(CLIENT_A)] * 3) == [200, 200, 200]  # legítimo intacto


def test_inundar_el_cubo_de_cadenas_anomalas_no_afecta_a_cadenas_validas():
    app = make_app(hops=1, networks=PROXY_NETS)
    c = TestClient(no_proxy_headers(app), client=PROXY)
    flood = [{"X-Forwarded-For": f"x{i}"} for i in range(20)] + [{}] * 5
    assert burst(c, flood).count(429) == 22  # sigue limitado: sin evasión
    assert burst(c, [xff(CLIENT_A)] * 3) == [200, 200, 200]


def test_el_cubo_de_peer_no_confiable_es_distinto_del_de_cadena_anomala():
    app = make_app(hops=1, networks=PROXY_NETS)
    direct = TestClient(no_proxy_headers(app), client=DIRECT_ATTACKER)
    proxied = TestClient(no_proxy_headers(app), client=PROXY)
    assert burst(direct, [xff(CLIENT_A)] * 5).count(429) == 2
    assert burst(proxied, [{}] * 3) == [200, 200, 200]  # su cubo está intacto
    assert set(limiter_keys(app)) == {UNTRUSTED_CHAIN_KEY, UNTRUSTED_PEER_KEY}


# --- configuración coherente al arrancar
def test_redes_con_comodin_de_uvicorn_impiden_arrancar(monkeypatch):
    monkeypatch.setenv("FORWARDED_ALLOW_IPS", "*")
    with pytest.raises(ValueError, match=TRUSTED_CIDRS_ENV):
        AnalyzeRateLimitMiddleware(FastAPI(), trusted_proxy_hops=1, trusted_proxy_networks=PROXY_NETS)


def test_redes_con_comodin_en_lista_tambien_impiden_arrancar(monkeypatch):
    monkeypatch.setenv("FORWARDED_ALLOW_IPS", "127.0.0.1, *")
    with pytest.raises(ValueError):
        AnalyzeRateLimitMiddleware(FastAPI(), trusted_proxy_hops=1, trusted_proxy_networks=PROXY_NETS)


def test_redes_con_uvicorn_sin_comodin_arrancan_sin_aviso_de_cadena_sin_verificar(monkeypatch, caplog):
    monkeypatch.setenv("FORWARDED_ALLOW_IPS", "127.0.0.1")
    with caplog.at_level(logging.WARNING, logger="backend.client_ip"):
        AnalyzeRateLimitMiddleware(FastAPI(), trusted_proxy_hops=1, trusted_proxy_networks=PROXY_NETS)
    assert not [r for r in caplog.records if "no se verifica" in r.getMessage()]


def test_con_cero_saltos_las_redes_no_se_usan_y_no_bloquean_el_arranque(monkeypatch):
    monkeypatch.setenv("FORWARDED_ALLOW_IPS", "*")
    AnalyzeRateLimitMiddleware(FastAPI(), trusted_proxy_hops=0, trusted_proxy_networks=PROXY_NETS)


def test_redes_invalidas_en_el_entorno_impiden_arrancar(monkeypatch):
    monkeypatch.setenv(TRUSTED_CIDRS_ENV, "10.0.0.0/8, no-es-una-red")
    monkeypatch.setenv(TRUSTED_HOPS_ENV, "1")
    with pytest.raises(ValueError):
        AnalyzeRateLimitMiddleware(FastAPI())


# --- el error de configuración debe verse al arrancar, no en la 1ª petición
def _import_main_with(env):
    import os
    import subprocess
    import sys

    clean = {k: v for k, v in os.environ.items() if not k.startswith("NERSIVO_") and k != "FORWARDED_ALLOW_IPS"}
    return subprocess.run(
        [sys.executable, "-c", "import backend.main"],
        env={**clean, **env}, capture_output=True, text=True, timeout=60,
    )


@pytest.mark.parametrize(
    "env",
    [
        {TRUSTED_HOPS_ENV: "1", TRUSTED_CIDRS_ENV: "10.0.0.0/8", "FORWARDED_ALLOW_IPS": "*"},
        {TRUSTED_HOPS_ENV: "abc"},
        {TRUSTED_HOPS_ENV: "1", TRUSTED_CIDRS_ENV: "no-es-una-red"},
    ],
)
def test_importar_la_app_con_configuracion_incoherente_falla_al_arrancar(env):
    result = _import_main_with(env)
    assert result.returncode != 0
    assert "ValueError" in result.stderr


@pytest.mark.parametrize(
    "env",
    [
        {},
        {TRUSTED_HOPS_ENV: "1", "FORWARDED_ALLOW_IPS": "*"},
        {TRUSTED_HOPS_ENV: "1", TRUSTED_CIDRS_ENV: "10.0.0.0/8", "FORWARDED_ALLOW_IPS": "127.0.0.1"},
    ],
)
def test_importar_la_app_con_configuracion_valida_funciona(env):
    result = _import_main_with(env)
    assert result.returncode == 0, result.stderr


# --- diagnóstico: puerto y truncado por la izquierda
def _diag_lines(caplog):
    return [r.getMessage() for r in caplog.records if "A3-diagnostico" in r.getMessage()]


def test_el_diagnostico_incluye_el_puerto_del_cliente_que_ve_la_app(monkeypatch, caplog):
    monkeypatch.setenv("NERSIVO_LOG_CLIENT_IP_RESOLUTION", "1")
    c = TestClient(no_proxy_headers(make_app(hops=1)), client=PROXY)
    with caplog.at_level(logging.WARNING, logger="backend.client_ip"):
        c.get("/analyze/example.com", headers=xff(CLIENT_A))
    (line,) = _diag_lines(caplog)
    assert "peer='10.0.0.5' port=4000" in line  # sin reescritura: el peer real


def test_con_comodin_el_diagnostico_muestra_la_direccion_reescrita_y_puerto_0(monkeypatch, caplog):
    """Con `*` Uvicorn sustituye el cliente por la 1ª entrada de la cabecera:
    `peer`/`port` NO son el peer TCP (aquí 10.0.0.5:4000, que no se ve)."""
    monkeypatch.setenv("NERSIVO_LOG_CLIENT_IP_RESOLUTION", "1")
    c = TestClient(behind_uvicorn(make_app(hops=1), RENDER_DEFAULT), client=PROXY)
    with caplog.at_level(logging.WARNING, logger="backend.client_ip"):
        c.get("/analyze/example.com", headers=xff("203.0.113.77", CLIENT_A))
    (line,) = _diag_lines(caplog)
    assert "peer='203.0.113.77' port=0" in line
    assert "10.0.0.5" not in line and "4000" not in line
    assert f"key={CLIENT_A}" in line  # el limitador no usa el valor reescrito


def test_el_diagnostico_conserva_el_final_de_una_cabecera_larga(monkeypatch, caplog):
    """Lo añadido por los proxies está al final: no puede quedar truncado."""
    monkeypatch.setenv("NERSIVO_LOG_CLIENT_IP_RESOLUTION", "1")
    c = TestClient(no_proxy_headers(make_app(hops=1)), client=PROXY)
    long_forged = ", ".join(f"203.0.113.{i % 250}" for i in range(400))  # > 300 caracteres
    assert len(long_forged) > 1000
    with caplog.at_level(logging.WARNING, logger="backend.client_ip"):
        c.get("/analyze/example.com", headers=xff(long_forged, CLIENT_A))
    (line,) = _diag_lines(caplog)
    assert f"{CLIENT_A}'" in line  # el último elemento sigue visible en xff=
    assert f"key={CLIENT_A}" in line
    assert len(line) < 500
    assert "\n" not in line


def test_log_resolution_sin_puerto_sigue_funcionando():
    from backend.client_ip import ClientIdentity, log_resolution

    log_resolution("10.0.0.5", [CLIENT_A], 1, ClientIdentity(CLIENT_A, "forwarded-for"))
