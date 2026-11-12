"""Pruebas de A2 - M1 (límite de `POST /monitor`), M2 (memoria) y CORS (R5).

Todo es local: SQLite temporal, analizador simulado y reloj falso. No se hace
ninguna petición de red ni contra Render.

Direcciones: 203.0.113.0/24 y 198.51.100.0/24 son rangos de documentación
(RFC 5737); 10.0.0.5 representa al proxy interno, igual que en los tests de A3.
"""

import asyncio
import itertools
import os
import subprocess
import sys
import threading
import tracemalloc

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend import main, rate_limit
from backend.client_ip import TRUSTED_HOPS_ENV
from backend.monitoring import routes
from backend.monitoring.config import MonitorSettings
from backend.monitoring.repository import repository_from_url
from backend.monitoring.service import MonitorService
from backend.rate_limit import (
    DEFAULT_MONITOR_RATE_MAX,
    DEFAULT_MONITOR_RATE_WINDOW,
    MONITOR_RATE_MAX_ENV,
    MONITOR_RATE_WINDOW_ENV,
    OVERFLOW_KEY,
    AnalyzeRateLimitMiddleware,
    InMemoryRateLimiter,
    validate_environment,
)
from backend.tests.monitor_helpers import analysis

OFFICIAL_ORIGIN = "https://nersivo-frontend.onrender.com"
PROXY = ("10.0.0.5", 4000)
CLIENT_A = "198.51.100.9"
CLIENT_B = "198.51.100.10"
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_counter = itertools.count()


# ------------------------------------------------------------------ utilidades
class StubAnalyzer:
    """Analizador simulado (sin red) que registra las llamadas."""

    def __init__(self):
        self.calls = []
        self._lock = threading.Lock()

    def __call__(self, domain):
        with self._lock:
            self.calls.append(domain)
        return analysis(domain)


class Clock:
    """Reloj falso para el limitador (sustituye a `rate_limit.monotonic`)."""

    def __init__(self, now=1000.0):
        self.now = now

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


@pytest.fixture
def clock(monkeypatch):
    fake = Clock()
    monkeypatch.setattr(rate_limit, "monotonic", fake)
    return fake


@pytest.fixture
def env(tmp_path, monkeypatch):
    """Servicio real sobre SQLite temporal inyectado en las rutas, con los
    valores por defecto de A2 (ninguna variable de entorno de límites)."""
    for name in (
        MONITOR_RATE_MAX_ENV,
        MONITOR_RATE_WINDOW_ENV,
        TRUSTED_HOPS_ENV,
        "NERSIVO_CRON_TOKEN",
    ):
        monkeypatch.delenv(name, raising=False)
    stub = StubAnalyzer()
    repo = repository_from_url(f"sqlite:///{tmp_path / 'm.db'}")
    repo.init_schema()
    # Hueco de activaciones amplio: estos tests miden el limitador por IP, no R2.
    service = MonitorService(
        repo, MonitorSettings(max_concurrent_activations=64), analyzer=stub
    )
    monkeypatch.setattr(routes, "_service", service)
    yield type("Env", (), {"service": service, "analyzer": stub})
    routes.reset_service()


def client_for(ip=CLIENT_A, **kwargs):
    return TestClient(main.app, client=(ip, 50000), **kwargs)


def post(client, headers=None):
    """`POST /monitor` con un dominio distinto cada vez (evita el tope por dominio)."""
    return client.post(
        "/monitor", json={"domain": f"d{next(_counter)}.example.com"}, headers=headers
    )


def find_middleware():
    layer = main.app.middleware_stack
    assert layer is not None, "la pila de middlewares aún no se ha construido"
    while layer is not None:
        if isinstance(layer, AnalyzeRateLimitMiddleware):
            return layer
        layer = getattr(layer, "app", None)
    pytest.fail("AnalyzeRateLimitMiddleware NO está registrado en main.app")


def xff(spoof, client):
    """Cadena de Render con 3 saltos: lo que escribe el cliente va a la izquierda."""
    return {"X-Forwarded-For": f"{spoof}, {client}, 10.0.0.1, 10.0.0.2"}


# ===================================================================== M1
def test_valores_por_defecto_son_5_por_600_y_analyze_sigue_en_30_por_60(env):
    assert (DEFAULT_MONITOR_RATE_MAX, DEFAULT_MONITOR_RATE_WINDOW) == (5, 600)
    client_for().get("/health")
    mw = find_middleware()
    assert (mw.monitor_limiter.max_requests, mw.monitor_limiter.window_seconds) == (5, 600)
    assert (mw.limiter.max_requests, mw.limiter.window_seconds) == (30, 60)
    assert mw.monitor_limiter is not mw.limiter


def test_cinco_activaciones_permitidas_y_la_sexta_se_rechaza(env, clock):
    c = client_for()
    assert [post(c).status_code for _ in range(5)] == [201] * 5

    r = post(c)
    assert r.status_code == 429
    assert r.json() == {"detail": "monitor_rate_limited"}
    retry_after = r.headers["retry-after"]
    assert retry_after.isdigit() and 1 <= int(retry_after) <= 600
    # La rechazada no llega al servicio: ni analiza ni inserta.
    assert len(env.analyzer.calls) == 5
    assert env.service.repo.count_active() == 5


def test_retry_after_decrece_y_la_cuota_se_recupera_al_terminar_la_ventana(env, clock):
    c = client_for()
    for _ in range(5):
        assert post(c).status_code == 201

    assert int(post(c).headers["retry-after"]) == 600
    clock.advance(100)
    assert int(post(c).headers["retry-after"]) == 500
    clock.advance(499)  # t = 599 s desde la primera: aún bloqueado
    r = post(c)
    assert r.status_code == 429 and int(r.headers["retry-after"]) == 1
    clock.advance(1)  # t = 600 s: la ventana ha terminado
    assert post(c).status_code == 201


def test_las_peticiones_bloqueadas_no_amplian_la_ventana(env, clock):
    c = client_for()
    for _ in range(5):
        assert post(c).status_code == 201
    clock.advance(300)
    assert all(post(c).status_code == 429 for _ in range(20))
    clock.advance(300)  # 600 s desde las 5 permitidas
    assert post(c).status_code == 201


def test_los_cuerpos_invalidos_tambien_consumen_cuota(env, clock):
    c = client_for()
    bodies = [{}, {"domain": 5}, {"domain": "localhost"}, {"domain": "http://x.com"}, []]
    assert [c.post("/monitor", json=b).status_code for b in bodies] == [422, 422, 400, 400, 422]

    r = post(c)
    assert r.status_code == 429 and r.json() == {"detail": "monitor_rate_limited"}
    assert env.analyzer.calls == []


def test_otra_ip_conserva_su_cuota(env, clock):
    a, b = client_for(CLIENT_A), client_for(CLIENT_B)
    for _ in range(5):
        assert post(a).status_code == 201
    assert post(a).status_code == 429
    assert [post(b).status_code for _ in range(5)] == [201] * 5
    assert post(b).status_code == 429


def test_agotar_monitor_no_gasta_la_cuota_de_analyze(env, clock, monkeypatch):
    monkeypatch.setattr(main, "analyze_domain", lambda d: analysis(d))
    c = client_for()
    for _ in range(5):
        assert post(c).status_code == 201
    assert post(c).status_code == 429

    assert [c.get("/analyze/example.com").status_code for _ in range(30)] == [200] * 30
    assert c.get("/analyze/example.com").status_code == 429


def test_agotar_analyze_no_gasta_la_cuota_de_monitor(env, clock, monkeypatch):
    monkeypatch.setattr(main, "analyze_domain", lambda d: analysis(d))
    c = client_for()
    for _ in range(30):
        assert c.get("/analyze/example.com").status_code == 200
    assert c.get("/analyze/example.com").status_code == 429

    assert [post(c).status_code for _ in range(5)] == [201] * 5
    assert post(c).status_code == 429


def test_el_429_de_analyze_conserva_su_contrato(env, clock, monkeypatch):
    monkeypatch.setattr(main, "analyze_domain", lambda d: analysis(d))
    c = client_for()
    for _ in range(30):
        c.get("/analyze/example.com")
    r = c.get("/analyze/example.com")
    assert r.status_code == 429
    assert r.json() == {
        "detail": "Demasiadas solicitudes de análisis. Inténtalo de nuevo más tarde."
    }
    assert r.headers["retry-after"].isdigit() and 1 <= int(r.headers["retry-after"]) <= 60


def test_solo_cuenta_post_con_la_ruta_exacta_monitor(env, clock, monkeypatch):
    monkeypatch.setenv("NERSIVO_CRON_TOKEN", "token-de-cron")
    c = client_for(follow_redirects=False)
    for _ in range(5):
        assert post(c).status_code == 201
    assert post(c).status_code == 429  # cuota de POST /monitor agotada

    preflight = {
        "Origin": OFFICIAL_ORIGIN,
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "content-type",
    }
    for _ in range(20):
        # Otros métodos de /monitor.
        assert c.get("/monitor").status_code == 401
        assert c.delete("/monitor").status_code == 401
        assert c.request("PUT", "/monitor").status_code == 405
        assert c.options("/monitor", headers=preflight).status_code == 200
        # Otras rutas.
        assert c.get("/health").status_code == 200
        assert c.post("/guides", json={}).status_code == 422
        run = c.post("/internal/monitor/run", headers={"X-Cron-Token": "token-de-cron"})
        assert run.status_code == 200
        # Variantes de ruta: no coinciden con `/monitor` y no llegan al servicio.
        assert c.post("/monitor/", json={"domain": "x.example.com"}).status_code == 307
        assert c.post("/MONITOR", json={"domain": "x.example.com"}).status_code == 404
    assert len(env.analyzer.calls) == 5


def test_la_redireccion_de_barra_final_no_consume_cuota(env, clock):
    c = client_for(follow_redirects=False)
    for _ in range(10):
        assert c.post("/monitor/", json={"domain": "x.example.com"}).status_code == 307
    assert [post(c).status_code for _ in range(5)] == [201] * 5


# ----------------------------------------------------------- configuración
def test_limite_y_ventana_se_configuran_por_entorno(env, clock, monkeypatch):
    monkeypatch.setenv(MONITOR_RATE_MAX_ENV, "2")
    monkeypatch.setenv(MONITOR_RATE_WINDOW_ENV, "30")
    c = client_for()
    assert [post(c).status_code for _ in range(2)] == [201, 201]
    r = post(c)
    assert r.status_code == 429
    assert 1 <= int(r.headers["retry-after"]) <= 30
    clock.advance(30)
    assert post(c).status_code == 201


@pytest.mark.parametrize("value", ["", "   "])
def test_valor_vacio_usa_el_predeterminado(monkeypatch, value):
    monkeypatch.setenv(MONITOR_RATE_MAX_ENV, value)
    monkeypatch.setenv(MONITOR_RATE_WINDOW_ENV, value)
    assert rate_limit.monitor_rate_from_env() == (5, 600)


@pytest.mark.parametrize(
    "name,value",
    [
        (MONITOR_RATE_MAX_ENV, v)
        for v in ("0", "1001", "abc", "-1", "5.5", "1_0", "+5", "٥", "5 peticiones")
    ]
    + [
        (MONITOR_RATE_WINDOW_ENV, v)
        for v in ("0", "86401", "x", "-600", "10 s", "6e2")
    ],
)
def test_variables_invalidas_impiden_arrancar(monkeypatch, name, value):
    monkeypatch.setenv(name, value)
    with pytest.raises(ValueError, match=name):
        validate_environment()
    with pytest.raises(ValueError, match=name):
        AnalyzeRateLimitMiddleware(app=FastAPI())


@pytest.mark.parametrize(
    "name,value", [(MONITOR_RATE_MAX_ENV, "1"), (MONITOR_RATE_MAX_ENV, "1000"),
                   (MONITOR_RATE_WINDOW_ENV, "1"), (MONITOR_RATE_WINDOW_ENV, "86400")]
)
def test_los_limites_inclusivos_son_validos(monkeypatch, name, value):
    monkeypatch.setenv(name, value)
    validate_environment()


@pytest.mark.parametrize(
    "extra,variable",
    [
        ({MONITOR_RATE_MAX_ENV: "0"}, MONITOR_RATE_MAX_ENV),
        ({MONITOR_RATE_WINDOW_ENV: "abc"}, MONITOR_RATE_WINDOW_ENV),
        ({MONITOR_RATE_MAX_ENV: "5", MONITOR_RATE_WINDOW_ENV: "600"}, None),
    ],
)
def test_importar_la_app_con_variable_invalida_falla_y_con_valida_arranca(extra, variable):
    """El error de configuración debe verse al arrancar, no en la primera petición."""
    environ = {k: v for k, v in os.environ.items() if not k.startswith("NERSIVO_")}
    environ.update(extra)
    environ["PYTHONDONTWRITEBYTECODE"] = "1"
    proc = subprocess.run(
        [sys.executable, "-W", "ignore", "-c", "import backend.main"],
        cwd=ROOT, env=environ, capture_output=True, text=True, timeout=120,
    )
    if variable is None:
        assert proc.returncode == 0, proc.stderr
    else:
        assert proc.returncode != 0
        assert "ValueError" in proc.stderr and variable in proc.stderr


# ------------------------------------------------- XFF falsificado (reusa A3)
@pytest.fixture
def prod_like(env, clock, monkeypatch):
    """Como Render: 3 saltos de confianza y la app detrás del proxy."""
    monkeypatch.setenv(TRUSTED_HOPS_ENV, "3")
    return TestClient(main.app, client=PROXY)


def test_xff_falsificado_no_devuelve_cuota_en_post_monitor(prod_like):
    c = prod_like
    for i in range(5):
        assert post(c, xff(f"203.0.113.{i + 1}", CLIENT_A)).status_code == 201

    for forged in ("1.1.1.1", "9.9.9.9, 8.8.8.8", "::1", "", "unknown", "a" * 500):
        r = post(c, xff(forged, CLIENT_A))
        assert r.status_code == 429, f"falsificar {forged!r:.20} no debe devolver cuota"
        assert r.json() == {"detail": "monitor_rate_limited"}
        assert "retry-after" in r.headers


def test_con_tres_saltos_otro_cliente_real_conserva_su_cuota(prod_like):
    c = prod_like
    for _ in range(5):
        assert post(c, xff("203.0.113.1", CLIENT_A)).status_code == 201
    assert post(c, xff("203.0.113.1", CLIENT_A)).status_code == 429
    assert post(c, xff("203.0.113.1", CLIENT_B)).status_code == 201


@pytest.mark.parametrize("header", ["X-Real-IP", "Forwarded", "CF-Connecting-IP", "True-Client-IP"])
def test_otras_cabeceras_de_ip_no_influyen_en_la_clave(prod_like, header):
    c = prod_like
    for i in range(5):
        assert post(c, {**xff("203.0.113.1", CLIENT_A), header: f"203.0.113.{i + 50}"}).status_code == 201
    r = post(c, {**xff("203.0.113.1", CLIENT_A), header: "203.0.113.99"})
    assert r.status_code == 429


def test_cadena_demasiado_corta_cae_en_un_cubo_de_respaldo_y_sigue_limitada(prod_like):
    c = prod_like
    # Sin X-Forwarded-For con 3 saltos configurados: cubo de respaldo constante.
    assert [post(c).status_code for _ in range(5)] == [201] * 5
    assert post(c).status_code == 429  # el límite NO se desactiva
    # Un cliente con cadena válida no comparte ese cubo.
    assert post(c, xff("203.0.113.1", CLIENT_A)).status_code == 201


# ===================================================================== R5 (CORS)
def test_el_429_de_monitor_lleva_cors_y_expone_retry_after(env, clock):
    c = client_for()
    for _ in range(5):
        post(c)
    r = post(c, {"Origin": OFFICIAL_ORIGIN})
    assert r.status_code == 429
    assert r.headers["access-control-allow-origin"] == OFFICIAL_ORIGIN
    assert r.headers["access-control-expose-headers"] == "Retry-After"
    assert "retry-after" in r.headers


def test_el_429_de_analyze_tambien_expone_retry_after(env, clock, monkeypatch):
    monkeypatch.setattr(main, "analyze_domain", lambda d: analysis(d))
    c = client_for()
    for _ in range(30):
        c.get("/analyze/example.com")
    r = c.get("/analyze/example.com", headers={"Origin": OFFICIAL_ORIGIN})
    assert r.status_code == 429
    assert r.headers["access-control-expose-headers"] == "Retry-After"


def test_origen_no_permitido_no_puede_leer_el_429(env, clock):
    c = client_for()
    for _ in range(5):
        post(c)
    r = post(c, {"Origin": "https://evil.example"})
    assert r.status_code == 429
    # Lo que decide si un navegador puede leer la respuesta es Allow-Origin.
    # (Starlette añade `Access-Control-Expose-Headers` a toda respuesta con
    # `Origin`, permitido o no; sin Allow-Origin es inerte y no se afirma nada
    # sobre ella para no fijar un detalle interno de Starlette.)
    assert "access-control-allow-origin" not in r.headers
    assert "access-control-allow-credentials" not in r.headers


def test_cors_no_amplia_origenes_ni_credenciales_ni_cabeceras_permitidas(env):
    assert main.ALLOWED_ORIGINS == [
        "https://nersivo-frontend.onrender.com",
        "http://localhost:5500", "http://127.0.0.1:5500",
        "http://localhost:3000", "http://127.0.0.1:3000",
        "http://localhost:5173", "http://127.0.0.1:5173",
    ]
    c = client_for()
    r = c.options("/monitor", headers={
        "Origin": OFFICIAL_ORIGIN,
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "content-type, x-monitor-token",
    })
    assert r.status_code == 200
    assert r.headers["access-control-allow-origin"] == OFFICIAL_ORIGIN
    assert "access-control-allow-credentials" not in r.headers
    bad = c.options("/monitor", headers={
        "Origin": OFFICIAL_ORIGIN,
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "x-cron-token",
    })
    assert bad.status_code == 400  # X-Cron-Token sigue sin permitirse


# ===================================================================== concurrencia
def test_100_peticiones_concurrentes_dejan_pasar_exactamente_5(env):
    async def run():
        transport = httpx.ASGITransport(app=main.app, client=("198.51.100.77", 5000))
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as ac:
            return await asyncio.gather(
                *[ac.post("/monitor", json={"domain": f"c{i}.example.com"}) for i in range(100)]
            )

    responses = asyncio.run(run())
    codes = [r.status_code for r in responses]
    assert codes.count(201) == 5 and codes.count(429) == 95
    assert all(r.json() == {"detail": "monitor_rate_limited"}
               for r in responses if r.status_code == 429)
    assert all(r.headers["retry-after"].isdigit() for r in responses if r.status_code == 429)
    assert len(env.analyzer.calls) == 5
    assert env.service.repo.count_active() == 5


def test_el_limitador_respeta_el_maximo_con_hilos_simultaneos():
    limiter = InMemoryRateLimiter(10, 60)
    barrier = threading.Barrier(50)
    results = []

    def worker():
        barrier.wait()
        results.append(limiter.allow("misma-clave", now=0.0)[0])

    threads = [threading.Thread(target=worker) for _ in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(10)
    assert all(not t.is_alive() for t in threads)
    assert results.count(True) == 10 and results.count(False) == 40


# ===================================================================== M2
def test_el_barrido_elimina_claves_expiradas_y_conserva_las_vivas():
    lim = InMemoryRateLimiter(5, 60, max_keys=1000)
    for i in range(100):
        lim.allow(f"k{i}", now=0.0)
    assert len(lim._requests) == 100

    lim.allow("viva", now=59.0)  # aún no toca barrer (próximo barrido en t=60)
    assert len(lim._requests) == 101
    lim.allow("otra", now=61.0)  # toca: k0..k99 (t=0) expiradas; "viva" (t=59) no
    assert set(lim._requests) == {"viva", "otra"}


def test_el_barrido_se_hace_como_mucho_una_vez_por_ventana():
    lim = InMemoryRateLimiter(5, 60)
    lim.allow("a", now=0.0)
    assert lim._next_sweep == 60.0
    lim.allow("b", now=30.0)
    lim.allow("c", now=59.9)
    assert lim._next_sweep == 60.0  # sin barrido antes de tiempo
    lim.allow("d", now=61.0)
    assert lim._next_sweep == 121.0
    lim.allow("e", now=100.0)
    assert lim._next_sweep == 121.0
    lim.allow("f", now=121.0)
    assert lim._next_sweep == 181.0


def test_tope_de_claves_usa_cubo_de_respaldo_y_no_permite_eludir_el_limite():
    lim = InMemoryRateLimiter(2, 60, max_keys=10)
    assert all(lim.allow(f"ip{i}", now=0.0)[0] for i in range(10))
    assert len(lim._requests) == 10

    # Claves NUEVAS: comparten un único cubo con la cuota de cualquier otra clave.
    overflow = [lim.allow(f"nuevo{i}", now=0.0)[0] for i in range(50)]
    assert overflow.count(True) == 2 and overflow.count(False) == 48
    assert OVERFLOW_KEY in lim._requests and len(lim._requests) == 11

    # Las claves ya registradas conservan su propio cubo.
    assert lim.allow("ip0", now=0.0)[0] is True
    assert lim.allow("ip0", now=0.0)[0] is False

    # Rotar identidades no devuelve cuota ni hace crecer la tabla.
    assert not any(lim.allow(f"rotada{i}", now=0.0)[0] for i in range(1000))
    assert len(lim._requests) == 11
    blocked, retry_after = lim.allow("otra-mas", now=0.0)
    assert blocked is False and retry_after == 60


def test_tras_la_ventana_el_cubo_de_respaldo_se_vacia_y_las_claves_vuelven_a_registrarse():
    lim = InMemoryRateLimiter(2, 60, max_keys=5)
    for i in range(20):
        lim.allow(f"ip{i}", now=0.0)
    assert OVERFLOW_KEY in lim._requests

    assert lim.allow("recien-llegada", now=61.0)[0] is True
    assert set(lim._requests) == {"recien-llegada"}  # tabla y cubo de respaldo vacíos


def test_con_la_tabla_llena_de_claves_caducadas_se_liberan_a_demanda():
    """Sin barrido a demanda, los clientes nuevos compartían cubo hasta la
    siguiente pasada programada aunque todas las claves ya hubieran caducado."""
    lim = InMemoryRateLimiter(2, 600, max_keys=5)
    for i in range(5):
        lim.allow(f"ip{i}", now=0.0)
    lim._next_sweep = 10_000.0  # peor caso: el barrido programado queda lejos

    assert lim.allow("nuevo", now=601.0) == (True, 0)
    assert OVERFLOW_KEY not in lim._requests
    assert set(lim._requests) == {"nuevo"}
    # Tiene su propia cuota completa (2), no la comparte con nadie.
    assert lim.allow("nuevo", now=601.0)[0] is True
    assert lim.allow("nuevo", now=601.0)[0] is False


def test_el_barrido_a_demanda_no_libera_claves_vigentes_ni_permite_eludir_el_limite():
    lim = InMemoryRateLimiter(2, 600, max_keys=5)
    for i in range(5):
        lim.allow(f"ip{i}", now=0.0)
    lim._next_sweep = 10_000.0

    # Ninguna ha caducado (t=599 < 600): el barrido no libera nada y se usa el cubo.
    results = [lim.allow(f"rotada{i}", now=599.0)[0] for i in range(50)]
    assert results.count(True) == 2 and results.count(False) == 48
    assert {f"ip{i}" for i in range(5)} <= set(lim._requests)
    assert OVERFLOW_KEY in lim._requests


def test_el_barrido_a_demanda_esta_limitado_a_uno_por_segundo():
    lim = InMemoryRateLimiter(2, 600, max_keys=3)
    for i in range(3):
        lim.allow(f"ip{i}", now=0.0)
    lim._next_sweep = 10**9  # solo cuentan los barridos a demanda

    sweeps = []
    original = lim._remove_expired
    lim._remove_expired = lambda current: (sweeps.append(current), original(current))[1]

    for i in range(1000):  # una avalancha de claves nuevas en el mismo instante
        lim.allow(f"x{i}", now=5.0)
    assert sweeps == [5.0]
    lim.allow("y", now=5.5)
    assert sweeps == [5.0]
    lim.allow("z", now=6.0)
    assert sweeps == [5.0, 6.0]


def test_la_memoria_queda_acotada_con_100000_ips_distintas():
    lim = InMemoryRateLimiter(30, 60, max_keys=10_000)
    tracemalloc.start()
    try:
        before = tracemalloc.get_traced_memory()[0]
        for i in range(100_000):
            lim.allow(f"2001:db8::{i:x}", now=0.0)
        used = tracemalloc.get_traced_memory()[0] - before
    finally:
        tracemalloc.stop()
    assert len(lim._requests) == 10_001  # 10 000 claves + el cubo de respaldo
    assert used < 20 * 1024 * 1024, f"{used / 1e6:.1f} MB"


def test_sin_tope_la_tabla_crecia_sin_limite_caracterizacion():
    """Documenta el problema que corrige M2: con un tope enorme la tabla crece."""
    lim = InMemoryRateLimiter(30, 60, max_keys=10**9)
    for i in range(5000):
        lim.allow(f"k{i}", now=0.0)
    assert len(lim._requests) == 5000


def test_acceso_concurrente_con_barridos_y_tope_no_falla_ni_se_desborda():
    lim = InMemoryRateLimiter(5, 1, max_keys=500)
    errors = []

    def worker(offset):
        try:
            for i in range(20_000):
                # `now` crece en cada hilo, así que hay barridos durante la prueba.
                lim.allow(f"h{offset}-{i}", now=i * 0.01)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    assert all(not t.is_alive() for t in threads)
    assert errors == []
    assert len(lim._requests) <= 501


def test_los_dos_limitadores_de_la_app_aplican_el_tope_de_claves(env, clock, monkeypatch):
    monkeypatch.setattr(rate_limit, "DEFAULT_MAX_KEYS", 3)
    monkeypatch.setattr(main, "analyze_domain", lambda d: analysis(d))
    ips = [f"203.0.113.{i}" for i in range(1, 7)]

    client_for(ips[0]).get("/health")
    mw = find_middleware()
    assert mw.limiter.max_keys == 3 and mw.monitor_limiter.max_keys == 3

    # POST /monitor: 3 claves propias; las 3 siguientes comparten el cubo (5 en total).
    for ip in ips[:3]:
        assert post(client_for(ip)).status_code == 201
    shared = [post(client_for(ip)).status_code for ip in ips[3:] for _ in range(3)]
    assert shared.count(201) == 5 and shared.count(429) == 4
    assert len(mw.monitor_limiter._requests) == 4  # 3 + cubo de respaldo
    # Los ya registrados conservan su cuota (1 usada de 5).
    assert [post(client_for(ips[0])).status_code for _ in range(4)] == [201] * 4

    # /analyze/: mismo comportamiento (30 compartidas entre claves nuevas).
    for ip in ips[:3]:
        assert client_for(ip).get("/analyze/example.com").status_code == 200
    extra = [client_for(ip).get("/analyze/example.com").status_code for ip in ips[3:] for _ in range(15)]
    assert extra.count(200) == 30 and extra.count(429) == 15
    assert len(mw.limiter._requests) == 4
