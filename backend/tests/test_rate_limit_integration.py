"""
Tests de integración del rate limiter y de CORS sobre la aplicación REAL
(`backend.main.app`), no sobre la clase aislada.

Los 6 checks se sustituyen por resultados fijos: no hay red real.

Qué se demuestra aquí (y por qué el test unitario de `InMemoryRateLimiter` no
bastaba): que `AnalyzeRateLimitMiddleware` está REGISTRADO en la app, que
`/analyze/{domain}` devuelve 429 al superar el límite, que ese 429 lleva
`Retry-After` y cabeceras CORS, y que `/health`, `/guides` y los preflight
OPTIONS no consumen cuota.

No se asume nada sobre la IP real que recibe el backend detrás de Render: el
TestClient usa un `client.host` sintético y aquí solo se comprueba la lógica.
"""

import pytest
from fastapi.testclient import TestClient

from backend import analyzer, main
from backend.models import Status
from backend.rate_limit import AnalyzeRateLimitMiddleware
from backend.tests.helpers import make_check

OFFICIAL_ORIGIN = "https://nersivo-frontend.onrender.com"
LOCAL_ORIGINS = [
    "http://localhost:5500",
    "http://127.0.0.1:5500",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]
LIMIT = 30  # 30 peticiones / 60 s (valores por defecto de rate_limit.py)

client = TestClient(main.app)


@pytest.fixture(autouse=True)
def fake_checks(monkeypatch):
    """Los 6 checks devuelven OK sin tocar la red."""
    for name in ("web", "https", "dns", "mx", "spf", "dmarc"):
        monkeypatch.setattr(analyzer, f"check_{name}", lambda d: make_check(Status.OK))


def find_limiter(app) -> AnalyzeRateLimitMiddleware:
    """
    Localiza la instancia REAL de `AnalyzeRateLimitMiddleware` dentro de la
    pila de middlewares ya construida. Falla si no está registrada.
    """
    layer = app.middleware_stack
    assert layer is not None, "la pila de middlewares aún no se ha construido"
    while layer is not None:
        if isinstance(layer, AnalyzeRateLimitMiddleware):
            return layer
        layer = getattr(layer, "app", None)
    pytest.fail("AnalyzeRateLimitMiddleware NO está registrado en main.app")


def exhaust_analyze_quota(c=client):
    for i in range(LIMIT):
        r = c.get("/analyze/example.com")
        assert r.status_code == 200, f"la petición {i + 1} debería ser 200"


# ---------------------------------------------------------------- registro
def test_el_limitador_esta_registrado_en_la_app_con_30_por_60s():
    assert client.get("/health").status_code == 200  # construye la pila
    limiter = find_limiter(main.app).limiter
    assert limiter.max_requests == 30
    assert limiter.window_seconds == 60


def test_cors_envuelve_al_limitador_orden_de_middlewares():
    """CORS debe ser más externo que el limitador para que el 429 lleve CORS."""
    from starlette.middleware.cors import CORSMiddleware

    assert client.get("/health").status_code == 200
    order = []
    layer = main.app.middleware_stack
    while layer is not None:
        order.append(type(layer))
        layer = getattr(layer, "app", None)
    assert order.index(CORSMiddleware) < order.index(AnalyzeRateLimitMiddleware)


# --------------------------------------------------------------------- 429
def test_analyze_devuelve_429_al_superar_el_limite_con_retry_after():
    exhaust_analyze_quota()
    r = client.get("/analyze/example.com")
    assert r.status_code == 429
    assert "Demasiadas solicitudes" in r.json()["detail"]
    retry_after = r.headers["retry-after"]
    assert retry_after.isdigit()
    assert 1 <= int(retry_after) <= 60


def test_el_429_incluye_cabeceras_cors_para_el_origen_oficial():
    exhaust_analyze_quota()
    r = client.get("/analyze/example.com", headers={"Origin": OFFICIAL_ORIGIN})
    assert r.status_code == 429
    assert r.headers["access-control-allow-origin"] == OFFICIAL_ORIGIN
    assert "retry-after" in r.headers


@pytest.mark.parametrize("origin", LOCAL_ORIGINS)
def test_el_429_incluye_cabeceras_cors_para_origenes_locales(origin):
    exhaust_analyze_quota()
    r = client.get("/analyze/example.com", headers={"Origin": origin})
    assert r.status_code == 429
    assert r.headers["access-control-allow-origin"] == origin


def test_el_429_no_da_cors_a_un_origen_no_permitido():
    exhaust_analyze_quota()
    r = client.get("/analyze/example.com", headers={"Origin": "https://evil.example"})
    assert r.status_code == 429
    assert "access-control-allow-origin" not in r.headers


def test_las_peticiones_bloqueadas_no_amplian_la_ventana():
    """Los 429 no se anotan: el contador se mantiene en el máximo."""
    exhaust_analyze_quota()
    for _ in range(5):
        assert client.get("/analyze/example.com").status_code == 429
    limiter = find_limiter(main.app).limiter
    assert all(len(q) == LIMIT for q in limiter._requests.values())


def test_el_limite_es_por_cliente_no_global():
    exhaust_analyze_quota()
    assert client.get("/analyze/example.com").status_code == 429
    other = TestClient(main.app, client=("203.0.113.7", 50000))
    assert other.get("/analyze/example.com").status_code == 200


def test_otros_endpoints_siguen_disponibles_con_analyze_limitado():
    exhaust_analyze_quota()
    assert client.get("/analyze/example.com").status_code == 429
    assert client.get("/health").status_code == 200
    assert client.get("/").status_code == 200


# ---------------------------------------- lo que NO debe consumir cuota
def test_health_guides_y_options_no_consumen_cuota():
    assert client.get("/health").status_code == 200  # construye la pila
    limiter = find_limiter(main.app).limiter

    for _ in range(LIMIT * 2):
        assert client.get("/health").status_code == 200
        assert client.get("/").status_code == 200
        # Preflight de /analyze: es OPTIONS y lo atiende CORSMiddleware.
        pre = client.options(
            "/analyze/example.com",
            headers={
                "Origin": OFFICIAL_ORIGIN,
                "Access-Control-Request-Method": "GET",
            },
        )
        assert pre.status_code == 200
        # /guides (cuerpo vacío -> 422 de validación; el limitador ni lo mira).
        assert client.post("/guides", json={}).status_code == 422
        assert client.options(
            "/guides",
            headers={
                "Origin": OFFICIAL_ORIGIN,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type",
            },
        ).status_code == 200

    # Ninguna de esas peticiones ha creado ni incrementado contadores...
    assert dict(limiter._requests) == {}
    # ...y la cuota de /analyze sigue completa: 30 OK y la 31 bloqueada.
    exhaust_analyze_quota()
    assert client.get("/analyze/example.com").status_code == 429


# --------------------------------------------- reinicio de estado entre tests
def test_poner_middleware_stack_a_none_reinicia_realmente_los_contadores():
    """
    No se da por supuesto que `middleware_stack = None` reinicie el estado:
    se agota la cuota, se reinicia y se comprueba (a) que el limitador es otra
    instancia, (b) que sus contadores están vacíos y (c) que /analyze vuelve a
    responder 200 con la cuota completa.
    """
    exhaust_analyze_quota()
    assert client.get("/analyze/example.com").status_code == 429
    old_limiter = find_limiter(main.app).limiter
    assert len(old_limiter._requests) == 1

    main.app.middleware_stack = None  # lo mismo que hace la fixture autouse

    assert client.get("/health").status_code == 200  # reconstruye la pila
    new_limiter = find_limiter(main.app).limiter
    assert new_limiter is not old_limiter
    assert dict(new_limiter._requests) == {}
    exhaust_analyze_quota()
    assert client.get("/analyze/example.com").status_code == 429


def test_la_fixture_autouse_deja_cada_test_con_cuota_completa_a():
    """Primera mitad de la pareja: consume toda la cuota."""
    exhaust_analyze_quota()


def test_la_fixture_autouse_deja_cada_test_con_cuota_completa_b():
    """Segunda mitad: si el estado se filtrara, esto daría 429."""
    exhaust_analyze_quota()


# --------------------------------------------------------------- CORS (cfg)
@pytest.mark.parametrize("origin", [OFFICIAL_ORIGIN] + LOCAL_ORIGINS)
def test_cors_origen_permitido_se_devuelve_literal_sin_credenciales(origin):
    r = client.get("/health", headers={"Origin": origin})
    assert r.headers["access-control-allow-origin"] == origin
    assert r.headers["access-control-allow-origin"] != "*"
    assert "access-control-allow-credentials" not in r.headers


@pytest.mark.parametrize(
    "origin",
    [
        "https://evil.example",
        "http://localhost:8000",
        "http://localhost",
        "https://nersivo-frontend.onrender.com.evil.example",
        "http://nersivo-frontend.onrender.com",
        "null",
    ],
)
def test_cors_origen_no_permitido_no_recibe_cabecera(origin):
    r = client.get("/health", headers={"Origin": origin})
    assert "access-control-allow-origin" not in r.headers


def test_cors_no_usa_comodines():
    assert "*" not in main.ALLOWED_ORIGINS
    assert main.ALLOWED_ORIGINS == [OFFICIAL_ORIGIN] + [
        o for o in main.ALLOWED_ORIGINS if o != OFFICIAL_ORIGIN
    ]
    assert set(main.ALLOWED_ORIGINS) == {OFFICIAL_ORIGIN, *LOCAL_ORIGINS}


@pytest.mark.parametrize(
    "method,path",
    [("GET", "/analyze/example.com"), ("POST", "/monitor"), ("DELETE", "/monitor")],
)
def test_preflight_permite_metodos_y_cabeceras_del_frontend(method, path):
    r = client.options(
        path,
        headers={
            "Origin": OFFICIAL_ORIGIN,
            "Access-Control-Request-Method": method,
            "Access-Control-Request-Headers": "content-type, x-monitor-token",
        },
    )
    assert r.status_code == 200
    assert r.headers["access-control-allow-origin"] == OFFICIAL_ORIGIN
    allowed_methods = {m.strip() for m in r.headers["access-control-allow-methods"].split(",")}
    assert allowed_methods == {"GET", "POST", "DELETE"}
    allowed_headers = {h.strip().lower() for h in r.headers["access-control-allow-headers"].split(",")}
    assert {"content-type", "x-monitor-token"} <= allowed_headers
    assert "access-control-allow-credentials" not in r.headers


def test_preflight_no_expone_x_cron_token_al_navegador():
    r = client.options(
        "/internal/monitor/run",
        headers={
            "Origin": OFFICIAL_ORIGIN,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "x-cron-token",
        },
    )
    assert r.status_code == 400
    assert "x-cron-token" not in r.headers.get("access-control-allow-headers", "").lower()


@pytest.mark.parametrize("method", ["PUT", "PATCH", "DELETE_ALL"])
def test_preflight_rechaza_metodos_no_permitidos(method):
    r = client.options(
        "/monitor",
        headers={"Origin": OFFICIAL_ORIGIN, "Access-Control-Request-Method": method},
    )
    assert r.status_code == 400


def test_preflight_rechaza_origen_no_permitido():
    r = client.options(
        "/analyze/example.com",
        headers={
            "Origin": "https://evil.example",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert r.status_code == 400
    assert "access-control-allow-origin" not in r.headers
