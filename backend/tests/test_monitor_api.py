"""Tests de la API de monitorización (`/monitor`, `/internal/monitor/run`)."""

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from backend import main
from backend.monitoring import routes
from backend.monitoring.config import MonitorSettings
from backend.monitoring.repository import repository_from_url
from backend.monitoring.service import MonitorService
from backend.tests.monitor_helpers import analysis, check
from backend.tests.test_monitor_service import BAD_SPF, FakeAnalyzer, FakeClock

client = TestClient(main.app)
HDR = "X-Monitor-Token"


@pytest.fixture
def env(tmp_path, monkeypatch):
    """Servicio real sobre SQLite temporal, inyectado en las rutas."""
    clock, analyzer = FakeClock(), FakeAnalyzer()
    repo = repository_from_url(f"sqlite:///{tmp_path / 'm.db'}")
    repo.init_schema()
    service = MonitorService(repo, MonitorSettings(), analyzer=analyzer, clock=clock)
    monkeypatch.setattr(routes, "_service", service)
    monkeypatch.delenv("NERSIVO_CRON_TOKEN", raising=False)
    yield type("Env", (), {"service": service, "clock": clock, "analyzer": analyzer})
    routes.reset_service()


def activate(domain="example.com"):
    return client.post("/monitor", json={"domain": domain})


# ------------------------------------------------------------------ activar
def test_activar_devuelve_token_y_estado(env):
    r = activate("Example.com")
    assert r.status_code == 201
    body = r.json()
    assert set(body) == {"token", "monitor"} and len(body["token"]) >= 40
    m = body["monitor"]
    assert m["status"] == "active" and m["domain"] == "example.com"
    assert m["last_checked_at"] and m["next_check_at"] and m["recent_events"] == []
    assert "token" not in m


@pytest.mark.parametrize("bad", ["localhost", "127.0.0.1", "169.254.169.254", "10.0.0.5", "http://evil.com", "a@b.com", "x"])
def test_activar_rechaza_dominios_internos_o_invalidos(env, bad):
    r = activate(bad)
    assert r.status_code == 400
    assert env.analyzer.calls == []  # SSRF: nunca se llega a analizar


@pytest.mark.parametrize("body", [{}, {"domain": 5}, [], {"dominio": "example.com"}])
def test_activar_cuerpo_invalido(env, body):
    assert client.post("/monitor", json=body).status_code == 422


def test_activar_limite_devuelve_429(env):
    for _ in range(3):
        assert activate().status_code == 201
    r = activate()
    assert r.status_code == 429 and r.json()["detail"] == "monitor_domain_limit_reached"


# ---------------------------------------------------------------- estado
def test_estado_con_token(env):
    token = activate().json()["token"]
    r = client.get("/monitor", headers={HDR: token})
    assert r.status_code == 200 and r.json()["status"] == "active"


def test_estado_sin_token_o_con_token_incorrecto(env):
    activate()
    assert client.get("/monitor").status_code == 401
    assert client.get("/monitor", headers={HDR: ""}).status_code == 401
    assert client.get("/monitor", headers={HDR: "incorrecto"}).status_code == 404


def test_el_token_no_viaja_en_la_url(env):
    token = activate().json()["token"]
    assert client.get(f"/monitor/{token}").status_code in (404, 405)


# ------------------------------------------------------------- desactivar
def test_desactivar_y_consultar(env):
    token = activate().json()["token"]
    r = client.delete("/monitor", headers={HDR: token})
    assert r.status_code == 200 and r.json()["status"] == "disabled" and r.json()["next_check_at"] is None
    assert client.get("/monitor", headers={HDR: token}).json()["status"] == "disabled"
    assert client.delete("/monitor", headers={HDR: token}).status_code == 200  # idempotente


def test_desactivar_token_inexistente(env):
    assert client.delete("/monitor", headers={HDR: "nada"}).status_code == 404
    assert client.delete("/monitor").status_code == 401


# --------------------------------------------------------------- cron / job
def test_job_deshabilitado_sin_cron_token(env):
    assert client.post("/internal/monitor/run", headers={"X-Cron-Token": "x"}).status_code == 404


def test_job_rechaza_token_ausente_o_incorrecto(env, monkeypatch):
    monkeypatch.setenv("NERSIVO_CRON_TOKEN", "secreto")
    assert client.post("/internal/monitor/run").status_code == 403
    assert client.post("/internal/monitor/run", headers={"X-Cron-Token": "otro"}).status_code == 403
    assert client.post("/internal/monitor/run", headers={"X-Cron-Token": "secreto "}).status_code == 403


def test_job_ejecuta_comprobaciones_vencidas_y_se_ve_en_el_estado(env, monkeypatch):
    monkeypatch.setenv("NERSIVO_CRON_TOKEN", "secreto")
    token = activate().json()["token"]
    env.analyzer.default = BAD_SPF
    env.clock.advance(hours=25)
    r = client.post("/internal/monitor/run", headers={"X-Cron-Token": "secreto"})
    assert r.status_code == 200
    assert r.json() == {"claimed": 1, "checked": 1, "with_changes": 1, "events": 2, "failed": 0, "skipped_for_time": 0}
    view = client.get("/monitor", headers={HDR: token}).json()
    assert {e["kind"] for e in view["recent_events"]} == {"new_problem", "score_change"}
    again = client.post("/internal/monitor/run", headers={"X-Cron-Token": "secreto"}).json()
    assert again["claimed"] == 0


def test_job_no_acepta_el_token_de_cron_en_la_url(env, monkeypatch):
    monkeypatch.setenv("NERSIVO_CRON_TOKEN", "secreto")
    assert client.post("/internal/monitor/run?token=secreto").status_code == 403


# ------------------------------------------------------- disponibilidad / CORS
def test_base_de_datos_no_disponible_solo_afecta_a_la_monitorizacion(tmp_path, monkeypatch):
    routes.reset_service()
    monkeypatch.setenv("NERSIVO_DATABASE_URL", f"sqlite:///{tmp_path}/no/existe/dir/x.db")
    assert activate().status_code == 503
    assert activate().json()["detail"] == "monitoring_unavailable"
    assert client.get("/monitor", headers={HDR: "x"}).status_code == 503
    assert client.get("/").status_code == 200
    assert client.post("/guides", json=analysis().model_dump(mode="json")).status_code == 200
    routes.reset_service()


def test_url_de_base_de_datos_no_soportada(monkeypatch):
    routes.reset_service()
    monkeypatch.setenv("NERSIVO_DATABASE_URL", "mysql://x")
    assert activate().status_code == 503
    routes.reset_service()


def test_cors_permite_delete_y_cabecera_del_token(env):
    r = client.options("/monitor", headers={
        "Origin": "https://nersivo-frontend.onrender.com", "Access-Control-Request-Method": "DELETE",
        "Access-Control-Request-Headers": "x-monitor-token",
    })
    assert r.status_code == 200
    assert r.headers["access-control-allow-origin"] == "https://nersivo-frontend.onrender.com"
    assert "DELETE" in r.headers["access-control-allow-methods"]
    assert "x-monitor-token" in r.headers["access-control-allow-headers"].lower()


def test_analyze_sigue_sin_depender_de_la_base_de_datos(monkeypatch):
    from backend import analyzer
    from backend.models import Status
    from backend.tests.helpers import make_check

    routes.reset_service()
    monkeypatch.setenv("NERSIVO_DATABASE_URL", "mysql://roto")
    for n in ("web", "https", "dns", "mx", "spf", "dmarc"):
        monkeypatch.setattr(analyzer, f"check_{n}", lambda d: make_check(Status.OK))
    assert client.get("/analyze/example.com").status_code == 200
