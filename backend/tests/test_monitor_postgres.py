"""
Los mismos escenarios del servicio contra un Postgres REAL.

Se omiten salvo que `NERSIVO_TEST_POSTGRES_URL` apunte a una base de datos de
PRUEBAS (se vacían las tablas `monitors` y `monitor_events`) y `psycopg` esté
instalado. Ejemplo:

    NERSIVO_TEST_POSTGRES_URL=postgresql://user:pass@localhost/nersivo_test pytest backend/tests/test_monitor_postgres.py
"""

import os
from datetime import timedelta

import pytest

from backend.monitoring.config import MonitorSettings
from backend.monitoring.repository import repository_from_url, to_iso
from backend.monitoring.service import MonitorLimitError, MonitorService, hash_token
from backend.tests.monitor_helpers import analysis, check
from backend.tests.test_monitor_service import BAD_SPF, FakeAnalyzer, FakeClock, RecordingNotifier

URL = os.environ.get("NERSIVO_TEST_POSTGRES_URL")
pytestmark = pytest.mark.skipif(not URL, reason="NERSIVO_TEST_POSTGRES_URL no definida")


@pytest.fixture
def pg():
    pytest.importorskip("psycopg")
    repo = repository_from_url(URL)
    repo.init_schema()
    with repo._cursor() as cur:
        cur.execute("DELETE FROM monitor_events")
        cur.execute("DELETE FROM monitors")
    clock, analyzer, notifier = FakeClock(), FakeAnalyzer(), RecordingNotifier()
    service = MonitorService(repo, MonitorSettings(), analyzer=analyzer, notifier=notifier, clock=clock)
    return type("PG", (), {"repo": repo, "service": service, "clock": clock, "analyzer": analyzer, "notifier": notifier})


def test_pg_esquema_idempotente(pg):
    pg.repo.init_schema(); pg.repo.init_schema()


def test_pg_activar_y_estado(pg):
    token, view = pg.service.activate("Example.com")
    assert view["status"] == "active" and view["next_check_at"] == "2026-10-08T10:00:00Z"
    assert pg.service.status(token) == view
    record = pg.repo.get_by_token_hash(hash_token(token))
    assert record.token_hash != token and record.current_fp["score"] == 90


def test_pg_ciclo_completo_con_cambios_y_eventos(pg):
    token, _ = pg.service.activate("example.com")
    pg.analyzer.default = BAD_SPF
    pg.clock.advance(hours=25)
    s = pg.service.run_due()
    assert (s.checked, s.with_changes, s.events) == (1, 1, 2)
    view = pg.service.status(token)
    assert {e["kind"] for e in view["recent_events"]} == {"new_problem", "score_change"}
    assert "Tu dominio no tiene SPF" in " ".join(e["summary"] for e in view["recent_events"])  # unicode/ñ intacto
    assert pg.notifier.sent
    pg.clock.advance(hours=25)
    assert pg.service.run_due().with_changes == 0  # sin duplicados


def test_pg_reclamo_atomico(pg):
    pg.service.activate("example.com")
    pg.clock.advance(hours=25)
    lease = pg.clock.now + timedelta(minutes=15)
    assert len(pg.repo.claim_due(pg.clock.now, 10, lease)) == 1
    assert pg.repo.claim_due(pg.clock.now, 10, lease) == []


def test_pg_desactivar_limites_y_fallos(pg):
    token, _ = pg.service.activate("example.com")
    assert pg.repo.count_active() == 1 and pg.repo.count_active_for_domain("example.com") == 1
    pg.service.activate("example.com"); pg.service.activate("example.com")
    with pytest.raises(MonitorLimitError):
        pg.service.activate("example.com")
    assert pg.service.deactivate(token)["status"] == "disabled"
    assert pg.repo.count_active() == 2
    pg.analyzer.fail = True
    pg.clock.advance(hours=25)
    assert pg.service.run_due().failed == 2
    rec = pg.repo.claim_due(pg.clock.now + timedelta(hours=2), 10, pg.clock.now + timedelta(hours=3))
    assert rec and rec[0].consecutive_failures == 1
