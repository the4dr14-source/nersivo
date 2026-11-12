"""R1 contra un Postgres REAL: los topes se respetan con concurrencia.

Complementa a test_monitor_postgres.py (mismos requisitos): se omite salvo que
`NERSIVO_TEST_POSTGRES_URL` apunte a una base de datos de PRUEBAS (se vacían las
tablas `monitors` y `monitor_events`) y `psycopg` esté instalado. Es el motor que
usa producción, mientras que el resto de pruebas de concurrencia usan SQLite.

    NERSIVO_TEST_POSTGRES_URL=postgresql://user:pass@localhost/nersivo_test \\
        pytest backend/tests/test_monitor_postgres_concurrency.py
"""

import os
import threading

import pytest

from backend.monitoring.config import MonitorSettings
from backend.monitoring.repository import repository_from_url
from backend.monitoring.service import MonitorLimitError, MonitorService
from backend.tests.monitor_helpers import analysis
from backend.tests.test_monitor_service_lifecycle import PausedInsert
from backend.tests.test_monitor_activation_limits import join_all

URL = os.environ.get("NERSIVO_TEST_POSTGRES_URL")
pytestmark = pytest.mark.skipif(not URL, reason="NERSIVO_TEST_POSTGRES_URL no definida")


def make(**settings):
    """Un servicio sobre un repositorio NUEVO (como hace `get_service()` tras un reset)."""
    repo = repository_from_url(URL)
    repo.init_schema()
    cfg = MonitorSettings(max_concurrent_activations=64, **settings)
    return MonitorService(repo, cfg, analyzer=analysis)


@pytest.fixture(autouse=True)
def clean_tables():
    pytest.importorskip("psycopg")
    repo = repository_from_url(URL)
    repo.init_schema()
    with repo._cursor() as cur:
        cur.execute("DELETE FROM monitor_events")
        cur.execute("DELETE FROM monitors")


def run_all(calls):
    outcomes, guard = [], threading.Lock()

    def work(call):
        try:
            call()
            result = "ok"
        except MonitorLimitError as exc:
            result = exc.code
        with guard:
            outcomes.append(result)

    threads = [threading.Thread(target=work, args=(c,)) for c in calls]
    for t in threads:
        t.start()
    join_all(threads)
    return outcomes


def test_pg_30_activaciones_simultaneas_respetan_el_tope_por_dominio():
    service = make(max_per_domain=3)
    outcomes = run_all([lambda: service.activate("mismo.example.com")] * 30)
    assert outcomes.count("ok") == 3, outcomes
    assert outcomes.count("monitor_domain_limit_reached") == 27, outcomes
    assert service.repo.count_active_for_domain("mismo.example.com") == 3


def test_pg_30_activaciones_simultaneas_respetan_el_tope_global():
    service = make(max_active=5)
    outcomes = run_all([lambda i=i: service.activate(f"d{i}.example.com") for i in range(30)])
    assert outcomes.count("ok") == 5, outcomes
    assert outcomes.count("monitor_capacity_reached") == 25, outcomes
    assert service.repo.count_active() == 5


@pytest.mark.parametrize(
    "settings,domains,expected",
    [
        ({"max_per_domain": 1}, ("carrera.example.com",) * 2, "monitor_domain_limit_reached"),
        ({"max_active": 1}, ("uno.example.com", "dos.example.com"), "monitor_capacity_reached"),
    ],
)
def test_pg_dos_instancias_con_repositorios_distintos_no_superan_los_topes(
    settings, domains, expected
):
    first, second = make(**settings), make(**settings)
    PausedInsert(first.repo, second.repo)
    outcomes = run_all(
        [lambda: first.activate(domains[0]), lambda: second.activate(domains[1])]
    )
    assert first.repo.count_active() == 1, outcomes
    assert sorted(outcomes) == sorted(["ok", expected]), outcomes
