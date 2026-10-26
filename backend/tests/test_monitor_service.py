"""Tests del servicio de monitorización y del repositorio (SQLite temporal, sin red)."""

import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from backend.monitoring.config import MonitorSettings
from backend.monitoring.repository import (
    SqlRepository, repository_from_url, to_iso,
)
from backend.monitoring.service import MonitorLimitError, MonitorService, hash_token
from backend.tests.monitor_helpers import analysis, check

T0 = datetime(2026, 10, 7, 10, 0, 0, tzinfo=timezone.utc)


class FakeClock:
    def __init__(self, now=T0):
        self.now = now

    def __call__(self):
        return self.now

    def advance(self, **kwargs):
        self.now += timedelta(**kwargs)


class FakeAnalyzer:
    """Devuelve análisis encolados por dominio (o el último) y registra llamadas."""

    def __init__(self, default=None):
        self.calls = []
        self.queue = []
        self.default = default if default is not None else analysis()
        self.fail = False

    def push(self, a):
        self.queue.append(a)

    def __call__(self, domain):
        self.calls.append(domain)
        if self.fail:
            raise RuntimeError("fallo del análisis")
        return self.queue.pop(0) if self.queue else self.default


class RecordingNotifier:
    def __init__(self, raises=False):
        self.sent = []
        self.raises = raises

    def notify(self, monitor, events):
        if self.raises:
            raise RuntimeError("fallo al notificar")
        self.sent.append((monitor.domain, [e.kind for e in events]))


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "monitor.sqlite3")


@pytest.fixture
def repo(db_path):
    r = repository_from_url(f"sqlite:///{db_path}")
    r.init_schema()
    return r


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def analyzer():
    return FakeAnalyzer()


@pytest.fixture
def notifier():
    return RecordingNotifier()


@pytest.fixture
def service(repo, clock, analyzer, notifier):
    return MonitorService(repo, MonitorSettings(), analyzer=analyzer, notifier=notifier, clock=clock)


BAD_SPF = analysis(spf=check("spf", "warning", "missing_spf", records=[], found=False), score=80)


# ================================================================= activación
def test_activar_hace_primer_analisis_y_no_genera_eventos(service, analyzer):
    token, view = service.activate("Example.com")
    assert analyzer.calls == ["example.com"]
    assert view["status"] == "active" and view["domain"] == "example.com"
    assert view["last_checked_at"] == "2026-10-07T10:00:00Z"
    assert view["next_check_at"] == "2026-10-08T10:00:00Z"
    assert view["current_status"] == "ok" and view["current_score"] == 90
    assert view["last_changes"] == [] and view["recent_events"] == []
    assert len(token) >= 40


def test_el_token_no_se_guarda_en_claro(service, db_path):
    token, _ = service.activate("example.com")
    raw = sqlite3.connect(db_path)
    dump = " ".join(str(v) for row in raw.execute("SELECT * FROM monitors") for v in row)
    assert token not in dump and hash_token(token) in dump
    assert token not in str(service.status(token))  # la vista tampoco lo incluye


def test_activar_guarda_score_null_y_unknown_sin_inventar(service):
    unknown = analysis(score=None, global_status="unknown", spf=check("spf", "unknown", "timeout"))
    service._analyze = lambda d: unknown
    _, view = service.activate("example.com")
    assert view["current_score"] is None and view["current_status"] == "unknown"


@pytest.mark.parametrize("bad", ["localhost", "127.0.0.1", "10.0.0.1", "169.254.169.254", "192.168.1.1",
                                 "http://example.com", "example", "user@example.com", "a b.com", "", "::1",
                                 "example.com/ruta", "example.com:8080"])
def test_ssrf_dominios_no_validos_nunca_se_analizan(service, analyzer, bad):
    with pytest.raises(ValueError):
        service.activate(bad)
    assert analyzer.calls == [] and service.repo.count_active() == 0


def test_limite_por_dominio(service):
    for _ in range(3):
        service.activate("example.com")
    with pytest.raises(MonitorLimitError) as exc:
        service.activate("example.com")
    assert exc.value.code == "monitor_domain_limit_reached"
    service.activate("otro.com")  # otro dominio sigue permitido


def test_limite_global(repo, clock, analyzer):
    svc = MonitorService(repo, MonitorSettings(max_active=2), analyzer=analyzer, clock=clock)
    svc.activate("a.com"); svc.activate("b.com")
    with pytest.raises(MonitorLimitError) as exc:
        svc.activate("c.com")
    assert exc.value.code == "monitor_capacity_reached"


def test_desactivar_libera_cupo(repo, clock, analyzer):
    svc = MonitorService(repo, MonitorSettings(max_per_domain=1), analyzer=analyzer, clock=clock)
    token, _ = svc.activate("example.com")
    svc.deactivate(token)
    svc.activate("example.com")


# ============================================================ estado / desactivar
@pytest.mark.parametrize("token", ["", "nope", "x" * 500, None])
def test_token_inexistente(service, token):
    assert service.status(token) is None and service.deactivate(token) is None


def test_estado_tras_activar(service):
    token, view = service.activate("example.com")
    assert service.status(token) == view


def test_desactivar_es_idempotente_y_oculta_proxima_comprobacion(service, clock):
    token, _ = service.activate("example.com")
    clock.advance(hours=1)
    first = service.deactivate(token)
    assert first["status"] == "disabled" and first["next_check_at"] is None
    assert service.deactivate(token)["status"] == "disabled"
    assert service.status(token)["status"] == "disabled"


def test_un_monitor_desactivado_no_se_comprueba(service, clock, analyzer):
    token, _ = service.activate("example.com")
    service.deactivate(token)
    analyzer.calls.clear()
    clock.advance(days=3)
    summary = service.run_due()
    assert summary.claimed == 0 and analyzer.calls == []


# ======================================================================== job
def test_nada_vencido_no_hace_nada(service, analyzer):
    service.activate("example.com")
    analyzer.calls.clear()
    assert service.run_due().to_dict() == {
        "claimed": 0, "checked": 0, "with_changes": 0, "events": 0, "failed": 0, "skipped_for_time": 0,
    }
    assert analyzer.calls == []


def test_comprobacion_sin_cambios(service, clock, analyzer, notifier):
    token, _ = service.activate("example.com")
    clock.advance(hours=25)
    s = service.run_due()
    assert (s.claimed, s.checked, s.with_changes, s.events) == (1, 1, 0, 0)
    view = service.status(token)
    assert view["last_checked_at"] == "2026-10-08T11:00:00Z"
    assert view["next_check_at"] == "2026-10-09T11:00:00Z"
    assert view["recent_events"] == [] and notifier.sent == []


def test_comprobacion_con_cambios_guarda_eventos_y_notifica(service, clock, analyzer, notifier):
    token, _ = service.activate("example.com")
    analyzer.push(BAD_SPF)
    clock.advance(hours=25)
    s = service.run_due()
    assert (s.checked, s.with_changes, s.events) == (1, 1, 2)  # problema SPF + score 90->80
    view = service.status(token)
    kinds = sorted(e["kind"] for e in view["recent_events"])
    assert kinds == ["new_problem", "score_change"]
    assert view["current_score"] == 80 and view["current_status"] == "ok"
    assert {c["check"] for c in view["last_changes"]} == {"spf", None}
    assert notifier.sent == [("example.com", ["new_problem", "score_change"])]


def test_segunda_comprobacion_igual_no_duplica_eventos(service, clock, analyzer):
    token, _ = service.activate("example.com")
    analyzer.default = BAD_SPF
    for _ in range(3):
        clock.advance(hours=25)
        service.run_due()
    view = service.status(token)
    assert len(view["recent_events"]) == 2  # solo los del primer cambio
    assert len(view["last_changes"]) == 2  # el último aviso conocido se conserva


def test_problema_resuelto_genera_evento(service, clock, analyzer):
    analyzer.default = BAD_SPF
    token, _ = service.activate("example.com")
    analyzer.default = analysis()
    clock.advance(hours=25)
    service.run_due()
    assert "resolved_problem" in {e["kind"] for e in service.status(token)["recent_events"]}


def test_unknown_no_genera_eventos_y_no_borra_el_ultimo_estado_conocido(service, clock, analyzer):
    token, _ = service.activate("example.com")
    analyzer.default = analysis(score=None, global_status="unknown", spf=check("spf", "unknown", "timeout"),
                                dmarc=check("dmarc", "unknown", "timeout"))
    clock.advance(hours=25)
    service.run_due()
    view = service.status(token)
    assert view["recent_events"] == [] and view["current_score"] is None
    # El problema aparece justo después del unknown: no se pierde.
    analyzer.default = BAD_SPF
    clock.advance(hours=25)
    service.run_due()
    assert "new_problem" in {e["kind"] for e in service.status(token)["recent_events"]}


def test_score_null_se_mantiene_null(service, clock, analyzer):
    analyzer.default = analysis(score=None, global_status="unknown")
    token, _ = service.activate("example.com")
    clock.advance(hours=25)
    service.run_due()
    assert service.status(token)["current_score"] is None


def test_resultado_anterior_y_actual_se_conservan(service, clock, analyzer, repo):
    token, _ = service.activate("example.com")
    analyzer.default = BAD_SPF
    clock.advance(hours=25)
    service.run_due()
    record = repo.get_by_token_hash(hash_token(token))
    assert record.previous_fp["score"] == 90 and record.current_fp["score"] == 80
    assert record.baseline_fp["checks"]["spf"]["status"] == "warning"


def test_fallo_del_analisis_reintenta_en_una_hora_y_no_detiene_el_job(repo, clock):
    fake = FakeAnalyzer()
    svc = MonitorService(repo, MonitorSettings(), analyzer=fake, clock=clock)
    t1, _ = svc.activate("uno.com")
    t2, _ = svc.activate("dos.com")
    clock.advance(hours=25)
    original = fake.__call__

    def flaky(domain):
        if domain == "uno.com":
            raise RuntimeError("boom")
        return analysis(domain)

    svc._analyze = flaky
    s = svc.run_due()
    assert (s.claimed, s.checked, s.failed) == (2, 1, 1)
    rec = repo.get_by_token_hash(hash_token(t1))
    assert rec.consecutive_failures == 1 and rec.next_check_at == to_iso(clock.now + timedelta(hours=1))
    assert svc.status(t1)["status"] == "active"
    svc._analyze = original
    clock.advance(hours=2)
    assert svc.run_due().checked == 1
    assert repo.get_by_token_hash(hash_token(t1)).consecutive_failures == 0


def test_fallo_del_notificador_no_rompe_la_comprobacion(repo, clock, analyzer):
    svc = MonitorService(repo, MonitorSettings(), analyzer=analyzer, notifier=RecordingNotifier(raises=True), clock=clock)
    token, _ = svc.activate("example.com")
    analyzer.default = BAD_SPF
    clock.advance(hours=25)
    assert svc.run_due().checked == 1
    assert svc.status(token)["recent_events"]


def test_limite_de_lote(repo, clock, analyzer):
    svc = MonitorService(repo, MonitorSettings(run_batch=2), analyzer=analyzer, clock=clock)
    for d in ("a.com", "b.com", "c.com", "d.com"):
        svc.activate(d)
    clock.advance(hours=25)
    assert svc.run_due().checked == 2
    assert svc.run_due().checked == 2  # los otros dos, en la siguiente llamada
    assert svc.run_due().claimed == 0


def test_presupuesto_de_tiempo_deja_el_resto_para_la_siguiente(repo, clock, analyzer):
    ticks = iter([0, 0, 100, 100, 100, 100])  # el primer análisis agota el presupuesto
    svc = MonitorService(repo, MonitorSettings(), analyzer=analyzer, clock=clock, monotonic=lambda: next(ticks))
    for d in ("a.com", "b.com", "c.com"):
        svc.activate(d)
    clock.advance(hours=25)
    s = svc.run_due(budget_seconds=50)
    assert (s.claimed, s.checked, s.skipped_for_time) == (3, 1, 2)
    clock.advance(minutes=16)  # caduca el "reclamo" de los pendientes
    assert svc.run_due().claimed == 2


def test_dos_ejecuciones_solapadas_no_procesan_el_mismo_monitor(service, clock, repo):
    service.activate("example.com")
    clock.advance(hours=25)
    first = repo.claim_due(clock.now, 10, clock.now + timedelta(minutes=15))
    second = repo.claim_due(clock.now, 10, clock.now + timedelta(minutes=15))
    assert len(first) == 1 and second == []


def test_dominio_manipulado_en_la_base_no_se_analiza(service, clock, analyzer, repo, db_path):
    token, _ = service.activate("example.com")
    raw = sqlite3.connect(db_path)
    raw.execute("UPDATE monitors SET domain = 'localhost'")
    raw.commit()
    analyzer.calls.clear()
    clock.advance(hours=25)
    s = service.run_due()
    assert s.failed == 1 and analyzer.calls == []


def test_varios_cambios_de_estado_en_distintos_checks(service, clock, analyzer):
    token, _ = service.activate("example.com")
    analyzer.default = analysis(
        score=60,
        https=check("https", "error", "certificate_expired"),
        mx=check("mx", records=[{"priority": 1, "hostname": "otro.mx.com", "resolves": True}]),
    )
    clock.advance(hours=25)
    service.run_due()
    events = {(e["check"], e["kind"]) for e in service.status(token)["recent_events"]}
    assert events == {("https", "new_problem"), ("mx", "config_change"), (None, "score_change")}


# ================================================================= repositorio
def test_repository_from_url_errores():
    with pytest.raises(ValueError):
        repository_from_url("mysql://x")
    with pytest.raises(ValueError):
        repository_from_url("sqlite:///:memory:")
    with pytest.raises(ValueError):
        repository_from_url("")


def test_postgres_se_crea_sin_importar_psycopg_hasta_usarlo():
    repo = repository_from_url("postgresql://user:pw@localhost/db")
    assert isinstance(repo, SqlRepository) and repo._placeholder == "%s"
    assert repository_from_url("postgres://u:p@h/db")._placeholder == "%s"


def test_traduccion_de_marcadores_para_postgres():
    repo = SqlRepository(lambda: None, "%s")
    assert repo._sql("SELECT * FROM t WHERE a = ? AND b = ?") == "SELECT * FROM t WHERE a = %s AND b = %s"
    assert SqlRepository(lambda: None, "?")._sql("a = ?") == "a = ?"


def test_init_schema_es_idempotente(repo):
    repo.init_schema(); repo.init_schema()


def test_configuracion_desde_entorno():
    s = MonitorSettings.from_env({
        "NERSIVO_DATABASE_URL": " postgresql://x ", "NERSIVO_CRON_TOKEN": " secreto ",
        "NERSIVO_MONITOR_INTERVAL_HOURS": "6", "NERSIVO_MONITOR_MAX_ACTIVE": "abc",
        "NERSIVO_MONITOR_RUN_BATCH": "0",
    })
    assert s.database_url == "postgresql://x" and s.cron_token == "secreto"
    assert s.interval_hours == 6 and s.max_active == 200 and s.run_batch == 1
    d = MonitorSettings.from_env({})
    assert d.cron_token is None and d.database_url.startswith("sqlite:///")


def test_integracion_con_el_analizador_real(repo, clock, monkeypatch):
    """El servicio usa `analyze_domain` real (6 checks), no una copia de su lógica."""
    from backend import analyzer as real
    from backend.models import Status
    from backend.tests.helpers import make_check

    for n in ("web", "https", "dns", "mx", "spf", "dmarc"):
        monkeypatch.setattr(real, f"check_{n}", lambda d, s=Status.UNKNOWN: make_check(s))
    svc = MonitorService(repo, MonitorSettings(), clock=clock)
    token, view = svc.activate("example.com")
    assert view["current_status"] == "unknown" and view["current_score"] is None
