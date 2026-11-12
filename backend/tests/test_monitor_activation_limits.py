"""Pruebas de A2 - R1 (carrera en los topes) y R2 (activaciones simultáneas).

Todo es local: SQLite temporal y un analizador simulado que se detiene en una
"puerta" controlada por el test, de modo que la concurrencia es determinista y
no depende de tiempos. No se hace ninguna petición de red ni contra Render.

Qué se comprueba:

* R2 - como máximo 4 activaciones (cada una con su análisis) a la vez; las
  rechazadas dan `monitor_busy` con `Retry-After` SIN analizar ni insertar; el
  hueco se libera siempre, también ante excepciones.
* R1 - con activaciones simultáneas no se superan el tope global ni el de
  dominio, y el cerrojo no se mantiene durante el análisis.
* El cron (`run_due`, `/internal/monitor/run`) y `/analyze` no se ven afectados.
"""

import asyncio
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx
import pytest
from fastapi.testclient import TestClient

from backend import main
from backend.monitoring import routes
from backend.monitoring.config import MonitorSettings
from backend.monitoring.repository import repository_from_url
from backend.monitoring.service import (
    BUSY_RETRY_AFTER_SECONDS,
    MonitorBusyError,
    MonitorLimitError,
    MonitorService,
)
from backend.tests.monitor_helpers import analysis

OFFICIAL_ORIGIN = "https://nersivo-frontend.onrender.com"
CRON_TOKEN = "token-de-cron-de-prueba"
WAIT = 10.0


# ------------------------------------------------------------------ utilidades
class GateAnalyzer:
    """Analizador simulado (sin red) que se detiene hasta que el test lo libera.

    * `blocking=None`: todos los dominios esperan a `release`.
    * `blocking={...}`: solo esos dominios esperan; el resto responde al instante.
    * `failing`: dominios cuyo análisis lanza una excepción (tras la puerta).
    Mide cuántos análisis están en curso a la vez (`peak`).
    """

    def __init__(self, blocking: Optional[set] = None, failing: Optional[set] = None):
        self.release = threading.Event()
        self.entered = threading.Semaphore(0)  # +1 por cada análisis que arranca
        self.blocking = blocking
        self.failing = failing or set()
        self.calls = []
        self.running = 0
        self.peak = 0
        self._lock = threading.Lock()

    def __call__(self, domain):
        with self._lock:
            self.calls.append(domain)
            self.running += 1
            self.peak = max(self.peak, self.running)
        self.entered.release()
        try:
            if self.blocking is None or domain in self.blocking:
                if not self.release.wait(WAIT):
                    raise TimeoutError("el test no liberó la puerta del análisis")
            if domain in self.failing:
                raise RuntimeError("fallo simulado del análisis")
            return analysis(domain)
        finally:
            with self._lock:
                self.running -= 1

    def wait_entered(self, count):
        for _ in range(count):
            assert self.entered.acquire(timeout=WAIT), "un análisis no llegó a empezar"


@pytest.fixture
def gate():
    """Puerta cerrada por defecto; se abre siempre al terminar para no dejar hilos colgados."""
    analyzer = GateAnalyzer()
    yield analyzer
    analyzer.release.set()


def make_service(tmp_path, analyzer, **settings):
    repo = repository_from_url(f"sqlite:///{tmp_path / 'm.db'}")
    repo.init_schema()
    return MonitorService(repo, MonitorSettings(**settings), analyzer=analyzer)


def wait_for(condition, what, timeout=WAIT):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return
        time.sleep(0.005)
    pytest.fail(f"tiempo agotado esperando: {what}")


def start_activations(service, domains):
    """Lanza una activación por elemento de `domains` en su propio hilo.

    Devuelve `(hilos, resultados)`. `resultados` se indexa por dominio; si la
    lista repite dominios, por `dominio#n`, de modo que cada hilo tiene SU
    entrada y ninguna se pisa (un resultado perdido haría pasar un test en vano).
    """
    outcomes = {}
    unique = len(set(domains)) == len(domains)

    def work(key, domain):
        try:
            service.activate(domain)
            outcomes[key] = "ok"
        except MonitorLimitError as exc:
            outcomes[key] = exc.code
        except Exception as exc:  # noqa: BLE001
            outcomes[key] = type(exc).__name__

    threads = [
        threading.Thread(target=work, args=(d if unique else f"{d}#{i}", d))
        for i, d in enumerate(domains)
    ]
    for t in threads:
        t.start()
    return threads, outcomes


def join_all(threads):
    for t in threads:
        t.join(WAIT)
    assert all(not t.is_alive() for t in threads), "hilos colgados"


def count(outcomes, code):
    return sum(1 for value in outcomes.values() if value == code)


# ===================================================================== R2
def test_por_defecto_son_4_activaciones_simultaneas_y_se_configura_por_entorno():
    assert MonitorSettings().max_concurrent_activations == 4
    assert MonitorSettings.from_env({}).max_concurrent_activations == 4
    name = "NERSIVO_MONITOR_MAX_CONCURRENT_ACTIVATIONS"
    assert MonitorSettings.from_env({name: "2"}).max_concurrent_activations == 2
    # A2.1: la variable es ESTRICTA; antes `abc` valía 4 y `0` valía 1 en silencio.
    # El detalle (valores, arranque real) está en test_monitor_config_strict.py.
    for invalid in ("abc", "0"):
        with pytest.raises(ValueError, match=name):
            MonitorSettings.from_env({name: invalid})


def test_monitor_busy_es_un_limite_con_codigo_y_retry_after():
    err = MonitorBusyError()
    assert isinstance(err, MonitorLimitError)
    assert err.code == "monitor_busy" and err.retry_after == BUSY_RETRY_AFTER_SECONDS
    assert MonitorLimitError("monitor_capacity_reached").retry_after is None


def test_como_maximo_4_analisis_simultaneos_y_los_demas_se_rechazan_sin_analizar(tmp_path, gate):
    service = make_service(tmp_path, gate)
    domains = [f"r{i}.example.com" for i in range(12)]
    threads, outcomes = start_activations(service, domains)

    gate.wait_entered(4)
    wait_for(lambda: count(outcomes, "monitor_busy") == 8, "8 rechazos monitor_busy")
    # Con la puerta aún cerrada: exactamente 4 en curso, ni uno más.
    assert gate.running == 4 and service.activations_in_flight == 4
    assert len(gate.calls) == 4

    gate.release.set()
    join_all(threads)

    assert count(outcomes, "ok") == 4 and count(outcomes, "monitor_busy") == 8
    assert gate.peak == 4  # nunca hubo más de 4 análisis a la vez
    assert len(gate.calls) == 4  # las rechazadas no iniciaron ningún análisis
    assert service.repo.count_active() == 4  # ...ni insertaron registros
    rejected = [d for d, v in outcomes.items() if v == "monitor_busy"]
    assert all(service.repo.count_active_for_domain(d) == 0 for d in rejected)
    assert service.activations_in_flight == 0


def test_el_hueco_se_libera_al_terminar_y_se_pueden_activar_mas(tmp_path, gate):
    service = make_service(tmp_path, gate)
    threads, outcomes = start_activations(service, [f"a{i}.example.com" for i in range(4)])
    gate.wait_entered(4)
    with pytest.raises(MonitorBusyError):
        service.activate("extra.example.com")  # con los 4 huecos ocupados
    gate.release.set()
    join_all(threads)
    assert count(outcomes, "ok") == 4

    # Libres otra vez: otras 4 activaciones seguidas funcionan.
    for i in range(4):
        service.activate(f"b{i}.example.com")
    assert service.activations_in_flight == 0


def test_la_activacion_rechazada_por_ocupacion_lleva_retry_after(tmp_path, gate):
    service = make_service(tmp_path, gate)
    threads, _ = start_activations(service, [f"a{i}.example.com" for i in range(4)])
    gate.wait_entered(4)
    try:
        service.activate("extra.example.com")
    except MonitorBusyError as exc:
        assert exc.code == "monitor_busy" and exc.retry_after == BUSY_RETRY_AFTER_SECONDS
    else:
        pytest.fail("debía rechazarse por ocupación")
    finally:
        gate.release.set()
        join_all(threads)


# ------------------------------------------------ liberación ante excepciones
def test_el_hueco_se_libera_si_el_analisis_lanza_una_excepcion(tmp_path):
    domains = [f"f{i}.example.com" for i in range(10)]  # más que los 4 huecos
    analyzer = GateAnalyzer(blocking=set(), failing=set(domains))
    service = make_service(tmp_path, analyzer)

    for domain in domains:
        with pytest.raises(RuntimeError):
            service.activate(domain)
        assert service.activations_in_flight == 0
    assert service.repo.count_active() == 0  # una activación fallida no deja registros

    # Si algún hueco se hubiera "fugado", ya no quedaría ninguno libre.
    for i in range(4):
        service.activate(f"ok{i}.example.com")


def test_el_hueco_se_libera_si_falla_la_insercion(tmp_path, monkeypatch):
    service = make_service(tmp_path, GateAnalyzer(blocking=set()))
    original = service.repo.create_monitor

    def broken(record):
        raise RuntimeError("fallo simulado de la base de datos")

    monkeypatch.setattr(service.repo, "create_monitor", broken)
    for i in range(10):
        with pytest.raises(RuntimeError):
            service.activate(f"i{i}.example.com")
        assert service.activations_in_flight == 0

    # El cerrojo de R1 tampoco queda tomado.
    assert service._commit_lock.acquire(timeout=1)
    service._commit_lock.release()

    monkeypatch.setattr(service.repo, "create_monitor", original)
    for i in range(4):
        service.activate(f"ok{i}.example.com")


def test_una_excepcion_en_hilos_concurrentes_no_filtra_huecos(tmp_path):
    bad = {f"x{i}.example.com" for i in range(8)}
    analyzer = GateAnalyzer(blocking=set(), failing=bad)
    service = make_service(tmp_path, analyzer, max_concurrent_activations=4)

    threads, outcomes = start_activations(service, sorted(bad))
    join_all(threads)
    # Cada una falló (RuntimeError) o se rechazó por ocupación; ninguna se coló.
    assert all(v in ("RuntimeError", "monitor_busy") for v in outcomes.values())
    assert service.activations_in_flight == 0
    assert service.repo.count_active() == 0
    for i in range(4):
        service.activate(f"ok{i}.example.com")


def test_un_dominio_invalido_no_consume_hueco_ni_llega_al_analizador(tmp_path):
    analyzer = GateAnalyzer(blocking=set())
    service = make_service(tmp_path, analyzer)
    for bad in ("localhost", "127.0.0.1", "http://evil.com", ""):
        with pytest.raises(ValueError):
            service.activate(bad)
        assert service.activations_in_flight == 0
    assert analyzer.calls == []


def test_los_topes_de_dominio_y_global_no_analizan_ni_consumen_hueco(tmp_path):
    analyzer = GateAnalyzer(blocking=set())
    service = make_service(tmp_path, analyzer, max_per_domain=1, max_active=2)
    service.activate("uno.example.com")
    with pytest.raises(MonitorLimitError) as dominio:
        service.activate("uno.example.com")
    assert dominio.value.code == "monitor_domain_limit_reached"
    assert dominio.value.retry_after is None
    service.activate("dos.example.com")
    with pytest.raises(MonitorLimitError) as global_:
        service.activate("tres.example.com")
    assert global_.value.code == "monitor_capacity_reached"

    assert analyzer.calls == ["uno.example.com", "dos.example.com"]
    assert service.activations_in_flight == 0


# ===================================================================== R1
def test_carrera_por_dominio_no_supera_el_tope(tmp_path, gate):
    """Antes de A2 pasaban las 30 (comprobar-y-luego-insertar sin atomicidad)."""
    service = make_service(
        tmp_path, gate, max_per_domain=3, max_active=200, max_concurrent_activations=64
    )
    threads, outcomes = start_activations(service, ["carrera.example.com"] * 30)

    # Las 30 superan la comprobación rápida (aún no hay ninguna insertada) y
    # analizan a la vez; solo la comprobación final, bajo cerrojo, las frena.
    gate.wait_entered(30)
    gate.release.set()
    join_all(threads)

    assert service.repo.count_active_for_domain("carrera.example.com") == 3
    results = list(outcomes.values())
    assert len(results) == 30  # un resultado por hilo, ninguno perdido
    assert results.count("ok") == 3
    assert results.count("monitor_domain_limit_reached") == 27


def test_carrera_global_no_supera_el_tope(tmp_path, gate):
    service = make_service(
        tmp_path, gate, max_per_domain=3, max_active=5, max_concurrent_activations=64
    )
    threads, outcomes = start_activations(service, [f"g{i}.example.com" for i in range(30)])
    gate.wait_entered(30)
    gate.release.set()
    join_all(threads)

    assert service.repo.count_active() == 5
    assert count(outcomes, "ok") == 5
    assert count(outcomes, "monitor_capacity_reached") == 25


def test_con_el_limite_de_4_los_topes_tambien_se_respetan(tmp_path, gate):
    """R1 y R2 juntos, con los valores por defecto de producción."""
    service = make_service(tmp_path, gate)  # 4 simultáneas, 3 por dominio, 200 globales
    gate.release.set()
    threads, outcomes = start_activations(service, ["mismo.example.com"] * 40)
    join_all(threads)

    assert len(outcomes) == 40  # un resultado por hilo, ninguno perdido
    assert service.repo.count_active_for_domain("mismo.example.com") <= 3
    assert set(outcomes.values()) <= {
        "ok", "monitor_busy", "monitor_domain_limit_reached",
    }
    assert count(outcomes, "ok") == service.repo.count_active_for_domain("mismo.example.com")
    assert count(outcomes, "ok") <= 3
    assert gate.peak <= 4
    assert service.activations_in_flight == 0


def test_el_cerrojo_no_se_mantiene_durante_un_analisis_lento(tmp_path):
    """Una activación lenta no bloquea a otra rápida: el cerrojo solo cubre el
    tramo corto de comprobación + inserción."""
    analyzer = GateAnalyzer(blocking={"lento.example.com"})
    service = make_service(tmp_path, analyzer)
    slow, _ = start_activations(service, ["lento.example.com"])
    try:
        analyzer.wait_entered(1)  # el análisis lento está en curso

        assert service._commit_lock.acquire(timeout=1), "el cerrojo está tomado durante el análisis"
        service._commit_lock.release()

        fast, outcomes = start_activations(service, ["rapido.example.com"])
        join_all(fast)
        assert outcomes == {"rapido.example.com": "ok"}
        assert service.activations_in_flight == 1  # solo la lenta sigue en curso
    finally:
        analyzer.release.set()
        join_all(slow)
    assert service.repo.count_active() == 2


# ===================================================================== cron
def test_el_cron_funciona_con_las_4_activaciones_ocupadas_y_no_usa_sus_huecos(tmp_path):
    analyzer = GateAnalyzer(blocking={f"s{i}.example.com" for i in range(4)})
    service = make_service(tmp_path, analyzer)

    # Un monitor existente que vencerá (intervalo de 24 h por defecto): se
    # adelanta el reloj del servicio 25 h para que el job lo encuentre vencido.
    service.activate("viejo.example.com")
    service._clock = lambda: datetime.now(timezone.utc).replace(microsecond=0) + timedelta(hours=25)

    threads, _ = start_activations(service, [f"s{i}.example.com" for i in range(4)])
    try:
        analyzer.wait_entered(5)  # 1 de "viejo" + 4 lentas
        assert service.activations_in_flight == 4
        with pytest.raises(MonitorBusyError):
            service.activate("otra.example.com")

        summary = service.run_due()  # el job periódico no se ve afectado
        assert summary.claimed == 1 and summary.checked == 1 and summary.failed == 0
        assert service.activations_in_flight == 4  # y no ha tocado el contador
    finally:
        analyzer.release.set()
        join_all(threads)


# ===================================================================== HTTP
@pytest.fixture
def http_service(tmp_path, monkeypatch, gate):
    monkeypatch.setenv("NERSIVO_CRON_TOKEN", CRON_TOKEN)
    monkeypatch.delenv("NERSIVO_TRUSTED_PROXY_HOPS", raising=False)
    monkeypatch.setattr(main, "analyze_domain", lambda d: analysis(d))  # /analyze sin red
    service = make_service(tmp_path, gate)
    monkeypatch.setattr(routes, "_service", service)
    yield service
    routes.reset_service()


def test_http_monitor_busy_429_con_retry_after_cors_y_sin_efectos(http_service, gate):
    async def scenario():
        async def post(index, **headers):
            transport = httpx.ASGITransport(app=main.app, client=(f"198.51.100.{index}", 5000))
            async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
                return await c.post(
                    "/monitor", json={"domain": f"h{index}.example.com"},
                    headers={"Origin": OFFICIAL_ORIGIN},
                )

        tasks = [asyncio.create_task(post(i)) for i in range(1, 11)]  # IPs distintas
        pending, first_done = set(tasks), []
        while len(first_done) < 6:  # las rechazadas responden de inmediato
            done, pending = await asyncio.wait(
                pending, return_when=asyncio.FIRST_COMPLETED, timeout=WAIT
            )
            assert done, "tiempo agotado esperando los rechazos"
            first_done.extend(done)

        # Los 4 huecos están tomados, pero un hilo puede no haber llegado aún al
        # analizador: se espera a que estén los 4 DENTRO antes de medir y de abrir
        # la puerta (sin esto el pico medido podía ser 3 de forma intermitente).
        await asyncio.to_thread(gate.wait_entered, 4)

        # Con 4 análisis detenidos en la puerta: el cron y /analyze siguen vivos.
        transport = httpx.ASGITransport(app=main.app, client=("203.0.113.5", 5000))
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
            cron = await c.post("/internal/monitor/run", headers={"X-Cron-Token": CRON_TOKEN})
            analyze = await c.get("/analyze/example.com")
        in_flight = http_service.activations_in_flight

        gate.release.set()
        rest = await asyncio.gather(*pending)
        return [t.result() for t in first_done], rest, cron, analyze, in_flight

    busy, accepted, cron, analyze, in_flight = asyncio.run(scenario())

    assert in_flight == 4
    for r in busy:
        assert r.status_code == 429
        assert r.json() == {"detail": "monitor_busy"}
        assert r.headers["retry-after"] == str(BUSY_RETRY_AFTER_SECONDS)
        assert r.headers["access-control-allow-origin"] == OFFICIAL_ORIGIN
        assert r.headers["access-control-expose-headers"] == "Retry-After"
    assert [r.status_code for r in accepted] == [201] * 4
    assert cron.status_code == 200 and cron.json()["claimed"] == 0
    assert analyze.status_code == 200

    assert len(gate.calls) == 4 and gate.peak == 4
    assert http_service.repo.count_active() == 4
    assert http_service.activations_in_flight == 0


def test_http_los_429_de_capacidad_y_dominio_no_cambian(tmp_path, monkeypatch):
    analyzer = GateAnalyzer(blocking=set())
    service = make_service(tmp_path, analyzer, max_per_domain=1, max_active=2)
    monkeypatch.setattr(routes, "_service", service)
    client = TestClient(main.app, client=("198.51.100.20", 5000))
    try:
        assert client.post("/monitor", json={"domain": "a.example.com"}).status_code == 201

        r = client.post("/monitor", json={"domain": "a.example.com"})
        assert r.status_code == 429
        assert r.json() == {"detail": "monitor_domain_limit_reached"}
        assert "retry-after" not in r.headers  # no se libera con el tiempo

        assert client.post("/monitor", json={"domain": "b.example.com"}).status_code == 201
        r = client.post("/monitor", json={"domain": "c.example.com"})
        assert r.status_code == 429
        assert r.json() == {"detail": "monitor_capacity_reached"}
        assert "retry-after" not in r.headers
    finally:
        routes.reset_service()
