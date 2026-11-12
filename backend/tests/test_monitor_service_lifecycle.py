"""A2.1 (punto 2): ciclo de vida de `MonitorService` y cerrojo de confirmación.

Pregunta: ¿pueden existir dos instancias activas de `MonitorService` que
compartan base de datos y tengan cerrojos de confirmación independientes?

Los tests se dividen en dos bloques:

A. CICLO DE VIDA REAL (`get_service()` sin `reset_service()`): una única
   instancia por proceso, también con inicializaciones fallidas y peticiones
   concurrentes. Es el camino que recorre cualquier petición HTTP.
B. DOS INSTANCIAS (lo que produce `reset_service()` + `get_service()` mientras
   hay activaciones en curso): comparten la base de datos pero cada una crea su
   propio repositorio. Aquí se comprueba que los topes se respetan igualmente.

Todo es local: SQLite temporal, analizadores simulados, sin red ni producción.
"""

import ast
import asyncio
import os
import threading
from pathlib import Path

import httpx
import pytest
from fastapi import HTTPException

from backend import main
from backend.monitoring import routes
from backend.monitoring.config import MonitorSettings
from backend.monitoring.repository import repository_from_url
from backend.monitoring.service import MonitorLimitError, MonitorService
from backend.tests.monitor_helpers import analysis
from backend.tests.test_monitor_activation_limits import (
    WAIT,
    GateAnalyzer,
    join_all,
    start_activations,
    wait_for,
)

BACKEND = Path(__file__).resolve().parents[1]


# ------------------------------------------------------------------ utilidades
class Probe:
    """Registra qué repositorios y servicios crea `get_service()` y fuerza fallos.

    `plan` indica, para cada intento de inicialización por orden, cómo falla:
    "repo" (falla `repository_from_url`), "schema" (el repositorio se crea pero
    falla `init_schema`) o `None` (funciona). Pasados los intentos del plan,
    todos funcionan.
    """

    def __init__(self, plan=()):
        self.plan = list(plan)
        self.attempts = 0
        self.repos = []
        self.services = []
        self._lock = threading.Lock()

    def next_mode(self):
        with self._lock:
            self.attempts += 1
            return self.plan.pop(0) if self.plan else None


@pytest.fixture
def lifecycle(tmp_path, monkeypatch):
    """`get_service()` real (con su cerrojo), sobre SQLite temporal y sin red."""
    for name in [n for n in os.environ if n.startswith("NERSIVO_")]:
        monkeypatch.delenv(name)
    monkeypatch.setenv("NERSIVO_DATABASE_URL", f"sqlite:///{tmp_path / 'm.db'}")
    # Estos tests miden el ciclo de vida, no el limitador por IP ni R2.
    monkeypatch.setenv("NERSIVO_MONITOR_RATE_MAX_REQUESTS", "1000")
    monkeypatch.setenv("NERSIVO_MONITOR_MAX_CONCURRENT_ACTIVATIONS", "64")
    probe = Probe()
    real_repository_from_url = routes.repository_from_url

    def fake_repository_from_url(url):
        mode = probe.next_mode()
        if mode == "repo":
            raise RuntimeError("BD caída (repository_from_url)")
        repo = real_repository_from_url(url)
        probe.repos.append(repo)
        if mode == "schema":
            def broken_init_schema():
                raise RuntimeError("BD caída (init_schema)")
            repo.init_schema = broken_init_schema
        return repo

    def fake_service(repo, settings):
        service = MonitorService(repo, settings, analyzer=analysis)
        probe.services.append(service)
        return service

    monkeypatch.setattr(routes, "repository_from_url", fake_repository_from_url)
    monkeypatch.setattr(routes, "MonitorService", fake_service)
    routes.reset_service()
    yield probe
    routes.reset_service()


def call_get_service_concurrently(count):
    """`count` hilos llaman a `get_service()` a la vez. Devuelve (servicios, códigos)."""
    barrier = threading.Barrier(count)
    services, codes = [], []
    guard = threading.Lock()

    def work():
        barrier.wait(WAIT)
        try:
            service = routes.get_service()
            with guard:
                services.append(service)
        except HTTPException as exc:
            with guard:
                codes.append(exc.status_code)

    threads = [threading.Thread(target=work) for _ in range(count)]
    for t in threads:
        t.start()
    join_all(threads)
    return services, codes


# ===================================================================== A. ciclo real
def test_peticiones_concurrentes_comparten_una_unica_instancia(lifecycle):
    services, codes = call_get_service_concurrently(32)
    assert codes == []
    assert len(services) == 32 and len({id(s) for s in services}) == 1
    assert len(lifecycle.services) == 1, "se construyó más de un MonitorService"
    assert len(lifecycle.repos) == 1, "se creó más de un repositorio"


def test_inicializacion_fallida_no_cachea_ni_deja_instancias_vivas(lifecycle):
    lifecycle.plan = ["repo", "schema"] * 8  # los 16 intentos fallan
    services, codes = call_get_service_concurrently(16)
    assert services == []
    assert codes == [503] * 16
    assert routes._service is None, "un fallo dejó un servicio a medio inicializar"
    assert lifecycle.services == [], "se construyó un MonitorService pese al fallo"


def test_fallos_y_exito_mezclados_producen_como_mucho_una_instancia(lifecycle):
    lifecycle.plan = ["repo", "schema", "repo"]  # 3 fallos y luego funciona
    services, codes = call_get_service_concurrently(24)
    assert codes == [503] * 3, "cada intento fallido debe corresponder a un 503"
    assert len(services) == 21 and len({id(s) for s in services}) == 1
    assert len(lifecycle.services) == 1
    survivor = lifecycle.services[0]
    # El repositorio del intento con init_schema roto NO es el que quedó en uso.
    assert survivor.repo is lifecycle.repos[-1]
    assert survivor.repo is not lifecycle.repos[0]
    assert routes._service is survivor


def test_tras_un_fallo_inicial_los_topes_se_respetan_con_http_concurrente(
    lifecycle, monkeypatch
):
    """Extremo a extremo: 1 fallo de inicialización y luego 40 POST simultáneos al
    mismo dominio con tope 3 -> exactamente 1x503, 3x201, 36x429 y 3 activos."""
    monkeypatch.setenv("NERSIVO_MONITOR_MAX_PER_DOMAIN", "3")
    lifecycle.plan = ["repo"]

    async def scenario():
        transport = httpx.ASGITransport(app=main.app, client=("203.0.113.9", 50000))
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as http:
            replies = await asyncio.gather(
                *[http.post("/monitor", json={"domain": "mismo.example.com"}) for _ in range(40)]
            )
        return [(r.status_code, r.json().get("detail")) for r in replies]

    results = asyncio.run(scenario())
    statuses = [status for status, _ in results]
    assert statuses.count(503) == 1, results
    assert statuses.count(201) == 3, results
    assert statuses.count(429) == 36, results
    assert {d for s, d in results if s == 429} == {"monitor_domain_limit_reached"}
    assert len(lifecycle.services) == 1
    assert lifecycle.services[0].repo.count_active_for_domain("mismo.example.com") == 3


def test_reset_service_y_servicios_solo_se_construyen_en_el_codigo_de_produccion_indicado():
    """Guarda de la afirmación 'solo los tests llaman a reset_service()': ninguna ruta
    ni módulo de producción lo invoca, y MonitorService se construye en un único sitio."""
    resets, constructions = [], []
    for path in BACKEND.rglob("*.py"):
        if "tests" in path.relative_to(BACKEND).parts:
            continue
        # AST y no texto: así los docstrings y comentarios que NOMBRAN estas
        # funciones no cuentan como llamadas.
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"), str(path))):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", None)
            if name == "reset_service":
                resets.append(f"{path.name}:{node.lineno}")
            elif name == "MonitorService":
                constructions.append(f"{path.name}:{node.lineno}")
    assert resets == [], f"código de producción llama a reset_service(): {resets}"
    assert len(constructions) == 1 and constructions[0].startswith("routes.py"), constructions


# ===================================================================== B. dos instancias
def two_services(tmp_path, **settings):
    """Dos servicios sobre el MISMO archivo SQLite, cada uno con SU repositorio.

    Es exactamente lo que deja `get_service()` tras un `reset_service()`: el
    repositorio se vuelve a crear, así que los dos objetos son distintos pero la
    base de datos es la misma.
    """
    url = f"sqlite:///{tmp_path / 'shared.db'}"
    first_repo, second_repo = repository_from_url(url), repository_from_url(url)
    first_repo.init_schema()
    second_repo.init_schema()
    cfg = dict(max_concurrent_activations=64, **settings)
    first = MonitorService(first_repo, MonitorSettings(**cfg), analyzer=analysis)
    second = MonitorService(second_repo, MonitorSettings(**cfg), analyzer=analysis)
    return first, second


def test_reset_service_deja_dos_instancias_vivas_con_repositorios_distintos_y_misma_bd(
    lifecycle,
):
    first = routes.get_service()
    routes.reset_service()
    second = routes.get_service()
    assert first is not second
    assert first.repo is not second.repo  # repository_from_url crea uno nuevo
    first.activate("compartida.example.com")
    assert second.repo.count_active() == 1, "no comparten base de datos"
    assert first._commit_lock is second._commit_lock, (
        "dos instancias vivas con cerrojos de confirmación independientes"
    )


class PausedInsert:
    """Detiene cada `create_monitor` hasta que los DOS hilos están dentro del tramo
    comprobar+insertar. Si el cerrojo es compartido, el segundo hilo no puede entrar
    y la barrera caduca (1,5 s) con el primero dentro; si no lo es, entran los dos."""

    def __init__(self, *repos):
        self.barrier = threading.Barrier(2, timeout=1.5)
        for repo in repos:
            original = repo.create_monitor

            def paused(record, _original=original):
                try:
                    self.barrier.wait()
                except threading.BrokenBarrierError:
                    pass
                return _original(record)

            repo.create_monitor = paused


@pytest.mark.parametrize(
    "scope,domains,settings,expected_code",
    [
        ("por dominio", ("carrera.example.com", "carrera.example.com"),
         {"max_per_domain": 1}, "monitor_domain_limit_reached"),
        ("global", ("uno.example.com", "dos.example.com"),
         {"max_active": 1}, "monitor_capacity_reached"),
    ],
)
def test_dos_instancias_con_la_misma_bd_no_superan_los_topes(
    tmp_path, scope, domains, settings, expected_code
):
    first, second = two_services(tmp_path, **settings)
    PausedInsert(first.repo, second.repo)
    outcomes = {}

    def work(label, service, domain):
        try:
            service.activate(domain)
            outcomes[label] = "ok"
        except MonitorLimitError as exc:
            outcomes[label] = exc.code

    threads = [
        threading.Thread(target=work, args=("primera", first, domains[0])),
        threading.Thread(target=work, args=("segunda", second, domains[1])),
    ]
    for t in threads:
        t.start()
    join_all(threads)

    assert first.repo.count_active() == 1, (
        f"tope {scope} superado con dos instancias: "
        f"{first.repo.count_active()} activos, resultados {outcomes}"
    )
    assert sorted(outcomes.values()) == sorted(["ok", expected_code]), outcomes


def test_el_cerrojo_compartido_no_se_mantiene_durante_el_analisis(tmp_path):
    """Con el cerrojo compartido: mientras una instancia está DENTRO de un análisis
    lento, el cerrojo está libre y la otra instancia activa y termina sin esperarla."""
    first, second = two_services(tmp_path)
    slow = GateAnalyzer(blocking={"lento.example.com"})
    first._analyze = slow
    second._analyze = GateAnalyzer(blocking=set())  # responde al instante
    try:
        threads, outcomes = start_activations(first, ["lento.example.com"])
        slow.wait_entered(1)  # la primera está dentro del análisis de red
        assert not first._commit_lock.locked(), "cerrojo retenido durante el análisis"
        assert not second._commit_lock.locked()

        other_threads, other_outcomes = start_activations(second, ["rapido.example.com"])
        join_all(other_threads)  # termina sin esperar a la análisis lento
        assert other_outcomes == {"rapido.example.com": "ok"}
        assert threads[0].is_alive(), "la activación lenta debía seguir en curso"
    finally:
        slow.release.set()
    join_all(threads)
    assert outcomes == {"lento.example.com": "ok"}
    wait_for(lambda: not first._commit_lock.locked(), "cerrojo liberado")
    assert first.repo.count_active() == 2
