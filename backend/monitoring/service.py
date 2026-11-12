"""
Servicio de monitorización: reutiliza el análisis existente, no lo duplica.

Cada comprobación llama a `analyzer.analyze_domain` (los 6 checks con todas sus
protecciones SSRF), calcula una huella estable, la compara con la base de
comparación y persiste resultado + eventos.

Seguridad:
- El dominio se valida con `validate_and_normalize_domain` al activar y de
  nuevo en cada ejecución (defensa en profundidad ante datos manipulados).
- Nunca se hace una petición propia: todo el acceso a red pasa por el analizador.
- El token de gestión solo se devuelve al activar; en base de datos solo
  se guarda su hash SHA-256.
"""

import hashlib
import secrets
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional, Tuple

from ..analyzer import analyze_domain
from ..domain_utils import validate_and_normalize_domain
from .config import MonitorSettings
from .diff import Change, diff_fingerprints
from .fingerprint import make_fingerprint, merge_baseline
from .notifications import NullNotifier, Notifier
from .repository import (
    STATUS_ACTIVE,
    EventRecord,
    MonitorRecord,
    MonitorRepository,
    to_iso,
    utcnow,
)

_RECENT_EVENTS = 20

# Segundos que se sugieren esperar (`Retry-After`) cuando no hay hueco para
# otra activación simultánea.
BUSY_RETRY_AFTER_SECONDS = 5

# Cerrojo de proceso de la comprobación final de topes + inserción (R1). Solo se
# toma alrededor de dos COUNT y un INSERT; nunca durante un análisis de red.
_COMMIT_LOCK = threading.Lock()


class MonitorLimitError(Exception):
    """Se alcanzó un límite de monitorización (global, por dominio o de carga).

    `retry_after` (segundos) es opcional: solo lo definen los límites que se
    liberan solos con el tiempo (p. ej. `MonitorBusyError`).
    """

    def __init__(self, code: str, retry_after: Optional[int] = None):
        super().__init__(code)
        self.code = code
        self.retry_after = retry_after


class MonitorBusyError(MonitorLimitError):
    """Ya hay el máximo de activaciones simultáneas en este proceso."""

    def __init__(self) -> None:
        super().__init__("monitor_busy", BUSY_RETRY_AFTER_SECONDS)


@dataclass
class RunSummary:
    """Resumen de una ejecución del job periódico."""

    claimed: int = 0
    checked: int = 0
    with_changes: int = 0
    events: int = 0
    failed: int = 0
    skipped_for_time: int = 0

    def to_dict(self) -> Dict[str, int]:
        return dict(self.__dict__)


def hash_token(token: str) -> str:
    """SHA-256 hexadecimal del token (lo único que se guarda)."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class MonitorService:
    """Casos de uso de la monitorización.

    Concurrencia de `activate` (A2/R1 y R2):

    * R2 - Como máximo `settings.max_concurrent_activations` activaciones a la
      vez. Se reserva un hueco SIN bloquear al empezar; si no hay, se rechaza
      con `MonitorBusyError` antes de tocar la base de datos o el analizador.
      El hueco se libera siempre (`finally`), también si el análisis falla.
    * R1 - Los topes global y por dominio se comprueban dos veces: al empezar
      (rápido y sin cerrojo, para no pagar un análisis inútil) y de nuevo, de
      forma AUTORITATIVA, justo antes de insertar y bajo `_commit_lock`.
      El cerrojo solo cubre dos `COUNT` y un `INSERT` (operaciones cortas de
      base de datos); NUNCA se mantiene durante el análisis de red. Además, al
      haber como mucho `max_concurrent_activations` activaciones en curso,
      como mucho ese número de hilos puede esperar el cerrojo.

    Limitación: `_commit_lock` es un cerrojo de PROCESO compartido por todas las
    instancias de `MonitorService` (A2.1), de modo que los topes global y por
    dominio se respetan aunque convivan varias instancias en el mismo proceso.
    El contador de activaciones (R2), en cambio, es POR INSTANCIA: `get_service()`
    solo construye una (comprobado en test_monitor_service_lifecycle.py) y solo
    `reset_service()` (uso exclusivo de tests) puede dejar dos vivas.
    Ninguna de las dos garantías cruza procesos: la de los topes vale con UNA sola
    instancia del backend (el despliegue actual en Render Free). Con varios
    procesos haría falta imponer los topes en la base de datos (bloqueo
    consultivo o restricción), porque dos procesos no se ven entre sí.
    """

    def __init__(
        self,
        repository: MonitorRepository,
        settings: Optional[MonitorSettings] = None,
        analyzer: Callable[[str], Any] = analyze_domain,
        notifier: Optional[Notifier] = None,
        clock: Callable[[], datetime] = utcnow,
        monotonic: Callable[[], float] = time.monotonic,
    ):
        self.repo = repository
        self.settings = settings or MonitorSettings()
        self._analyze = analyzer
        self.notifier: Notifier = notifier or NullNotifier()
        self._clock = clock
        self._monotonic = monotonic
        # R1: cerrojo de la comprobación final + inserción (nunca durante el análisis).
        # Es el de PROCESO (A2.1), no uno por instancia: `get_service()` mantiene una
        # sola instancia, pero tras `reset_service()` pueden convivir dos con la misma
        # base de datos y cada una crea su propio repositorio.
        self._commit_lock = _COMMIT_LOCK
        # R2: activaciones en curso (contador protegido, no bloqueante).
        self._activations_lock = threading.Lock()
        self._activations_in_flight = 0

    @property
    def activations_in_flight(self) -> int:
        """Activaciones en curso ahora mismo (observabilidad y tests)."""
        with self._activations_lock:
            return self._activations_in_flight

    def _try_begin_activation(self) -> bool:
        """Reserva un hueco de activación sin bloquear. `False` si no hay."""
        with self._activations_lock:
            if self._activations_in_flight >= self.settings.max_concurrent_activations:
                return False
            self._activations_in_flight += 1
            return True

    def _end_activation(self) -> None:
        with self._activations_lock:
            self._activations_in_flight -= 1

    def _check_capacity(self, normalized: str) -> None:
        """Lanza `MonitorLimitError` si se alcanzó el tope global o por dominio."""
        if self.repo.count_active() >= self.settings.max_active:
            raise MonitorLimitError("monitor_capacity_reached")
        if self.repo.count_active_for_domain(normalized) >= self.settings.max_per_domain:
            raise MonitorLimitError("monitor_domain_limit_reached")

    # -- casos de uso -------------------------------------------------------------
    def activate(self, domain: str) -> Tuple[str, Dict[str, Any]]:
        """
        Activa la monitorización de un dominio (gratuita en esta fase).

        Ejecuta un primer análisis que sirve de base de comparación (sin
        eventos). Devuelve `(token, vista)`.

        Raises:
            ValueError: dominio no válido.
            MonitorBusyError: demasiadas activaciones simultáneas (R2).
            MonitorLimitError: límite global o por dominio alcanzado.
        """
        normalized = validate_and_normalize_domain(domain)

        # R2: sin hueco no se toca la BD, ni se analiza, ni se inserta nada.
        if not self._try_begin_activation():
            raise MonitorBusyError()
        try:
            # Comprobación rápida (sin cerrojo): evita pagar un análisis inútil.
            self._check_capacity(normalized)

            now = self._clock()
            analysis = self._analyze(normalized)
            fingerprint = make_fingerprint(analysis)

            token = secrets.token_urlsafe(32)
            record = MonitorRecord(
                id=str(uuid.uuid4()),
                token_hash=hash_token(token),
                domain=normalized,
                status=STATUS_ACTIVE,
                created_at=to_iso(now) or "",
                last_checked_at=to_iso(now),
                next_check_at=to_iso(now + timedelta(hours=self.settings.interval_hours)) or "",
                interval_hours=self.settings.interval_hours,
                current_status=fingerprint.get("global_status"),
                current_score=fingerprint.get("score"),
                current_fp=fingerprint,
                previous_fp=None,
                baseline_fp=merge_baseline(None, fingerprint),
                last_changes=[],
            )
            # R1: comprobación autoritativa + inserción como una unidad.
            with self._commit_lock:
                self._check_capacity(normalized)
                self.repo.create_monitor(record)
        finally:
            self._end_activation()
        return token, self._view(record)

    def status(self, token: str) -> Optional[Dict[str, Any]]:
        """Vista del monitor asociado al token (None si no existe)."""
        record = self._find(token)
        return self._view(record) if record else None

    def deactivate(self, token: str) -> Optional[Dict[str, Any]]:
        """Desactiva el monitor (idempotente). None si el token no existe."""
        record = self._find(token)
        if record is None:
            return None
        self.repo.deactivate(record.id, self._clock())
        return self._view(self._find(token) or record)

    def run_due(
        self, limit: Optional[int] = None, budget_seconds: Optional[float] = None
    ) -> RunSummary:
        """
        Comprueba los monitores vencidos (lo invoca un job externo).

        Procesa como máximo `limit` monitores y deja de empezar análisis nuevos
        al agotar `budget_seconds`; los no procesados siguen vencidos para la
        siguiente llamada (el "reclamo" caduca a los `lease_minutes`).
        """
        limit = limit or self.settings.run_batch
        budget = budget_seconds if budget_seconds is not None else self.settings.run_budget_seconds
        now = self._clock()
        started = self._monotonic()
        summary = RunSummary()

        claimed = self.repo.claim_due(
            now, limit, now + timedelta(minutes=self.settings.lease_minutes)
        )
        summary.claimed = len(claimed)
        for index, record in enumerate(claimed):
            if self._monotonic() - started >= budget:
                summary.skipped_for_time = len(claimed) - index
                break
            self._check_one(record, summary)
        return summary

    # -- internos -------------------------------------------------------------------
    def _find(self, token: str) -> Optional[MonitorRecord]:
        if not token or len(token) > 200:
            return None
        return self.repo.get_by_token_hash(hash_token(token))

    def _check_one(self, record: MonitorRecord, summary: RunSummary) -> None:
        now = self._clock()
        try:
            domain = validate_and_normalize_domain(record.domain)
            analysis = self._analyze(domain)
            fingerprint = make_fingerprint(analysis)
        except Exception:  # noqa: BLE001 - un monitor roto no debe detener el job
            summary.failed += 1
            self.repo.record_failure(
                record.id, now + timedelta(hours=self.settings.retry_hours)
            )
            return

        changes: List[Change] = diff_fingerprints(record.baseline_fp, fingerprint)
        events = [self._event(record, now, change) for change in changes]

        record.previous_fp = record.current_fp
        record.current_fp = fingerprint
        record.baseline_fp = merge_baseline(record.baseline_fp, fingerprint)
        record.current_status = fingerprint.get("global_status")
        record.current_score = fingerprint.get("score")
        record.last_checked_at = to_iso(now)
        record.next_check_at = to_iso(now + timedelta(hours=record.interval_hours)) or ""
        record.consecutive_failures = 0
        if changes:  # sin cambios no se borra el último aviso conocido
            record.last_changes = [c.to_dict() for c in changes]
        self.repo.save_check_result(record, events)

        summary.checked += 1
        if events:
            summary.with_changes += 1
            summary.events += len(events)
            try:
                self.notifier.notify(record, events)
            except Exception:  # noqa: BLE001 - notificar nunca rompe la comprobación
                pass

    @staticmethod
    def _event(record: MonitorRecord, now: datetime, change: Change) -> EventRecord:
        return EventRecord(
            id=str(uuid.uuid4()),
            monitor_id=record.id,
            created_at=to_iso(now) or "",
            kind=change.kind,
            severity=change.severity,
            check_key=change.check,
            summary=change.summary,
            details={"before": change.before, "after": change.after},
        )

    def _view(self, record: MonitorRecord) -> Dict[str, Any]:
        """Vista pública del monitor (nunca incluye token ni huellas completas)."""
        active = record.status == STATUS_ACTIVE
        events = self.repo.list_events(record.id, _RECENT_EVENTS)
        return {
            "domain": record.domain,
            "status": record.status,
            "created_at": record.created_at,
            "last_checked_at": record.last_checked_at,
            "next_check_at": record.next_check_at if active else None,
            "interval_hours": record.interval_hours,
            "current_status": record.current_status,
            "current_score": record.current_score,
            "last_changes": record.last_changes,
            "recent_events": [
                {
                    "created_at": e.created_at,
                    "kind": e.kind,
                    "severity": e.severity,
                    "check": e.check_key,
                    "summary": e.summary,
                }
                for e in events
            ],
        }
