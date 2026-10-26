"""
Persistencia de la monitorización.

`SqlRepository` es la única implementación y usa SQL estándar y portable
(TEXT/INTEGER, fechas ISO-8601 UTC como texto, sin autoincrement ni JSON
nativo), de modo que el mismo código funciona sobre SQLite (desarrollo/tests)
y Postgres (producción). El resto del código depende solo de la interfaz
`MonitorRepository`; migrar de proveedor es cambiar `NERSIVO_DATABASE_URL`, y
migrar de motor es escribir otra clase con la misma interfaz.

Los tokens de usuario NO se guardan: solo su hash SHA-256.
"""

import json
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterator, List, Optional, Protocol
from urllib.parse import urlparse

_TS_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

STATUS_ACTIVE = "active"
STATUS_DISABLED = "disabled"


def utcnow() -> datetime:
    """Fecha/hora actual en UTC (sin microsegundos)."""
    return datetime.now(timezone.utc).replace(microsecond=0)


def to_iso(moment: Optional[datetime]) -> Optional[str]:
    """datetime -> `YYYY-MM-DDTHH:MM:SSZ` (ordenable como texto)."""
    return moment.astimezone(timezone.utc).strftime(_TS_FORMAT) if moment else None


@dataclass
class MonitorRecord:
    """Fila de `monitors`."""

    id: str
    token_hash: str
    domain: str
    status: str
    created_at: str
    next_check_at: str
    interval_hours: int
    last_checked_at: Optional[str] = None
    current_status: Optional[str] = None
    current_score: Optional[int] = None
    current_fp: Optional[Dict[str, Any]] = None  # último resultado
    previous_fp: Optional[Dict[str, Any]] = None  # resultado anterior
    baseline_fp: Optional[Dict[str, Any]] = None  # base de comparación (sin unknown)
    last_changes: List[Dict[str, Any]] = field(default_factory=list)
    consecutive_failures: int = 0
    deactivated_at: Optional[str] = None


@dataclass
class EventRecord:
    """Fila de `monitor_events`."""

    id: str
    monitor_id: str
    created_at: str
    kind: str
    severity: str
    check_key: Optional[str]
    summary: str
    details: Dict[str, Any] = field(default_factory=dict)
    notified_at: Optional[str] = None


class MonitorRepository(Protocol):
    """Interfaz de persistencia (la única que conoce el servicio)."""

    def init_schema(self) -> None: ...
    def create_monitor(self, record: MonitorRecord) -> None: ...
    def get_by_token_hash(self, token_hash: str) -> Optional[MonitorRecord]: ...
    def count_active(self) -> int: ...
    def count_active_for_domain(self, domain: str) -> int: ...
    def claim_due(self, now: datetime, limit: int, lease_until: datetime) -> List[MonitorRecord]: ...
    def save_check_result(self, record: MonitorRecord, events: List[EventRecord]) -> None: ...
    def record_failure(self, monitor_id: str, next_check_at: datetime) -> None: ...
    def deactivate(self, monitor_id: str, now: datetime) -> None: ...
    def list_events(self, monitor_id: str, limit: int) -> List[EventRecord]: ...


_DDL = (
    """CREATE TABLE IF NOT EXISTS monitors (
        id TEXT PRIMARY KEY,
        token_hash TEXT NOT NULL UNIQUE,
        domain TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at TEXT NOT NULL,
        last_checked_at TEXT,
        next_check_at TEXT NOT NULL,
        current_status TEXT,
        current_score INTEGER,
        current_fp TEXT,
        previous_fp TEXT,
        baseline_fp TEXT,
        last_changes TEXT NOT NULL DEFAULT '[]',
        interval_hours INTEGER NOT NULL,
        consecutive_failures INTEGER NOT NULL DEFAULT 0,
        deactivated_at TEXT
    )""",
    "CREATE INDEX IF NOT EXISTS idx_monitors_due ON monitors (status, next_check_at)",
    "CREATE INDEX IF NOT EXISTS idx_monitors_domain ON monitors (domain, status)",
    """CREATE TABLE IF NOT EXISTS monitor_events (
        id TEXT PRIMARY KEY,
        monitor_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        kind TEXT NOT NULL,
        severity TEXT NOT NULL,
        check_key TEXT,
        summary TEXT NOT NULL,
        details TEXT NOT NULL DEFAULT '{}',
        notified_at TEXT
    )""",
    "CREATE INDEX IF NOT EXISTS idx_events_monitor ON monitor_events (monitor_id, created_at)",
)

_MONITOR_COLUMNS = (
    "id, token_hash, domain, status, created_at, last_checked_at, next_check_at, "
    "current_status, current_score, current_fp, previous_fp, baseline_fp, last_changes, "
    "interval_hours, consecutive_failures, deactivated_at"
)
_EVENT_COLUMNS = "id, monitor_id, created_at, kind, severity, check_key, summary, details, notified_at"


def _dumps(value: Any) -> Optional[str]:
    return None if value is None else json.dumps(value, ensure_ascii=False, sort_keys=True)


def _loads(value: Optional[str], default: Any = None) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except ValueError:
        return default


def _row_to_monitor(row: Any) -> MonitorRecord:
    return MonitorRecord(
        id=row[0], token_hash=row[1], domain=row[2], status=row[3], created_at=row[4],
        last_checked_at=row[5], next_check_at=row[6], current_status=row[7],
        current_score=row[8], current_fp=_loads(row[9]), previous_fp=_loads(row[10]),
        baseline_fp=_loads(row[11]), last_changes=_loads(row[12], []),
        interval_hours=row[13], consecutive_failures=row[14], deactivated_at=row[15],
    )


def _row_to_event(row: Any) -> EventRecord:
    return EventRecord(
        id=row[0], monitor_id=row[1], created_at=row[2], kind=row[3], severity=row[4],
        check_key=row[5], summary=row[6], details=_loads(row[7], {}), notified_at=row[8],
    )


class SqlRepository:
    """
    Repositorio SQL portable.

    Args:
        connect: función sin argumentos que devuelve una conexión DB-API nueva.
        placeholder: marcador de parámetros del driver (`?` en sqlite3, `%s` en psycopg).
    """

    def __init__(self, connect: Callable[[], Any], placeholder: str = "?"):
        self._connect = connect
        self._placeholder = placeholder

    def _sql(self, query: str) -> str:
        return query if self._placeholder == "?" else query.replace("?", self._placeholder)

    @contextmanager
    def _cursor(self) -> Iterator[Any]:
        conn = self._connect()
        try:
            cur = conn.cursor()
            yield cur
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _exec(self, cur: Any, query: str, params: tuple = ()) -> None:
        cur.execute(self._sql(query), params)

    # -- esquema ---------------------------------------------------------------
    def init_schema(self) -> None:
        with self._cursor() as cur:
            for statement in _DDL:
                cur.execute(statement)

    # -- monitores -------------------------------------------------------------
    def create_monitor(self, r: MonitorRecord) -> None:
        with self._cursor() as cur:
            self._exec(
                cur,
                f"INSERT INTO monitors ({_MONITOR_COLUMNS}) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    r.id, r.token_hash, r.domain, r.status, r.created_at, r.last_checked_at,
                    r.next_check_at, r.current_status, r.current_score, _dumps(r.current_fp),
                    _dumps(r.previous_fp), _dumps(r.baseline_fp), _dumps(r.last_changes) or "[]",
                    r.interval_hours, r.consecutive_failures, r.deactivated_at,
                ),
            )

    def get_by_token_hash(self, token_hash: str) -> Optional[MonitorRecord]:
        with self._cursor() as cur:
            self._exec(cur, f"SELECT {_MONITOR_COLUMNS} FROM monitors WHERE token_hash = ?", (token_hash,))
            row = cur.fetchone()
        return _row_to_monitor(row) if row else None

    def count_active(self) -> int:
        with self._cursor() as cur:
            self._exec(cur, "SELECT COUNT(*) FROM monitors WHERE status = ?", (STATUS_ACTIVE,))
            return int(cur.fetchone()[0])

    def count_active_for_domain(self, domain: str) -> int:
        with self._cursor() as cur:
            self._exec(
                cur, "SELECT COUNT(*) FROM monitors WHERE status = ? AND domain = ?",
                (STATUS_ACTIVE, domain),
            )
            return int(cur.fetchone()[0])

    def claim_due(self, now: datetime, limit: int, lease_until: datetime) -> List[MonitorRecord]:
        """
        Reclama de forma atómica hasta `limit` monitores vencidos.

        Cada uno se "reserva" adelantando `next_check_at` con un UPDATE
        condicional: si dos ejecuciones del job se solapan, solo una gana cada
        monitor (el UPDATE de la otra afecta a 0 filas).
        """
        now_s, lease_s = to_iso(now), to_iso(lease_until)
        claimed: List[MonitorRecord] = []
        with self._cursor() as cur:
            self._exec(
                cur,
                f"SELECT {_MONITOR_COLUMNS} FROM monitors WHERE status = ? AND next_check_at <= ? "
                "ORDER BY next_check_at ASC LIMIT ?",
                (STATUS_ACTIVE, now_s, limit),
            )
            candidates = [_row_to_monitor(row) for row in cur.fetchall()]
            for record in candidates:
                self._exec(
                    cur,
                    "UPDATE monitors SET next_check_at = ? WHERE id = ? AND status = ? AND next_check_at <= ?",
                    (lease_s, record.id, STATUS_ACTIVE, now_s),
                )
                if cur.rowcount == 1:
                    claimed.append(record)
        return claimed

    def save_check_result(self, r: MonitorRecord, events: List[EventRecord]) -> None:
        """Guarda el resultado de una comprobación y sus eventos en una transacción."""
        with self._cursor() as cur:
            self._exec(
                cur,
                "UPDATE monitors SET last_checked_at = ?, next_check_at = ?, current_status = ?, "
                "current_score = ?, current_fp = ?, previous_fp = ?, baseline_fp = ?, "
                "last_changes = ?, consecutive_failures = ? WHERE id = ?",
                (
                    r.last_checked_at, r.next_check_at, r.current_status, r.current_score,
                    _dumps(r.current_fp), _dumps(r.previous_fp), _dumps(r.baseline_fp),
                    _dumps(r.last_changes) or "[]", r.consecutive_failures, r.id,
                ),
            )
            for e in events:
                self._exec(
                    cur,
                    f"INSERT INTO monitor_events ({_EVENT_COLUMNS}) VALUES (?,?,?,?,?,?,?,?,?)",
                    (e.id, e.monitor_id, e.created_at, e.kind, e.severity, e.check_key,
                     e.summary, _dumps(e.details) or "{}", e.notified_at),
                )

    def record_failure(self, monitor_id: str, next_check_at: datetime) -> None:
        with self._cursor() as cur:
            self._exec(
                cur,
                "UPDATE monitors SET consecutive_failures = consecutive_failures + 1, "
                "next_check_at = ? WHERE id = ?",
                (to_iso(next_check_at), monitor_id),
            )

    def deactivate(self, monitor_id: str, now: datetime) -> None:
        with self._cursor() as cur:
            self._exec(
                cur,
                "UPDATE monitors SET status = ?, deactivated_at = ? WHERE id = ? AND status = ?",
                (STATUS_DISABLED, to_iso(now), monitor_id, STATUS_ACTIVE),
            )

    def list_events(self, monitor_id: str, limit: int) -> List[EventRecord]:
        with self._cursor() as cur:
            self._exec(
                cur,
                f"SELECT {_EVENT_COLUMNS} FROM monitor_events WHERE monitor_id = ? "
                "ORDER BY created_at DESC, id DESC LIMIT ?",
                (monitor_id, limit),
            )
            return [_row_to_event(row) for row in cur.fetchall()]


# ---------------------------------------------------------------------------
# Fábrica a partir de la URL de base de datos
# ---------------------------------------------------------------------------
def repository_from_url(database_url: str) -> SqlRepository:
    """
    Crea el repositorio según la URL.

    - `sqlite:///ruta/archivo.db` (o `sqlite:///:memory:` no soportado: cada
      operación abre una conexión nueva).
    - `postgresql://...` / `postgres://...` (requiere `psycopg`, importado
      solo si se usa).

    Raises:
        ValueError: esquema de URL no soportado.
    """
    parsed = urlparse(database_url)
    if parsed.scheme == "sqlite":
        path = database_url[len("sqlite:///"):] if database_url.startswith("sqlite:///") else parsed.path
        if not path or path == ":memory:":
            raise ValueError("sqlite_requires_file_path")

        def connect_sqlite() -> sqlite3.Connection:
            conn = sqlite3.connect(path, timeout=10)
            return conn

        return SqlRepository(connect_sqlite, "?")

    if parsed.scheme in ("postgres", "postgresql"):
        def connect_postgres() -> Any:
            import psycopg  # import perezoso: solo hace falta en producción

            return psycopg.connect(database_url, connect_timeout=10)

        return SqlRepository(connect_postgres, "%s")

    raise ValueError("unsupported_database_url")
