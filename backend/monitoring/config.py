"""
Configuración de la monitorización (variables de entorno).

Se lee en el momento de uso, no al importar: así los tests y el arranque de
`/analyze` no dependen de ninguna variable ni de la base de datos.

Variables (todas opcionales):

- NERSIVO_DATABASE_URL: `sqlite:///ruta.db` (desarrollo) o `postgresql://...`
  (producción). Por defecto: `sqlite:///./nersivo_monitor.sqlite3`.
  ATENCIÓN: SQLite en el disco de Render gratuito se pierde en cada reinicio o
  despliegue; en producción usa Postgres.
- NERSIVO_CRON_TOKEN: secreto que debe enviar el job externo en la cabecera
  `X-Cron-Token`. Si no está definido, el endpoint de ejecución queda
  deshabilitado (seguro por defecto).
- NERSIVO_MONITOR_INTERVAL_HOURS: horas entre comprobaciones (por defecto 24).
- NERSIVO_MONITOR_MAX_ACTIVE: máximo de monitores activos (por defecto 200).
- NERSIVO_MONITOR_MAX_PER_DOMAIN: máximo de monitores activos por dominio (3).
- NERSIVO_MONITOR_RUN_BATCH: dominios por ejecución del job (por defecto 10).
- NERSIVO_MONITOR_RUN_BUDGET_SECONDS: tiempo máximo por ejecución (por defecto 45).
"""

import os
from dataclasses import dataclass
from typing import Mapping, Optional

DEFAULT_DATABASE_URL = "sqlite:///./nersivo_monitor.sqlite3"


def _int(env: Mapping[str, str], name: str, default: int, minimum: int = 1) -> int:
    try:
        return max(minimum, int(env.get(name, default)))
    except (TypeError, ValueError):
        return default


@dataclass(frozen=True)
class MonitorSettings:
    """Ajustes efectivos de monitorización."""

    database_url: str = DEFAULT_DATABASE_URL
    cron_token: Optional[str] = None
    interval_hours: int = 24
    max_active: int = 200
    max_per_domain: int = 3
    run_batch: int = 10
    run_budget_seconds: int = 45
    # Reintento tras un fallo del análisis (horas).
    retry_hours: int = 1
    # Margen durante el que un monitor "reclamado" no se vuelve a reclamar.
    lease_minutes: int = 15

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None) -> "MonitorSettings":
        env = os.environ if env is None else env
        return cls(
            database_url=(env.get("NERSIVO_DATABASE_URL") or DEFAULT_DATABASE_URL).strip(),
            cron_token=(env.get("NERSIVO_CRON_TOKEN") or "").strip() or None,
            interval_hours=_int(env, "NERSIVO_MONITOR_INTERVAL_HOURS", 24),
            max_active=_int(env, "NERSIVO_MONITOR_MAX_ACTIVE", 200),
            max_per_domain=_int(env, "NERSIVO_MONITOR_MAX_PER_DOMAIN", 3),
            run_batch=_int(env, "NERSIVO_MONITOR_RUN_BATCH", 10),
            run_budget_seconds=_int(env, "NERSIVO_MONITOR_RUN_BUDGET_SECONDS", 45),
        )
