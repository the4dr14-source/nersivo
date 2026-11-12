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
- NERSIVO_MONITOR_MAX_CONCURRENT_ACTIVATIONS: máximo de activaciones
  (`POST /monitor`) en curso a la vez en este proceso (por defecto 4). Acota
  los hilos que puede ocupar la ruta pública; no afecta al job periódico.
  ESTRICTA: ausente = 4; si está presente debe ser un entero >= 1 y cualquier
  otro valor (`abc`, `0`, `-1`, `4.5`, vacío) impide arrancar. Las demás
  variables de este módulo siguen siendo tolerantes (valor inválido = defecto).
"""

import os
import re
from dataclasses import dataclass
from typing import Mapping, Optional

DEFAULT_DATABASE_URL = "sqlite:///./nersivo_monitor.sqlite3"


def _int(env: Mapping[str, str], name: str, default: int, minimum: int = 1) -> int:
    try:
        return max(minimum, int(env.get(name, default)))
    except (TypeError, ValueError):
        return default


# Dígitos ASCII, como mucho 9: acota el valor (y evita depender del límite de
# conversión de `int()` de cada versión de Python con cadenas enormes).
_POSITIVE_INT = re.compile(r"[0-9]{1,9}")


def _strict_positive_int(env: Mapping[str, str], name: str, default: int) -> int:
    """Entero decimal >= 1. Ausente -> `default`; presente pero inválido -> `ValueError`.

    A diferencia de `_int`, NUNCA corrige en silencio: `abc`, `0`, `-1`, `4.5`,
    `+4`, `1_0`, cadena vacía o solo espacios son un error explícito. Un límite
    de seguridad que se ajusta solo a otro valor es peor que no arrancar.
    """
    raw = env.get(name)
    if raw is None:
        return default
    text = raw.strip()
    if _POSITIVE_INT.fullmatch(text) and int(text) >= 1:
        return int(text)
    raise ValueError(
        f"{name} debe ser un entero positivo (>= 1, hasta 9 dígitos), no {raw[:40]!r}"
    )


def validate_monitor_environment(env: Optional[Mapping[str, str]] = None) -> None:
    """Falla (``ValueError``) si la configuración ESTRICTA de monitorización es errónea.

    Se llama al importar la aplicación (`main.py`): `MonitorSettings.from_env()`
    solo se ejecuta en la primera petición a `/monitor` y allí cualquier error
    acabaría convertido en un 503, así que sin esto el servicio arrancaría con
    la variable mal escrita sin que nadie lo viera.
    """
    MonitorSettings.from_env(env)


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
    # Activaciones (`POST /monitor`) simultáneas como máximo en este proceso.
    max_concurrent_activations: int = 4

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
            max_concurrent_activations=_strict_positive_int(
                env, "NERSIVO_MONITOR_MAX_CONCURRENT_ACTIVATIONS", 4
            ),
        )
