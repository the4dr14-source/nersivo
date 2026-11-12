"""Rate limiting sencillo en memoria para proteger endpoints costosos.

Está pensado como primera capa de protección para el MVP desplegado en una
sola instancia. El estado se reinicia cuando el proceso se reinicia y no se
comparte entre instancias.

Endpoints protegidos (cada uno con su PROPIO limitador, de modo que agotar la
cuota de uno no afecta al otro):

* ``/analyze/...`` (cualquier método): 30 peticiones / 60 s por cliente.
* ``POST /monitor`` (método y ruta exactos): por defecto 5 peticiones / 600 s
  por cliente, configurable con ``NERSIVO_MONITOR_RATE_MAX_REQUESTS`` y
  ``NERSIVO_MONITOR_RATE_WINDOW_SECONDS``.

Control de memoria (A2/M2)
--------------------------
El estado es un diccionario ``clave -> marcas de tiempo``. Sin control crecía
sin límite (una clave por IP distinta, nunca eliminada). Ahora:

* Barrido: como mucho una vez por ventana se eliminan las claves cuyas marcas
  ya han expirado. No hay tareas en segundo plano: el barrido lo hace, cuando
  toca, la propia llamada a ``allow``.
* Barrido a demanda: con la tabla llena, antes de usar el cubo de respaldo se
  intenta liberar claves caducadas (como mucho una vez por segundo).
* Tope de claves (``DEFAULT_MAX_KEYS``): al alcanzarlo, las claves NUEVAS no
  crean entrada propia y comparten un único cubo de respaldo
  (``OVERFLOW_KEY``) con la misma cuota que cualquier otra clave. Así rotar
  identidades no sirve para eludir el límite (fallo cerrado, igual que los
  cubos de respaldo de A3). El coste es que, mientras dure un ataque que llene
  la tabla, los clientes NUEVOS comparten cuota; los ya registrados no se ven
  afectados.
* Todo el acceso al estado se hace bajo un ``threading.Lock`` (nunca se
  mantiene a través de un ``await``).
"""

from __future__ import annotations

import os
import re
import threading
from collections import defaultdict, deque
from time import monotonic
from typing import Deque, Mapping, Optional

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from .client_ip import (
    FallbackReporter,
    check_peer_verification_config,
    diagnostics_enabled,
    log_resolution,
    resolve_client,
    trusted_hops_from_env,
    trusted_networks_from_env,
    validate_trusted_hops,
    validate_trusted_networks,
    warn_if_proxy_headers_untrusted,
)

# Máximo de claves distintas por limitador. Con ~1-2 KB por clave el techo de
# memoria queda en el orden de 10-20 MB por limitador.
DEFAULT_MAX_KEYS = 10_000

# Cubo compartido al que van las claves nuevas cuando la tabla está llena.
OVERFLOW_KEY = "rate-limit-overflow"

# Intervalo mínimo (s) entre barridos a demanda con la tabla llena.
FULL_SWEEP_MIN_INTERVAL = 1.0

# --- Configuración de POST /monitor (A2/M1) ----------------------------------
MONITOR_RATE_MAX_ENV = "NERSIVO_MONITOR_RATE_MAX_REQUESTS"
MONITOR_RATE_WINDOW_ENV = "NERSIVO_MONITOR_RATE_WINDOW_SECONDS"

DEFAULT_MONITOR_RATE_MAX = 5
DEFAULT_MONITOR_RATE_WINDOW = 600

MONITOR_RATE_MAX_BOUNDS = (1, 1000)
MONITOR_RATE_WINDOW_BOUNDS = (1, 86_400)

_DIGITS = re.compile(r"[0-9]{1,9}")


class InMemoryRateLimiter:
    """Limita peticiones por identificador dentro de una ventana deslizante."""

    def __init__(
        self,
        max_requests: int = 30,
        window_seconds: int = 60,
        max_keys: int = DEFAULT_MAX_KEYS,
    ) -> None:
        if max_requests < 1:
            raise ValueError("max_requests debe ser >= 1")
        if window_seconds < 1:
            raise ValueError("window_seconds debe ser >= 1")
        if max_keys < 1:
            raise ValueError("max_keys debe ser >= 1")

        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.max_keys = max_keys
        self._requests: dict[str, Deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()
        self._next_sweep: Optional[float] = None
        self._last_full_sweep: Optional[float] = None

    def allow(self, key: str, now: float | None = None) -> tuple[bool, int]:
        """Devuelve (permitido, segundos_para_reintentar)."""
        current = monotonic() if now is None else now
        with self._lock:
            self._sweep_if_due(current)

            # Tabla llena: antes de recurrir al cubo común se intenta liberar
            # claves ya caducadas (el barrido programado puede tardar hasta una
            # ventana entera). Si sigue llena, la clave nueva no crea entrada.
            if key not in self._requests and len(self._requests) >= self.max_keys:
                self._sweep_when_full(current)
                if key not in self._requests and len(self._requests) >= self.max_keys:
                    key = OVERFLOW_KEY

            timestamps = self._requests[key]
            cutoff = current - self.window_seconds

            while timestamps and timestamps[0] <= cutoff:
                timestamps.popleft()

            if len(timestamps) >= self.max_requests:
                retry_after = max(
                    1, int(timestamps[0] + self.window_seconds - current + 0.999)
                )
                return False, retry_after

            timestamps.append(current)
            return True, 0

    def _sweep_if_due(self, current: float) -> None:
        """Elimina las claves expiradas, como mucho una vez por ventana.

        Debe llamarse con el cerrojo tomado. El coste es O(claves) y se paga
        una vez por ventana, así que es amortizado O(1) por petición.
        """
        if self._next_sweep is None:
            self._next_sweep = current + self.window_seconds
            return
        if current < self._next_sweep:
            return

        self._remove_expired(current)
        self._next_sweep = current + self.window_seconds

    def _sweep_when_full(self, current: float) -> None:
        """Barrido a demanda con la tabla llena, como mucho una vez por segundo.

        Sin él, un atacante que llenase la tabla justo después de un barrido
        dejaría a los clientes nuevos en el cubo común hasta la siguiente pasada
        aunque todas esas claves ya hubieran caducado (hasta una ventana entera:
        10 minutos en ``POST /monitor``). El límite de frecuencia acota el coste:
        O(claves) como mucho una vez por segundo aunque lleguen miles de claves
        nuevas. Debe llamarse con el cerrojo tomado.
        """
        last = self._last_full_sweep
        if last is not None and current - last < FULL_SWEEP_MIN_INTERVAL:
            return
        self._last_full_sweep = current
        self._remove_expired(current)

    def _remove_expired(self, current: float) -> None:
        """Elimina las claves sin marcas vigentes. Con el cerrojo tomado."""
        cutoff = current - self.window_seconds
        expired = [
            key
            for key, timestamps in self._requests.items()
            if not timestamps or timestamps[-1] <= cutoff
        ]
        for key in expired:
            del self._requests[key]


def _bounded_int(
    name: str, raw: object, low: int, high: int
) -> int:
    """Entero decimal estricto dentro de [low, high]; si no, ``ValueError``."""
    text = str(raw).strip()
    if not _DIGITS.fullmatch(text):
        raise ValueError(
            f"{name} debe ser un entero entre {low} y {high}, no {raw!r}"
        )
    value = int(text)
    if not low <= value <= high:
        raise ValueError(f"{name} debe estar entre {low} y {high}, no {value}")
    return value


def monitor_rate_from_env(
    environ: Optional[Mapping[str, str]] = None,
) -> tuple[int, int]:
    """Lee ``(max_peticiones, ventana_en_segundos)`` de ``POST /monitor``.

    Ausente o vacío: valor por defecto. Un valor inválido es un error (igual
    que en A3): es preferible no arrancar a arrancar con un límite distinto del
    que cree el operador.
    """
    env = os.environ if environ is None else environ
    raw_max = env.get(MONITOR_RATE_MAX_ENV)
    raw_window = env.get(MONITOR_RATE_WINDOW_ENV)
    max_requests = (
        DEFAULT_MONITOR_RATE_MAX
        if raw_max is None or raw_max.strip() == ""
        else _bounded_int(MONITOR_RATE_MAX_ENV, raw_max, *MONITOR_RATE_MAX_BOUNDS)
    )
    window = (
        DEFAULT_MONITOR_RATE_WINDOW
        if raw_window is None or raw_window.strip() == ""
        else _bounded_int(
            MONITOR_RATE_WINDOW_ENV, raw_window, *MONITOR_RATE_WINDOW_BOUNDS
        )
    )
    return max_requests, window


def validate_environment() -> None:
    """Falla al importar la aplicación si la configuración es errónea.

    Sin esto el ``ValueError`` del middleware saltaría en la primera petición
    (Starlette lo construye de forma perezosa) y el servicio arrancaría roto.
    Cubre la configuración de A3 y la del limitador de ``POST /monitor``.
    """
    check_peer_verification_config(
        trusted_hops_from_env(), trusted_networks_from_env(), warn=False
    )
    monitor_rate_from_env()


class AnalyzeRateLimitMiddleware(BaseHTTPMiddleware):
    """Aplica límites a ``/analyze/`` y a ``POST /monitor``.

    Cada ruta tiene su propio ``InMemoryRateLimiter`` (``limiter`` para
    ``/analyze/``, ``monitor_limiter`` para ``POST /monitor``). La clave del
    cliente se obtiene con `client_ip.resolve_client` (ver ese módulo para el
    modelo de confianza). `trusted_proxy_hops` se lee de
    `NERSIVO_TRUSTED_PROXY_HOPS` si no se indica.

    El límite de ``POST /monitor`` se aplica ANTES de validar el cuerpo, así que
    también cuentan las peticiones con cuerpo inválido. Solo coincide el método
    ``POST`` con la ruta exacta ``/monitor``: ``GET``/``DELETE /monitor``,
    ``/internal/monitor/run``, ``/guides`` y ``/health`` no se ven afectados.
    """

    def __init__(
        self,
        app,
        max_requests: int = 30,
        window_seconds: int = 60,
        trusted_proxy_hops: int | None = None,
        trusted_proxy_networks=None,
        monitor_max_requests: int | None = None,
        monitor_window_seconds: int | None = None,
        max_keys: int | None = None,
    ):
        super().__init__(app)
        keys = DEFAULT_MAX_KEYS if max_keys is None else max_keys
        env_max, env_window = monitor_rate_from_env()
        monitor_max = (
            env_max
            if monitor_max_requests is None
            else _bounded_int(
                MONITOR_RATE_MAX_ENV, monitor_max_requests, *MONITOR_RATE_MAX_BOUNDS
            )
        )
        monitor_window = (
            env_window
            if monitor_window_seconds is None
            else _bounded_int(
                MONITOR_RATE_WINDOW_ENV,
                monitor_window_seconds,
                *MONITOR_RATE_WINDOW_BOUNDS,
            )
        )
        self.limiter = InMemoryRateLimiter(max_requests, window_seconds, keys)
        self.monitor_limiter = InMemoryRateLimiter(monitor_max, monitor_window, keys)
        self.trusted_proxy_hops = (
            trusted_hops_from_env()
            if trusted_proxy_hops is None
            else validate_trusted_hops(trusted_proxy_hops)
        )
        self.trusted_proxy_networks = (
            trusted_networks_from_env()
            if trusted_proxy_networks is None
            else validate_trusted_networks(trusted_proxy_networks)
        )
        check_peer_verification_config(
            self.trusted_proxy_hops, self.trusted_proxy_networks
        )
        self._fallback_reporter = FallbackReporter()
        self._log_resolution = diagnostics_enabled()
        warn_if_proxy_headers_untrusted(self.trusted_proxy_hops)

    def _limiter_for(self, request: Request):
        """Devuelve ``(limitador, es_monitor)`` o ``(None, False)`` si no aplica."""
        path = request.url.path
        if path.startswith("/analyze/"):
            return self.limiter, False
        if request.method == "POST" and path == "/monitor":
            return self.monitor_limiter, True
        return None, False

    async def dispatch(self, request: Request, call_next):
        limiter, is_monitor = self._limiter_for(request)
        if limiter is not None:
            peer_host = request.client.host if request.client else None
            peer_port = request.client.port if request.client else None
            forwarded_for = request.headers.getlist("x-forwarded-for")
            identity = resolve_client(
                peer_host,
                forwarded_for,
                self.trusted_proxy_hops,
                self.trusted_proxy_networks,
            )
            self._fallback_reporter.report(peer_host, identity)
            if self._log_resolution:
                log_resolution(
                    peer_host,
                    forwarded_for,
                    self.trusted_proxy_hops,
                    identity,
                    peer_port,
                )
            allowed, retry_after = limiter.allow(identity.key)

            if not allowed:
                detail = (
                    "monitor_rate_limited"
                    if is_monitor
                    else (
                        "Demasiadas solicitudes de análisis. "
                        "Inténtalo de nuevo más tarde."
                    )
                )
                return JSONResponse(
                    status_code=429,
                    content={"detail": detail},
                    headers={"Retry-After": str(retry_after)},
                )

        return await call_next(request)
