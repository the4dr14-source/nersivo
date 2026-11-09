"""Rate limiting sencillo en memoria para proteger endpoints costosos.

Está pensado como primera capa de protección para el MVP desplegado en una
sola instancia. El estado se reinicia cuando el proceso se reinicia.
"""

from __future__ import annotations

from collections import defaultdict, deque
from time import monotonic
from typing import Deque

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


class InMemoryRateLimiter:
    """Limita peticiones por identificador dentro de una ventana deslizante."""

    def __init__(self, max_requests: int = 30, window_seconds: int = 60) -> None:
        if max_requests < 1:
            raise ValueError("max_requests debe ser >= 1")
        if window_seconds < 1:
            raise ValueError("window_seconds debe ser >= 1")

        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests: dict[str, Deque[float]] = defaultdict(deque)

    def allow(self, key: str, now: float | None = None) -> tuple[bool, int]:
        """Devuelve (permitido, segundos_para_reintentar)."""
        current = monotonic() if now is None else now
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


def validate_environment() -> None:
    """Falla al importar la aplicación si la configuración de A3 es errónea.

    Sin esto el ``ValueError`` del middleware saltaría en la primera petición
    (Starlette lo construye de forma perezosa) y el servicio arrancaría roto.
    """
    check_peer_verification_config(
        trusted_hops_from_env(), trusted_networks_from_env(), warn=False
    )


class AnalyzeRateLimitMiddleware(BaseHTTPMiddleware):
    """Aplica el límite únicamente al endpoint de análisis.

    La clave del cliente se obtiene con `client_ip.resolve_client` (ver ese
    módulo para el modelo de confianza). `trusted_proxy_hops` se lee de
    `NERSIVO_TRUSTED_PROXY_HOPS` si no se indica.
    """

    def __init__(
        self,
        app,
        max_requests: int = 30,
        window_seconds: int = 60,
        trusted_proxy_hops: int | None = None,
        trusted_proxy_networks=None,
    ):
        super().__init__(app)
        self.limiter = InMemoryRateLimiter(max_requests, window_seconds)
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

    async def dispatch(self, request: Request, call_next):
        if request.url.path.startswith("/analyze/"):
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
            allowed, retry_after = self.limiter.allow(identity.key)

            if not allowed:
                return JSONResponse(
                    status_code=429,
                    content={
                        "detail": (
                            "Demasiadas solicitudes de análisis. "
                            "Inténtalo de nuevo más tarde."
                        )
                    },
                    headers={"Retry-After": str(retry_after)},
                )

        return await call_next(request)
