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


class AnalyzeRateLimitMiddleware(BaseHTTPMiddleware):
    """Aplica el límite únicamente al endpoint de análisis."""

    def __init__(self, app, max_requests: int = 30, window_seconds: int = 60):
        super().__init__(app)
        self.limiter = InMemoryRateLimiter(max_requests, window_seconds)

    async def dispatch(self, request: Request, call_next):
        if request.url.path.startswith("/analyze/"):
            client_host = request.client.host if request.client else "unknown"
            allowed, retry_after = self.limiter.allow(client_host)

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
