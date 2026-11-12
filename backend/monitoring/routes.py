"""
Endpoints de monitorización.

- `POST   /monitor`               activa la monitorización (gratuita en pruebas).
                                  Limitada por IP (middleware, `rate_limit.py`) y a
                                  N activaciones simultáneas (`MonitorService`).
- `GET    /monitor`               estado (cabecera `X-Monitor-Token`).
- `DELETE /monitor`               desactiva (cabecera `X-Monitor-Token`).
- `POST   /internal/monitor/run`  job periódico (cabecera `X-Cron-Token`).

No hay cuentas de usuario: el navegador guarda el token que devuelve la
activación. El token va en una cabecera (no en la URL) para que no quede en
los logs de acceso.

La base de datos se inicializa de forma perezosa: si no está disponible, solo
fallan estos endpoints (503) y `/analyze` y `/guides` siguen funcionando.
"""

import hmac
import threading
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel

from .config import MonitorSettings
from .repository import repository_from_url
from .service import MonitorLimitError, MonitorService

router = APIRouter()

_service: Optional[MonitorService] = None
_service_lock = threading.Lock()


def get_service() -> MonitorService:
    """Servicio singleton (creado en el primer uso). 503 si no se puede iniciar."""
    global _service
    with _service_lock:
        if _service is None:
            try:
                settings = MonitorSettings.from_env()
                repo = repository_from_url(settings.database_url)
                repo.init_schema()
                _service = MonitorService(repo, settings)
            except Exception as exc:  # noqa: BLE001
                raise HTTPException(status_code=503, detail="monitoring_unavailable") from exc
        return _service


def reset_service() -> None:
    """Olvida el servicio cacheado (tests)."""
    global _service
    with _service_lock:
        _service = None


class ActivateRequest(BaseModel):
    """Cuerpo de `POST /monitor`."""

    domain: str


def _require_token(token: Optional[str]) -> str:
    if not token:
        raise HTTPException(status_code=401, detail="missing_monitor_token")
    return token


@router.post("/monitor", status_code=201)
def activate_monitor(
    body: ActivateRequest, service: MonitorService = Depends(get_service)
) -> Dict[str, Any]:
    """Activa la monitorización y devuelve el token de gestión (solo esta vez)."""
    try:
        token, view = service.activate(body.domain)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except MonitorLimitError as exc:
        # Solo los límites que se liberan con el tiempo (`monitor_busy`) llevan
        # `Retry-After`; los de capacidad y dominio no cambian.
        headers = {"Retry-After": str(exc.retry_after)} if exc.retry_after else None
        raise HTTPException(status_code=429, detail=exc.code, headers=headers) from exc
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=503, detail="monitoring_unavailable") from exc
    return {"token": token, "monitor": view}


@router.get("/monitor")
def get_monitor(
    x_monitor_token: Optional[str] = Header(default=None),
    service: MonitorService = Depends(get_service),
) -> Dict[str, Any]:
    """Estado de la monitorización asociada al token."""
    view = service.status(_require_token(x_monitor_token))
    if view is None:
        raise HTTPException(status_code=404, detail="monitor_not_found")
    return view


@router.delete("/monitor")
def delete_monitor(
    x_monitor_token: Optional[str] = Header(default=None),
    service: MonitorService = Depends(get_service),
) -> Dict[str, Any]:
    """Desactiva la monitorización (idempotente)."""
    view = service.deactivate(_require_token(x_monitor_token))
    if view is None:
        raise HTTPException(status_code=404, detail="monitor_not_found")
    return view


@router.post("/internal/monitor/run")
def run_monitor_job(x_cron_token: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    """
    Ejecuta las comprobaciones vencidas (lo llama un cron externo).

    Si `NERSIVO_CRON_TOKEN` no está definido, el endpoint no existe (404);
    con un token incorrecto responde 403.
    """
    expected = MonitorSettings.from_env().cron_token
    if not expected:
        raise HTTPException(status_code=404, detail="Not Found")
    if not x_cron_token or not hmac.compare_digest(x_cron_token, expected):
        raise HTTPException(status_code=403, detail="invalid_cron_token")
    return get_service().run_due().to_dict()
