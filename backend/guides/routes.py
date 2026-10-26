"""
Endpoint `POST /guides`.

Recibe el JSON que el frontend ya tiene de `/analyze/{domain}` y devuelve las
guías de solución. NO modifica el contrato de `/analyze`.

Seguridad:
- El cuerpo se valida con el modelo Pydantic `AnalyzeResponse` (estructura
  estricta) y el dominio se revalida con `validate_and_normalize_domain`.
- El texto de las guías sale del catálogo; el contenido del cuerpo solo se
  usa para elegir guías y para mostrar datos del propio análisis.
- La única operación de red es una consulta DNS NS (dnspython, con timeout) y
  solo si alguna guía la necesita: no hay conexiones HTTP ni a IPs.
"""

from fastapi import APIRouter, HTTPException

from ..domain_utils import validate_and_normalize_domain
from ..models import AnalyzeResponse
from ..providers import identify_providers, lookup_nameservers
from .builder import build_guides, needs_dns_panel
from .models import GuidesResponse, ProviderOut, ProvidersOut

router = APIRouter()


def _out(match) -> "ProviderOut | None":
    if match is None:
        return None
    return ProviderOut(
        id=match.id, name=match.name, confidence=match.confidence, evidence=list(match.evidence)
    )


@router.post("/guides", response_model=GuidesResponse)
def post_guides(analysis: AnalyzeResponse) -> GuidesResponse:
    """Genera las guías «Cómo solucionarlo» de un análisis ya realizado."""
    try:
        domain = validate_and_normalize_domain(analysis.domain)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    normalized = analysis.model_copy(update={"domain": domain})
    nameservers = lookup_nameservers(domain) if needs_dns_panel(normalized) else []
    ctx = identify_providers(normalized, nameservers)
    return GuidesResponse(
        domain=domain,
        providers=ProvidersOut(
            mail=_out(ctx.mail),
            dns_panel=_out(ctx.dns_panel),
            mail_intermediary=_out(ctx.mail_intermediary),
        ),
        guides=build_guides(normalized, ctx),
    )
