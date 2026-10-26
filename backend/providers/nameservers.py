"""
Consulta NS ligera para saber dónde se gestiona el DNS de un dominio.

Solo hace una consulta DNS (dnspython, con `lifetime` acotado) sobre el
dominio registrable. No abre conexiones HTTP ni a ninguna IP devuelta, por lo
que no puede usarse para alcanzar destinos internos. Cualquier fallo devuelve
una lista vacía (la guía será genérica); nunca lanza excepciones.
"""

from typing import List

from ..domain_utils import get_registrable_domain, validate_and_normalize_domain
from ..infrastructure.dns_lookup import query_records
from ..infrastructure.providers import normalize_host

_NS_TIMEOUT_SECONDS = 4.0


def lookup_nameservers(domain: str, *, lifetime: float = _NS_TIMEOUT_SECONDS) -> List[str]:
    """Nameservers (normalizados) del dominio registrable de `domain`."""
    try:
        # Defensa propia: nunca se consulta un nombre sin validar (localhost,
        # IPs, esquemas...), aunque el llamador ya lo haya validado.
        registrable = get_registrable_domain(validate_and_normalize_domain(domain))
    except Exception:  # noqa: BLE001 - nunca romper la generación de guías
        return []
    result = query_records(registrable, "NS", lifetime=lifetime)
    hosts: List[str] = []
    for rdata in result.records:
        host = normalize_host(str(getattr(rdata, "target", "")))
        if host and host not in hosts:
            hosts.append(host)
    return hosts
