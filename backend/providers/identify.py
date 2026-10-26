"""
Identificación de proveedor de correo (MX) y de panel DNS (NS).

Reglas de fiabilidad (nunca se presenta una inferencia como certeza):

- Correo: solo se afirma un proveedor (`confidence="high"`) si TODOS los
  registros MX del dominio pertenecen al mismo proveedor reconocido y este es
  un servicio de buzones. Pasarelas de seguridad (Mimecast, Proofpoint...) y
  servicios de reenvío no se consideran "el proveedor de correo": indican
  que hay un intermediario, no dónde están los buzones.
- Panel DNS: se afirma solo si TODOS los nameservers son del mismo proveedor.
- Mezclas, hosts sin reconocer o datos ausentes -> `None` (guía genérica).

Las tablas de patrones viven en `backend/infrastructure/providers.py` (una
única fuente de verdad, ya probada contra imitaciones tipo `evilgoogle.com`).
"""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ..infrastructure import providers as patterns
from ..infrastructure.providers import ProviderRule


@dataclass(frozen=True)
class ProviderMatch:
    """Proveedor identificado, con la evidencia que lo respalda."""

    id: str
    name: str
    confidence: str  # siempre "high": si no hay certeza suficiente, no se devuelve
    evidence: Tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class ProviderContext:
    """Proveedores identificables para un dominio (cada uno puede ser None)."""

    mail: Optional[ProviderMatch] = None
    dns_panel: Optional[ProviderMatch] = None
    # Intermediario de correo detectado (pasarela/reenvío); informativo.
    mail_intermediary: Optional[ProviderMatch] = None


def provider_id(name: str) -> str:
    """Identificador estable (slug) a partir del nombre de la regla."""
    return re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")


def _unanimous(
    hosts: Sequence[str], matcher, label: str
) -> Tuple[Optional[ProviderRule], Tuple[str, ...]]:
    """Regla común a TODOS los hosts, o None si hay mezcla/hosts sin reconocer."""
    if not hosts:
        return None, ()
    rules: List[Optional[ProviderRule]] = [matcher(h) for h in hosts]
    if any(r is None for r in rules):
        return None, ()
    names = {r.name for r in rules if r is not None}
    if len(names) != 1:
        return None, ()
    return rules[0], tuple(f"{label} {h}" for h in hosts[:5])


def _mx_hosts(analysis: Any) -> List[str]:
    """Hostnames MX del check `mx` (ya resueltos por Nersivo)."""
    details = _details(analysis, "mx")
    hosts: List[str] = []
    for record in details.get("records") or []:
        if isinstance(record, dict) and isinstance(record.get("hostname"), str):
            host = patterns.normalize_host(record["hostname"])
            if host:
                hosts.append(host)
    return hosts


def as_dict(analysis: Any) -> Dict[str, Any]:
    """`AnalyzeResponse` (pydantic) o dict -> dict plano."""
    if isinstance(analysis, dict):
        return analysis
    dump = getattr(analysis, "model_dump", None) or getattr(analysis, "dict")
    return dump(mode="json") if getattr(analysis, "model_dump", None) else dump()


def _details(analysis: Any, check: str) -> Dict[str, Any]:
    """`details` de un check del análisis (dict vacío si no existe)."""
    result = (as_dict(analysis).get("checks") or {}).get(check) or {}
    details = result.get("details")
    return details if isinstance(details, dict) else {}


def identify_mail_provider(analysis: Any) -> Tuple[Optional[ProviderMatch], Optional[ProviderMatch]]:
    """
    Proveedor de correo e intermediario a partir de los MX.

    Returns:
        `(proveedor_de_buzones, intermediario)`; cada uno puede ser None.
    """
    hosts = _mx_hosts(analysis)
    rule, evidence = _unanimous(hosts, patterns.match_mx, "MX")
    if rule is None:
        return None, None
    match = ProviderMatch(provider_id(rule.name), rule.name, "high", evidence)
    if rule.role is not None:  # pasarela de seguridad / reenvío
        return None, match
    return match, None


def identify_dns_panel(nameservers: Sequence[str]) -> Optional[ProviderMatch]:
    """Proveedor del panel DNS a partir de los nameservers (todos del mismo)."""
    hosts = [patterns.normalize_host(h) for h in nameservers if h]
    rule, evidence = _unanimous(hosts, patterns.match_nameserver, "NS")
    if rule is None:
        return None
    return ProviderMatch(provider_id(rule.name), rule.name, "high", evidence)


def identify_providers(analysis: Any, nameservers: Sequence[str] = ()) -> ProviderContext:
    """
    Identifica los proveedores disponibles para un análisis.

    Args:
        analysis: `AnalyzeResponse` (o su dict equivalente).
        nameservers: NS del dominio registrable (opcional).
    """
    mail, intermediary = identify_mail_provider(analysis)
    return ProviderContext(
        mail=mail,
        dns_panel=identify_dns_panel(nameservers),
        mail_intermediary=intermediary,
    )
