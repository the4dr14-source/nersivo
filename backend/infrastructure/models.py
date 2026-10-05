"""
Modelos INTERNOS del módulo de infraestructura de Nersivo.

Son dataclasses simples y NO forman parte del contrato JSON público ni de los
modelos Pydantic de `backend/models.py`. Cuando el módulo se incorpore al
análisis principal, será esa integración la que decida qué campos se exponen.

Semántica de las detecciones (muy importante):

- `status == "detected"`: señal DIRECTA y explícita. El nombre de un
  nameserver, de un MX o de un CNAME pertenece al espacio de nombres del
  proveedor (p. ej. `ada.ns.cloudflare.com`). Es un hecho observable, no una
  suposición, aunque describe lo que apunta el DNS y no un contrato comercial.
- `status == "inferred"`: señal INDIRECTA (p. ej. la IP pertenece al ASN de una
  empresa). Es compatible con ese proveedor, pero no lo demuestra.
- `confidence` (`high` / `medium` / `low`) indica cuánta evidencia respalda la
  detección, no si es un hecho o una inferencia (eso lo dice `status`).
"""

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

# --- Estado de una detección -----------------------------------------------
DETECTED = "detected"
INFERRED = "inferred"

# --- Confianza ---------------------------------------------------------------
CONFIDENCE_HIGH = "high"
CONFIDENCE_MEDIUM = "medium"
CONFIDENCE_LOW = "low"

# --- Tipos de detección ------------------------------------------------------
KIND_DNS_PROVIDER = "dns_provider"
KIND_EMAIL_SERVICE = "email_service"
KIND_WEB_INFRASTRUCTURE = "web_infrastructure"

ALL_KINDS = (KIND_DNS_PROVIDER, KIND_EMAIL_SERVICE, KIND_WEB_INFRASTRUCTURE)

# --- Origen de la evidencia --------------------------------------------------
BASIS_NAMESERVER = "nameserver"
BASIS_MX = "mx"
BASIS_CNAME = "cname"
BASIS_ASN = "asn"

# --- Estados de la consulta RDAP ---------------------------------------------
RDAP_OK = "ok"
RDAP_SKIPPED = "skipped"
RDAP_UNSUPPORTED_TLD = "unsupported_tld"
RDAP_BOOTSTRAP_UNAVAILABLE = "bootstrap_unavailable"
RDAP_NOT_FOUND = "not_found"
RDAP_RATE_LIMITED = "rate_limited"
RDAP_TIMEOUT = "timeout"
RDAP_NETWORK_ERROR = "network_error"
RDAP_BLOCKED = "blocked"
RDAP_INVALID_RESPONSE = "invalid_response"
RDAP_HTTP_ERROR = "http_error"


@dataclass
class Detection:
    """Un proveedor/servicio identificado a partir de patrones conocidos."""

    kind: str
    name: str
    status: str  # DETECTED | INFERRED
    confidence: str  # high | medium | low
    basis: str  # nameserver | mx | cname | asn
    role: Optional[str] = None
    evidence: List[str] = field(default_factory=list)
    note: Optional[str] = None


@dataclass
class RdapResult:
    """
    Resultado de la consulta RDAP.

    `data` solo contiene los campos que el servidor ha devuelto realmente;
    `missing_fields` lista los que no aparecieron (no todos los TLD ofrecen
    los mismos campos). `conclusive` es False cuando un 404 u otra respuesta
    no permite sacar conclusiones fiables (TLD tratados de forma conservadora).
    """

    status: str
    reason: Optional[str] = None
    server: Optional[str] = None  # solo el host, sin ruta
    coverage: str = "standard"  # standard | limited
    conclusive: bool = True
    data: Dict[str, Any] = field(default_factory=dict)
    missing_fields: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


@dataclass
class InfrastructureReport:
    """Informe completo de infraestructura de un dominio."""

    domain: str
    registrable_domain: str
    mail_domain: str
    tld: str
    rdap: RdapResult
    dns: Dict[str, Any]
    dnssec: Dict[str, Any]
    detections: Dict[str, List[Detection]]
    unrecognized: Dict[str, List[str]]
    cross_checks: Dict[str, Any]
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convierte el informe a un diccionario serializable en JSON."""
        return asdict(self)
