"""
Cliente RDAP seguro para Nersivo.

Flujo:
1. Descubre el servidor RDAP autoritativo del TLD con el bootstrap oficial de
   IANA (RFC 9224): https://data.iana.org/rdap/dns.json (con caché en memoria).
2. Consulta `<servidor>/domain/<dominio-registrable>`.
3. Extrae SOLO los campos que el servidor devuelva (no todos los TLD ofrecen
   los mismos) y lista en `missing_fields` los que faltan.

Seguridad (reutiliza `net_safety`, no introduce una vía alternativa):
- Cada URL (bootstrap, consulta y cada redirect) se valida con
  `resolve_public_ips`: todas las IPs deben ser públicas y se conecta a la IP
  ya validada (sin segunda resolución DNS -> sin DNS rebinding).
- Solo HTTPS, sin credenciales en la URL y solo puertos 80/443 permitidos por
  `net_safety`; el esquema nunca puede degradarse a HTTP en un redirect.
- Redirects limitados y revalidados en cada salto; nunca se siguen los
  enlaces (`links`) que el JSON RDAP pueda contener.
- Timeout por petición y plazo global (`deadline`); tamaño de respuesta
  acotado; ningún dato del usuario decide a qué servidor se conecta (el
  servidor sale del bootstrap de IANA).

NOTA: `net_safety.safe_get` no devuelve el cuerpo de la respuesta (RDAP lo
necesita), y `net_safety.py` no debe modificarse en esta fase. Por eso este
módulo reutiliza sus primitivas (`resolve_public_ips`, `_fetch_once`,
`_validate_url_shape`) en un bucle de redirects propio y mínimo. Si más
adelante `safe_get` ofrece devolver el cuerpo, `_http_get_json` puede
sustituirse por él.

.es y otros TLD "conservadores": ver `_CONSERVATIVE_TLDS`.
"""

import json
import socket
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import httpx

from .. import net_safety
from .models import (
    RDAP_BLOCKED,
    RDAP_BOOTSTRAP_UNAVAILABLE,
    RDAP_HTTP_ERROR,
    RDAP_INVALID_RESPONSE,
    RDAP_NETWORK_ERROR,
    RDAP_NOT_FOUND,
    RDAP_OK,
    RDAP_RATE_LIMITED,
    RDAP_SKIPPED,
    RDAP_TIMEOUT,
    RDAP_UNSUPPORTED_TLD,
    RdapResult,
)

# --- Constantes de configuración -------------------------------------------
IANA_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
_USER_AGENT = "Nersivo/1.0 (Domain Analyzer)"
_ACCEPT = "application/rdap+json, application/json;q=0.9"
_TIMEOUT_SECONDS = 5.0
_MAX_REDIRECTS = 3
_MAX_BODY_BYTES = 2 * 1024 * 1024  # el bootstrap de IANA ronda cientos de KB
_BOOTSTRAP_TTL_SECONDS = 24 * 3600
_BOOTSTRAP_FAILURE_TTL_SECONDS = 300  # evita bloquear cada análisis si IANA falla

# TLD cuyo servicio RDAP NO se asume equivalente al de un gTLD. Hoy: `.es`.
# Para estos TLD: (a) no se usa ningún servidor que no figure en el bootstrap,
# (b) la cobertura se marca como `limited`, (c) un 404 no se interpreta como
# "el dominio no existe", y (d) la respuesta debe parecer un objeto `domain`.
_CONSERVATIVE_TLDS = frozenset({"es"})

# Campos que intentamos extraer (para `missing_fields`).
_EXPECTED_FIELDS = (
    "registrar",
    "registrar_iana_id",
    "created",
    "expires",
    "updated",
    "domain_status",
    "nameservers",
    "dnssec",
)


class _DeadlineExceeded(Exception):
    """Se agotó el plazo global de la consulta RDAP."""


class _BodyTooLarge(Exception):
    """El cuerpo de la respuesta supera el máximo permitido."""


# ---------------------------------------------------------------------------
# HTTP seguro con cuerpo
# ---------------------------------------------------------------------------
@dataclass
class _HttpJson:
    status_code: int
    body: Any  # JSON parseado (o None si no hay cuerpo parseable)
    final_url: str


def _http_get_json(
    url: str,
    *,
    timeout: float,
    deadline: float,
    max_redirects: int = _MAX_REDIRECTS,
    max_bytes: int = _MAX_BODY_BYTES,
    transport: Optional[httpx.BaseTransport] = None,
) -> _HttpJson:
    """
    GET que devuelve JSON, con validación SSRF en la URL y en cada redirect.

    Raises:
        net_safety.BlockedDestinationError: destino/redirect no permitido.
        httpx.TooManyRedirects, httpx.HTTPError, socket.gaierror: errores de red.
        _DeadlineExceeded: se agotó el plazo global.
        _BodyTooLarge: cuerpo demasiado grande.
        ValueError: el cuerpo no es JSON válido.
    """
    headers = {"User-Agent": _USER_AGENT, "Accept": _ACCEPT}
    current = httpx.URL(url)
    redirects = 0

    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise _DeadlineExceeded()

        is_redirect_hop = redirects > 0
        try:
            net_safety._validate_url_shape(current)
            if current.scheme != "https":  # RDAP exige TLS: sin degradación
                raise net_safety.BlockedDestinationError(net_safety.BLOCKED_REDIRECT)
            port = current.port or net_safety._default_port(current.scheme)
            ips = net_safety.resolve_public_ips(current.host, port)
        except net_safety.BlockedDestinationError as exc:
            if is_redirect_hop:
                raise net_safety.BlockedDestinationError(
                    net_safety.BLOCKED_REDIRECT
                ) from exc
            raise

        with httpx.Client(
            timeout=min(timeout, remaining), follow_redirects=False, transport=transport
        ) as client:
            response = net_safety._fetch_once(client, current, headers, ips)
            try:
                status = response.status_code
                location = response.headers.get("location")
                if status in net_safety._REDIRECT_STATUSES and location:
                    redirects += 1
                    if redirects > max_redirects:
                        raise httpx.TooManyRedirects(
                            f"Exceeded maximum allowed redirects ({max_redirects}).",
                            request=response.request,
                        )
                    try:
                        current = httpx.URL(httpx.URL(str(current)).join(location))
                    except Exception as exc:  # noqa: BLE001 - Location malformada
                        raise net_safety.BlockedDestinationError(
                            net_safety.BLOCKED_REDIRECT
                        ) from exc
                    continue

                raw = _read_limited(response, max_bytes)
            finally:
                response.close()

        body: Any = None
        if raw:
            try:
                body = json.loads(raw)
            except ValueError as exc:
                if 200 <= status < 300:
                    raise ValueError("invalid_json") from exc
        return _HttpJson(status_code=status, body=body, final_url=str(current))


def _read_limited(response: httpx.Response, max_bytes: int) -> bytes:
    """Lee el cuerpo en streaming sin superar `max_bytes`."""
    chunks: List[bytes] = []
    total = 0
    for chunk in response.iter_bytes():
        total += len(chunk)
        if total > max_bytes:
            raise _BodyTooLarge()
        chunks.append(chunk)
    return b"".join(chunks)


# ---------------------------------------------------------------------------
# Bootstrap de IANA (con caché)
# ---------------------------------------------------------------------------
_cache_lock = threading.Lock()
_bootstrap_cache: Optional[Tuple[float, Dict[str, List[str]]]] = None
_bootstrap_failure_until: float = 0.0


def clear_bootstrap_cache() -> None:
    """Vacía la caché del bootstrap (útil en tests)."""
    global _bootstrap_cache, _bootstrap_failure_until
    with _cache_lock:
        _bootstrap_cache = None
        _bootstrap_failure_until = 0.0


def parse_bootstrap(payload: Any) -> Dict[str, List[str]]:
    """
    Convierte el JSON del bootstrap en `tld -> [urls https]`.

    Formato (RFC 9224): `{"services": [[["com", "net"], ["https://..."]], ...]}`.
    Las entradas mal formadas se ignoran; las URLs no HTTPS se descartan.

    Raises:
        ValueError: si el documento no tiene la estructura esperada.
    """
    if not isinstance(payload, dict) or not isinstance(payload.get("services"), list):
        raise ValueError("invalid_bootstrap")
    mapping: Dict[str, List[str]] = {}
    for service in payload["services"]:
        if (
            not isinstance(service, list)
            or len(service) != 2
            or not isinstance(service[0], list)
            or not isinstance(service[1], list)
        ):
            continue
        urls = [
            u for u in service[1] if isinstance(u, str) and u.lower().startswith("https://")
        ]
        if not urls:
            continue
        for tld in service[0]:
            if isinstance(tld, str) and tld:
                mapping.setdefault(tld.strip().lower(), urls)
    return mapping


def _load_bootstrap(
    *, timeout: float, deadline: float, transport: Optional[httpx.BaseTransport]
) -> Dict[str, List[str]]:
    """Devuelve el bootstrap cacheado o lo descarga de IANA."""
    global _bootstrap_cache, _bootstrap_failure_until
    now = time.monotonic()
    with _cache_lock:
        if _bootstrap_cache and now - _bootstrap_cache[0] < _BOOTSTRAP_TTL_SECONDS:
            return _bootstrap_cache[1]
        if now < _bootstrap_failure_until:
            raise ValueError("bootstrap_recently_failed")

    try:
        result = _http_get_json(
            IANA_BOOTSTRAP_URL, timeout=timeout, deadline=deadline, transport=transport
        )
        if result.status_code != 200:
            raise ValueError(f"bootstrap_http_{result.status_code}")
        mapping = parse_bootstrap(result.body)
    except Exception:
        with _cache_lock:
            _bootstrap_failure_until = time.monotonic() + _BOOTSTRAP_FAILURE_TTL_SECONDS
        raise

    with _cache_lock:
        _bootstrap_cache = (time.monotonic(), mapping)
    return mapping


# ---------------------------------------------------------------------------
# Extracción de campos RDAP
# ---------------------------------------------------------------------------
def _vcard_field(vcard_array: Any, wanted: str) -> Optional[str]:
    """Valor de una propiedad (p. ej. `fn`) de un vCard jCard."""
    if not isinstance(vcard_array, list) or len(vcard_array) < 2:
        return None
    for prop in vcard_array[1] if isinstance(vcard_array[1], list) else []:
        if isinstance(prop, list) and len(prop) >= 4 and prop[0] == wanted:
            value = prop[3]
            if isinstance(value, str) and value.strip():
                return value.strip()
    return None


def _find_registrar(entities: Any, depth: int = 0) -> Tuple[Optional[str], Optional[str]]:
    """Busca la entidad con rol `registrar` -> `(nombre, iana_id)`."""
    if not isinstance(entities, list) or depth > 2:
        return None, None
    for entity in entities:
        if not isinstance(entity, dict):
            continue
        roles = entity.get("roles")
        if isinstance(roles, list) and "registrar" in roles:
            name = _vcard_field(entity.get("vcardArray"), "fn")
            iana_id: Optional[str] = None
            public_ids = entity.get("publicIds")
            for pid in public_ids if isinstance(public_ids, list) else []:
                if (
                    isinstance(pid, dict)
                    and str(pid.get("type", "")).strip().lower() == "iana registrar id"
                    and pid.get("identifier") not in (None, "")
                ):
                    iana_id = str(pid["identifier"]).strip()
                    break
            if name or iana_id:
                return name, iana_id
        nested = _find_registrar(entity.get("entities"), depth + 1)
        if nested != (None, None):
            return nested
    return None, None


def _event_date(events: Any, action: str) -> Optional[str]:
    """Fecha (tal cual la da el servidor) de un evento RDAP concreto."""
    for event in events if isinstance(events, list) else []:
        if (
            isinstance(event, dict)
            and str(event.get("eventAction", "")).strip().lower() == action
            and isinstance(event.get("eventDate"), str)
        ):
            return event["eventDate"]
    return None


def parse_domain_object(payload: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
    """
    Extrae del objeto `domain` RDAP los campos disponibles.

    Solo se incluyen en `data` los campos realmente presentes. `updated` usa
    únicamente el evento `last changed` (el evento `last update of RDAP
    database` es la fecha de la base de datos, no del dominio).

    Returns:
        `(data, missing_fields)`.
    """
    data: Dict[str, Any] = {}

    registrar, iana_id = _find_registrar(payload.get("entities"))
    if registrar:
        data["registrar"] = registrar
    if iana_id:
        data["registrar_iana_id"] = iana_id

    events = payload.get("events")
    for key, action in (
        ("created", "registration"),
        ("expires", "expiration"),
        ("updated", "last changed"),
    ):
        value = _event_date(events, action)
        if value:
            data[key] = value

    statuses = payload.get("status")
    if isinstance(statuses, list):
        cleaned = [s.strip() for s in statuses if isinstance(s, str) and s.strip()]
        if cleaned:
            data["domain_status"] = cleaned

    nameservers: List[str] = []
    for ns in payload.get("nameservers") if isinstance(payload.get("nameservers"), list) else []:
        if isinstance(ns, dict) and isinstance(ns.get("ldhName"), str) and ns["ldhName"].strip():
            host = ns["ldhName"].strip().lower().rstrip(".")
            if host not in nameservers:
                nameservers.append(host)
    if nameservers:
        data["nameservers"] = nameservers

    secure_dns = payload.get("secureDNS")
    if isinstance(secure_dns, dict):
        dnssec: Dict[str, Any] = {}
        if isinstance(secure_dns.get("delegationSigned"), bool):
            dnssec["delegation_signed"] = secure_dns["delegationSigned"]
        if isinstance(secure_dns.get("zoneSigned"), bool):
            dnssec["zone_signed"] = secure_dns["zoneSigned"]
        if dnssec:
            data["dnssec"] = dnssec

    missing = [f for f in _EXPECTED_FIELDS if f not in data]
    return data, missing


# ---------------------------------------------------------------------------
# Consulta principal
# ---------------------------------------------------------------------------
def _server_host(url: str) -> Optional[str]:
    try:
        return httpx.URL(url).host or None
    except Exception:  # noqa: BLE001
        return None


def lookup_rdap(
    registrable_domain: str,
    *,
    timeout: float = _TIMEOUT_SECONDS,
    deadline_seconds: float = 12.0,
    transport: Optional[httpx.BaseTransport] = None,
) -> RdapResult:
    """
    Consulta RDAP de un dominio registrable. Nunca lanza excepciones.

    Args:
        registrable_domain: Dominio ya validado (p. ej. `empresa.com`).
        timeout: timeout por petición HTTP (segundos).
        deadline_seconds: plazo total para bootstrap + consulta.
        transport: transporte httpx alternativo (solo para tests).

    Returns:
        `RdapResult` con `status` indicando qué ha pasado. Que un TLD no tenga
        RDAP (`unsupported_tld`) es un resultado normal, no un error.
    """
    tld = registrable_domain.rsplit(".", 1)[-1].lower()
    conservative = tld in _CONSERVATIVE_TLDS
    base = RdapResult(
        status=RDAP_OK,
        coverage="limited" if conservative else "standard",
    )
    if conservative:
        base.notes.append(
            f".{tld} se trata de forma conservadora: no se asume que su servicio "
            "RDAP exista ni que ofrezca los mismos campos que un gTLD."
        )

    deadline = time.monotonic() + deadline_seconds

    # 1) Bootstrap de IANA
    try:
        bootstrap = _load_bootstrap(timeout=timeout, deadline=deadline, transport=transport)
    except Exception as exc:  # noqa: BLE001 - el módulo nunca debe romper el análisis
        return _failure(base, RDAP_BOOTSTRAP_UNAVAILABLE, _error_reason(exc))

    servers = bootstrap.get(tld)
    if not servers:
        base.status = RDAP_UNSUPPORTED_TLD
        base.reason = "tld_not_in_iana_bootstrap"
        base.conclusive = False
        base.notes.append(
            f"IANA no publica un servidor RDAP para .{tld}; no se consulta WHOIS "
            "ni ningún otro servicio alternativo."
        )
        return base

    # 2) Consulta al servidor autoritativo
    server = servers[0]
    base.server = _server_host(server)
    url = f"{server.rstrip('/')}/domain/{registrable_domain}"
    try:
        result = _http_get_json(url, timeout=timeout, deadline=deadline, transport=transport)
    except Exception as exc:  # noqa: BLE001
        return _failure(base, *_classify_exception(exc))

    status = result.status_code
    if status == 404:
        base.status = RDAP_NOT_FOUND
        base.reason = "domain_not_found"
        if conservative:
            base.conclusive = False
            base.notes.append(
                "Un 404 en este TLD no es concluyente: no se afirma que el "
                "dominio no esté registrado."
            )
        return base
    if status == 429:
        return _failure(base, RDAP_RATE_LIMITED, "rate_limited")
    if status != 200:
        return _failure(base, RDAP_HTTP_ERROR, f"http_{status}")

    payload = result.body
    if not isinstance(payload, dict):
        return _failure(base, RDAP_INVALID_RESPONSE, "not_a_json_object")
    object_class = payload.get("objectClassName")
    if object_class is not None and object_class != "domain":
        return _failure(base, RDAP_INVALID_RESPONSE, "unexpected_object_class")
    if conservative and object_class != "domain" and not payload.get("ldhName"):
        return _failure(base, RDAP_INVALID_RESPONSE, "not_a_domain_object")

    base.data, base.missing_fields = parse_domain_object(payload)
    return base


def _failure(base: RdapResult, status: str, reason: str) -> RdapResult:
    base.status = status
    base.reason = reason
    base.conclusive = False
    return base


def _error_reason(exc: Exception) -> str:
    if isinstance(exc, _DeadlineExceeded):
        return "deadline_exceeded"
    if isinstance(exc, httpx.TimeoutException):
        return "timeout"
    if isinstance(exc, net_safety.BlockedDestinationError):
        return exc.code
    if isinstance(exc, _BodyTooLarge):
        return "response_too_large"
    if isinstance(exc, ValueError):
        return str(exc) or "invalid_data"
    return "network_error"


def _classify_exception(exc: Exception) -> Tuple[str, str]:
    """Traduce una excepción de la consulta RDAP a `(status, reason)`."""
    if isinstance(exc, (_DeadlineExceeded, httpx.TimeoutException)):
        return RDAP_TIMEOUT, _error_reason(exc)
    if isinstance(exc, net_safety.BlockedDestinationError):
        return RDAP_BLOCKED, exc.code
    if isinstance(exc, (_BodyTooLarge, ValueError)):
        return RDAP_INVALID_RESPONSE, _error_reason(exc)
    if isinstance(exc, httpx.TooManyRedirects):
        return RDAP_NETWORK_ERROR, "too_many_redirects"
    if isinstance(exc, socket.gaierror):
        return RDAP_NETWORK_ERROR, "dns_error"
    if isinstance(exc, httpx.HTTPError):
        return RDAP_NETWORK_ERROR, "connection_error"
    return RDAP_NETWORK_ERROR, "unexpected_error"


def skipped_result() -> RdapResult:
    """Resultado cuando el llamador desactiva RDAP."""
    return RdapResult(status=RDAP_SKIPPED, reason="disabled_by_caller", conclusive=False)
