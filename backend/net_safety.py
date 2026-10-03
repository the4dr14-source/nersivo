"""
Protección SSRF de Nersivo.

Nersivo realiza peticiones HTTP/HTTPS (y una conexión TLS) hacia dominios que
introduce el usuario. Sin protección, un dominio público cuyo DNS apunte a
`127.0.0.1`, o un redirect hacia `http://169.254.169.254/`, haría que el
servidor de Nersivo conectase con recursos internos (SSRF).

Este módulo centraliza las defensas:

1. `resolve_public_ips`  -> resuelve un hostname y exige que TODAS sus IPs sean
   públicas (módulo `ipaddress`, nunca comparaciones de strings).
2. `create_safe_connection` -> conexión TCP a una IP ya validada (usada por el
   check HTTPS).
3. `safe_get` -> GET HTTP/HTTPS que sigue los redirects de forma MANUAL,
   validando cada destino antes de conectar y conectando a la IP validada
   (evita DNS rebinding: no se vuelve a resolver el nombre entre validar y
   conectar).

Los códigos de bloqueo (`blocked_private_ip`, `blocked_non_public_ip`,
`blocked_redirect`) son internos y NO incluyen IPs ni datos del servidor.
"""

import ipaddress
import socket
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urljoin

import httpx

# --- Códigos de bloqueo ----------------------------------------------------
BLOCKED_PRIVATE_IP = "blocked_private_ip"
BLOCKED_NON_PUBLIC_IP = "blocked_non_public_ip"
BLOCKED_REDIRECT = "blocked_redirect"

BLOCKED_CODES = frozenset(
    {BLOCKED_PRIVATE_IP, BLOCKED_NON_PUBLIC_IP, BLOCKED_REDIRECT}
)

# Mensaje común (sin detalles internos) cuando se bloquea un destino.
BLOCKED_SUMMARY = (
    "Nersivo no ha podido verificar el destino porque la conexión fue "
    "bloqueada por motivos de seguridad."
)

# Solo se permiten estos puertos en los redirects (evita usar Nersivo para
# sondear servicios en puertos arbitrarios de hosts públicos).
_ALLOWED_PORTS = {80, 443}
_REDIRECT_STATUSES = {301, 302, 303, 307, 308}
_MAX_ADDRESSES_TO_TRY = 4


class BlockedDestinationError(Exception):
    """El destino (o un redirect) apunta a una dirección no pública."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


# ---------------------------------------------------------------------------
# Validación de IPs
# ---------------------------------------------------------------------------
def classify_ip(ip_str: str) -> Optional[str]:
    """
    Devuelve None si la IP es pública (permitida) o el código de bloqueo.

    - `blocked_private_ip`: privadas (RFC 1918, ULA), loopback y link-local.
    - `blocked_non_public_ip`: multicast, unspecified, reservadas, CGNAT,
      documentación y cualquier otra dirección no enrutable globalmente.

    Las direcciones IPv6 que embeben una IPv4 (IPv4-mapped `::ffff:a.b.c.d`,
    NAT64 `64:ff9b::/96` y 6to4 `2002::/16`) se evalúan según la IPv4 que
    contienen.
    """
    try:
        ip = ipaddress.ip_address(ip_str.split("%", 1)[0])  # quita zone id
    except ValueError:
        return BLOCKED_NON_PUBLIC_IP

    ip = _unwrap_embedded_ipv4(ip)

    if ip.is_loopback or ip.is_link_local or _is_rfc1918_or_ula(ip):
        return BLOCKED_PRIVATE_IP
    if ip.is_multicast or ip.is_unspecified or ip.is_reserved or not ip.is_global:
        return BLOCKED_NON_PUBLIC_IP
    return None


_PRIVATE_NETWORKS = [
    ipaddress.ip_network(n)
    for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
]
_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_SIXTO4 = ipaddress.ip_network("2002::/16")


def _is_rfc1918_or_ula(ip) -> bool:
    return any(ip.version == n.version and ip in n for n in _PRIVATE_NETWORKS)


def _unwrap_embedded_ipv4(ip):
    """Si una IPv6 embebe una IPv4, devuelve esa IPv4; si no, la misma IP."""
    if ip.version != 6:
        return ip
    if ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    if ip in _NAT64:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    if ip in _SIXTO4:
        return ipaddress.IPv4Address((int(ip) >> 80) & 0xFFFFFFFF)
    return ip


def resolve_public_ips(host: str, port: int) -> List[str]:
    """
    Resuelve `host` y comprueba CADA dirección obtenida.

    Si alguna dirección no es pública se rechaza todo el host (un atacante
    podría mezclar IPs públicas y privadas en la respuesta DNS).

    Raises:
        BlockedDestinationError: si alguna IP no es pública.
        socket.gaierror: si el nombre no resuelve (se propaga tal cual para
            conservar el comportamiento de errores DNS existente).
    """
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    ips: List[str] = []
    for info in infos:
        ip = info[4][0]
        if ip not in ips:
            ips.append(ip)
    if not ips:
        raise socket.gaierror(socket.EAI_NONAME, "no addresses")

    for ip in ips:
        code = classify_ip(ip)
        if code is not None:
            raise BlockedDestinationError(code)
    return ips


def create_safe_connection(host: str, port: int, timeout: float) -> socket.socket:
    """
    Abre una conexión TCP a una IP pública ya validada de `host`.

    Equivalente a `socket.create_connection`, pero valida las IPs antes y
    conecta a la IP validada (sin segunda resolución DNS).
    """
    ips = resolve_public_ips(host, port)
    last_error: Optional[OSError] = None
    for ip in ips[:_MAX_ADDRESSES_TO_TRY]:
        try:
            return socket.create_connection((ip, port), timeout=timeout)
        except socket.timeout:
            raise
        except OSError as exc:
            last_error = exc
    assert last_error is not None
    raise last_error


# ---------------------------------------------------------------------------
# GET con redirects validados
# ---------------------------------------------------------------------------
@dataclass
class SafeResponse:
    """Resultado de `safe_get` (el cuerpo de la respuesta no se descarga)."""

    status_code: int
    final_url: str
    # URLs visitadas en orden (la primera es la solicitada, la última la final).
    redirect_chain: List[str] = field(default_factory=list)


def _default_port(scheme: str) -> int:
    return 443 if scheme == "https" else 80


def _host_header(url: httpx.URL) -> str:
    host = url.host
    if ":" in host:  # IPv6 literal
        host = f"[{host}]"
    if url.port is not None and url.port != _default_port(url.scheme):
        return f"{host}:{url.port}"
    return host


def _fetch_once(
    client: httpx.Client, url: httpx.URL, headers: dict, ips: List[str]
) -> httpx.Response:
    """
    Una petición GET a `url` conectando a una de las IPs ya validadas.

    La URL real se sustituye por la IP (conexión fijada) y se conservan el
    header Host y el SNI/verificación de certificado del hostname original.
    """
    port = url.port or _default_port(url.scheme)
    request_headers = dict(headers)
    request_headers["Host"] = _host_header(url)
    extensions = {"sni_hostname": url.host} if url.scheme == "https" else {}

    last_error: Optional[Exception] = None
    for ip in ips[:_MAX_ADDRESSES_TO_TRY]:
        pinned = url.copy_with(host=ip, port=port)
        request = client.build_request(
            "GET", pinned, headers=request_headers, extensions=extensions
        )
        try:
            return client.send(request, stream=True)
        except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
            last_error = exc
    assert last_error is not None
    raise last_error


def safe_get(
    url: str,
    *,
    timeout: float,
    max_redirects: int,
    headers: Optional[dict] = None,
    transport: Optional[httpx.BaseTransport] = None,
) -> SafeResponse:
    """
    GET con validación SSRF en la URL inicial y en cada redirect.

    Args:
        url: URL inicial (http:// o https://).
        timeout: timeout por petición (segundos).
        max_redirects: máximo de redirects a seguir.
        headers: cabeceras a enviar.
        transport: transporte httpx alternativo (solo para tests).

    Raises:
        BlockedDestinationError: destino o redirect no público/no permitido.
        httpx.TooManyRedirects: se superó `max_redirects`.
        socket.gaierror / httpx.*: errores de red habituales.
    """
    headers = headers or {}
    current = httpx.URL(url)
    chain: List[str] = [str(current)]
    redirects = 0

    with httpx.Client(
        timeout=timeout, follow_redirects=False, transport=transport
    ) as client:
        while True:
            is_redirect_hop = redirects > 0
            try:
                _validate_url_shape(current)
                port = current.port or _default_port(current.scheme)
                ips = resolve_public_ips(current.host, port)
            except BlockedDestinationError as exc:
                if is_redirect_hop:
                    raise BlockedDestinationError(BLOCKED_REDIRECT) from exc
                raise

            response = _fetch_once(client, current, headers, ips)
            status = response.status_code
            location = response.headers.get("location")
            response.close()

            if status in _REDIRECT_STATUSES and location:
                redirects += 1
                if redirects > max_redirects:
                    raise httpx.TooManyRedirects(
                        f"Exceeded maximum allowed redirects ({max_redirects}).",
                        request=response.request,
                    )
                try:
                    current = httpx.URL(urljoin(str(current), location))
                except Exception as exc:  # noqa: BLE001 - Location malformada
                    raise BlockedDestinationError(BLOCKED_REDIRECT) from exc
                chain.append(str(current))
                continue

            return SafeResponse(
                status_code=status, final_url=str(current), redirect_chain=chain
            )


def _validate_url_shape(url: httpx.URL) -> None:
    """Esquema http/https, host presente, sin credenciales y puerto permitido."""
    if url.scheme not in ("http", "https") or not url.host:
        raise BlockedDestinationError(BLOCKED_REDIRECT)
    if url.userinfo:
        raise BlockedDestinationError(BLOCKED_REDIRECT)
    port = url.port or _default_port(url.scheme)
    if port not in _ALLOWED_PORTS:
        raise BlockedDestinationError(BLOCKED_REDIRECT)
