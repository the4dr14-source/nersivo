"""Identificación del cliente para el rate limiter (corrección de A3).

Problema
--------
El limitador usaba ``request.client.host``. Detrás de Render, Uvicorn arranca
con ``FORWARDED_ALLOW_IPS=*`` (valor por defecto de la plataforma para Python),
con lo que confía en cualquier origen y toma el PRIMER elemento de
``X-Forwarded-For``. Ese elemento lo escribe el propio cliente, así que podía
elegir la IP con la que se le limitaba y evadir la cuota cambiando la cabecera.

Modelo de confianza
-------------------
Cada proxy de confianza AÑADE al final de ``X-Forwarded-For`` la dirección del
extremo que le ha conectado. Un cliente solo puede escribir a la IZQUIERDA de
lo que añaden los proxies. Por tanto, contando desde la derecha, la entrada
número ``N`` (``N`` = proxies de confianza que añaden una entrada) es la
dirección que vio nuestro primer proxy y el cliente no puede alterarla.

* ``NERSIVO_TRUSTED_PROXY_HOPS=0`` (por defecto): no se confía en ninguna
  cabecera; se usa la dirección TCP (``request.client.host``). Solo es seguro
  si Uvicorn NO reescribe esa dirección a partir de la cabecera (arrancar con
  ``--no-proxy-headers`` o con ``FORWARDED_ALLOW_IPS`` sin comodín).
* ``NERSIVO_TRUSTED_PROXY_HOPS=N`` (N >= 1): se usa la entrada ``-N`` de
  ``X-Forwarded-For`` leída directamente de la cabecera, sin depender de lo que
  haya hecho Uvicorn con ``scope["client"]``.

Verificación del origen (opcional, explícita)
---------------------------------------------
Con ``N >= 1`` y SIN ``NERSIVO_TRUSTED_PROXY_CIDRS`` la cabecera se lee de
cualquier conexión: la aplicación no puede ver el peer TCP real mientras
Uvicorn tenga ``FORWARDED_ALLOW_IPS=*`` (reescribe ``scope["client"]`` con una
entrada que controla el cliente), así que no hay nada fiable contra lo que
comprobarlo. El riesgo residual es que alguien alcance el contenedor sin pasar
por el proxy de Render; se avisa al arrancar.

Con ``NERSIVO_TRUSTED_PROXY_CIDRS`` definido (lista de redes de los proxies,
obtenida del diagnóstico) la cabecera solo se lee si la conexión TCP procede de
esas redes; si no, se ignora y la petición cae en ``UNTRUSTED_PEER_KEY``. Eso
solo es válido si Uvicorn NO reescribe el cliente (``--no-proxy-headers`` o
``FORWARDED_ALLOW_IPS`` sin comodín); la combinación con ``*`` impide arrancar,
porque con ella TODOS los usuarios legítimos compartirían un cubo.

Nunca se leen ``X-Real-IP``, ``Forwarded``, ``CF-Connecting-IP`` ni
``True-Client-IP``: no se ha demostrado quién las establece ni que un cliente
no pueda suministrarlas.

Si la cadena no es la esperada (más corta que ``N`` o entrada ilegible), el
limitador NO se desactiva: la petición cae en un cubo compartido y constante
(``UNTRUSTED_CHAIN_KEY``) cuyo nombre no depende de nada que envíe el cliente.
"""

from __future__ import annotations

import ipaddress
import logging
import os
from typing import Mapping, NamedTuple, Optional, Sequence

logger = logging.getLogger(__name__)

TRUSTED_HOPS_ENV = "NERSIVO_TRUSTED_PROXY_HOPS"
LOG_RESOLUTION_ENV = "NERSIVO_LOG_CLIENT_IP_RESOLUTION"
MAX_TRUSTED_HOPS = 5

TRUSTED_CIDRS_ENV = "NERSIVO_TRUSTED_PROXY_CIDRS"

UNKNOWN_CLIENT_KEY = "unknown"
# Cadena de un proxy de confianza demasiado corta o ilegible.
UNTRUSTED_CHAIN_KEY = "untrusted-proxy-chain"
# La conexión TCP no procede de un proxy de confianza: se ignora la cabecera.
UNTRUSTED_PEER_KEY = "untrusted-peer"

_MAX_ADDRESS_TEXT = 64


class ClientIdentity(NamedTuple):
    """Resultado de identificar al cliente de una petición."""

    key: str
    source: str  # "peer" | "forwarded-for" | "fallback"
    detail: str = ""


def trusted_hops_from_env(environ: Optional[Mapping[str, str]] = None) -> int:
    """Lee ``NERSIVO_TRUSTED_PROXY_HOPS``. Un valor inválido es un error.

    Es preferible fallar al arrancar que dejar el limitador en un modo que el
    operador cree distinto del real.
    """
    env = os.environ if environ is None else environ
    raw = env.get(TRUSTED_HOPS_ENV)
    if raw is None or raw.strip() == "":
        return 0
    return validate_trusted_hops(raw)


def validate_trusted_hops(value: object) -> int:
    try:
        hops = int(str(value).strip())
    except ValueError:
        raise ValueError(
            f"{TRUSTED_HOPS_ENV} debe ser un entero entre 0 y {MAX_TRUSTED_HOPS}, "
            f"no {value!r}"
        ) from None
    if not 0 <= hops <= MAX_TRUSTED_HOPS:
        raise ValueError(
            f"{TRUSTED_HOPS_ENV} debe estar entre 0 y {MAX_TRUSTED_HOPS}, no {hops}"
        )
    return hops


def trusted_networks_from_env(
    environ: Optional[Mapping[str, str]] = None,
) -> Optional[tuple]:
    """Lee ``NERSIVO_TRUSTED_PROXY_CIDRS`` (lista separada por comas).

    Ausente o vacío: ``None`` (sin verificación del peer; no se presupone
    ninguna dirección de Render). Un valor inválido es un error de arranque.
    """
    env = os.environ if environ is None else environ
    raw = env.get(TRUSTED_CIDRS_ENV)
    if raw is None or raw.strip() == "":
        return None
    return validate_trusted_networks(item for item in raw.split(","))


def validate_trusted_networks(items) -> tuple:
    networks = []
    for item in items:
        text = str(item).strip()
        try:
            networks.append(ipaddress.ip_network(text))
        except ValueError:
            raise ValueError(
                f"{TRUSTED_CIDRS_ENV} contiene una red inválida: {text!r}"
            ) from None
    if not networks:
        raise ValueError(f"{TRUSTED_CIDRS_ENV} no contiene ninguna red")
    return tuple(networks)


def peer_is_trusted(peer_host: Optional[str], networks: Sequence) -> bool:
    """``True`` si la dirección TCP pertenece a una red de proxies de confianza."""
    ip = normalize_ip(peer_host) if peer_host else None
    if ip is None:
        return False
    address = ipaddress.ip_address(ip)
    return any(address in net for net in networks if net.version == address.version)


def normalize_ip(value: str) -> Optional[str]:
    """Devuelve la IP en forma canónica o ``None`` si no es una IP válida.

    Acepta ``IPv4``, ``IPv4:puerto``, ``IPv6``, ``[IPv6]`` y ``[IPv6]:puerto``.
    Rechaza nombres, ceros a la izquierda, identificadores de zona y cualquier
    cosa que no sea ASCII. Las direcciones IPv4 mapeadas en IPv6 se reducen a
    IPv4 y el IPv6 se escribe siempre comprimido y en minúsculas, de modo que
    cambiar la forma textual de una misma dirección no crea un cubo nuevo.
    """
    text = value.strip()
    if not text or len(text) > _MAX_ADDRESS_TEXT or not text.isascii():
        return None

    host = text
    if text.startswith("["):
        end = text.find("]")
        if end == -1:
            return None
        host = text[1:end]
        rest = text[end + 1 :]
        if rest and not (rest.startswith(":") and _valid_port(rest[1:])):
            return None
    elif text.count(":") == 1:
        host, port = text.split(":")
        if not _valid_port(port):
            return None

    if "%" in host:
        return None
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return str(address)


def _valid_port(port: str) -> bool:
    return port.isascii() and port.isdigit() and 0 <= int(port) <= 65535


def _peer_key(peer_host: Optional[str]) -> str:
    if not peer_host:
        return UNKNOWN_CLIENT_KEY
    return normalize_ip(peer_host) or peer_host


def resolve_client(
    peer_host: Optional[str],
    forwarded_for_values: Sequence[str],
    trusted_hops: int,
    trusted_networks: Optional[Sequence] = None,
) -> ClientIdentity:
    """Identifica al cliente según el modelo de confianza descrito arriba.

    ``forwarded_for_values`` son los valores de TODAS las líneas
    ``X-Forwarded-For`` recibidas (se unen en orden, como indica la RFC 9110).
    """
    if trusted_hops == 0:
        return ClientIdentity(_peer_key(peer_host), "peer")

    if trusted_networks is not None and not peer_is_trusted(
        peer_host, trusted_networks
    ):
        # Clave constante: no depende de nada que el cliente pueda elegir, ni
        # siquiera de una dirección TCP que Uvicorn pudiera haber reescrito.
        return ClientIdentity(UNTRUSTED_PEER_KEY, "fallback", "peer-not-trusted-proxy")

    raw = ", ".join(forwarded_for_values)
    # Solo importan las últimas N entradas: se parte por la derecha como mucho
    # N veces, así que una cabecera enorme no cuesta más que una pequeña.
    parts = raw.rsplit(",", trusted_hops)
    if len(parts) < trusted_hops:
        return ClientIdentity(UNTRUSTED_CHAIN_KEY, "fallback", "chain-too-short")

    ip = normalize_ip(parts[-trusted_hops])
    if ip is None:
        return ClientIdentity(UNTRUSTED_CHAIN_KEY, "fallback", "invalid-entry")
    return ClientIdentity(ip, "forwarded-for")


def warn_if_proxy_headers_untrusted(
    trusted_hops: int, environ: Optional[Mapping[str, str]] = None
) -> None:
    """Avisa de la combinación vulnerable: sin saltos configurados y con
    Uvicorn confiando en cualquier origen."""
    env = os.environ if environ is None else environ
    if trusted_hops == 0 and _uvicorn_trusts_everyone(env):
        logger.warning(
            "A3: FORWARDED_ALLOW_IPS='*' y %s=0. Uvicorn toma la IP de la "
            "primera entrada de X-Forwarded-For, que controla el cliente, y el "
            "rate limiter puede evadirse. Configura %s (o arranca Uvicorn con "
            "--no-proxy-headers; en ese caso este aviso es un falso positivo "
            "porque la aplicación no puede ver los flags de arranque).",
            TRUSTED_HOPS_ENV,
            TRUSTED_HOPS_ENV,
        )


def _uvicorn_trusts_everyone(env: Mapping[str, str]) -> bool:
    allowed = env.get("FORWARDED_ALLOW_IPS", "")
    return "*" in [item.strip() for item in allowed.split(",")]


def check_peer_verification_config(
    trusted_hops: int,
    trusted_networks: Optional[Sequence],
    environ: Optional[Mapping[str, str]] = None,
    warn: bool = True,
) -> None:
    """Coherencia entre saltos, redes de confianza y arranque de Uvicorn.

    * Redes definidas con ``FORWARDED_ALLOW_IPS=*``: error de arranque. Uvicorn
      reescribe ``scope["client"]`` y el chequeo de peer metería a todos los
      usuarios legítimos en un único cubo.
    * Saltos >= 1 sin redes: aviso de que la cadena no está verificada.
    """
    env = os.environ if environ is None else environ
    if trusted_networks is not None and trusted_hops > 0:
        if _uvicorn_trusts_everyone(env):
            raise ValueError(
                f"{TRUSTED_CIDRS_ENV} es incompatible con FORWARDED_ALLOW_IPS='*': "
                "Uvicorn reescribe la dirección del cliente y no se puede "
                "comprobar el peer TCP. Arranca con --no-proxy-headers o "
                "define FORWARDED_ALLOW_IPS sin comodín."
            )
    elif warn and trusted_networks is None and trusted_hops > 0:
        logger.warning(
            "A3: %s=%d sin %s. X-Forwarded-For se lee de cualquier conexión; "
            "no se verifica que proceda de un proxy autorizado. Es seguro "
            "mientras solo se llegue al contenedor a través del proxy de Render.",
            TRUSTED_HOPS_ENV,
            trusted_hops,
            TRUSTED_CIDRS_ENV,
        )


def diagnostics_enabled(environ: Optional[Mapping[str, str]] = None) -> bool:
    env = os.environ if environ is None else environ
    return env.get(LOG_RESOLUTION_ENV, "").strip() == "1"


def log_resolution(
    peer_host: Optional[str],
    forwarded_for_values: Sequence[str],
    trusted_hops: int,
    identity: ClientIdentity,
    peer_port: Optional[int] = None,
) -> None:
    """Diagnóstico opcional para determinar cuántos saltos añade Render.

    Se registra con nivel WARNING porque el logger raíz no muestra INFO. Se
    escribe con ``%r`` y truncado para que una cabecera hostil no pueda
    inyectar líneas en el registro. Del ``X-Forwarded-For`` se conservan los
    ÚLTIMOS 300 caracteres: lo que añaden los proxies está al final y es lo
    que hay que ver aunque el cliente envíe una cabecera enorme.

    ``peer`` y ``port`` son ``request.client`` tal como lo entrega Uvicorn, NO
    necesariamente el peer TCP original. Con ``FORWARDED_ALLOW_IPS=*`` Uvicorn
    los sustituye por la primera entrada de ``X-Forwarded-For`` (y el puerto
    vale 0 si esa entrada no lleva puerto); un puerto 0 indica, por tanto,
    que la dirección fue reescrita. Un puerto distinto de 0 sugiere (no
    demuestra) que es la conexión TCP real.
    """
    raw = ", ".join(forwarded_for_values)
    logger.warning(
        "A3-diagnostico peer=%r port=%s xff=%r hops=%d -> key=%s source=%s %s",
        peer_host,
        peer_port,
        raw[-300:],
        trusted_hops,
        identity.key,
        identity.source,
        identity.detail,
    )


class FallbackReporter:
    """Avisa (como mucho una vez por intervalo) de que hay peticiones en un cubo
    de respaldo.

    Es la señal de que ``NERSIVO_TRUSTED_PROXY_HOPS``/``..._CIDRS`` o el
    arranque de Uvicorn no coinciden con la realidad: si Render añade menos
    entradas de las esperadas, TODOS los usuarios compartirían un cubo y la
    cuota de uno agotaría la de los demás. Sin este aviso el fallo sería mudo.
    """

    def __init__(self, interval: float = 60.0, clock=None) -> None:
        import time

        self.interval = interval
        self._clock = clock or time.monotonic
        self._last: Optional[float] = None
        self._suppressed = 0

    def report(self, peer_host, identity: ClientIdentity) -> bool:
        if identity.source != "fallback":
            return False
        now = self._clock()
        if self._last is not None and now - self._last < self.interval:
            self._suppressed += 1
            return False
        logger.warning(
            "A3: peticion en cubo de respaldo %s (%s) peer=%r; "
            "%d mas desde el ultimo aviso. Si afecta a usuarios legitimos, "
            "revisa %s, %s y --no-proxy-headers.",
            identity.key,
            identity.detail,
            peer_host,
            self._suppressed,
            TRUSTED_HOPS_ENV,
            TRUSTED_CIDRS_ENV,
        )
        self._last = now
        self._suppressed = 0
        return True
