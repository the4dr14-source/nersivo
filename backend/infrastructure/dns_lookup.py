"""
Consultas DNS del módulo de infraestructura (dnspython).

Seguridad:
- Solo se hacen consultas DNS con el resolver configurado en el sistema
  (`dns.resolver.resolve`), igual que los checks existentes. NO se conecta a
  ninguna IP devuelta por el DNS.
- Cada consulta tiene `lifetime` acotado y el conjunto respeta un plazo global.
- La consulta de ASN (Team Cymru, servicio DNS gratuito) solo se hace para IPs
  que `net_safety.classify_ip` considera públicas; las IPs privadas/reservadas
  nunca salen del servidor.

Los códigos de error son los mismos que usan `checks/dns.py` y `checks/mx.py`
(`dns_resolution_error` = NXDOMAIN, `timeout`, `dns_error`) para mantener
coherencia; aquí se necesitan los rdata completos (NS, MX, CNAME, DS...), por
eso la consulta genérica es propia en lugar de reutilizar los helpers privados
de A/AAAA.
"""

import ipaddress
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import dns.exception
import dns.resolver

from .. import net_safety
from .providers import normalize_host

_TIMEOUT_SECONDS = 5.0
_MAX_ASN_LOOKUPS = 4

ERR_NXDOMAIN = "dns_resolution_error"
ERR_TIMEOUT = "timeout"
ERR_GENERIC = "dns_error"
ERR_DEADLINE = "deadline_exceeded"

_CYMRU_V4_ZONE = "origin.asn.cymru.com"
_CYMRU_V6_ZONE = "origin6.asn.cymru.com"


@dataclass
class QueryResult:
    """Resultado de una consulta: rdata (vacío si no hay) y código de error."""

    records: List[Any] = field(default_factory=list)
    error: Optional[str] = None  # None = respuesta correcta (incluso NoAnswer)


def query_records(name: str, rtype: str, *, lifetime: float = _TIMEOUT_SECONDS) -> QueryResult:
    """
    Consulta un tipo de registro. Nunca lanza excepciones.

    `NoAnswer` (el nombre existe pero sin registros de ese tipo) NO es un
    error: devuelve `records=[]` y `error=None`.
    """
    try:
        answers = dns.resolver.resolve(name, rtype, lifetime=lifetime)
        return QueryResult(records=list(answers))
    except dns.resolver.NXDOMAIN:
        return QueryResult(error=ERR_NXDOMAIN)
    except dns.resolver.NoAnswer:
        return QueryResult()
    except dns.resolver.Timeout:
        return QueryResult(error=ERR_TIMEOUT)
    except (dns.resolver.NoNameservers, dns.exception.DNSException):
        return QueryResult(error=ERR_GENERIC)
    except Exception:  # noqa: BLE001 - último recurso: nunca romper el análisis
        return QueryResult(error=ERR_GENERIC)


# ---------------------------------------------------------------------------
# Instantánea DNS
# ---------------------------------------------------------------------------
@dataclass
class DnsSnapshot:
    """Datos DNS recogidos para un dominio."""

    domain_exists: Optional[bool] = None  # False solo si NXDOMAIN confirmado
    ns: List[str] = field(default_factory=list)
    mx: List[Tuple[int, str]] = field(default_factory=list)
    null_mx: bool = False
    a: List[str] = field(default_factory=list)
    aaaa: List[str] = field(default_factory=list)
    cnames: Dict[str, str] = field(default_factory=dict)  # host -> destino
    ds_found: Optional[bool] = None
    dnskey_found: Optional[bool] = None
    errors: Dict[str, str] = field(default_factory=dict)  # consulta -> código


class _Budget:
    """Plazo global: reparte el tiempo restante entre las consultas."""

    def __init__(self, deadline: float, per_query: float):
        self.deadline = deadline
        self.per_query = per_query

    def lifetime(self) -> Optional[float]:
        remaining = self.deadline - time.monotonic()
        return min(self.per_query, remaining) if remaining > 0.05 else None


def _run(budget: _Budget, snapshot: DnsSnapshot, key: str, name: str, rtype: str) -> QueryResult:
    lifetime = budget.lifetime()
    if lifetime is None:
        snapshot.errors[key] = ERR_DEADLINE
        return QueryResult(error=ERR_DEADLINE)
    result = query_records(name, rtype, lifetime=lifetime)
    if result.error:
        snapshot.errors[key] = result.error
    return result


def _hostnames(records: List[Any], attr: str) -> List[str]:
    hosts: List[str] = []
    for rdata in records:
        host = normalize_host(str(getattr(rdata, attr, "")))
        if host and host not in hosts:
            hosts.append(host)
    return hosts


def collect_dns(
    *,
    registrable_domain: str,
    hostname: str,
    mail_domain: str,
    web_hosts: List[str],
    deadline: float,
    per_query_timeout: float = _TIMEOUT_SECONDS,
) -> DnsSnapshot:
    """
    Recoge NS, MX, A, AAAA, CNAME y señales DNSSEC.

    - NS y DS/DNSKEY se consultan en el dominio registrable (zona delegada).
    - MX en `mail_domain` (el mismo criterio que el check MX: sin `www.`).
    - A/AAAA en `hostname`; CNAME en cada host de `web_hosts`.

    Si el dominio registrable no existe (NXDOMAIN en NS) se detiene pronto:
    el resto de consultas no aportaría nada.
    """
    snap = DnsSnapshot()
    budget = _Budget(deadline, per_query_timeout)

    ns = _run(budget, snap, "ns", registrable_domain, "NS")
    snap.ns = _hostnames(ns.records, "target")
    if ns.error == ERR_NXDOMAIN:
        snap.domain_exists = False
        return snap

    mx = _run(budget, snap, "mx", mail_domain, "MX")
    for rdata in mx.records:
        snap.mx.append((int(rdata.preference), normalize_host(str(rdata.exchange))))
    snap.mx.sort(key=lambda item: item[0])
    # Null MX (RFC 7505): un único MX con host vacío ("."): el dominio no recibe correo.
    if len(snap.mx) == 1 and snap.mx[0][1] == "":
        snap.null_mx = True
        snap.mx = []

    a = _run(budget, snap, "a", hostname, "A")
    snap.a = [str(r) for r in a.records]
    aaaa = _run(budget, snap, "aaaa", hostname, "AAAA")
    snap.aaaa = [str(r) for r in aaaa.records]

    for host in web_hosts:
        cname = _run(budget, snap, f"cname:{host}", host, "CNAME")
        targets = _hostnames(cname.records, "target")
        if targets:
            snap.cnames[host] = targets[0]

    ds = _run(budget, snap, "ds", registrable_domain, "DS")
    snap.ds_found = bool(ds.records) if not ds.error else None
    dnskey = _run(budget, snap, "dnskey", registrable_domain, "DNSKEY")
    snap.dnskey_found = bool(dnskey.records) if not dnskey.error else None

    # `domain_exists` solo es False con NXDOMAIN confirmado en el dominio
    # registrable (ver arriba). Aquí solo se confirma que existe si hay datos;
    # sin datos y sin NXDOMAIN se deja en None (no concluyente).
    if snap.ns or snap.a or snap.aaaa or snap.mx or snap.null_mx:
        snap.domain_exists = True
    return snap


# ---------------------------------------------------------------------------
# ASN (Team Cymru, DNS gratuito)
# ---------------------------------------------------------------------------
@dataclass
class AsnInfo:
    """Resultado de la consulta de origen BGP para una IP."""

    ip: str
    asn: Optional[int] = None
    prefix: Optional[str] = None
    public: bool = True
    error: Optional[str] = None


def _cymru_name(ip: "ipaddress._BaseAddress") -> str:
    if ip.version == 4:
        return ".".join(reversed(str(ip).split("."))) + "." + _CYMRU_V4_ZONE
    nibbles = ip.exploded.replace(":", "")
    return ".".join(reversed(nibbles)) + "." + _CYMRU_V6_ZONE


def parse_cymru_txt(text: str) -> Tuple[Optional[int], Optional[str]]:
    """
    Parsea la respuesta TXT de Team Cymru: `"13335 | 104.16.0.0/13 | US | ..."`.

    Si hay varios ASN de origen separados por espacios, se usa el primero.
    """
    fields = [part.strip() for part in text.strip().strip('"').split("|")]
    if not fields or not fields[0]:
        return None, None
    first = fields[0].split()[0]
    if not first.isdigit():
        return None, None
    prefix = fields[1] if len(fields) > 1 and fields[1] else None
    return int(first), prefix


def lookup_asn(ip: str, *, lifetime: float = _TIMEOUT_SECONDS) -> AsnInfo:
    """
    Origen BGP (ASN) de una IP pública mediante DNS. Nunca lanza excepciones.

    Las IPs no públicas se descartan sin hacer ninguna consulta.
    """
    if net_safety.classify_ip(ip) is not None:
        return AsnInfo(ip=ip, public=False)
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return AsnInfo(ip=ip, public=False)

    result = query_records(_cymru_name(address), "TXT", lifetime=lifetime)
    if result.error:
        return AsnInfo(ip=ip, error=result.error)
    for rdata in result.records:
        strings = getattr(rdata, "strings", ())
        text = "".join(
            s.decode("utf-8", "ignore") if isinstance(s, bytes) else str(s) for s in strings
        )
        asn, prefix = parse_cymru_txt(text)
        if asn is not None:
            return AsnInfo(ip=ip, asn=asn, prefix=prefix)
    return AsnInfo(ip=ip, error="no_asn_data")


def lookup_asns(
    ips: List[str], *, deadline: float, per_query_timeout: float = _TIMEOUT_SECONDS
) -> List[AsnInfo]:
    """ASN de hasta `_MAX_ASN_LOOKUPS` IPs distintas, respetando el plazo global."""
    infos: List[AsnInfo] = []
    seen: List[str] = []
    for ip in ips:
        if ip in seen:
            continue
        seen.append(ip)
        if len([i for i in infos if i.public]) >= _MAX_ASN_LOOKUPS:
            break
        remaining = deadline - time.monotonic()
        if remaining <= 0.05:
            infos.append(AsnInfo(ip=ip, error=ERR_DEADLINE))
            continue
        infos.append(lookup_asn(ip, lifetime=min(per_query_timeout, remaining)))
    return infos
