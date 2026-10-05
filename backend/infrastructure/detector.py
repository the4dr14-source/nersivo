"""
Orquestador del módulo de infraestructura de Nersivo.

`analyze_infrastructure(domain)` reúne RDAP + DNS (+ ASN opcional) y devuelve un
`InfrastructureReport` que SEPARA lo confirmado de lo inferido:

- Datos confirmados (fuente directa): campos RDAP del registro, registros DNS
  tal como los devuelve el resolver, y detecciones `status="detected"`.
- Inferencias: detecciones `status="inferred"` (p. ej. IP -> ASN -> red).

El módulo NO se usa todavía desde `analyzer.py`: es una pieza aislada y sin
dependencias del contrato JSON público. Es síncrono, como el resto de checks.
"""

import time
from typing import Any, Dict, List, Optional, Tuple

import httpx

from ..domain_utils import (
    get_email_check_domain,
    get_registrable_domain,
    is_subdomain,
    validate_and_normalize_domain,
)
from . import dns_lookup, rdap
from .models import (
    BASIS_ASN,
    BASIS_CNAME,
    BASIS_MX,
    BASIS_NAMESERVER,
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    DETECTED,
    INFERRED,
    KIND_DNS_PROVIDER,
    KIND_EMAIL_SERVICE,
    KIND_WEB_INFRASTRUCTURE,
    Detection,
    InfrastructureReport,
    RdapResult,
)
from .providers import (
    ProviderRule,
    group_matches,
    match_asn,
    match_cname,
    match_mx,
    match_nameserver,
)

_MAX_EVIDENCE = 5
_RDAP_MAX_SECONDS = 12.0
_CNAME_NOTE = (
    "El DNS del sitio apunta a esta plataforma: indica la infraestructura "
    "utilizada, no un contrato de hosting."
)


# ---------------------------------------------------------------------------
# Detecciones
# ---------------------------------------------------------------------------
def detect_from_hosts(
    kind: str,
    basis: str,
    label: str,
    hosts: List[str],
    matcher,
) -> Tuple[List[Detection], List[str]]:
    """
    Identifica proveedores a partir de nombres de host (NS o MX).

    Todas las coincidencias son `detected` (el nombre pertenece al espacio de
    nombres del proveedor). La confianza es `high` solo si TODOS los hosts
    coinciden con un único proveedor; si hay hosts sin reconocer o varios
    proveedores, es `medium`.

    Returns:
        `(detections, unrecognized_hosts)`.
    """
    grouped, unrecognized = group_matches(hosts, matcher)
    clean = len(grouped) == 1 and not unrecognized
    detections = [
        Detection(
            kind=kind,
            name=rule.name,
            status=DETECTED,
            confidence=CONFIDENCE_HIGH if clean else CONFIDENCE_MEDIUM,
            basis=basis,
            role=rule.role,
            evidence=[f"{label} {h}" for h in matched[:_MAX_EVIDENCE]],
            note=rule.note,
        )
        for rule, matched in grouped.values()
    ]
    return detections, unrecognized


def detect_from_cnames(cnames: Dict[str, str]) -> Tuple[List[Detection], List[str]]:
    """Plataformas/infraestructura web a partir de CNAME (`origen -> destino`)."""
    grouped: Dict[str, Tuple[ProviderRule, List[str]]] = {}
    unrecognized: List[str] = []
    for source, target in cnames.items():
        rule = match_cname(target)
        if rule is None:
            unrecognized.append(target)
            continue
        grouped.setdefault(rule.name, (rule, []))[1].append(f"CNAME {source} -> {target}")
    clean = len(grouped) == 1 and not unrecognized
    detections = [
        Detection(
            kind=KIND_WEB_INFRASTRUCTURE,
            name=rule.name,
            status=DETECTED,
            confidence=CONFIDENCE_HIGH if clean else CONFIDENCE_MEDIUM,
            basis=BASIS_CNAME,
            role=rule.role,
            evidence=evidence[:_MAX_EVIDENCE],
            note=rule.note or _CNAME_NOTE,
        )
        for rule, evidence in grouped.values()
    ]
    return detections, unrecognized


def detect_from_asns(infos: List[dns_lookup.AsnInfo]) -> List[Detection]:
    """
    Infraestructura compatible a partir del ASN de las IPs públicas.

    Siempre `inferred`: que una IP pertenezca a la red de una empresa no
    demuestra que esa empresa sea el hosting. Confianza `medium` si TODAS las
    IPs con ASN conocido pertenecen al mismo proveedor; `low` si solo algunas.
    """
    with_asn = [i for i in infos if i.public and i.asn is not None]
    if not with_asn:
        return []
    by_rule: Dict[str, Tuple[Any, List[dns_lookup.AsnInfo]]] = {}
    for info in with_asn:
        rule = match_asn(info.asn)
        if rule is not None:
            by_rule.setdefault(rule.name, (rule, []))[1].append(info)
    detections: List[Detection] = []
    for rule, matched in by_rule.values():
        all_match = len(matched) == len(with_asn)
        detections.append(
            Detection(
                kind=KIND_WEB_INFRASTRUCTURE,
                name=rule.name,
                status=INFERRED,
                confidence=CONFIDENCE_MEDIUM if all_match else CONFIDENCE_LOW,
                basis=BASIS_ASN,
                role=rule.role,
                evidence=[f"IP {i.ip} -> AS{i.asn}" for i in matched[:_MAX_EVIDENCE]],
                note=rule.note,
            )
        )
    return detections


# ---------------------------------------------------------------------------
# DNSSEC y comprobaciones cruzadas
# ---------------------------------------------------------------------------
def summarize_dnssec(rdap_result: RdapResult, snap: dns_lookup.DnsSnapshot) -> Dict[str, Any]:
    """
    Resume DNSSEC combinando RDAP (`delegationSigned`) y el DS publicado en DNS.

    NO se valida la cadena de confianza (eso exige un resolver validador):
    `validated` es siempre False y `signed` significa "se publica la
    delegación firmada", no "la validación criptográfica es correcta".
    """
    rdap_signed = (rdap_result.data.get("dnssec") or {}).get("delegation_signed")
    # La AUSENCIA de DS solo es una señal de "sin firmar" si la delegación existe
    # (hay NS); en un dominio sin NS no dice nada. Un DS presente siempre cuenta.
    ds_signal = snap.ds_found if (snap.ds_found or snap.ns) else None
    signals = [s for s in (rdap_signed, ds_signal) if s is not None]

    if not signals:
        status, confidence = "unknown", CONFIDENCE_LOW
    elif all(signals):
        status = "signed"
        confidence = CONFIDENCE_HIGH if len(signals) == 2 else CONFIDENCE_MEDIUM
    elif not any(signals):
        status = "unsigned"
        confidence = CONFIDENCE_HIGH if len(signals) == 2 else CONFIDENCE_MEDIUM
    else:
        status, confidence = "inconsistent", CONFIDENCE_LOW

    return {
        "status": status,
        "confidence": confidence,
        "validated": False,
        "sources": {
            "rdap_delegation_signed": rdap_signed,
            "ds_record_found": snap.ds_found,
            "dnskey_found": snap.dnskey_found,
        },
    }


def _nameservers_match(rdap_result: RdapResult, snap: dns_lookup.DnsSnapshot) -> Optional[bool]:
    rdap_ns = rdap_result.data.get("nameservers")
    if not rdap_ns or not snap.ns:
        return None
    return {n.lower() for n in rdap_ns} == {n.lower() for n in snap.ns}


# ---------------------------------------------------------------------------
# API pública
# ---------------------------------------------------------------------------
def analyze_infrastructure(
    domain: str,
    *,
    use_rdap: bool = True,
    use_asn_lookup: bool = True,
    timeout: float = 5.0,
    deadline_seconds: float = 25.0,
    transport: Optional[httpx.BaseTransport] = None,
) -> InfrastructureReport:
    """
    Detecta información pública sobre la infraestructura de un dominio.

    Args:
        domain: dominio introducido por el usuario (se valida y normaliza con
            `validate_and_normalize_domain`).
        use_rdap: consultar RDAP (bootstrap IANA).
        use_asn_lookup: consultar el ASN de las IPs públicas (DNS de Team Cymru).
        timeout: timeout por consulta/petición (segundos).
        deadline_seconds: plazo global aproximado; las consultas pendientes se
            omiten cuando se agota (no hay espera indefinida).
        transport: transporte httpx alternativo (solo para tests).

    Returns:
        `InfrastructureReport`. Los fallos de red/DNS se reflejan en el informe
        (`rdap.status`, `dns.errors`) y nunca provocan excepciones.

    Raises:
        ValueError: si `domain` no es un dominio válido.
    """
    hostname = validate_and_normalize_domain(domain)
    registrable = get_registrable_domain(hostname)
    mail_domain = get_email_check_domain(hostname)
    tld = registrable.rsplit(".", 1)[-1]
    deadline = time.monotonic() + deadline_seconds

    web_hosts = [hostname]
    if not is_subdomain(hostname):
        web_hosts.append(f"www.{hostname}")

    # --- DNS ---------------------------------------------------------------
    snap = dns_lookup.collect_dns(
        registrable_domain=registrable,
        hostname=hostname,
        mail_domain=mail_domain,
        web_hosts=web_hosts,
        deadline=deadline,
        per_query_timeout=timeout,
    )

    # --- RDAP --------------------------------------------------------------
    if use_rdap:
        remaining = max(deadline - time.monotonic(), 0.0)
        rdap_result = rdap.lookup_rdap(
            registrable,
            timeout=timeout,
            deadline_seconds=min(_RDAP_MAX_SECONDS, remaining),
            transport=transport,
        )
    else:
        rdap_result = rdap.skipped_result()

    # --- ASN (inferencia) --------------------------------------------------
    notes: List[str] = []
    asn_infos: List[dns_lookup.AsnInfo] = []
    if use_asn_lookup and snap.domain_exists is not False:
        asn_infos = dns_lookup.lookup_asns(
            snap.a + snap.aaaa, deadline=deadline, per_query_timeout=timeout
        )
        if any(not i.public for i in asn_infos):
            notes.append(
                "El DNS devuelve direcciones no públicas; no se han consultado."
            )

    # --- Detecciones -------------------------------------------------------
    detections: Dict[str, List[Detection]] = {
        KIND_DNS_PROVIDER: [],
        KIND_EMAIL_SERVICE: [],
        KIND_WEB_INFRASTRUCTURE: [],
    }
    unrecognized: Dict[str, List[str]] = {"nameservers": [], "mx": [], "cnames": []}

    ns_det, unrecognized["nameservers"] = detect_from_hosts(
        KIND_DNS_PROVIDER, BASIS_NAMESERVER, "NS", snap.ns, match_nameserver
    )
    detections[KIND_DNS_PROVIDER] = ns_det

    mx_det, unrecognized["mx"] = detect_from_hosts(
        KIND_EMAIL_SERVICE, BASIS_MX, "MX", [h for _, h in snap.mx], match_mx
    )
    detections[KIND_EMAIL_SERVICE] = mx_det

    cname_det, unrecognized["cnames"] = detect_from_cnames(snap.cnames)
    detections[KIND_WEB_INFRASTRUCTURE] = cname_det + detect_from_asns(asn_infos)

    # --- Notas -------------------------------------------------------------
    if snap.domain_exists is False:
        notes.append("El dominio no existe en el DNS (NXDOMAIN).")
    if any(code != dns_lookup.ERR_NXDOMAIN for code in snap.errors.values()):
        notes.append(
            "Algunas consultas DNS han fallado (ver dns.errors): el resultado "
            "puede estar incompleto."
        )
    if snap.null_mx:
        notes.append("El dominio declara que no recibe correo (Null MX, RFC 7505).")
    notes.extend(rdap_result.notes)

    dns_section: Dict[str, Any] = {
        "domain_exists": snap.domain_exists,
        "nameservers": snap.ns,
        "mx": [{"priority": p, "host": h} for p, h in snap.mx],
        "null_mx": snap.null_mx,
        "a": snap.a,
        "aaaa": snap.aaaa,
        "cnames": snap.cnames,
        "addresses": [
            {"ip": i.ip, "public": i.public, "asn": i.asn, "prefix": i.prefix}
            for i in asn_infos
        ],
        "errors": snap.errors,
    }

    return InfrastructureReport(
        domain=hostname,
        registrable_domain=registrable,
        mail_domain=mail_domain,
        tld=tld,
        rdap=rdap_result,
        dns=dns_section,
        dnssec=summarize_dnssec(rdap_result, snap),
        detections=detections,
        unrecognized=unrecognized,
        cross_checks={"nameservers_match_rdap": _nameservers_match(rdap_result, snap)},
        notes=notes,
    )
