"""
Patrones conocidos para identificar proveedores (DNS, correo, infraestructura web).

Este módulo solo contiene DATOS y funciones de coincidencia puras (sin red).
Añadir un proveedor es añadir una entrada a la tabla correspondiente.

Criterio de la tabla: solo se incluyen patrones que identifican de forma
inequívoca el espacio de nombres del proveedor. Ante la duda, un patrón NO se
incluye: es preferible "proveedor no reconocido" a una detección errónea.

Los patrones comparan por sufijo de etiquetas completas: `ns.cloudflare.com`
coincide con `ada.ns.cloudflare.com`, pero NO con `evilcloudflare.com`.
"""

import re
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Pattern, Tuple


@dataclass(frozen=True)
class ProviderRule:
    """Regla de identificación de un proveedor por nombre de host."""

    name: str
    patterns: Tuple[Pattern[str], ...]
    role: Optional[str] = None
    note: Optional[str] = None


@dataclass(frozen=True)
class AsnRule:
    """Regla de identificación por número de sistema autónomo (ASN)."""

    name: str
    asns: Tuple[int, ...]
    role: Optional[str] = None
    note: Optional[str] = None


def _suffixes(*suffixes: str) -> Pattern[str]:
    """Patrón que coincide con el host exacto o con cualquier subdominio suyo."""
    alternatives = "|".join(re.escape(s) for s in suffixes)
    return re.compile(rf"(?:^|\.)(?:{alternatives})$")


def _rx(expression: str) -> Pattern[str]:
    """Patrón regex anclado al final del host (para casos con partes variables)."""
    return re.compile(expression)


def _rule(
    name: str,
    *patterns: Pattern[str],
    role: Optional[str] = None,
    note: Optional[str] = None,
) -> ProviderRule:
    return ProviderRule(name=name, patterns=tuple(patterns), role=role, note=note)


# ---------------------------------------------------------------------------
# Nameservers -> proveedor DNS
# ---------------------------------------------------------------------------
NAMESERVER_RULES: Tuple[ProviderRule, ...] = (
    _rule("Cloudflare", _suffixes("ns.cloudflare.com")),
    _rule("Amazon Route 53", _rx(r"(?:^|\.)awsdns-\d+\.(?:com|net|org|co\.uk)$")),
    _rule("Google Cloud DNS", _rx(r"(?:^|\.)ns-cloud-[a-e]\d\.googledomains\.com$")),
    _rule(
        "Azure DNS",
        _rx(r"(?:^|\.)azure-dns\.(?:com|net|org|info)$"),
    ),
    _rule("GoDaddy", _suffixes("domaincontrol.com")),
    _rule("Namecheap", _suffixes("registrar-servers.com")),
    _rule("OVHcloud", _suffixes("ovh.net")),
    _rule("IONOS", _rx(r"(?:^|\.)ui-dns\.(?:com|de|org|biz)$")),
    _rule("DigitalOcean", _suffixes("digitalocean.com")),
    _rule("Hetzner", _suffixes("ns.hetzner.com", "first-ns.de", "second-ns.de", "second-ns.com")),
    _rule("Wix", _suffixes("wixdns.net")),
    _rule("Vercel", _suffixes("vercel-dns.com")),
    _rule("Gandi", _suffixes("gandi.net")),
    _rule("Hostinger", _suffixes("dns-parking.com")),
    _rule("NS1", _suffixes("nsone.net")),
    _rule("Akamai", _suffixes("akam.net")),
    _rule("UltraDNS", _rx(r"(?:^|\.)ultradns\.(?:net|com|org|biz)$")),
    _rule("DNS Made Easy", _suffixes("dnsmadeeasy.com")),
    _rule("Dyn", _suffixes("dynect.net")),
    _rule("Linode", _suffixes("linode.com")),
)

# ---------------------------------------------------------------------------
# MX -> servicio de correo
# ---------------------------------------------------------------------------
_GATEWAY_NOTE = (
    "Es una pasarela de seguridad de correo: filtra el correo antes de "
    "entregarlo, por lo que no indica dónde están los buzones."
)
_FORWARD_NOTE = (
    "Es un servicio de reenvío: no indica que los buzones estén alojados aquí."
)

MX_RULES: Tuple[ProviderRule, ...] = (
    _rule("Microsoft 365", _suffixes("mail.protection.outlook.com")),
    _rule(
        "Google Workspace",
        _suffixes("aspmx.l.google.com", "smtp.google.com"),
        _rx(r"(?:^|\.)aspmx\d*\.googlemail\.com$"),
    ),
    _rule(
        "Zoho Mail",
        _rx(r"(?:^|\.)(?:zoho|zohomail)\.(?:com|eu|in|com\.au|jp|sa|ca)$"),
    ),
    _rule("Proton Mail", _suffixes("mail.protonmail.ch", "mailsec.protonmail.ch")),
    _rule("Fastmail", _suffixes("messagingengine.com")),
    _rule("Cloudflare Email Routing", _suffixes("mx.cloudflare.net"), role="forwarding", note=_FORWARD_NOTE),
    _rule("OVHcloud Email", _suffixes("mail.ovh.net")),
    _rule("IONOS", _suffixes("mx00.ionos.es", "mx00.ionos.com", "mx00.1and1.es", "kundenserver.de")),
    _rule("GoDaddy", _suffixes("secureserver.net")),
    _rule("Namecheap Private Email", _suffixes("privateemail.com")),
    _rule("Namecheap Email Forwarding", _rx(r"(?:^|\.)eforward\d+\.registrar-servers\.com$"), role="forwarding", note=_FORWARD_NOTE),
    _rule("Gandi Mail", _suffixes("mail.gandi.net")),
    _rule("Hostinger", _suffixes("mx1.hostinger.com", "mx2.hostinger.com")),
    _rule("Yandex Mail", _suffixes("mx.yandex.net")),
    _rule("Amazon SES (entrada)", _rx(r"(?:^|\.)inbound-smtp\.[a-z0-9-]+\.amazonaws\.com$")),
    _rule("Mimecast", _rx(r"(?:^|\.)mimecast\.(?:com|co\.za|org)$"), role="security_gateway", note=_GATEWAY_NOTE),
    _rule("Proofpoint", _suffixes("pphosted.com", "ppe-hosted.com"), role="security_gateway", note=_GATEWAY_NOTE),
    _rule("Barracuda", _suffixes("barracudanetworks.com"), role="security_gateway", note=_GATEWAY_NOTE),
)

# ---------------------------------------------------------------------------
# CNAME -> plataforma / infraestructura web
# ---------------------------------------------------------------------------
CNAME_RULES: Tuple[ProviderRule, ...] = (
    _rule("Amazon CloudFront", _suffixes("cloudfront.net"), role="cdn"),
    _rule("AWS (balanceador / S3 / Beanstalk)", _suffixes("elb.amazonaws.com", "s3.amazonaws.com", "elasticbeanstalk.com"), role="cloud"),
    _rule("Microsoft Azure", _suffixes("azurewebsites.net", "azureedge.net", "azurefd.net", "trafficmanager.net", "cloudapp.azure.com"), role="cloud"),
    _rule("Google (servicios alojados)", _suffixes("ghs.googlehosted.com", "ghs.google.com"), role="platform"),
    _rule("Cloudflare (SaaS / Pages)", _suffixes("cdn.cloudflare.net", "pages.dev"), role="cdn"),
    _rule("Shopify", _suffixes("myshopify.com"), role="platform"),
    _rule("Wix", _suffixes("wixdns.net", "wixsite.com"), role="platform"),
    _rule("Squarespace", _suffixes("squarespace.com"), role="platform"),
    _rule("Netlify", _suffixes("netlify.app", "netlify.com"), role="platform"),
    _rule("Vercel", _suffixes("vercel-dns.com", "vercel.app"), role="platform"),
    _rule("GitHub Pages", _suffixes("github.io"), role="platform"),
    _rule("Heroku", _suffixes("herokudns.com", "herokuapp.com"), role="platform"),
    _rule("WP Engine", _suffixes("wpengine.com"), role="platform"),
    _rule("Pantheon", _suffixes("pantheonsite.io"), role="platform"),
    _rule("Render", _suffixes("onrender.com"), role="platform"),
    _rule("Fly.io", _suffixes("fly.dev"), role="platform"),
    _rule("Fastly", _suffixes("fastly.net"), role="cdn"),
    _rule("Akamai", _suffixes("akamaiedge.net", "edgekey.net", "edgesuite.net"), role="cdn"),
    _rule("Webflow", _suffixes("proxy-ssl.webflow.com", "webflow.io"), role="platform"),
    _rule("Weebly", _suffixes("weebly.com"), role="platform"),
)

# ---------------------------------------------------------------------------
# ASN -> red propietaria de la IP (solo INFERENCIA)
# ---------------------------------------------------------------------------
_ASN_NOTE = (
    "La IP pertenece a la red de este proveedor; eso no demuestra que sea el "
    "hosting contratado (puede haber un CDN, proxy o revendedor por delante)."
)

ASN_RULES: Tuple[AsnRule, ...] = (
    AsnRule("Cloudflare", (13335,), role="cdn_proxy", note="El servidor de origen real no es visible detrás de Cloudflare. " + _ASN_NOTE),
    AsnRule("Amazon Web Services", (16509, 14618), role="cloud", note=_ASN_NOTE),
    AsnRule("Google (incl. Google Cloud)", (15169, 396982), role="cloud", note=_ASN_NOTE),
    AsnRule("Microsoft (incl. Azure)", (8075,), role="cloud", note=_ASN_NOTE),
    AsnRule("DigitalOcean", (14061,), role="cloud", note=_ASN_NOTE),
    AsnRule("Hetzner", (24940,), role="hosting_network", note=_ASN_NOTE),
    AsnRule("OVHcloud", (16276,), role="hosting_network", note=_ASN_NOTE),
    AsnRule("Vultr", (20473,), role="cloud", note=_ASN_NOTE),
    AsnRule("Akamai / Linode", (63949, 20940), role="cloud", note=_ASN_NOTE),
    AsnRule("Fastly", (54113,), role="cdn_proxy", note=_ASN_NOTE),
    AsnRule("IONOS", (8560,), role="hosting_network", note=_ASN_NOTE),
    AsnRule("GoDaddy", (26496,), role="hosting_network", note=_ASN_NOTE),
    AsnRule("Namecheap", (22612,), role="hosting_network", note=_ASN_NOTE),
    AsnRule("Bluehost / Unified Layer", (46606,), role="hosting_network", note=_ASN_NOTE),
    AsnRule("IBM Cloud (SoftLayer)", (36351,), role="cloud", note=_ASN_NOTE),
    AsnRule("Oracle Cloud", (31898,), role="cloud", note=_ASN_NOTE),
    AsnRule("Alibaba Cloud", (45102,), role="cloud", note=_ASN_NOTE),
)

_ASN_INDEX: Dict[int, AsnRule] = {asn: rule for rule in ASN_RULES for asn in rule.asns}


# ---------------------------------------------------------------------------
# Funciones de coincidencia
# ---------------------------------------------------------------------------
def normalize_host(host: str) -> str:
    """Minúsculas y sin punto final (forma canónica para comparar)."""
    return host.strip().lower().rstrip(".")


def _match(host: str, rules: Iterable[ProviderRule]) -> Optional[ProviderRule]:
    normalized = normalize_host(host)
    if not normalized:
        return None
    for rule in rules:
        if any(p.search(normalized) for p in rule.patterns):
            return rule
    return None


def match_nameserver(host: str) -> Optional[ProviderRule]:
    """Proveedor DNS al que pertenece un nameserver, o None si no se reconoce."""
    return _match(host, NAMESERVER_RULES)


def match_mx(host: str) -> Optional[ProviderRule]:
    """Servicio de correo al que pertenece un host MX, o None si no se reconoce."""
    return _match(host, MX_RULES)


def match_cname(host: str) -> Optional[ProviderRule]:
    """Plataforma/infraestructura a la que apunta un CNAME, o None."""
    return _match(host, CNAME_RULES)


def match_asn(asn: int) -> Optional[AsnRule]:
    """Regla de red propietaria para un ASN, o None si no está en la tabla."""
    return _ASN_INDEX.get(asn)


def group_matches(
    hosts: List[str], matcher
) -> Tuple[Dict[str, Tuple[ProviderRule, List[str]]], List[str]]:
    """
    Agrupa `hosts` por proveedor reconocido.

    Returns:
        `(grouped, unrecognized)` donde `grouped` es `nombre -> (regla, hosts)`
        (en orden de aparición) y `unrecognized` los hosts sin coincidencia.
    """
    grouped: Dict[str, Tuple[ProviderRule, List[str]]] = {}
    unrecognized: List[str] = []
    for host in hosts:
        rule = matcher(host)
        if rule is None:
            unrecognized.append(host)
            continue
        grouped.setdefault(rule.name, (rule, []))[1].append(host)
    return grouped, unrecognized
