"""
Tests de integración de `analyze_infrastructure` (detector.py).

RDAP, bootstrap de IANA, DNS y ASN están mockeados: no hay red real.
"""

import ast
import ipaddress
import json
import pathlib

import dns.resolver
import httpx
import pytest

from backend.infrastructure import analyze_infrastructure, detector, dns_lookup
from backend.infrastructure.models import (
    DETECTED,
    INFERRED,
    KIND_DNS_PROVIDER,
    KIND_EMAIL_SERVICE,
    KIND_WEB_INFRASTRUCTURE,
    RDAP_NOT_FOUND,
    RDAP_OK,
    RDAP_SKIPPED,
    RDAP_TIMEOUT,
    RDAP_UNSUPPORTED_TLD,
    RdapResult,
)
from backend.tests.helpers import FakeIp, FakeMx
from backend.tests.infra_fixtures import (  # noqa: F401
    FakeCname,
    FakeDs,
    FakeNs,
    add_bootstrap,
    cymru,
    isolate_network,
    make_bootstrap,
    net,
    rdap_domain,
)

NOANSWER = dns.resolver.NoAnswer
NXDOMAIN = dns.resolver.NXDOMAIN
TIMEOUT = dns.resolver.Timeout

VERISIGN = "rdap.verisign.com"
CF_NS = ["ada.ns.cloudflare.com", "bob.ns.cloudflare.com"]
M365_MX = "empresa-com.mail.protection.outlook.com"


def _asn_key(ip):
    return (dns_lookup._cymru_name(ipaddress.ip_address(ip)), "TXT")


def dns_table(
    registrable="empresa.com",
    *,
    hostname=None,
    mail_domain=None,
    ns=None,
    mx=None,
    a=None,
    aaaa=None,
    cnames=None,
    ds=None,
    dnskey=None,
    asn=None,
    web_hosts=None,
):
    """Tabla DNS completa: todo lo no indicado responde NoAnswer."""
    hostname = hostname or registrable
    mail_domain = mail_domain or registrable
    web_hosts = web_hosts if web_hosts is not None else [hostname, f"www.{hostname}"]
    cnames = cnames or {}

    def rr(value):
        return value if value else NOANSWER()

    table = {
        (registrable, "NS"): rr([FakeNs(n) for n in ns or []]),
        (mail_domain, "MX"): rr([FakeMx(p, h) for p, h in mx or []]),
        (hostname, "A"): rr([FakeIp(i) for i in a or []]),
        (hostname, "AAAA"): rr([FakeIp(i) for i in aaaa or []]),
        (registrable, "DS"): rr([FakeDs()] if ds else []),
        (registrable, "DNSKEY"): rr([FakeDs()] if dnskey else []),
    }
    for host in web_hosts:
        table[(host, "CNAME")] = rr([FakeCname(cnames[host])] if host in cnames else [])
    for ip, number in (asn or {}).items():
        table[_asn_key(ip)] = cymru(number) if number else NOANSWER()
    return table


def serve_rdap(net, domain="empresa.com", path=None, **kwargs):
    add_bootstrap(net.router)
    net.router.add(VERISIGN, path or f"/com/v1/domain/{domain}", json_body=rdap_domain(domain, **kwargs))


def run(net, domain, **kwargs):
    return analyze_infrastructure(domain, transport=net.router.transport, **kwargs)


def names(report, kind):
    return [d.name for d in report.detections[kind]]


# ===========================================================================
# Escenario principal: Cloudflare + Microsoft 365
# ===========================================================================
def test_cloudflare_dns_microsoft365_y_infraestructura_cloudflare(net):
    ip = "104.16.1.1"
    net.install_dns(dns_table(ns=CF_NS, mx=[(0, M365_MX)], a=[ip], asn={ip: 13335}))
    serve_rdap(net)
    r = run(net, "empresa.com")

    (dns_det,) = r.detections[KIND_DNS_PROVIDER]
    assert (dns_det.name, dns_det.status, dns_det.confidence) == ("Cloudflare", DETECTED, "high")
    assert dns_det.basis == "nameserver" and dns_det.evidence == [f"NS {n}" for n in CF_NS]

    (mail_det,) = r.detections[KIND_EMAIL_SERVICE]
    assert (mail_det.name, mail_det.status, mail_det.confidence) == ("Microsoft 365", DETECTED, "high")
    assert mail_det.basis == "mx"

    (web_det,) = r.detections[KIND_WEB_INFRASTRUCTURE]
    assert web_det.name == "Cloudflare" and web_det.status == INFERRED
    assert web_det.confidence == "medium" and web_det.basis == "asn"
    assert web_det.evidence == [f"IP {ip} -> AS13335"]
    assert "origen" in web_det.note

    assert r.rdap.status == RDAP_OK and r.rdap.data["registrar"]
    assert r.cross_checks["nameservers_match_rdap"] is True


def test_ninguna_deteccion_de_infraestructura_se_etiqueta_como_provider_o_hosting(net):
    ip = "104.16.1.1"
    net.install_dns(dns_table(ns=CF_NS, a=[ip], asn={ip: 13335}))
    serve_rdap(net)
    data = run(net, "empresa.com").to_dict()
    for kind, items in data["detections"].items():
        assert kind in {"dns_provider", "email_service", "web_infrastructure"}
        for item in items:
            assert "provider" not in item and "hosting" not in item
            assert item["status"] in {"detected", "inferred"} and item["confidence"] in {"high", "medium", "low"}


def test_infraestructura_compatible_con_aws_es_inferencia_de_confianza_media(net):
    ip = "52.1.2.3"
    net.install_dns(dns_table(ns=["ns1.proveedor-raro.es"], a=[ip], asn={ip: 16509}))
    serve_rdap(net)
    r = run(net, "empresa.com")
    (det,) = r.detections[KIND_WEB_INFRASTRUCTURE]
    assert det.name == "Amazon Web Services"
    assert det.status == INFERRED and det.confidence == "medium"
    assert "no demuestra" in det.note


def test_asn_parcial_baja_la_confianza_a_low(net):
    aws, otro = "52.1.2.3", "93.184.216.34"
    net.install_dns(dns_table(a=[aws, otro], asn={aws: 16509, otro: 15133}))
    serve_rdap(net)
    (det,) = run(net, "empresa.com").detections[KIND_WEB_INFRASTRUCTURE]
    assert det.name == "Amazon Web Services" and det.confidence == "low"


def test_asn_desconocido_no_genera_deteccion_pero_se_informa(net):
    ip = "93.184.216.34"
    net.install_dns(dns_table(a=[ip], asn={ip: 15133}))
    serve_rdap(net)
    r = run(net, "empresa.com")
    assert r.detections[KIND_WEB_INFRASTRUCTURE] == []
    assert r.dns["addresses"] == [{"ip": ip, "public": True, "asn": 15133, "prefix": "104.16.0.0/13"}]


def test_cname_de_plataforma_es_deteccion_directa_con_nota_de_hosting(net):
    net.install_dns(dns_table(ns=["ns1.raro.es"], cnames={"www.empresa.com": "shops.myshopify.com"}, a=["93.184.216.34"], asn={"93.184.216.34": None}))
    serve_rdap(net)
    (det,) = run(net, "empresa.com").detections[KIND_WEB_INFRASTRUCTURE]
    assert (det.name, det.status, det.confidence, det.basis) == ("Shopify", DETECTED, "high", "cname")
    assert det.evidence == ["CNAME www.empresa.com -> shops.myshopify.com"]
    assert "no un contrato de hosting" in det.note


# ===========================================================================
# Proveedores desconocidos y mixtos
# ===========================================================================
def test_proveedores_desconocidos_no_generan_detecciones(net):
    net.install_dns(dns_table(ns=["ns1.hosting-raro.es", "ns2.hosting-raro.es"], mx=[(10, "mail.hosting-raro.es")], a=["93.184.216.34"], asn={"93.184.216.34": 15133}))
    serve_rdap(net)
    r = run(net, "empresa.com")
    assert all(v == [] for v in r.detections.values())
    assert r.unrecognized["nameservers"] == ["ns1.hosting-raro.es", "ns2.hosting-raro.es"]
    assert r.unrecognized["mx"] == ["mail.hosting-raro.es"]
    assert r.dns["nameservers"] == ["ns1.hosting-raro.es", "ns2.hosting-raro.es"]  # el dato crudo sí se conserva


def test_nameservers_mixtos_conocido_y_desconocido_bajan_a_medium(net):
    net.install_dns(dns_table(ns=["ada.ns.cloudflare.com", "ns1.legado.es"]))
    serve_rdap(net)
    r = run(net, "empresa.com")
    (det,) = r.detections[KIND_DNS_PROVIDER]
    assert det.name == "Cloudflare" and det.status == DETECTED and det.confidence == "medium"
    assert r.unrecognized["nameservers"] == ["ns1.legado.es"]


def test_dos_proveedores_dns_distintos_se_reportan_por_separado(net):
    net.install_dns(dns_table(ns=["ada.ns.cloudflare.com", "ns1.digitalocean.com"]))
    serve_rdap(net)
    dets = run(net, "empresa.com").detections[KIND_DNS_PROVIDER]
    assert sorted(d.name for d in dets) == ["Cloudflare", "DigitalOcean"]
    assert all(d.confidence == "medium" for d in dets)


def test_mx_google_y_pasarela_mimecast(net):
    net.install_dns(dns_table(mx=[(1, "aspmx.l.google.com"), (5, "alt1.aspmx.l.google.com"), (10, "eu-smtp-inbound-1.mimecast.com")]))
    serve_rdap(net)
    dets = {d.name: d for d in run(net, "empresa.com").detections[KIND_EMAIL_SERVICE]}
    assert set(dets) == {"Google Workspace", "Mimecast"}
    assert dets["Mimecast"].role == "security_gateway" and "no indica dónde están los buzones" in dets["Mimecast"].note
    assert dets["Google Workspace"].confidence == "medium"  # no todos los MX coinciden


def test_mx_de_un_solo_proveedor_es_high(net):
    net.install_dns(dns_table(mx=[(1, "aspmx.l.google.com"), (5, "alt1.aspmx.l.google.com"), (10, "aspmx2.googlemail.com")]))
    serve_rdap(net)
    (det,) = run(net, "empresa.com").detections[KIND_EMAIL_SERVICE]
    assert det.name == "Google Workspace" and det.confidence == "high"
    assert len(det.evidence) == 3


def test_evidencia_se_limita_a_cinco_entradas(net):
    net.install_dns(dns_table(mx=[(i, f"mx{i}.mail.ovh.net") for i in range(1, 9)]))
    serve_rdap(net)
    (det,) = run(net, "empresa.com").detections[KIND_EMAIL_SERVICE]
    assert len(det.evidence) == 5


def test_null_mx_no_genera_deteccion_de_correo(net):
    net.install_dns(dns_table(mx=[(0, ".")]))
    serve_rdap(net)
    r = run(net, "empresa.com")
    assert r.dns["null_mx"] is True and r.dns["mx"] == []
    assert r.detections[KIND_EMAIL_SERVICE] == []
    assert any("Null MX" in n for n in r.notes)


# ===========================================================================
# TLD: .com .net .org .eu
# ===========================================================================
@pytest.mark.parametrize(
    "domain,tld,host,path",
    [
        ("empresa.com", "com", VERISIGN, "/com/v1/domain/empresa.com"),
        ("empresa.net", "net", VERISIGN, "/com/v1/domain/empresa.net"),
        ("empresa.org", "org", "rdap.publicinterestregistry.org", "/rdap/domain/empresa.org"),
        ("empresa.eu", "eu", "rdap.eu", "/domain/empresa.eu"),
    ],
)
def test_gtld_y_eu_se_resuelven_por_rdap(net, domain, tld, host, path):
    net.install_dns(dns_table(domain, ns=CF_NS))
    add_bootstrap(net.router)
    net.router.add(host, path, json_body=rdap_domain(domain))
    r = run(net, domain)
    assert r.tld == tld and r.rdap.status == RDAP_OK and r.rdap.server == host
    assert r.rdap.coverage == "standard"
    assert r.rdap.data["registrar"] == "Example Registrar, Inc." and r.rdap.data["registrar_iana_id"] == "1068"
    assert r.rdap.data["created"] and r.rdap.data["expires"] and r.rdap.data["updated"]


def test_tld_multinivel_com_es_usa_el_dominio_registrable(net):
    net.install_dns(dns_table("empresa.com.es", hostname="www.empresa.com.es", mail_domain="empresa.com.es", ns=["ns1.raro.es"], web_hosts=["www.empresa.com.es"]))
    add_bootstrap(net.router, make_bootstrap(include_es=True))
    net.router.add("rdap.nic.es.example", "/domain/empresa.com.es", json_body={"objectClassName": "domain", "ldhName": "empresa.com.es"})
    r = run(net, "www.empresa.com.es")
    assert r.registrable_domain == "empresa.com.es" and r.tld == "es" and r.mail_domain == "empresa.com.es"
    assert r.rdap.coverage == "limited"


# ===========================================================================
# .es
# ===========================================================================
def test_es_sin_rdap_el_dns_sigue_funcionando_y_se_explica_la_limitacion(net):
    net.install_dns(dns_table("empresa.es", ns=["ada.ns.cloudflare.com"], mx=[(1, "aspmx.l.google.com")]))
    add_bootstrap(net.router, make_bootstrap(include_es=False))
    r = run(net, "empresa.es")
    assert r.rdap.status == RDAP_UNSUPPORTED_TLD and r.rdap.coverage == "limited" and r.rdap.data == {}
    assert names(r, KIND_DNS_PROVIDER) == ["Cloudflare"] and names(r, KIND_EMAIL_SERVICE) == ["Google Workspace"]
    assert any("conservadora" in n for n in r.notes)
    assert r.cross_checks["nameservers_match_rdap"] is None
    assert r.dnssec["sources"]["rdap_delegation_signed"] is None


def test_es_con_rdap_publicado_limita_la_cobertura(net):
    net.install_dns(dns_table("empresa.es", ns=["ns1.raro.es"]))
    add_bootstrap(net.router, make_bootstrap(include_es=True))
    net.router.add("rdap.nic.es.example", "/domain/empresa.es", json_body={"objectClassName": "domain", "ldhName": "empresa.es", "status": ["active"]})
    r = run(net, "empresa.es")
    assert r.rdap.status == RDAP_OK and r.rdap.coverage == "limited"
    assert "registrar" in r.rdap.missing_fields


def test_es_404_no_afirma_que_el_dominio_no_exista(net):
    net.install_dns(dns_table("empresa.es", ns=["ns1.raro.es"]))
    add_bootstrap(net.router, make_bootstrap(include_es=True))
    net.router.add("rdap.nic.es.example", "/domain/empresa.es", status=404)
    r = run(net, "empresa.es")
    assert r.rdap.status == RDAP_NOT_FOUND and r.rdap.conclusive is False


# ===========================================================================
# TLD sin RDAP / dominio inexistente / ausencia de datos / datos parciales
# ===========================================================================
def test_tld_desconocido_sin_rdap(net):
    net.install_dns(dns_table("ejemplo.xyz", ns=["dns1.registrar-servers.com"]))
    add_bootstrap(net.router)
    r = run(net, "ejemplo.xyz")
    assert r.rdap.status == RDAP_UNSUPPORTED_TLD and r.rdap.reason == "tld_not_in_iana_bootstrap"
    assert names(r, KIND_DNS_PROVIDER) == ["Namecheap"]


def test_dominio_inexistente(net):
    net.install_dns({("noexiste.com", "NS"): NXDOMAIN()})
    add_bootstrap(net.router)
    net.router.add(VERISIGN, "/com/v1/domain/noexiste.com", status=404)
    r = run(net, "noexiste.com")
    assert r.dns["domain_exists"] is False
    assert r.rdap.status == RDAP_NOT_FOUND and r.rdap.conclusive is True
    assert all(v == [] for v in r.detections.values())
    assert r.dns["addresses"] == []  # sin ASN para un dominio que no existe
    assert any("NXDOMAIN" in n for n in r.notes)
    assert net.dns.calls == [("noexiste.com", "NS")]


def test_ausencia_total_de_datos(net):
    net.install_dns(dns_table("vacio.com"))
    add_bootstrap(net.router)
    net.router.add(VERISIGN, "/com/v1/domain/vacio.com", json_body={"objectClassName": "domain", "ldhName": "VACIO.COM"})
    r = run(net, "vacio.com")
    assert all(v == [] for v in r.detections.values())
    assert r.dns["domain_exists"] is None and r.dns["nameservers"] == [] and r.dns["errors"] == {}
    assert r.rdap.status == RDAP_OK and r.rdap.data == {} and len(r.rdap.missing_fields) == 8
    assert r.dnssec["status"] == "unknown" and r.dnssec["confidence"] == "low"
    assert r.cross_checks["nameservers_match_rdap"] is None


def test_datos_parciales_rdap_sin_registrador_dns_solo_ns(net):
    net.install_dns(dns_table(ns=CF_NS))
    add_bootstrap(net.router)
    net.router.add(VERISIGN, "/com/v1/domain/empresa.com", json_body=rdap_domain(registrar=None, iana_id=None, updated=None, nameservers=None, delegation_signed=None))
    r = run(net, "empresa.com")
    assert names(r, KIND_DNS_PROVIDER) == ["Cloudflare"]
    assert "registrar" in r.rdap.missing_fields and "updated" in r.rdap.missing_fields
    assert r.rdap.data["created"] and r.rdap.data["expires"]


# ===========================================================================
# Fallos de red
# ===========================================================================
def test_timeout_dns_en_todo_no_rompe_y_se_refleja(net):
    table = {(registrable, t): TIMEOUT() for registrable in ("empresa.com",) for t in ("NS", "MX", "A", "AAAA", "DS", "DNSKEY", "CNAME")}
    table[("www.empresa.com", "CNAME")] = TIMEOUT()
    net.install_dns(table)
    serve_rdap(net)
    r = run(net, "empresa.com")
    assert set(r.dns["errors"].values()) == {"timeout"}
    assert all(v == [] for v in r.detections.values())
    assert r.dns["domain_exists"] is None
    assert any("fallado" in n for n in r.notes)
    assert r.rdap.status == RDAP_OK  # RDAP sigue funcionando aunque el DNS falle


def test_timeout_rdap_no_afecta_a_las_detecciones_dns(net):
    net.install_dns(dns_table(ns=CF_NS, mx=[(0, M365_MX)]))
    add_bootstrap(net.router)
    net.router.add(VERISIGN, "/com/v1/domain/empresa.com", raises=httpx.ReadTimeout("t"))
    r = run(net, "empresa.com")
    assert r.rdap.status == RDAP_TIMEOUT
    assert names(r, KIND_DNS_PROVIDER) == ["Cloudflare"] and names(r, KIND_EMAIL_SERVICE) == ["Microsoft 365"]


def test_fallo_parcial_de_dns_mantiene_el_resto(net):
    table = dns_table(ns=CF_NS, mx=[(0, M365_MX)])
    table[("empresa.com", "A")] = TIMEOUT()
    net.install_dns(table)
    serve_rdap(net)
    r = run(net, "empresa.com")
    assert r.dns["errors"] == {"a": "timeout"}
    assert names(r, KIND_DNS_PROVIDER) == ["Cloudflare"]


def test_plazo_global_agotado_devuelve_informe_sin_excepciones(net):
    net.install_dns({})
    add_bootstrap(net.router)
    r = run(net, "empresa.com", deadline_seconds=0)
    assert set(r.dns["errors"].values()) == {"deadline_exceeded"}
    assert r.rdap.status != RDAP_OK
    assert net.dns.calls == [] and net.router.requests == []


# ===========================================================================
# Opciones
# ===========================================================================
def test_use_rdap_false_no_hace_peticiones_http(net):
    net.install_dns(dns_table(ns=CF_NS))
    r = run(net, "empresa.com", use_rdap=False)
    assert r.rdap.status == RDAP_SKIPPED and net.router.requests == []
    assert names(r, KIND_DNS_PROVIDER) == ["Cloudflare"]


def test_use_asn_lookup_false_no_consulta_cymru(net):
    net.install_dns(dns_table(a=["52.1.2.3"]))
    serve_rdap(net)
    r = run(net, "empresa.com", use_asn_lookup=False)
    assert not any("cymru" in n for n, _ in net.dns.calls)
    assert r.detections[KIND_WEB_INFRASTRUCTURE] == [] and r.dns["addresses"] == []


# ===========================================================================
# Dominios de entrada y qué se consulta
# ===========================================================================
def test_subdominio_www_usa_dominio_de_correo_sin_www_y_ns_en_registrable(net):
    net.install_dns(dns_table("empresa.com", hostname="www.empresa.com", mail_domain="empresa.com", ns=CF_NS, web_hosts=["www.empresa.com"]))
    serve_rdap(net)
    r = run(net, "www.empresa.com")
    assert (r.domain, r.registrable_domain, r.mail_domain) == ("www.empresa.com", "empresa.com", "empresa.com")
    assert net.dns.queried("CNAME") == ["www.empresa.com"]  # no se añade www.www.


def test_subdominio_que_no_es_www_mantiene_su_dominio_de_correo(net):
    net.install_dns(dns_table("empresa.com", hostname="mail.empresa.com", mail_domain="mail.empresa.com", ns=CF_NS, web_hosts=["mail.empresa.com"]))
    serve_rdap(net)
    r = run(net, "mail.empresa.com")
    assert r.mail_domain == "mail.empresa.com" and r.registrable_domain == "empresa.com"


def test_dominio_apex_consulta_cname_en_apex_y_www(net):
    net.install_dns(dns_table(ns=CF_NS))
    serve_rdap(net)
    run(net, "empresa.com")
    assert sorted(net.dns.queried("CNAME")) == ["empresa.com", "www.empresa.com"]


@pytest.mark.parametrize("bad", ["", "   ", "127.0.0.1", "http://empresa.com", "localhost", "empresa", "empresa.com/ruta", "::1", "a b.com"])
def test_dominio_invalido_lanza_valueerror_sin_hacer_peticiones(net, bad):
    net.install_dns({})
    with pytest.raises(ValueError):
        run(net, bad)
    assert net.dns.calls == [] and net.router.requests == []


def test_se_normaliza_la_entrada(net):
    net.install_dns(dns_table(ns=CF_NS))
    serve_rdap(net)
    assert run(net, "  EMPRESA.com ").domain == "empresa.com"


# ===========================================================================
# Seguridad: IPs no públicas en el DNS del dominio
# ===========================================================================
def test_ips_privadas_en_dns_no_se_consultan_y_se_avisa(net):
    table = dns_table(ns=CF_NS, a=["10.0.0.5", "127.0.0.1"], aaaa=["::1"])
    net.install_dns(table)
    serve_rdap(net)
    r = run(net, "empresa.com")
    assert not any("cymru" in n for n, _ in net.dns.calls)
    assert all(a["public"] is False for a in r.dns["addresses"])
    assert r.detections[KIND_WEB_INFRASTRUCTURE] == []
    assert any("no públicas" in n for n in r.notes)
    assert net.router.hosts_requested().count("empresa.com") == 0  # nunca se contacta el dominio


def test_el_modulo_nunca_contacta_con_el_dominio_analizado_ni_sus_ips(net):
    net.install_dns(dns_table(ns=CF_NS, a=["93.184.216.34"], asn={"93.184.216.34": 15133}))
    serve_rdap(net)
    run(net, "empresa.com")
    assert set(net.router.hosts_requested()) <= {"data.iana.org", VERISIGN}


# ===========================================================================
# DNSSEC
# ===========================================================================
def _snap(ds=None, dnskey=None, ns=("ns1.ejemplo.example",)):
    return dns_lookup.DnsSnapshot(ds_found=ds, dnskey_found=dnskey, ns=list(ns))


def _rdap(signed=None):
    data = {} if signed is None else {"dnssec": {"delegation_signed": signed}}
    return RdapResult(status=RDAP_OK, data=data)


@pytest.mark.parametrize(
    "rdap_signed,ds,status,confidence",
    [
        (True, True, "signed", "high"),
        (False, False, "unsigned", "high"),
        (True, None, "signed", "medium"),
        (None, True, "signed", "medium"),
        (False, None, "unsigned", "medium"),
        (None, False, "unsigned", "medium"),
        (True, False, "inconsistent", "low"),
        (False, True, "inconsistent", "low"),
        (None, None, "unknown", "low"),
    ],
)
def test_dnssec_combinaciones(rdap_signed, ds, status, confidence):
    out = detector.summarize_dnssec(_rdap(rdap_signed), _snap(ds=ds))
    assert (out["status"], out["confidence"]) == (status, confidence)
    assert out["validated"] is False  # nunca se afirma validación criptográfica


def test_dnssec_ausencia_de_ds_sin_delegacion_no_cuenta_como_sin_firmar():
    out = detector.summarize_dnssec(_rdap(None), _snap(ds=False, ns=()))
    assert (out["status"], out["confidence"]) == ("unknown", "low")


def test_dnssec_ds_presente_cuenta_aunque_no_haya_ns():
    out = detector.summarize_dnssec(_rdap(None), _snap(ds=True, ns=()))
    assert (out["status"], out["confidence"]) == ("signed", "medium")


def test_dnssec_e2e_firmado_segun_rdap_y_ds(net):
    net.install_dns(dns_table(ns=CF_NS, ds=True, dnskey=True))
    serve_rdap(net, delegation_signed=True)
    r = run(net, "empresa.com")
    assert r.dnssec == {
        "status": "signed", "confidence": "high", "validated": False,
        "sources": {"rdap_delegation_signed": True, "ds_record_found": True, "dnskey_found": True},
    }


def test_dnssec_e2e_sin_firmar(net):
    net.install_dns(dns_table(ns=CF_NS))
    serve_rdap(net, delegation_signed=False)
    r = run(net, "empresa.com")
    assert r.dnssec["status"] == "unsigned" and r.dnssec["confidence"] == "high"


# ===========================================================================
# Comprobaciones cruzadas
# ===========================================================================
def test_nameservers_rdap_distintos_a_los_dns(net):
    net.install_dns(dns_table(ns=CF_NS))
    serve_rdap(net, nameservers=["ns1.otro.example"])
    assert run(net, "empresa.com").cross_checks["nameservers_match_rdap"] is False


def test_nameservers_rdap_coinciden_ignorando_orden_y_mayusculas(net):
    net.install_dns(dns_table(ns=["BOB.ns.cloudflare.com", "ada.ns.cloudflare.com"]))
    serve_rdap(net)
    assert run(net, "empresa.com").cross_checks["nameservers_match_rdap"] is True


# ===========================================================================
# Forma del informe y aislamiento del módulo
# ===========================================================================
def test_to_dict_es_serializable_y_estable(net):
    ip = "104.16.1.1"
    net.install_dns(dns_table(ns=CF_NS, mx=[(0, M365_MX)], a=[ip], asn={ip: 13335}))
    serve_rdap(net)
    data = run(net, "empresa.com").to_dict()
    json.dumps(data)  # no debe lanzar
    assert set(data) == {
        "domain", "registrable_domain", "mail_domain", "tld", "rdap", "dns", "dnssec",
        "detections", "unrecognized", "cross_checks", "notes",
    }
    assert set(data["detections"]) == {"dns_provider", "email_service", "web_infrastructure"}
    assert set(data["rdap"]) == {"status", "reason", "server", "coverage", "conclusive", "data", "missing_fields", "notes"}
    assert set(data["detections"]["dns_provider"][0]) == {"kind", "name", "status", "confidence", "basis", "role", "evidence", "note"}


def test_el_informe_no_filtra_ips_de_servidores_rdap(net):
    net.install_dns(dns_table(ns=CF_NS))
    serve_rdap(net)
    text = json.dumps(run(net, "empresa.com").to_dict())
    assert "199.7.59.74" not in text and "192.0.32.8" not in text


def test_el_paquete_no_importa_analyzer_modelos_publicos_main_ni_frontend():
    package = pathlib.Path(detector.__file__).parent
    forbidden = {"analyzer", "models", "main"}
    for path in package.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.level == 2 and node.module:
                assert node.module.split(".")[0] not in forbidden, f"{path.name} importa ..{node.module}"
            if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                assert not node.module.startswith(("backend.analyzer", "backend.models", "backend.main")), path.name
