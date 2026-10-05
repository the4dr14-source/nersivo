"""Tests de infrastructure/providers.py: patrones de proveedores (sin red)."""

import pytest

from backend.infrastructure import providers as p


# --- Nameservers -------------------------------------------------------------
@pytest.mark.parametrize(
    "host,expected",
    [
        ("ada.ns.cloudflare.com", "Cloudflare"),
        ("ns-123.awsdns-45.com", "Amazon Route 53"),
        ("ns-1234.awsdns-56.co.uk", "Amazon Route 53"),
        ("ns-12.awsdns-01.org", "Amazon Route 53"),
        ("ns-cloud-a1.googledomains.com", "Google Cloud DNS"),
        ("ns1-01.azure-dns.com", "Azure DNS"),
        ("ns2-01.azure-dns.net", "Azure DNS"),
        ("ns03.domaincontrol.com", "GoDaddy"),
        ("dns1.registrar-servers.com", "Namecheap"),
        ("dns10.ovh.net", "OVHcloud"),
        ("ns1019.ui-dns.com", "IONOS"),
        ("ns1019.ui-dns.de", "IONOS"),
        ("ns1.digitalocean.com", "DigitalOcean"),
        ("hydrogen.ns.hetzner.com", "Hetzner"),
        ("ns1.first-ns.de", "Hetzner"),
        ("ns3.second-ns.com", "Hetzner"),
        ("ns1.wixdns.net", "Wix"),
        ("ns1.vercel-dns.com", "Vercel"),
        ("a.ns.gandi.net", "Gandi"),
        ("ns1.dns-parking.com", "Hostinger"),
        ("dns1.p01.nsone.net", "NS1"),
        ("a1-1.akam.net", "Akamai"),
        ("pdns1.ultradns.net", "UltraDNS"),
        ("ns1.dnsmadeeasy.com", "DNS Made Easy"),
        ("ns1.p01.dynect.net", "Dyn"),
        ("ns1.linode.com", "Linode"),
    ],
)
def test_nameservers_reconocibles(host, expected):
    rule = p.match_nameserver(host)
    assert rule is not None and rule.name == expected


@pytest.mark.parametrize("host", ["ADA.NS.CLOUDFLARE.COM", "ada.ns.cloudflare.com.", "  Ada.Ns.Cloudflare.com.  "])
def test_nameserver_ignora_mayusculas_punto_final_y_espacios(host):
    assert p.match_nameserver(host).name == "Cloudflare"


@pytest.mark.parametrize(
    "host",
    [
        "ns1.proveedor-desconocido.es",
        "ns1.example.com",
        "",
        "   ",
        ".",
        # Imitaciones: el patrón compara etiquetas completas, no subcadenas.
        "evilcloudflare.com",
        "ns.cloudflare.com.attacker.net",
        "notdomaincontrol.com",
        "ns1.fake-ns.cloudflare.com.evil.example",
        "awsdns-1.example.com",
        "azure-dns.example.com",
        "ovh.net.attacker.org",
    ],
)
def test_nameservers_no_reconocidos_o_imitaciones(host):
    assert p.match_nameserver(host) is None


# --- MX ------------------------------------------------------------------------
@pytest.mark.parametrize(
    "host,expected",
    [
        ("empresa-es.mail.protection.outlook.com", "Microsoft 365"),
        ("aspmx.l.google.com", "Google Workspace"),
        ("alt1.aspmx.l.google.com", "Google Workspace"),
        ("aspmx2.googlemail.com", "Google Workspace"),
        ("aspmx3.googlemail.com", "Google Workspace"),
        ("smtp.google.com", "Google Workspace"),
        ("mx.zoho.com", "Zoho Mail"),
        ("mx.zoho.eu", "Zoho Mail"),
        ("mx2.zohomail.com", "Zoho Mail"),
        ("mail.protonmail.ch", "Proton Mail"),
        ("mailsec.protonmail.ch", "Proton Mail"),
        ("in1-smtp.messagingengine.com", "Fastmail"),
        ("route1.mx.cloudflare.net", "Cloudflare Email Routing"),
        ("mx1.mail.ovh.net", "OVHcloud Email"),
        ("mx00.ionos.es", "IONOS"),
        ("mx00.kundenserver.de", "IONOS"),
        ("mailstore1.secureserver.net", "GoDaddy"),
        ("mx1.privateemail.com", "Namecheap Private Email"),
        ("eforward1.registrar-servers.com", "Namecheap Email Forwarding"),
        ("spool.mail.gandi.net", "Gandi Mail"),
        ("mx1.hostinger.com", "Hostinger"),
        ("mx.yandex.net", "Yandex Mail"),
        ("inbound-smtp.eu-west-1.amazonaws.com", "Amazon SES (entrada)"),
        ("eu-smtp-inbound-1.mimecast.com", "Mimecast"),
        ("mxa-001.pphosted.com", "Proofpoint"),
        ("d1234.a.ess.barracudanetworks.com", "Barracuda"),
    ],
)
def test_mx_reconocibles(host, expected):
    rule = p.match_mx(host)
    assert rule is not None and rule.name == expected


@pytest.mark.parametrize(
    "host",
    [
        "mail.empresa.es",
        "mx.proveedor-raro.net",
        "mail.protection.outlook.com.evil.example",
        "evil-aspmx.l.google.com.attacker.org",
        "notmimecast.com",
        "",
    ],
)
def test_mx_no_reconocidos(host):
    assert p.match_mx(host) is None


@pytest.mark.parametrize("host", ["eu-smtp-inbound-1.mimecast.com", "mxa-001.pphosted.com", "x.barracudanetworks.com"])
def test_mx_pasarelas_de_seguridad_llevan_rol_y_nota(host):
    rule = p.match_mx(host)
    assert rule.role == "security_gateway"
    assert "no indica dónde están los buzones" in rule.note


def test_mx_reenvio_lleva_rol_forwarding():
    assert p.match_mx("route1.mx.cloudflare.net").role == "forwarding"


# --- CNAME -----------------------------------------------------------------------
@pytest.mark.parametrize(
    "host,expected",
    [
        ("d111111abcdef8.cloudfront.net", "Amazon CloudFront"),
        ("my-lb-123.eu-west-1.elb.amazonaws.com", "AWS (balanceador / S3 / Beanstalk)"),
        ("miapp.azurewebsites.net", "Microsoft Azure"),
        ("x.azureedge.net", "Microsoft Azure"),
        ("ghs.googlehosted.com", "Google (servicios alojados)"),
        ("tienda.pages.dev", "Cloudflare (SaaS / Pages)"),
        ("shops.myshopify.com", "Shopify"),
        ("cdn1.wixdns.net", "Wix"),
        ("ext-cust.squarespace.com", "Squarespace"),
        ("apex-loadbalancer.netlify.com", "Netlify"),
        ("sitio.netlify.app", "Netlify"),
        ("cname.vercel-dns.com", "Vercel"),
        ("usuario.github.io", "GitHub Pages"),
        ("algo.herokudns.com", "Heroku"),
        ("sitio.wpengine.com", "WP Engine"),
        ("a.global.fastly.net", "Fastly"),
        ("e1234.a.akamaiedge.net", "Akamai"),
        ("proxy-ssl.webflow.com", "Webflow"),
    ],
)
def test_cname_reconocibles(host, expected):
    rule = p.match_cname(host)
    assert rule is not None and rule.name == expected


@pytest.mark.parametrize(
    "host",
    ["tienda.ejemplo.es", "cloudfront.net.evil.com", "notmyshopify.com", "github.io.attacker.net", ""],
)
def test_cname_no_reconocidos_o_imitaciones(host):
    assert p.match_cname(host) is None


# --- ASN ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "asn,expected",
    [
        (13335, "Cloudflare"),
        (16509, "Amazon Web Services"),
        (14618, "Amazon Web Services"),
        (15169, "Google (incl. Google Cloud)"),
        (8075, "Microsoft (incl. Azure)"),
        (14061, "DigitalOcean"),
        (24940, "Hetzner"),
        (16276, "OVHcloud"),
    ],
)
def test_asn_conocidos(asn, expected):
    assert p.match_asn(asn).name == expected


def test_asn_desconocido():
    assert p.match_asn(64512) is None


def test_asn_cloudflare_avisa_de_que_el_origen_no_es_visible():
    assert "origen" in p.match_asn(13335).note


def test_todas_las_notas_de_asn_advierten_que_no_es_hosting_contratado():
    for rule in p.ASN_RULES:
        assert "no demuestra" in rule.note


def test_asn_sin_duplicados_entre_reglas():
    all_asns = [asn for rule in p.ASN_RULES for asn in rule.asns]
    assert len(all_asns) == len(set(all_asns))


# --- Integridad de las tablas -------------------------------------------------------
@pytest.mark.parametrize("table", [p.NAMESERVER_RULES, p.MX_RULES, p.CNAME_RULES])
def test_tablas_sin_nombres_duplicados_ni_reglas_vacias(table):
    names = [r.name for r in table]
    assert len(names) == len(set(names))
    assert all(r.patterns for r in table)


@pytest.mark.parametrize("table", [p.NAMESERVER_RULES, p.MX_RULES, p.CNAME_RULES])
def test_ningun_patron_coincide_con_un_tld_desnudo(table):
    for rule in table:
        for tld in ("com", "net", "org", "es", "de", "io"):
            assert not any(pat.search(tld) for pat in rule.patterns), (rule.name, tld)


# --- group_matches ---------------------------------------------------------------
def test_group_matches_agrupa_y_separa_no_reconocidos():
    hosts = ["a.ns.cloudflare.com", "ns1.raro.es", "b.ns.cloudflare.com", "ns1.digitalocean.com"]
    grouped, unrecognized = p.group_matches(hosts, p.match_nameserver)
    assert list(grouped) == ["Cloudflare", "DigitalOcean"]
    assert grouped["Cloudflare"][1] == ["a.ns.cloudflare.com", "b.ns.cloudflare.com"]
    assert unrecognized == ["ns1.raro.es"]


def test_group_matches_vacio():
    assert p.group_matches([], p.match_mx) == ({}, [])


def test_normalize_host():
    assert p.normalize_host("  MX.Example.COM. ") == "mx.example.com"
