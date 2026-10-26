"""Tests de `backend/providers`: identificación fiable de proveedores."""

import pytest

from backend.providers import identify_providers, lookup_nameservers
from backend.providers.identify import identify_dns_panel, identify_mail_provider
from backend.tests.helpers import FakeIp
from backend.tests.infra_fixtures import FakeNs, isolate_network, net  # noqa: F401
from backend.tests.monitor_helpers import analysis, check

import dns.resolver


def mx_analysis(*hosts, resolves=True):
    records = [{"priority": i, "hostname": h, "resolves": resolves} for i, h in enumerate(hosts, 1)]
    return analysis(mx=check("mx", records=records))


GOOGLE = ("aspmx.l.google.com", "alt1.aspmx.l.google.com", "aspmx2.googlemail.com")


# --- correo -----------------------------------------------------------------
def test_google_workspace_identificado_con_evidencia():
    mail, intermediary = identify_mail_provider(mx_analysis(*GOOGLE))
    assert (mail.id, mail.name, mail.confidence) == ("google_workspace", "Google Workspace", "high")
    assert mail.evidence[0] == "MX aspmx.l.google.com" and intermediary is None


def test_microsoft_365_identificado():
    mail, _ = identify_mail_provider(mx_analysis("empresa-es.mail.protection.outlook.com"))
    assert mail.id == "microsoft_365"


def test_mx_con_punto_final_y_mayusculas():
    mail, _ = identify_mail_provider(mx_analysis("ASPMX.L.GOOGLE.COM."))
    assert mail.id == "google_workspace"


def test_proveedor_no_reconocido_devuelve_none():
    assert identify_mail_provider(mx_analysis("mail.hosting-raro.es")) == (None, None)


def test_mx_mixto_proveedor_conocido_y_desconocido_no_se_afirma():
    assert identify_mail_provider(mx_analysis("aspmx.l.google.com", "mail.raro.es")) == (None, None)


def test_mx_de_dos_proveedores_distintos_no_se_afirma():
    result = identify_mail_provider(mx_analysis("aspmx.l.google.com", "x.mail.protection.outlook.com"))
    assert result == (None, None)


@pytest.mark.parametrize("host", ["aspmx.l.google.com.evil.com", "evilaspmx.l.google.com", "google.com.attacker.net"])
def test_imitaciones_no_identifican_proveedor(host):
    assert identify_mail_provider(mx_analysis(host)) == (None, None)


def test_sin_mx_o_null_mx():
    assert identify_mail_provider(analysis(mx=check("mx", "warning", "missing_mx", records=[]))) == (None, None)
    assert identify_mail_provider(mx_analysis("")) == (None, None)


def test_pasarela_de_seguridad_es_intermediario_no_proveedor_de_buzones():
    mail, intermediary = identify_mail_provider(mx_analysis("eu-smtp-inbound-1.mimecast.com"))
    assert mail is None and intermediary.name == "Mimecast"


def test_reenvio_de_correo_es_intermediario():
    mail, intermediary = identify_mail_provider(mx_analysis("route1.mx.cloudflare.net"))
    assert mail is None and intermediary.name == "Cloudflare Email Routing"


def test_acepta_dict_y_modelo():
    model = mx_analysis(*GOOGLE)
    assert identify_mail_provider(model.model_dump())[0].id == "google_workspace"


def test_analisis_sin_checks_no_rompe():
    assert identify_mail_provider({"checks": {}}) == (None, None)
    assert identify_mail_provider({}) == (None, None)


# --- panel DNS ------------------------------------------------------------------
def test_panel_cloudflare():
    match = identify_dns_panel(["ada.ns.cloudflare.com", "bob.ns.cloudflare.com"])
    assert (match.id, match.confidence) == ("cloudflare", "high")


def test_panel_mixto_o_desconocido_o_vacio():
    assert identify_dns_panel(["ada.ns.cloudflare.com", "ns1.raro.es"]) is None
    assert identify_dns_panel(["ns1.raro.es"]) is None
    assert identify_dns_panel([]) is None
    assert identify_dns_panel(["ada.ns.cloudflare.com", "ns1.digitalocean.com"]) is None


def test_identify_providers_combinado():
    ctx = identify_providers(mx_analysis(*GOOGLE), ["ada.ns.cloudflare.com"])
    assert ctx.mail.id == "google_workspace" and ctx.dns_panel.id == "cloudflare"
    empty = identify_providers(mx_analysis("mail.raro.es"))
    assert empty.mail is None and empty.dns_panel is None and empty.mail_intermediary is None


# --- lookup_nameservers (sin red) ---------------------------------------------------
def test_lookup_nameservers_ok(net):
    net.install_dns({("empresa.com", "NS"): [FakeNs("ada.ns.cloudflare.com."), FakeNs("ADA.ns.cloudflare.com")]})
    assert lookup_nameservers("www.empresa.com") == ["ada.ns.cloudflare.com"]
    assert net.dns.calls == [("empresa.com", "NS")]  # consulta el dominio registrable


@pytest.mark.parametrize("exc", [dns.resolver.NXDOMAIN(), dns.resolver.NoAnswer(), dns.resolver.Timeout(), dns.resolver.NoNameservers()])
def test_lookup_nameservers_errores_devuelven_lista_vacia(net, exc):
    net.install_dns({("empresa.com", "NS"): exc})
    assert lookup_nameservers("empresa.com") == []


@pytest.mark.parametrize("bad", ["localhost", "127.0.0.1", "10.0.0.1", "http://empresa.com", "", "a b.com"])
def test_lookup_nameservers_no_consulta_nombres_invalidos(net, bad):
    net.install_dns({})
    assert lookup_nameservers(bad) == []
    assert net.dns.calls == []
