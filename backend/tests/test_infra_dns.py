"""Tests de infrastructure/dns_lookup.py con DNS mockeado (sin red real)."""

import time

import dns.exception
import dns.resolver
import pytest

from backend.infrastructure import dns_lookup as d
from backend.tests.helpers import FakeIp, FakeMx, FakeTxt
from backend.tests.infra_fixtures import (  # noqa: F401
    FakeCname,
    FakeDs,
    FakeNs,
    cymru,
    isolate_network,
    net,
)

NXDOMAIN = dns.resolver.NXDOMAIN
NOANSWER = dns.resolver.NoAnswer
TIMEOUT = dns.resolver.Timeout
SERVFAIL = dns.resolver.NoNameservers

D = "empresa.com"


def _future(seconds=30.0):
    return time.monotonic() + seconds


def _collect(**overrides):
    kwargs = dict(
        registrable_domain=D, hostname=D, mail_domain=D,
        web_hosts=[D, f"www.{D}"], deadline=_future(),
    )
    kwargs.update(overrides)
    return d.collect_dns(**kwargs)


def _full_table(overrides=None):
    table = {
        (D, "NS"): [FakeNs("ada.ns.cloudflare.com"), FakeNs("bob.ns.cloudflare.com.")],
        (D, "MX"): [FakeMx(20, "alt.mail.example."), FakeMx(10, "mx.mail.example.")],
        (D, "A"): [FakeIp("93.184.216.34")],
        (D, "AAAA"): NOANSWER(),
        (D, "CNAME"): NOANSWER(),
        (f"www.{D}", "CNAME"): NOANSWER(),
        (D, "DS"): NOANSWER(),
        (D, "DNSKEY"): NOANSWER(),
    }
    table.update(overrides or {})
    return table


# ===========================================================================
# query_records
# ===========================================================================
def test_query_ok_devuelve_registros(net):
    net.install_dns({(D, "A"): [FakeIp("1.2.3.4"), FakeIp("5.6.7.8")]})
    r = d.query_records(D, "A")
    assert [str(x) for x in r.records] == ["1.2.3.4", "5.6.7.8"] and r.error is None


def test_query_noanswer_no_es_error(net):
    net.install_dns({(D, "AAAA"): NOANSWER()})
    r = d.query_records(D, "AAAA")
    assert r.records == [] and r.error is None


@pytest.mark.parametrize(
    "exc,code",
    [
        (NXDOMAIN(), d.ERR_NXDOMAIN),
        (TIMEOUT(), d.ERR_TIMEOUT),
        (SERVFAIL(), d.ERR_GENERIC),
        (dns.exception.DNSException(), d.ERR_GENERIC),
        (RuntimeError("raro"), d.ERR_GENERIC),
    ],
)
def test_query_errores_se_clasifican_y_no_se_propagan(net, exc, code):
    net.install_dns({(D, "NS"): exc})
    r = d.query_records(D, "NS")
    assert r.records == [] and r.error == code


def test_query_pasa_lifetime_acotado(net):
    net.install_dns({(D, "A"): [FakeIp("1.2.3.4")]})
    d.query_records(D, "A", lifetime=2.5)
    assert net.dns.lifetimes == [2.5]


# ===========================================================================
# collect_dns
# ===========================================================================
def test_collect_completo(net):
    net.install_dns(_full_table({(D, "AAAA"): [FakeIp("2606:4700::1")]}))
    s = _collect()
    assert s.ns == ["ada.ns.cloudflare.com", "bob.ns.cloudflare.com"]
    assert s.mx == [(10, "mx.mail.example"), (20, "alt.mail.example")]  # ordenado por prioridad
    assert s.a == ["93.184.216.34"] and s.aaaa == ["2606:4700::1"]
    assert s.domain_exists is True and s.errors == {}
    assert s.ds_found is False and s.dnskey_found is False


def test_collect_cname_en_hosts_web(net):
    net.install_dns(_full_table({(f"www.{D}", "CNAME"): [FakeCname("shops.myshopify.com.")]}))
    s = _collect()
    assert s.cnames == {f"www.{D}": "shops.myshopify.com"}


def test_collect_consulta_solo_los_hosts_web_indicados(net):
    net.install_dns(_full_table({(f"www.{D}", "A"): NOANSWER(), (f"www.{D}", "AAAA"): NOANSWER()}))
    _collect(web_hosts=[f"www.{D}"], hostname=f"www.{D}")
    assert net.dns.queried("CNAME") == [f"www.{D}"]


def test_collect_null_mx(net):
    net.install_dns(_full_table({(D, "MX"): [FakeMx(0, ".")]}))
    s = _collect()
    assert s.null_mx is True and s.mx == []


def test_collect_ds_y_dnskey_presentes(net):
    net.install_dns(_full_table({(D, "DS"): [FakeDs()], (D, "DNSKEY"): [FakeDs()]}))
    s = _collect()
    assert s.ds_found is True and s.dnskey_found is True


def test_collect_ds_con_error_es_desconocido_no_falso(net):
    net.install_dns(_full_table({(D, "DS"): TIMEOUT(), (D, "DNSKEY"): SERVFAIL()}))
    s = _collect()
    assert s.ds_found is None and s.dnskey_found is None
    assert s.errors["ds"] == d.ERR_TIMEOUT and s.errors["dnskey"] == d.ERR_GENERIC


def test_collect_dominio_inexistente_corta_pronto(net):
    net.install_dns({(D, "NS"): NXDOMAIN()})
    s = _collect()
    assert s.domain_exists is False and s.ns == [] and s.mx == [] and s.a == []
    assert net.dns.calls == [(D, "NS")]  # no se hacen más consultas


def test_collect_un_fallo_no_impide_las_demas_consultas(net):
    net.install_dns(_full_table({(D, "MX"): TIMEOUT(), (D, "A"): SERVFAIL()}))
    s = _collect()
    assert s.errors == {"mx": d.ERR_TIMEOUT, "a": d.ERR_GENERIC}
    assert s.ns and s.mx == [] and s.a == []
    assert s.domain_exists is True


def test_collect_todo_con_timeout(net):
    net.install_dns({(D, t): TIMEOUT() for t in ("NS", "MX", "A", "AAAA", "DS", "DNSKEY")}
                    | {(D, "CNAME"): TIMEOUT(), (f"www.{D}", "CNAME"): TIMEOUT()})
    s = _collect()
    assert s.domain_exists is None  # no concluyente: no es NXDOMAIN
    assert set(s.errors.values()) == {d.ERR_TIMEOUT}
    assert s.ns == [] and s.mx == [] and s.cnames == {}


def test_collect_sin_ningun_dato_ni_error_deja_existencia_sin_concluir(net):
    net.install_dns({
        (D, "NS"): NOANSWER(), (D, "MX"): NOANSWER(), (D, "A"): NOANSWER(), (D, "AAAA"): NOANSWER(),
        (D, "CNAME"): NOANSWER(), (f"www.{D}", "CNAME"): NOANSWER(),
        (D, "DS"): NOANSWER(), (D, "DNSKEY"): NOANSWER(),
    })
    s = _collect()
    assert s.domain_exists is None and s.errors == {}


def test_collect_plazo_agotado_no_hace_consultas(net):
    net.install_dns({})
    s = _collect(deadline=time.monotonic() - 1)
    assert net.dns.calls == []
    assert set(s.errors.values()) == {d.ERR_DEADLINE}


def test_collect_registros_cname_duplicados_o_vacios(net):
    net.install_dns(_full_table({(D, "CNAME"): [FakeCname("a.example."), FakeCname("b.example.")]}))
    s = _collect()
    assert s.cnames[D] == "a.example"  # se usa el primero


# ===========================================================================
# ASN (Team Cymru)
# ===========================================================================
@pytest.mark.parametrize(
    "text,expected",
    [
        ('"13335 | 104.16.0.0/13 | US | arin | 2014-03-28"', (13335, "104.16.0.0/13")),
        ("16509 | 52.0.0.0/11 | US", (16509, "52.0.0.0/11")),
        ("13335 | ", (13335, None)),
        ("64500 64501 | 10.0.0.0/8", (64500, "10.0.0.0/8")),  # varios ASN: el primero
        ("", (None, None)),
        ("NA | x", (None, None)),
        ("| 1.1.1.0/24", (None, None)),
        ("abc", (None, None)),
    ],
)
def test_parse_cymru_txt(text, expected):
    assert d.parse_cymru_txt(text) == expected


def test_lookup_asn_ipv4_construye_el_nombre_invertido(net):
    net.install_dns({("34.216.184.93.origin.asn.cymru.com", "TXT"): cymru(15133, "93.184.216.0/24")})
    info = d.lookup_asn("93.184.216.34")
    assert info.asn == 15133 and info.prefix == "93.184.216.0/24" and info.public is True
    assert net.dns.calls == [("34.216.184.93.origin.asn.cymru.com", "TXT")]


def test_lookup_asn_ipv6_usa_nibbles_y_zona_origin6(net):
    name = ".".join(reversed("260647000000000000000000000000" + "11")) + ".origin6.asn.cymru.com"
    net.install_dns({(name, "TXT"): cymru(13335, "2606:4700::/32")})
    info = d.lookup_asn("2606:4700::11")
    assert info.asn == 13335
    assert net.dns.calls[0][0].endswith(".origin6.asn.cymru.com")
    assert len(net.dns.calls[0][0].split(".origin6")[0].split(".")) == 32


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.1.2.3", "192.168.0.1", "169.254.169.254", "::1", "fd00::1", "100.64.0.1", "0.0.0.0"])
def test_lookup_asn_no_consulta_ips_no_publicas(net, ip):
    net.install_dns({})
    info = d.lookup_asn(ip)
    assert info.public is False and info.asn is None
    assert net.dns.calls == []  # la IP privada nunca sale hacia ningún DNS


def test_lookup_asn_ip_invalida(net):
    net.install_dns({})
    assert d.lookup_asn("no-es-una-ip").public is False
    assert net.dns.calls == []


@pytest.mark.parametrize("exc,err", [(NXDOMAIN(), d.ERR_NXDOMAIN), (TIMEOUT(), d.ERR_TIMEOUT), (SERVFAIL(), d.ERR_GENERIC)])
def test_lookup_asn_errores(net, exc, err):
    net.install_dns({("34.216.184.93.origin.asn.cymru.com", "TXT"): exc})
    info = d.lookup_asn("93.184.216.34")
    assert info.asn is None and info.error == err


def test_lookup_asn_sin_respuesta_o_txt_malformado(net):
    name = "34.216.184.93.origin.asn.cymru.com"
    net.install_dns({(name, "TXT"): NOANSWER()})
    assert d.lookup_asn("93.184.216.34").error == "no_asn_data"
    net.install_dns({(name, "TXT"): [FakeTxt("esto no es cymru")]})
    assert d.lookup_asn("93.184.216.34").error == "no_asn_data"


def test_lookup_asns_deduplica_y_limita_a_cuatro_publicas(net):
    ips = [f"93.184.216.{n}" for n in range(1, 9)]
    table = {(".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com", "TXT"): cymru(15133) for ip in ips}
    net.install_dns(table)
    infos = d.lookup_asns(ips + ips[:2], deadline=_future())
    assert len([i for i in infos if i.public]) == 4
    assert len(net.dns.calls) == 4


def test_lookup_asns_ips_privadas_no_cuentan_para_el_limite_ni_se_consultan(net):
    pub = "93.184.216.34"
    net.install_dns({("34.216.184.93.origin.asn.cymru.com", "TXT"): cymru(15133)})
    infos = d.lookup_asns(["10.0.0.1", pub, "127.0.0.1"], deadline=_future())
    assert [i.public for i in infos] == [False, True, False]
    assert len(net.dns.calls) == 1


def test_lookup_asns_plazo_agotado(net):
    net.install_dns({})
    infos = d.lookup_asns(["93.184.216.34"], deadline=time.monotonic() - 1)
    assert infos[0].error == d.ERR_DEADLINE and net.dns.calls == []
