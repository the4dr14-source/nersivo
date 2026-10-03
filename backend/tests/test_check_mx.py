"""Tests de checks/mx.py con DNS mockeado (sin red real)."""

import dns.resolver
import pytest

from backend.checks.mx import check_mx
from backend.models import Status
from backend.tests.helpers import FakeIp, FakeMx, install_dns

D = "empresa.es"
MAIL = "mail.empresa.es"
MAIL2 = "mail2.empresa.es"
IP = [FakeIp("93.184.216.34")]

NXDOMAIN = dns.resolver.NXDOMAIN
NOANSWER = dns.resolver.NoAnswer
TIMEOUT = dns.resolver.Timeout
SERVFAIL = dns.resolver.NoNameservers


def _hosts(mail=(IP, NOANSWER()), mail2=None):
    h = {"mail.empresa.es": mail}
    if mail2 is not None:
        h["mail2.empresa.es"] = mail2
    return h


def _run(monkeypatch, mx, hosts):
    t = {(D, "MX"): mx}
    for name, (a, aaaa) in hosts.items():
        t[(name, "A")] = a
        t[(name, "AAAA")] = aaaa
    install_dns(monkeypatch, t)
    return check_mx(D)


# --- Casos básicos -----------------------------------------------------------
def test_mx_valido(monkeypatch):
    r = _run(monkeypatch, [FakeMx(10, MAIL)], _hosts())
    assert r.status == Status.OK and r.checked is True
    assert r.details["found"] is True
    assert r.details["records"] == [{"priority": 10, "hostname": MAIL, "resolves": True}]


def test_multiples_mx_validos(monkeypatch):
    r = _run(
        monkeypatch,
        [FakeMx(10, MAIL), FakeMx(20, MAIL2)],
        _hosts(mail2=(IP, NOANSWER())),
    )
    assert r.status == Status.OK
    assert [x["priority"] for x in r.details["records"]] == [10, 20]
    assert all(x["resolves"] is True for x in r.details["records"])


def test_sin_mx_es_warning(monkeypatch):
    install_dns(monkeypatch, {(D, "MX"): NOANSWER()})
    r = check_mx(D)
    assert r.status == Status.WARNING
    assert r.technical_reason == "missing_mx"
    assert r.checked is True


def test_null_mx_es_ok(monkeypatch):
    install_dns(monkeypatch, {(D, "MX"): [FakeMx(0, ".")]})
    r = check_mx(D)
    assert r.status == Status.OK
    assert r.technical_reason == "null_mx"


# --- Resolución del hostname MX ----------------------------------------------
def test_hostname_mx_resoluble_por_a(monkeypatch):
    r = _run(monkeypatch, [FakeMx(10, MAIL)], _hosts(mail=(IP, NOANSWER())))
    assert r.details["records"][0]["resolves"] is True


def test_hostname_mx_resoluble_solo_por_aaaa(monkeypatch):
    r = _run(monkeypatch, [FakeMx(10, MAIL)], _hosts(mail=(NOANSWER(), [FakeIp("2001:db8::1")])))
    assert r.status == Status.OK
    assert r.details["records"][0]["resolves"] is True


def test_hostname_mx_nxdomain_es_warning_real(monkeypatch):
    r = _run(monkeypatch, [FakeMx(10, MAIL)], _hosts(mail=(NXDOMAIN(), NXDOMAIN())))
    assert r.status == Status.WARNING
    assert r.technical_reason == "mx_resolution_issue"
    assert r.checked is True
    assert r.details["records"][0]["resolves"] is False


def test_hostname_mx_existe_pero_sin_a_ni_aaaa_es_warning(monkeypatch):
    r = _run(monkeypatch, [FakeMx(10, MAIL)], _hosts(mail=(NOANSWER(), NOANSWER())))
    assert r.status == Status.WARNING
    assert r.technical_reason == "mx_resolution_issue"
    assert r.details["records"][0]["resolves"] is False


# --- Fallos temporales: NO se convierten en error del dominio ----------------
@pytest.mark.parametrize("exc", [TIMEOUT, SERVFAIL])
def test_fallo_temporal_al_resolver_hostname_mx_es_unknown(monkeypatch, exc):
    r = _run(monkeypatch, [FakeMx(10, MAIL)], _hosts(mail=(exc(), exc())))
    assert r.status == Status.UNKNOWN
    assert r.checked is False
    assert r.technical_reason == "dns_error"
    assert r.details["records"][0]["resolves"] is None  # no verificable
    assert r.status not in (Status.WARNING, Status.ERROR)


def test_a_timeout_y_aaaa_noanswer_es_unknown(monkeypatch):
    r = _run(monkeypatch, [FakeMx(10, MAIL)], _hosts(mail=(TIMEOUT(), NOANSWER())))
    assert r.status == Status.UNKNOWN and r.checked is False


def test_a_timeout_pero_aaaa_resuelve_es_ok(monkeypatch):
    r = _run(monkeypatch, [FakeMx(10, MAIL)], _hosts(mail=(TIMEOUT(), [FakeIp("2001:db8::1")])))
    assert r.status == Status.OK


def test_servfail_en_a_y_nxdomain_en_aaaa_no_es_concluyente_o_nxdomain(monkeypatch):
    # NXDOMAIN en cualquier consulta indica que el nombre no existe.
    r = _run(monkeypatch, [FakeMx(10, MAIL)], _hosts(mail=(SERVFAIL(), NXDOMAIN())))
    assert r.status == Status.WARNING


def test_un_mx_nxdomain_y_otro_timeout_sigue_siendo_warning(monkeypatch):
    r = _run(
        monkeypatch,
        [FakeMx(10, MAIL), FakeMx(20, MAIL2)],
        _hosts(mail=(NXDOMAIN(), NXDOMAIN()), mail2=(TIMEOUT(), TIMEOUT())),
    )
    assert r.status == Status.WARNING  # hay un fallo confirmado
    assert [x["resolves"] for x in r.details["records"]] == [False, None]


def test_un_mx_resuelve_y_otro_timeout_es_unknown(monkeypatch):
    r = _run(
        monkeypatch,
        [FakeMx(10, MAIL), FakeMx(20, MAIL2)],
        _hosts(mail=(IP, NOANSWER()), mail2=(TIMEOUT(), TIMEOUT())),
    )
    assert r.status == Status.UNKNOWN and r.checked is False
    assert [x["resolves"] for x in r.details["records"]] == [True, None]


# --- Errores al consultar el MX del propio dominio (comportamiento previo) ---
def test_dominio_inexistente_es_unknown(monkeypatch):
    install_dns(monkeypatch, {})
    r = check_mx(D)
    assert r.status == Status.UNKNOWN and r.checked is False
    assert r.technical_reason == "dns_resolution_error"


def test_timeout_consultando_mx_es_unknown(monkeypatch):
    install_dns(monkeypatch, {(D, "MX"): TIMEOUT()})
    r = check_mx(D)
    assert r.status == Status.UNKNOWN and r.technical_reason == "timeout"


def test_servfail_consultando_mx_es_unknown(monkeypatch):
    install_dns(monkeypatch, {(D, "MX"): SERVFAIL()})
    r = check_mx(D)
    assert r.status == Status.UNKNOWN and r.technical_reason == "dns_error"
