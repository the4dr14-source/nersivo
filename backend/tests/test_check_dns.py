"""Tests de checks/dns.py con DNS mockeado (sin red real)."""

import dns.resolver
import pytest

from backend.checks.dns import check_dns
from backend.models import Status
from backend.tests.helpers import FakeIp, install_dns

D = "empresa.es"
A = [FakeIp("93.184.216.34")]
AAAA = [FakeIp("2001:db8::1")]
NOANSWER = dns.resolver.NoAnswer


def _run(monkeypatch, a, aaaa):
    install_dns(monkeypatch, {(D, "A"): a, (D, "AAAA"): aaaa})
    return check_dns(D)


def test_a_valido(monkeypatch):
    r = _run(monkeypatch, A, NOANSWER())
    assert r.status == Status.OK and r.checked is True
    assert r.details["resolves"] is True
    assert r.details["a_records"] == ["93.184.216.34"]
    assert r.details["aaaa_records"] == []


def test_aaaa_valido(monkeypatch):
    r = _run(monkeypatch, NOANSWER(), AAAA)
    assert r.status == Status.OK
    assert r.details["aaaa_records"] == ["2001:db8::1"]


def test_a_mas_aaaa(monkeypatch):
    r = _run(monkeypatch, A, AAAA)
    assert r.status == Status.OK
    assert r.details["a_records"] and r.details["aaaa_records"]


def test_a_inexistente_con_aaaa_valido_sigue_resolviendo(monkeypatch):
    r = _run(monkeypatch, NOANSWER(), AAAA)
    assert r.status == Status.OK
    assert r.details["resolves"] is True


def test_a_con_error_dns_pero_aaaa_valido_sigue_resolviendo(monkeypatch):
    r = _run(monkeypatch, dns.resolver.Timeout(), AAAA)
    assert r.status == Status.OK


def test_sin_a_ni_aaaa(monkeypatch):
    r = _run(monkeypatch, NOANSWER(), NOANSWER())
    assert r.status == Status.UNKNOWN
    assert r.technical_reason == "no_records"
    assert r.details["resolves"] is False


def test_nxdomain(monkeypatch):
    r = _run(monkeypatch, dns.resolver.NXDOMAIN(), dns.resolver.NXDOMAIN())
    assert r.status == Status.UNKNOWN
    assert r.technical_reason == "dns_resolution_error"
    assert r.details["resolves"] is False


@pytest.mark.parametrize("exc", [dns.resolver.Timeout, dns.resolver.NoNameservers])
def test_timeout_o_fallo_dns_es_unknown(monkeypatch, exc):
    r = _run(monkeypatch, exc(), exc())
    assert r.status == Status.UNKNOWN
    assert r.technical_reason in ("timeout", "dns_error")
    assert r.status not in (Status.WARNING, Status.ERROR)
