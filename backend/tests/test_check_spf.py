"""Tests de checks/spf.py con DNS mockeado (sin red real)."""

import dns.resolver
import pytest

from backend.checks.spf import check_spf
from backend.models import Status
from backend.tests.helpers import FakeTxt, install_dns

D = "empresa.es"


def _run(monkeypatch, answer):
    install_dns(monkeypatch, {(D, "TXT"): answer})
    return check_spf(D)


def test_sin_registros_txt_es_warning(monkeypatch):
    r = _run(monkeypatch, dns.resolver.NoAnswer())
    assert r.status == Status.WARNING
    assert r.technical_reason == "missing_spf"
    assert r.details["found"] is False
    assert r.details["syntax_valid"] is None


def test_txt_que_no_es_spf_cuenta_como_sin_spf(monkeypatch):
    r = _run(monkeypatch, [FakeTxt("google-site-verification=abc"), FakeTxt("hola mundo")])
    assert r.status == Status.WARNING
    assert r.technical_reason == "missing_spf"
    assert r.details["record_count"] == 0


def test_un_spf_basico_es_ok(monkeypatch):
    r = _run(monkeypatch, [FakeTxt("v=spf1 include:_spf.google.com ~all"), FakeTxt("otro txt")])
    assert r.status == Status.OK and r.checked is True
    assert r.details["found"] is True
    assert r.details["record_count"] == 1
    assert r.details["records"] == ["v=spf1 include:_spf.google.com ~all"]
    assert r.details["syntax_valid"] is True


def test_spf_en_mayusculas_se_detecta(monkeypatch):
    r = _run(monkeypatch, [FakeTxt("V=SPF1 -all")])
    assert r.status == Status.OK


def test_spf_dividido_en_varios_fragmentos_se_reconstruye(monkeypatch):
    r = _run(monkeypatch, [FakeTxt("v=spf1 include:_spf.goo", "gle.com include:spf.protection", ".outlook.com ~all")])
    assert r.status == Status.OK
    assert r.details["records"] == [
        "v=spf1 include:_spf.google.com include:spf.protection.outlook.com ~all"
    ]


def test_multiples_spf_es_error(monkeypatch):
    r = _run(monkeypatch, [FakeTxt("v=spf1 -all"), FakeTxt("v=spf1 include:a.com ~all")])
    assert r.status == Status.ERROR
    assert r.technical_reason == "multiple_spf_records"
    assert r.details["record_count"] == 2
    assert r.details["syntax_valid"] is not True  # no se presenta como válido


# --- Significado real de syntax_valid: SOLO detección básica de `v=spf1` -----
def test_syntax_valid_es_solo_deteccion_basica_no_parser_completo(monkeypatch):
    """
    Un registro con prefijo `v=spf1` pero contenido sin sentido da
    syntax_valid=True: el campo NO valida la sintaxis SPF (RFC 7208).
    Este test documenta ese alcance; si algún día se añade un parser, hay que
    cambiarlo conscientemente.
    """
    r = _run(monkeypatch, [FakeTxt("v=spf1 esto-no-es-un-mecanismo ???")])
    assert r.status == Status.OK
    assert r.details["syntax_valid"] is True


def test_el_resumen_no_afirma_validez_completa(monkeypatch):
    r = _run(monkeypatch, [FakeTxt("v=spf1 -all")])
    assert "válido" not in r.summary.lower()


def test_el_modulo_documenta_el_alcance_de_syntax_valid():
    from backend.checks import spf

    assert "v=spf1" in spf.__doc__ and "NO implica" in spf.__doc__


# --- Errores DNS -> unknown, nunca error -------------------------------------
@pytest.mark.parametrize(
    "exc,reason",
    [
        (dns.resolver.NXDOMAIN(), "dns_resolution_error"),
        (dns.resolver.Timeout(), "timeout"),
        (dns.resolver.NoNameservers(), "dns_error"),
    ],
)
def test_errores_dns_son_unknown(monkeypatch, exc, reason):
    r = _run(monkeypatch, exc)
    assert r.status == Status.UNKNOWN
    assert r.checked is False
    assert r.technical_reason == reason
