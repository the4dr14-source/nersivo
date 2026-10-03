"""
Tests de subdominios y checks de correo (MX/SPF/DMARC).

Un hostname con varios labels (p. ej. www.empresa.es) NO debe excluirse
automáticamente de MX/SPF/DMARC.
"""

import dns.exception
import dns.resolver
import pytest

from backend import analyzer
from backend.checks.dmarc import check_dmarc
from backend.checks.mx import check_mx
from backend.checks.spf import check_spf
from backend.domain_utils import get_email_check_domain
from backend.models import Status
from backend.tests.helpers import make_check


class _Txt:
    def __init__(self, text):
        self.strings = (text.encode(),)


class _Mx:
    def __init__(self, pref, exchange):
        self.preference = pref
        self.exchange = exchange


def _install_dns(monkeypatch, table):
    """
    Mockea `Resolver.resolve`. `table`: (qname, rdtype) -> lista de rdata o
    excepción. Lo que no está en la tabla lanza NXDOMAIN.
    """

    def _resolve(self, qname, rdtype="A", *args, **kwargs):
        key = (str(qname).rstrip("."), rdtype)
        value = table.get(key, dns.resolver.NXDOMAIN())
        if isinstance(value, Exception):
            raise value
        return value

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", _resolve)


# ---------------------------------------------------------------------------
# analyzer: ya no hay exclusión automática por tener varios labels
# ---------------------------------------------------------------------------
def _record_calls(monkeypatch):
    calls = {}

    def recorder(name):
        def _check(domain):
            calls[name] = domain
            return make_check(Status.OK)

        return _check

    for name in ("web", "https", "dns", "mx", "spf", "dmarc"):
        monkeypatch.setattr(analyzer, f"check_{name}", recorder(name))
    return calls


@pytest.mark.parametrize(
    "host,email_domain",
    [
        ("example.com", "example.com"),
        ("www.example.com", "example.com"),
        ("petitglamour.es", "petitglamour.es"),
        ("www.petitglamour.es", "petitglamour.es"),
        ("www.empresa.com.es", "empresa.com.es"),
        # Subdominios que NO son www: se mantienen tal cual.
        ("mail.example.com", "mail.example.com"),
        ("smtp.example.com", "smtp.example.com"),
        ("aula-virtual.empresa.es", "aula-virtual.empresa.es"),
        ("a.b.empresa.com.es", "a.b.empresa.com.es"),
    ],
)
def test_analyzer_dominio_realmente_usado_por_cada_check(monkeypatch, host, email_domain):
    calls = _record_calls(monkeypatch)

    result = analyzer.analyze_domain(host)

    # La web, HTTPS y DNS usan SIEMPRE el hostname introducido.
    assert calls["web"] == host
    assert calls["https"] == host
    assert calls["dns"] == host
    # MX, SPF y DMARC usan el dominio de correo.
    assert calls["mx"] == email_domain
    assert calls["spf"] == email_domain
    assert calls["dmarc"] == email_domain
    # Ningún subdominio se marca como "no aplicable".
    for name in ("mx", "spf", "dmarc"):
        check = getattr(result.checks, name)
        assert check.technical_reason != "not_applicable_subdomain"
        assert check.checked is True
    assert result.score == 100


@pytest.mark.parametrize(
    "hostname,expected",
    [
        ("example.com", "example.com"),
        ("www.example.com", "example.com"),
        ("petitglamour.es", "petitglamour.es"),
        ("www.petitglamour.es", "petitglamour.es"),
        ("www.empresa.com.es", "empresa.com.es"),
        ("mail.example.com", "mail.example.com"),
        ("smtp.example.com", "smtp.example.com"),
        ("www.mail.example.com", "mail.example.com"),  # solo se quita el www. inicial
        ("wwwx.example.com", "wwwx.example.com"),  # 'wwwx' no es 'www'
        ("example.www.es", "example.www.es"),  # www no inicial: intacto
        ("www.com.es", "www.com.es"),  # quitar www. dejaría un sufijo público
        ("www.co.uk", "www.co.uk"),
    ],
)
def test_get_email_check_domain(hostname, expected):
    assert get_email_check_domain(hostname) == expected


def test_ya_no_existe_la_logica_not_applicable_subdomain():
    assert not hasattr(analyzer, "_mail_check_not_applicable")


# ---------------------------------------------------------------------------
# Checks reales sobre un subdominio (DNS mockeado)
# ---------------------------------------------------------------------------
def test_subdominio_con_registros_de_correo_es_ok(monkeypatch):
    host = "www.empresa.es"
    _install_dns(
        monkeypatch,
        {
            (host, "MX"): [_Mx(10, dns.name.from_text("mail.empresa.es."))],
            ("mail.empresa.es", "A"): [object()],
            (host, "TXT"): [_Txt("v=spf1 include:_spf.google.com ~all")],
            (f"_dmarc.{host}", "TXT"): [_Txt("v=DMARC1; p=reject")],
        },
    )

    assert check_mx(host).status == Status.OK
    assert check_spf(host).status == Status.OK
    assert check_dmarc(host).status == Status.OK


def test_subdominio_sin_registros_reales_es_warning_no_excluido(monkeypatch):
    host = "www.empresa.es"
    _install_dns(
        monkeypatch,
        {
            (host, "MX"): dns.resolver.NoAnswer(),
            (host, "TXT"): dns.resolver.NoAnswer(),
            (f"_dmarc.{host}", "TXT"): dns.resolver.NXDOMAIN(),
            (host, "A"): [object()],  # el host existe
        },
    )

    mx, spf, dmarc = check_mx(host), check_spf(host), check_dmarc(host)

    assert mx.technical_reason == "missing_mx" and mx.status == Status.WARNING
    assert spf.technical_reason == "missing_spf" and spf.status == Status.WARNING
    assert dmarc.technical_reason == "missing_dmarc" and dmarc.status == Status.WARNING
    assert all(c.checked for c in (mx, spf, dmarc))


# ---------------------------------------------------------------------------
# Se mantienen: Null MX, errores DNS y dominio inexistente
# ---------------------------------------------------------------------------
def test_null_mx_se_mantiene(monkeypatch):
    host = "empresa.es"
    _install_dns(monkeypatch, {(host, "MX"): [_Mx(0, dns.name.from_text("."))]})

    result = check_mx(host)

    assert result.status == Status.OK
    assert result.technical_reason == "null_mx"


def test_dominio_inexistente_es_unknown_en_los_tres_checks(monkeypatch):
    _install_dns(monkeypatch, {})  # todo NXDOMAIN

    for check in (check_mx, check_spf, check_dmarc):
        result = check("no-existe.empresa.es")
        assert result.status == Status.UNKNOWN
        assert result.checked is False
        assert result.technical_reason == "dns_resolution_error"


def test_timeout_dns_es_unknown(monkeypatch):
    host = "empresa.es"
    _install_dns(
        monkeypatch,
        {
            (host, "MX"): dns.resolver.Timeout(),
            (host, "TXT"): dns.resolver.Timeout(),
            (f"_dmarc.{host}", "TXT"): dns.resolver.Timeout(),
        },
    )

    for check in (check_mx, check_spf, check_dmarc):
        result = check(host)
        assert result.status == Status.UNKNOWN
        assert result.technical_reason in ("timeout", "dns_error", "dns_lookup_error")
