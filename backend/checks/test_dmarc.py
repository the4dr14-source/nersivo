"""
Tests del check DMARC (backend/checks/dmarc.py).

Se mockea `dns.resolver.Resolver.resolve` para no depender de la red y cubrir
los 9 casos de la especificación del MVP.
"""

import logging
from unittest import mock

import pytest

import dns.exception
import dns.resolver

from backend.checks.dmarc import check_dmarc
from backend.models import Status


class _FakeRdata:
    """Simula un rdata TXT de dnspython con atributo `strings` (tupla de bytes)."""

    def __init__(self, *string_fragments):
        # dnspython entrega los fragmentos del TXT como bytes.
        self.strings = tuple(
            s if isinstance(s, bytes) else s.encode("utf-8") for s in string_fragments
        )


def _make_resolve(return_value=None, exception=None):
    """
    Crea una función que sustituye a Resolver.resolve.

    Si se pasa `exception`, la lanza. Si no, devuelve `return_value` (lista de
    _FakeRdata).
    """

    def _resolve(self, qname, rdtype):  # noqa: ANN001
        if exception is not None:
            raise exception
        return return_value

    return _resolve


# ---------------------------------------------------------------------------
# Caso 1, 2, 3 y 9: registros DMARC válidos -> ok
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "record,expected_policy",
    [
        ("v=DMARC1; p=none", "none"),
        ("v=DMARC1; p=quarantine", "quarantine"),
        ("v=DMARC1; p=reject", "reject"),
        ("v=DMARC1; p=none; rua=mailto:dmarc@example.com; pct=100", "none"),
    ],
)
def test_dmarc_valido_es_ok(record, expected_policy):
    fake_answers = [_FakeRdata(record)]
    with mock.patch.object(
        dns.resolver.Resolver, "resolve", _make_resolve(return_value=fake_answers)
    ):
        result = check_dmarc("example.com")

    assert result.status == Status.OK
    assert result.details["found"] is True
    assert result.details["policy"] == expected_policy
    assert result.details["syntax_valid"] is True
    assert result.details["error"] is None
    assert result.technical_reason is None


# ---------------------------------------------------------------------------
# Caso 4: DMARC inexistente (el dominio base SÍ existe) -> warning
# ---------------------------------------------------------------------------
def _make_resolve_by_name(dmarc_exc, base_resolves=True):
    """
    Mock de Resolver.resolve sensible al nombre consultado.

    - Para `_dmarc.<domain>` lanza `dmarc_exc`.
    - Para el dominio base (consulta A/AAAA en `_base_domain_resolvable`):
        * si `base_resolves` es True  -> lanza NoAnswer (el nombre existe).
        * si `base_resolves` es False -> lanza NXDOMAIN (el nombre no existe).
    """

    def _resolve(self, qname, rdtype):  # noqa: ANN001
        if str(qname).startswith("_dmarc."):
            raise dmarc_exc
        if base_resolves:
            raise dns.resolver.NoAnswer()
        raise dns.resolver.NXDOMAIN()

    return _resolve


@pytest.mark.parametrize(
    "exc",
    [
        dns.resolver.NXDOMAIN(),
        dns.resolver.NoAnswer(),
    ],
)
def test_dmarc_inexistente_es_warning(exc):
    # El dominio base existe pero no tiene DMARC -> missing_dmarc (warning).
    with mock.patch.object(
        dns.resolver.Resolver, "resolve", _make_resolve_by_name(exc, base_resolves=True)
    ):
        result = check_dmarc("example.com")

    assert result.status == Status.WARNING
    assert result.technical_reason == "missing_dmarc"
    assert result.details["found"] is False
    assert result.details["error"] is None
    assert result.checked is True


def test_dmarc_dominio_base_inexistente_es_unknown():
    # NXDOMAIN también del dominio base -> no podemos concluir que falte DMARC.
    with mock.patch.object(
        dns.resolver.Resolver,
        "resolve",
        _make_resolve_by_name(dns.resolver.NXDOMAIN(), base_resolves=False),
    ):
        result = check_dmarc("este-dominio-no-existe-12345.com")

    assert result.status == Status.UNKNOWN
    assert result.severity.value == "unknown"
    assert result.checked is False
    assert result.technical_reason == "dns_resolution_error"
    assert result.details["error"] == "dns_resolution_error"


def test_dmarc_sin_candidatos_pero_con_otros_txt_es_warning():
    # Hay TXT pero ninguno es DMARC (p. ej. un SPF colocado por error aquí).
    fake_answers = [_FakeRdata("v=spf1 include:_spf.google.com ~all")]
    with mock.patch.object(
        dns.resolver.Resolver, "resolve", _make_resolve(return_value=fake_answers)
    ):
        result = check_dmarc("example.com")

    assert result.status == Status.WARNING
    assert result.technical_reason == "missing_dmarc"
    assert result.details["found"] is False


# ---------------------------------------------------------------------------
# Caso 5: DMARC sin p= -> error invalid_dmarc_record
# ---------------------------------------------------------------------------
def test_dmarc_sin_politica_es_error():
    fake_answers = [_FakeRdata("v=DMARC1; rua=mailto:dmarc@example.com")]
    with mock.patch.object(
        dns.resolver.Resolver, "resolve", _make_resolve(return_value=fake_answers)
    ):
        result = check_dmarc("example.com")

    assert result.status == Status.ERROR
    assert result.technical_reason == "invalid_dmarc_record"
    assert result.details["syntax_valid"] is False
    assert result.details["policy"] is None
    assert result.details["error"] == "invalid_dmarc_record"


# ---------------------------------------------------------------------------
# Caso 6: política p= inválida -> error invalid_dmarc_record
# ---------------------------------------------------------------------------
def test_dmarc_politica_invalida_es_error():
    fake_answers = [_FakeRdata("v=DMARC1; p=invalid")]
    with mock.patch.object(
        dns.resolver.Resolver, "resolve", _make_resolve(return_value=fake_answers)
    ):
        result = check_dmarc("example.com")

    assert result.status == Status.ERROR
    assert result.technical_reason == "invalid_dmarc_record"
    assert result.details["syntax_valid"] is False


# ---------------------------------------------------------------------------
# Caso 7: múltiples registros DMARC -> error multiple_dmarc_records
# ---------------------------------------------------------------------------
def test_dmarc_multiples_registros_es_error():
    fake_answers = [
        _FakeRdata("v=DMARC1; p=none"),
        _FakeRdata("v=DMARC1; p=reject"),
    ]
    with mock.patch.object(
        dns.resolver.Resolver, "resolve", _make_resolve(return_value=fake_answers)
    ):
        result = check_dmarc("example.com")

    assert result.status == Status.ERROR
    assert result.technical_reason == "multiple_dmarc_records"
    assert result.details["error"] == "multiple_dmarc_records"


# ---------------------------------------------------------------------------
# Caso 8: error/timeout de consulta DNS -> unknown (NO error y NUNCA "sin DMARC")
# ---------------------------------------------------------------------------
def _assert_fallo_no_es_ausencia(result):
    """Un fallo de resolución jamás debe presentarse como DMARC ausente confirmado."""
    assert result.status == Status.UNKNOWN
    assert result.status != Status.WARNING
    assert result.technical_reason != "missing_dmarc"
    assert result.details["found"] is False
    assert result.details["record"] is None
    assert result.checked is True


@pytest.mark.parametrize(
    "exc",
    [
        dns.resolver.Timeout(),
        dns.resolver.LifetimeTimeout(timeout=5.0, errors=[]),
        dns.exception.Timeout(),  # clase base: no es el alias de `dns.resolver.Timeout`
    ],
)
def test_dmarc_timeout_dns_es_unknown_con_codigo_timeout(exc):
    # `timeout` es el mismo código que ya usan SPF/MX/DNS y que entiende el frontend.
    with mock.patch.object(
        dns.resolver.Resolver, "resolve", _make_resolve(exception=exc)
    ):
        result = check_dmarc("example.com")

    _assert_fallo_no_es_ausencia(result)
    assert result.technical_reason == "timeout"
    assert result.details["error"] == "timeout"


@pytest.mark.parametrize(
    "exc",
    [
        dns.resolver.NoNameservers(),  # SERVFAIL/REFUSED de todos los servidores
        dns.resolver.NoResolverConfiguration(),
        dns.resolver.YXDOMAIN(),
        dns.exception.DNSException(),
    ],
)
def test_dmarc_error_dns_es_unknown(exc):
    with mock.patch.object(
        dns.resolver.Resolver, "resolve", _make_resolve(exception=exc)
    ):
        result = check_dmarc("example.com")

    _assert_fallo_no_es_ausencia(result)
    assert result.technical_reason == "dns_lookup_error"
    assert result.details["error"] == "dns_lookup_error"


def test_dmarc_resolver_que_falla_al_crearse_es_error_dns():
    # `Resolver()` lee la configuración del sistema y puede lanzar
    # NoResolverConfiguration (una DNSException) al construirse.
    with mock.patch.object(
        dns.resolver.Resolver,
        "__init__",
        side_effect=dns.resolver.NoResolverConfiguration(),
    ):
        result = check_dmarc("example.com")

    _assert_fallo_no_es_ausencia(result)
    assert result.technical_reason == "dns_lookup_error"


# ---------------------------------------------------------------------------
# Errores INTERNOS (no DNS): no deben disfrazarse de dns_lookup_error
# ---------------------------------------------------------------------------
def _assert_error_interno(result, caplog, exc_type):
    assert result.status == Status.UNKNOWN
    assert result.technical_reason == "unknown_error"
    assert result.technical_reason != "dns_lookup_error"
    assert result.details["error"] == "unknown_error"
    assert result.details["found"] is False
    assert result.checked is True
    # La traza queda registrada para que el bug no pase desapercibido.
    assert any(
        r.levelno == logging.ERROR and r.exc_info and r.exc_info[0] is exc_type
        for r in caplog.records
    )


@pytest.mark.parametrize("exc", [RuntimeError("bug"), AttributeError("bug"), TypeError("bug")])
def test_dmarc_excepcion_no_dns_no_se_clasifica_como_error_dns(exc, caplog):
    with caplog.at_level(logging.ERROR, logger="backend.checks.dmarc"), mock.patch.object(
        dns.resolver.Resolver, "resolve", _make_resolve(exception=exc)
    ):
        result = check_dmarc("example.com")

    _assert_error_interno(result, caplog, type(exc))


def test_dmarc_error_de_parseo_no_se_clasifica_como_error_dns(caplog):
    # La consulta DNS termina bien, pero la respuesta no se puede interpretar
    # (un rdata sin `.strings`): es un bug interno, no un fallo de resolución.
    with caplog.at_level(logging.ERROR, logger="backend.checks.dmarc"), mock.patch.object(
        dns.resolver.Resolver, "resolve", _make_resolve(return_value=[object()])
    ):
        result = check_dmarc("example.com")

    _assert_error_interno(result, caplog, AttributeError)


# ---------------------------------------------------------------------------
# NXDOMAIN de `_dmarc.<dominio>`: el resultado depende de `_base_domain_resolvable`
#   True -> DMARC ausente | False -> dominio no resoluble | None -> no concluyente
#   excepción inesperada -> error interno (no DNS)
# ---------------------------------------------------------------------------
_BASE_DOMAIN = "backend.checks.dmarc._base_domain_resolvable"


def test_dmarc_nxdomain_con_dominio_base_resoluble_es_ausencia_confirmada():
    with mock.patch.object(
        dns.resolver.Resolver, "resolve", _make_resolve(exception=dns.resolver.NXDOMAIN())
    ), mock.patch(_BASE_DOMAIN, return_value=True):
        result = check_dmarc("example.com")

    assert result.status == Status.WARNING
    assert result.severity.value == "medium"
    assert result.technical_reason == "missing_dmarc"
    assert result.details["found"] is False
    assert result.details["error"] is None
    assert result.checked is True


def test_dmarc_nxdomain_con_dominio_base_inexistente_se_conserva():
    with mock.patch.object(
        dns.resolver.Resolver, "resolve", _make_resolve(exception=dns.resolver.NXDOMAIN())
    ), mock.patch(_BASE_DOMAIN, return_value=False):
        result = check_dmarc("este-dominio-no-existe-12345.com")

    assert result.status == Status.UNKNOWN
    assert result.severity.value == "unknown"
    assert result.checked is False
    assert result.technical_reason == "dns_resolution_error"
    assert result.details["error"] == "dns_resolution_error"


def test_dmarc_nxdomain_con_dominio_base_indeterminado_no_es_missing_dmarc():
    # `_base_domain_resolvable` devuelve None: no sabemos si el dominio existe.
    with mock.patch.object(
        dns.resolver.Resolver, "resolve", _make_resolve(exception=dns.resolver.NXDOMAIN())
    ), mock.patch(_BASE_DOMAIN, return_value=None):
        result = check_dmarc("example.com")

    _assert_fallo_no_es_ausencia(result)  # UNKNOWN, no warning, no missing_dmarc, checked=True
    assert result.severity.value == "unknown"
    assert result.technical_reason == "dns_lookup_error"
    assert result.details["error"] == "dns_lookup_error"


@pytest.mark.parametrize(
    "base_exc",
    [
        dns.resolver.Timeout(),
        dns.resolver.NoNameservers(),
        dns.exception.DNSException(),
    ],
)
def test_dmarc_nxdomain_y_dominio_base_con_fallo_dns_es_unknown(base_exc):
    # Sin parchear el helper: las consultas A y AAAA del dominio base fallan sin
    # respuesta concluyente, así que el helper devuelve None de verdad.
    def _resolve(self, qname, rdtype):  # noqa: ANN001
        if str(qname).startswith("_dmarc."):
            raise dns.resolver.NXDOMAIN()
        raise base_exc

    with mock.patch.object(dns.resolver.Resolver, "resolve", _resolve):
        result = check_dmarc("example.com")

    _assert_fallo_no_es_ausencia(result)
    assert result.technical_reason == "dns_lookup_error"
    assert result.details["error"] == "dns_lookup_error"


@pytest.mark.parametrize("exc", [RuntimeError("bug"), AttributeError("bug"), TypeError("bug")])
def test_dmarc_error_inesperado_al_comprobar_dominio_base_es_error_interno(exc, caplog):
    # Un bug en `_base_domain_resolvable` NO debe escapar de `check_dmarc` ni
    # disfrazarse de error DNS ni de DMARC ausente.
    with caplog.at_level(logging.ERROR, logger="backend.checks.dmarc"), mock.patch.object(
        dns.resolver.Resolver, "resolve", _make_resolve(exception=dns.resolver.NXDOMAIN())
    ), mock.patch(_BASE_DOMAIN, side_effect=exc):
        result = check_dmarc("example.com")

    _assert_error_interno(result, caplog, type(exc))
    assert result.status != Status.WARNING
    assert result.technical_reason != "missing_dmarc"


# ---------------------------------------------------------------------------
# Configuración del resolver: timeout por intento (2 s) < lifetime total (5 s)
# ---------------------------------------------------------------------------
def test_dmarc_configura_el_resolver_con_timeout_2_y_lifetime_5():
    seen = {}

    def _resolve(self, qname, rdtype):  # noqa: ANN001
        seen["timeout"] = self.timeout
        seen["lifetime"] = self.lifetime
        return [_FakeRdata("v=DMARC1; p=reject")]

    with mock.patch.object(dns.resolver.Resolver, "resolve", _resolve):
        result = check_dmarc("example.com")

    # La consulta termina correctamente con el resolver configurado.
    assert result.status == Status.OK
    assert result.details["policy"] == "reject"
    assert seen == {"timeout": 2.0, "lifetime": 5.0}
    # Si timeout >= lifetime, un nameserver caído agota el plazo sin failover.
    assert seen["timeout"] < seen["lifetime"]


# ---------------------------------------------------------------------------
# Extra: TXT dividido en varias cadenas se reconstruye correctamente
# ---------------------------------------------------------------------------
def test_dmarc_txt_dividido_se_reconstruye():
    fake_answers = [_FakeRdata("v=DMARC1; p=", "quarantine; pct=100")]
    with mock.patch.object(
        dns.resolver.Resolver, "resolve", _make_resolve(return_value=fake_answers)
    ):
        result = check_dmarc("example.com")

    assert result.status == Status.OK
    assert result.details["policy"] == "quarantine"


# ---------------------------------------------------------------------------
# Extra: se consulta _dmarc.<dominio>, no el dominio raíz
# ---------------------------------------------------------------------------
def test_dmarc_consulta_subdominio_dmarc():
    captured = {}

    def _resolve(self, qname, rdtype):  # noqa: ANN001
        captured["qname"] = qname
        captured["rdtype"] = rdtype
        return [_FakeRdata("v=DMARC1; p=none")]

    with mock.patch.object(dns.resolver.Resolver, "resolve", _resolve):
        check_dmarc("example.com")

    assert captured["qname"] == "_dmarc.example.com"
    assert captured["rdtype"] == "TXT"
