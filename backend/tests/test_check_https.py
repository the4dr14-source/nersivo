"""Tests de checks/https.py con TLS y reloj mockeados (sin red real)."""

import socket
import ssl
from datetime import datetime, timedelta, timezone

import pytest

from backend import net_safety
from backend.checks import https as https_mod
from backend.checks.https import check_https
from backend.models import Status

NOW = datetime(2026, 10, 1, 12, 0, 0, tzinfo=timezone.utc)


class FixedDatetime(datetime):
    """datetime con `now()` fijo para tests deterministas."""

    @classmethod
    def now(cls, tz=None):
        return NOW if tz else NOW.replace(tzinfo=None)


def _cert_date(dt: datetime) -> str:
    # Formato ASN.1 que entiende ssl.cert_time_to_seconds.
    return dt.strftime("%b %d %H:%M:%S %Y GMT")


def _cert(expires_at: datetime, dns_names=("example.com",)) -> dict:
    return {
        "notBefore": _cert_date(NOW - timedelta(days=60)),
        "notAfter": _cert_date(expires_at),
        "subjectAltName": tuple(("DNS", n) for n in dns_names),
    }


class _FakeSSock:
    def __init__(self, cert):
        self._cert = cert

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def getpeercert(self):
        return self._cert


class _FakeContext:
    def __init__(self, cert=None, wrap_error=None):
        self.cert, self.wrap_error = cert, wrap_error

    def wrap_socket(self, sock, server_hostname=None):
        if self.wrap_error:
            raise self.wrap_error
        return _FakeSSock(self.cert)


@pytest.fixture(autouse=True)
def _fixed_clock_and_socket(monkeypatch):
    monkeypatch.setattr(https_mod, "datetime", FixedDatetime)
    monkeypatch.setattr(
        net_safety, "create_safe_connection", lambda *a, **k: object()
    )


def _run(monkeypatch, cert=None, wrap_error=None, connect_error=None, domain="example.com"):
    monkeypatch.setattr(
        ssl, "create_default_context", lambda: _FakeContext(cert, wrap_error)
    )
    if connect_error is not None:
        def _raise(*a, **k):
            raise connect_error

        monkeypatch.setattr(net_safety, "create_safe_connection", _raise)
    return check_https(domain)


def _expiring_in(delta: timedelta, monkeypatch):
    return _run(monkeypatch, cert=_cert(NOW + delta))


# --- Clasificación por tiempo real restante ----------------------------------
def test_mas_de_30_dias_ok(monkeypatch):
    r = _expiring_in(timedelta(days=31), monkeypatch)
    assert r.status == Status.OK
    assert r.details["days_remaining"] == 31
    assert r.details["valid"] is True


def test_30_dias_y_unas_horas_sigue_siendo_ok(monkeypatch):
    assert _expiring_in(timedelta(days=30, hours=5), monkeypatch).status == Status.OK


def test_exactamente_30_dias_warning(monkeypatch):
    r = _expiring_in(timedelta(days=30), monkeypatch)
    assert r.status == Status.WARNING
    assert r.technical_reason == "expiring_soon"


@pytest.mark.parametrize("days", [8, 7, 1])
def test_dias_restantes_warning(monkeypatch, days):
    r = _expiring_in(timedelta(days=days), monkeypatch)
    assert r.status == Status.WARNING
    assert r.checked is True
    assert r.details["valid"] is True


def test_8_dias_es_expiring_soon_y_7_dias_expiring_very_soon(monkeypatch):
    assert _expiring_in(timedelta(days=8), monkeypatch).technical_reason == "expiring_soon"
    assert _expiring_in(timedelta(days=7), monkeypatch).technical_reason == "expiring_very_soon"


def test_23_horas_es_warning_y_nunca_error(monkeypatch):
    r = _expiring_in(timedelta(hours=23), monkeypatch)
    assert r.status == Status.WARNING
    assert r.status != Status.ERROR
    assert r.details["days_remaining"] == 0  # solo informativo
    assert r.details["valid"] is True
    assert r.technical_reason == "expiring_very_soon"
    assert "0 días" not in r.summary  # no se muestra "0 días"
    assert "menos de 1 día" in r.summary


def test_1_hora_es_warning(monkeypatch):
    r = _expiring_in(timedelta(hours=1), monkeypatch)
    assert r.status == Status.WARNING
    assert r.technical_reason != "certificate_expired"


def test_1_segundo_restante_es_warning(monkeypatch):
    assert _expiring_in(timedelta(seconds=1), monkeypatch).status == Status.WARNING


def test_exactamente_expirado_es_error(monkeypatch):
    r = _expiring_in(timedelta(0), monkeypatch)  # expires_at == now
    assert r.status == Status.ERROR
    assert r.technical_reason == "certificate_expired"
    assert r.details["valid"] is False


@pytest.mark.parametrize("delta", [timedelta(seconds=-1), timedelta(hours=-1), timedelta(days=-3)])
def test_expirado_es_error(monkeypatch, delta):
    r = _expiring_in(delta, monkeypatch)
    assert r.status == Status.ERROR
    assert r.technical_reason == "certificate_expired"
    assert r.severity.value == "critical"


def test_days_remaining_no_decide_la_expiracion(monkeypatch):
    # Con 23 h days_remaining vale 0 (<= 0) y aun así NO está expirado.
    r = _expiring_in(timedelta(hours=23), monkeypatch)
    assert r.details["days_remaining"] <= 0
    assert r.technical_reason != "certificate_expired"


def test_estructura_de_details_se_mantiene(monkeypatch):
    r = _expiring_in(timedelta(days=60), monkeypatch)
    assert set(r.details) == {
        "https_available", "valid", "matches_domain",
        "issued_at", "expires_at", "days_remaining", "error",
    }
    assert r.details["expires_at"] == (NOW + timedelta(days=60)).strftime("%Y-%m-%dT%H:%M:%SZ")


# --- Hostname y errores TLS/red ----------------------------------------------
def test_hostname_mismatch_por_certificado(monkeypatch):
    r = _run(monkeypatch, cert=_cert(NOW + timedelta(days=90), dns_names=("otro.com",)))
    assert r.status == Status.ERROR
    assert r.technical_reason == "hostname_mismatch"
    assert r.details["matches_domain"] is False


def test_hostname_mismatch_por_excepcion_tls(monkeypatch):
    exc = ssl.SSLCertVerificationError("Hostname mismatch, certificate is not valid for 'example.com'")
    r = _run(monkeypatch, wrap_error=exc)
    assert r.status == Status.ERROR
    assert r.technical_reason == "hostname_mismatch"


def test_certificado_expirado_por_excepcion_tls(monkeypatch):
    exc = ssl.SSLCertVerificationError("certificate has expired")
    r = _run(monkeypatch, wrap_error=exc)
    assert r.status == Status.ERROR
    assert r.technical_reason == "certificate_expired"


def test_certificado_autofirmado(monkeypatch):
    exc = ssl.SSLCertVerificationError("self signed certificate")
    r = _run(monkeypatch, wrap_error=exc)
    assert r.status == Status.ERROR
    assert r.technical_reason == "self_signed_certificate"


def test_error_tls_generico(monkeypatch):
    r = _run(monkeypatch, wrap_error=ssl.SSLError("handshake failure"))
    assert r.status == Status.ERROR
    assert r.technical_reason == "tls_error"


def test_timeout_es_unknown(monkeypatch):
    r = _run(monkeypatch, connect_error=socket.timeout())
    assert r.status == Status.UNKNOWN
    assert r.technical_reason == "timeout"


def test_conexion_rechazada_es_error_https_no_disponible(monkeypatch):
    r = _run(monkeypatch, connect_error=ConnectionRefusedError())
    assert r.status == Status.ERROR
    assert r.technical_reason == "https_not_available"
    assert r.details["https_available"] is False


def test_dns_no_resuelve_es_unknown(monkeypatch):
    r = _run(monkeypatch, connect_error=socket.gaierror(socket.EAI_NONAME, "x"))
    assert r.status == Status.UNKNOWN


def test_otro_error_de_conexion_es_unknown(monkeypatch):
    r = _run(monkeypatch, connect_error=OSError("network unreachable"))
    assert r.status == Status.UNKNOWN


def test_excepcion_inesperada_es_unknown(monkeypatch):
    r = _run(monkeypatch, connect_error=RuntimeError("boom"))
    assert r.status == Status.UNKNOWN
