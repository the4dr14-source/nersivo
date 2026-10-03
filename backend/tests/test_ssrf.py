"""
Tests de protección SSRF (net_safety + check_web + check_https).

Todo el DNS y el HTTP están mockeados: NO se realizan conexiones reales ni
contra servicios internos. El transporte falso falla el test si se intenta
conectar a una IP no pública.
"""

import json
import socket

import httpx
import pytest

from backend import net_safety
from backend.checks.https import check_https
from backend.checks.web import check_web
from backend.models import Status
from backend.tests.helpers import fake_getaddrinfo

PUBLIC_IP = "93.184.216.34"
BLOCKED_CODES = {"blocked_private_ip", "blocked_non_public_ip", "blocked_redirect"}


class RecordingTransport(httpx.BaseTransport):
    """Transporte falso: registra peticiones y falla si la IP no es pública."""

    def __init__(self, handler):
        self.handler = handler
        self.requests = []

    def handle_request(self, request):
        self.requests.append(request)
        assert net_safety.classify_ip(request.url.host) is None, (
            f"Se intentó conectar a una IP no pública: {request.url.host}"
        )
        return self.handler(request)


def _patch_dns(monkeypatch, mapping):
    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo(mapping))


# ---------------------------------------------------------------------------
# Clasificación de IPs
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "ip,code",
    [
        ("127.0.0.1", "blocked_private_ip"),
        ("127.255.255.254", "blocked_private_ip"),
        ("10.0.0.1", "blocked_private_ip"),
        ("172.16.0.1", "blocked_private_ip"),
        ("172.31.255.255", "blocked_private_ip"),
        ("192.168.1.1", "blocked_private_ip"),
        ("169.254.169.254", "blocked_private_ip"),
        ("::1", "blocked_private_ip"),
        ("fe80::1", "blocked_private_ip"),
        ("fc00::1", "blocked_private_ip"),
        ("::ffff:127.0.0.1", "blocked_private_ip"),
        ("::ffff:10.0.0.1", "blocked_private_ip"),
        ("64:ff9b::7f00:1", "blocked_private_ip"),
        ("224.0.0.1", "blocked_non_public_ip"),
        ("ff02::1", "blocked_non_public_ip"),
        ("0.0.0.0", "blocked_non_public_ip"),
        ("::", "blocked_non_public_ip"),
        ("100.64.0.1", "blocked_non_public_ip"),
        ("240.0.0.1", "blocked_non_public_ip"),
    ],
)
def test_classify_ip_bloquea_no_publicas(ip, code):
    assert net_safety.classify_ip(ip) == code


@pytest.mark.parametrize("ip", ["8.8.8.8", PUBLIC_IP, "2606:4700:4700::1111"])
def test_classify_ip_permite_publicas(ip):
    assert net_safety.classify_ip(ip) is None


# ---------------------------------------------------------------------------
# check_web: dominio que RESUELVE a una IP no pública
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",
        "10.0.0.1",
        "192.168.1.1",
        "172.16.0.1",
        "169.254.169.254",
        "::1",  # loopback IPv6
        "fe80::1",  # link-local IPv6
    ],
)
def test_web_bloquea_dominio_que_resuelve_a_ip_no_publica(monkeypatch, ip):
    _patch_dns(monkeypatch, {"evil.example": ip})
    transport = RecordingTransport(lambda r: httpx.Response(200))

    result = check_web("evil.example", transport=transport)

    assert transport.requests == []  # nunca se llegó a conectar
    assert result.status == Status.UNKNOWN  # no se dice que el dominio esté mal
    assert result.checked is False
    assert result.technical_reason in BLOCKED_CODES
    assert "bloqueada por motivos de seguridad" in result.summary
    # No se expone la IP interna en ninguna parte de la respuesta.
    assert ip not in json.dumps(result.model_dump(mode="json"))


def test_web_bloquea_si_alguna_ip_del_dns_es_privada(monkeypatch):
    _patch_dns(monkeypatch, {"mixed.example": [PUBLIC_IP, "10.0.0.5"]})
    transport = RecordingTransport(lambda r: httpx.Response(200))

    result = check_web("mixed.example", transport=transport)

    assert transport.requests == []
    assert result.technical_reason == "blocked_private_ip"


# ---------------------------------------------------------------------------
# check_web: redirects
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "location,extra_dns",
    [
        ("http://127.0.0.1/", {}),
        ("http://127.0.0.1:8080/admin", {}),
        ("http://169.254.169.254/latest/meta-data/", {}),
        ("http://[::1]/", {}),
        ("http://[fe80::1]/", {}),
        ("http://2130706433/", {}),  # 127.0.0.1 en decimal
        ("http://0x7f.1/", {}),  # 127.0.0.1 en hex/forma abreviada
        ("http://127.1/", {}),
        ("http://internal.example/", {"internal.example": "192.168.1.10"}),
        ("https://internal.example/", {"internal.example": "10.0.0.5"}),
    ],
)
def test_web_bloquea_redirect_hacia_ip_privada(monkeypatch, location, extra_dns):
    _patch_dns(monkeypatch, {"public.example": PUBLIC_IP, **extra_dns})

    def handler(request):
        return httpx.Response(302, headers={"Location": location})

    transport = RecordingTransport(handler)
    result = check_web("public.example", transport=transport)

    assert len(transport.requests) == 1  # solo la petición al dominio público
    assert result.status == Status.UNKNOWN
    assert result.checked is False
    assert result.technical_reason == "blocked_redirect"
    assert "bloqueada por motivos de seguridad" in result.summary


@pytest.mark.parametrize(
    "location",
    ["file:///etc/passwd", "gopher://public.example/", "http://public.example:6379/"],
)
def test_web_bloquea_redirect_a_esquema_o_puerto_no_permitido(monkeypatch, location):
    _patch_dns(monkeypatch, {"public.example": PUBLIC_IP})
    transport = RecordingTransport(
        lambda r: httpx.Response(301, headers={"Location": location})
    )

    result = check_web("public.example", transport=transport)

    assert len(transport.requests) == 1
    assert result.technical_reason == "blocked_redirect"
    assert result.status == Status.UNKNOWN


# ---------------------------------------------------------------------------
# check_web: sitios normales NO se rompen
# ---------------------------------------------------------------------------
def test_web_http_publico_a_https_publico_sigue_funcionando(monkeypatch):
    _patch_dns(monkeypatch, {"example.com": PUBLIC_IP, "www.example.com": PUBLIC_IP})

    def handler(request):
        if request.url.scheme == "http":
            return httpx.Response(
                301, headers={"Location": "https://www.example.com/"}
            )
        return httpx.Response(200, text="hola")

    transport = RecordingTransport(handler)
    result = check_web("example.com", transport=transport)

    assert result.status == Status.OK
    assert result.checked is True
    d = result.details
    assert d["status_code"] == 200
    assert d["final_url"] == "https://www.example.com/"
    assert d["final_is_https"] is True
    assert d["redirected_to_https"] is True
    assert d["redirect_chain"][0] == "http://example.com"
    assert d["redirect_chain"][-1] == "https://www.example.com/"


def test_web_conecta_a_la_ip_validada_y_conserva_host_y_sni(monkeypatch):
    """Anti DNS-rebinding: se conecta a la IP validada, no se re-resuelve."""
    _patch_dns(monkeypatch, {"example.com": PUBLIC_IP})
    transport = RecordingTransport(lambda r: httpx.Response(200))

    check_web("example.com", transport=transport)

    req = transport.requests[0]
    assert req.url.host == PUBLIC_IP
    assert req.headers["Host"] == "example.com"


def test_web_https_directo_usa_sni_del_hostname(monkeypatch):
    _patch_dns(monkeypatch, {"example.com": PUBLIC_IP})
    transport = RecordingTransport(
        lambda r: httpx.Response(301, headers={"Location": "https://example.com/"})
    )
    # segunda petición (https) -> 200
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(301, headers={"Location": "https://example.com/"})
        return httpx.Response(200)

    transport = RecordingTransport(handler)
    result = check_web("example.com", transport=transport)

    assert result.status == Status.OK
    https_req = transport.requests[1]
    assert https_req.extensions["sni_hostname"] == "example.com"
    assert https_req.headers["Host"] == "example.com"


def test_web_redirect_relativo_publico(monkeypatch):
    _patch_dns(monkeypatch, {"example.com": PUBLIC_IP})
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(302, headers={"Location": "/home"})
        return httpx.Response(200)

    result = check_web("example.com", transport=RecordingTransport(handler))
    assert result.status == Status.WARNING  # 200 por HTTP, sin HTTPS
    assert result.details["final_url"] == "http://example.com/home"


def test_web_limite_de_redirects_se_mantiene(monkeypatch):
    _patch_dns(monkeypatch, {"loop.example": PUBLIC_IP})
    transport = RecordingTransport(
        lambda r: httpx.Response(302, headers={"Location": "http://loop.example/"})
    )

    result = check_web("loop.example", transport=transport)

    assert result.status == Status.WARNING
    assert result.technical_reason == "too_many_redirects"
    assert len(transport.requests) == 11  # petición inicial + 10 redirects


def test_web_dominio_inexistente_sigue_siendo_unknown_dns(monkeypatch):
    _patch_dns(monkeypatch, {})  # nada resuelve
    result = check_web("no-existe.example", transport=RecordingTransport(lambda r: None))

    assert result.status == Status.UNKNOWN
    assert result.technical_reason == "dns_resolution_error"
    assert result.checked is True  # fallo DNS normal, no bloqueo de seguridad


# ---------------------------------------------------------------------------
# check_https
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "fe80::1"])
def test_https_bloquea_dominio_que_resuelve_a_ip_no_publica(monkeypatch, ip):
    _patch_dns(monkeypatch, {"evil.example": ip})

    def no_connect(*a, **k):
        raise AssertionError("No debe abrirse ninguna conexión")

    monkeypatch.setattr(socket, "create_connection", no_connect)

    result = check_https("evil.example")

    assert result.status == Status.UNKNOWN
    assert result.checked is False
    assert result.technical_reason in BLOCKED_CODES
    assert "bloqueada por motivos de seguridad" in result.summary
    assert ip not in json.dumps(result.model_dump(mode="json"))


def test_https_conecta_a_la_ip_validada(monkeypatch):
    _patch_dns(monkeypatch, {"example.com": PUBLIC_IP})
    seen = {}

    def fake_connect(address, timeout=None, **kw):
        seen["address"] = address
        raise ConnectionRefusedError()

    monkeypatch.setattr(socket, "create_connection", fake_connect)

    result = check_https("example.com")

    assert seen["address"] == (PUBLIC_IP, 443)  # IP validada, no el nombre
    assert result.technical_reason == "https_not_available"
