"""Tests de checks/web.py con DNS y HTTP mockeados (sin red real)."""

import socket

import httpx
import pytest

from backend.checks.web import check_web
from backend.models import Status
from backend.tests.helpers import fake_getaddrinfo

PUBLIC_IP = "93.184.216.34"


class Transport(httpx.BaseTransport):
    def __init__(self, handler):
        self.handler = handler

    def handle_request(self, request):
        return self.handler(request)


@pytest.fixture(autouse=True)
def _dns(monkeypatch):
    monkeypatch.setattr(
        socket, "getaddrinfo",
        fake_getaddrinfo({"example.com": PUBLIC_IP, "www.example.com": PUBLIC_IP}),
    )


def _run(handler):
    return check_web("example.com", transport=Transport(handler))


def test_http_2xx_sin_https_es_warning():
    r = _run(lambda req: httpx.Response(200))
    assert r.status == Status.WARNING
    assert r.technical_reason == "no_https_redirect"
    assert r.details["status_code"] == 200
    assert r.details["final_is_https"] is False


def test_http_redirige_a_https_es_ok():
    def handler(req):
        if req.url.scheme == "http":
            return httpx.Response(301, headers={"Location": "https://example.com/"})
        return httpx.Response(200)

    r = _run(handler)
    assert r.status == Status.OK
    assert r.details["redirected_to_https"] is True
    assert r.details["final_is_https"] is True
    assert r.details["redirect_chain"][-1] == "https://example.com/"


def test_http_con_varias_redirecciones_hasta_https_es_ok():
    calls = {"n": 0}

    def handler(req):
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(301, headers={"Location": "http://www.example.com/"})
        if calls["n"] == 2:
            return httpx.Response(301, headers={"Location": "https://www.example.com/"})
        return httpx.Response(200)

    r = _run(handler)
    assert r.status == Status.OK
    assert len(r.details["redirect_chain"]) == 3


def test_http_3xx_sin_resolver_es_warning():
    r = _run(lambda req: httpx.Response(302))  # redirección sin Location
    assert r.status == Status.WARNING
    assert r.technical_reason == "unresolved_redirect"


@pytest.mark.parametrize("code", [400, 401, 403, 404, 410])
def test_http_4xx_es_error(code):
    r = _run(lambda req: httpx.Response(code))
    assert r.status == Status.ERROR
    assert r.technical_reason == f"http_{code}"
    assert r.checked is True


@pytest.mark.parametrize("code", [500, 502, 503])
def test_http_5xx_es_error(code):
    r = _run(lambda req: httpx.Response(code))
    assert r.status == Status.ERROR
    assert r.technical_reason == "http_5xx"


def test_timeout_es_unknown():
    def handler(req):
        raise httpx.ConnectTimeout("timeout", request=req)

    r = _run(handler)
    assert r.status == Status.UNKNOWN
    assert r.technical_reason == "timeout"
    assert r.details["timeout"] is True


def test_error_de_conexion_es_unknown():
    def handler(req):
        raise httpx.ConnectError("Connection refused", request=req)

    r = _run(handler)
    assert r.status == Status.UNKNOWN
    assert r.technical_reason == "connection_error"


def test_estructura_de_details_se_mantiene():
    r = _run(lambda req: httpx.Response(200))
    assert set(r.details) >= {
        "requested_url", "final_url", "status_code", "redirect_chain",
        "redirected_to_https", "final_is_https", "response_time_ms", "error", "timeout",
    }
