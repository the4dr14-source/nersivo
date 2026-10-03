"""
Regresión: GET /analyze/<dominio inexistente> devolvía HTTP 500 porque el modelo
`AnalyzeResponse` en ejecución seguía exigiendo `score: int` y `analyze_domain`
devuelve `score=None` con menos de 3 checks evaluados.
"""

import socket

import dns.resolver
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from backend import analyzer
from backend import main
from backend import models
from backend.models import AnalyzeResponse, Status
from backend.tests.helpers import make_check

client = TestClient(main.app)

SUMMARY = dict(headline="h", total_checks=6, passed=0, warnings=0, errors=0, unknown=6)


def _payload(**overrides):
    ok = make_check(Status.UNKNOWN).model_dump()
    data = dict(
        domain="example.com",
        analyzed_at="2026-10-01T00:00:00Z",
        global_status="unknown",
        score=None,
        summary=SUMMARY,
        checks={n: ok for n in ("web", "https", "dns", "mx", "spf", "dmarc")},
    )
    data.update(overrides)
    return data


# --- El modelo usado en ejecución -------------------------------------------
def test_main_usa_el_mismo_AnalyzeResponse_que_models():
    assert main.AnalyzeResponse is models.AnalyzeResponse
    assert analyzer.AnalyzeResponse is models.AnalyzeResponse


def test_solo_hay_una_definicion_de_AnalyzeResponse():
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[1]
    hits = [
        p.name
        for p in root.rglob("*.py")
        if ".venv" not in p.parts
        and "tests" not in p.parts
        and "class AnalyzeResponse" in p.read_text(encoding="utf-8")
    ]
    assert hits == ["models.py"]


# --- AnalyzeResponse(score=None) es válido -----------------------------------
def test_analyzeresponse_acepta_score_none():
    assert AnalyzeResponse(**_payload(score=None)).score is None


@pytest.mark.parametrize("value", [0, 1, 50, 100])
def test_analyzeresponse_acepta_enteros_0_100(value):
    assert AnalyzeResponse(**_payload(score=value)).score == value


@pytest.mark.parametrize("value", [-1, 101, "abc"])
def test_analyzeresponse_rechaza_otros_valores(value):
    with pytest.raises(ValidationError):
        AnalyzeResponse(**_payload(score=value))


def test_analyzeresponse_score_sigue_siendo_obligatorio():
    data = _payload()
    del data["score"]
    with pytest.raises(ValidationError):
        AnalyzeResponse(**data)


# --- Dominio inexistente, usando los checks REALES con red mockeada ----------
def test_dominio_inexistente_http_200_score_null_global_unknown(monkeypatch):
    def nxdomain(self, qname, *a, **k):
        raise dns.resolver.NXDOMAIN()

    def gaierror(*a, **k):
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")

    def no_network(*a, **k):
        raise AssertionError("no debe haber conexiones reales")

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", nxdomain)
    monkeypatch.setattr(socket, "getaddrinfo", gaierror)
    monkeypatch.setattr(socket, "create_connection", no_network)

    r = client.get("/analyze/este-dominio-no-existe-987654321.com")

    assert r.status_code == 200  # no HTTP 500
    body = r.json()
    assert body["score"] is None
    assert body["global_status"] == "unknown"
    assert body["summary"]["unknown"] == 6
    assert all(c["status"] == "unknown" for c in body["checks"].values())


# --- Casos de score a través del endpoint (checks mockeados) -----------------
def _set(monkeypatch, **by_name):
    for name, status in by_name.items():
        monkeypatch.setattr(analyzer, f"check_{name}", lambda d, s=status: make_check(s))


def test_endpoint_google_com_score_92(monkeypatch):
    # 5 ok + 1 warning
    _set(monkeypatch, web=Status.OK, https=Status.OK, dns=Status.OK,
         mx=Status.OK, spf=Status.WARNING, dmarc=Status.OK)
    body = client.get("/analyze/google.com").json()
    assert body["score"] == 92


def test_endpoint_github_com_score_100(monkeypatch):
    _set(monkeypatch, web=Status.OK, https=Status.OK, dns=Status.OK,
         mx=Status.OK, spf=Status.OK, dmarc=Status.OK)
    body = client.get("/analyze/github.com").json()
    assert body["score"] == 100


def test_endpoint_mail_example_com_score_50(monkeypatch):
    # web/https/dns no evaluables; mx/spf/dmarc en warning -> 3 evaluados, 50
    _set(monkeypatch, web=Status.UNKNOWN, https=Status.UNKNOWN, dns=Status.UNKNOWN,
         mx=Status.WARNING, spf=Status.WARNING, dmarc=Status.WARNING)
    body = client.get("/analyze/mail.example.com").json()
    assert body["score"] == 50
    assert body["global_status"] == "warning"
