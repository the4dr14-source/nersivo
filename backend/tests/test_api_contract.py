"""
Tests de la API (FastAPI TestClient) y del contrato `nersivo_mvp_v1.json`.

Los checks de red se sustituyen por resultados fijos: no hay conexiones reales.
"""

import json
import os

import jsonschema
import pytest
from fastapi.testclient import TestClient

from backend import analyzer
from backend import main
from backend.models import AnalyzeResponse, Status
from backend.tests.helpers import make_check

SCHEMA_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "nersivo_mvp_v1.json")
)
CHECK_NAMES = ["web", "https", "dns", "mx", "spf", "dmarc"]

client = TestClient(main.app)


@pytest.fixture
def schema():
    with open(SCHEMA_PATH, encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture
def fake_checks(monkeypatch):
    """Sustituye los 6 checks por estados fijos (ok, ok, ok, warning, error, unknown)."""
    statuses = {
        "web": Status.OK,
        "https": Status.OK,
        "dns": Status.OK,
        "mx": Status.WARNING,
        "spf": Status.ERROR,
        "dmarc": Status.UNKNOWN,
    }
    for name, status in statuses.items():
        monkeypatch.setattr(analyzer, f"check_{name}", lambda d, s=status: make_check(s))


def test_root():
    r = client.get("/")
    assert r.status_code == 200
    assert r.json()["status"] == "running"


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "healthy"


def test_analyze_respuesta_valida_y_score_real(fake_checks):
    r = client.get("/analyze/example.com")
    assert r.status_code == 200
    body = r.json()
    assert list(body.keys()) == [
        "domain", "analyzed_at", "global_status", "score", "summary", "checks",
    ]
    assert body["domain"] == "example.com"
    assert body["global_status"] == "error"
    assert body["score"] == 70  # (3 + 0.5 + 0) / 5
    assert set(body["checks"]) == set(CHECK_NAMES)
    AnalyzeResponse.model_validate(body)


def test_analyze_subdominio_responde_200(fake_checks):
    r = client.get("/analyze/www.empresa.es")
    assert r.status_code == 200
    assert r.json()["domain"] == "www.empresa.es"


def test_analyze_dominio_invalido_400():
    for bad in ["127.0.0.1", "localhost", "foo"]:
        assert client.get(f"/analyze/{bad}").status_code == 400


def test_respuesta_cumple_el_contrato_json_schema(fake_checks, schema):
    body = client.get("/analyze/example.com").json()
    jsonschema.validate(body, schema)


def test_contrato_es_un_json_schema_valido_y_no_esta_vacio(schema):
    jsonschema.Draft202012Validator.check_schema(schema)
    assert schema["type"] == "object"
    assert set(schema["required"]) == {
        "domain", "analyzed_at", "global_status", "score", "summary", "checks",
    }
    # Sin campos inventados: solo los de la API.
    assert set(schema["properties"]) == set(schema["required"])
    assert schema.get("additionalProperties") is False


def test_contrato_define_los_seis_checks_y_los_enums(schema):
    defs = schema["$defs"]
    assert schema["properties"]["checks"]["$ref"] == "#/$defs/Checks"
    checks = defs["Checks"]
    assert set(checks["required"]) == set(CHECK_NAMES)
    assert set(checks["properties"]) == set(CHECK_NAMES)
    assert defs["Status"]["enum"] == ["ok", "warning", "error", "unknown"]
    assert defs["Severity"]["enum"] == [
        "none", "low", "medium", "high", "critical", "unknown",
    ]
    # score: entero 0-100 O null, y nada mÃ¡s.
    score = schema["properties"]["score"]
    assert score["anyOf"] == [
        {"type": "integer", "minimum": 0, "maximum": 100},
        {"type": "null"},
    ]
    assert "score" in schema["required"]  # siempre presente (puede ser null)


def test_contrato_campos_opcionales_del_check(schema):
    check = schema["$defs"]["CheckResult"]
    for required in ["status", "severity", "title", "summary", "checked", "details"]:
        assert required in check["required"]
    for optional in ["technical_reason", "recommendation", "user_message"]:
        assert optional not in check["required"]
        assert optional in check["properties"]


def test_contrato_rechaza_respuestas_invalidas(fake_checks, schema):
    body = client.get("/analyze/example.com").json()
    bad = dict(body, score=101)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(bad, schema)
    bad = dict(body, global_status="mock")
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(bad, schema)
    bad = {k: v for k, v in body.items() if k != "checks"}
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(bad, schema)


def test_contrato_no_se_desincroniza_de_los_modelos_pydantic(schema):
    """Si cambia models.py hay que regenerar/revisar nersivo_mvp_v1.json."""
    generated = AnalyzeResponse.model_json_schema()
    assert set(schema["properties"]) == set(generated["properties"])
    assert set(schema["required"]) == set(generated["required"])
    for name, definition in generated["$defs"].items():
        assert name in schema["$defs"]
        assert schema["$defs"][name].get("enum") == definition.get("enum")
        assert set(schema["$defs"][name].get("properties", {})) == set(
            definition.get("properties", {})
        )
        assert set(schema["$defs"][name].get("required", [])) == set(
            definition.get("required", [])
        )


def _set_all_unknown(monkeypatch):
    for name in CHECK_NAMES:
        monkeypatch.setattr(
            analyzer, f"check_{name}", lambda d: make_check(Status.UNKNOWN)
        )


def test_api_6_unknown_devuelve_score_null_y_global_unknown(monkeypatch, schema):
    _set_all_unknown(monkeypatch)
    body = client.get("/analyze/no-existe.example").json()
    assert body["score"] is None
    assert body["global_status"] == "unknown"
    assert body["summary"]["unknown"] == 6
    jsonschema.validate(body, schema)


def test_api_2_ok_4_unknown_score_null_pero_global_status_ok(monkeypatch, schema):
    for i, name in enumerate(CHECK_NAMES):
        st = Status.OK if i < 2 else Status.UNKNOWN
        monkeypatch.setattr(analyzer, f"check_{name}", lambda d, s=st: make_check(s))
    body = client.get("/analyze/example.com").json()
    assert body["score"] is None
    assert body["global_status"] == "ok"  # semÃ¡ntica existente, sin cambios
    assert body["summary"]["passed"] == 2 and body["summary"]["unknown"] == 4
    jsonschema.validate(body, schema)


def test_contrato_acepta_score_null_y_rechaza_otros_valores(fake_checks, schema):
    body = client.get("/analyze/example.com").json()
    jsonschema.validate(dict(body, score=None), schema)
    jsonschema.validate(dict(body, score=0), schema)
    jsonschema.validate(dict(body, score=100), schema)
    for bad in (-1, 101, 50.5, "72", True):
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(dict(body, score=bad), schema)


def test_contrato_score_coincide_con_pydantic(schema):
    generated = AnalyzeResponse.model_json_schema()["properties"]["score"]
    assert schema["properties"]["score"]["anyOf"] == generated["anyOf"]
