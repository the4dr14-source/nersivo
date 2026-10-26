"""Tests de `backend/guides`: catálogo, constructor y `POST /guides`."""

import re
import socket

import httpx
import pytest
from fastapi.testclient import TestClient

from backend import main
from backend.guides import builder, catalog
from backend.guides import routes as guides_routes
from backend.providers import ProviderContext, ProviderMatch
from backend.tests.monitor_helpers import analysis, check

client = TestClient(main.app)

GOOGLE = ProviderMatch("google_workspace", "Google Workspace", "high", ("MX aspmx.l.google.com",))
MICROSOFT = ProviderMatch("microsoft_365", "Microsoft 365", "high", ("MX x.mail.protection.outlook.com",))
IONOS = ProviderMatch("ionos", "IONOS", "high", ("MX mx00.ionos.es",))
CLOUDFLARE = ProviderMatch("cloudflare", "Cloudflare", "high", ("NS ada.ns.cloudflare.com",))
HETZNER = ProviderMatch("hetzner", "Hetzner", "high", ("NS hydrogen.ns.hetzner.com",))
NONE = ProviderContext()

REQUIRED = [
    ("web", "no_https_redirect", "warning"),
    ("https", "https_not_available", "error"),
    ("https", "expiring_soon", "warning"),
    ("https", "expiring_very_soon", "warning"),
    ("https", "certificate_expired", "error"),
    ("https", "hostname_mismatch", "error"),
    ("https", "self_signed_certificate", "error"),
    ("https", "invalid_certificate", "error"),
    ("https", "tls_error", "error"),
    ("mx", "missing_mx", "warning"),
    ("mx", "mx_resolution_issue", "warning"),
    ("spf", "missing_spf", "warning"),
    ("spf", "multiple_spf_records", "error"),
    ("dmarc", "missing_dmarc", "warning"),
    ("dmarc", "multiple_dmarc_records", "error"),
    ("dmarc", "invalid_dmarc_record", "error"),
    ("web", "too_many_redirects", "error"),
    ("web", "unresolved_redirect", "error"),
]


def one(name, status, reason, ctx=NONE, domain="example.com", **details):
    a = analysis(domain, **{name: check(name, status, reason, **details)})
    return builder.build_guides(a, ctx)


# ---------------------------------------------------------------- catálogo
def test_catalogo_es_consistente():
    macros = {"@dns_open", "@dns_save", "@recheck"}
    for key, d in catalog.GUIDES.items():
        check_name = key.split(":")[0]
        assert check_name in builder.CHECK_ORDER
        assert d.title and d.why and d.steps and d.verify
        assert all(not s.startswith("@") or s in macros for s in d.steps), key
        assert d.values is None or d.values in builder.VALUE_BUILDERS
        assert d.detected is None or d.detected in builder.DETECTED_BUILDERS
        assert d.uses in (None, "mail", "dns_panel", "both")
    assert set(catalog.FALLBACKS) == set(builder.CHECK_ORDER)


def test_valores_spf_solo_para_proveedores_verificados():
    assert set(catalog.SPF_INCLUDES) == {"google_workspace", "microsoft_365"}
    assert all(v.startswith("v=spf1 include:") for v in catalog.SPF_INCLUDES.values())


@pytest.mark.parametrize("name,reason,status", REQUIRED)
def test_cada_problema_requerido_tiene_guia_especifica(name, reason, status):
    (guide,) = one(name, status, reason)
    assert not guide.guide_id.startswith("fallback"), (name, reason)
    assert guide.check == name and guide.problem_code == reason
    assert guide.steps and guide.verify and guide.why and guide.title


def test_codigo_desconocido_cae_en_la_guia_generica_del_check():
    (guide,) = one("spf", "warning", "algo_nuevo")
    assert guide.guide_id == "fallback.spf" and guide.audience == "generic"


def test_codigo_http_de_web_usa_la_guia_de_error_http():
    for code in ("http_404", "http_503"):
        (guide,) = one("web", "error", code)
        assert guide.guide_id == "web.http_error"


@pytest.mark.parametrize("name", builder.CHECK_ORDER)
def test_todo_check_con_problema_siempre_tiene_alguna_guia(name):
    assert len(one(name, "error", None)) == 1 and len(one(name, "warning", "zzz")) == 1


def test_ok_y_unknown_no_generan_guias():
    a = analysis(
        spf=check("spf", "unknown", "timeout"),
        dmarc=check("dmarc", "unknown", "dns_resolution_error"),
        mx=check("mx", "ok"),
    )
    assert builder.build_guides(a, NONE) == []


def test_orden_estable_de_las_guias():
    a = analysis(
        dmarc=check("dmarc", "warning", "missing_dmarc"),
        web=check("web", "warning", "no_https_redirect"),
        spf=check("spf", "warning", "missing_spf"),
    )
    assert [g.check for g in builder.build_guides(a, NONE)] == ["web", "spf", "dmarc"]


def test_plantillas_y_macros_siempre_resueltas():
    for key, d in catalog.GUIDES.items():
        name, reason = key.split(":")
        for ctx in (NONE, ProviderContext(mail=GOOGLE, dns_panel=CLOUDFLARE)):
            (guide,) = one(name, "error", reason, ctx, domain="www.example.com")
            text = " ".join([guide.title, guide.why, guide.intro, guide.verify, *guide.steps, *guide.notes])
            assert "{" not in text and "@dns_" not in text and "@recheck" not in text, key
            assert guide.steps[-1].startswith("Vuelve a Nersivo")


# -------------------------------------------------- proveedor: SPF específica
def test_spf_con_google_workspace_da_guia_especifica_y_valor_verificado():
    (g,) = one("spf", "warning", "missing_spf", ProviderContext(mail=GOOGLE, dns_panel=CLOUDFLARE))
    assert g.audience == "specific"
    assert "Hemos detectado que tu correo utiliza Google Workspace" in g.intro
    (v,) = g.values
    assert (v.record_type, v.host, v.value) == ("TXT", "@", "v=spf1 include:_spf.google.com ~all")
    assert "Cloudflare" in g.steps[0] and "sección «DNS»" in g.steps[0]


def test_spf_con_microsoft_365():
    (g,) = one("spf", "warning", "missing_spf", ProviderContext(mail=MICROSOFT))
    assert g.values[0].value == "v=spf1 include:spf.protection.outlook.com ~all"
    assert "Microsoft 365" in g.intro


def test_spf_proveedor_conocido_sin_valor_verificado_no_inventa_valor():
    (g,) = one("spf", "warning", "missing_spf", ProviderContext(mail=IONOS))
    assert g.values == []
    assert any("IONOS" in n and "no tenemos su valor SPF verificado" in n for n in g.notes)


# --------------------------------------------- proveedor desconocido: genérica
def test_spf_sin_proveedor_es_generica_segura_y_no_nombra_a_nadie():
    (g,) = one("spf", "warning", "missing_spf", NONE)
    assert g.audience == "generic" and g.values == []
    assert "No hemos podido identificar automáticamente tu proveedor" in g.intro
    assert any("No hemos podido identificar tu proveedor de correo" in n for n in g.notes)
    text = " ".join([g.intro, g.why, *g.steps, *g.notes]).lower()
    for name in ("google", "microsoft", "outlook", "cloudflare", "godaddy", "ionos"):
        assert name not in text


def test_pasarela_de_seguridad_se_menciona_pero_no_se_asume_el_buzon():
    ctx = ProviderContext(mail_intermediary=ProviderMatch("mimecast", "Mimecast", "high"))
    (g,) = one("spf", "warning", "missing_spf", ctx)
    assert g.values == [] and any("Mimecast" in n and "filtro de seguridad" in n for n in g.notes)


def test_panel_dns_conocido_sin_pista_no_inventa_navegacion():
    (g,) = one("spf", "warning", "multiple_spf_records", ProviderContext(dns_panel=HETZNER))
    assert "parece ser Hetzner" in g.steps[0]
    assert "«" not in g.steps[0].split("parece ser Hetzner.")[1].split("(Las pantallas")[0]


def test_panel_dns_desconocido_usa_texto_generico():
    (g,) = one("mx", "warning", "missing_mx", NONE)
    assert "normalmente es la web de la empresa donde compraste el dominio" in g.steps[1]
    assert g.audience == "generic"


def test_guias_de_hosting_no_dependen_de_proveedores():
    ctx = ProviderContext(mail=GOOGLE, dns_panel=CLOUDFLARE)
    (g,) = one("https", "error", "certificate_expired", ctx)
    assert g.audience == "generic"
    assert "Cloudflare" not in " ".join(g.steps) and "Google" not in " ".join(g.steps)


# ----------------------------------------------------------- dmarc y datos reales
def test_dmarc_missing_valor_y_host():
    (g,) = one("dmarc", "warning", "missing_dmarc", ProviderContext(dns_panel=CLOUDFLARE))
    (v,) = g.values
    assert (v.record_type, v.host, v.value) == ("TXT", "_dmarc", "v=DMARC1; p=none;")
    assert "rua=mailto:tu-correo@example.com" in v.note
    assert any("p=none" in n for n in g.notes)


def test_dmarc_invalido_muestra_el_registro_encontrado():
    (g,) = one("dmarc", "error", "invalid_dmarc_record", record="v=DMARC2; x")
    assert g.detected == ["Registro encontrado: v=DMARC2; x"] and g.values[0].value == "v=DMARC1; p=none;"


def test_spf_multiple_muestra_los_registros_reales():
    (g,) = one("spf", "error", "multiple_spf_records", records=["v=spf1 include:a.com ~all", "v=spf1 include:b.com -all"], record_count=2)
    assert g.detected == ["Registro encontrado: v=spf1 include:a.com ~all", "Registro encontrado: v=spf1 include:b.com -all"]
    assert g.values == []  # no se inventa una fusión


def test_datos_largos_se_truncan():
    (g,) = one("dmarc", "error", "invalid_dmarc_record", record="v=" + "a" * 1000)
    assert len(g.detected[0]) <= 300 + len("Registro encontrado: ")


def test_certificado_muestra_fecha_y_dias_reales():
    (g,) = one("https", "warning", "expiring_soon", expires_at="2026-10-20T00:00:00+00:00", days_remaining=13)
    assert g.detected == ["Fecha de caducidad: 2026-10-20", "Días restantes: 13"]
    (g,) = one("https", "error", "certificate_expired", expires_at="2026-10-01T00:00:00+00:00", days_remaining=-6)
    assert "Caducó hace 6 días" in g.detected


def test_certificado_sin_datos_no_inventa():
    (g,) = one("https", "error", "certificate_expired", expires_at=None, days_remaining=None)
    assert g.detected == []


def test_mx_muestra_los_servidores_que_no_resuelven():
    recs = [{"priority": 1, "hostname": "mx.ok.com", "resolves": True}, {"priority": 2, "hostname": "mx.roto.com", "resolves": False}]
    (g,) = one("mx", "warning", "mx_resolution_issue", records=recs)
    assert g.detected == ["No responde: mx.roto.com"]


def test_dominio_de_correo_sin_www():
    (g,) = one("spf", "warning", "missing_spf", NONE, domain="www.example.com")
    assert "example.com" in g.why and "www.example.com" not in g.why


def test_needs_dns_panel():
    assert builder.needs_dns_panel(analysis(spf=check("spf", "warning", "missing_spf")))
    assert not builder.needs_dns_panel(analysis(https=check("https", "error", "certificate_expired")))
    assert not builder.needs_dns_panel(analysis())


# ------------------------------------------------------------- POST /guides
@pytest.fixture
def ns_calls(monkeypatch):
    calls = []

    def fake(domain, **_):
        calls.append(domain)
        return ["ada.ns.cloudflare.com", "bob.ns.cloudflare.com"]

    monkeypatch.setattr(guides_routes, "lookup_nameservers", fake)
    return calls


def post(a):
    return client.post("/guides", json=a.model_dump(mode="json"))


def test_endpoint_spf_google_cloudflare(ns_calls):
    a = analysis(
        "www.example.com",
        spf=check("spf", "warning", "missing_spf", records=[], found=False),
        mx=check("mx", records=[{"priority": 1, "hostname": "aspmx.l.google.com", "resolves": True}]),
    )
    r = post(a)
    assert r.status_code == 200
    body = r.json()
    assert body["domain"] == "www.example.com"
    assert body["providers"]["mail"]["id"] == "google_workspace"
    assert body["providers"]["dns_panel"]["id"] == "cloudflare"
    assert body["providers"]["mail_intermediary"] is None
    (g,) = body["guides"]
    assert g["audience"] == "specific" and g["values"][0]["value"] == "v=spf1 include:_spf.google.com ~all"
    assert ns_calls == ["www.example.com"]


def test_endpoint_sin_problemas_no_consulta_ns(ns_calls):
    r = post(analysis())
    assert r.status_code == 200 and r.json()["guides"] == [] and ns_calls == []


def test_endpoint_solo_consulta_ns_si_una_guia_lo_necesita(ns_calls):
    post(analysis(https=check("https", "error", "certificate_expired")))
    assert ns_calls == []


def test_endpoint_proveedor_desconocido_es_generico(monkeypatch):
    monkeypatch.setattr(guides_routes, "lookup_nameservers", lambda d, **_: [])
    a = analysis(
        spf=check("spf", "warning", "missing_spf", records=[]),
        mx=check("mx", records=[{"priority": 1, "hostname": "mail.raro.es", "resolves": True}]),
    )
    body = post(a).json()
    assert body["providers"] == {"mail": None, "dns_panel": None, "mail_intermediary": None}
    assert body["guides"][0]["audience"] == "generic" and body["guides"][0]["values"] == []


@pytest.mark.parametrize("bad", ["localhost", "127.0.0.1", "10.0.0.5", "169.254.169.254", "http://example.com", "example", "a b.com", ""])
def test_endpoint_rechaza_dominios_no_validos_sin_consultas(monkeypatch, bad):
    called = []
    monkeypatch.setattr(guides_routes, "lookup_nameservers", lambda d, **_: called.append(d) or [])
    r = client.post("/guides", json={**analysis().model_dump(mode="json"), "domain": bad})
    assert r.status_code in (400, 422) and called == []


@pytest.mark.parametrize("body", [{}, {"domain": "example.com"}, [], "texto"])
def test_endpoint_rechaza_cuerpos_invalidos(body):
    assert client.post("/guides", json=body).status_code == 422


def test_endpoint_rechaza_estados_fuera_del_contrato():
    data = analysis().model_dump(mode="json")
    data["checks"]["spf"]["status"] = "hackeado"
    assert client.post("/guides", json=data).status_code == 422


def _network_forbidden(*a, **k):
    raise AssertionError("No debe haber conexiones de red")


@pytest.fixture
def offline_client(monkeypatch):
    """`TestClient` con el bucle de AnyIO ya creado y TODA conexión de red prohibida.

    El orden es deliberado. Un `TestClient` usado sin `with` crea un bucle de
    AnyIO nuevo en cada petición, es decir, DESPUÉS de instalar los parches. En
    Windows ese bucle (`ProactorEventLoop`) abre un `socket.socketpair()` interno
    implementado en Python con `csock.connect(...)`, y un parche global de
    `socket.socket.connect` lo bloquearía antes de llegar al endpoint.

    Por eso: 1) `with TestClient(...)` crea el portal y el bucle (y su socketpair
    interno) con la red todavía intacta; 2) solo entonces se prohíbe la red; 3) los
    parches se retiran antes de cerrar el bucle. Desde el paso 2 no se permite
    NINGUNA conexión (ni siquiera a loopback), así que no hay lista blanca de
    destinos que pueda ocultar una conexión indebida del endpoint.
    """
    with TestClient(main.app) as c:
        assert c.portal is not None, "el bucle de AnyIO debe existir antes de prohibir la red"
        with monkeypatch.context() as mp:
            mp.setattr(httpx.HTTPTransport, "handle_request", _network_forbidden)  # transporte de red real
            mp.setattr(httpx.AsyncHTTPTransport, "handle_async_request", _network_forbidden)
            mp.setattr(socket.socket, "connect", _network_forbidden)
            yield c


def _spf_missing_analysis():
    return analysis(spf=check("spf", "warning", "missing_spf", records=[]), https=check("https", "error", "tls_error"))


def test_endpoint_no_hace_conexiones_http_ni_tcp(offline_client, ns_calls):
    a = _spf_missing_analysis()
    r = offline_client.post("/guides", json=a.model_dump(mode="json"))
    assert r.status_code == 200
    assert len(ns_calls) == 1  # la ruta que consulta DNS sí se ejecutó (sin red real: usa el mock)


@pytest.mark.parametrize(
    "intento",
    [
        pytest.param(lambda: socket.socket().connect(("203.0.113.10", 443)), id="tcp"),
        pytest.param(lambda: httpx.Client().get("http://203.0.113.10/"), id="http"),
    ],
)
def test_guardia_de_red_detecta_conexiones_desde_el_endpoint(offline_client, monkeypatch, intento):
    """Control positivo: si el endpoint intentara conectarse, el test anterior fallaría."""

    def lookup_que_se_conecta(domain, **_):
        intento()
        return []

    monkeypatch.setattr(guides_routes, "lookup_nameservers", lookup_que_se_conecta)
    a = _spf_missing_analysis()
    with pytest.raises(AssertionError, match="No debe haber conexiones de red"):
        offline_client.post("/guides", json=a.model_dump(mode="json"))


def test_endpoint_texto_del_cliente_solo_aparece_como_dato_escapado_por_el_frontend(ns_calls):
    evil = "v=spf1 <script>alert(1)</script>"
    body = post(analysis(spf=check("spf", "error", "multiple_spf_records", records=[evil]))).json()
    assert body["guides"][0]["detected"] == [f"Registro encontrado: {evil}"]  # texto plano, sin interpretar


def test_analyze_no_cambia_su_contrato(monkeypatch):
    from backend import analyzer
    from backend.models import Status
    from backend.tests.helpers import make_check

    for n in ("web", "https", "dns", "mx", "spf", "dmarc"):
        monkeypatch.setattr(analyzer, f"check_{n}", lambda d: make_check(Status.OK))
    body = client.get("/analyze/example.com").json()
    assert set(body) == {"domain", "analyzed_at", "global_status", "score", "summary", "checks"}
    assert "guides" not in body
