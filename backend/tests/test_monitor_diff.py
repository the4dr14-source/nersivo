"""Tests de huella estable y comparación (`monitoring/fingerprint.py`, `diff.py`)."""

import pytest

from backend.monitoring.diff import (
    KIND_CERT_RENEWED, KIND_CONFIG_CHANGE, KIND_NEW_PROBLEM, KIND_RESOLVED,
    KIND_SCORE_CHANGE, KIND_STATUS_CHANGE, SCORE_THRESHOLD, diff_fingerprints,
)
from backend.monitoring.fingerprint import make_fingerprint, merge_baseline
from backend.tests.monitor_helpers import analysis, check


def fp(**kwargs):
    return make_fingerprint(analysis(**kwargs))


def changes(old, new):
    return diff_fingerprints(merge_baseline(None, old), new)


def kinds(old, new):
    return [c.kind for c in changes(old, new)]


# ============================================================ huella estable
def test_huella_ignora_campos_dinamicos():
    a = analysis(analyzed_at="2026-10-07T10:00:00Z")
    b = analysis(
        analyzed_at="2026-10-08T23:59:59Z",
        web=check("web", response_time_ms=9999, status_code=204),
        https=check("https", days_remaining=99),
        dns=check("dns", a_records=["1.2.3.4", "5.6.7.8"], aaaa_records=["2001:db8::1"]),
    )
    assert make_fingerprint(a) == make_fingerprint(b)


def test_huella_normaliza_espacios_mayusculas_y_orden():
    a = analysis(spf=check("spf", records=["v=spf1  include:B.com   ~all", "v=spf1 include:a.com ~all"]))
    b = analysis(spf=check("spf", records=["V=SPF1 include:a.com ~all", " v=spf1 include:b.com ~all "]))
    assert make_fingerprint(a)["checks"]["spf"]["facts"] == make_fingerprint(b)["checks"]["spf"]["facts"]


def test_huella_mx_conjunto_ordenado_sin_punto_final():
    a = analysis(mx=check("mx", records=[{"hostname": "B.mx.com.", "priority": 2}, {"hostname": "a.mx.com", "priority": 1}]))
    assert make_fingerprint(a)["checks"]["mx"]["facts"] == {"hosts": ["a.mx.com", "b.mx.com"]}


def test_huella_conserva_unknown_y_score_null():
    a = analysis(score=None, global_status="unknown", dmarc=check("dmarc", "unknown", "timeout"))
    f = make_fingerprint(a)
    assert f["score"] is None and f["checks"]["dmarc"]["status"] == "unknown"
    assert f["global_status"] == "unknown"


def test_huella_solo_fecha_del_certificado():
    f = make_fingerprint(analysis(https=check("https", expires_at="2027-03-04T12:34:56+00:00")))
    assert f["checks"]["https"]["facts"] == {"expires_on": "2027-03-04"}


def test_huella_es_json_serializable():
    import json
    json.dumps(make_fingerprint(analysis()))


# ================================================================ comparación
def test_primer_analisis_no_genera_cambios():
    assert diff_fingerprints(None, fp()) == []
    assert diff_fingerprints({}, fp()) == []


def test_sin_cambios_no_hay_eventos():
    assert changes(fp(), fp()) == []


def test_cambios_irrelevantes_no_generan_eventos():
    old = fp()
    new = fp(
        analyzed_at="2026-10-09T00:00:00Z",
        web=check("web", response_time_ms=777),
        https=check("https", days_remaining=40),
        dns=check("dns", a_records=["8.8.8.8"]),
    )
    assert changes(old, new) == []


def test_ok_a_warning_es_problema_nuevo_con_severidad_warning():
    (c,) = changes(fp(), fp(spf=check("spf", "warning", "missing_spf", records=[])))
    assert (c.kind, c.severity, c.check) == (KIND_NEW_PROBLEM, "warning", "spf")
    assert "Tu dominio no tiene SPF" in c.summary and (c.before, c.after) == ("ok", "warning")


def test_ok_a_error_es_critico():
    (c,) = changes(fp(), fp(https=check("https", "error", "certificate_expired")))
    assert (c.kind, c.severity) == (KIND_NEW_PROBLEM, "critical")


def test_problema_resuelto():
    old = fp(dmarc=check("dmarc", "warning", "missing_dmarc", record=None))
    (c,) = changes(old, fp())
    assert (c.kind, c.severity, c.check) == (KIND_RESOLVED, "info", "dmarc")


def test_warning_a_error_y_viceversa_es_cambio_de_estado():
    w = fp(spf=check("spf", "warning", "missing_spf", records=[]))
    e = fp(spf=check("spf", "error", "multiple_spf_records"))
    (up,) = changes(w, e)
    (down,) = changes(e, w)
    assert (up.kind, up.severity) == (KIND_STATUS_CHANGE, "critical")
    assert (down.kind, down.severity) == (KIND_STATUS_CHANGE, "warning")


def test_mismo_estado_pero_otro_problema_es_cambio_de_estado():
    a = fp(https=check("https", "error", "certificate_expired"))
    b = fp(https=check("https", "error", "hostname_mismatch"))
    (c,) = changes(a, b)
    assert c.kind == KIND_STATUS_CHANGE and (c.before, c.after) == ("certificate_expired", "hostname_mismatch")


def test_varios_cambios_a_la_vez_en_orden_de_checks():
    old = fp()
    new = fp(web=check("web", "warning", "no_https_redirect"), dmarc=check("dmarc", "warning", "missing_dmarc", record=None))
    assert [(c.check, c.kind) for c in changes(old, new)] == [("web", KIND_NEW_PROBLEM), ("dmarc", KIND_NEW_PROBLEM)]


# -------------------------------------------------------------------- UNKNOWN
def test_ok_a_unknown_no_genera_cambio_ni_problema():
    assert changes(fp(), fp(spf=check("spf", "unknown", "timeout"))) == []


def test_unknown_a_ok_no_es_una_mejora():
    old = fp(spf=check("spf", "unknown", "timeout"))
    assert changes(old, fp()) == []


def test_unknown_no_es_resuelto_ni_nuevo_aunque_el_otro_sea_problema():
    bad = fp(spf=check("spf", "warning", "missing_spf", records=[]))
    unk = fp(spf=check("spf", "unknown", "timeout"))
    assert changes(bad, unk) == [] and changes(unk, bad) == []


def test_problema_tras_un_unknown_no_se_pierde_gracias_a_la_base_fusionada():
    ok = fp()
    unk = fp(spf=check("spf", "unknown", "timeout"))
    bad = fp(spf=check("spf", "warning", "missing_spf", records=[]))
    baseline = merge_baseline(None, ok)
    assert diff_fingerprints(baseline, unk) == []
    baseline = merge_baseline(baseline, unk)  # conserva el último valor conocido (ok)
    assert baseline["checks"]["spf"]["status"] == "ok"
    (c,) = diff_fingerprints(baseline, bad)
    assert c.kind == KIND_NEW_PROBLEM


def test_ok_unknown_ok_no_genera_nada():
    ok, unk = fp(), fp(spf=check("spf", "unknown", "timeout"))
    baseline = merge_baseline(merge_baseline(None, ok), unk)
    assert diff_fingerprints(baseline, ok) == []


def test_baseline_nunca_conocido_se_actualiza_en_cuanto_hay_dato():
    unk = fp(spf=check("spf", "unknown", "timeout"))
    baseline = merge_baseline(None, unk)
    assert baseline["checks"]["spf"]["status"] == "unknown"
    assert merge_baseline(baseline, fp())["checks"]["spf"]["status"] == "ok"


# ----------------------------------------------------------------------- config
def test_cambio_de_servidores_mx_es_config_change():
    new = fp(mx=check("mx", records=[{"priority": 1, "hostname": "mx.protection.outlook.com", "resolves": True}]))
    (c,) = changes(fp(), new)
    assert (c.kind, c.severity, c.check) == (KIND_CONFIG_CHANGE, "warning", "mx")
    assert c.before == {"hosts": ["aspmx.l.google.com"]} and c.after == {"hosts": ["mx.protection.outlook.com"]}


def test_cambio_de_spf_con_mismo_estado_es_config_change():
    (c,) = changes(fp(), fp(spf=check("spf", records=["v=spf1 include:otro.com ~all"])))
    assert (c.kind, c.check) == (KIND_CONFIG_CHANGE, "spf")


def test_cambio_de_politica_dmarc():
    (c,) = changes(fp(), fp(dmarc=check("dmarc", record="v=DMARC1; p=reject;", policy="reject")))
    assert (c.kind, c.check) == (KIND_CONFIG_CHANGE, "dmarc")


def test_ip_no_genera_cambio_pero_dns_que_deja_de_resolver_si():
    assert changes(fp(), fp(dns=check("dns", a_records=["9.9.9.9"]))) == []
    (c,) = changes(fp(), fp(dns=check("dns", "error", "dns_resolution_error", resolves=False)))
    assert (c.kind, c.check) == (KIND_NEW_PROBLEM, "dns")


def test_no_se_duplica_config_change_si_el_check_ya_cambio_de_estado():
    new = fp(spf=check("spf", "warning", "missing_spf", records=[], found=False))
    assert [c.kind for c in changes(fp(), new)] == [KIND_NEW_PROBLEM]


def test_certificado_renovado():
    (c,) = changes(fp(), fp(https=check("https", expires_at="2027-04-15T00:00:00+00:00")))
    assert (c.kind, c.severity) == (KIND_CERT_RENEWED, "info") and "2027-04-15" in c.summary


def test_certificado_con_caducidad_anterior_es_config_change():
    (c,) = changes(fp(), fp(https=check("https", expires_at="2026-12-01T00:00:00+00:00")))
    assert c.kind == KIND_CONFIG_CHANGE


def test_cambio_de_redireccion_https_sin_cambio_de_estado():
    new = fp(web=check("web", redirected_to_https=False))
    (c,) = changes(fp(), new)
    assert (c.kind, c.check) == (KIND_CONFIG_CHANGE, "web")


# ------------------------------------------------------------------------ score
@pytest.mark.parametrize("old,new,expected", [
    (90, 80, True), (80, 90, True), (90, 81, False), (81, 90, False), (100, 100, False), (95, 40, True),
])
def test_umbral_de_score(old, new, expected):
    result = changes(fp(score=old), fp(score=new))
    assert (len(result) == 1 and result[0].kind == KIND_SCORE_CHANGE) == expected
    assert SCORE_THRESHOLD == 10


def test_score_baja_es_warning_y_sube_es_info():
    (down,) = changes(fp(score=90), fp(score=70))
    (up,) = changes(fp(score=70), fp(score=90))
    assert (down.severity, up.severity) == ("warning", "info")
    assert down.summary == "La puntuación ha bajado de 90 a 70." and (down.before, down.after) == (90, 70)


def test_score_null_nunca_genera_evento():
    assert changes(fp(score=None), fp(score=90)) == []
    assert changes(fp(score=90), fp(score=None)) == []
    assert changes(fp(score=None), fp(score=None)) == []


def test_change_to_dict():
    (c,) = changes(fp(), fp(spf=check("spf", "warning", "missing_spf", records=[])))
    assert set(c.to_dict()) == {"kind", "severity", "check", "summary", "before", "after"}
