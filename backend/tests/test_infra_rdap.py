"""
Tests de infrastructure/rdap.py con bootstrap de IANA y servidores RDAP
mockeados. No se realiza ninguna conexión real (ver infra_fixtures).
"""

import socket

import httpx
import pytest

from backend.infrastructure import rdap
from backend.infrastructure.models import (
    RDAP_BLOCKED,
    RDAP_BOOTSTRAP_UNAVAILABLE,
    RDAP_HTTP_ERROR,
    RDAP_INVALID_RESPONSE,
    RDAP_NETWORK_ERROR,
    RDAP_NOT_FOUND,
    RDAP_OK,
    RDAP_RATE_LIMITED,
    RDAP_TIMEOUT,
    RDAP_UNSUPPORTED_TLD,
)
from backend.tests.infra_fixtures import (  # noqa: F401
    HOST_IPS,
    IANA_HOST,
    add_bootstrap,
    isolate_network,
    make_bootstrap,
    net,
    rdap_domain,
)

VERISIGN = "rdap.verisign.com"


def _lookup(net, domain, **kwargs):
    return rdap.lookup_rdap(domain, transport=net.router.transport, **kwargs)


def _serve_com(net, domain="example.com", **domain_kwargs):
    add_bootstrap(net.router)
    net.router.add(VERISIGN, f"/com/v1/domain/{domain}", json_body=rdap_domain(domain, **domain_kwargs))


# ===========================================================================
# parse_bootstrap
# ===========================================================================
def test_parse_bootstrap_valido():
    mapping = rdap.parse_bootstrap(make_bootstrap(include_es=True))
    assert mapping["com"] == ["https://rdap.verisign.com/com/v1/"]
    assert mapping["net"] == mapping["com"]
    assert mapping["es"] == ["https://rdap.nic.es.example/"]


def test_parse_bootstrap_ignora_entradas_mal_formadas_y_urls_no_https():
    payload = {
        "services": [
            "basura",
            [["a"]],
            [["b"], "no-es-lista"],
            [["http-only"], ["http://inseguro.example/"]],
            [["Mixto"], ["http://x.example/", "https://ok.example/"]],
            [[None, 5, ""], ["https://z.example/"]],
        ]
    }
    mapping = rdap.parse_bootstrap(payload)
    assert mapping == {"mixto": ["https://ok.example/"]}


@pytest.mark.parametrize("payload", [None, [], "texto", {}, {"services": "no"}, {"services": None}])
def test_parse_bootstrap_estructura_invalida(payload):
    with pytest.raises(ValueError):
        rdap.parse_bootstrap(payload)


# ===========================================================================
# parse_domain_object
# ===========================================================================
def test_parse_domain_completo():
    data, missing = rdap.parse_domain_object(rdap_domain("example.com"))
    assert data["registrar"] == "Example Registrar, Inc."
    assert data["registrar_iana_id"] == "1068"
    assert data["created"] == "2010-05-04T10:00:00Z"
    assert data["expires"] == "2027-05-04T10:00:00Z"
    assert data["updated"] == "2025-04-01T08:30:00Z"
    assert data["domain_status"] == ["client transfer prohibited"]
    assert data["nameservers"] == ["ada.ns.cloudflare.com", "bob.ns.cloudflare.com"]
    assert data["dnssec"] == {"delegation_signed": False}
    assert missing == []


def test_parse_domain_minimo_lista_todos_los_campos_como_ausentes():
    data, missing = rdap.parse_domain_object({"objectClassName": "domain", "ldhName": "x.com"})
    assert data == {}
    assert set(missing) == {
        "registrar", "registrar_iana_id", "created", "expires", "updated",
        "domain_status", "nameservers", "dnssec",
    }


def test_updated_ignora_la_fecha_de_la_base_de_datos_rdap():
    body = rdap_domain(updated=None)  # solo queda "last update of RDAP database"
    data, missing = rdap.parse_domain_object(body)
    assert "updated" not in data and "updated" in missing


def test_registrar_solo_con_iana_id():
    data, _ = rdap.parse_domain_object(rdap_domain(registrar=None, iana_id="292"))
    assert "registrar" not in data and data["registrar_iana_id"] == "292"


def test_registrar_solo_con_nombre():
    data, missing = rdap.parse_domain_object(rdap_domain(registrar="Solo Nombre", iana_id=None))
    assert data["registrar"] == "Solo Nombre"
    assert "registrar_iana_id" in missing


def test_registrar_en_entidad_anidada():
    body = {
        "objectClassName": "domain",
        "entities": [
            {"roles": ["reseller"], "entities": [
                {"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Anidado SL"]]]}
            ]}
        ],
    }
    data, _ = rdap.parse_domain_object(body)
    assert data["registrar"] == "Anidado SL"


def test_entidad_que_no_es_registrar_se_ignora():
    body = {"entities": [{"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "Particular"]]]}]}
    data, _ = rdap.parse_domain_object(body)
    assert "registrar" not in data


def test_nameservers_normalizados_y_sin_duplicados():
    body = {"nameservers": [{"ldhName": "NS1.Example.COM."}, {"ldhName": "ns1.example.com"}, {"ldhName": ""}, "x", {}]}
    data, _ = rdap.parse_domain_object(body)
    assert data["nameservers"] == ["ns1.example.com"]


def test_dnssec_zone_signed_y_delegation_signed():
    data, _ = rdap.parse_domain_object({"secureDNS": {"delegationSigned": True, "zoneSigned": True}})
    assert data["dnssec"] == {"delegation_signed": True, "zone_signed": True}


def test_dnssec_ausente_o_invalido():
    assert "dnssec" not in rdap.parse_domain_object({})[0]
    assert "dnssec" not in rdap.parse_domain_object({"secureDNS": {"delegationSigned": "si"}})[0]
    assert "dnssec" not in rdap.parse_domain_object({"secureDNS": "x"})[0]


def test_tipos_inesperados_no_rompen_el_parser():
    body = {"status": "no-es-lista", "events": "x", "entities": 5, "nameservers": {"a": 1}, "secureDNS": []}
    data, missing = rdap.parse_domain_object(body)
    assert data == {} and len(missing) == 8


def test_estados_vacios_se_descartan():
    data, _ = rdap.parse_domain_object({"status": ["", "  ", "active", 5]})
    assert data["domain_status"] == ["active"]


# ===========================================================================
# lookup_rdap: TLD con RDAP
# ===========================================================================
def test_com_completo_y_peticion_correcta(net):
    _serve_com(net)
    result = _lookup(net, "example.com")
    assert result.status == RDAP_OK and result.reason is None
    assert result.server == VERISIGN
    assert result.coverage == "standard" and result.conclusive is True
    assert result.data["registrar"] == "Example Registrar, Inc."
    assert result.missing_fields == []
    # La segunda petición es la consulta de dominio, con IP fijada y Host/UA/Accept.
    iana_req, query_req = net.router.requests
    assert iana_req.headers["host"] == IANA_HOST
    assert query_req.url.host == HOST_IPS[VERISIGN]
    assert query_req.url.path == "/com/v1/domain/example.com"
    assert query_req.headers["user-agent"].startswith("Nersivo/")
    assert "rdap+json" in query_req.headers["accept"]
    assert not net.router.unrouted


def test_net(net):
    add_bootstrap(net.router)
    net.router.add(VERISIGN, "/com/v1/domain/ejemplo.net", json_body=rdap_domain("ejemplo.net"))
    # .net comparte servidor con .com en el bootstrap de prueba (igual que Verisign)
    result = _lookup(net, "ejemplo.net")
    assert result.status == RDAP_OK and result.data["nameservers"]


@pytest.mark.parametrize(
    "domain,host,path",
    [
        ("asociacion.org", "rdap.publicinterestregistry.org", "/rdap/domain/asociacion.org"),
        ("empresa.eu", "rdap.eu", "/domain/empresa.eu"),
    ],
)
def test_org_y_eu_usan_su_servidor_del_bootstrap(net, domain, host, path):
    add_bootstrap(net.router)
    net.router.add(host, path, json_body=rdap_domain(domain, delegation_signed=True))
    result = _lookup(net, domain)
    assert result.status == RDAP_OK
    assert result.server == host
    assert result.data["dnssec"] == {"delegation_signed": True}


def test_datos_parciales_se_reportan_sin_inventar_campos(net):
    add_bootstrap(net.router)
    net.router.add(
        VERISIGN, "/com/v1/domain/parcial.com",
        json_body={"objectClassName": "domain", "ldhName": "PARCIAL.COM", "status": ["active"]},
    )
    result = _lookup(net, "parcial.com")
    assert result.status == RDAP_OK
    assert result.data == {"domain_status": ["active"]}
    assert "registrar" in result.missing_fields and "expires" in result.missing_fields


def test_respuesta_sin_objectclassname_se_acepta_en_gtld(net):
    add_bootstrap(net.router)
    net.router.add(VERISIGN, "/com/v1/domain/x.com", json_body={"ldhName": "x.com", "status": ["ok"]})
    assert _lookup(net, "x.com").status == RDAP_OK


def test_dominio_inexistente_404_es_concluyente_en_gtld(net):
    add_bootstrap(net.router)
    net.router.add(VERISIGN, "/com/v1/domain/noexiste.com", status=404, json_body={"errorCode": 404})
    result = _lookup(net, "noexiste.com")
    assert result.status == RDAP_NOT_FOUND and result.reason == "domain_not_found"
    assert result.conclusive is True and result.data == {}


# ===========================================================================
# lookup_rdap: TLD desconocido / sin RDAP
# ===========================================================================
def test_tld_sin_rdap_no_consulta_nada_mas(net):
    add_bootstrap(net.router)
    result = _lookup(net, "ejemplo.xyz")
    assert result.status == RDAP_UNSUPPORTED_TLD
    assert result.reason == "tld_not_in_iana_bootstrap"
    assert result.conclusive is False and result.server is None
    assert net.router.hosts_requested() == [IANA_HOST]
    assert any("WHOIS" in n for n in result.notes)


# ===========================================================================
# .es: tratamiento conservador y separado
# ===========================================================================
def test_es_sin_rdap_en_bootstrap_es_unsupported_y_no_se_inventa_servidor(net):
    add_bootstrap(net.router, make_bootstrap(include_es=False))
    result = _lookup(net, "empresa.es")
    assert result.status == RDAP_UNSUPPORTED_TLD
    assert result.coverage == "limited"
    assert result.server is None and result.data == {}
    assert net.router.hosts_requested() == [IANA_HOST]
    assert any("conservadora" in n for n in result.notes)


def test_es_con_rdap_en_bootstrap_marca_cobertura_limitada(net):
    add_bootstrap(net.router, make_bootstrap(include_es=True))
    net.router.add(
        "rdap.nic.es.example", "/domain/empresa.es",
        json_body={"objectClassName": "domain", "ldhName": "empresa.es", "status": ["active"],
                   "events": [{"eventAction": "registration", "eventDate": "2015-01-01T00:00:00Z"}]},
    )
    result = _lookup(net, "empresa.es")
    assert result.status == RDAP_OK and result.coverage == "limited"
    assert result.data["created"] == "2015-01-01T00:00:00Z"
    # No se asume que existan los campos de un gTLD:
    assert "registrar" not in result.data and "registrar" in result.missing_fields
    assert any("conservadora" in n for n in result.notes)


def test_es_404_no_es_concluyente(net):
    add_bootstrap(net.router, make_bootstrap(include_es=True))
    net.router.add("rdap.nic.es.example", "/domain/empresa.es", status=404)
    result = _lookup(net, "empresa.es")
    assert result.status == RDAP_NOT_FOUND and result.conclusive is False
    assert any("no es concluyente" in n for n in result.notes)


def test_es_composite_com_es_tambien_es_conservador(net):
    add_bootstrap(net.router, make_bootstrap(include_es=True))
    net.router.add("rdap.nic.es.example", "/domain/empresa.com.es",
                   json_body={"objectClassName": "domain", "ldhName": "empresa.com.es"})
    result = _lookup(net, "empresa.com.es")
    assert result.coverage == "limited" and result.status == RDAP_OK


def test_es_respuesta_que_no_parece_un_dominio_es_invalida(net):
    add_bootstrap(net.router, make_bootstrap(include_es=True))
    net.router.add("rdap.nic.es.example", "/domain/empresa.es", json_body={"algo": "raro"})
    result = _lookup(net, "empresa.es")
    assert result.status == RDAP_INVALID_RESPONSE and result.reason == "not_a_domain_object"


def test_es_nunca_cae_en_un_servidor_distinto_del_bootstrap(net):
    add_bootstrap(net.router, make_bootstrap(include_es=False))
    _lookup(net, "empresa.es")
    assert set(net.router.hosts_requested()) == {IANA_HOST}


# ===========================================================================
# Errores de red y respuestas anómalas
# ===========================================================================
def test_rdap_timeout(net):
    add_bootstrap(net.router)
    net.router.add(VERISIGN, "/com/v1/domain/lento.com", raises=httpx.ReadTimeout("t"))
    result = _lookup(net, "lento.com")
    assert result.status == RDAP_TIMEOUT and result.reason == "timeout" and result.conclusive is False


def test_rdap_connect_timeout(net):
    add_bootstrap(net.router)
    net.router.add(VERISIGN, "/com/v1/domain/lento.com", raises=httpx.ConnectTimeout("t"))
    assert _lookup(net, "lento.com").status == RDAP_TIMEOUT


def test_rdap_error_de_conexion(net):
    add_bootstrap(net.router)
    net.router.add(VERISIGN, "/com/v1/domain/caido.com", raises=httpx.ConnectError("boom"))
    result = _lookup(net, "caido.com")
    assert result.status == RDAP_NETWORK_ERROR and result.reason == "connection_error"


def test_rdap_servidor_no_resuelve(net):
    add_bootstrap(net.router, make_bootstrap(extra=[[["zzz"], ["https://no-resuelve.example/"]]]))
    result = _lookup(net, "algo.zzz")
    assert result.status == RDAP_NETWORK_ERROR and result.reason == "dns_error"


def test_rdap_excepcion_inesperada_no_se_propaga(net):
    add_bootstrap(net.router)
    net.router.add(VERISIGN, "/com/v1/domain/raro.com", raises=RuntimeError("inesperado"))
    result = _lookup(net, "raro.com")
    assert result.status == RDAP_NETWORK_ERROR and result.reason == "unexpected_error"


def test_rdap_429(net):
    add_bootstrap(net.router)
    net.router.add(VERISIGN, "/com/v1/domain/x.com", status=429)
    result = _lookup(net, "x.com")
    assert result.status == RDAP_RATE_LIMITED and result.conclusive is False


@pytest.mark.parametrize("code", [400, 403, 500, 502, 503])
def test_rdap_otros_codigos_http(net, code):
    add_bootstrap(net.router)
    net.router.add(VERISIGN, "/com/v1/domain/x.com", status=code)
    result = _lookup(net, "x.com")
    assert result.status == RDAP_HTTP_ERROR and result.reason == f"http_{code}"


def test_rdap_json_invalido(net):
    add_bootstrap(net.router)
    net.router.add(VERISIGN, "/com/v1/domain/x.com", content=b"<html>no json</html>")
    result = _lookup(net, "x.com")
    assert result.status == RDAP_INVALID_RESPONSE and result.reason == "invalid_json"


@pytest.mark.parametrize("body", [[1, 2], "texto", 5])
def test_rdap_json_que_no_es_objeto(net, body):
    add_bootstrap(net.router)
    net.router.add(VERISIGN, "/com/v1/domain/x.com", json_body=body)
    result = _lookup(net, "x.com")
    assert result.status == RDAP_INVALID_RESPONSE and result.reason == "not_a_json_object"


def test_rdap_objeto_de_otra_clase(net):
    add_bootstrap(net.router)
    net.router.add(VERISIGN, "/com/v1/domain/x.com", json_body={"objectClassName": "nameserver"})
    result = _lookup(net, "x.com")
    assert result.status == RDAP_INVALID_RESPONSE and result.reason == "unexpected_object_class"


def test_rdap_respuesta_demasiado_grande(net):
    add_bootstrap(net.router)
    net.router.add(VERISIGN, "/com/v1/domain/x.com", content=b" " * (2 * 1024 * 1024 + 1))
    result = _lookup(net, "x.com")
    assert result.status == RDAP_INVALID_RESPONSE and result.reason == "response_too_large"


def test_rdap_json_vacio_con_200_es_invalido(net):
    add_bootstrap(net.router)
    net.router.add(VERISIGN, "/com/v1/domain/x.com", content=b"")
    assert _lookup(net, "x.com").status == RDAP_INVALID_RESPONSE


# ===========================================================================
# Bootstrap: fallos y caché
# ===========================================================================
@pytest.mark.parametrize(
    "kwargs,reason",
    [
        ({"status": 503}, "bootstrap_http_503"),
        ({"raises": httpx.ReadTimeout("t")}, "timeout"),
        ({"raises": httpx.ConnectError("x")}, "network_error"),
        ({"content": b"no es json"}, "invalid_json"),
    ],
)
def test_bootstrap_no_disponible(net, kwargs, reason):
    net.router.add(IANA_HOST, "/rdap/dns.json", **kwargs)
    result = _lookup(net, "example.com")
    assert result.status == RDAP_BOOTSTRAP_UNAVAILABLE and result.reason == reason
    assert result.conclusive is False


def test_bootstrap_con_estructura_invalida(net):
    net.router.add(IANA_HOST, "/rdap/dns.json", json_body={"services": "mal"})
    result = _lookup(net, "example.com")
    assert result.status == RDAP_BOOTSTRAP_UNAVAILABLE and result.reason == "invalid_bootstrap"


def test_bootstrap_se_cachea_entre_consultas(net):
    add_bootstrap(net.router)
    net.router.add(VERISIGN, "/com/v1/domain/a.com", json_body=rdap_domain("a.com"))
    net.router.add(VERISIGN, "/com/v1/domain/b.com", json_body=rdap_domain("b.com"))
    _lookup(net, "a.com")
    _lookup(net, "b.com")
    assert net.router.hosts_requested().count(IANA_HOST) == 1


def test_fallo_del_bootstrap_se_cachea_brevemente(net):
    net.router.add(IANA_HOST, "/rdap/dns.json", status=503)
    _lookup(net, "a.com")
    before = len(net.router.requests)
    result = _lookup(net, "b.com")
    assert len(net.router.requests) == before  # no reintenta inmediatamente
    assert result.status == RDAP_BOOTSTRAP_UNAVAILABLE and result.reason == "bootstrap_recently_failed"


def test_cache_del_bootstrap_expira(net, monkeypatch):
    add_bootstrap(net.router)
    net.router.add(VERISIGN, "/com/v1/domain/a.com", json_body=rdap_domain("a.com"))
    clock = [1000.0]
    monkeypatch.setattr(rdap.time, "monotonic", lambda: clock[0])
    _lookup(net, "a.com")
    clock[0] += rdap._BOOTSTRAP_TTL_SECONDS + 1
    _lookup(net, "a.com")
    assert net.router.hosts_requested().count(IANA_HOST) == 2


# ===========================================================================
# Plazo global
# ===========================================================================
def test_plazo_agotado_antes_de_empezar(net):
    add_bootstrap(net.router)
    result = _lookup(net, "example.com", deadline_seconds=0)
    assert result.status == RDAP_BOOTSTRAP_UNAVAILABLE and result.reason == "deadline_exceeded"
    assert net.router.requests == []


def test_plazo_agotado_entre_bootstrap_y_consulta(net, monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(rdap.time, "monotonic", lambda: clock[0])

    def slow_bootstrap(request):
        clock[0] += 100.0  # el bootstrap "tarda" más que el plazo
        return httpx.Response(200, json=make_bootstrap())

    net.router.add(IANA_HOST, "/rdap/dns.json", handler=slow_bootstrap)
    net.router.add(VERISIGN, "/com/v1/domain/example.com", json_body=rdap_domain())
    result = _lookup(net, "example.com", deadline_seconds=10)
    assert result.status == RDAP_TIMEOUT and result.reason == "deadline_exceeded"
    assert VERISIGN not in net.router.hosts_requested()


# ===========================================================================
# Seguridad (SSRF)
# ===========================================================================
@pytest.mark.parametrize(
    "ip,code",
    [
        ("127.0.0.1", "blocked_private_ip"),
        ("10.0.0.5", "blocked_private_ip"),
        ("169.254.169.254", "blocked_private_ip"),
        ("192.168.1.10", "blocked_private_ip"),
        ("::1", "blocked_private_ip"),
        ("100.64.0.1", "blocked_non_public_ip"),
        ("0.0.0.0", "blocked_non_public_ip"),
    ],
)
def test_servidor_rdap_que_resuelve_a_ip_no_publica_se_bloquea(net, ip, code):
    add_bootstrap(net.router, make_bootstrap(extra=[[["evil"], ["https://rdap.interno.example/"]]]))
    net.resolve("rdap.interno.example", ip)
    result = _lookup(net, "algo.evil")
    assert result.status == RDAP_BLOCKED and result.reason == code
    assert "rdap.interno.example" not in net.router.hosts_requested()


def test_servidor_rdap_con_ips_mezcladas_publica_y_privada_se_bloquea(net):
    add_bootstrap(net.router, make_bootstrap(extra=[[["evil"], ["https://rdap.mixto.example/"]]]))
    net.resolve("rdap.mixto.example", ["93.184.216.34", "10.0.0.5"])
    result = _lookup(net, "algo.evil")
    assert result.status == RDAP_BLOCKED
    assert "rdap.mixto.example" not in net.router.hosts_requested()


def test_bootstrap_que_resuelve_a_ip_privada_se_bloquea(net, monkeypatch):
    net.hosts[IANA_HOST] = "127.0.0.1"
    result = _lookup(net, "example.com")
    assert result.status == RDAP_BOOTSTRAP_UNAVAILABLE and result.reason == "blocked_private_ip"
    assert net.router.requests == []


def test_bootstrap_con_url_http_se_descarta(net):
    add_bootstrap(net.router, make_bootstrap(extra=[[["inseg"], ["http://rdap.inseguro.example/"]]]))
    result = _lookup(net, "algo.inseg")
    assert result.status == RDAP_UNSUPPORTED_TLD  # nunca se consulta por HTTP plano
    assert net.router.hosts_requested() == [IANA_HOST]


def test_bootstrap_con_puerto_no_permitido_se_bloquea(net):
    add_bootstrap(net.router, make_bootstrap(extra=[[["raro"], ["https://rdap.otro-registro.example:8443/"]]]))
    result = _lookup(net, "algo.raro")
    assert result.status == RDAP_BLOCKED
    assert "rdap.otro-registro.example" not in net.router.hosts_requested()


def test_bootstrap_con_credenciales_en_la_url_se_bloquea(net):
    add_bootstrap(net.router, make_bootstrap(extra=[[["cred"], ["https://user:pw@rdap.otro-registro.example/"]]]))
    result = _lookup(net, "algo.cred")
    assert result.status == RDAP_BLOCKED
    assert net.router.hosts_requested() == [IANA_HOST]


def _redirect_to(location):
    return lambda request: httpx.Response(302, headers={"location": location})


def test_redirect_a_host_privado_se_bloquea_y_no_se_conecta(net):
    add_bootstrap(net.router)
    net.resolve("interno.example", "10.0.0.5")
    net.router.add(VERISIGN, "/com/v1/domain/x.com", handler=_redirect_to("https://interno.example/secreto"))
    result = _lookup(net, "x.com")
    assert result.status == RDAP_BLOCKED and result.reason == "blocked_redirect"
    assert "interno.example" not in net.router.hosts_requested()


@pytest.mark.parametrize(
    "location",
    [
        "https://127.0.0.1/",
        "https://169.254.169.254/latest/meta-data/",
        "https://[::1]/",
        "https://2130706433/",  # 127.0.0.1 en decimal
    ],
)
def test_redirect_a_ip_literal_no_publica_se_bloquea(net, location):
    add_bootstrap(net.router)
    net.router.add(VERISIGN, "/com/v1/domain/x.com", handler=_redirect_to(location))
    result = _lookup(net, "x.com")
    assert result.status == RDAP_BLOCKED and result.reason == "blocked_redirect"
    assert net.router.violations == []


@pytest.mark.parametrize(
    "location",
    [
        "http://rdap.otro-registro.example/domain/x.com",  # degradación a HTTP
        "https://rdap.otro-registro.example:8443/domain/x.com",  # puerto no permitido
        "https://u:p@rdap.otro-registro.example/domain/x.com",  # credenciales
        "ftp://rdap.otro-registro.example/x",
        "file:///etc/passwd",
        "gopher://rdap.otro-registro.example/",
    ],
)
def test_redirect_con_esquema_puerto_o_credenciales_no_permitidos(net, location):
    add_bootstrap(net.router)
    net.router.add(VERISIGN, "/com/v1/domain/x.com", handler=_redirect_to(location))
    result = _lookup(net, "x.com")
    assert result.status == RDAP_BLOCKED and result.reason == "blocked_redirect"
    assert "rdap.otro-registro.example" not in net.router.hosts_requested()


def test_redirect_a_otro_host_publico_se_sigue_y_se_revalida(net):
    add_bootstrap(net.router)
    net.router.add(
        VERISIGN, "/com/v1/domain/x.com",
        handler=_redirect_to("https://rdap.otro-registro.example/domain/x.com"),
    )
    net.router.add("rdap.otro-registro.example", "/domain/x.com", json_body=rdap_domain("x.com"))
    result = _lookup(net, "x.com")
    assert result.status == RDAP_OK and result.data["registrar"]
    assert net.router.hosts_requested()[-1] == "rdap.otro-registro.example"


def test_redirect_relativo_se_resuelve_contra_la_url_actual(net):
    add_bootstrap(net.router)
    net.router.add(VERISIGN, "/com/v1/domain/x.com", handler=_redirect_to("/com/v1/domain/otro.com"))
    net.router.add(VERISIGN, "/com/v1/domain/otro.com", json_body=rdap_domain("otro.com"))
    assert _lookup(net, "x.com").status == RDAP_OK


def test_demasiados_redirects(net):
    add_bootstrap(net.router)
    net.router.add(VERISIGN, "/com/v1/domain/x.com", handler=_redirect_to("/com/v1/domain/x.com"))
    result = _lookup(net, "x.com")
    assert result.status == RDAP_NETWORK_ERROR and result.reason == "too_many_redirects"
    # 1 (bootstrap) + 1 inicial + 3 redirects permitidos; el cuarto corta.
    assert len(net.router.requests) == 1 + 4


def test_redirect_sin_location_no_se_sigue(net):
    add_bootstrap(net.router)
    net.router.add(VERISIGN, "/com/v1/domain/x.com", status=302)
    assert _lookup(net, "x.com").status == RDAP_HTTP_ERROR


def test_los_enlaces_del_json_rdap_nunca_se_siguen(net):
    add_bootstrap(net.router)
    body = rdap_domain("x.com")
    body["links"] = [{"rel": "related", "href": "https://interno.example/admin"}]
    body["entities"][0]["links"] = [{"href": "http://169.254.169.254/"}]
    net.router.add(VERISIGN, "/com/v1/domain/x.com", json_body=body)
    result = _lookup(net, "x.com")
    assert result.status == RDAP_OK
    assert set(net.router.hosts_requested()) == {IANA_HOST, VERISIGN}


def test_el_dominio_del_usuario_no_decide_el_servidor_de_destino(net):
    """Aunque el 'dominio' contenga trucos, el host de destino sale del bootstrap."""
    add_bootstrap(net.router)
    net.router.add(VERISIGN, "/com/v1/domain/evil.com", json_body=rdap_domain("evil.com"))
    _lookup(net, "evil.com")
    assert set(net.router.hosts_requested()) <= {IANA_HOST, VERISIGN}


def test_no_hay_conexion_tcp_real(net):
    with pytest.raises(AssertionError):
        socket.socket().connect(("93.184.216.34", 443))
