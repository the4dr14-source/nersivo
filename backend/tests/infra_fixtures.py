"""
Utilidades y fixtures compartidas por los tests del módulo de infraestructura.

Garantías (todos los tests que importen `isolate_network` las heredan):
- Ninguna conexión TCP real (`socket.socket.connect` falla el test).
- Ninguna resolución DNS real: `getaddrinfo` solo conoce los hosts que el test
  declare y `dns.resolver.Resolver.resolve` registra cualquier consulta no
  mockeada y hace fallar el test al terminar.
- El transporte HTTP falso falla el test si se intenta conectar a una IP no
  pública (mismo criterio que `test_ssrf.py`).
- La caché del bootstrap de IANA se vacía antes y después de cada test.
"""

import json
import socket
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

import dns.name
import dns.resolver
import httpx
import pytest

from backend import net_safety
from backend.infrastructure import rdap
from backend.tests.helpers import FakeTxt, fake_getaddrinfo

PUBLIC_IP = "93.184.216.34"
IANA_HOST = "data.iana.org"

# IPs PÚBLICAS reales (no de documentación) para los hosts RDAP de prueba.
HOST_IPS = {
    IANA_HOST: "192.0.32.8",
    "rdap.verisign.com": "199.7.59.74",
    "rdap.publicinterestregistry.org": "199.19.56.1",
    "rdap.eu": "185.36.4.10",
    "rdap.nic.es.example": "145.1.1.1",
    "rdap.otro-registro.example": "8.8.4.4",
}


# --- rdata falsos ------------------------------------------------------------
class FakeNs:
    def __init__(self, target: str):
        self.target = dns.name.from_text(target)


class FakeCname:
    def __init__(self, target: str):
        self.target = dns.name.from_text(target)


class FakeDs:
    """Registro DS/DNSKEY: solo importa que exista."""

    def __str__(self) -> str:
        return "12345 13 2 ABCDEF"


def cymru(asn: int, prefix: str = "104.16.0.0/13") -> List[FakeTxt]:
    """Respuesta TXT de Team Cymru para un ASN."""
    return [FakeTxt(f"{asn} | {prefix} | US | arin | 2014-03-28")]


# --- DNS mockeado con registro de consultas ---------------------------------
@dataclass
class DnsRecorder:
    calls: List[Tuple[str, str]] = field(default_factory=list)
    lifetimes: List[Optional[float]] = field(default_factory=list)
    unexpected: List[Tuple[str, str]] = field(default_factory=list)

    def queried(self, rtype: str) -> List[str]:
        return [name for name, t in self.calls if t == rtype]


def install_dns_recording(
    monkeypatch, table: Dict[Tuple[str, str], Any], recorder: DnsRecorder
) -> DnsRecorder:
    """
    Mockea `Resolver.resolve` como `helpers.install_dns`, pero registrando las
    consultas. Una consulta ausente de la tabla se anota en `unexpected` y
    devuelve NXDOMAIN (los tests que necesiten NoAnswer deben declararlo).
    """

    def _resolve(self, qname, rdtype="A", *args, **kwargs):
        key = (str(qname).rstrip("."), rdtype)
        recorder.calls.append(key)
        # `dns.resolver.resolve` pasa `lifetime` por posición (7º argumento tras qname/rdtype).
        recorder.lifetimes.append(kwargs.get("lifetime", args[5] if len(args) > 5 else None))
        if key not in table:
            recorder.unexpected.append(key)
            raise dns.resolver.NXDOMAIN()
        value = table[key]
        if isinstance(value, Exception) or (isinstance(value, type) and issubclass(value, Exception)):
            raise value
        return value

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", _resolve)
    return recorder


# --- RDAP / HTTP mockeado ----------------------------------------------------
class RdapRouter:
    """
    Servidor HTTP falso (httpx.MockTransport) enrutado por (host, path).

    Las peticiones llegan con la URL fijada a la IP validada; el hostname
    original se lee de la cabecera Host (igual que haría un servidor real).
    """

    def __init__(self) -> None:
        self.routes: Dict[Tuple[str, str], Any] = {}
        self.requests: List[httpx.Request] = []
        self.violations: List[str] = []
        self.unrouted: List[Tuple[str, str]] = []

    def add(
        self,
        host: str,
        path: str,
        *,
        status: int = 200,
        json_body: Any = None,
        content: Optional[bytes] = None,
        headers: Optional[dict] = None,
        raises: Optional[Exception] = None,
        handler: Optional[Callable[[httpx.Request], httpx.Response]] = None,
    ) -> None:
        self.routes[(host, path)] = (status, json_body, content, headers or {}, raises, handler)

    def hosts_requested(self) -> List[str]:
        return [r.headers["host"].split(":")[0] for r in self.requests]

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if net_safety.classify_ip(request.url.host) is not None:
            self.violations.append(request.url.host)
        host = request.headers["host"].split(":")[0]
        key = (host, request.url.path)
        route = self.routes.get(key)
        if route is None:
            self.unrouted.append(key)
            return httpx.Response(599, content=b"unrouted")
        status, json_body, content, headers, raises, handler = route
        if raises is not None:
            raise raises
        if handler is not None:
            return handler(request)
        if json_body is not None:
            return httpx.Response(status, json=json_body, headers=headers)
        return httpx.Response(status, content=content or b"", headers=headers)

    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self)


@dataclass
class NetEnv:
    router: RdapRouter
    hosts: Dict[str, str]
    dns: DnsRecorder

    def resolve(self, host: str, ip) -> None:
        """Declara a qué IP(s) resuelve un hostname (socket.getaddrinfo)."""
        self.hosts[host] = ip


def make_bootstrap(extra: Optional[List[list]] = None, *, include_es: bool = False) -> dict:
    services: List[list] = [
        [["com", "net"], ["https://rdap.verisign.com/com/v1/"]],
        [["org"], ["https://rdap.publicinterestregistry.org/rdap/"]],
        [["eu"], ["https://rdap.eu/"]],
    ]
    if include_es:
        services.append([["es"], ["https://rdap.nic.es.example/"]])
    services.extend(extra or [])
    return {"version": "1.0", "publication": "2026-01-01T00:00:00Z", "services": services}


def rdap_domain(
    name: str = "example.com",
    *,
    registrar: Optional[str] = "Example Registrar, Inc.",
    iana_id: Optional[str] = "1068",
    created: Optional[str] = "2010-05-04T10:00:00Z",
    expires: Optional[str] = "2027-05-04T10:00:00Z",
    updated: Optional[str] = "2025-04-01T08:30:00Z",
    status: Optional[List[str]] = ("client transfer prohibited",),
    nameservers: Optional[List[str]] = ("ada.ns.cloudflare.com", "bob.ns.cloudflare.com"),
    delegation_signed: Optional[bool] = False,
) -> dict:
    """Objeto `domain` RDAP realista; los parámetros a None omiten el campo."""
    body: Dict[str, Any] = {
        "objectClassName": "domain",
        "ldhName": name.upper(),
        "events": [{"eventAction": "last update of RDAP database", "eventDate": "2026-10-05T00:00:00Z"}],
    }
    if created:
        body["events"].append({"eventAction": "registration", "eventDate": created})
    if expires:
        body["events"].append({"eventAction": "expiration", "eventDate": expires})
    if updated:
        body["events"].append({"eventAction": "last changed", "eventDate": updated})
    if status is not None:
        body["status"] = list(status)
    if nameservers is not None:
        body["nameservers"] = [{"objectClassName": "nameserver", "ldhName": n.upper()} for n in nameservers]
    if delegation_signed is not None:
        body["secureDNS"] = {"delegationSigned": delegation_signed}
    if registrar or iana_id:
        entity: Dict[str, Any] = {"objectClassName": "entity", "roles": ["registrar"]}
        if registrar:
            entity["vcardArray"] = ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", registrar]]]
        if iana_id:
            entity["publicIds"] = [{"type": "IANA Registrar ID", "identifier": iana_id}]
        body["entities"] = [entity]
    return body


def add_bootstrap(router: RdapRouter, bootstrap: Optional[dict] = None, **kwargs) -> None:
    router.add(IANA_HOST, "/rdap/dns.json", json_body=bootstrap or make_bootstrap(), **kwargs)


# --- Fixtures ----------------------------------------------------------------
@pytest.fixture(autouse=True)
def isolate_network(monkeypatch):
    """Bloquea red real, vacía la caché del bootstrap y vigila violaciones."""
    rdap.clear_bootstrap_cache()

    def _no_connect(self, *args, **kwargs):
        raise AssertionError("Conexión TCP real bloqueada en tests")

    monkeypatch.setattr(socket.socket, "connect", _no_connect)

    hosts: Dict[str, Any] = dict(HOST_IPS)
    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo(hosts))

    recorder = DnsRecorder()
    install_dns_recording(monkeypatch, {}, recorder)  # por defecto: todo es "inesperado"
    router = RdapRouter()
    env = NetEnv(router=router, hosts=hosts, dns=recorder)
    # Los tests que declaran su propia tabla DNS reemplazan este mock con
    # `env.install_dns(...)`; aquí solo se vigila que nada se escape.
    env.install_dns = lambda table: install_dns_recording(monkeypatch, table, recorder)  # type: ignore[attr-defined]
    yield env
    rdap.clear_bootstrap_cache()
    assert not router.violations, f"Conexión a IP no pública: {router.violations}"
    assert not recorder.unexpected, f"Consultas DNS no mockeadas: {recorder.unexpected}"


@pytest.fixture
def net(isolate_network):
    """Alias legible del entorno de red de test."""
    return isolate_network
