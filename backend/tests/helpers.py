"""Utilidades compartidas por los tests (sin red real)."""

import socket

from backend.models import CheckResult, Severity, Status


def make_check(status: Status, **overrides) -> CheckResult:
    """CheckResult mínimo con el estado indicado."""
    severity = {
        Status.OK: Severity.NONE,
        Status.WARNING: Severity.MEDIUM,
        Status.ERROR: Severity.HIGH,
        Status.UNKNOWN: Severity.UNKNOWN,
    }[status]
    data = dict(
        status=status,
        severity=severity,
        title="t",
        summary="s",
        checked=status != Status.UNKNOWN,
        details={},
    )
    data.update(overrides)
    return CheckResult(**data)


def fake_getaddrinfo(mapping):
    """
    Sustituto de `socket.getaddrinfo` sin DNS real.

    `mapping`: hostname -> IP o lista de IPs. Un host ausente lanza gaierror.
    """

    def _getaddrinfo(host, port, *args, **kwargs):
        if host in mapping:
            ips = mapping[host]
        else:
            try:  # IPv4 literal; inet_aton acepta formas como 2130706433, 0x7f.1 o 127.1
                ips = [socket.inet_ntoa(socket.inet_aton(host))]
            except OSError:
                try:
                    socket.inet_pton(socket.AF_INET6, host)
                    ips = [host]
                except OSError:
                    raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
        if isinstance(ips, str):
            ips = [ips]
        result = []
        for ip in ips:
            family = socket.AF_INET6 if ":" in ip else socket.AF_INET
            sockaddr = (ip, port, 0, 0) if family == socket.AF_INET6 else (ip, port)
            result.append((family, socket.SOCK_STREAM, 6, "", sockaddr))
        return result

    return _getaddrinfo


# --- DNS mockeado compartido por los tests de checks -------------------------
import dns.name  # noqa: E402
import dns.resolver  # noqa: E402


class FakeTxt:
    """Registro TXT; `parts` son los fragmentos (cadenas) del registro."""

    def __init__(self, *parts):
        self.strings = tuple(p.encode() if isinstance(p, str) else p for p in parts)


class FakeMx:
    def __init__(self, preference, exchange):
        self.preference = preference
        self.exchange = dns.name.from_text(exchange)


class FakeIp:
    def __init__(self, ip):
        self.ip = ip

    def __str__(self):
        return self.ip


def install_dns(monkeypatch, table):
    """
    Mockea `dns.resolver.Resolver.resolve` (y por tanto `dns.resolver.resolve`).

    `table`: (nombre, tipo) -> lista de rdata o excepción a lanzar. Lo que no
    esté en la tabla lanza NXDOMAIN. Los nombres se comparan sin punto final.
    """

    def _resolve(self, qname, rdtype="A", *args, **kwargs):
        key = (str(qname).rstrip("."), rdtype)
        value = table.get(key, dns.resolver.NXDOMAIN())
        if isinstance(value, Exception):
            raise value
        return value

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", _resolve)
