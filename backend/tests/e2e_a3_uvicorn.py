"""Pruebas HTTP REALES de A3: Uvicorn real + proxy falso que añade entradas a XFF.

Uso (desde la raíz del proyecto):  python backend/tests/e2e_a3_uvicorn.py
No es un test de pytest (no se recolecta) y NO toca producción ni la red externa:
arranca Uvicorn en 127.0.0.1 y un proxy local que imita a Render añadiendo
entradas a ``X-Forwarded-For``. Demuestra el comportamiento del código, NO cuántas
entradas añade Render de verdad (eso solo se verifica en producción).
Los límites se bajan por entorno (LIMIT) para agotar la cuota rápido.
"""
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PY = sys.executable
LIMIT = 3  # peticiones permitidas por ventana en POST /monitor


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class FakeEdge(threading.Thread):
    """Proxy que añade al final de X-Forwarded-For: peer real + `extra` fijas.

    Cabecera de simulación `X-Sim-Peer` (solo del arnés): sustituye la IP que el
    proxy "ve" como cliente, para simular clientes IPv6 / NAT distintos sin
    abrir sockets IPv6. Se elimina antes de reenviar.
    """

    def __init__(self, backend_port, extra):
        super().__init__(daemon=True)
        self.backend_port = backend_port
        self.extra = extra
        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(64)
        self.port = self.srv.getsockname()[1]

    def run(self):
        while True:
            try:
                c, addr = self.srv.accept()
            except OSError:
                return
            threading.Thread(target=self.handle, args=(c, addr), daemon=True).start()

    def handle(self, c, addr):
        try:
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = c.recv(65536)
                if not chunk:
                    return
                data += chunk
            head, _, body = data.partition(b"\r\n\r\n")
            lines = head.split(b"\r\n")
            out, xff, sim = [lines[0]], [], None
            for ln in lines[1:]:
                name = ln.split(b":", 1)[0].strip().lower()
                if name == b"x-forwarded-for":
                    xff.append(ln.split(b":", 1)[1].strip().decode("latin1"))
                elif name == b"x-sim-peer":
                    sim = ln.split(b":", 1)[1].strip().decode()
                elif name == b"connection":
                    pass
                else:
                    out.append(ln)
            peer = sim or addr[0]
            chain = xff + [peer] + self.extra
            out.append(b"X-Forwarded-For: " + ", ".join(chain).encode("latin1"))
            out.append(b"Connection: close")
            b = socket.create_connection(("127.0.0.1", self.backend_port))
            b.sendall(b"\r\n".join(out) + b"\r\n\r\n" + body)
            resp = b""
            while True:
                chunk = b.recv(65536)
                if not chunk:
                    break
                resp += chunk
            c.sendall(resp)
        finally:
            c.close()


def start_uvicorn(env_extra, flags=()):
    port = free_port()
    env = dict(os.environ)
    for k in list(env):
        if k.startswith("NERSIVO_") or k == "FORWARDED_ALLOW_IPS":
            del env[k]
    env.update(
        {
            "NERSIVO_MONITOR_RATE_MAX_REQUESTS": str(LIMIT),
            "NERSIVO_MONITOR_RATE_WINDOW_SECONDS": "600",
            "NERSIVO_LOG_CLIENT_IP_RESOLUTION": "0",
        }
    )
    env.update(env_extra)
    log = tempfile.NamedTemporaryFile(prefix="uv_a3_", suffix=".log", delete=False)
    p = subprocess.Popen(
        [PY, "-m", "uvicorn", "backend.main:app", "--port", str(port), "--host", "127.0.0.1", *flags],
        cwd=REPO, env=env, stdout=log, stderr=subprocess.STDOUT,
    )
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            return p, port, log.name
        except OSError:
            if p.poll() is not None:
                raise RuntimeError(open(log.name).read())
            time.sleep(0.1)
    raise RuntimeError("uvicorn no arrancó")


def request(port, headers=(), method="POST", path="/monitor", body=b"{}", bind=None):
    s = socket.create_connection(("127.0.0.1", port), timeout=10, source_address=bind)
    hs = [f"{method} {path} HTTP/1.1", "Host: x", "Content-Type: application/json",
          f"Content-Length: {len(body)}", "Connection: close"]
    hs += [f"{k}: {v}" for k, v in headers]
    s.sendall("\r\n".join(hs).encode("latin1") + b"\r\n\r\n" + body)
    resp = b""
    while True:
        c = s.recv(65536)
        if not c:
            break
        resp += c
    s.close()
    return int(resp.split(b" ", 2)[1])


def count_until_429(port, headers_fn, n=40):
    """Devuelve cuántas peticiones se aceptan antes del primer 429 (o n)."""
    for i in range(n):
        if request(port, headers_fn(i)) == 429:
            return i
    return n



def row(name, got, expect, ok):
    print(("OK    " if ok else "FALLO ") + f"{name:<62} {got!s:<10} esperado: {expect}")
    return ok


def probe(port, label):
    """Bateria de ataques contra `port` (edge o backend directo). Devuelve dict."""
    r = {}
    r["honesto"] = count_until_429(port, lambda i: [("X-Sim-Peer", "198.51.100.1")])
    r["spoof_rotando_izq"] = count_until_429(
        port, lambda i: [("X-Sim-Peer", "198.51.100.2"), ("X-Forwarded-For", f"203.0.113.{i+1}")])
    r["spoof_relleno_5"] = count_until_429(
        port, lambda i: [("X-Sim-Peer", "198.51.100.3"),
                         ("X-Forwarded-For", ", ".join(f"203.0.{i}.{j}" for j in range(1, 6)))])
    r["spoof_varias_lineas"] = count_until_429(
        port, lambda i: [("X-Sim-Peer", "198.51.100.4"), ("X-Forwarded-For", f"203.0.113.{i+1}"),
                         ("X-Forwarded-For", f"203.0.114.{i+1}")])
    r["basura_izq"] = count_until_429(
        port, lambda i: [("X-Sim-Peer", "198.51.100.5"), ("X-Forwarded-For", f"basura{i}, ;;{i}, <{i}>")])
    r["ipv6_mismo_64"] = count_until_429(
        port, lambda i: [("X-Sim-Peer", f"2001:db8:aaaa:bbbb::{i+1:x}")])
    r["ipv6_formas_mismo_host"] = count_until_429(
        port, lambda i: [("X-Sim-Peer", ["2001:db8:1::1", "2001:0db8:0001:0000:0000:0000:0000:0001",
                                         "2001:DB8:1::0001", "[2001:db8:1::1]", "::ffff:198.51.100.6"][i % 5])])
    a, b = "198.51.100.10", "198.51.100.11"
    for _ in range(LIMIT):
        request(port, [("X-Sim-Peer", a)])
    r["a_bloqueado"] = request(port, [("X-Sim-Peer", a)])
    r["b_permitido"] = request(port, [("X-Sim-Peer", b)])
    # NAT: dos usuarios con la misma IP publica comparten cuota (por diseño)
    n1 = count_until_429(port, lambda i: [("X-Sim-Peer", "198.51.100.20")])
    r["nat_misma_ip_comparte"] = request(port, [("X-Sim-Peer", "198.51.100.20")])
    return r


def main():
    ok_all = True
    print("== A. Render-like: Uvicorn FORWARDED_ALLOW_IPS=*, HOPS=3, proxy añade 3 entradas ==")
    p, port, _ = start_uvicorn({"FORWARDED_ALLOW_IPS": "*", "NERSIVO_TRUSTED_PROXY_HOPS": "3"})
    edge = FakeEdge(port, ["162.158.0.1", "10.16.0.5"]); edge.start()
    r = probe(edge.port, "A")
    ok_all &= row("honesto agota en LIMIT", r["honesto"], LIMIT, r["honesto"] == LIMIT)
    for k in ("spoof_rotando_izq", "spoof_relleno_5", "spoof_varias_lineas", "basura_izq"):
        ok_all &= row(k, r[k], LIMIT, r[k] == LIMIT)
    ok_all &= row("a bloqueado / b permitido", (r["a_bloqueado"], r["b_permitido"]), "(429, 4xx)",
                  r["a_bloqueado"] == 429 and r["b_permitido"] != 429)
    ok_all &= row("ipv6_formas_mismo_host (una sola cuota)", r["ipv6_formas_mismo_host"], LIMIT,
                  r["ipv6_formas_mismo_host"] == LIMIT)
    ok_all &= row("ipv6: 40 direcciones de un /64 comparten cuota", r["ipv6_mismo_64"], LIMIT,
                  r["ipv6_mismo_64"] == LIMIT)
    print("   NAT misma IP publica comparte cuota ->", r["nat_misma_ip_comparte"])
    p.terminate(); p.wait(); edge.srv.close()

    print("\n== B. Cadena MAS CORTA de lo configurado (proxy añade 2, HOPS=3) [LIMITE CONOCIDO, informativo] ==")
    p, port, _ = start_uvicorn({"FORWARDED_ALLOW_IPS": "*", "NERSIVO_TRUSTED_PROXY_HOPS": "3"})
    edge = FakeEdge(port, ["162.158.0.1"]); edge.start()
    r = probe(edge.port, "B")
    print("   spoof_rotando_izq ->", r["spoof_rotando_izq"], "(40 = EVASION TOTAL)")
    print("   spoof_relleno_5   ->", r["spoof_relleno_5"])
    print("   honesto           ->", r["honesto"])
    p.terminate(); p.wait(); edge.srv.close()

    print("\n== C. Cadena MAS LARGA de lo configurado (proxy añade 4, HOPS=3) [LIMITE CONOCIDO, informativo] ==")
    p, port, _ = start_uvicorn({"FORWARDED_ALLOW_IPS": "*", "NERSIVO_TRUSTED_PROXY_HOPS": "3"})
    edge = FakeEdge(port, ["162.158.0.1", "10.16.0.5", "10.16.0.9"]); edge.start()
    r = probe(edge.port, "C")
    print("   a_bloqueado/b_permitido ->", r["a_bloqueado"], r["b_permitido"],
          "(b=429 => usuarios legítimos comparten cubo)")
    p.terminate(); p.wait(); edge.srv.close()

    print("\n== D. Acceso DIRECTO al backend (sin proxy), HOPS=3, sin CIDRS [LIMITE CONOCIDO, informativo] ==")
    p, port, _ = start_uvicorn({"FORWARDED_ALLOW_IPS": "*", "NERSIVO_TRUSTED_PROXY_HOPS": "3"})
    n = count_until_429(port, lambda i: [("X-Forwarded-For", f"1.1.1.{i+1}, 9.9.9.9, 8.8.8.8")])
    print("   rotando 1ª de 3 entradas ->", n, "(40 = EVASION TOTAL)")
    p.terminate(); p.wait()

    print("\n== E. HOPS=0 con FORWARDED_ALLOW_IPS=* (config por defecto de Render) [LIMITE CONOCIDO, informativo] ==")
    p, port, _ = start_uvicorn({"FORWARDED_ALLOW_IPS": "*", "NERSIVO_TRUSTED_PROXY_HOPS": "0"})
    n = count_until_429(port, lambda i: [("X-Forwarded-For", f"203.0.113.{i+1}")])
    print("   rotando XFF ->", n, "(40 = EVASION TOTAL: vulnerabilidad original A3)")
    p.terminate(); p.wait()
    return ok_all


class EdgeFrom127002(FakeEdge):
    """Como FakeEdge, pero conecta al backend desde 127.0.0.2 (peer TCP distinguible)."""

    def handle(self, c, addr):
        orig = socket.create_connection

        def cc(address, timeout=None, source_address=None):
            return orig(address, timeout=timeout, source_address=("127.0.0.2", 0))

        socket.create_connection = cc
        try:
            super().handle(c, addr)
        finally:
            socket.create_connection = orig


def cidrs_scenarios():
    base = {"NERSIVO_TRUSTED_PROXY_HOPS": "3", "NERSIVO_TRUSTED_PROXY_CIDRS": "127.0.0.2/32"}
    print("\n== F. CIDRS + FORWARDED_ALLOW_IPS con el proxy dentro: debe NO arrancar ==")
    try:
        p, port, _ = start_uvicorn({**base, "FORWARDED_ALLOW_IPS": "127.0.0.2"})
        p.terminate(); p.wait()
        print("FALLO arrancó (antes del cierre A3 arrancaba y metía a todos en un cubo)")
        return False
    except RuntimeError as exc:
        print("OK    no arranca:", str(exc).strip().splitlines()[-1][:110])

    print("== G. CIDRS + FORWARDED_ALLOW_IPS que no incluye al proxy ==")
    p, port, _ = start_uvicorn({**base, "FORWARDED_ALLOW_IPS": "10.99.99.99"})
    edge = EdgeFrom127002(port, ["162.158.0.1", "10.16.0.5"]); edge.start()
    a, b = "198.51.100.10", "198.51.100.11"
    for _ in range(LIMIT):
        request(edge.port, [("X-Sim-Peer", a)])
    ra, rb = request(edge.port, [("X-Sim-Peer", a)]), request(edge.port, [("X-Sim-Peer", b)])
    direct = count_until_429(port, lambda i: [("X-Forwarded-For", f"1.1.1.{i+1}, 9.9.9.9, 8.8.8.8")])
    p.terminate(); p.wait(); edge.srv.close()
    ok = row("por el proxy: a limitado, b no", (ra, rb), "(429, no-429)", ra == 429 and rb != 429)
    ok &= row("directo desde peer no confiable: sin evasión", direct, LIMIT, direct == LIMIT)
    return ok


def path_scenarios():
    print("\n== H. Variantes de ruta y cabecera gigante ==")
    p, port, _ = start_uvicorn({"FORWARDED_ALLOW_IPS": "*", "NERSIVO_TRUSTED_PROXY_HOPS": "3"})
    edge = FakeEdge(port, ["162.158.0.1", "10.16.0.5"]); edge.start()
    ok = True
    for i, (method, path) in enumerate([("POST", "/monitor"), ("POST", "/%6Donitor"), ("POST", "/monitor?x=1")]):
        codes = [request(edge.port, [("X-Sim-Peer", f"198.51.101.{i+1}")], method=method, path=path) for _ in range(8)]
        ok &= row(f"{method} {path} se limita", codes.count(429), 5, codes.count(429) == 8 - LIMIT)
    for path in ("//monitor", "/Monitor", "/monitor;x=1", "/./monitor"):
        codes = {request(edge.port, [("X-Sim-Peer", "198.51.101.9")], path=path) for _ in range(5)}
        ok &= row(f"POST {path} no alcanza el handler", sorted(codes), "[404]", codes == {404})
    big = "1.1.1.1, " * 12000
    code = request(edge.port, [("X-Sim-Peer", "198.51.102.1"), ("X-Forwarded-For", big)])
    ok &= row("XFF de 100 KB no rompe el servicio", code, "422", code == 422)
    p.terminate(); p.wait(); edge.srv.close()
    return ok



if __name__ == "__main__":
    ok = main()
    ok = cidrs_scenarios() and ok
    ok = path_scenarios() and ok
    print("\nRESULTADO GLOBAL:", "OK" if ok else "FALLOS")
    sys.exit(0 if ok else 1)
