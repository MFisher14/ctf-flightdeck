"""B-091: the Tor fetch engine end to end and the `ctf tor-fetch` command.

A fake SOCKS5h proxy and a fake TLS server on 127.0.0.1 stand in for Tor and a hidden service -- no
real Tor daemon, no real onion, no network off the loopback. The proxy accepts a SOCKS5 CONNECT to a
domain name (as Tor does for a `.onion`) and bridges to the local TLS server, which presents a
self-signed certificate with a known serial (the thing a "read the certificate" task asks for) and
serves an HTML page that declares a favicon. The tests prove the fetch resolves the name through the
proxy (SOCKS5h), reads the leaf serial + fingerprints, captures headers/body, hashes the favicon with
B-089, writes the evidence files, and that the CLI prints the serial and exits 0 -- and exits 3 with
no proxy and 4 out of scope, contacting nothing.
"""
from __future__ import annotations

import argparse
import datetime as dt
import socket
import ssl
import struct
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ctf import event, favicon, scope, tor
from ctf.cli import tor_fetch as cli

pytest.importorskip("socks")                       # PySocks: the SOCKS5h client under test
cryptography = pytest.importorskip("cryptography")
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

PLATFORM = "https://board.ctf.example"
ONION = "4uybrxybehxbf646wqbnyjxyjk2xis6mpvo4d57dv25zf5jsazf5tsad.onion"
SERIAL = 0x6FDBE5407014B76F971FAFC7E888BD66FEC5D2FD
SERIAL_HEX = "6FDBE5407014B76F971FAFC7E888BD66FEC5D2FD"
ICON = b"\x00\x00\x01\x00" + b"\x42" * 300
PAGE = (b'<html><head><link rel="shortcut icon" href="/favicon.ico"></head>'
        b'<body>ParsnipLocker leak blog</body></html>')


def _profile(live_service_scope, slug="tor-e2e"):
    return event.parse({
        "slug": slug, "name": "tor e2e",
        "dates": {"start": dt.date(2026, 1, 1), "end": dt.date(2026, 1, 2)},
        "platform": {"kind": "ctfd", "base_url": PLATFORM},
        "flag": {"prefixes": []},
        "rules": {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed",
                  "live_service_scope": list(live_service_scope)},
    }, src="<test>")


@pytest.fixture
def pin_scope():
    before = scope.pinned()

    def _use(globs):
        scope.pin(_profile(globs))
    yield _use
    scope.unpin() if before is None else scope.pin(before)


def _write_self_signed(tmp: Path, serial: int, cn: str = ONION):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(serial)
            .not_valid_before(now).not_valid_after(now + dt.timedelta(days=30))
            .sign(key, hashes.SHA256()))
    cert_path, key_path = tmp / "cert.pem", tmp / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                         serialization.PrivateFormat.TraditionalOpenSSL,
                         serialization.NoEncryption()))
    return cert_path, key_path


def _recvn(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("short read")
        buf += chunk
    return buf


class FakeTLSService:
    """A loopback TLS server presenting `cert` and serving the page + favicon. Stands in for an onion
    HTTPS hidden service."""

    def __init__(self, cert_path, key_path, routes):
        self.routes = routes
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(str(cert_path), str(key_path))
        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(8)
        self.port = self.srv.getsockname()[1]
        self.stop = False
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self):
        while not self.stop:
            try:
                self.srv.settimeout(0.5)
                raw, _ = self.srv.accept()
            except (OSError, socket.timeout):
                continue
            threading.Thread(target=self._handle, args=(raw,), daemon=True).start()

    def _handle(self, raw):
        try:
            conn = self.ctx.wrap_socket(raw, server_side=True)
        except OSError:
            raw.close()
            return
        try:
            conn.settimeout(3.0)
            req = b""
            while b"\r\n\r\n" not in req:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                req += chunk
            path = req.split(b" ", 2)[1].decode("latin-1") if b" " in req else "/"
            status, ctype, data = self.routes.get(path, (404, "text/plain", b"not found"))
            resp = (f"HTTP/1.1 {status} OK\r\nContent-Type: {ctype}\r\n"
                    f"Content-Length: {len(data)}\r\nConnection: close\r\n\r\n").encode() + data
            conn.sendall(resp)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_exc):
        self.stop = True
        self.srv.close()
        self.thread.join(timeout=5)


class FakeSocks5h:
    """A minimal SOCKS5 proxy that accepts a CONNECT to a domain name (SOCKS5h, as Tor does for an
    .onion) and bridges to a fixed loopback (host, port): the local TLS service. It never resolves the
    name itself -- exactly the Tor contract this engine relies on."""

    def __init__(self, upstream):
        self.upstream = upstream              # (host, port) to bridge every CONNECT to
        self.requested = []                   # the domain names clients asked for
        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(8)
        self.port = self.srv.getsockname()[1]
        self.stop = False
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self):
        while not self.stop:
            try:
                self.srv.settimeout(0.5)
                conn, _ = self.srv.accept()
            except (OSError, socket.timeout):
                continue
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        try:
            ver, nmethods = _recvn(conn, 2)
            _recvn(conn, nmethods)                       # the offered methods
            conn.sendall(b"\x05\x00")                    # choose "no authentication"
            ver, cmd, _rsv, atyp = _recvn(conn, 4)
            if atyp == 3:
                dlen = _recvn(conn, 1)[0]
                domain = _recvn(conn, dlen).decode("latin-1")
                self.requested.append(domain)
            elif atyp == 1:
                _recvn(conn, 4)
            _recvn(conn, 2)                              # the port
            conn.sendall(b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0") + struct.pack(">H", 0))
            up = socket.create_connection(self.upstream, timeout=5)
            self._bridge(conn, up)
        except (OSError, ConnectionError):
            try:
                conn.close()
            except OSError:
                pass

    def _bridge(self, a, b):
        def pump(src, dst):
            try:
                while True:
                    data = src.recv(65536)
                    if not data:
                        break
                    dst.sendall(data)
            except OSError:
                pass
            finally:
                for s in (src, dst):
                    try:
                        s.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
        t1 = threading.Thread(target=pump, args=(a, b), daemon=True)
        t2 = threading.Thread(target=pump, args=(b, a), daemon=True)
        t1.start(); t2.start(); t1.join(timeout=10); t2.join(timeout=10)
        for s in (a, b):
            try:
                s.close()
            except OSError:
                pass

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_exc):
        self.stop = True
        self.srv.close()
        self.thread.join(timeout=5)


def _stack(tmp_path, routes=None):
    routes = routes or {"/": (200, "text/html", PAGE), "/favicon.ico": (200, "image/x-icon", ICON)}
    cert_path, key_path = _write_self_signed(tmp_path, SERIAL)
    tls = FakeTLSService(cert_path, key_path, routes)
    return tls


def test_fetch_reads_leaf_serial_over_socks5h(pin_scope, tmp_path):
    pin_scope([ONION])
    with _stack(tmp_path) as tls, FakeSocks5h(("127.0.0.1", tls.port)) as proxy:
        resp = tor.fetch_onion(f"https://{ONION}/", socks_port=proxy.port)
    # The name was resolved by the proxy (SOCKS5h), not locally.
    assert proxy.requested == [ONION, ONION]        # page fetch, then favicon fetch
    assert resp.status_code == 200
    assert b"ParsnipLocker" in resp.body
    assert resp.cert["serial"] == SERIAL_HEX
    assert resp.cert["subject_cn"] == ONION


def test_fetch_captures_favicon_with_b089_hashes(pin_scope, tmp_path):
    pin_scope([ONION])
    with _stack(tmp_path) as tls, FakeSocks5h(("127.0.0.1", tls.port)) as proxy:
        resp = tor.fetch_onion(f"https://{ONION}/", socks_port=proxy.port)
    assert resp.favicon == ICON
    assert resp.favicon_url.endswith("/favicon.ico")
    assert resp.favicon_hashes["md5"] == favicon.fingerprint(ICON).md5
    assert resp.favicon_hashes["mmh3"] == favicon.fingerprint(ICON).mmh3


def test_write_evidence_files(pin_scope, tmp_path):
    pin_scope([ONION])
    with _stack(tmp_path) as tls, FakeSocks5h(("127.0.0.1", tls.port)) as proxy:
        resp = tor.fetch_onion(f"https://{ONION}/", socks_port=proxy.port)
    out = tmp_path / "evidence"
    written = tor.write_evidence(resp, out)
    names = {p.name for p in written}
    assert {"headers.txt", "body.html", "leaf-cert.pem", "leaf-cert.json", "tor-fetch.json",
            "favicon.bin"} <= names
    assert SERIAL_HEX in (out / "leaf-cert.json").read_text()
    assert (out / "leaf-cert.pem").read_text().startswith("-----BEGIN CERTIFICATE-----")
    assert (out / "favicon.bin").read_bytes() == ICON


def test_cli_prints_serial_and_exits_zero(pin_scope, tmp_path, capsys):
    pin_scope([ONION])
    out = tmp_path / "ev"
    with _stack(tmp_path) as tls, FakeSocks5h(("127.0.0.1", tls.port)) as proxy:
        args = argparse.Namespace(url=f"https://{ONION}/", socks_port=proxy.port,
                                  socks_host="127.0.0.1", timeout=10.0, out=str(out),
                                  no_favicon=False, json=False)
        rc = cli.run(args)
    captured = capsys.readouterr().out
    assert rc == 0
    assert SERIAL_HEX in captured
    assert (out / "tor-fetch.json").exists()


def test_cli_exit_3_when_no_tor_proxy(pin_scope, tmp_path, capsys):
    pin_scope([ONION])
    s = socket.socket(); s.bind(("127.0.0.1", 0)); dead = s.getsockname()[1]; s.close()
    args = argparse.Namespace(url=f"https://{ONION}/", socks_port=dead, socks_host="127.0.0.1",
                              timeout=5.0, out=None, no_favicon=False, json=False)
    rc = cli.run(args)
    err = capsys.readouterr().err
    assert rc == cli.NO_TOR_EXIT
    assert "SOCKS" in err or "SocksPort" in err


def test_cli_exit_4_out_of_scope(pin_scope, tmp_path, capsys):
    pin_scope(["*.other.onion"])                      # the target onion is not in scope
    s = socket.socket(); s.bind(("127.0.0.1", 0)); dead = s.getsockname()[1]; s.close()
    args = argparse.Namespace(url=f"https://{ONION}/", socks_port=dead, socks_host="127.0.0.1",
                              timeout=5.0, out=None, no_favicon=False, json=False)
    rc = cli.run(args)
    assert rc == cli.REFUSED_EXIT
