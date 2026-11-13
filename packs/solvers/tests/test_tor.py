"""B-091: the Tor fetch + leaf-certificate engine core (ctf/tor.py).

Unit tests for the pieces that do not need the full SOCKS/TLS stack: HTTP parsing, leaf-certificate
reading (serial + fingerprints), SOCKS5-proxy detection (against a tiny fake responder on 127.0.0.1,
never a real tor), the scope guard running before any connection, and the loud failures (non-onion
target, no SOCKS proxy). No test contacts a real service or a real Tor daemon.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import socket
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ctf import event, scope, tor

cryptography = pytest.importorskip("cryptography")
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


PLATFORM = "https://board.ctf.example"
ONION = "4uybrxybehxbf646wqbnyjxyjk2xis6mpvo4d57dv25zf5jsazf5tsad.onion"


def _profile(live_service_scope, slug="tor-test"):
    return event.parse({
        "slug": slug, "name": "tor test",
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


def _self_signed(serial: int, cn: str = ONION):
    """A self-signed certificate (as an onion blog presents) with a chosen serial. Returns the DER."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(serial)
            .not_valid_before(now).not_valid_after(now + dt.timedelta(days=30))
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.DER)


# ---------------------------------------------------------------- leaf certificate

def test_leaf_cert_serial_is_uppercase_hex_no_colons():
    der = _self_signed(0x6FDBE5407014B76F971FAFC7E888BD66FEC5D2FD)
    info = tor.leaf_cert_info(der)
    assert info["serial"] == "6FDBE5407014B76F971FAFC7E888BD66FEC5D2FD"
    assert info["serial"] == info["serial"].upper()
    assert ":" not in info["serial"] and " " not in info["serial"]
    assert info["subject_cn"] == ONION


def test_leaf_cert_serial_zero_pads_to_whole_bytes():
    # A serial whose top byte has no high bit still renders with an even number of nibbles, the way
    # openssl prints it: 0x0ABC -> "0ABC", not "ABC".
    info = tor.leaf_cert_info(_self_signed(0x0ABC))
    assert info["serial"] == "0ABC"


def test_leaf_cert_fingerprints_are_digests_of_the_der():
    der = _self_signed(0x1234)
    info = tor.leaf_cert_info(der)
    assert info["sha1"] == hashlib.sha1(der).hexdigest()
    assert info["sha256"] == hashlib.sha256(der).hexdigest()
    assert info["fingerprint_sha256"] == ":".join(
        info["sha256"][i:i + 2] for i in range(0, 64, 2)).upper()
    # The fingerprint is the standard one: cryptography agrees.
    cert = x509.load_der_x509_certificate(der)
    assert cert.fingerprint(hashes.SHA256()).hex() == info["sha256"]


def test_leaf_cert_info_returns_none_for_junk():
    assert tor.leaf_cert_info(b"not a certificate") is None
    assert tor.leaf_cert_info(b"") is None


# ---------------------------------------------------------------- HTTP response parsing

def test_parse_http_content_length():
    raw = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5\r\n\r\n"
           b"hello-trailing-garbage")
    status_line, code, headers, body = tor._parse_http_response(raw)
    assert code == 200 and status_line == "HTTP/1.1 200 OK"
    assert body == b"hello"
    assert ("Content-Type", "text/html") in headers


def test_parse_http_chunked():
    raw = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
           b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n")
    _s, code, _h, body = tor._parse_http_response(raw)
    assert code == 200 and body == b"Wikipedia"


def test_dechunk_offset_is_pinned():
    # Pins the trailing-CRLF skip in _dechunk (`i = end + 2`). Across three chunks the second and
    # third size lines are reached only by the previous chunk's exact end+2 advance. Advancing by
    # one byte too few leaves a stray "\n" heading the next size line, which strict parsing rejects
    # instead of silently resyncing -- so an off-by-one in that skip makes this raise, not mis-decode.
    body = (b"5\r\nalpha\r\n"          # "alpha"
            b"3\r\nbra\r\n"            # "bra"
            b"10\r\n0123456789abcdef\r\n"  # 16 bytes, multi-digit size
            b"0\r\n\r\n")
    assert tor._dechunk(body) == b"alpha" + b"bra" + b"0123456789abcdef"


def test_dechunk_rejects_bad_crlf_termination():
    # A chunk whose data is not CRLF-terminated (a byte short) is a loud TorError, never a silent
    # partial body (R-6). This is also the shape a wrong trailing-CRLF skip would stumble into.
    with pytest.raises(tor.TorError, match="chunked body"):
        tor._dechunk(b"4\r\nWiki\nX5\r\npedia\r\n0\r\n\r\n")


def test_dechunk_rejects_non_hex_size_line():
    with pytest.raises(tor.TorError, match="hex digit"):
        tor._dechunk(b"\n4\r\nWiki\r\n0\r\n\r\n")


def test_parse_http_no_terminator_is_loud():
    with pytest.raises(tor.TorError, match="no header terminator"):
        tor._parse_http_response(b"HTTP/1.1 200 OK\r\nno blank line here")


# ---------------------------------------------------------------- SOCKS5 proxy detection


class _FakeSocks5:
    """A one-shot responder that completes only the SOCKS5 method-selection handshake (VER 5,
    METHOD 0). Stands in for a running Tor SocksPort for the detection probe, with no real Tor."""

    def __init__(self, reply=b"\x05\x00"):
        self.reply = reply
        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(4)
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
            try:
                conn.recv(16)
                conn.sendall(self.reply)
            except OSError:
                pass
            finally:
                conn.close()

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_exc):
        self.stop = True
        self.srv.close()
        self.thread.join(timeout=5)


def test_detect_socks_port_finds_a_socks5_responder():
    with _FakeSocks5() as fake:
        assert tor.detect_socks_port(ports=[fake.port]) == fake.port


def test_detect_socks_port_rejects_a_non_socks_port():
    # An open port that answers with the wrong bytes (not a SOCKS5 proxy) must not be accepted.
    with _FakeSocks5(reply=b"HTTP/1.1 400\r\n") as fake:
        assert tor._is_socks5("127.0.0.1", fake.port) is False


def test_detect_socks_port_loud_when_absent():
    # Bind a port, then close it, so the port is almost certainly closed: detection must fail loudly
    # and name the tor human step, never fall back.
    s = socket.socket(); s.bind(("127.0.0.1", 0)); closed_port = s.getsockname()[1]; s.close()
    with pytest.raises(tor.TorError, match="no Tor SOCKS5 proxy"):
        tor.detect_socks_port(ports=[closed_port])


# ---------------------------------------------------------------- fetch_onion guards

def test_fetch_rejects_non_onion_host(pin_scope):
    pin_scope(["*"])  # even with a wide scope, a clearnet host is refused by the engine itself
    with pytest.raises(tor.TorError, match="not a .onion host"):
        tor.fetch_onion("https://example.com/")


def test_fetch_scope_refusal_before_any_connection(pin_scope):
    # The onion is NOT in scope; the refusal must happen before any SOCKS connection, so pointing at a
    # closed socks port still yields OutOfScope (not a TorError about the proxy).
    pin_scope(["*.example.onion"])
    s = socket.socket(); s.bind(("127.0.0.1", 0)); dead = s.getsockname()[1]; s.close()
    with pytest.raises(scope.OutOfScope):
        tor.fetch_onion(f"https://{ONION}/", socks_port=dead)


def test_fetch_loud_when_socks_port_dead(pin_scope):
    # In scope, but the named socks port is closed: a loud TorError naming the proxy, no fallback.
    pin_scope([ONION])
    s = socket.socket(); s.bind(("127.0.0.1", 0)); dead = s.getsockname()[1]; s.close()
    with pytest.raises(tor.TorError, match="SOCKS5 proxy"):
        tor.fetch_onion(f"https://{ONION}/", socks_port=dead)
