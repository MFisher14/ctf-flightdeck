"""Tor fetch + leaf-certificate engine (B-091): the online half of the .onion OSINT path.

`solvers/toolkits/osint.py` extracts `.onion` leads offline and says the content is "reachable only
over Tor"; it never fetches. This module does the fetch, the one way that is safe and in scope: a
single passive GET to one identified hidden service over a *local* Tor SOCKS5h proxy, capturing the
response headers, the body, the declared favicon (hashed with B-089's `ctf.favicon`) and -- the point
of a "read the certificate" challenge -- the leaf certificate a hidden service presents (its serial,
in uppercase hex, and its SHA-1 / SHA-256 fingerprints). A self-signed onion certificate never enters
Certificate Transparency, so it cannot be looked up remotely; it has to be read straight off the
service, which is exactly what this engine does.

    from ctf import tor
    resp = tor.fetch_onion("https://abc...d.onion/")      # OnionResponse
    resp.cert["serial"]                                   # "6FDBE5407014B76F971FAFC7E888BD66FEC5D2FD"
    tor.write_evidence(resp, out_dir)                     # headers/body/favicon/leaf-cert files

Rules this engine keeps:

* **Scope first.** `scope.check_host` runs on the `.onion` host before any socket is opened. An
  out-of-scope onion raises `OutOfScope` with no connection, like every other client (ctf/scope.py).
* **SOCKS5h, remote resolution.** `.onion` names resolve only inside Tor, so the host name is handed
  to the proxy (PySocks `rdns=True`); nothing is resolved locally. The proxy itself (127.0.0.1) is
  local Tor infrastructure, not a target, so it is not scope-checked.
* **No silent fallback (R-5/R-6).** A missing Tor SOCKS proxy is a loud `TorError` naming the ports
  tried; it never falls back to a clearnet fetch. Starting a `tor` daemon is a human step (a named job
  under B-175); this engine detects a running SocksPort, it does not launch one.
* **Self-signed is expected.** An onion leaf certificate is self-signed, so the TLS verify mode is
  `CERT_NONE` -- the certificate is *read*, never trusted -- and the DER is captured with
  `getpeercert(binary_form=True)`, which returns the leaf even without verification.

PySocks (`socks`) is required; it is pinned in requirements.in. `cryptography` parses the leaf (the
same dependency `osint.parse_certificates` already uses); without it the fetch still records headers,
body and favicon and leaves `cert` as None.
"""
from __future__ import annotations

import hashlib
import json
import socket
import ssl
import urllib.parse
from dataclasses import dataclass
from pathlib import Path

from . import scope as _scope

try:  # PySocks; pinned in requirements.in. A missing import is a loud failure at fetch time.
    import socks as _socks  # type: ignore
    _SOCKS_IMPORT_ERROR: Exception | None = None
except Exception as e:  # pragma: no cover - exercised only where PySocks is absent
    _socks = None
    _SOCKS_IMPORT_ERROR = e

# The two conventional local Tor SOCKS ports: the tor daemon default and Tor Browser's.
DEFAULT_SOCKS_PORTS = (9050, 9150)
DEFAULT_SOCKS_HOST = "127.0.0.1"
USER_AGENT = "ctf-tools-tor/1 (B-091)"
MAX_BODY = 8 * 1024 * 1024          # cap a response body / favicon
_DEFAULT_PORTS = {"http": 80, "https": 443}


class TorError(RuntimeError):
    """A loud failure on the Tor fetch path: no SOCKS proxy, a non-onion target, a fetch or parse
    failure. Never a silent fallback to a clearnet route."""


class OutOfScope(_scope.OutOfScope):
    """A `.onion` host outside the event profile's rules.live_service_scope. Never contacted."""


# =====================================================================================
#  Tor SOCKS proxy detection
# =====================================================================================

def _is_socks5(host: str, port: int, timeout: float = 2.0) -> bool:
    """True when `host:port` answers a SOCKS5 no-authentication handshake (VER 5, METHOD 0). An open
    port that is not a SOCKS5 proxy (a web server, an echo) answers wrong and returns False; a closed
    port returns False. Opens one short-lived TCP connection and sends 3 bytes."""
    try:
        with socket.create_connection((host, int(port)), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(b"\x05\x01\x00")          # SOCKS5, 1 method, "no authentication"
            reply = s.recv(2)
    except OSError:
        return False
    return reply == b"\x05\x00"


def detect_socks_port(ports=DEFAULT_SOCKS_PORTS, *, host: str = DEFAULT_SOCKS_HOST,
                      timeout: float = 2.0) -> int:
    """The first `ports` entry on `host` that answers a SOCKS5 handshake, or raise `TorError` naming
    every port tried and that starting a `tor` daemon is a human step (a named job, B-175)."""
    tried = []
    for port in ports:
        if _is_socks5(host, int(port), timeout):
            return int(port)
        tried.append(int(port))
    listed = ", ".join(str(p) for p in tried) or "(none)"
    raise TorError(
        f"no Tor SOCKS5 proxy answered on {host}:{{{listed}}}; .onion names resolve only inside Tor, so "
        f"this fetch needs a running Tor SocksPort. Start a tor daemon first (a human step -- a named job "
        f"under B-175, e.g. `tor --SocksPort 9050 --DataDirectory <scratch>`, wait for "
        f"'Bootstrapped 100%'), then re-run. This engine never launches tor and never falls back to a "
        f"clearnet fetch.")


# =====================================================================================
#  Leaf certificate
# =====================================================================================

def _serial_hex(serial: int) -> str:
    """A certificate serial as uppercase hex, no colons or spaces, zero-padded to a whole number of
    bytes -- the form `openssl x509 -serial` prints and a "read the certificate" task asks for."""
    h = format(int(serial), "X")
    return ("0" + h) if len(h) % 2 else h


def _colon_hex(digest_hex: str) -> str:
    return ":".join(digest_hex[i:i + 2] for i in range(0, len(digest_hex), 2)).upper()


def leaf_cert_info(der: bytes) -> dict | None:
    """Parse one DER leaf certificate into a record: serial (uppercase hex), SHA-1 / SHA-256
    fingerprints (over the DER, the standard certificate fingerprint), subject / issuer common names,
    validity and the PEM text. Returns None when `cryptography` is absent or the bytes do not parse.

    The fingerprints are plain `hashlib` over the DER, which is what a certificate fingerprint *is*
    (a digest of the whole DER-encoded certificate); it equals `cryptography`'s `cert.fingerprint`."""
    if not der:
        return None
    try:
        from cryptography import x509  # type: ignore
        from cryptography.hazmat.primitives import serialization  # type: ignore
        from cryptography.x509.oid import NameOID  # type: ignore
    except Exception:
        return None
    try:
        cert = x509.load_der_x509_certificate(bytes(der))
    except Exception:
        return None
    sha1 = hashlib.sha1(bytes(der)).hexdigest()
    sha256 = hashlib.sha256(bytes(der)).hexdigest()

    def _cn(name) -> str | None:
        try:
            attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
            return str(attrs[0].value) if attrs else None
        except Exception:
            return None

    def _iso(getter) -> str | None:
        try:
            return getter().isoformat()
        except Exception:
            return None

    try:
        pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    except Exception:
        pem = None
    return {
        "serial": _serial_hex(cert.serial_number),
        "serial_int": int(cert.serial_number),
        "sha1": sha1,
        "sha256": sha256,
        "fingerprint_sha1": _colon_hex(sha1),
        "fingerprint_sha256": _colon_hex(sha256),
        "subject_cn": _cn(cert.subject),
        "issuer_cn": _cn(cert.issuer),
        "not_before": _iso(lambda: cert.not_valid_before_utc),
        "not_after": _iso(lambda: cert.not_valid_after_utc),
        "pem": pem,
    }


# =====================================================================================
#  HTTP over a Tor-proxied TLS socket
# =====================================================================================

def _split_onion_url(url: str) -> tuple[str, int, str]:
    """(host, port, path-with-query) of a URL; the scheme defaults to https (hidden-service blogs are
    HTTPS), the port by scheme, the path to '/'."""
    u = url if "://" in url else "https://" + url
    parts = urllib.parse.urlsplit(u)
    host = (parts.hostname or "").strip().lower().rstrip(".")
    try:
        port = parts.port
    except ValueError:
        port = None
    if port is None:
        port = _DEFAULT_PORTS.get(parts.scheme.lower(), 443)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    return host, int(port), path


_HEX_DIGITS = frozenset(b"0123456789abcdefABCDEF")


def _dechunk(data: bytes) -> bytes:
    """Decode an HTTP/1.1 ``Transfer-Encoding: chunked`` body.

    Each chunk is ``<hex-size>[;ext]CRLF`` then exactly ``size`` bytes then a CRLF; a zero size ends
    the body. The parse is strict and does not silently resync (R-6): a size line that does not begin
    with a hex digit, a size that runs past the buffer, or chunk data not terminated by CRLF raises
    ``TorError``. Strictness is also what pins the trailing-CRLF skip -- advancing ``i`` by one byte
    too few leaves a stray ``\\n`` at the head of the next size line, which is then rejected instead of
    being absorbed by a lenient ``int()``/``find()`` resync."""
    out = bytearray()
    i, n = 0, len(data)
    while i < n:
        j = data.find(b"\r\n", i)
        if j < 0:
            raise TorError("malformed chunked body: unterminated chunk-size line")
        token = data[i:j].split(b";", 1)[0]
        if not token or token[0] not in _HEX_DIGITS:
            raise TorError("malformed chunked body: chunk-size line does not begin with a hex digit")
        try:
            size = int(token, 16)
        except ValueError:
            raise TorError("malformed chunked body: bad chunk size")
        if size == 0:
            break
        start = j + 2
        end = start + size
        if end > n:
            raise TorError("malformed chunked body: chunk size runs past the response")
        out += data[start:end]
        if data[end:end + 2] != b"\r\n":
            raise TorError("malformed chunked body: chunk data not terminated by CRLF")
        i = end + 2                     # skip the chunk's trailing CRLF
    return bytes(out)


def _parse_http_response(raw: bytes) -> tuple[str, int, list[tuple[str, str]], bytes]:
    """(status_line, status_code, [(name, value)], body) from a raw HTTP/1.x response. Honours
    Transfer-Encoding: chunked and Content-Length; otherwise the body is close-delimited."""
    sep = raw.find(b"\r\n\r\n")
    if sep < 0:
        raise TorError("malformed HTTP response from the onion service: no header terminator")
    head = raw[:sep].decode("latin-1", "replace")
    body = raw[sep + 4:]
    lines = head.split("\r\n")
    status_line = lines[0] if lines else ""
    code = 0
    parts = status_line.split(" ", 2)
    if len(parts) >= 2 and parts[1].isdigit():
        code = int(parts[1])
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            headers.append((k.strip(), v.strip()))
    hmap = {k.lower(): v for k, v in headers}
    if "chunked" in hmap.get("transfer-encoding", "").lower():
        body = _dechunk(body)
    else:
        cl = hmap.get("content-length", "")
        if cl.isdigit():
            body = body[:int(cl)]
    return status_line, code, headers, body


def _tls_connect(host: str, port: int, socks_host: str, socks_port: int, timeout: float):
    """A TLS socket to `host:port` through the local SOCKS5h proxy. The onion name is resolved by Tor
    (rdns=True), and the self-signed onion certificate is read, not trusted (CERT_NONE)."""
    if _socks is None:
        raise TorError(
            f"PySocks (the 'socks' module) is not importable ({_SOCKS_IMPORT_ERROR}); the Tor fetch "
            f"needs it. Install it into the venv: it is pinned in requirements.in.")
    sock = _socks.socksocket()
    sock.set_proxy(_socks.SOCKS5, socks_host, int(socks_port), rdns=True)   # SOCKS5h: Tor resolves .onion
    sock.settimeout(timeout)
    try:
        sock.connect((host, int(port)))
    except Exception as e:
        try:
            sock.close()
        except Exception:
            pass
        raise TorError(f"could not open a Tor circuit to {host}:{port} via {socks_host}:{socks_port} ({e})") from e
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        return ctx.wrap_socket(sock, server_hostname=host)
    except Exception as e:
        try:
            sock.close()
        except Exception:
            pass
        raise TorError(f"TLS handshake with {host}:{port} over Tor failed ({e})") from e


def _http_get(tls, host: str, path: str, max_body: int = MAX_BODY) -> bytes:
    """Send one GET over `tls` and return the raw response bytes (headers + body), capped. Uses
    Connection: close so the server ends the body for us."""
    req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {USER_AGENT}\r\n"
           f"Accept: */*\r\nConnection: close\r\n\r\n").encode("latin-1")
    tls.sendall(req)
    chunks: list[bytes] = []
    total = 0
    cap = max_body + 65536            # a little headroom over the body cap for headers
    while True:
        try:
            buf = tls.recv(65536)
        except (ssl.SSLWantReadError, ssl.SSLWantWriteError):  # pragma: no cover - timing dependent
            continue
        except (ssl.SSLEOFError, OSError):
            break
        if not buf:
            break
        chunks.append(buf)
        total += len(buf)
        if total >= cap:
            break
    return b"".join(chunks)


# =====================================================================================
#  The fetch
# =====================================================================================

@dataclass
class OnionResponse:
    url: str
    host: str
    port: int
    status_line: str
    status_code: int
    headers: list[tuple[str, str]]
    body: bytes
    cert_der: bytes | None
    cert: dict | None
    socks: str                                        # "127.0.0.1:9050", for the evidence trail
    favicon: bytes | None = None
    favicon_url: str | None = None
    favicon_hashes: dict | None = None

    def header(self, name: str) -> str | None:
        low = name.lower()
        for k, v in self.headers:
            if k.lower() == low:
                return v
        return None


def _is_onion(host: str) -> bool:
    return host.endswith(".onion")


def fetch_onion(url: str, *, socks_port: int | None = None, socks_host: str = DEFAULT_SOCKS_HOST,
                timeout: float = 30.0, profile=None, want_favicon: bool = True,
                max_body: int = MAX_BODY) -> OnionResponse:
    """Fetch one `.onion` URL over Tor and return an OnionResponse (headers, body, leaf certificate
    and, when declared, the favicon with B-089's hashes).

    `scope.check_host` on the onion host runs first, so an out-of-scope onion raises `OutOfScope`
    before any socket. A non-onion URL, or a missing Tor SOCKS proxy, raises `TorError`. `socks_port`
    None auto-detects the local SocksPort; passing one checks that a SOCKS5 proxy answers there."""
    host, port, path = _split_onion_url(url)
    if not host:
        raise TorError(f"{url!r} has no host")
    if not _is_onion(host):
        raise TorError(f"{host!r} is not a .onion host; the Tor fetch engine is for hidden services only "
                       f"(use `python -m ctf favicon` / a clearnet client for a normal host)")
    _scope.check_host(host, port, what=f"tor fetch {url!r}", profile=profile, error=OutOfScope)
    if socks_port is None:
        socks_port = detect_socks_port(host=socks_host)
    elif not _is_socks5(socks_host, int(socks_port)):
        raise TorError(f"no Tor SOCKS5 proxy answered on {socks_host}:{socks_port}; start a tor daemon "
                       f"(human step, B-175) or point --socks-port at a running SocksPort")
    socks_port = int(socks_port)
    tls = _tls_connect(host, port, socks_host, socks_port, timeout)
    try:
        der = tls.getpeercert(binary_form=True)
        raw = _http_get(tls, host, path, max_body)
    finally:
        try:
            tls.close()
        except Exception:
            pass
    status_line, code, headers, body = _parse_http_response(raw)
    resp = OnionResponse(url=url, host=host, port=port, status_line=status_line, status_code=code,
                         headers=headers, body=body, cert_der=der, cert=leaf_cert_info(der),
                         socks=f"{socks_host}:{socks_port}")
    if want_favicon:
        _attach_favicon(resp, socks_host, socks_port, timeout, profile, max_body)
    return resp


def _attach_favicon(resp: OnionResponse, socks_host: str, socks_port: int, timeout: float,
                    profile, max_body: int) -> None:
    """Fetch the first reachable declared icon over the same Tor path and record B-089's hashes.
    Only `.onion` icons are fetched (a clearnet icon URL would need a clearnet route); a different
    onion host is scope-checked before it is contacted. Failures are left as a None favicon."""
    from . import favicon as _favicon
    try:
        html = resp.body.decode("utf-8", "replace")
    except Exception:  # pragma: no cover - decode("replace") does not raise
        return
    for icon_url in _favicon.icon_links(html, base_url=resp.url):
        ihost, iport, ipath = _split_onion_url(icon_url)
        if not _is_onion(ihost):
            continue
        if ihost != resp.host:
            try:
                _scope.check_host(ihost, iport, what=f"tor favicon {icon_url!r}", profile=profile,
                                  error=OutOfScope)
            except OutOfScope:
                continue
        try:
            tls = _tls_connect(ihost, iport, socks_host, socks_port, timeout)
            try:
                raw = _http_get(tls, ihost, ipath, max_body)
            finally:
                try:
                    tls.close()
                except Exception:
                    pass
            _, code, _, ibody = _parse_http_response(raw)
        except TorError:
            continue
        if code == 200 and ibody:
            resp.favicon = ibody
            resp.favicon_url = icon_url
            resp.favicon_hashes = _favicon.fingerprint(ibody).to_dict()
            return


# =====================================================================================
#  Evidence files
# =====================================================================================

def _looks_html(resp: OnionResponse) -> bool:
    ctype = (resp.header("Content-Type") or "").lower()
    if "html" in ctype:
        return True
    head = resp.body[:512].lstrip().lower()
    return head.startswith(b"<!doctype html") or head.startswith(b"<html")


def write_evidence(resp: OnionResponse, out_dir) -> list[Path]:
    """Write the capture under `out_dir` and return the files written: `tor-fetch.json` (the summary,
    including the leaf serial and fingerprints), `headers.txt`, the body, the PEM/DER leaf certificate
    and, when present, the favicon and its hashes."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    def _write_bytes(name: str, data: bytes) -> None:
        p = out / name
        p.write_bytes(data)
        written.append(p)

    def _write_text(name: str, text: str) -> None:
        p = out / name
        p.write_text(text, encoding="utf-8")
        written.append(p)

    header_block = resp.status_line + "\n" + "".join(f"{k}: {v}\n" for k, v in resp.headers)
    _write_text("headers.txt", header_block)
    _write_bytes("body.html" if _looks_html(resp) else "body.bin", resp.body)
    if resp.cert_der:
        _write_bytes("leaf-cert.der", resp.cert_der)
    if resp.cert:
        if resp.cert.get("pem"):
            _write_text("leaf-cert.pem", resp.cert["pem"])
        _write_text("leaf-cert.json", json.dumps(
            {k: v for k, v in resp.cert.items() if k != "pem"}, indent=2) + "\n")
    if resp.favicon:
        _write_bytes("favicon.bin", resp.favicon)
        if resp.favicon_hashes:
            _write_text("favicon.json", json.dumps(
                {"source": resp.favicon_url, **resp.favicon_hashes}, indent=2) + "\n")
    summary = {
        "url": resp.url,
        "host": resp.host,
        "port": resp.port,
        "socks": resp.socks,
        "status": resp.status_code,
        "status_line": resp.status_line,
        "headers": [[k, v] for k, v in resp.headers],
        "body_bytes": len(resp.body),
        "certificate": {k: v for k, v in (resp.cert or {}).items() if k != "pem"} or None,
        "favicon": ({"source": resp.favicon_url, **(resp.favicon_hashes or {})}
                    if resp.favicon else None),
    }
    _write_text("tor-fetch.json", json.dumps(summary, indent=2) + "\n")
    return written
