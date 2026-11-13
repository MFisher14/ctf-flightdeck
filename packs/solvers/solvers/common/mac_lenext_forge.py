#!/usr/bin/env python3
"""Hash length-extension forge driver for secret-prefix MACs (B-061).

Secret-prefix MAC length extension -- ``tag = H(secret || message)`` with ``H`` a Merkle--Damgard
hash (MD5/SHA-1/SHA-256, also MD4/SHA-512) -- was re-implemented twice at CSCTF: once for an offline
handout and once for a live cookie/MAC endpoint (csctf 9106 "countersign", 9115 "operation dawn").
This module is the one driver in front of the forge arithmetic that already lives, fail-closed, in the
crypto lane:

* ``solvers/common/modern_crypto.length_extension`` computes the forgery WITHOUT the secret and
  ``length_extension_verified`` proves the premise when the secret is in hand; and
* ``solvers/common/oracle_aead.forge_prefix_mac_length_extension`` is the verifier-gated wrapper that
  confirms the supplied ``(message, tag)`` is accepted, a tampered tag is rejected, and returns a
  forgery only when exactly one secret length in a band is accepted.

What this driver adds, and what was missing, is everything in *front* of those functions:

1. **Fingerprinting** a ``payload<sep>MAC`` token or a ``(message, signature)`` pair: find the MAC,
   read the hash from its digest length (32/40/64/128 hex -> md5/sha1/sha256/sha512), and recover the
   signed message bytes (``fingerprint`` / ``fingerprint_token`` / ``fingerprint_pair``).
2. **Confirming and forging across a key-length band** without ``hashpumpy``: ``forge_with_verifier``
   drives the oracle wrapper over a ``[lo, hi]`` band against a caller verifier; ``forge_offline`` is
   the no-model primary when the handout gives the secret (the premise is proven locally first).
3. **A schema map** (``ForgeSchema``) -- the per-challenge field layout the live token needed, read
   from the challenge's own signing spec (the blocker: a generic driver needs a schema map or a model
   step, not a guess).
4. **A scope-locked live client** (``MacEndpointClient``): sends the forged command to the one
   assigned endpoint through ``ctf.scope`` (the guard shared with the web/chat/pwn clients) and reads
   the authorization code it returns. It never follows a redirect (a 3xx is a rejection) and ignores
   proxy variables, so its one URL is the only host it reaches. The forged token is submitted to the
   *endpoint* here; the recovered flag is submitted to the *scoreboard* through the B-006 submit
   queue (``live --submit <id>`` calls ``ctf.cli.submit_queue.submit_one``), never re-paced here.

The offline handout path is the no-model primary and makes no connection. The live path makes one
bounded request per band candidate plus one to read the flag, and only ever to the scope-approved
host. Challenge-returned text is DATA: it is logged and searched for a flag, never executed. No
challenge binary or challenge-provided code is ever imported or run.
"""
from __future__ import annotations

import argparse
import http.client
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Optional, Sequence

try:                                            # package import (tests, `import solvers.common...`)
    from . import oracle_aead as _oracle
    from ._shadowed import common_module
except ImportError:                             # flat engine sys.path (`ctf run`, `tools/ctfpy`)
    import oracle_aead as _oracle               # type: ignore
    from _shadowed import common_module         # type: ignore

_modern = common_module("modern_crypto")        # solvers/common/modern_crypto.py (toolkits shadows it)


# -- bounds ------------------------------------------------------------------------------------------
MAX_MESSAGE_BYTES = 1 << 20
MAX_TOKEN_CHARS = 1 << 20
MAX_BAND_WIDTH = 512
MAX_BODY = 1 << 20
DEFAULT_TIMEOUT = 15.0

# Secret-prefix MAC hashes keyed by DIGEST BYTE length. md5/sha1/sha256 are the item's confirmed set;
# sha512 is length-extendable too and reads the same way (sha224/sha384 are truncated and are NOT
# listed -- they are not length-extendable, and md4 shares md5's 16-byte length so it is not claimed).
_ALGO_BY_DIGEST_BYTES = {16: "md5", 20: "sha1", 32: "sha256", 64: "sha512"}
# Hashes a caller may NAME (schema / option / --algorithm) on top of the ones read from a digest
# length: md4 is length-extendable and shares md5's 16-byte digest, so it is never inferred, only named.
_NAMEABLE_ALGOS = frozenset(_ALGO_BY_DIGEST_BYTES.values()) | {"md4"}
_HEX_RE = re.compile(r"\A[0-9a-fA-F]+\Z")
# Separators a signed token uses between payload and MAC, most-specific first. The base64/base64url
# and hex payload alphabets contain none of these, so a split on the LAST occurrence is unambiguous.
_TOKEN_SEPARATORS = (".", "|", "~", ":")


class MacForgeError(ValueError):
    """A malformed token, band, or schema -- surfaced loudly, never swallowed into a guess."""


class MacEndpointError(MacForgeError):
    """A live-endpoint request failed (refused, timed out, dropped, or could not be encoded). The
    band verdict is then unknown, so the run fails with this named error instead of reading the
    failure as a rejection."""


# == fingerprinting =================================================================================

@dataclass(frozen=True)
class MacToken:
    """A fingerprinted secret-prefix MAC token: the signed ``message`` bytes, the ``mac`` bytes, the
    hash read from the MAC length, and where the split came from. ``message`` is the bytes that were
    hashed after the secret; a schema may re-encode them before the wire, but the forge works on
    exactly these bytes."""
    algorithm: str
    message: bytes
    mac: bytes
    separator: Optional[str]
    source: str

    @property
    def mac_hex(self) -> str:
        return self.mac.hex()


def algo_for_mac(mac: bytes | str) -> Optional[str]:
    """The Merkle--Damgard hash a MAC came from, read from its digest length, or ``None`` when the
    length is not one a length-extendable hash produces. ``mac`` is hex (str) or raw bytes."""
    if isinstance(mac, str):
        s = mac.strip()
        if not s or not _HEX_RE.match(s) or len(s) % 2:
            return None
        return _ALGO_BY_DIGEST_BYTES.get(len(s) // 2)
    if isinstance(mac, (bytes, bytearray)):
        return _ALGO_BY_DIGEST_BYTES.get(len(mac))
    return None


def _is_hex_mac(segment: str) -> Optional[str]:
    seg = segment.strip()
    if not seg or len(seg) % 2 or not _HEX_RE.match(seg):
        return None
    return _ALGO_BY_DIGEST_BYTES.get(len(seg) // 2)


def fingerprint_token(token: str) -> tuple[MacToken, ...]:
    """Fingerprint a combined ``payload<sep>MAC`` token (a signed cookie, URL parameter, header).

    For each candidate separator, split on its LAST occurrence and keep the split only when the tail
    is a pure-hex MAC of a length-extendable digest length and the head is non-empty. The head bytes
    are taken verbatim (``utf-8``/``surrogateescape``) as the signed message; the schema decides any
    re-encoding. Returns every plausible split (several separators can match); empty when none does.
    """
    if not isinstance(token, str):
        raise MacForgeError("token must be a string")
    if len(token) > MAX_TOKEN_CHARS:
        raise MacForgeError(f"token exceeds {MAX_TOKEN_CHARS} characters")
    out: list[MacToken] = []
    seen: set[tuple[str, bytes]] = set()
    for sep in _TOKEN_SEPARATORS:
        idx = token.rfind(sep)
        if idx <= 0 or idx == len(token) - len(sep):
            continue
        head, tail = token[:idx], token[idx + len(sep):]
        algo = _is_hex_mac(tail)
        if algo is None:
            continue
        message = head.encode("utf-8", "surrogateescape")
        mac = bytes.fromhex(tail.strip())
        key = (algo, mac + b"\x00" + message)
        if key in seen:
            continue
        seen.add(key)
        out.append(MacToken(algorithm=algo, message=message, mac=mac,
                            separator=sep, source=f"token:last{sep!r}"))
    return tuple(out)


def fingerprint_pair(message: bytes | str, signature: bytes | str) -> Optional[MacToken]:
    """Fingerprint a separate ``(message, signature)`` pair (the 9106 form: a query-string message and
    its own hex signature field). The hash is read from the signature length. ``None`` when the
    signature is not a length-extendable digest length."""
    msg = message.encode("utf-8", "surrogateescape") if isinstance(message, str) else bytes(message)
    if len(msg) > MAX_MESSAGE_BYTES:
        raise MacForgeError(f"message exceeds {MAX_MESSAGE_BYTES} bytes")
    algo = algo_for_mac(signature)
    if algo is None:
        return None
    mac = bytes.fromhex(signature.strip()) if isinstance(signature, str) else bytes(signature)
    return MacToken(algorithm=algo, message=msg, mac=mac, separator=None, source="pair")


def fingerprint(*, token: Optional[str] = None, message=None,
                signature=None) -> tuple[MacToken, ...]:
    """Fingerprint a combined ``token`` or a ``(message, signature)`` pair. Exactly one form must be
    given. Returns a tuple of candidates (possibly empty); never raises on a non-MAC input, only on a
    misuse (both/neither form, oversized input)."""
    has_token = token is not None
    has_pair = message is not None and signature is not None
    if has_token == has_pair:
        raise MacForgeError("give exactly one of token= or (message=, signature=)")
    if has_token:
        return fingerprint_token(token)
    mt = fingerprint_pair(message, signature)
    return (mt,) if mt is not None else ()


# == confirm + forge over a key-length band =========================================================

@dataclass(frozen=True)
class ForgeResult:
    """A verifier-accepted forgery: the forged message (orig || glue padding || appended bytes), the
    forged tag, the secret length that was accepted, and the appended bytes."""
    algorithm: str
    forged_message: bytes
    forged_tag: bytes
    secret_len: int
    appended: bytes

    @property
    def forged_tag_hex(self) -> str:
        return self.forged_tag.hex()


def _band_lengths(band: Iterable[int] | tuple[int, int]) -> list[int]:
    """Normalise a band to a sorted list of distinct non-negative ints. A 2-tuple ``(lo, hi)`` is the
    inclusive range ``lo..hi``; any other iterable is taken as an explicit set. Raises on a negative,
    non-integer, inverted, or over-wide band (loud, never silently clamped)."""
    if isinstance(band, tuple) and len(band) == 2 and all(isinstance(x, int) for x in band) \
            and not any(isinstance(x, bool) for x in band):
        lo, hi = band
        if lo < 0 or hi < 0:
            raise MacForgeError("band bounds must be non-negative")
        if hi < lo:
            raise MacForgeError(f"band hi ({hi}) is below lo ({lo})")
        lengths = list(range(lo, hi + 1))
    else:
        lengths = []
        for x in band:
            if isinstance(x, bool) or not isinstance(x, int):
                raise MacForgeError(f"band values must be ints, got {x!r}")
            if x < 0:
                raise MacForgeError("band values must be non-negative")
            lengths.append(x)
        lengths = sorted(set(lengths))
    if not lengths:
        raise MacForgeError("band is empty")
    if len(lengths) > MAX_BAND_WIDTH:
        raise MacForgeError(f"band has {len(lengths)} candidates, over the cap of {MAX_BAND_WIDTH}")
    return lengths


def forge_with_verifier(algorithm: str, message: bytes, original_mac: bytes | str,
                        append: bytes, band: Iterable[int] | tuple[int, int],
                        verify: Callable[[bytes, bytes], bool]) -> Optional[ForgeResult]:
    """Confirm the ``(message, original_mac)`` secret-prefix MAC and forge ``message || glue ||
    append`` across a key-length ``band``, driven by ``verify(message, tag_bytes) -> bool``.

    Delegates to ``oracle_aead.forge_prefix_mac_length_extension``: the original tag must be accepted,
    a tampered tag rejected, and exactly one band length accepted, or ``None`` is returned. No guess is
    emitted. ``append`` is the bytes to append to the signed message (e.g. ``b"&cmd=DISPATCH"``)."""
    if not callable(verify):
        raise MacForgeError("verify must be callable")
    message = bytes(message)
    append = bytes(append)
    if len(message) + len(append) > MAX_MESSAGE_BYTES:
        raise MacForgeError("message + append exceeds the size cap")
    lengths = _band_lengths(band)
    forged = _oracle.forge_prefix_mac_length_extension(
        algorithm, original_mac, message, append, lengths, verify,
    )
    if forged is None:
        return None
    forged_message, forged_tag, secret_len = forged
    return ForgeResult(algorithm=algorithm, forged_message=forged_message, forged_tag=forged_tag,
                       secret_len=secret_len, appended=append)


def secret_prefix_verifier(algorithm: str, secret: bytes) -> Callable[[bytes, bytes], bool]:
    """A local verifier ``(message, tag) -> H(secret || message) == tag`` for the offline handout
    path. The secret never leaves the process; it is used only to prove the premise and to accept the
    forgery before it is emitted."""
    secret = bytes(secret)

    def verify(message: bytes, tag: bytes) -> bool:
        return _modern.md_hash(algorithm, secret + bytes(message)) == bytes(tag)

    return verify


def forge_offline(algorithm: str, message: bytes, original_mac: bytes | str, append: bytes,
                  secret: bytes, band: Iterable[int] | tuple[int, int] | None = None,
                  ) -> Optional[ForgeResult]:
    """No-model primary: forge when the handout gives the ``secret``. The premise
    ``H(secret || message) == original_mac`` is proven locally first (``None`` and no forgery if it
    fails), then the forgery is built and accepted by the same local verifier. Makes no connection.

    ``band`` defaults to the single true length ``len(secret)``; pass a wider band to exercise the
    key-length search offline."""
    secret = bytes(secret)
    if not _modern.length_extension_verified(algorithm, secret, message, original_mac):
        return None
    if band is None:
        band = (len(secret), len(secret))
    return forge_with_verifier(algorithm, message, original_mac, append, band,
                               secret_prefix_verifier(algorithm, secret))


# == schema map (the per-challenge signing/wire layout) =============================================

@dataclass(frozen=True)
class ForgeSchema:
    """The per-challenge layout a live token needs -- read from the challenge's own signing spec, not
    guessed. ``algorithm``/``key_length_band``/``append`` drive the forge; the ``*_field``, ``encoding``
    and ``content_type`` describe how the forged ``(message, tag)`` goes on the wire; ``accept_markers``
    name the response substrings that mean the command was accepted."""
    algorithm: Optional[str] = None
    key_length_band: tuple[int, int] = (1, 64)
    append: bytes = b""
    message_field: str = "message"
    mac_field: str = "signature"
    mac_encoding: str = "hex"              # "hex" | "base64"
    content_type: str = "json"             # "json" | "form"
    method: str = "POST"
    accept_markers: tuple[str, ...] = ("authorization_code", "ACCEPTED")

    @classmethod
    def from_spec(cls, spec: dict) -> "ForgeSchema":
        """Build a schema from a signing-spec dict (the challenge's ``/api/spec`` read by an operator
        or a model step). Tolerant of the field names seen in the evidence."""
        if not isinstance(spec, dict):
            raise MacForgeError("spec must be a JSON object")
        algo = spec.get("algorithm") or spec.get("hash") or spec.get("algo")
        if algo is not None:
            algo = _normalise_algo(algo)
        band = spec.get("key_length_band") or spec.get("key_length_band_bytes") or spec.get("band")
        if band is not None:
            band = _coerce_band_tuple(band)
        else:
            band = (1, 64)
        append = spec.get("append")
        append_b = _as_bytes(append) if append is not None else b""
        marks = spec.get("accept_markers")
        markers = tuple(str(m) for m in marks) if marks else cls.accept_markers
        return cls(
            algorithm=algo,
            key_length_band=band,
            append=append_b,
            message_field=str(spec.get("message_field", cls.message_field)),
            mac_field=str(spec.get("mac_field") or spec.get("signature_field") or cls.mac_field),
            mac_encoding=str(spec.get("mac_encoding", cls.mac_encoding)),
            content_type=str(spec.get("content_type", cls.content_type)),
            method=str(spec.get("method", cls.method)),
            accept_markers=markers,
        )


def _normalise_algo(algo: str) -> str:
    a = str(algo).lower().replace("-", "").replace("_", "")
    if a not in _NAMEABLE_ALGOS:
        raise MacForgeError(f"unsupported hash {algo!r}; this driver forges "
                            f"{', '.join(sorted(_NAMEABLE_ALGOS))}")
    return a


def _coerce_band_tuple(band) -> tuple[int, int]:
    if isinstance(band, (list, tuple)) and len(band) == 2 \
            and all(isinstance(x, int) and not isinstance(x, bool) for x in band):
        lo, hi = int(band[0]), int(band[1])
        if lo < 0 or hi < lo:
            raise MacForgeError(f"bad key-length band {band!r}")
        return (lo, hi)
    raise MacForgeError(f"key-length band must be [lo, hi], got {band!r}")


def _as_bytes(value) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, str):
        return value.encode("utf-8", "surrogateescape")
    raise MacForgeError(f"expected bytes or str, got {type(value).__name__}")


def _encode_mac(tag: bytes, encoding: str) -> str:
    if encoding == "hex":
        return tag.hex()
    if encoding == "base64":
        import base64
        return base64.b64encode(tag).decode("ascii")
    raise MacForgeError(f"unknown mac_encoding {encoding!r}")


# == scope-locked live client =======================================================================

class _NoRedirects(urllib.request.HTTPRedirectHandler):
    """Never follow a 30x. The client is single-target and scope was checked for its one URL only:
    a followed redirect could take the forged command to ANY host, and an off-scope host could then
    confirm the forgery and hand back the "flag". Returning ``None`` makes urllib raise the 3xx as an
    ``HTTPError``, which the transport returns as an ordinary (non-2xx, so rejected) response."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _opener() -> urllib.request.OpenerDirector:
    # ProxyHandler({}) ignores *_proxy environment variables: the one scope-approved URL is the only
    # host contacted, never a proxy in between.
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirects())


def _default_transport(url: str, data: bytes, headers: dict, method: str,
                       timeout: float) -> tuple[int, bytes, dict]:
    """POST through the no-redirect opener. Returns ``(status, body, extra)``; ``extra`` carries
    ``refused_redirect`` (the unfollowed Location) when the endpoint answered with a 3xx."""
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with _opener().open(req, timeout=timeout) as resp:
            return resp.getcode(), resp.read(MAX_BODY), {}
    except urllib.error.HTTPError as e:              # a 3xx/4xx/5xx body is still evidence
        body = (e.read(MAX_BODY) if hasattr(e, "read") else b"") or b""
        extra: dict = {}
        if 300 <= e.code < 400:
            loc = e.headers.get("Location") if e.headers is not None else None
            extra["refused_redirect"] = loc or ""
        return e.code, body, extra


class MacEndpointClient:
    """A single-target, scope-locked client for a live cookie/MAC endpoint.

    Scope is enforced in code before any connection by ``ctf.scope.check_host`` -- the one guard shared
    with the web/chat/pwn clients, read from the current event profile. The client contacts only its
    one URL: a redirect is never followed (the 3xx comes back as a rejection with the refused target
    logged) and proxy environment variables are ignored. Every request and response is logged to
    ``self.transcript``. The endpoint's reply is DATA:
    it is searched for an accept marker and a flag, never executed.

    ``transport`` is injectable only to drive the forge logic in unit tests without a socket; the
    loopback end-to-end test uses the default urllib transport against a 127.0.0.1 server.
    """

    def __init__(self, url: str, schema: ForgeSchema, *, timeout: float = DEFAULT_TIMEOUT,
                 transport: Optional[Callable[..., tuple[int, bytes]]] = None,
                 user_agent: str = "ctf-tools-mac-forge/1"):
        from ctf import scope as _scope
        parts = urllib.parse.urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise MacForgeError(f"{url!r} is not an absolute http(s) URL")
        _scope.check_host(parts.hostname, parts.port, what=repr(url), error=_scope.OutOfScope)
        self.url = url
        self.schema = schema
        self.timeout = float(timeout)
        self.user_agent = user_agent
        self._transport = transport or _default_transport
        self.transcript: list[dict] = []
        self.calls = 0
        # The first error a verifier call hit (see make_verifier). run_live re-raises it.
        self.request_error: Optional[BaseException] = None

    def _build_body(self, message: bytes, tag: bytes) -> tuple[bytes, dict]:
        mac_text = _encode_mac(tag, self.schema.mac_encoding)
        hdrs = {"User-Agent": self.user_agent}
        if self.schema.content_type == "form":
            # urlencode percent-encodes a bytes value byte-for-byte, so the binary glue padding in a
            # forged message round-trips exactly. This is the byte-safe default for a forged token.
            body = urllib.parse.urlencode({self.schema.message_field: message,
                                           self.schema.mac_field: mac_text}).encode("ascii")
            hdrs["Content-Type"] = "application/x-www-form-urlencoded"
        elif self.schema.content_type == "json":
            # A JSON string carries text, not bytes. A message that is not valid UTF-8 (the glue
            # padding's 0x80, the length field) has no faithful JSON form: json.dumps would escape a
            # surrogateescape'd byte as "\udcXX" and the endpoint would get different bytes. So it is
            # refused here, loudly; binary forged messages use content_type="form".
            try:
                msg_text = message.decode("utf-8")
            except UnicodeDecodeError as e:
                raise MacForgeError(
                    f"content_type 'json' cannot carry this message: it is not valid UTF-8 "
                    f"({e.reason} at byte {e.start}); use content_type 'form', which is byte-exact"
                ) from None
            body = json.dumps({self.schema.message_field: msg_text,
                               self.schema.mac_field: mac_text}).encode("utf-8")
            hdrs["Content-Type"] = "application/json"
        else:
            raise MacForgeError(f"unknown content_type {self.schema.content_type!r}")
        return body, hdrs

    def send_command(self, message: bytes, tag: bytes) -> dict:
        """POST one forged ``(message, tag)`` to the endpoint. Returns ``{status, body, json}`` and
        logs the exchange. Opens exactly one connection, to the scope-approved URL."""
        body, hdrs = self._build_body(bytes(message), bytes(tag))
        self.calls += 1
        try:
            got = self._transport(self.url, body, hdrs, self.schema.method, self.timeout)
        except (OSError, http.client.HTTPException) as e:
            # Refused, timed out, reset, a malformed reply: no verdict was read. Logged, then raised
            # under a named error -- never turned into a rejection.
            self.transcript.append({"status": None, "error": f"{type(e).__name__}: {e}",
                                    "message": message.decode("utf-8", "surrogateescape"),
                                    "tag": tag.hex()})
            raise MacEndpointError(f"request to {self.url} failed: {type(e).__name__}: {e}") from e
        status, raw = got[0], got[1]
        extra = dict(got[2]) if len(got) > 2 and got[2] else {}
        text = raw.decode("utf-8", "replace")
        try:
            parsed = json.loads(text)
        except ValueError:
            parsed = None
        entry = {"status": status, "body": text, "json": parsed,
                 "message": message.decode("utf-8", "surrogateescape"), "tag": tag.hex()}
        if "refused_redirect" in extra:                # never followed: a 3xx is a rejection
            entry["refused_redirect"] = extra["refused_redirect"]
        self.transcript.append(entry)
        return entry

    def accepted(self, response: dict) -> bool:
        """Whether a response means the forged command was accepted: a 2xx status AND an accept
        marker present in the body. A marker-less or error response is a rejection."""
        if not 200 <= int(response.get("status", 0)) < 300:
            return False
        body = response.get("body") or ""
        return any(marker in body for marker in self.schema.accept_markers)

    def make_verifier(self) -> Callable[[bytes, bytes], bool]:
        """A ``verify(message, tag) -> bool`` that sends to the endpoint and reads the accept marker.
        One request per call; the forge band bounds the call count.

        The oracle wrapper (``oracle_aead._bool_result``) turns any exception a verifier raises into
        ``False``, which would read a refused connection or a timeout as "this length was rejected".
        So the verifier keeps the first error in ``self.request_error`` and, once one is set, sends
        nothing more (the run is void). ``run_live`` raises it as ``MacEndpointError``; a caller that
        uses this verifier directly must check ``request_error`` after the forge."""
        def verify(message: bytes, tag: bytes) -> bool:
            if self.request_error is not None:
                return False
            try:
                return self.accepted(self.send_command(message, tag))
            except Exception as e:                # kept and re-raised by run_live, not swallowed
                self.request_error = e
                return False
        return verify


@dataclass(frozen=True)
class LiveForge:
    """Outcome of the live forge: the forgery, the flag the endpoint returned (if the shape matched),
    the accepted secret length, and the raw response. ``ok`` is false with a named ``reason`` when the
    band yielded no unique acceptance."""
    ok: bool
    reason: str = ""
    forge: Optional[ForgeResult] = None
    flag: Optional[str] = None
    response: Optional[dict] = None


def run_live(client: MacEndpointClient, token: MacToken, schema: ForgeSchema,
             flag_shape=None) -> LiveForge:
    """Forge against the live endpoint and read back the authorization code.

    Confirms + forges across ``schema.key_length_band`` using the endpoint as the verifier, then sends
    the forged command once more to capture the flag from the response. The algorithm is the one the
    token fingerprinted; ``schema.algorithm`` overrides it only when set. The recovered flag is handed
    back for submission to the scoreboard through the B-006 submit queue -- this driver never submits
    the flag itself."""
    algorithm = schema.algorithm or token.algorithm
    if not schema.append:
        return LiveForge(ok=False, reason="schema has no append bytes; nothing to forge")
    if client.schema.content_type == "json":
        _check_json_wire(algorithm, token.message, schema.append, schema.key_length_band)
    client.request_error = None
    forge = forge_with_verifier(algorithm, token.message, token.mac, schema.append,
                                schema.key_length_band, client.make_verifier())
    err = client.request_error
    if err is not None:
        # A failed request leaves its band length unjudged, so neither "none accepted" nor "exactly
        # one accepted" is known. Fail with the cause, never with a guessed verdict.
        raise MacEndpointError(f"live forge void after {client.calls} request(s): {err}") from err
    if forge is None:
        return LiveForge(ok=False, reason="no unique secret length in the band was accepted; widen "
                                          "the band or re-read the signing spec")
    response = client.send_command(forge.forged_message, forge.forged_tag)
    flag = None
    if flag_shape is not None:
        found = flag_shape.find_flags(response.get("body") or "")
        flag = found[0] if found else None
    return LiveForge(ok=True, forge=forge, flag=flag, response=response)


def _check_json_wire(algorithm: str, message: bytes, append: bytes, band) -> None:
    """Refuse, before any request, a JSON wire that cannot carry the messages the band would send:
    the original message and every ``message || glue || append`` candidate must be valid UTF-8 (the
    glue starts with 0x80, so in practice a forged message never is). Raises ``MacForgeError``."""
    message, append = bytes(message), bytes(append)
    candidates = [("the signed message", message)]
    for n in _band_lengths(band):
        glue = _modern.md_padding(n + len(message), algorithm)
        candidates.append((f"the forged message for secret length {n}", message + glue + append))
    for what, data in candidates:
        try:
            data.decode("utf-8")
        except UnicodeDecodeError as e:
            raise MacForgeError(
                f"content_type 'json' cannot carry {what}: it is not valid UTF-8 ({e.reason} at byte "
                f"{e.start}; the MD glue padding is binary); use content_type 'form', which is "
                f"byte-exact") from None


# == contract entry =================================================================================

_HANDOUT_NAMES = ("spec.json", "sample.json", "handout.json", "challenge.json", "mac.json")


def _read_handout(challenge_dir: Path) -> Optional[tuple[str, dict]]:
    """Find one JSON handout describing the MAC challenge. Reads only JSON files, bounded; returns the
    first that carries a message/tag or a signing spec. Handout text is data."""
    candidates: list[Path] = []
    for name in _HANDOUT_NAMES:
        p = challenge_dir / name
        if p.is_file():
            candidates.append(p)
    for p in sorted(challenge_dir.glob("*.json")):
        if p not in candidates and p.is_file() and p.stat().st_size <= MAX_MESSAGE_BYTES:
            candidates.append(p)
    for p in candidates:
        try:
            obj = json.loads(p.read_text(encoding="utf-8"))
        except (ValueError, OSError, UnicodeDecodeError):
            continue
        if isinstance(obj, dict) and _looks_like_mac_handout(obj):
            return p.name, obj
    return None


def _looks_like_mac_handout(obj: dict) -> bool:
    keys = {k.lower() for k in obj}
    has_sig = bool(keys & {"signature", "mac", "tag", "sig"})
    has_msg = bool(keys & {"message", "msg", "command", "record", "payload", "token"})
    has_spec = bool(keys & {"algorithm", "hash", "algo", "key_length_band",
                            "key_length_band_bytes", "band"})
    # A payload<sep>MAC token is a complete MAC by itself (the headline form), so one that fingerprints
    # is enough on its own. A 'token' value that does not fingerprint is no signal by itself.
    if _token_value_fingerprints(obj):
        return True
    return (has_sig and has_msg) or (has_msg and has_spec) or (has_sig and has_spec)


def _token_value_fingerprints(obj: dict) -> bool:
    for k, v in obj.items():
        if isinstance(k, str) and k.lower() == "token" and isinstance(v, str):
            try:
                if fingerprint_token(v):
                    return True
            except MacForgeError:               # oversized token: not a readable handout
                return False
    return False


def _handout_message_mac(obj: dict) -> Optional[MacToken]:
    token = obj.get("token")
    if isinstance(token, str):
        got = fingerprint_token(token)
        if got:
            return got[0]
    msg = obj.get("message") or obj.get("msg") or obj.get("command") or obj.get("record") \
        or obj.get("payload")
    sig = obj.get("signature") or obj.get("mac") or obj.get("tag") or obj.get("sig")
    if msg is not None and sig is not None:
        return fingerprint_pair(msg, sig)
    return None


def _opt_bytes(value) -> Optional[bytes]:
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    s = str(value)
    if s.startswith("hex:"):
        try:
            return bytes.fromhex(s[4:])
        except ValueError as e:
            raise MacForgeError(f"bad hex value {s!r}: {e}") from e
    return s.encode("utf-8", "surrogateescape")


def solve(challenge_dir, profile, **opts):
    """Contract entry (offline, no network): read a MAC handout and forge the secret-prefix MAC.

    Options: ``append`` (bytes to append; ``hex:..`` for raw), ``secret`` (``hex:..`` or text; the
    no-model primary when the handout gives it), ``algorithm``, ``band`` (``"lo-hi"``). The handout is
    a JSON file carrying a ``token`` or a ``(message, signature)`` and, optionally, a signing spec.

    With the secret in hand the forgery is built and verified offline and emitted as a candidate (plus
    the handout's ``flag_on_accept`` as a candidate flag when present). Without it the live endpoint is
    required: the engine reports ``unsure`` and names the live driver and the schema the operator must
    supply -- it never fabricates a flag or silently falls back.
    """
    from ctf.result import Cost, Evidence, SolverResult

    challenge_dir = Path(challenge_dir)
    engine_id = "common.mac_lenext_forge"

    found = _read_handout(challenge_dir)
    if found is None:
        return SolverResult(status="none", engine=engine_id,
                            notes="no JSON handout with a MAC token or (message, signature) found")
    name, obj = found
    token = _handout_message_mac(obj)
    if token is None:
        return SolverResult(status="none", engine=engine_id,
                            notes=f"{name}: no readable MAC token or (message, signature) -- the "
                                  f"signature is not an md5/sha1/sha256/sha512 digest length")

    try:
        schema = ForgeSchema.from_spec(obj)
    except MacForgeError as e:
        return SolverResult(status="blocked", engine=engine_id,
                            notes=f"{name}: {e}")
    algorithm = opts.get("algorithm") or schema.algorithm or token.algorithm
    try:
        algorithm = _normalise_algo(algorithm)
    except MacForgeError as e:
        return SolverResult(status="blocked", engine=engine_id, notes=str(e))

    try:
        append = _opt_bytes(opts.get("append"))
        secret = _opt_bytes(opts.get("secret"))
        if secret is None and obj.get("secret") is not None:
            secret = _opt_bytes(obj.get("secret"))
    except MacForgeError as e:
        return SolverResult(status="blocked", engine=engine_id, notes=f"{name}: {e}")
    if append is None:
        append = schema.append
    if not append:
        return SolverResult(status="blocked", engine=engine_id,
                            notes=f"{name}: no append/target command given; pass append=... or set "
                                  f"it in the spec (the forge needs the bytes to append)")

    band: Iterable[int] | tuple[int, int] = schema.key_length_band
    if opts.get("band"):
        m = re.fullmatch(r"\s*(\d+)\s*-\s*(\d+)\s*", str(opts["band"]))
        if not m:
            return SolverResult(status="blocked", engine=engine_id,
                                notes=f"band option {opts['band']!r} must be 'lo-hi'")
        band = (int(m.group(1)), int(m.group(2)))

    if secret is not None:
        try:
            forge = forge_offline(algorithm, token.message, token.mac, append, secret, band=band)
        except MacForgeError as e:
            return SolverResult(status="blocked", engine=engine_id, notes=f"{name}: {e}")
        if forge is None:
            return SolverResult(status="none", engine=engine_id,
                                notes=f"{name}: the supplied secret does not produce the given MAC "
                                      f"(H(secret || message) != tag); wrong secret or wrong hash")
        ev = [Evidence("match",
                       f"forged {algorithm} secret-prefix MAC offline (secret_len={forge.secret_len}): "
                       f"appended {append!r}; forged tag {forge.forged_tag_hex}", path=name)]
        flag_on_accept = obj.get("flag_on_accept") or obj.get("flag")
        flags: tuple[str, ...] = ()
        status = "unsure"
        flag_note = ""
        if isinstance(flag_on_accept, str) and flag_on_accept:
            from ctf import event as _event, flagfmt
            try:
                shape = flagfmt.for_profile(profile) if profile is not None else flagfmt.current()
                is_flag = shape.is_flag(flag_on_accept)
            except (LookupError, ValueError, re.error, _event.EventError) as e:
                is_flag = False
                flag_note = (f" The handout's flag_on_accept was NOT emitted: the event flag format "
                             f"could not be checked ({type(e).__name__}: {e}).")
            else:
                if is_flag:
                    flags = (flag_on_accept,)
                    status = "candidate"
                else:
                    flag_note = (" The handout's flag_on_accept does not match this event's flag "
                                 "format, so it is not emitted as a candidate.")
        notes = (f"Forged message: {forge.forged_message.hex()} (hex). Forged tag: "
                 f"{forge.forged_tag_hex}. Send (message, tag) to the live endpoint; submit the "
                 f"returned authorization code through `ctf submit` (B-006).{flag_note}")
        return SolverResult(status=status, flags=flags, evidence=tuple(ev),
                            engine=engine_id, notes=notes, cost=Cost())

    return SolverResult(
        status="unsure", engine=engine_id,
        notes=(f"{name}: fingerprinted a {algorithm} secret-prefix MAC "
               f"(message {len(token.message)} B, tag {token.mac_hex}). No secret in the handout, so "
               f"the forgery must be confirmed against the live endpoint: run "
               f"`solvers/common/mac_lenext_forge.py live --url <assigned URL> --schema <spec.json> "
               f"--message .. --signature .. [--submit <challenge id>]` (or MacEndpointClient + "
               f"run_live()) with the signing spec's schema (algorithm, key-length band, append "
               f"command, wire fields). --submit hands the recovered flag to the B-006 submit queue. "
               f"The live schema is operator/model input, not guessed here."))


# == CLI ============================================================================================
# `fingerprint` and `forge` are offline and make no request. `live` contacts exactly one URL, the one
# the operator passes, after ctf.scope admits it; `--submit <id>` hands a recovered flag to the B-006
# submit queue (ctf.cli.submit_queue.submit_one), which owns pacing, dedupe and the event's rules.

LIVE_REFUSED_EXIT = 4          # matches `ctf submit`: refused before anything was sent


def _load_schema(path: str) -> ForgeSchema:
    try:
        spec = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise MacForgeError(f"cannot read schema {path!r}: {e}") from e
    return ForgeSchema.from_spec(spec)


def _live_token(args) -> MacToken:
    if args.token is not None:
        if args.message is not None or args.signature is not None:
            raise MacForgeError("give --token or (--message and --signature), not both")
        toks = fingerprint_token(args.token)
        if not toks:
            raise MacForgeError("--token is not a payload<sep>MAC token of a length-extendable digest")
        if len(toks) > 1:
            raise MacForgeError(f"--token splits {len(toks)} ways ({', '.join(t.source for t in toks)}); "
                                f"pass --message and --signature instead")
        return toks[0]
    if args.message is None or args.signature is None:
        raise MacForgeError("give --token or both --message and --signature")
    mt = fingerprint_pair(_opt_bytes(args.message), args.signature)
    if mt is None:
        raise MacForgeError("--signature is not an md5/sha1/sha256/sha512 digest length")
    return mt


def _main_live(args) -> int:
    from ctf import event as _event, flagfmt, scope as _scope
    try:
        schema = _load_schema(args.schema)
        token = _live_token(args)
        profile = _event.load(args.event) if args.event else _event.current()
        shape = flagfmt.for_profile(profile)
    except (MacForgeError, _event.EventError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    if args.submit is not None:
        # submit_one submits for the CURRENT event (ctf.event.current()). Checking the flag shape
        # against --event X and then submitting to another event's platform is refused here, before
        # the endpoint is contacted.
        try:
            current = _event.current()
        except _event.EventError as e:
            print(f"refused: --submit needs a current event (the submit queue posts to it): {e}",
                  file=sys.stderr)
            return LIVE_REFUSED_EXIT
        if current.slug != profile.slug:
            print(f"refused: --event {profile.slug} differs from the current event {current.slug}; "
                  f"the submit queue posts to the current event. Set CTF_EVENT={profile.slug} or "
                  f"drop --event.", file=sys.stderr)
            return LIVE_REFUSED_EXIT
    if not schema.append:
        print("error: the schema has no 'append' command; nothing to forge", file=sys.stderr)
        return 2
    try:
        client = MacEndpointClient(args.url, schema, timeout=args.timeout)
    except _scope.OutOfScope as e:
        print(f"refused: {e}", file=sys.stderr)
        return LIVE_REFUSED_EXIT
    except MacForgeError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    try:
        result = run_live(client, token, schema, flag_shape=shape)
    except (OSError, MacForgeError) as e:      # connection refused / timeout / unencodable message
        print(f"error: live endpoint {args.url}: {e}", file=sys.stderr)
        return 2
    out = {"ok": result.ok, "reason": result.reason, "requests": client.calls,
           "flag": result.flag}
    if result.forge is not None:
        out.update(algorithm=result.forge.algorithm, secret_len=result.forge.secret_len,
                   forged_message_hex=result.forge.forged_message.hex(),
                   forged_tag=result.forge.forged_tag_hex)
    print(json.dumps(out), flush=True)
    if not result.ok:
        return 1
    if result.flag is None:
        print("forged command accepted but no flag in this event's format was in the response",
              file=sys.stderr)
        return 1
    if args.submit is None:
        return 0
    from ctf.cli import submit_queue
    from ctf.platform import NotAllowed
    try:
        return submit_queue.submit_one(
            str(args.submit), result.flag,
            note=f"B-061 mac_lenext_forge live forge (secret_len={result.forge.secret_len})",
            call="mac_lenext_forge live --submit", source="live endpoint response")
    except NotAllowed as e:
        print(f"refused: {e}", file=sys.stderr)
        return LIVE_REFUSED_EXIT


def _main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Hash length-extension forge driver for secret-prefix MACs (B-061).")
    sub = parser.add_subparsers(dest="cmd", required=True)

    lv = sub.add_parser("live", help="forge against ONE scope-approved live endpoint (schema JSON); "
                                     "--submit hands the flag to the B-006 submit queue")
    lv.add_argument("--url", required=True, help="the assigned endpoint URL (scope-checked)")
    lv.add_argument("--schema", required=True,
                    help="signing-spec JSON (algorithm, key_length_band, append, wire fields)")
    lv.add_argument("--token")
    lv.add_argument("--message", help="signed message (hex:.. or text)")
    lv.add_argument("--signature", help="its MAC, hex")
    lv.add_argument("--event", help="event slug for the flag format (default: the current event)")
    lv.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    lv.add_argument("--submit", metavar="CHALLENGE_ID",
                    help="submit the recovered flag through the B-006 queue (ctf submit)")

    fp = sub.add_parser("fingerprint", help="read the hash + split of a token or (message, signature)")
    fp.add_argument("--token")
    fp.add_argument("--message")
    fp.add_argument("--signature")

    fo = sub.add_parser("forge", help="offline forge with a known secret (hex:.. or text)")
    fo.add_argument("--message", required=True)
    fo.add_argument("--signature", required=True, help="original MAC, hex")
    fo.add_argument("--append", required=True, help="bytes to append (hex:.. or text)")
    fo.add_argument("--secret", required=True, help="the key (hex:.. or text)")
    fo.add_argument("--algorithm",
                    help="md4/md5/sha1/sha256/sha512 (default: read from the MAC length)")

    args = parser.parse_args(list(argv))

    if args.cmd == "live":
        return _main_live(args)

    if args.cmd == "fingerprint":
        try:
            toks = fingerprint(token=args.token, message=args.message, signature=args.signature) \
                if args.token else fingerprint(message=args.message, signature=args.signature)
        except MacForgeError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        if not toks:
            print("no secret-prefix MAC token recognised", flush=True)
            return 1
        for t in toks:
            print(json.dumps({"algorithm": t.algorithm, "message_bytes": len(t.message),
                              "mac": t.mac_hex, "separator": t.separator, "source": t.source}),
                  flush=True)
        return 0

    algorithm = args.algorithm or algo_for_mac(args.signature)
    if algorithm is None:
        print("error: could not read the hash from the MAC length; pass --algorithm", file=sys.stderr)
        return 2
    try:
        message = _opt_bytes(args.message)
        append = _opt_bytes(args.append)
        secret = _opt_bytes(args.secret)
        algorithm = _normalise_algo(algorithm)
        forge = forge_offline(algorithm, message, args.signature, append, secret)
    except MacForgeError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    if forge is None:
        print("the secret does not produce the given MAC (wrong key or wrong hash)", flush=True)
        return 1
    print(json.dumps({"algorithm": forge.algorithm, "secret_len": forge.secret_len,
                      "forged_message_hex": forge.forged_message.hex(),
                      "forged_tag": forge.forged_tag_hex}), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
