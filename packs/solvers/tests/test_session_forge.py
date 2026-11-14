"""session_forge: forge framework session cookies from a leaked secret, verified against the real
signing/encryption scheme (and round-tripped through itsdangerous for Flask when available)."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import struct

import pytest

import session_forge as sf


# ---------------------------------------------------------------------------- Flask
def _itsdangerous_loads(cookie, secret):
    its = pytest.importorskip("itsdangerous")
    s = its.URLSafeTimedSerializer(
        secret, salt="cookie-session",
        signer_kwargs={"key_derivation": "hmac", "digest_method": hashlib.sha1},
    )
    return s.loads(cookie)


def test_flask_cookie_roundtrips_through_itsdangerous():
    secret = "s3cr3t-flask-key"
    session = {"user": "admin", "is_admin": True, "n": 7}
    cookie = sf.forge_flask(secret, session)
    assert cookie.count(".") >= 2
    # gold standard: a real itsdangerous serializer (same salt/signer) must accept and decode it.
    loaded = _itsdangerous_loads(cookie, secret)
    assert loaded == session


def test_flask_signature_matches_derived_hmac_manually():
    secret = b"another-key"
    cookie = sf.forge_flask(secret, {"a": 1})
    value, ts, sig = cookie.rsplit(".", 2)
    derived = hmac.new(secret, b"cookie-session", hashlib.sha1).digest()
    want = base64.urlsafe_b64encode(
        hmac.new(derived, f"{value}.{ts}".encode(), hashlib.sha1).digest()).rstrip(b"=").decode()
    assert sig == want


# ---------------------------------------------------------------------------- Django
def test_django_cookie_matches_core_signing_scheme():
    secret = "django-secret-key"
    salt = "django.contrib.sessions.backends.signed_cookies"
    session = {"_auth_user_id": "1", "admin": True}
    value = sf.forge_django(secret, session)
    b64, ts, sig = value.rsplit(":", 2)
    # re-derive the signer key exactly as django.core.signing.salted_hmac (sha256) does.
    derived = hashlib.sha256((salt + "signer").encode() + secret.encode()).digest()
    want = base64.urlsafe_b64encode(
        hmac.new(derived, f"{b64}:{ts}".encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
    assert sig == want
    # the payload must decode back to the session (handle the optional zlib '.' prefix).
    body = b64
    compressed = body.startswith(".")
    if compressed:
        body = body[1:]
    raw = base64.urlsafe_b64decode(body + "=" * ((-len(body)) % 4))
    import zlib
    if compressed:
        raw = zlib.decompress(raw)
    assert json.loads(raw) == session


# ---------------------------------------------------------------------------- Express cookie-session
def test_express_cookie_session_value_and_sig():
    secret = "express-keygrip-key"
    session = {"passport": {"user": 1}, "admin": True}
    pair = sf.forge_express_cookie_session(secret, session, name="session")
    value, sig = pair["session"], pair["session.sig"]
    # value decodes back to the JSON session
    raw = base64.urlsafe_b64decode(value + "=" * ((-len(value)) % 4))
    assert json.loads(raw) == session
    # sig = b64url(HMAC-SHA256("session=<value>", key)) no padding
    want = base64.urlsafe_b64encode(
        hmac.new(secret.encode(), f"session={value}".encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
    assert sig == want


# ---------------------------------------------------------------------------- express-session (connect)
def test_connect_signed_sid():
    secret = "connect-session-secret"
    sid = "abc123sessionid"
    cookie = sf.forge_express_connect(secret, sid)
    assert cookie.startswith(f"s:{sid}.")
    sig = cookie.split(".", 1)[1]
    want = base64.b64encode(hmac.new(secret.encode(), sid.encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
    assert sig == want


# ---------------------------------------------------------------------------- Laravel
def test_laravel_envelope_decrypts_and_mac_verifies():
    key = base64.b64encode(bytes(range(32))).decode()
    app_key = "base64:" + key
    cookie = sf.forge_laravel(app_key, "forged-laravel-value")
    env = json.loads(base64.b64decode(cookie))
    assert set(env) >= {"iv", "value", "mac"}
    key_bytes = base64.b64decode(key)
    # mac = hex(HMAC(key, iv_b64 + value_b64, sha256))
    want_mac = hmac.new(key_bytes, (env["iv"] + env["value"]).encode(), hashlib.sha256).hexdigest()
    assert env["mac"] == want_mac
    # AES-256-CBC decrypt the value and strip PKCS7 padding -> plaintext
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    iv = base64.b64decode(env["iv"])
    ct = base64.b64decode(env["value"])
    dec = Cipher(algorithms.AES(key_bytes), modes.CBC(iv)).decryptor()
    padded = dec.update(ct) + dec.finalize()
    plain = padded[:-padded[-1]]
    assert plain == b"forged-laravel-value"


def test_laravel_rejects_wrong_key_length():
    with pytest.raises(sf.ForgeError):
        sf.forge_laravel("base64:" + base64.b64encode(b"short").decode(), "x")


# ---------------------------------------------------------------------------- fail-closed
@pytest.mark.parametrize("call", [
    lambda: sf.forge_flask("k", ["not", "a", "dict"]),
    lambda: sf.forge_django("k", "nope"),
    lambda: sf.forge_express_cookie_session("k", {}, name="bad=name"),
    lambda: sf.forge_express_connect("k", ""),
    lambda: sf.forge("bogus-framework", "k", {}),
    lambda: sf.forge("connect", "k", {"not": "a string sid"}),
])
def test_bad_inputs_fail_closed(call):
    with pytest.raises(sf.ForgeError):
        call()


# ---------------------------------------------------------------------------- dispatcher + CLI
def test_dispatcher_matches_direct_calls():
    # connect is deterministic (no timestamp) so the dispatcher and direct call must be identical.
    assert sf.forge("connect", "k", "sid-1") == sf.forge_express_connect("k", "sid-1")
    # express is also deterministic (no timestamp).
    assert sf.forge("express", "k", {"a": 1}) == sf.forge_express_cookie_session("k", {"a": 1})


def test_cli_help_and_forge_and_error(capsys):
    assert sf.main(["--help"]) == 0  # --help exits cleanly
    capsys.readouterr()  # clear the help text before checking the JSON output
    rc = sf.main(["connect", "secret", "mysid", "--json"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["framework"] == "connect" and out["cookie"].startswith("s:mysid.")
    # bad laravel key -> guarded error, no traceback
    rc2 = sf.main(["laravel", "base64:" + base64.b64encode(b"short").decode(), "x"])
    assert rc2 == 1
