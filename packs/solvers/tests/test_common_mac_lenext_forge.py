"""B-061: Hash length-extension forge driver for secret-prefix MACs.

Covers the three new layers the driver adds in front of the carried forge arithmetic:
  * fingerprinting a payload.MAC token / (message, signature) pair and reading the hash from the MAC;
  * confirming + forging across a key-length band (offline with a known secret, and verifier-gated);
  * the scope-locked live client, driven end to end against a loopback secret-prefix MAC endpoint on
    127.0.0.1 that mimics csctf 9106 "countersign" (SHA-256 H(key||msg), '&'/'=' parser, last value
    wins, DISPATCH returns the authorization code).

No challenge binary is run: the endpoint is a synthetic server built in-test with a freshly generated
secret. The suite pins a test scope profile (tests/conftest.py) that admits 127.0.0.1, so the real
ctf.scope + urllib path is exercised.
"""
from __future__ import annotations

import datetime
import hashlib
import http.client
import json
import re
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from ctf import event, flagfmt, scope
from solvers.common import mac_lenext_forge as mlf

CSCTF = event.load("csctf")
SYNTH_FLAG = "CSCTF{synthetic_lenext_ok}"


# ----------------------------------------------------------------- fingerprinting / algo reading

def test_algo_for_mac_reads_hash_from_digest_length():
    assert mlf.algo_for_mac("a" * 32) == "md5"
    assert mlf.algo_for_mac("a" * 40) == "sha1"
    assert mlf.algo_for_mac("a" * 64) == "sha256"
    assert mlf.algo_for_mac("a" * 128) == "sha512"
    assert mlf.algo_for_mac(b"\x00" * 32) == "sha256"
    # A length no length-extendable hash produces, and non-hex, are not claimed.
    assert mlf.algo_for_mac("a" * 48) is None          # sha384 is truncated: not extendable
    assert mlf.algo_for_mac("zz" * 20) is None
    assert mlf.algo_for_mac("a" * 63) is None           # odd length


def test_fingerprint_token_splits_payload_and_mac():
    payload = "user=guest&role=user"
    mac = hashlib.sha1(payload.encode()).hexdigest()    # content irrelevant; length drives the read
    toks = mlf.fingerprint_token(f"{payload}.{mac}")
    assert len(toks) == 1
    t = toks[0]
    assert t.algorithm == "sha1"
    assert t.message == payload.encode()
    assert t.mac_hex == mac
    assert t.separator == "."


def test_fingerprint_token_rejects_non_mac_tail():
    # A trailing segment that is not a length-extendable digest length yields nothing (no guess).
    assert mlf.fingerprint_token("a.b.c") == ()
    assert mlf.fingerprint_token("payload." + "a" * 10) == ()
    assert mlf.fingerprint_token("nomac") == ()


def test_fingerprint_pair_and_dispatcher_misuse():
    msg = "station=UNIT-01&cmd=STATUS"
    sig = hashlib.sha256(msg.encode()).hexdigest()
    mt = mlf.fingerprint_pair(msg, sig)
    assert mt is not None and mt.algorithm == "sha256" and mt.message == msg.encode()
    # Dispatcher requires exactly one form.
    with pytest.raises(mlf.MacForgeError):
        mlf.fingerprint(token="x", message="y", signature="z")
    with pytest.raises(mlf.MacForgeError):
        mlf.fingerprint()
    assert mlf.fingerprint(message=msg, signature=sig)[0].algorithm == "sha256"


# ----------------------------------------------------------------- band normalisation

def test_band_tuple_is_inclusive_range_and_set_is_explicit():
    assert mlf._band_lengths((8, 11)) == [8, 9, 10, 11]
    assert mlf._band_lengths([4, 4, 2]) == [2, 4]


@pytest.mark.parametrize("band", [(5, 3), (-1, 4), [-2], [1.5], [True]])
def test_band_rejects_bad_input(band):
    with pytest.raises(mlf.MacForgeError):
        mlf._band_lengths(band)


def test_band_width_cap():
    with pytest.raises(mlf.MacForgeError):
        mlf._band_lengths((0, mlf.MAX_BAND_WIDTH + 5))


# ----------------------------------------------------------------- offline forge (no-model primary)

def _oracle_for(secret: bytes, algo="sha256"):
    def accept(message: bytes, tag: bytes) -> bool:
        return hashlib.new(algo, secret + bytes(message)).digest() == bytes(tag)
    return accept


def test_forge_offline_appends_and_verifies():
    secret = b"supersecretkey!!"          # 16 bytes
    message = b"station=A&cmd=STATUS"
    mac = hashlib.sha256(secret + message).hexdigest()
    append = b"&cmd=DISPATCH"
    forge = mlf.forge_offline("sha256", message, mac, append, secret, band=(8, 32))
    assert forge is not None
    assert forge.secret_len == len(secret)
    # The forged message is orig || glue || append, and its tag is the real MAC of it.
    assert forge.forged_message.startswith(message)
    assert forge.forged_message.endswith(append)
    assert hashlib.sha256(secret + forge.forged_message).hexdigest() == forge.forged_tag_hex


def test_forge_offline_rejects_wrong_secret():
    secret = b"the-real-key-xyz"
    message = b"id=7"
    mac = hashlib.sha256(secret + message).hexdigest()
    # Premise H(secret||message)==mac fails for a wrong key: no forgery, no guess.
    assert mlf.forge_offline("sha256", message, mac, b"&admin=1", b"wrong-key") is None


def test_forge_offline_rejects_tampered_mac():
    secret = b"abcdefgh"
    message = b"m=1"
    bad = hashlib.sha256(b"nope" + message).hexdigest()
    assert mlf.forge_offline("sha256", message, bad, b"&x=1", secret) is None


def test_forge_with_verifier_needs_true_length_in_band():
    secret = b"0123456789"               # length 10
    message = b"a=1&b=2"
    mac = hashlib.sha256(secret + message).hexdigest()
    verify = _oracle_for(secret)
    # A band that misses the true length cannot forge.
    assert mlf.forge_with_verifier("sha256", message, mac, b"&c=3", (11, 20), verify) is None
    got = mlf.forge_with_verifier("sha256", message, mac, b"&c=3", (5, 15), verify)
    assert got is not None and got.secret_len == 10


def test_forge_with_verifier_rejects_a_non_mac_verifier():
    # A verifier that accepts everything (not a secret-prefix MAC) must not yield a forgery, because
    # the tampered-tag negative control also passes.
    message, mac = b"x=1", hashlib.sha256(b"k" + b"x=1").hexdigest()
    assert mlf.forge_with_verifier("sha256", message, mac, b"&y=2", (1, 8),
                                   lambda m, t: True) is None


# ----------------------------------------------------------------- live endpoint (loopback fake)

class _MacConsole:
    """A synthetic secret-prefix MAC endpoint (csctf 9106 shape) on 127.0.0.1.

    POST /api/command, form-encoded {message, signature}. The message is parsed '&'-then-'=', keys
    `^[A-Za-z][A-Za-z0-9_]*$`, last value wins. A valid SHA-256 H(secret||message) tag is 'accepted';
    an accepted DISPATCH returns the authorization code (the flag). Everything else is 401/invalid.
    """

    KEY_RE = re.compile(rb"\A[A-Za-z][A-Za-z0-9_]*\Z")

    def __init__(self, secret: bytes, flag: str):
        self.secret = secret
        self.flag = flag
        self.hits = 0
        console = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                console.hits += 1
                n = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(n)
                fields = {}
                for pair in raw.split(b"&"):
                    if b"=" not in pair:
                        continue
                    k, v = pair.split(b"=", 1)
                    fields[urllib.parse.unquote_to_bytes(k)] = urllib.parse.unquote_to_bytes(v)
                message = fields.get(b"message", b"")
                sig = fields.get(b"signature", b"").decode("ascii", "replace")
                good = hashlib.sha256(console.secret + message).hexdigest() == sig.lower()
                if not good:
                    return self._json(401, {"accepted": False, "error": "bad signature"})
                cmd = console._command(message)
                if cmd == b"DISPATCH":
                    return self._json(200, {"accepted": True, "status": "DISPATCH_ACCEPTED",
                                            "authorization_code": console.flag})
                return self._json(200, {"accepted": True, "status": "OK", "command": cmd.decode()})

            def _json(self, code, obj):
                body = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    @classmethod
    def _command(cls, message: bytes) -> bytes:
        cmd = b""
        for tok in message.split(b"&"):
            if b"=" not in tok:
                continue
            k, v = tok.split(b"=", 1)
            if cls.KEY_RE.match(k) and k == b"cmd":
                cmd = v                     # last value wins
        return cmd

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.httpd.server_port}/api/command"

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)


@pytest.fixture
def console():
    # Synthetic values throughout: a made-up flag, and a 25-byte key so the band search has to walk
    # well into the band before it finds the one accepted length.
    c = _MacConsole(secret=b"x" * 25, flag=SYNTH_FLAG)
    try:
        yield c
    finally:
        c.close()


def _status_token(secret: bytes) -> mlf.MacToken:
    message = b"station=UNIT-01&cmd=STATUS&ts=1700000000&nonce=00c0ffee"
    sig = hashlib.sha256(secret + message).hexdigest()
    return mlf.fingerprint_pair(message, sig)


def test_live_forge_recovers_the_authorization_code(console):
    token = _status_token(console.secret)
    schema = mlf.ForgeSchema(algorithm="sha256", key_length_band=(8, 32),
                             append=b"&cmd=DISPATCH", content_type="form",
                             accept_markers=('accepted": true',))
    client = mlf.MacEndpointClient(console.url, schema)
    shape = flagfmt.for_profile(CSCTF)
    result = mlf.run_live(client, token, schema, flag_shape=shape)
    assert result.ok, result.reason
    assert result.forge.secret_len == 25
    assert result.flag == console.flag
    # Only the one true length was accepted across the whole band; the client really spoke to the net.
    assert client.calls >= (32 - 8 + 1)


def test_live_verifier_rejects_a_tampered_original_mac(console):
    token = _status_token(console.secret)
    # Flip the real tag: the endpoint rejects it, so the confirm gate refuses to forge (no guess).
    bad = mlf.MacToken(algorithm="sha256", message=token.message,
                       mac=bytes([token.mac[0] ^ 1]) + token.mac[1:], separator=None, source="pair")
    schema = mlf.ForgeSchema(algorithm="sha256", key_length_band=(8, 32), append=b"&cmd=DISPATCH",
                             content_type="form", accept_markers=('accepted": true',))
    client = mlf.MacEndpointClient(console.url, schema)
    result = mlf.run_live(client, bad, schema, flag_shape=flagfmt.for_profile(CSCTF))
    assert not result.ok and "band" in result.reason


def test_accepted_requires_2xx_and_marker():
    schema = mlf.ForgeSchema(accept_markers=("authorization_code",))
    client = mlf.MacEndpointClient.__new__(mlf.MacEndpointClient)   # no socket needed
    client.schema = schema
    assert client.accepted({"status": 200, "body": '{"authorization_code":"X"}'}) is True
    assert client.accepted({"status": 200, "body": '{"accepted":true}'}) is False   # marker absent
    assert client.accepted({"status": 401, "body": '{"authorization_code":"X"}'}) is False


def test_client_refuses_out_of_scope_host():
    # A public host matches no glob in the suite scope profile; the scope check raises before any
    # connection is attempted (so no network under the sandbox).
    with pytest.raises(scope.OutOfScope):
        mlf.MacEndpointClient("http://console.example.org:8080/api/command", mlf.ForgeSchema())


# ----------------------------------------------------------------- contract entry (solve, offline)

def _write(tmp_path: Path, name: str, obj: dict) -> Path:
    (tmp_path / name).write_text(json.dumps(obj), encoding="utf-8")
    return tmp_path


def test_solve_offline_with_secret_emits_forge_and_flag(tmp_path):
    secret = b"knownhandoutkey!"          # 16
    message = "amount=10&to=alice"
    mac = hashlib.sha256(secret + message.encode()).hexdigest()
    flag = "CSCTF{handout_forged_ok}"
    _write(tmp_path, "spec.json", {
        "algorithm": "sha256", "key_length_band": [8, 24], "message": message,
        "signature": mac, "append": "&to=mallory", "secret": secret.decode(),
        "flag_on_accept": flag,
    })
    res = mlf.solve(tmp_path, CSCTF)
    assert res.status == "candidate"
    assert flag in res.flags
    assert res.evidence and "secret_len=16" in res.evidence[0].detail


def test_solve_without_secret_reports_live_needed_not_a_guess(tmp_path):
    message = "station=A&cmd=STATUS"
    mac = hashlib.sha256(b"serverkey" + message.encode()).hexdigest()
    _write(tmp_path, "spec.json", {
        "algorithm": "sha256", "key_length_band": [8, 32],
        "message": message, "signature": mac, "append": "&cmd=DISPATCH",
    })
    res = mlf.solve(tmp_path, CSCTF)
    assert res.status == "unsure"
    assert not res.flags                       # never fabricated
    assert "live endpoint" in res.notes and "B-006" in res.notes


def test_solve_no_handout_is_none(tmp_path):
    res = mlf.solve(tmp_path, CSCTF)
    assert res.status == "none" and not res.flags


# ================================================================ verification round 1 (fixer)

# ----------------------------------------------------------------- live client never follows a redirect

class _Server:
    """A loopback HTTP server whose every GET/POST is answered by ``reply(handler) -> (code, headers,
    body)`` and counted in ``hits``."""

    def __init__(self, reply):
        self.hits = 0
        srv = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _answer(self):
                srv.hits += 1
                n = int(self.headers.get("Content-Length") or 0)
                if n:
                    self.rfile.read(n)
                code, headers, body = reply(self)
                self.send_response(code)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_GET = _answer
            do_POST = _answer

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    @property
    def port(self) -> int:
        return self.httpd.server_port

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)


def _scope_only_127_0_0_1():
    return event.parse({
        "slug": "b061-redirect", "name": "B-061 redirect scope profile",
        "dates": {"start": datetime.date(2026, 1, 1), "end": datetime.date(2026, 12, 31)},
        "platform": {"kind": "ctfd", "base_url": "https://board.b061-platform.test"},
        "flag": {"prefixes": []},
        "rules": {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed",
                  "live_service_scope": ["127.0.0.1"]},
    }, src="tests/test_common_mac_lenext_forge.py")


@pytest.fixture
def pinned_127_only():
    prev = scope.pinned()
    scope.pin(_scope_only_127_0_0_1())
    try:
        yield
    finally:
        if prev is None:
            scope.unpin()
        else:
            scope.pin(prev)


def test_live_client_does_not_follow_a_redirect_off_scope(pinned_127_only):
    # The off-scope host answers like an accepting endpoint, so following the 302 would both leak the
    # forged command to it and let it "confirm" the forgery.
    offscope = _Server(lambda h: (200, {"Content-Type": "application/json"},
                                  json.dumps({"accepted": True,
                                              "authorization_code": SYNTH_FLAG}).encode()))
    target = f"http://localhost:{offscope.port}/api/command"
    redirector = _Server(lambda h: (302, {"Location": target}, b""))
    try:
        schema = mlf.ForgeSchema(algorithm="sha256", key_length_band=(1, 4), append=b"&cmd=X",
                                 content_type="form", accept_markers=("authorization_code",))
        # Premise: the pinned scope refuses the redirect target outright.
        with pytest.raises(scope.OutOfScope):
            mlf.MacEndpointClient(target, schema)
        client = mlf.MacEndpointClient(f"http://127.0.0.1:{redirector.port}/api/command", schema)
        resp = client.send_command(b"a=1", b"\x00" * 32)
        assert redirector.hits == 1
        assert offscope.hits == 0                       # the 302 was not followed
        assert resp["status"] == 302
        assert resp["refused_redirect"] == target       # the refused target is logged
        assert client.accepted(resp) is False
    finally:
        redirector.close()
        offscope.close()


def test_live_client_does_not_follow_even_an_in_scope_redirect():
    # Single-target: a 3xx to another in-scope URL is still a rejection, never a second request.
    other = _Server(lambda h: (200, {}, b'{"accepted": true}'))
    redirector = _Server(lambda h: (303, {"Location": f"http://127.0.0.1:{other.port}/x"}, b"moved"))
    try:
        client = mlf.MacEndpointClient(f"http://127.0.0.1:{redirector.port}/api/command",
                                       mlf.ForgeSchema(content_type="form",
                                                       accept_markers=('accepted": true',)))
        resp = client.send_command(b"a=1", b"\x01" * 32)
        assert other.hits == 0 and resp["status"] == 303 and resp["body"] == "moved"
        assert client.accepted(resp) is False
    finally:
        redirector.close()
        other.close()


# ----------------------------------------------------------------- fingerprint edge: empty head

@pytest.mark.parametrize("sep", [".", "|", "~", ":"])
def test_fingerprint_token_rejects_an_empty_payload(sep):
    # A token that is ONLY a separator + MAC signs nothing readable: no split is claimed.
    assert mlf.fingerprint_token(sep + "ab" * 20) == ()
    # Control: one payload byte makes it a token.
    assert mlf.fingerprint_token("u" + sep + "ab" * 20)[0].message == b"u"


# ----------------------------------------------------------------- run_live honours schema.algorithm

def _md4(data: bytes) -> bytes:
    from Crypto.Hash import MD4                        # pycryptodome, pinned in requirements.in
    return MD4.new(data).digest()


def test_run_live_uses_schema_algorithm_over_the_fingerprint():
    # MD4 and MD5 share a 16-byte digest, so the token fingerprints as md5; only the schema's named
    # algorithm can make the forge right. The endpoint is a pure function behind the injectable
    # transport (no socket), verifying H = MD4(secret || message).
    secret = b"k" * 7
    message = b"user=bob&role=user"
    token = mlf.fingerprint_pair(message, _md4(secret + message).hex())
    assert token.algorithm == "md5"

    def transport(url, data, headers, method, timeout):
        fields = {urllib.parse.unquote_to_bytes(k): urllib.parse.unquote_to_bytes(v)
                  for k, v in (p.split(b"=", 1) for p in data.split(b"&") if b"=" in p)}
        ok = _md4(secret + fields[b"message"]).hex() == fields[b"signature"].decode()
        if not ok:
            return 401, b'{"accepted": false}'
        role = fields[b"message"].rsplit(b"role=", 1)[-1]
        body = {"accepted": True}
        if role == b"admin":
            body["authorization_code"] = SYNTH_FLAG
        return 200, json.dumps(body).encode()

    schema = mlf.ForgeSchema(algorithm="md4", key_length_band=(1, 16), append=b"&role=admin",
                             content_type="form", accept_markers=('accepted": true',))
    client = mlf.MacEndpointClient("http://127.0.0.1:9/api", schema, transport=transport)
    res = mlf.run_live(client, token, schema, flag_shape=flagfmt.for_profile(CSCTF))
    assert res.ok, res.reason
    assert res.forge.algorithm == "md4" and res.forge.secret_len == 7
    assert res.flag == SYNTH_FLAG


# ----------------------------------------------------------------- solve(): token-only handout

def _sha1_token(secret: bytes, payload: str) -> str:
    return f"{payload}.{hashlib.sha1(secret + payload.encode()).hexdigest()}"


def test_solve_reads_a_token_only_handout(tmp_path):
    # The headline form: a payload.MAC token with no algorithm/hash/band key alongside it.
    secret = b"tok-secret"
    _write(tmp_path, "handout.json", {"token": _sha1_token(secret, "user=bob&role=user"),
                                      "secret": secret.decode(), "append": "&role=admin"})
    res = mlf.solve(tmp_path, CSCTF)
    assert res.status == "unsure" and not res.flags
    assert res.evidence and "sha1" in res.evidence[0].detail
    assert f"secret_len={len(secret)}" in res.evidence[0].detail


def test_token_key_alone_is_no_signal_when_it_does_not_fingerprint(tmp_path):
    _write(tmp_path, "handout.json", {"token": "not-a-mac-token", "secret": "x", "append": "y"})
    res = mlf.solve(tmp_path, CSCTF)
    assert res.status == "none"


# ----------------------------------------------------------------- solve(): flag_on_accept gating

def _flag_handout(tmp_path, flag_value):
    secret = b"k3y-for-flag"
    message = "amount=1"
    _write(tmp_path, "spec.json", {
        "message": message, "signature": hashlib.sha256(secret + message.encode()).hexdigest(),
        "append": "&amount=999", "secret": secret.decode(), "flag_on_accept": flag_value})
    return tmp_path


def test_solve_does_not_emit_a_non_flag_flag_on_accept(tmp_path):
    res = mlf.solve(_flag_handout(tmp_path, "thanks for playing"), CSCTF)
    assert res.status == "unsure"
    assert res.flags == ()
    assert "does not match" in res.notes
    assert res.evidence                                    # the forge itself still succeeded


def test_solve_names_why_the_flag_format_could_not_be_checked(tmp_path, monkeypatch):
    # profile=None falls to the current event; an unknown CTF_EVENT cannot load, and the reason is
    # named in the notes instead of being swallowed.
    monkeypatch.setenv("CTF_EVENT", "no-such-event-b061")
    res = mlf.solve(_flag_handout(tmp_path, SYNTH_FLAG), None)
    assert res.status == "unsure" and res.flags == ()
    assert "could not be checked" in res.notes and "EventError" in res.notes


def test_solve_with_a_wrong_secret_is_none(tmp_path):
    message = "amount=1"
    _write(tmp_path, "spec.json", {
        "message": message, "signature": hashlib.sha256(b"real-key" + message.encode()).hexdigest(),
        "append": "&amount=999", "secret": "wrong-key", "flag_on_accept": SYNTH_FLAG})
    res = mlf.solve(tmp_path, CSCTF)
    assert res.status == "none" and res.flags == ()
    assert "does not produce the given MAC" in res.notes


def test_solve_hex_options(tmp_path):
    secret = bytes(range(1, 13))                         # binary key: only expressible as hex:
    message = "a=1"
    _write(tmp_path, "spec.json", {
        "message": message, "signature": hashlib.sha256(secret + message.encode()).hexdigest()})
    res = mlf.solve(tmp_path, CSCTF, secret="hex:" + secret.hex(), append="hex:26623d32")
    assert res.status == "unsure" and res.evidence
    assert "secret_len=12" in res.evidence[0].detail and "b'&b=2'" in res.evidence[0].detail
    bad = mlf.solve(tmp_path, CSCTF, secret="hex:zz", append="&b=2")
    assert bad.status == "blocked" and "bad hex" in bad.notes


def test_solve_algorithm_option_and_band_option(tmp_path):
    secret = b"abcdef"
    message = "q=1"
    _write(tmp_path, "spec.json", {"message": message,
                                   "signature": hashlib.sha256(secret + message.encode()).hexdigest(),
                                   "secret": secret.decode(), "append": "&q=2"})
    assert mlf.solve(tmp_path, CSCTF, algorithm="sha384").status == "blocked"
    assert mlf.solve(tmp_path, CSCTF, band="7").status == "blocked"
    # A band that misses the true length (6) cannot be forged even with the secret.
    assert mlf.solve(tmp_path, CSCTF, band="8-10").status == "none"
    assert "secret_len=6" in mlf.solve(tmp_path, CSCTF, band="1-10").evidence[0].detail


# ----------------------------------------------------------------- ForgeSchema.from_spec

def test_from_spec_maps_field_aliases():
    s = mlf.ForgeSchema.from_spec({
        "hash": "SHA-1", "key_length_band_bytes": [4, 9], "signature_field": "sig",
        "message_field": "msg", "append": "&x=1", "accept_markers": ["OK"],
        "content_type": "form", "mac_encoding": "base64", "method": "PUT"})
    assert s.algorithm == "sha1" and s.key_length_band == (4, 9)
    assert s.mac_field == "sig" and s.message_field == "msg" and s.append == b"&x=1"
    assert s.accept_markers == ("OK",) and s.content_type == "form"
    assert s.mac_encoding == "base64" and s.method == "PUT"
    s2 = mlf.ForgeSchema.from_spec({"algo": "md4", "band": [2, 3], "mac_field": "m",
                                    "signature_field": "ignored"})
    assert s2.algorithm == "md4" and s2.key_length_band == (2, 3) and s2.mac_field == "m"
    assert mlf.ForgeSchema.from_spec({}) == mlf.ForgeSchema()      # defaults when nothing is given


@pytest.mark.parametrize("spec", [{"hash": "sha384"}, {"band": [5, 2]}, {"band": [1]},
                                  {"band": "1-5"}, {"append": 5}, ["not", "a", "dict"]])
def test_from_spec_rejects_bad_specs(spec):
    with pytest.raises(mlf.MacForgeError):
        mlf.ForgeSchema.from_spec(spec)


def test_wire_body_json_and_base64_mac():
    seen = {}

    def transport(url, data, headers, method, timeout):
        seen.update(json.loads(data))
        seen["method"] = method
        seen["ctype"] = headers["Content-Type"]
        return 200, b"{}"
    schema = mlf.ForgeSchema(mac_encoding="base64", method="PUT", message_field="m", mac_field="t")
    client = mlf.MacEndpointClient("http://127.0.0.1:9/x", schema, transport=transport)
    client.send_command(b"hi", b"\xff\x00")
    assert seen == {"m": "hi", "t": "/wA=", "method": "PUT", "ctype": "application/json"}


# ----------------------------------------------------------------- CLI exit codes

def test_cli_fingerprint_exit_codes(capsys):
    tok = _sha1_token(b"s", "user=a")
    assert mlf._main(["fingerprint", "--token", tok]) == 0
    out = json.loads(capsys.readouterr().out.splitlines()[0])
    assert out["algorithm"] == "sha1" and out["message_bytes"] == len("user=a")
    assert mlf._main(["fingerprint", "--token", "plain"]) == 1
    assert mlf._main(["fingerprint", "--token", tok, "--message", "m", "--signature", "a" * 64]) == 2


def test_cli_forge_exit_codes(capsys):
    secret, message = b"clikey", b"x=1"
    mac = hashlib.sha256(secret + message).hexdigest()
    assert mlf._main(["forge", "--message", "x=1", "--signature", mac, "--append", "&y=2",
                      "--secret", "clikey"]) == 0
    out = json.loads(capsys.readouterr().out)
    forged = bytes.fromhex(out["forged_message_hex"])
    assert forged.endswith(b"&y=2")
    assert hashlib.sha256(secret + forged).hexdigest() == out["forged_tag"]
    assert mlf._main(["forge", "--message", "x=1", "--signature", mac, "--append", "&y=2",
                      "--secret", "nope"]) == 1
    # A MAC length no extendable hash produces and no --algorithm: a named error.
    assert mlf._main(["forge", "--message", "x=1", "--signature", "ab" * 24, "--append", "&y=2",
                      "--secret", "k"]) == 2
    assert "pass --algorithm" in capsys.readouterr().err
    assert mlf._main(["forge", "--message", "x=1", "--signature", mac, "--append", "hex:q",
                      "--secret", "k"]) == 2


# ----------------------------------------------------------------- CLI live (+ B-006 submit hand-off)

def _live_args(tmp_path, console, *extra):
    schema = tmp_path / "schema.json"
    schema.write_text(json.dumps({"algorithm": "sha256", "key_length_band": [20, 30],
                                  "append": "&cmd=DISPATCH", "content_type": "form",
                                  "accept_markers": ['accepted": true']}), encoding="utf-8")
    tok = _status_token(console.secret)
    return ["live", "--url", console.url, "--schema", str(schema), "--event", "csctf",
            "--message", tok.message.decode(), "--signature", tok.mac_hex, *extra]


def test_cli_live_recovers_the_flag(tmp_path, console, capsys):
    assert mlf._main(_live_args(tmp_path, console)) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["ok"] is True and out["flag"] == SYNTH_FLAG and out["secret_len"] == 25


def test_cli_live_submit_hands_the_flag_to_the_b006_queue(tmp_path, console, monkeypatch):
    from ctf.cli import submit_queue
    monkeypatch.setenv("CTF_EVENT", "csctf")         # the queue posts to the current event
    calls = []

    def record(challenge_id, flag, **kw):
        calls.append((challenge_id, flag, kw))
        return 0
    monkeypatch.setattr(submit_queue, "submit_one", record)
    assert mlf._main(_live_args(tmp_path, console, "--submit", "4242")) == 0
    assert len(calls) == 1 and calls[0][0] == "4242" and calls[0][1] == SYNTH_FLAG
    assert "secret_len=25" in calls[0][2]["note"]


def test_cli_live_returns_the_submit_queue_exit_code(tmp_path, console, monkeypatch):
    from ctf.cli import submit_queue
    monkeypatch.setenv("CTF_EVENT", "csctf")
    monkeypatch.setattr(submit_queue, "submit_one", lambda *a, **kw: 1)   # e.g. judged incorrect
    assert mlf._main(_live_args(tmp_path, console, "--submit", "4242")) == 1


def test_cli_live_submit_refused_by_event_rules_exits_4(tmp_path, console, monkeypatch, capsys):
    from ctf.cli import submit_queue
    from ctf.platform import NotAllowed

    def refuse(*a, **kw):
        raise NotAllowed("manual event: submit by hand")
    monkeypatch.setenv("CTF_EVENT", "csctf")
    monkeypatch.setattr(submit_queue, "submit_one", refuse)
    assert mlf._main(_live_args(tmp_path, console, "--submit", "4242")) == 4
    assert "refused" in capsys.readouterr().err


def test_cli_live_out_of_scope_url_is_refused_before_any_request(tmp_path, console, capsys):
    args = _live_args(tmp_path, console)
    args[args.index("--url") + 1] = "http://console.example.org:8080/api/command"
    assert mlf._main(args) == 4
    assert "refused" in capsys.readouterr().err


def test_cli_live_band_missing_the_key_exits_1(tmp_path, console, capsys):
    args = _live_args(tmp_path, console)
    schema = Path(args[args.index("--schema") + 1])
    spec = json.loads(schema.read_text())
    spec["key_length_band"] = [1, 10]                    # the true length 25 is outside
    schema.write_text(json.dumps(spec))
    assert mlf._main(args) == 1
    assert json.loads(capsys.readouterr().out)["ok"] is False


def test_cli_live_schema_without_append_is_an_error(tmp_path, console, capsys):
    args = _live_args(tmp_path, console)
    schema = Path(args[args.index("--schema") + 1])
    schema.write_text(json.dumps({"algorithm": "sha256"}))
    assert mlf._main(args) == 2
    assert "no 'append'" in capsys.readouterr().err


# ================================================================ verification round 2 (fixer)

# ----------------------------------------------------------------- transport errors are not rejections

def _closed_loopback_port() -> int:
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()                                          # nothing listens there now
    return port


def _form_schema(**kw):
    base = dict(algorithm="sha256", key_length_band=(1, 16), append=b"&cmd=DISPATCH",
                content_type="form", accept_markers=('accepted": true',))
    base.update(kw)
    return mlf.ForgeSchema(**base)


def test_live_refused_connection_is_a_named_error_not_a_band_miss():
    # Before the fix oracle_aead swallowed the URLError, the original tag read as "rejected", and the
    # run reported the misleading "no unique secret length in the band".
    schema = _form_schema()
    client = mlf.MacEndpointClient(f"http://127.0.0.1:{_closed_loopback_port()}/api/command", schema)
    token = _status_token(b"k" * 7)
    with pytest.raises(mlf.MacEndpointError) as ei:
        mlf.run_live(client, token, schema, flag_shape=flagfmt.for_profile(CSCTF))
    assert "failed" in str(ei.value) and "URLError" in str(ei.value)
    assert client.calls == 1                           # the first failure stops the run
    assert client.transcript[0]["status"] is None and "URLError" in client.transcript[0]["error"]


def _secret_prefix_transport(secret: bytes, fail_on_call: int, exc: BaseException):
    """A sha256 H(secret || message) endpoint behind the injectable transport that raises ``exc`` on
    call number ``fail_on_call`` (1-based; 0 never fails)."""
    state = {"n": 0}

    def transport(url, data, headers, method, timeout):
        state["n"] += 1
        if state["n"] == fail_on_call:
            raise exc
        fields = {urllib.parse.unquote_to_bytes(k): urllib.parse.unquote_to_bytes(v)
                  for k, v in (p.split(b"=", 1) for p in data.split(b"&") if b"=" in p)}
        ok = hashlib.sha256(secret + fields[b"message"]).hexdigest() == fields[b"signature"].decode()
        return (200, b'{"accepted": true}') if ok else (401, b'{"accepted": false}')
    return transport, state


@pytest.mark.parametrize("exc", [ConnectionResetError("peer reset"), TimeoutError("timed out"),
                                 http.client.IncompleteRead(b"")])
def test_a_mid_band_transport_failure_voids_the_forge(exc):
    # Calls: 1 original tag, 2 tampered tag, 3 len 1, 4 len 2 -> fails. The true length (7) is still
    # accepted later in the band, so a swallowed error would yield ok=True from an unjudged length.
    secret = b"k" * 7
    transport, state = _secret_prefix_transport(secret, fail_on_call=4, exc=exc)
    schema = _form_schema()
    client = mlf.MacEndpointClient("http://127.0.0.1:9/api", schema, transport=transport)
    with pytest.raises(mlf.MacEndpointError) as ei:
        mlf.run_live(client, _status_token(secret), schema, flag_shape=flagfmt.for_profile(CSCTF))
    assert type(exc).__name__ in str(ei.value)
    assert state["n"] == 4 and client.calls == 4       # nothing more is sent once the run is void


def test_control_the_same_transport_without_a_failure_forges():
    secret = b"k" * 7
    transport, _ = _secret_prefix_transport(secret, fail_on_call=0, exc=OSError())
    schema = _form_schema()
    client = mlf.MacEndpointClient("http://127.0.0.1:9/api", schema, transport=transport)
    res = mlf.run_live(client, _status_token(secret), schema, flag_shape=flagfmt.for_profile(CSCTF))
    assert res.ok and res.forge.secret_len == 7


def test_a_new_run_live_on_the_same_client_starts_clean():
    # One transient failure voids that run only; the next run_live on the same client is judged anew.
    secret = b"k" * 7
    transport, _ = _secret_prefix_transport(secret, fail_on_call=1, exc=ConnectionRefusedError())
    schema = _form_schema()
    client = mlf.MacEndpointClient("http://127.0.0.1:9/api", schema, transport=transport)
    shape = flagfmt.for_profile(CSCTF)
    with pytest.raises(mlf.MacEndpointError):
        mlf.run_live(client, _status_token(secret), schema, flag_shape=shape)
    res = mlf.run_live(client, _status_token(secret), schema, flag_shape=shape)
    assert res.ok and res.forge.secret_len == 7


def test_cli_live_refused_connection_exits_2_with_the_cause(tmp_path, console, capsys):
    args = _live_args(tmp_path, console)
    args[args.index("--url") + 1] = f"http://127.0.0.1:{_closed_loopback_port()}/api/command"
    assert mlf._main(args) == 2
    err = capsys.readouterr().err
    assert "failed" in err and "URLError" in err


# ----------------------------------------------------------------- JSON wire refuses non-UTF-8 bytes

def test_json_body_refuses_a_non_utf8_message():
    # json.dumps does NOT reject a surrogateescape'd byte: it escapes it as "\udc80", so the endpoint
    # would get other bytes. The client refuses instead, before the transport is called.
    sent = []
    client = mlf.MacEndpointClient("http://127.0.0.1:9/x", mlf.ForgeSchema(content_type="json"),
                                   transport=lambda *a: sent.append(a) or (200, b"{}"))
    with pytest.raises(mlf.MacForgeError) as ei:
        client.send_command(b"a=1\x80\x00", b"\x00" * 32)
    assert "not valid UTF-8" in str(ei.value) and "form" in str(ei.value)
    assert sent == [] and client.calls == 0
    client.send_command("café".encode(), b"\x00" * 32)    # valid UTF-8 text still goes
    assert json.loads(sent[0][1])["message"] == "café"


def test_run_live_refuses_a_json_wire_before_any_request():
    sent = []
    schema = _form_schema(content_type="json")
    client = mlf.MacEndpointClient("http://127.0.0.1:9/api", schema,
                                   transport=lambda *a: sent.append(a) or (200, b"{}"))
    with pytest.raises(mlf.MacForgeError) as ei:
        mlf.run_live(client, _status_token(b"k" * 7), schema, flag_shape=flagfmt.for_profile(CSCTF))
    assert "json" in str(ei.value) and "secret length 1" in str(ei.value)
    assert sent == [] and client.calls == 0            # refused outside the verifier, up front


# ----------------------------------------------------------------- proxy variables are ignored

def test_live_client_ignores_proxy_environment_variables(monkeypatch):
    proxy = _Server(lambda h: (200, {}, b'{"accepted": true, "via": "proxy"}'))
    target = _Server(lambda h: (200, {}, b'{"accepted": true}'))
    try:
        for var in ("no_proxy", "NO_PROXY", "all_proxy", "ALL_PROXY"):
            monkeypatch.delenv(var, raising=False)
        monkeypatch.setenv("http_proxy", f"http://127.0.0.1:{proxy.port}")
        monkeypatch.setenv("HTTP_PROXY", f"http://127.0.0.1:{proxy.port}")
        client = mlf.MacEndpointClient(f"http://127.0.0.1:{target.port}/api/command",
                                       _form_schema())
        resp = client.send_command(b"a=1", b"\x00" * 32)
        assert proxy.hits == 0 and target.hits == 1
        assert resp["status"] == 200 and "proxy" not in resp["body"]
    finally:
        proxy.close()
        target.close()


# ----------------------------------------------------------------- run_live's own append guard

def test_run_live_with_no_append_sends_nothing():
    sent = []
    schema = _form_schema(append=b"")
    client = mlf.MacEndpointClient("http://127.0.0.1:9/api", schema,
                                   transport=lambda *a: sent.append(a) or (200, b'{"accepted": true}'))
    res = mlf.run_live(client, _status_token(b"k" * 7), schema, flag_shape=flagfmt.for_profile(CSCTF))
    assert res.ok is False and "append" in res.reason and res.forge is None
    assert sent == [] and client.calls == 0


# ----------------------------------------------------------------- CLI: accepted but no flag

@pytest.fixture
def flagless_console():
    c = _MacConsole(secret=b"x" * 25, flag="dispatch queued, see the operator")   # not CSCTF{...}
    try:
        yield c
    finally:
        c.close()


def test_cli_live_accepted_without_a_flag_exits_1_and_submits_nothing(tmp_path, flagless_console,
                                                                    monkeypatch, capsys):
    from ctf.cli import submit_queue
    monkeypatch.setenv("CTF_EVENT", "csctf")
    calls = []
    monkeypatch.setattr(submit_queue, "submit_one", lambda *a, **kw: calls.append(a) or 0)
    assert mlf._main(_live_args(tmp_path, flagless_console, "--submit", "4242")) == 1
    out = json.loads(capsys.readouterr().out)
    assert out["ok"] is True and out["flag"] is None and out["secret_len"] == 25
    assert calls == []
    assert mlf._main(_live_args(tmp_path, flagless_console)) == 1
    assert "no flag" in capsys.readouterr().err


# ----------------------------------------------------------------- CLI: --event must be the submit event

def test_cli_live_submit_refuses_an_event_other_than_the_current_one(tmp_path, console, monkeypatch,
                                                                   capsys):
    from ctf.cli import submit_queue
    monkeypatch.setenv("CTF_EVENT", "huntress")      # submit_one would post to huntress
    calls = []
    monkeypatch.setattr(submit_queue, "submit_one", lambda *a, **kw: calls.append(a) or 0)
    assert mlf._main(_live_args(tmp_path, console, "--submit", "4242")) == 4   # args say --event csctf
    err = capsys.readouterr().err
    assert "refused" in err and "differs" in err and "huntress" in err
    assert calls == [] and console.hits == 0           # refused before the endpoint is contacted


def test_cli_live_submit_refuses_without_a_current_event(tmp_path, console, monkeypatch, capsys):
    from ctf import env as ctf_env
    from ctf.cli import submit_queue
    for var in ("CTF_EVENT", *ctf_env.legacy_names("CTF_EVENT")):
        monkeypatch.delenv(var, raising=False)       # several profiles exist: no current event
    calls = []
    monkeypatch.setattr(submit_queue, "submit_one", lambda *a, **kw: calls.append(a) or 0)
    assert mlf._main(_live_args(tmp_path, console, "--submit", "4242")) == 4
    assert "current event" in capsys.readouterr().err
    assert calls == [] and console.hits == 0
    # Without --submit the same --event csctf run needs no current event and recovers the flag.
    assert mlf._main(_live_args(tmp_path, console)) == 0
