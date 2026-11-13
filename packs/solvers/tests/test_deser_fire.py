#!/usr/bin/env python3
"""Offline tests for solvers/web/deser_fire.py -- the GATED native-deserialization gadget-firing
engine (B-121). No network and no sockets: firing goes through an injected in-process fake transport,
so what reaches the wire is inspected directly. Every behaviour is a check that fails when the
behaviour is wrong (no tautology, no asserting on a mock of the thing under test).

Proofs covered:
  gate      fire() without a ConsentToken raises FireNotArmed and sends NOTHING; a token cannot be
            forged; arm('') is refused.
  o2        under the pinned huntress profile (web_state_changing=false) a fire is refused with a
            named reason and sends nothing; with no loadable profile it fails closed.
  killswitch CTF_WEB_DESER_FIRE=off refuses even with consent; nothing is sent.
  no-gadget firing never auto-generates RCE: an empty payload is refused, naming the cold generator.
  mismatch  a payload whose wire format is not the detected family is refused (deser_detect check).
  deliver   the happy path delivers the base64-wrapped gadget to the cookie sink, GET-firsts a
            control, and returns the single self-proving payoff; the wire bytes are exactly the
            encoded gadget. param / body-form / header / body-raw placements are pinned exactly.
  encoding  a two-layer chain is applied outermost-first (deser_detect's order): a detection of a
            captured base64(gzip(pickle)) re-wraps the gadget as base64(gzip(gadget)).
  decoy     a payoff shown on the plain control page too is rejected (self-proving / one-proof rule);
            max_requests < 2 (no control) is refused.
  ambiguous two distinct payoffs on the fire response -> proof None.
  rce       a computed nonce echoed only on the fire response confirms RCE; a nonce SENT literally
            and echoed back by a reflecting server does not.
  flag-evt  under a flag event the recovered flag is the payoff; nothing is ever auto-submitted.
  sink      destructive verbs raise FireRefused; a body-raw GET is refused before any request.
  cli       `fire` with neither, or only one, of the two explicit flags refuses, prints the cold plan,
            and never builds a WebClient.
"""
import event_pin  # noqa: E402  (tests/event_pin.py)
event_pin.pin(globals(), "huntress")  # proof_<32 hex> payoff; [flag] also defined; web_state_changing=false

import base64
import dataclasses
import gzip
import hashlib
import importlib.util
import io
import json
import pickle
import sys
import types
import urllib.parse
from contextlib import redirect_stdout
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "solvers" / "web"))
_spec = importlib.util.spec_from_file_location("deser_fire", REPO / "solvers" / "web" / "deser_fire.py")
DF = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(DF)
import deser_detect as DD  # noqa: E402  (solvers/web, read-only detector)


# --- synthetic payloads (built, never deserialized/executed) ----------------------------------------

def pickle_gadget():
    # A real, recognizable pickle of a benign object. deser_detect classifies it python_pickle; we
    # never unpickle it. It stands in for the player's cold-generated python gadget.
    return pickle.dumps({"deser_fire_test": 1})


def php_gadget():
    return b'O:4:"Evil":1:{s:3:"cmd";s:2:"id";}'


def a_proof(seed="x"):
    return "proof_" + hashlib.sha256(seed.encode()).hexdigest()[:32]


STD_WIRE = base64.b64encode(pickle_gadget()).decode()


# --- the O-2 switch: run with the pinned event's profile, web_state_changing flipped -----------------

@pytest.fixture
def state_ok(monkeypatch):
    """The real active profile (CTF_EVENT), with rules.web_state_changing=true. Injected through the
    engine's profile seam; everything else (flag format, slug) stays the real profile's."""
    def _profile():
        real = DF._event.current()
        return dataclasses.replace(real, rules=dataclasses.replace(real.rules, web_state_changing=True))
    monkeypatch.setattr(DF, "_event_profile", _profile)


# --- an in-process fake transport -------------------------------------------------------------------

class FakeClient:
    """Records every request and returns scripted responses. `.request` matches the WebClient shape
    the engine calls. A request that carries `blob` (in the path, body or any header value) gets
    `on_fire(method, path, data, headers)`; one that does not gets `control_body`. So a control read
    that wrongly carried the blob would be answered as a fire, and a fire that lost it as a control."""

    def __init__(self, on_fire=None, control_body=b"<p>home</p>", blob=STD_WIRE):
        self.calls = []            # (method, path, data, headers)
        self.on_fire = on_fire
        self.control_body = control_body
        self.blob = blob

    def carries_blob(self, path, data, headers):
        needles = {self.blob, urllib.parse.quote_plus(self.blob)}
        hay = [urllib.parse.unquote_plus(path), path]
        if data:
            hay += [bytes(data).decode("latin-1"), urllib.parse.unquote_plus(bytes(data).decode("latin-1"))]
        hay += [str(v) for v in (headers or {}).values()]
        return any(n in h for n in needles for h in hay)

    def request(self, method, path, data=None, headers=None, allow_redirects=True):
        headers = dict(headers or {})
        self.calls.append((method, path, data, headers))
        if not self.carries_blob(path, data, headers):
            return {"status": 200, "body": self.control_body}
        body = self.on_fire(method, path, data, headers) if self.on_fire else b""
        return {"status": 200, "body": body}


def cookie_sink(name="session", encoding=("base64",), path="/app"):
    return {"method": "GET", "path": path, "where": "cookie", "name": name, "encoding": list(encoding)}


def proof_on_fire(proof):
    return lambda method, path, data, headers: f"<p>welcome admin</p><!-- {proof} -->".encode()


# --- gate tests -------------------------------------------------------------------------------------

def test_fire_without_consent_sends_nothing(state_ok):
    c = FakeClient()
    with pytest.raises(DF.FireNotArmed):
        DF.fire(c, detection="python_pickle", payload=pickle_gadget(), sink=cookie_sink(), consent=None)
    assert c.calls == [], "nothing may be sent when firing is not armed"


def test_consent_token_cannot_be_forged():
    with pytest.raises(DF.FireNotArmed):
        DF.ConsentToken("sneaky", object())
    for bad in ("", "   ", None):
        with pytest.raises(DF.FireNotArmed):
            DF.arm(bad)
    tok = DF.arm("authorized: CTF scope, challenge web-7")
    assert isinstance(tok, DF.ConsentToken) and "web-7" in tok.reason


def test_state_changing_false_profile_refuses_and_sends_nothing():
    # No injection: the pinned huntress profile really ships web_state_changing=false.
    assert DF._event.current().rules.web_state_changing is False
    for sink in (cookie_sink(), {"method": "POST", "path": "/api", "where": "body-raw",
                                 "encoding": []}):
        c = FakeClient(on_fire=proof_on_fire(a_proof("o2")))
        with pytest.raises(DF.FireRefused) as ei:
            DF.fire(c, detection="python_pickle", payload=pickle_gadget(), sink=sink,
                    consent=DF.arm("scope ok"))
        assert "web_state_changing" in str(ei.value)
        assert c.calls == [], "the O-2 switch is off: nothing may be sent"


def test_no_event_profile_fails_closed(monkeypatch):
    monkeypatch.setenv("CTF_EVENT", "no-such-event-b121")
    c = FakeClient(on_fire=proof_on_fire(a_proof("x")))
    with pytest.raises(DF.FireRefused) as ei:
        DF.fire(c, detection="python_pickle", payload=pickle_gadget(), sink=cookie_sink(),
                consent=DF.arm("scope ok"))
    assert "no event profile" in str(ei.value)
    assert c.calls == []


def test_kill_switch_forbids_firing(monkeypatch, state_ok):
    monkeypatch.setenv(DF.FIRE_KILL_ENV, "off")
    c = FakeClient()
    with pytest.raises(DF.FireRefused) as ei:
        DF.fire(c, detection="python_pickle", payload=pickle_gadget(), sink=cookie_sink(),
                consent=DF.arm("scope ok"))
    assert DF.FIRE_KILL_ENV in str(ei.value)
    assert c.calls == [], "kill-switch refusal sends nothing"


def test_empty_payload_refused_naming_generator(state_ok):
    c = FakeClient()
    with pytest.raises(DF.FireRefused) as ei:
        DF.fire(c, detection="python_pickle", payload=b"", sink=cookie_sink(), consent=DF.arm("scope ok"))
    assert "deser_gadgets" in str(ei.value), "refusal must name the cold generator"
    assert c.calls == []


def test_family_mismatch_refused(state_ok):
    # A PHP blob while the detected sink is python_pickle: wrong gadget, must be refused before firing.
    c = FakeClient()
    with pytest.raises(DF.FireRefused) as ei:
        DF.fire(c, detection="python_pickle", payload=php_gadget(), sink=cookie_sink(),
                consent=DF.arm("scope ok"))
    assert "python" in str(ei.value)
    assert c.calls == []


# --- delivery ---------------------------------------------------------------------------------------

def test_happy_path_delivers_and_self_proves(state_ok):
    gadget = pickle_gadget()
    proof = a_proof("win")
    c = FakeClient(on_fire=proof_on_fire(proof))
    res = DF.fire(c, detection="python_pickle", payload=gadget, sink=cookie_sink(),
                  consent=DF.arm("scope ok"), max_requests=2)
    assert res["fired"] is True
    assert res["family"] == "python"
    assert res["proof"] == proof and res["proof_kind"] == "payoff"
    assert res["requests"] == 2 and len(c.calls) == 2, "GET-first control, then one fire"
    # GET-first: first call is a control GET with no blob anywhere.
    m, p, d, h = c.calls[0]
    assert m == "GET" and p == "/app" and d is None and "Cookie" not in h
    # Delivery/encoding: the fire request carries exactly base64(gadget) in the cookie.
    assert c.calls[1][3]["Cookie"] == f"session={STD_WIRE}"


def _fire_one(sink, gadget=None, blob=STD_WIRE):
    c = FakeClient(on_fire=proof_on_fire(a_proof("deliv")), blob=blob)
    res = DF.fire(c, detection="python_pickle", payload=gadget or pickle_gadget(), sink=sink,
                  consent=DF.arm("scope ok"))
    assert res["proof"] == a_proof("deliv"), "the fire request must carry the blob"
    assert len(c.calls) == 2
    return c.calls[1]


def test_param_delivery_exact(state_ok):
    m, p, d, h = _fire_one({"method": "GET", "path": "/view", "where": "param", "name": "data",
                            "encoding": ["base64"]})
    assert (m, d) == ("GET", None)
    assert p == "/view?" + urllib.parse.urlencode({"data": STD_WIRE})
    # A path that already has a query string gets '&', not a second '?'.
    m, p, d, h = _fire_one({"method": "GET", "path": "/view?page=1", "where": "param", "name": "data",
                            "encoding": ["base64"], "extra_params": {"x": "1"}})
    assert p == "/view?page=1&" + urllib.parse.urlencode({"x": "1", "data": STD_WIRE})
    assert p.count("?") == 1


def test_body_form_delivery_exact(state_ok):
    m, p, d, h = _fire_one({"method": "POST", "path": "/load", "where": "body-form", "name": "obj",
                            "encoding": ["base64"], "extra_params": {"csrf": "t0k"}})
    assert (m, p) == ("POST", "/load")
    assert d == urllib.parse.urlencode({"csrf": "t0k", "obj": STD_WIRE}).encode("ascii")
    assert h["Content-Type"] == "application/x-www-form-urlencoded"


def test_header_delivery_exact(state_ok):
    m, p, d, h = _fire_one({"method": "GET", "path": "/h", "where": "header", "name": "X-State",
                            "encoding": ["base64"], "headers": {"Accept": "text/html"}})
    assert (m, p, d) == ("GET", "/h", None)
    assert h == {"Accept": "text/html", "X-State": STD_WIRE}


def test_body_raw_delivery_exact(state_ok):
    gadget = pickle_gadget()
    m, p, d, h = _fire_one({"method": "POST", "path": "/raw", "where": "body-raw", "encoding": ["base64"]})
    assert (m, p) == ("POST", "/raw")
    assert d == base64.b64encode(gadget)
    assert h["Content-Type"] == "application/octet-stream"


# --- encoding order ---------------------------------------------------------------------------------

def test_two_layer_encoding_is_outermost_first():
    raw = pickle_gadget()
    wire = DF.encode_for_sink(raw, ["base64", "gzip"])
    assert wire == base64.b64encode(gzip.compress(raw, mtime=0))
    assert wire.startswith(b"H4sI"), "base64 of a gzip stream starts H4sI"
    assert gzip.decompress(base64.b64decode(wire)) == raw
    assert DF.encode_for_sink(b"a b", ["hex", "url"]) == b"6125323062"   # hex(url-quote(raw))


def test_detection_dict_encoding_round_trips_through_deser_detect(state_ok):
    # A captured cookie that is base64(gzip(pickle)): deser_detect peels it as ['base64', 'gzip'].
    captured = base64.b64encode(gzip.compress(pickle.dumps({"user": "guest"}), mtime=0)).decode()
    [det] = [f for f in DD.detect(captured) if f["format"] == "python_pickle"]
    assert det["outer_encoding"] == ["base64", "gzip"]
    gadget = pickle_gadget()
    expected = base64.b64encode(gzip.compress(gadget, mtime=0)).decode()
    c = FakeClient(on_fire=proof_on_fire(a_proof("gz")), blob=expected)
    # The sink omits `encoding`: the detection dict's outer_encoding is the default.
    res = DF.fire(c, detection=det, payload=gadget,
                  sink={"method": "GET", "path": "/app", "where": "cookie", "name": "session"},
                  consent=DF.arm("scope ok"))
    sent = c.calls[1][3]["Cookie"].split("=", 1)[1]
    assert sent == expected and sent.startswith("H4sI")
    assert res["proof"] == a_proof("gz") and res["sink"]["encoding"] == ["base64", "gzip"]
    # And the detector, fed what went on the wire, sees the same chain and format again.
    again = [f for f in DD.detect(sent) if f["format"] == "python_pickle"]
    assert again and again[0]["outer_encoding"] == ["base64", "gzip"]


def test_plan_takes_detection_encoding_outermost_first():
    det = {"format": "python_pickle", "outer_encoding": ["base64", "gzip"]}
    p = DF.plan(det, sink={"method": "GET", "path": "/", "where": "cookie", "name": "s"})
    assert p["sink"]["encoding"] == ["base64", "gzip"]


# --- proof rules ------------------------------------------------------------------------------------

def test_decoy_proof_on_control_is_rejected(state_ok):
    proof = a_proof("decoy")
    # The SAME proof is already on the plain control page -> it is a decoy, never claimed.
    c = FakeClient(on_fire=lambda *a: f"<!-- {proof} -->".encode(),
                   control_body=f"<p>home {proof}</p>".encode())
    res = DF.fire(c, detection="python_pickle", payload=pickle_gadget(), sink=cookie_sink(),
                  consent=DF.arm("scope ok"))
    assert res["proof"] is None, "a payoff shown on the control page is a decoy"
    assert any("decoy" in e for e in res["evidence"])


@pytest.mark.parametrize("budget", [1, 0, -3])
def test_max_requests_below_two_refused(state_ok, budget):
    proof = a_proof("nocontrol")
    c = FakeClient(on_fire=lambda *a: f"<!-- {proof} -->".encode(),
                   control_body=f"<p>home {proof}</p>".encode())
    with pytest.raises(DF.DeserFireError) as ei:
        DF.fire(c, detection="python_pickle", payload=pickle_gadget(), sink=cookie_sink(),
                consent=DF.arm("scope ok"), max_requests=budget)
    assert "control" in str(ei.value)
    assert c.calls == [], "no control possible -> nothing sent, no decoy claimable"


def test_two_distinct_payoffs_give_none(state_ok):
    p1, p2 = a_proof("one"), a_proof("two")
    c = FakeClient(on_fire=lambda *a: f"{p1} and also {p2}".encode())
    res = DF.fire(c, detection="python_pickle", payload=pickle_gadget(), sink=cookie_sink(),
                  consent=DF.arm("scope ok"))
    assert res["proof"] is None, "two distinct payoffs are ambiguous -> not claimed"
    assert any("ambiguous" in e for e in res["evidence"])


def test_computed_nonce_confirms_rce(state_ok):
    # The gadget computed its marker (e.g. `echo $((A*B))`); the nonce never appears in the request.
    nonce = "DESERFIRE_" + hashlib.sha256(b"n").hexdigest()[:12]
    c = FakeClient(on_fire=lambda *a: f"uid=0(root) {nonce}".encode())
    res = DF.fire(c, detection="python_pickle", payload=pickle_gadget(), sink=cookie_sink(),
                  consent=DF.arm("scope ok"), proof_nonce=nonce)
    assert res["rce_confirmed"] is True
    assert res["proof"] is None and res["proof_kind"] == "rce-nonce"
    assert any(nonce in e for e in res["evidence"])


def test_nonce_on_control_does_not_confirm(state_ok):
    nonce = "DESERFIRE_ctrl"
    # nonce already present on the control page -> echo is not evidence of our fire.
    c = FakeClient(on_fire=lambda *a: nonce.encode(), control_body=f"<p>{nonce}</p>".encode())
    res = DF.fire(c, detection="python_pickle", payload=pickle_gadget(), sink=cookie_sink(),
                  consent=DF.arm("scope ok"), proof_nonce=nonce)
    assert res["rce_confirmed"] is False and res["proof_kind"] is None


class ReflectingClient:
    """A server that deserializes NOTHING: it echoes the request (path, headers, body) back, plus
    `unwrap(path, data, headers)` -- the delivered blob with its transport encoding undone, as an app
    that decodes a parameter and prints it would."""

    def __init__(self, unwrap=None):
        self.calls = []
        self.unwrap = unwrap

    def request(self, method, path, data=None, headers=None, allow_redirects=True):
        headers = dict(headers or {})
        self.calls.append((method, path, data, headers))
        echo = f"{method} {path}\n" + "".join(f"{k}: {v}\n" for k, v in headers.items())
        body = echo.encode("latin-1", "replace") + bytes(data or b"")
        if self.unwrap is not None:
            try:
                body += b"\n" + self.unwrap(path, data, headers)
            except Exception:       # the control carries no blob to unwrap
                pass
        return {"status": 200, "body": body}


def _cookie_val(headers):
    return headers["Cookie"].split("=", 1)[1]


@pytest.mark.parametrize("encoding,where,unwrap", [
    ([], "body-raw", None),
    (["base64"], "body-raw", lambda p, d, h: base64.b64decode(d)),
    (["base64"], "cookie", lambda p, d, h: base64.b64decode(_cookie_val(h))),
    (["url"], "param", lambda p, d, h: urllib.parse.unquote_to_bytes(p.split("s=", 1)[1])),
])
def test_reflected_nonce_does_not_confirm_rce(state_ok, encoding, where, unwrap):
    nonce = "DESERFIRE_reflect_" + hashlib.sha256(b"r").hexdigest()[:8]
    # A pickle that literally carries `echo NONCE`: a reflecting server shows the nonce (raw, or once
    # its transport encoding is undone) without executing anything.
    gadget = pickle.dumps({"cmd": f"echo {nonce}"}, protocol=2)
    sink = {"method": "POST" if where == "body-raw" else "GET", "path": "/r", "where": where,
            "name": None if where == "body-raw" else "s", "encoding": encoding}
    c = ReflectingClient(unwrap)
    res = DF.fire(c, detection="python_pickle", payload=gadget, sink=sink,
                  consent=DF.arm("scope ok"), proof_nonce=nonce)
    assert len(c.calls) == 2
    m, pth, d, h = c.calls[1]
    assert nonce.encode() in ReflectingClient(unwrap).request(m, pth, d, h)["body"], \
        "the reflector must really show the nonce on the fire, or this test proves nothing"
    assert res["rce_confirmed"] is False, "a reflected, literally-sent nonce is not proof of RCE"
    assert res["proof_kind"] is None
    assert any("SENT literally in the raw payload" in e for e in res["evidence"])


@pytest.mark.parametrize("where,method,expect_site", [("param", "GET", "the request path"),
                                                      ("body-form", "POST", "the request body")])
def test_nonce_sent_in_extra_params_does_not_confirm(state_ok, where, method, expect_site):
    # The nonce rides only the FIRE request (extra_params are not on the control GET), so only the
    # sent-in-request check stops the reflection from being taken as RCE.
    nonce = "DESERFIRE_xp_9f9f"
    sink = {"method": method, "path": "/r", "where": where, "name": "s", "encoding": ["base64"],
            "extra_params": {"note": nonce}}
    c = ReflectingClient()
    res = DF.fire(c, detection="python_pickle", payload=pickle_gadget(), sink=sink,
                  consent=DF.arm("scope ok"), proof_nonce=nonce)
    m, pth, d, h = c.calls[0]
    assert nonce.encode() not in ReflectingClient().request(m, pth, d, h)["body"], "control must not show it"
    m, pth, d, h = c.calls[1]
    assert nonce.encode() in ReflectingClient().request(m, pth, d, h)["body"], "fire must reflect it"
    assert res["rce_confirmed"] is False
    assert any(expect_site in e for e in res["evidence"])


def test_nonce_sent_in_fire_header_does_not_confirm(state_ok):
    # A header sink named with the nonce in its NAME: only the header check catches it.
    nonce = "XDeserNonce77"
    sink = {"method": "GET", "path": "/r", "where": "header", "name": nonce, "encoding": ["base64"]}
    c = ReflectingClient()
    res = DF.fire(c, detection="python_pickle", payload=pickle_gadget(), sink=sink,
                  consent=DF.arm("scope ok"), proof_nonce=nonce)
    assert res["rce_confirmed"] is False
    assert any("request header" in e for e in res["evidence"])


def test_flag_event_returns_flag_never_submits(monkeypatch, state_ok):
    # Under a flag event the payoff is a flag; it is returned, not submitted (no submit path exists).
    monkeypatch.setenv("CTF_EVENT", "csctf")
    flag = "CSCTF{deser_rce_abc123}"
    c = FakeClient(on_fire=lambda *a: f"<pre>{flag}</pre>".encode())
    res = DF.fire(c, detection="python_pickle", payload=pickle_gadget(), sink=cookie_sink(),
                  consent=DF.arm("scope ok"))
    assert res["proof"] == flag and res["proof_kind"] == "payoff"
    assert "never auto-submits" in res["note"]


# --- sink guards ------------------------------------------------------------------------------------

@pytest.mark.parametrize("verb", ["DELETE", "PUT", "PATCH", "TRACE", "CONNECT"])
def test_destructive_verbs_raise_fire_refused(verb):
    with pytest.raises(DF.FireRefused) as ei:
        DF._normalize_sink({"method": verb, "path": "/x", "where": "cookie", "name": "c"})
    assert "destructive" in str(ei.value)


def test_destructive_verb_refused_by_fire_before_sending(state_ok):
    c = FakeClient()
    with pytest.raises(DF.FireRefused):
        DF.fire(c, detection="python_pickle", payload=pickle_gadget(),
                sink={"method": "DELETE", "path": "/x", "where": "cookie", "name": "c"},
                consent=DF.arm("scope ok"))
    assert c.calls == []


def test_sink_guards():
    with pytest.raises(DF.DeserFireError):
        DF._normalize_sink({"method": "GET", "path": "/x", "where": "body-raw"})
    with pytest.raises(DF.DeserFireError):
        DF._normalize_sink({"method": "FOO", "path": "/x", "where": "cookie", "name": "c"})


def test_plan_is_cold_and_maps_families():
    for fmt, fam in (("python_pickle", "python"), ("php_object_injection", "php"),
                     ("java_serialized_stream", "java"), ("node_serialize", "node"),
                     ("unsafe_yaml", "yaml"), ("dotnet_binaryformatter", "dotnet"),
                     ("ruby_marshal", "ruby")):
        p = DF.plan(fmt, sink=cookie_sink())
        assert p["family"] == fam and p["gated"] is True
        assert "COLD" in p["generator"]
        assert p["sink"]["where"] == "cookie"
    with pytest.raises(DF.DeserFireError):
        DF.family_for("not_a_real_format")


# --- CLI gate ---------------------------------------------------------------------------------------

@pytest.fixture
def no_webclient(monkeypatch):
    """Make the CLI's `import web` resolve to a module whose WebClient fails the test if built."""
    built = []

    class _Boom:
        def __init__(self, *a, **k):
            built.append(a)
            raise AssertionError("the CLI built a WebClient without both fire flags")

    monkeypatch.setitem(sys.modules, "web", types.SimpleNamespace(WebClient=_Boom))
    return built


@pytest.mark.parametrize("flags", [[], ["--fire"], ["--i-understand-this-is-rce"]])
def test_cli_fire_refuses_without_both_flags(tmp_path, no_webclient, flags, state_ok):
    payload = tmp_path / "gadget.bin"
    payload.write_bytes(pickle_gadget())
    sink = json.dumps(cookie_sink())
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = DF.main(["fire", "--target", "http://web.invalid/", "--sink", sink,
                      "--format", "python_pickle", "--payload", str(payload)] + flags)
    out = buf.getvalue()
    assert rc == 3, f"firing with flags {flags} must refuse"
    assert "REFUSED" in out and "Cold plan" in out
    assert json.loads(out.split("Cold plan:\n", 1)[1])["family"] == "python"
    assert no_webclient == [], "no client may be built"


def test_cli_both_flags_but_o2_off_refuses_before_client(tmp_path, no_webclient):
    # Pinned huntress: web_state_changing=false. Both flags are not enough.
    payload = tmp_path / "gadget.bin"
    payload.write_bytes(pickle_gadget())
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = DF.main(["fire", "--target", "http://web.invalid/", "--sink", json.dumps(cookie_sink()),
                      "--format", "python_pickle", "--payload", str(payload),
                      "--fire", "--i-understand-this-is-rce"])
    assert rc == 3 and "web_state_changing" in buf.getvalue()
    assert no_webclient == []


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
