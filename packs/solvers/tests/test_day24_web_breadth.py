#!/usr/bin/env python3
"""Day 24 SAFE web breadth (2026-10-23; branch wave2/web-breadth): the GET-only / offline halves of the web
classes the look-ahead left open, folded into the live solve path as READ-ONLY DETECTORS (plus a strict
read-only NoSQL payoff closer), with the
state-changing POST/OOB/write/gadget halves kept as hand tools.

  .venv/bin/python tests/test_day24_web_breadth.py        (TEST_KEEP=1 keeps the scratch folder)

A PERMANENT battery, fully OFFLINE except for loopback http.server fakes on 127.0.0.1: no Game Master, no
token, no live target, no network beyond localhost. What it proves:

  1. solvers/web/exploit_classes.py's new generators/classifiers decide from EVIDENCE, never a reflection:
     the prototype-pollution benign canary (refuses gadget keys; a structural reflection confirms, a bare
     query echo is only a lead), the deserialization BLIND DETECTOR (every wire signature; a plain cookie and
     a JWT are NOT serialized), the XXE surface detector, the GraphQL GET-introspection and NoSQL GET-param
     descriptors, and the JWT RS256->HS256 read-replay + the (gated) jku forge.
  2. solvers/web/proof_hunt.py's wave-9 breadth is GET-ONLY on the live path: against loopback fakes for each
     class it RECORDS a finding and NEVER sends a POST (every server hit is a GET; _Hunter._post is never
     called). A NoSQL boolean read banks only a sole proof inside records absent from its control.
  3. No false positives: a benign site yields no finding and no flag.
  4. The per-class kill-switches (CTF_WEB_CLASS_<NAME>=off) turn a detector off.

The flag is never produced or submitted; the only sockets opened are to 127.0.0.1 fakes this test starts.
"""

import event_pin  # noqa: E402  (tests/event_pin.py)
event_pin.pin(globals(), "huntress")  # Huntress web tests: proof_<32 hex> payoffs (events/huntress [proof])
import base64
import importlib.util
import json
import os
import re
import shutil
import sys
import tempfile
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
WEBDIR = REPO / "solvers" / "web"
SCRATCH = Path(tempfile.mkdtemp(prefix="day24-webbreadth-"))

FAILS = []


def check(name, ok, detail=""):
    if not ok:
        FAILS.append(name)
    print(("ok   " if ok else "FAIL ") + name + ("" if ok or not detail else f"  [{str(detail)[:600]}]"),
          flush=True)


def load(path, name, env=None):
    old = dict(os.environ)
    if env is not None:
        for k, v in env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    try:
        for m in ("proof_hunt", "huntress_exploit_classes_bx"):
            sys.modules.pop(m, None)
        spec = importlib.util.spec_from_file_location(name, path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    finally:
        if env is not None:
            os.environ.clear()
            os.environ.update(old)


EC = load(WEBDIR / "exploit_classes.py", "huntress_exploit_classes_bx")
PH = load(WEBDIR / "proof_hunt.py", "proof_hunt")


# ---------------------------------------------------------------------------------------------------------
#  Part 1: exploit_classes generators/classifiers (offline, no network)
# ---------------------------------------------------------------------------------------------------------
def resp(status=200, body="", ctype="application/json", headers=None):
    h = {"content-type": ctype}
    h.update(headers or {})
    return {"status": status, "body": body, "headers": h}


def test_proto_pollution():
    rows = EC.proto_pollution_payloads()
    names = [r["name"] for r in rows]
    check("proto: baseline + four pollute vectors", names == ["baseline", "proto_query", "ctor_query",
          "proto_json", "ctor_json"], names)
    c = rows[1]["confirm"]["canary"]
    v = rows[1]["confirm"]["value"]
    check("proto: GET vectors carry __proto__[canary] / constructor[prototype][canary]",
          f"__proto__[{c}]" in urllib.parse.unquote(rows[1]["query"])
          and f"constructor[prototype][{c}]" in urllib.parse.unquote(rows[2]["query"]), rows[1:3])
    # a benign canary reflected as a STRUCTURAL property confirms
    hit = EC.classify_proto_pollution(resp(body=json.dumps({"ok": True, c: v})), canary=c, value=v)
    check("proto: a structural reflected property confirms", hit["confirmed"] and hit["evidence"] ==
          "reflected_property", hit)
    # the canary/value echoed only inside the query string is a LEAD, not a confirmation
    lead = EC.classify_proto_pollution(resp(ctype="text/html",
           body=f"<p>bad param __proto__[{c}]={v}</p>"), canary=c, value=v)
    check("proto: a query-string echo is a lead, not confirmed", lead["confirmed"] is False, lead)
    # the control (baseline) must never confirm
    base = EC.classify_proto_pollution(resp(body=json.dumps({"ok": True})), canary=c, value=v)
    check("proto: a clean body does not confirm", base["confirmed"] is False, base)
    # a gadget/destructive canary is refused outright
    refused = False
    try:
        EC.proto_pollution_payloads(canary="isAdmin")
    except ValueError:
        refused = True
    check("proto: a gadget key (isAdmin) is refused as a canary", refused)
    refused2 = False
    try:
        EC.proto_pollution_payloads(canary="__proto__")
    except ValueError:
        refused2 = True
    check("proto: __proto__ is refused as a canary", refused2)


def test_deser_detector():
    java_b64 = base64.b64encode(b"\xac\xed\x00\x05t\x00\x04test").decode()
    pickle_raw = b"\x80\x04\x95\x05\x00\x00\x00\x00\x00\x00\x00}\x94."
    pickle_b64 = base64.b64encode(pickle_raw).decode()
    php = 'O:8:"stdClass":1:{s:1:"a";i:1;}'
    php_b64 = base64.b64encode(php.encode()).decode()
    dotnet = "AAEAAAD/////AQAAAAAAAAAMAgAAAA=="
    ruby = base64.b64encode(b"\x04\x08{\x06:\x06ai\x06").decode()
    node = '{"rce":"_$$ND_FUNC$$_function(){return 1}()"}'
    cases = [
        ("java raw", b"\xac\xed\x00\x05x", "java", "raw"),
        ("java base64", java_b64, "java", "base64"),
        ("python pickle raw", pickle_raw, "python_pickle", "raw"),
        ("python pickle base64", pickle_b64, "python_pickle", "base64"),
        ("php raw", php, "php", "raw"),
        ("php base64", php_b64, "php", "base64"),
        ("dotnet base64", dotnet, "dotnet", "base64"),
        ("ruby marshal base64", ruby, "ruby_marshal", "base64"),
        ("node-serialize", node, "node_serialize", "raw"),
    ]
    for label, value, kind, enc in cases:
        r = EC.classify_serialized_blob(value)
        check(f"deser: {label} recognized as {kind}/{enc}",
              r["serialized"] and r["kind"] == kind and r["encoding"] == enc, r)
    # NO false positives: a plain cookie, a short token, a JWT, a UUID-ish value
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1In0.c2ln"
    for label, value in [("plain cookie", "abc123session"), ("short", "x"), ("jwt", jwt),
                         ("uuid", "7b3f9c2e-0a1b-4c3d-8e9f-001122334455"), ("empty", ""),
                         ("plain words", "the quick brown fox jumps over")]:
        r = EC.classify_serialized_blob(value)
        check(f"deser: {label} is NOT flagged serialized (no false positive)", not r["serialized"], r)
    sig = EC.deserialization_signals({"cookie:sess": java_b64, "param:x": "plain", "cookie:id": php})
    check("deser: deserialization_signals returns one row per serialized blob",
          sorted(s["kind"] for s in sig) == ["java", "php"], sig)


def test_xxe_surface():
    for label, ct, body, want in [
        ("content-type xml", "application/xml", "<data/>", True),
        ("xml prolog", "text/plain", "<?xml version='1.0'?><r/>", True),
        ("doctype", "text/html", "<!DOCTYPE foo SYSTEM 'x'>", True),
        ("non-html bare doctype", "text/plain", "<!doctype feed><feed/>", True),
        ("html5 doctype lower", "text/html", "<!doctype html><title>safe</title>", False),
        ("html5 doctype upper", "text/html", "<!DOCTYPE HTML><title>safe</title>", False),
        ("plain html", "text/html", "<html><body>hi</body></html>", False),
        ("json", "application/json", '{"a":1}', False),
    ]:
        sig = EC.xxe_surface_signals(ct, body)
        check(f"xxe: {label} -> xml={want}", sig["xml"] is want, sig)


def test_graphql_and_nosql_get():
    g = EC.graphql_get_probes("/graphql")
    check("graphql: GET probes only (read-only), query param carries introspection",
          all(p["method"] == "GET" for p in g) and any("__schema" in urllib.parse.unquote(p["query"]) for p in g), g)
    n = EC.nosql_get_probes("user")
    check("nosql: GET probes only, with $ne/$gt/$regex bracket operators + a control",
          all(p["method"] == "GET" for p in n) and {p["kind"] for p in n} == {"control", "boolean"}
          and any("user[$ne]" in urllib.parse.unquote(p["query"]) for p in n), n)
    # classify_nosql differential (the hand-tool classifier): a bigger authenticated body confirms
    control = resp(status=200, ctype="text/html", body="<p>no results found</p>")
    bypass = resp(status=200, ctype="text/html", body="<ul>" + "<li>row</li>" * 50 + "</ul>",
                  headers={"set-cookie": "session=abc; Path=/"})
    cls = EC.classify_nosql(control, bypass)
    check("nosql: classify_nosql confirms on a new session cookie (hand tool)", cls["confirmed"], cls)


def test_jwt_confusion():
    def b64u(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    tok = f"{b64u({'alg': 'RS256', 'typ': 'JWT'})}.{b64u({'sub': 'u', 'role': 'user'})}.c2ln"
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.public_key().public_bytes(serialization.Encoding.PEM,
                                         serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    forged = EC.jwt_rs256_confusion(tok, pem)
    check("jwt: rs256_confusion returns a 3-part HS256 token", isinstance(forged, str)
          and forged.count(".") == 2, forged)
    # the forged token's raised claims
    body = json.loads(base64.urlsafe_b64decode(forged.split(".")[1] + "=="))
    check("jwt: rs256 confusion raises role to admin", body.get("role") == "admin", body)
    acc = EC.classify_jwt_access(resp(status=403, ctype="text/html", body="forbidden"),
                                 resp(status=200, ctype="text/html", body="welcome admin"))
    check("jwt: classify_jwt_access confirms a 403->200 transition", acc["confirmed"]
          and acc["evidence"] == "auth_transition", acc)
    # pem discovery is offline
    found = EC.rsa_public_keys_in("prefix " + pem + " suffix")
    check("jwt: rsa_public_keys_in finds a PEM in a body", len(found) == 1, found[:1])
    # the jku forge is a gated hand tool: it builds the token + the JWKS to host, nothing sent
    jk = EC.jwt_jku_forge(tok, "https://collector.example/jwks.json")
    check("jwt: jku forge returns a token + a JWKS to host (gated, nothing sent)",
          isinstance(jk, dict) and "token" in jk and jk.get("jwks", {}).get("keys"), list(jk))


# ---------------------------------------------------------------------------------------------------------
#  Part 2: the proof_hunt wave-9 breadth is GET-only, records findings, banks no flag
# ---------------------------------------------------------------------------------------------------------
class Site:
    def __init__(self, routes, default=None, set_cookie=None):
        self.routes = routes
        self.default = default
        self.set_cookie = set_cookie
        self.hits = []
        self.lock = threading.Lock()

    def handle(self, method, raw):
        with self.lock:
            self.hits.append((method, raw))
        path, _, q = raw.partition("?")
        query = urllib.parse.parse_qsl(q, keep_blank_values=True)
        fn = self.routes.get(path) or self.default
        if fn is None:
            return 404, "text/html", "<p>not found</p>", {}
        r = fn(path, query) if callable(fn) else fn
        return (tuple(r) + ({},))[:4]


def serve(site):
    class H(BaseHTTPRequestHandler):
        def _go(self):
            st, ctype, body, hdrs = site.handle(self.command, self.path)
            data = body.encode() if isinstance(body, str) else body
            self.send_response(st)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            if site.set_cookie:
                self.send_header("Set-Cookie", site.set_cookie)
            for k, v in (hdrs or {}).items():
                self.send_header(k, v)
            self.end_headers()
            try:
                self.wfile.write(data)
            except Exception:
                pass

        do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = _go

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/"


_POST_CALLS = []


def run_site(site, env=None, label="t"):
    """Serve `site`, run solve_targets once, return (flag, findings, methods). Wraps _Hunter._post to prove
    the breadth path never POSTs."""
    mod = PH if env is None else load(WEBDIR / "proof_hunt.py", "proof_hunt", env=env)
    srv, url = serve(site)
    log_dir = SCRATCH / (label + "-" + str(srv.server_address[1]))
    log_dir.mkdir(parents=True, exist_ok=True)
    orig_post = mod._Hunter._post

    def guarded_post(self, *a, **k):
        _POST_CALLS.append(label)
        return orig_post(self, *a, **k)

    mod._Hunter._post = guarded_post
    try:
        out = mod.solve_targets([{"answer_id": "proof-1", "url": url, "index": 1,
                                  "question": "Recover the proof from Target 1."}],
                                {"deadline": time.time() + 20, "max_requests": 400,
                                 "log_dir": str(log_dir), "challenge": label})
    finally:
        mod._Hunter._post = orig_post
        srv.shutdown()
        srv.server_close()
    findings = []
    jl = log_dir / "proof_hunt.jsonl"
    if jl.is_file():
        for line in jl.read_text().splitlines():
            try:
                findings += json.loads(line).get("findings") or []
            except Exception:
                pass
    return out.get("proof-1"), findings, [m for m, _ in site.hits]


HTML = "<!doctype html><html><body>{b}</body></html>"


def graphql_site():
    schema = {"data": {"__schema": {"queryType": {"name": "Query"},
              "types": [{"name": "Query"}, {"name": "User"}, {"name": "Secret"}]}}}

    def gql(path, query):
        return 200, "application/json", json.dumps(schema)

    return Site({"/": lambda p, q: (200, "text/html", HTML.format(b="<h1>api</h1>")), "/graphql": gql})


def nosql_site():
    def search(path, query):
        if any("[$" in k for k, _ in query):
            return 200, "text/html", "<ul>" + "<li>user</li>" * 60 + "</ul>"
        if any(k == "q" for k, _ in query):
            return 200, "text/html", "<p>no results found</p>"
        return 200, "text/html", "<p>search</p>"

    return Site({"/": lambda p, q: (200, "text/html",
                 HTML.format(b="<a href='/search?q=test'>search</a>")), "/search": search})


def nosql_proof_site(values, root_decoy=None):
    public = {"id": 1, "name": "public"}

    def search(path, query):
        rows = [public]
        if any("[$" in k for k, _ in query):
            rows += [{"id": i + 2, "evidence": value} for i, value in enumerate(values)]
        return 200, "application/json", json.dumps({"results": rows})

    body = "<a href='/search?q=test'>search</a>" + (root_decoy or "")
    return Site({"/": lambda p, q: (200, "text/html", HTML.format(b=body)), "/search": search})


def deser_site():
    tok = base64.b64encode(b"\xac\xed\x00\x05t\x00\x04user").decode()
    return Site({"/": lambda p, q: (200, "text/html",
                 HTML.format(b=f"<a href='/view?token={tok}'>view</a>")),
                 "/view": lambda p, q: (200, "text/html", "<p>viewer</p>")})


def xxe_site():
    return Site({"/": lambda p, q: (200, "text/html", HTML.format(b="<a href='/feed.xml'>feed</a>")),
                 "/feed.xml": lambda p, q: (200, "application/xml", "<?xml version='1.0'?><data>hi</data>")})


def proto_site():
    spec = {"paths": {"/api/profile": {"post": {"requestBody": {"content": {"application/json": {}}}}},
                      "/api/noop": {"get": {}}}}
    return Site({"/": lambda p, q: (200, "text/html", HTML.format(b="<h1>app</h1>")),
                 "/openapi.json": lambda p, q: (200, "application/json", json.dumps(spec))})


def jwt_site():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.public_key().public_bytes(serialization.Encoding.PEM,
                                         serialization.PublicFormat.SubjectPublicKeyInfo).decode()

    def b64u(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    tok = f"{b64u({'alg': 'RS256', 'typ': 'JWT'})}.{b64u({'sub': 'u', 'role': 'user'})}.c2lnbmF0dXJl"
    return Site({"/": lambda p, q: (200, "text/html", HTML.format(b=f"<p>token {tok}</p>")),
                 "/jwks.json": lambda p, q: (200, "text/plain", pem)})


def benign_site():
    return Site({"/": lambda p, q: (200, "text/html", HTML.format(b="<a href='/about'>about</a><p>home</p>")),
                 "/about": lambda p, q: (200, "text/html", HTML.format(b="<p>about us</p>"))},
                set_cookie="session=plain123; Path=/")


def benign_upper_doctype_site():
    return Site({"/": lambda p, q: (200, "text/html",
                 "<!DOCTYPE HTML><html><body><a href='/about'>about</a><p>home</p></body></html>"),
                 "/about": lambda p, q: (200, "text/html",
                 "<!DOCTYPE html><html><body><p>about us</p></body></html>")},
                set_cookie="session=plain123; Path=/")


def test_breadth_live_detectors():
    specs = [
        ("graphql", graphql_site, "introspection"),
        ("nosql", nosql_site, "boolean_differential"),
        ("deser", deser_site, "serialized_blob"),
        ("xxe", xxe_site, "xml_surface"),
        ("proto", proto_site, "json_merge_candidate"),
        ("jwtconf", jwt_site, "rs256_confusion_candidate"),
    ]
    for cls, mk, evidence in specs:
        _POST_CALLS.clear()
        flag, findings, methods = run_site(mk(), label=cls)
        mine = [f for f in findings if f.get("class") == cls]
        check(f"breadth[{cls}]: a finding was recorded with evidence={evidence}",
              any(f.get("evidence") == evidence for f in mine), findings)
        check(f"breadth[{cls}]: the flag is None (a detector never banks)", flag is None, flag)
        check(f"breadth[{cls}]: GET-ONLY on the live path (every server hit is a GET)",
              methods and set(methods) == {"GET"}, sorted(set(methods)))
        check(f"breadth[{cls}]: _Hunter._post was never called", _POST_CALLS == [], _POST_CALLS)


def test_no_false_positive():
    for label, make in (("benign-lower-doctype", benign_site),
                        ("benign-upper-doctype", benign_upper_doctype_site)):
        _POST_CALLS.clear()
        flag, findings, methods = run_site(make(), label=label)
        check(f"{label}: no finding on a plain HTML5 site (no false positive)", findings == [], findings)
        check(f"{label}: the flag is None", flag is None, flag)
        check(f"{label}: GET-only and no POST on a plain site",
              set(methods) == {"GET"} and _POST_CALLS == [],
              (sorted(set(methods)), _POST_CALLS))


def test_nosql_cold_payoff():
    real = "proof_123456789abc4def8abc123456789abc"
    flag, findings, methods = run_site(nosql_proof_site([real]), label="nosql-cold")
    check("nosql cold: one proof in records absent from control is banked", flag == real, (flag, findings))
    check("nosql cold: boolean differential remains GET-only", methods and set(methods) == {"GET"}, methods)

    decoy = "proof_aaaaaaaaaaaa4aaa8aaaaaaaaaaaaaaa"
    flag, findings, _ = run_site(nosql_proof_site([real], root_decoy=decoy), label="nosql-decoy")
    check("nosql cold: a distinct baseline decoy is subtracted, not globally poisoning", flag == real,
          (flag, findings))

    other = "proof_bbbbbbbbbbbb4bbb8bbbbbbbbbbbbbbb"
    flag, findings, _ = run_site(nosql_proof_site([real, other]), label="nosql-ambiguous")
    check("nosql cold: two novel extra-record proofs are ambiguous", flag is None, (flag, findings))


def test_per_class_killswitch():
    # graphql detector off -> no graphql finding even on a graphql server
    _POST_CALLS.clear()
    flag, findings, methods = run_site(graphql_site(), env={"CTF_WEB_CLASS_GRAPHQL": "off"},
                                       label="gqloff")
    check("killswitch: CTF_WEB_CLASS_GRAPHQL=off records no graphql finding",
          not any(f.get("class") == "graphql" for f in findings), findings)
    check("killswitch: still GET-only with a class off", set(methods) <= {"GET"}, sorted(set(methods)))
    # the flag dict reads the switch
    mod = load(WEBDIR / "proof_hunt.py", "proof_hunt", env={"CTF_WEB_CLASS_NOSQL": "off"})
    check("killswitch: EXPLOIT_CLASSES['nosql'] reads False with env off",
          mod.EXPLOIT_CLASSES.get("nosql") is False and mod.EXPLOIT_CLASSES.get("graphql") is True,
          mod.EXPLOIT_CLASSES)


def test_default_flags_on():
    check("default: all six breadth classes default ON (read-only detectors)",
          PH.EXPLOIT_CLASSES == {"graphql": True, "nosql": True, "xxe": True, "proto": True,
                                 "deser": True, "jwtconf": True}, PH.EXPLOIT_CLASSES)


def main():
    test_proto_pollution()
    test_deser_detector()
    test_xxe_surface()
    test_graphql_and_nosql_get()
    test_jwt_confusion()
    test_default_flags_on()
    test_breadth_live_detectors()
    test_nosql_cold_payoff()
    test_no_false_positive()
    test_per_class_killswitch()
    print(f"\n{'FAIL' if FAILS else 'PASS'} test_day24_web_breadth: {len(FAILS)} failed")
    for f in FAILS:
        print("  -", f)
    if not (FAILS or os.environ.get("TEST_KEEP")):
        shutil.rmtree(SCRATCH, ignore_errors=True)
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
