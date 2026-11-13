#!/usr/bin/env python3
"""Day-26 benign web-speed build: solvers/web/recon_triage.py (RECON -> vuln-class triage, and proof/flag
extraction), read-only and GET-only.

  .venv/bin/python tests/test_day26_web_recon_read.py

Local fake targets only (http.server on 127.0.0.1); no Game Master request, no live target, no network
egress. Checks:
  A. recon() classifies git exposure, backup exposure, a clue-driven class (/api/clues session_hint),
     an openapi-disclosed IDOR-shaped route, and an LFI-reader-param hint, each from the target's OWN
     disclosure only (no payload sent, GET only, bounded to RECON_PATHS).
  B. a target with nothing disclosed gets "no_clear_signal", never a fabricated class.
  C. recon() never sends more requests than len(RECON_PATHS), even with a huge --max-requests, and respects
     a near-past deadline (sends nothing after the pad).
  D. extract_proof / best_proof: exact lowercase proof_ + 32 lowercase hex is the only returnable form;
     UUID-v4 is validation only; uppercase/future proof shapes and generic flags are surfaced as candidates but
     never returned; two DISTINCT exact-form values give None; garbage gives [] / None without an exception.
  E. fuzz: a batch of junk response bodies (binary, huge, malformed JSON, nested braces) never raises and
     never produces a false proof.
  F. the destructive-word guard (_allowed) refuses a path or parameter whose words change or end state; every
     entry of RECON_PATHS passes it (so recon() never needs to skip one of its own fixed paths).
  G. nothing offensive: recon() sends only GET, never follows an off-host redirect, and the zip-member read
     of backup.zip never extracts or executes anything (names only).
"""

import event_pin  # noqa: E402  (tests/event_pin.py)
event_pin.pin(globals(), "huntress")  # Huntress web tests: proof_<32 hex> payoffs (events/huntress [proof])
import importlib.util
import io
import json
import os
import random
import string
import sys
import threading
import time
import urllib.parse
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
os.environ.pop("CTF_PLATFORM_URL", None)
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))

FAILS = []


def check(name, ok, detail=""):
    print(("ok   " if ok else "FAIL ") + name + ("" if ok or not detail else f"  [{str(detail)[:600]}]"), flush=True)
    if not ok:
        FAILS.append(name)


def load_solver():
    spec = importlib.util.spec_from_file_location("recon_triage", REPO / "solvers" / "web" / "recon_triage.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


RT = load_solver()


# ---------------------------------------------------------------------------------------------------------
#  a fake target (same pattern as tests/test_day21_web_solver.py: Site + http.server, local only)
# ---------------------------------------------------------------------------------------------------------
class Site:
    def __init__(self, routes, default=None):
        self.routes = routes
        self.default = default
        self.hits = []
        self.lock = threading.Lock()

    def handle(self, method, raw):
        with self.lock:
            self.hits.append((method, raw))
        path, _, q = raw.partition("?")
        query = dict(urllib.parse.parse_qsl(q, keep_blank_values=True))
        fn = self.routes.get(path) or self.default
        if fn is None:
            return 404, "text/html", "<p>not found</p>", {}
        r = fn(query) if callable(fn) else fn
        return (tuple(r) + ({},))[:4]


def serve(site):
    class H(BaseHTTPRequestHandler):
        def _go(self):
            st, ctype, body, hdrs = site.handle(self.command, self.path)
            data = body.encode() if isinstance(body, str) else body
            self.send_response(st)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            for k, v in (hdrs or {}).items():
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


def page(title, body):
    return 200, "text/html; charset=utf-8", f"<!doctype html><html><head><title>{title}</title></head><body>{body}</body></html>"


def js(obj, status=200):
    return status, "application/json", json.dumps(obj)


def run_recon(site, **kw):
    srv, url = serve(site)
    try:
        return RT.recon(url, **kw)
    finally:
        srv.shutdown()
        srv.server_close()


def class_names(out):
    return {c["vuln_class"] for c in out["classes"]}


# ---------------------------------------------------------------------------------------------------------
#  A. classification from disclosed surface only
# ---------------------------------------------------------------------------------------------------------
def test_git_exposure():
    site = Site({"/": page("Home", "<p>hi</p>"),
                 "/.git/HEAD": lambda q: (200, "text/plain", "ref: refs/heads/main\n")})
    out = run_recon(site)
    check("git exposure classified", "git_exposure" in class_names(out), class_names(out))
    check("git exposure high confidence", any(c["confidence"] == "high" for c in out["classes"] if c["vuln_class"] == "git_exposure"))
    check("only GET sent", all(h[0] == "GET" for h in site.hits))
    check("bounded to RECON_PATHS", len(site.hits) <= len(RT.RECON_PATHS), len(site.hits))


def test_backup_exposure_zip_names_only():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("dump.sql", "not a real db")
        zf.writestr("notes.json.bak", json.dumps({"support_note": "see proof_00000000000040008000000000000000"}))
    zip_bytes = buf.getvalue()
    site = Site({"/": page("Home", "<p>hi</p>"),
                 "/backup.zip": lambda q: (200, "application/zip", zip_bytes)})
    out = run_recon(site)
    check("backup exposure classified", "backup_exposure" in class_names(out), class_names(out))
    members = out["disclosed"].get("backup_zip_members", [])
    check("zip member NAMES only, nothing extracted/executed", set(members) == {"dump.sql", "notes.json.bak"}, members)


def test_clue_driven_session_class():
    site = Site({
        "/": page("Home", "<p>hi</p>"),
        "/api/clues": lambda q: js({"feature_route": "/set-session-ab12", "secondary_route": "/status-cd34",
                                    "session_hint": "deadbeef", "input_parameter": "sid"}),
    })
    out = run_recon(site)
    names = class_names(out)
    check("clue-driven session class", "session_fixation_or_idor" in names, names)
    cls = next(c for c in out["classes"] if c["vuln_class"] == "session_fixation_or_idor")
    check("endpoints are the clue's own routes", set(cls["endpoints"]) == {"/set-session-ab12", "/status-cd34"}, cls)
    check("stated param surfaced ahead of a guess", cls["params"] == ["sid"], cls["params"])


def test_openapi_idor_hint():
    spec = {"paths": {"/api/items/{item_id}": {}, "/api/items/{item_id}/detail": {}, "/health": {}}}
    site = Site({"/": page("Home", "<p>hi</p>"), "/openapi.json": lambda q: js(spec)})
    out = run_recon(site)
    names = class_names(out)
    check("openapi-disclosed idor-shaped route found", "idor" in names, names)
    cls = next(c for c in out["classes"] if c["vuln_class"] == "idor")
    check("idor endpoints come from the spec", any("item_id" in e for e in cls["endpoints"]), cls["endpoints"])


def test_lfi_param_hint_from_landing_links():
    body = "<p>Docs: <a href=\"/reader.php?doc=about.php\">reader</a></p>"
    site = Site({"/": page("Home", body)})
    out = run_recon(site)
    names = class_names(out)
    check("lfi hint from a reader-style link param", "lfi" in names, names)
    cls = next(c for c in out["classes"] if c["vuln_class"] == "lfi")
    check("lfi param is 'doc'", cls["params"] == ["doc"], cls["params"])


def test_graphql_and_ssrf_hints():
    spec = {"paths": {"/graphql": {}}}
    body = "<a href=\"/preview?url=http://example.invalid/x\">preview</a>"
    site = Site({"/": page("Home", body), "/openapi.json": lambda q: js(spec)})
    out = run_recon(site)
    names = class_names(out)
    check("graphql disclosed", "graphql" in names, names)
    check("ssrf-style param hint", "ssrf" in names, names)


# ---------------------------------------------------------------------------------------------------------
#  B. nothing disclosed -> no fabricated class
# ---------------------------------------------------------------------------------------------------------
def test_nothing_disclosed():
    site = Site({"/": page("Plain", "<p>nothing here</p>")})
    out = run_recon(site)
    names = class_names(out)
    check("no_clear_signal when nothing is disclosed", names == {"no_clear_signal"}, names)
    check("no_clear_signal is low confidence", out["classes"][0]["confidence"] == "low")


# ---------------------------------------------------------------------------------------------------------
#  C. bounded requests, deadline respected
# ---------------------------------------------------------------------------------------------------------
def test_bounded_by_fixed_path_list():
    site = Site({"/": page("Home", "<p>hi</p>")})
    out = run_recon(site, max_requests=10_000)
    check("never more requests than RECON_PATHS even with a huge cap",
          out["requests"] <= len(RT.RECON_PATHS), out["requests"])
    check("never more hits than RECON_PATHS on the fake server",
          len(site.hits) <= len(RT.RECON_PATHS), len(site.hits))


def test_deadline_respected():
    site = Site({"/": page("Home", "<p>hi</p>")})
    srv, url = serve(site)
    try:
        out = RT.recon(url, deadline=time.time() - 1.0)   # already past: nothing should be sent
    finally:
        srv.shutdown()
        srv.server_close()
    check("a past deadline sends nothing", out["requests"] == 0 and len(site.hits) == 0, out["requests"])


# ---------------------------------------------------------------------------------------------------------
#  D. proof / flag extraction
# ---------------------------------------------------------------------------------------------------------
def test_extract_proof_exact_wins_over_generic():
    exact = "proof_00000000000040008000000000000000"
    text = f"welcome! your token is flag{{not_this_one}} but the real proof is {exact}"
    got = RT.extract_proof(text)
    check("exact-form proof found", got and got[0] == (exact, "exact"), got)


def test_best_proof_two_distinct_exact_is_none():
    a = "proof_00000000000040008000000000000000"
    b = "proof_11111111111141118111111111111111"
    out = RT.best_proof([f"first body has {a}", f"second body has {b}"])
    check("two distinct exact-form proofs -> None (never guess which)", out is None, out)


def test_best_proof_single_exact_banked():
    a = "proof_00000000000040008000000000000000"
    out = RT.best_proof([f"plain page shows nothing", f"exploit response: {a}"])
    check("single exact-form proof is returned", out == (a, "exact"), out)


def test_non_v4_wire_is_exact_and_returnable():
    value = "proof_" + "0" * 32
    got = RT.extract_proof(f"successful response evidence={value}")
    check("a lowercase non-v4 proof_32hex is exact wire evidence", got == [(value, "exact")], got)
    check("a lowercase non-v4 proof_32hex is returnable", RT.best_proof([f"success: {value}"]) == (value, "exact"))
    check("UUID-v4 remains a validator, not the return gate",
          RT.PROOF_WIRE.fullmatch(value) is not None and RT.PROOF_FORMAT.fullmatch(value) is None)


def test_nonreturnable_shapes_are_surfaced():
    uppercase = "proof_" + "A" * 32
    future = "proof_future-format-alpha"
    for value in (uppercase, future):
        got = RT.extract_proof(f"successful response evidence={value}")
        check(f"{value[:24]} is surfaced as a candidate", got == [(value, "candidate")], got)
        check(f"{value[:24]} is never auto-returned", RT.best_proof([f"success: {value}"]) is None)
    exact = "proof_00000000000040008000000000000000"
    check("an evidence-only shape beside an exact proof makes the choice ambiguous",
          RT.best_proof([f"success: {exact} and {uppercase}"]) is None)


def test_generic_flag_is_evidence_only():
    flag = "hunt{this_is_a_generic_flag}"
    got = RT.extract_proof(flag)
    check("a lone generic flag{...} is surfaced as a low-confidence candidate", got == [(flag, "generic")], got)
    check("a generic flag is never auto-returned", RT.best_proof([f"the response says {flag}"]) is None)


def test_extract_proof_garbage_is_empty():
    for garbage in ("", None, "no proof here", "{}", "\x00\x01\x02binary\xff\xfe", "a" * 100000):
        got = RT.extract_proof(garbage)
        check(f"garbage input yields [] ({garbage!r:.30})", got == [], got)


# ---------------------------------------------------------------------------------------------------------
#  E. fuzz: junk responses never raise, never produce a false proof
# ---------------------------------------------------------------------------------------------------------
def test_fuzz_junk_responses_no_exception_no_false_proof():
    rng = random.Random(1337)
    N_RECON = 15     # a handful through full recon() (each spins a real local HTTP server: keep it cheap)
    N_EXTRACT = 2000  # extract_proof/best_proof are pure functions: fuzz them hard and fast, no server needed

    def junk():
        kind = rng.choice(["binary", "huge_text", "malformed_json", "nested_braces", "almost_proof"])
        if kind == "binary":
            return bytes(rng.randrange(256) for _ in range(rng.randrange(0, 4000)))
        if kind == "huge_text":
            return "".join(rng.choice(string.printable) for _ in range(rng.randrange(0, 20000)))
        if kind == "malformed_json":
            return rng.choice(["{", "{\"a\":", "[1,2,", "null null null", "{{{{{{"])
        if kind == "nested_braces":
            return "{" * rng.randrange(0, 50) + "x" * 10 + "}" * rng.randrange(0, 50)
        # A near-miss to the strict lowercase wire form: uppercase is surfaced, never exact/auto-returned.
        return "proof_" + "".join(rng.choice("0123456789ABCDEF") for _ in range(32))

    raised = []
    false_proofs = []

    # pure-function fuzz: fast, no server, high iteration count
    for i in range(N_EXTRACT):
        body = junk()
        text = body if isinstance(body, str) else body.decode("latin-1", "replace")
        try:
            got = RT.extract_proof(text)
            _ = RT.best_proof([text])
        except Exception as e:
            raised.append((i, "extract_proof:" + type(e).__name__, str(e)[:120]))
            continue
        for value, kind in got:
            if kind == "exact" and not RT.PROOF_WIRE.fullmatch(value):
                false_proofs.append((i, value))

    # a smaller end-to-end sample through recon() itself (each spins a real local HTTP server)
    for i in range(N_RECON):
        body = junk()

        def h(q, body=body):
            return 200, "application/octet-stream" if isinstance(body, bytes) else "text/plain", body

        site = Site({"/": h})
        try:
            run_recon(site)
        except Exception as e:
            raised.append((i, type(e).__name__, str(e)[:120]))

    check(f"{N_EXTRACT} junk bodies through extract_proof()/best_proof(): never raise", not raised, raised[:5])
    check("no malformed value accepted as an exact-form proof", not false_proofs, false_proofs[:5])


# ---------------------------------------------------------------------------------------------------------
#  F. destructive guard
# ---------------------------------------------------------------------------------------------------------
def test_destructive_guard():
    check("a destructive path is refused", RT._allowed("/reset-everything") is False)
    check("a destructive query param name is refused", RT._allowed("/x?delete=1") is False)
    check("a benign path passes", RT._allowed("/robots.txt") is True)
    bad = [p for p in RT.RECON_PATHS if not RT._allowed(p)]
    check("every fixed RECON_PATHS entry passes its own guard", not bad, bad)


# ---------------------------------------------------------------------------------------------------------
#  G. nothing offensive
# ---------------------------------------------------------------------------------------------------------
def test_nothing_offensive_get_only_and_no_followed_redirect():
    hit_offhost_marker = {"hit": False}

    def off(q):
        hit_offhost_marker["hit"] = True
        return 200, "text/plain", "should never be reached"

    site = Site({"/": lambda q: (302, "text/plain", "", {"Location": "http://example.invalid/off-host"}),
                 "/robots.txt": page("robots", "User-agent: *\n")})
    out = run_recon(site)
    check("an off-host redirect from / is never followed", hit_offhost_marker["hit"] is False)
    check("GET only", all(h[0] == "GET" for h in site.hits))
    # no payload characters (quotes, braces used by injection payloads) ever appear in a requested raw path
    check("no payload sent in any request path", all("'" not in h[1] and "{{" not in h[1] for h in site.hits))


def main():
    for fn in (test_git_exposure, test_backup_exposure_zip_names_only, test_clue_driven_session_class,
               test_openapi_idor_hint, test_lfi_param_hint_from_landing_links, test_graphql_and_ssrf_hints,
               test_nothing_disclosed, test_bounded_by_fixed_path_list, test_deadline_respected,
               test_extract_proof_exact_wins_over_generic, test_best_proof_two_distinct_exact_is_none,
               test_best_proof_single_exact_banked, test_non_v4_wire_is_exact_and_returnable,
               test_nonreturnable_shapes_are_surfaced, test_generic_flag_is_evidence_only,
               test_extract_proof_garbage_is_empty, test_fuzz_junk_responses_no_exception_no_false_proof,
               test_destructive_guard, test_nothing_offensive_get_only_and_no_followed_redirect):
        fn()
    if FAILS:
        print(f"\n{len(FAILS)} FAILED: {FAILS}")
        return 1
    print("\nok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
