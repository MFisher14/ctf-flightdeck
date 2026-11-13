#!/usr/bin/env python3
"""Wave 3 (branch wave3/proof-decode; backlog ticket A3): the proof-location + layered-encoding decode sweep
in solvers/web/proof_hunt.py.

  .venv/bin/python tests/test_wave3_proof_decode.py        (TEST_KEEP=1 keeps the scratch folder)

A PERMANENT, fully OFFLINE battery (loopback http.server fakes on 127.0.0.1 only: no Game Master, no token,
no live target, no network beyond localhost). What it proves, end to end through solve_targets:

  1. A proof that comes back LAYER-ENCODED, with no plaintext proof-like value anywhere, is recovered from
     bytes ALREADY fetched -- base64 in a response header, gzip+base64 in a JSON field, base64url in a
     Set-Cookie value, hex in a <pre> block, a data: URI -- and banked as the one judged proof.
  2. The novel-payoff rule decides: a decoy that decodes to a non-proof is None, two different decoded
     payoff proofs are None, and a distinct plaintext baseline decoy does not hide an encoded real payoff.
  3. GET-only is unchanged: every request the sweep's run makes is a GET and _Hunter._post is never called;
     the sweep itself sends nothing (the request count is the same with and without an encoded proof).
  4. The JSONL row carries decoded:true / shape:"decoded" when a proof was recovered by decoding, and the
     bound holds (decode depth <= 4): a proof wrapped five layers deep is NOT recovered.

The flag is never produced or submitted; the only sockets opened are to 127.0.0.1 fakes this test starts.
"""
import base64
import gzip
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
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
WEBDIR = REPO / "solvers" / "web"
SCRATCH = Path(tempfile.mkdtemp(prefix="wave3-proofdecode-"))

FAILS = []


try:
    import pytest

    @pytest.fixture(autouse=True)
    def _huntress_event(monkeypatch):
        """proof_<32 hex> is the Huntress event's proof token (events/huntress/event.toml [proof])."""
        monkeypatch.setenv("CTF_EVENT", "huntress")
except ImportError:                          # run as a script: set it for the whole process
    os.environ["CTF_EVENT"] = "huntress"


def check(name, ok, detail=""):
    if not ok:
        FAILS.append(name)
    print(("ok   " if ok else "FAIL ") + name + ("" if ok or not detail else f"  [{str(detail)[:600]}]"),
          flush=True)


def load():
    for m in ("proof_hunt",):
        sys.modules.pop(m, None)
    spec = importlib.util.spec_from_file_location("proof_hunt", WEBDIR / "proof_hunt.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


PH = load()


def proof():
    """A fresh value of the judged form (proof_ + a v4-UUID's hex); uuid4 sets the 13th/17th nibbles."""
    p = "proof_" + uuid.uuid4().hex
    assert PH.is_proof(p), p
    return p


# --- encoders used by the fakes (the layers the sweep must peel) -----------------------------------------
def b64(s):
    return base64.b64encode(s.encode()).decode()


def b64url(s):
    return base64.urlsafe_b64encode(s.encode()).decode().rstrip("=")


def gz_b64(s):
    return base64.b64encode(gzip.compress(s.encode())).decode()


def hexs(s):
    return s.encode().hex()


def layer5(s):
    """Five base64 layers deep: beyond the depth-4 bound, so NOT recovered."""
    b = s.encode()
    for _ in range(5):
        b = base64.b64encode(b)
    return b.decode()


# ---------------------------------------------------------------------------------------------------------
#  Loopback fake: routes return (status, ctype, body[, headers]); every method is recorded.
# ---------------------------------------------------------------------------------------------------------
class Site:
    def __init__(self, routes, default=None):
        self.routes = routes
        self.default = default or (lambda p, q: (404, "text/html", "<p>not found</p>", {}))
        self.hits = []
        self.lock = threading.Lock()

    def handle(self, method, raw):
        with self.lock:
            self.hits.append((method, raw))
        path = raw.partition("?")[0]
        fn = self.routes.get(path) or self.default
        r = fn(path, []) if callable(fn) else fn
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

        do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = _go

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/"


_POST_CALLS = []


# The route a decoded proof arrives on must be a PAYOFF (exploit/payoff answer), not a landing/recon/plain
# page (new-code audit H2): a decoded proof is gated exactly like a plaintext one, so an encoded proof on a
# plain page is a decoy and is NOT banked. PAYOFF_ROUTE is named in each recovery test's prompt, so the hunter
# fetches it as a `promptroute` payoff; the proof sits there, and the landing page `/` stays plain.
PAYOFF_ROUTE = "/vault/export"
PAYOFF_QUESTION = f"Recover the proof from Target 1 at {PAYOFF_ROUTE}."


def run_site(site, label="t", question="Recover the proof from Target 1."):
    """Serve `site`, run solve_targets once, return (flag, row, methods). Wraps _Hunter._post to prove the
    decode path never POSTs. `question` is the target prompt (name a route in it to have that route fetched
    as a payoff)."""
    srv, url = serve(site)
    log_dir = SCRATCH / (label + "-" + str(srv.server_address[1]))
    log_dir.mkdir(parents=True, exist_ok=True)
    orig_post = PH._Hunter._post

    def guarded_post(self, *a, **k):
        _POST_CALLS.append(label)
        return orig_post(self, *a, **k)

    PH._Hunter._post = guarded_post
    try:
        out = PH.solve_targets([{"answer_id": "proof-1", "url": url, "index": 1,
                                 "question": question}],
                               {"deadline": time.time() + 20, "max_requests": 400,
                                "log_dir": str(log_dir), "challenge": label, "prompt": question})
    finally:
        PH._Hunter._post = orig_post
        srv.shutdown()
        srv.server_close()
    row = {}
    jl = log_dir / "proof_hunt.jsonl"
    if jl.is_file():
        for line in jl.read_text().splitlines():
            try:
                row = json.loads(line)
            except Exception:
                pass
    return out.get("proof-1"), row, [m for m, _ in site.hits]


def landing(extra_headers=None, body="<html><body><h1>welcome</h1></body></html>"):
    hdrs = dict(extra_headers or {})
    return lambda p, q: (200, "text/html", body, hdrs)


def payoff_site(carrier, extra_routes=None):
    """A Site whose landing page `/` is a plain page with no proof and whose PAYOFF_ROUTE returns `carrier`
    (a (status, ctype, body[, headers]) tuple or a route fn). The recovery tests pass PAYOFF_QUESTION so the
    hunter fetches PAYOFF_ROUTE as a payoff."""
    routes = {"/": landing(), PAYOFF_ROUTE: carrier}
    routes.update(extra_routes or {})
    return Site(routes)


# ---------------------------------------------------------------------------------------------------------
#  Part 1: recovery of a layer-encoded proof that came back on a PAYOFF page (no plaintext proof anywhere).
#  The proof sits on PAYOFF_ROUTE (fetched as a payoff because the prompt names it); the landing page is plain.
# ---------------------------------------------------------------------------------------------------------
def test_header():
    p = proof()
    site = payoff_site((200, "text/html", "<p>export</p>", {"X-Debug-Token": b64(p)}))
    flag, row, methods = run_site(site, "header", PAYOFF_QUESTION)
    check("header: a base64 proof in a payoff response header is recovered", flag == p, flag)
    check("header: GET-only, no POST", set(methods) == {"GET"} and _POST_CALLS == [], (sorted(set(methods)),
          _POST_CALLS))
    check("header: the row marks it decoded (shape=decoded)", row.get("decoded") is True
          and row.get("shape") == "decoded", row)


def test_json_gzip():
    p = proof()
    site = payoff_site((200, "application/json", json.dumps({"ok": True, "note": gz_b64(p), "n": 7}), {}))
    flag, _, methods = run_site(site, "jsongz", PAYOFF_QUESTION)
    check("json: a gzip+base64 proof in a payoff JSON field is recovered (2 layers)", flag == p, flag)
    check("json: GET-only, no POST", set(methods) == {"GET"} and _POST_CALLS == [], sorted(set(methods)))


def test_cookie_b64url():
    p = proof()
    site = payoff_site((200, "text/html", "<p>ok</p>", {"Set-Cookie": f"sess={b64url(p)}; Path=/; HttpOnly"}))
    flag, _, _ = run_site(site, "cookie", PAYOFF_QUESTION)
    check("cookie: a base64url proof in a payoff Set-Cookie value is recovered", flag == p, flag)


def test_pre_hex():
    p = proof()
    body = f"<html><body><pre>{hexs(p)}</pre></body></html>"
    site = payoff_site((200, "text/html", body, {}))
    flag, _, _ = run_site(site, "prehex", PAYOFF_QUESTION)
    check("pre/hex: a hex proof in a payoff <pre> block is recovered", flag == p, flag)


def test_data_uri():
    p = proof()
    body = f'<html><body><img src="data:application/octet-stream;base64,{b64(p)}"></body></html>'
    site = payoff_site((200, "text/html", body, {}))
    flag, _, _ = run_site(site, "datauri", PAYOFF_QUESTION)
    check("data-uri: a base64 proof in a payoff data: URI is recovered", flag == p, flag)


# ---------------------------------------------------------------------------------------------------------
#  Part 2: the novel-payoff rule decides, and the payoff gate refuses a plain-page-only decoy (audit H2)
# ---------------------------------------------------------------------------------------------------------
def test_decoy_nonproof():
    # a base64 blob that decodes to text that is NOT the judged proof form (on a payoff route)
    decoy = b64("this is not a proof, just a long note for the operator team here")
    site = payoff_site((200, "text/html", "<p>ok</p>", {"X-Note": decoy}))
    flag, row, methods = run_site(site, "decoy", PAYOFF_QUESTION)
    check("decoy: a base64 value that decodes to a non-proof is None", flag is None, flag)
    check("decoy: not marked decoded", not row.get("decoded"), row)
    check("decoy: GET-only, no POST", set(methods) == {"GET"} and _POST_CALLS == [], sorted(set(methods)))


def test_decoy_on_plain_page_not_banked():
    # new-code audit H2: a base64 proof encoded on a PLAIN/recon page (the landing page `/`), with no
    # plaintext proof anywhere, is a decoy and must NOT be banked -- exactly as the same proof in plaintext
    # there is refused by answer() (pay != seen). Before the fix _recover_decoded banked it.
    p = proof()
    site = Site({"/": landing({"X-Debug-Token": b64(p)})})   # the proof is on the plain landing page only
    flag, row, methods = run_site(site, "plaindecode")        # default prompt: PAYOFF_ROUTE is NOT named
    check("audit H2: an encoded proof on a plain page is NOT banked", flag is None, flag)
    check("audit H2: not marked decoded", not row.get("decoded"), row)
    check("audit H2: GET-only, no POST", set(methods) == {"GET"} and _POST_CALLS == [], sorted(set(methods)))


def _bare_hunter():
    """A _Hunter with just the attributes the A3 recovery path reads, to unit-test _decode_tokens /
    _recover_decoded over hand-placed pages (no server)."""
    h = PH._Hunter.__new__(PH._Hunter)
    h.lock = threading.RLock()
    h.pages, h.seen, h.payoff, h.plain = {}, {}, {}, set()
    h.host, h.stopped, h.decoded, h.shape, h.where = "target.local", None, None, None, None
    h.candidates = []
    return h


def test_injection_detector_decoy_not_banked():
    # new-code audit H11: the wave-9 breadth/injection detectors (shape in BREADTH_CLASSES) are
    # detect-only. A proof_ value that exists ONLY because a detector injected an operator (the NoSQL
    # `$ne` oracle probe) must NEVER become the hunt's plain answer -- it is a crafted signal, not a
    # flag read from an exploit on the target. _decode_tokens leaves every such page out of the sweep,
    # so A3 cannot recover it -- true even if the detector page were (wrongly) flagged payoff.
    p = proof()
    for payoff in (False, True):
        h = _bare_hunter()
        h.pages["/search?q[$ne]=znone0\x00nq:boolean"] = {
            "path": "/search?q[$ne]=znone0", "status": 200, "text": "results: " + b64(p),
            "shape": "nosql", "tag": "nq:boolean", "payoff": payoff, "headers": {}, "ctype": "text/plain"}
        check(f"audit H11: a $ne-detector-surfaced decoy is not recovered (payoff={payoff})",
              h._recover_decoded() is None, h._recover_decoded())
        check(f"audit H11: _finish does not bank it (payoff={payoff})", h._finish("wave8") is None, h.decoded)
    # control: the SAME encoded proof on a genuine payoff (exploit) page IS recovered, so the exclusion
    # is narrow (breadth-detector shapes only) and the legit recovery path is untouched.
    h = _bare_hunter()
    h.pages["/vault/export"] = {"path": "/vault/export", "status": 200, "text": "export: " + b64(p),
                                "shape": "promptroute", "tag": None, "payoff": True,
                                "headers": {}, "ctype": "text/plain"}
    check("audit H11 control: the same encoded proof on an exploit payoff page IS recovered",
          h._recover_decoded() == p, h._recover_decoded())


def test_double_proof():
    # two different proofs, each decoded from a PAYOFF page -> None by the one-proof rule
    a, b = proof(), proof()
    assert a != b
    site = payoff_site((200, "text/html", "<p>ok</p>", {"X-Debug-Token": b64(a)}),
                       extra_routes={"/vault/dump": (200, "application/json", json.dumps({"note": gz_b64(b)}), {})})
    flag, _, _ = run_site(site, "double", f"Recover the proof from Target 1 at {PAYOFF_ROUTE} and /vault/dump.")
    check("double: two different decoded proofs are None (one-proof rule)", flag is None, flag)


def test_plain_decoy_beside_encoded():
    # a plaintext proof-like DECOY on the landing page + an encoded real proof on a payoff route:
    # subtract the baseline decoy and return the one distinct novel payoff.
    decoy_plain = "proof_" + uuid.uuid4().hex   # a proof-like value shown on a plain page is a decoy
    real = proof()
    body = f"<html><body><p>ref {decoy_plain}</p></body></html>"
    site = payoff_site((200, "text/html", "<p>ok</p>", {"X-Debug-Token": b64(real)}),
                       extra_routes={"/": landing(body=body)})
    flag, row, _ = run_site(site, "plaindecoy", PAYOFF_QUESTION)
    check("plain-decoy: a baseline decoy does not hide one novel encoded payoff", flag == real, flag)
    check("plain-decoy: the novel payoff is marked decoded", row.get("decoded") is True, row)


def test_decoded_offhost_url_not_banked():
    p = proof()
    encoded = b64(p)
    for carrier in (
            {"text": f"See https://evil.invalid/callback?token={encoded}", "headers": {}},
            {"text": f"See ftp://evil.invalid/callback?token={encoded}", "headers": {}},
            {"text": f"See //evil.invalid/callback?token={encoded}", "headers": {}},
            {"text": f"See https%3A%2F%2Fevil.invalid%2Fcallback%3Ftoken%3D{encoded}", "headers": {}},
            {"text": "redirecting", "headers": {"Location": f"https://evil.invalid/callback?token={encoded}"}},
    ):
        h = _bare_hunter()
        h.pages["/vault/export"] = {
            "path": "/vault/export", "status": 200, "text": carrier["text"],
            "shape": "promptroute", "tag": None, "payoff": True,
            "headers": carrier["headers"], "ctype": "text/plain",
        }
        check("off-host decode: an encoded proof inside an external URL is ignored",
              h._recover_decoded() is None, carrier)

    for carrier in (f"ftp://evil.invalid/{p}", f"//evil.invalid/{p}",
                    f"https%3A%2F%2Fevil.invalid%2F{p}",
                    f"https:\\/\\/evil.invalid\\/{p}",
                    f"https:\\u002f\\u002fevil.invalid\\u002f{p}",
                    f"https:&#47;&#47;evil.invalid&#47;{p}",
                    f"https:&#x2f;&#x2f;evil.invalid&#x2f;{p}"):
        check("off-host plaintext: arbitrary/encoded external URL carrier is ignored",
              not PH.scan_for_proofs(carrier, "target.local"), carrier)
    for depth in (4, 6, 10, 13):
        encoded_host = "https://evil.invalid"
        for _ in range(depth):
            encoded_host = urllib.parse.quote(encoded_host, safe="")
        carrier = encoded_host + "/" + p
        check(f"off-host plaintext: {depth}x-encoded carrier fails closed",
              not PH.scan_for_proofs(carrier, "target.local"), carrier)
    for index, carrier in enumerate((
            "https:" + "\\" + "evil.invalid\\" + p,
            "https:" + "\\\\" + "evil.invalid\\" + p,
            "\\\\" + "evil.invalid\\" + p,
            "http:////evil.invalid/" + p,
            "https:///evil.invalid/" + p,
            "http:/" + "\\" + "evil.invalid/" + p,
            "http:" + "\\" + "/evil.invalid/" + p)):
        check(f"off-host plaintext: backslash-authority carrier {index} fails closed",
              not PH.scan_for_proofs(carrier, "target.local"), carrier)

    # Keep the exclusion narrow: a value inside a URL on the target's own host
    # is still target-returned evidence and remains decodable.
    h = _bare_hunter()
    h.pages["/vault/export"] = {
        "path": "/vault/export", "status": 200,
        "text": f"See https://target.local/callback?token={encoded}",
        "shape": "promptroute", "tag": None, "payoff": True,
        "headers": {}, "ctype": "text/plain",
    }
    check("off-host decode: a same-host absolute URL remains eligible",
          h._recover_decoded() == p, h._recover_decoded())


def test_zero_request_budget_is_literal():
    for budget in (0, -1):
        hunter = PH._Hunter("http://127.0.0.1:9/", max_requests=budget)
        check(f"budget {budget}: constructor preserves exhausted budget",
              hunter.max_requests == 0, hunter.max_requests)
        out = PH.solve_targets(
            [{"answer_id": "proof-1", "url": "http://127.0.0.1:9/", "index": 1,
              "question": "Recover the proof."}],
            {"max_requests": budget, "deadline": time.time() + 5})
        check(f"budget {budget}: solve sends nothing and returns None",
              out == {"proof-1": None}, out)


def test_decoded_strict_beside_future_candidate_is_ambiguous():
    p = proof()
    future = "proof_future-format-2026"
    body = json.dumps({"ok": True, "evidence": future, "blob": b64(p)})
    site = payoff_site((200, "application/json", body, {}))
    flag, row, _ = run_site(site, "decoded-ambiguous", PAYOFF_QUESTION)
    check("decoded ambiguity: a strict encoded proof beside a future-format payoff is not auto-banked",
          flag is None, flag)
    check("decoded ambiguity: the future-format value is surfaced for the agent",
          future in json.dumps(row.get("candidates") or []), row)


def test_plain_strict_beside_future_candidate_is_ambiguous():
    p = proof()
    future = "proof_future-format-plain-2026"
    body = json.dumps({"ok": True, "proof": p, "evidence": future})
    site = payoff_site((200, "application/json", body, {}))
    flag, row, _ = run_site(site, "plain-ambiguous", PAYOFF_QUESTION)
    check("plaintext ambiguity: a strict proof beside a future-format payoff is not auto-banked",
          flag is None, flag)
    check("plaintext ambiguity: the future-format value is surfaced for the agent",
          future in json.dumps(row.get("candidates") or []), row)


# ---------------------------------------------------------------------------------------------------------
#  Part 3: bounds and GET-only invariance
# ---------------------------------------------------------------------------------------------------------
def test_depth_bound():
    p = proof()
    site = payoff_site((200, "text/html", "<p>ok</p>", {"X-Deep": layer5(p)}))   # 5 base64 layers: past depth 4
    flag, _, _ = run_site(site, "deep", PAYOFF_QUESTION)
    check("bound: a proof five base64 layers deep is NOT recovered (depth <= 4)", flag is None, flag)


def test_get_only_request_count_unchanged():
    # the sweep is pure post-processing: a benign payoff route and one whose header hides an encoded proof
    # make the SAME requests (the encoded proof adds no request, and all are GETs). Both name PAYOFF_ROUTE.
    benign = payoff_site((200, "text/html", "<p>export</p>", {}))
    f1, _, m1 = run_site(benign, "benign", PAYOFF_QUESTION)
    enc = payoff_site((200, "text/html", "<p>export</p>", {"X-Debug-Token": b64(proof())}))
    f2, _, m2 = run_site(enc, "enc", PAYOFF_QUESTION)
    check("get-only: the benign site banks nothing", f1 is None, f1)
    check("get-only: the encoded site banks a proof", PH.is_proof(f2), f2)
    check("get-only: the encoded proof adds no request (same GET count, all GET)",
          len(m1) == len(m2) and set(m1) == {"GET"} and set(m2) == {"GET"}, (len(m1), len(m2)))
    check("get-only: _Hunter._post never called across the whole run", _POST_CALLS == [], _POST_CALLS)


# ---------------------------------------------------------------------------------------------------------
#  Part 4: the decoder units (direct, no network)
# ---------------------------------------------------------------------------------------------------------
def test_decoder_units():
    p = proof()
    for label, enc in (("base64", b64(p)), ("base64url", b64url(p)), ("base32",
                        base64.b32encode(p.encode()).decode()), ("hex", hexs(p)), ("gzip+base64", gz_b64(p)),
                        ("zlib+base64", base64.b64encode(__import__("zlib").compress(p.encode())).decode()),
                        ("url+hex", urllib.parse.quote(hexs(p)))):
        leaves = [bytes(l).decode("latin-1", "ignore") for l in PH._decode_tree(enc)]
        got = any(p in l for l in leaves)
        check(f"unit[{label}]: the ladder peels it to the proof", got, enc[:40])
    # a run of random hex that is not a proof yields no strict proof
    junk = PH._decode_tree(b64("just some operator notes, nothing structured in here at all"))
    strict = [l for l in (bytes(x).decode("latin-1", "ignore") for x in junk) if PH.PROOF_FORMAT.search(l)]
    check("unit[junk]: a non-proof blob yields no strict proof", strict == [], strict)
    oversized = b"A" * (PH.DECODE_MAX_OUTPUT + 1)
    gzip_bomb = gzip.compress(oversized, compresslevel=9)
    zlib_bomb = __import__("zlib").compress(oversized, level=9)
    check("unit[gzip-bound]: expansion beyond the cap is rejected, not sliced after full inflation",
          PH._d_gzip(gzip_bomb) is None, len(gzip_bomb))
    check("unit[zlib-bound]: expansion beyond the cap is rejected, not sliced after full inflation",
          PH._d_zlib(zlib_bomb) == [], len(zlib_bomb))


def main():
    for fn in (test_header, test_json_gzip, test_cookie_b64url, test_pre_hex, test_data_uri,
               test_decoy_nonproof, test_decoy_on_plain_page_not_banked,
               test_injection_detector_decoy_not_banked, test_double_proof,
               test_plain_decoy_beside_encoded, test_decoded_offhost_url_not_banked,
               test_zero_request_budget_is_literal,
               test_decoded_strict_beside_future_candidate_is_ambiguous,
               test_plain_strict_beside_future_candidate_is_ambiguous, test_depth_bound,
               test_get_only_request_count_unchanged, test_decoder_units):
        try:
            fn()
        except Exception as e:
            check(fn.__name__, False, repr(e))
    if os.environ.get("TEST_KEEP") != "1":
        shutil.rmtree(SCRATCH, ignore_errors=True)
    print(("RESULT PASS (0 failed)" if not FAILS else f"RESULT FAIL: {len(FAILS)} -> {FAILS}"), flush=True)
    sys.exit(1 if FAILS else 0)


if __name__ == "__main__":
    main()
