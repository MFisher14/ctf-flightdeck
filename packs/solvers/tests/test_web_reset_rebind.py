#!/usr/bin/env python3
"""Local-only regressions for the bounded Day-17 reset-token rebind reader."""

from __future__ import annotations

import event_pin  # noqa: E402  (tests/event_pin.py)
event_pin.pin(globals(), "huntress")  # Huntress web tests: proof_<32 hex> payoffs (events/huntress [proof])

import contextlib
import hashlib
import importlib.util
import json
import os
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
WEB = REPO / "solvers" / "web"
TOOLKITS = REPO / "solvers" / "toolkits"
sys.dont_write_bytecode = True
sys.path[:0] = [str(WEB), str(TOOLKITS)]
TOKEN_SENTINEL = "TEST_GM_TOKEN_MUST_NEVER_REACH_TARGET"
os.environ["CTF_TOKEN"] = TOKEN_SENTINEL

spec = importlib.util.spec_from_file_location("reset_rebind_test", WEB / "reset_rebind.py")
assert spec and spec.loader
RR = importlib.util.module_from_spec(spec)
spec.loader.exec_module(RR)

FAILS = []


def check(name, condition, detail=""):
    print(("ok   " if condition else "FAIL ") + name + ("" if condition else f" [{detail}]"))
    if not condition:
        FAILS.append(name)


def proof(label):
    return "proof_" + hashlib.sha256(label.encode()).hexdigest()[:32]


class Site:
    def __init__(self, *, p=None, clues=None, guide=None, issue=None, redeem=None, clues_status=200):
        self.p = p or proof("reset-rebind")
        self.clues = clues if clues is not None else {
            "framework": "Symfony", "feature_route": "/submit-a1", "secondary_route": "/result-b2",
            "recovery_guide_route": "/api/recovery", "current_role": "analyst",
        }
        self.guide = guide if guide is not None else {
            "request_route": "/submit-a1", "redeem_route": "/result-b2",
            "account_parameter": "account_id", "token_parameter": "token",
            "accounts": [{"id": 7673, "label": "self", "self_service": True},
                         {"id": 10693, "label": "executive", "self_service": False}],
        }
        self.issue = issue
        self.redeem = redeem
        self.clues_status = clues_status
        self.calls = []

    @staticmethod
    def reply(status, value):
        return status, json.dumps(value, separators=(",", ":")).encode(), {"Content-Type": "application/json"}

    def handle(self, method, raw, headers):
        self.calls.append({"method": method, "path": raw, "headers": headers})
        split = urllib.parse.urlsplit(raw)
        params = dict(urllib.parse.parse_qsl(split.query, keep_blank_values=True))
        if method != "GET":
            return self.reply(405, {"error": "method_not_allowed"})
        if split.path == "/":
            return self.reply(200, {"page": "recovery lab"})
        if split.path == "/api/clues":
            return self.reply(self.clues_status, self.clues)
        guide_path = urllib.parse.urlsplit(str(self.clues.get("recovery_guide_route") or "")).path
        if split.path == guide_path:
            return self.reply(200, self.guide)
        request_path = urllib.parse.urlsplit(str(self.guide.get("request_route") or "")).path
        redeem_path = urllib.parse.urlsplit(str(self.guide.get("redeem_route") or "")).path
        ap = self.guide.get("account_parameter", "account_id")
        tp = self.guide.get("token_parameter", "token")
        if split.path == request_path:
            if callable(self.issue):
                return self.reply(*self.issue(params))
            return self.reply(200, {"ok": True, ap: params.get(ap), tp: "f80e3be6288d",
                                    "redeem_route": self.guide.get("redeem_route")})
        if split.path == redeem_path:
            if callable(self.redeem):
                return self.reply(*self.redeem(params))
            return self.reply(200, {"ok": True, "effect": "synthetic_account_recovery",
                                    ap: params.get(ap), "evidence": self.p})
        return self.reply(404, {"error": "not_found"})


@contextlib.contextmanager
def served(site):
    class Handler(BaseHTTPRequestHandler):
        def go(self):
            status, body, headers = site.handle(self.command, self.path, dict(self.headers.items()))
            self.send_response(status)
            for key, value in headers.items():
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except OSError:
                pass

        do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = go

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


# SH-10: the reader's deadline arithmetic (time.time() in reset_rebind) reads a step clock in run(): it starts
# at the real time and moves REQUEST_STEP seconds for each request the fake site has answered, so a deadline
# is spent by requests, not by waiting for a core. Under the suite's load three loopback GETs once took
# longer than the 5 s deadline and a fail-closed case stopped after two (camelCase /deleteUser). The
# sockets' own timeouts stay real. The clock's start is read before the fake site starts, and run() takes its
# deadline as an offset from that start (deadline_in), so the site's startup time is never charged to it.
REQUEST_STEP = 0.05


class _StepTime:
    """A stand-in for the `time` module inside reset_rebind: time() is the step clock, the rest is real."""

    def __init__(self, start, site):
        self.start, self.site = start, site

    def time(self):
        return self.start + REQUEST_STEP * len(self.site.calls)

    def __getattr__(self, name):
        return getattr(time, name)


@contextlib.contextmanager
def engine_clock(site, start):
    saved = RR.time
    RR.time = _StepTime(start, site)
    try:
        yield
    finally:
        RR.time = saved


def run(site, deadline_in=5, **ctx):
    """RR.solve against the fake site; its deadline is `deadline_in` step-clock seconds after the clock's start."""
    start = time.time()
    with served(site) as base:
        meta, evidence = {}, []
        context = {"deadline": start + deadline_in, "max_requests": 8, "result_sink": meta,
                   "evidence": evidence, **ctx}
        with engine_clock(site, start):
            got = RR.solve({"answer_id": "proof-1", "url": base}, context)
        return got, meta.get("proof-1", {}), evidence, list(site.calls), base


def test_happy_and_transport():
    site = Site()
    got, meta, _, calls, base = run(site)
    check("reset happy: exact proof", got == site.p, (got, meta))
    check("reset happy: five bounded GETs and one issue/one redeem",
          len(calls) == 5 and meta.get("requests") == 5 and meta.get("issue_requests") == 1
          and meta.get("redeem_requests") == 1 and all(c["method"] == "GET" for c in calls), calls)
    check("reset transport: only target origin and no Game Master authorization",
          all(c["path"].startswith("/") and TOKEN_SENTINEL not in str(c) for c in calls)
          and "2026.huntress.ctf.games" not in str(calls), (base, calls))
    check("reset one shot: final request is victim redeem",
          urllib.parse.parse_qs(urllib.parse.urlsplit(calls[-1]["path"]).query).get("account_id") == ["10693"],
          calls[-1])


def test_contract_variants_and_preload():
    p = proof("renamed")
    site = Site(p=p, clues={"framework": "X", "feature_route": "/ask-9", "secondary_route": "/use-8",
                               "recovery_guide_route": "/contract-7"},
                guide={"request_route": "/ask-9", "redeem_route": "/use-8",
                       "account_parameter": "subject", "token_parameter": "recovery_code",
                       "accounts": [{"id": "mine", "self_service": True},
                                    {"id": "theirs", "self_service": False}]})
    with served(site) as base:
        meta = {}
        preloaded = {
            "/": {"status": 200, "body": b'{"page":"control"}'},
            "/api/clues": {"status": 200, "body": json.dumps(site.clues).encode()},
        }
        got = RR.solve({"answer_id": "p", "url": base}, {"deadline": time.time() + 5,
                       "max_requests": 3, "preloaded": preloaded, "baseline_texts": ["control"],
                       "result_sink": meta})
    check("reset variant: advertised route/param/string ids", got == p, (got, site.calls))
    check("reset integration: preloaded wave1 costs only guide+issue+redeem",
          len(site.calls) == 3 and meta["p"]["requests"] == 3, (site.calls, meta))


def test_fail_closed_contracts():
    cases = []
    cases.append(("no recovery guide", Site(clues={"feature_route": "/submit-a1"}), 2))
    cases.append(("off-host guide", Site(clues={"recovery_guide_route": "https://evil.invalid/g"}), 2))
    cases.append(("non-2xx clue JSON", Site(clues_status=403), 2))
    many = Site()
    many.guide["accounts"].insert(1, {"id": 2, "self_service": True})
    cases.append(("multiple sources", many, 3))
    malformed = Site()
    malformed.guide["accounts"][1]["self_service"] = "false"
    cases.append(("non-boolean account policy", malformed, 3))
    mismatch = Site()
    mismatch.clues["feature_route"] = "/different"
    cases.append(("route disagreement", mismatch, 3))
    destructive = Site()
    destructive.guide["redeem_route"] = "/delete-account"
    destructive.clues["secondary_route"] = "/delete-account"
    cases.append(("destructive advertised route", destructive, 3))
    for route in ("/transferFunds", "/deleteUser", "/removeAccount", "/createUser",
                  "/updateProfile", "/payBill", "/shutdownNow", "/runTask"):
        destructive = Site()
        destructive.guide["redeem_route"] = route
        destructive.clues["secondary_route"] = route
        cases.append(("camelCase destructive advertised route " + route, destructive, 3))
    oversized = Site(clues={"recovery_guide_route": "/" + "g" * (RR.MAX_ROUTE_BYTES + 1)})
    cases.append(("oversized guide route", oversized, 2))
    query_guide = Site()
    query_guide.clues["recovery_guide_route"] = "/api/recovery?url=http%3A%2F%2Finternal%2F"
    cases.append(("guide route with target-authored query", query_guide, 2))
    query_request = Site()
    query_request.guide["request_route"] = "/submit-a1?action=issue"
    query_request.clues["feature_route"] = "/submit-a1?action=issue"
    cases.append(("request route with target-authored query", query_request, 3))
    query_redeem = Site()
    query_redeem.guide["redeem_route"] = "/result-b2?url=http%3A%2F%2Finternal%2F"
    query_redeem.clues["secondary_route"] = "/result-b2?url=http%3A%2F%2Finternal%2F"
    cases.append(("redeem route with target-authored query", query_redeem, 3))
    for label, site, count in cases:
        got, meta, _, calls, _ = run(site)
        check(f"reset contract: {label} => inert", got is None and len(calls) == count
              and meta.get("issue_requests") == 0 and meta.get("redeem_requests") == 0, (calls, meta))


def test_issue_and_redeem_rejections():
    issue_bad = Site(issue=lambda _q: (200, {"ok": True, "account_id": 9999, "token": "abc"}))
    got, meta, _, calls, _ = run(issue_bad)
    check("reset issue echo mismatch: no redeem", got is None and len(calls) == 4
          and meta.get("issue_requests") == 1 and meta.get("redeem_requests") == 0, (calls, meta))

    p = proof("rejected-decoy")
    denied = Site(p=p, redeem=lambda q: (403, {"ok": False, "error": "denied", "evidence": p,
                                             "account_id": q.get("account_id")}))
    got, meta, _, calls, _ = run(denied)
    check("reset rejected redeem with proof decoy: None and no retry", got is None and len(calls) == 5
          and meta.get("redeem_requests") == 1, (got, calls, meta))

    issued_query = Site(issue=lambda q: (200, {"ok": True, "account_id": q.get("account_id"), "token": "abc",
                                               "redeem_route": "/result-b2?action=redeem"}))
    got, meta, _, calls, _ = run(issued_query)
    check("reset issue cannot introduce a query-bearing redeem route", got is None and len(calls) == 4
          and meta.get("issue_requests") == 1 and meta.get("redeem_requests") == 0, (calls, meta))


def test_proof_policy():
    landing_decoy, real = proof("landing-decoy"), proof("novel-payoff")
    site = Site(p=real)
    original = site.handle

    def with_decoy(method, raw, headers):
        if urllib.parse.urlsplit(raw).path == "/":
            site.calls.append({"method": method, "path": raw, "headers": headers})
            return site.reply(200, {"evidence": landing_decoy, "page": "plain"})
        return original(method, raw, headers)

    site.handle = with_decoy
    got, _, _, _, _ = run(site)
    check("reset proof policy: distinct baseline decoy does not hide novel payoff", got == real, got)

    p1, p2 = proof("ambiguous-1"), proof("ambiguous-2")
    ambiguous = Site(redeem=lambda q: (200, {"ok": True, "effect": "synthetic_account_recovery",
                                             "account_id": q.get("account_id"), "proof": p1,
                                             "evidence": p2}))
    got, meta, evidence, calls, _ = run(ambiguous)
    check("reset proof policy: two novel proofs => None", got is None and len(calls) == 5
          and len(meta.get("candidates") or []) >= 2, (got, meta, evidence))

    future = "evidence-FUTURE_2026:abcd"
    odd = Site(redeem=lambda q: (200, {"ok": True, "effect": "synthetic_account_recovery",
                                       "account_id": q.get("account_id"), "evidence": future}))
    got, meta, evidence, _, _ = run(odd)
    check("reset proof policy: future shape surfaced, never returned", got is None and future in str(evidence)
          and future in str(meta.get("candidates")), (got, meta, evidence))

    class MultipartRedeem(Site):
        def __init__(self, split):
            super().__init__(p=proof("multipart-redeem"))
            self.split = split

        def handle(self, method, raw, headers):
            path = urllib.parse.urlsplit(raw).path
            redeem_path = urllib.parse.urlsplit(str(self.guide.get("redeem_route") or "")).path
            if method == "GET" and path == redeem_path:
                self.calls.append({"method": method, "path": raw, "headers": headers})
                params = dict(urllib.parse.parse_qsl(
                    urllib.parse.urlsplit(raw).query, keep_blank_values=True))
                doc = {"ok": True, "effect": "synthetic_account_recovery",
                       "account_id": params.get("account_id")}
                if not self.split:
                    doc["evidence"] = self.p
                boundary = "reset-carriers"
                first = self.p if self.split else "diagnostic only"
                body = (f"--{boundary}\r\nContent-Type: text/plain\r\n\r\n{first}\r\n"
                        f"--{boundary}\r\nContent-Type: application/json\r\n\r\n"
                        + json.dumps(doc, separators=(",", ":")) + "\r\n"
                        f"--{boundary}--\r\n").encode()
                return 200, body, {"Content-Type": f"multipart/mixed; boundary={boundary}"}
            return super().handle(method, raw, headers)

    got, meta, evidence, calls, _ = run(MultipartRedeem(split=True))
    check("reset proof policy: success JSON cannot bless a proof in a MIME sibling",
          got is None and len(calls) == 5 and meta.get("candidates"), (got, meta, evidence))
    coherent = MultipartRedeem(split=False)
    got, meta, _, calls, _ = run(coherent)
    check("reset proof policy: success and proof in one JSON member remain eligible",
          got == coherent.p and len(calls) == 5, (got, meta))


def test_bounds_and_switch():
    class WrongScope:
        base = "http://other.invalid/"

        def __init__(self):
            self.calls = []

        def request(self, *args, **kwargs):
            self.calls.append((args, kwargs))
            raise AssertionError("mismatched client must not be called")

    wrong = WrongScope()
    meta = {}
    got = RR.solve({"answer_id": "proof-1", "url": "http://target.invalid/"},
                   {"client": wrong, "deadline": time.time() + 2, "max_requests": 8,
                    "result_sink": meta})
    check("reset client scope: mismatch is refused with no real-client fallback",
          got is None and not wrong.calls and meta["proof-1"].get("requests") == 0,
          (got, wrong.calls, meta))

    long_redeem = "/" + "r" * 900
    combined = Site(
        clues={"feature_route": "/submit-a1", "secondary_route": long_redeem,
               "recovery_guide_route": "/api/recovery"},
        guide={"request_route": "/submit-a1", "redeem_route": long_redeem,
               "account_parameter": "account_id", "token_parameter": "token",
               "accounts": [{"id": 7673, "self_service": True},
                            {"id": 10693, "self_service": False}]},
        issue=lambda q: (200, {"ok": True, "account_id": q.get("account_id"),
                               "token": "x" * 256, "redeem_route": long_redeem}),
    )
    got, meta, _, calls, _ = run(combined)
    check("reset final URL guard: an overlong worst-case redeem is refused before token issue",
          got is None and len(calls) == 3 and meta.get("issue_requests") == 0
          and meta.get("redeem_requests") == 0 and all(len(c["path"].encode()) <= RR.MAX_ROUTE_BYTES
                                                       for c in calls),
          (calls, meta))

    site = Site()
    got, meta, _, calls, _ = run(site, max_requests=4)
    check("reset max_requests: issue is not sent without a reserved redeem slot",
          got is None and len(calls) == 3 and meta.get("issue_requests") == 0
          and meta.get("redeem_requests") == 0, (calls, meta))

    site = Site()
    # Deadline must stay below the solver's pair-reserve cutoff (DEADLINE_PAD + PAIR_REDEEM_RESERVE = 0.8)
    # so the issue is refused for lack of reserved redeem time, while leaving recon enough time to finish
    # all three loopback calls. On run()'s step clock recon spends 3 x REQUEST_STEP = 0.15 s of the 0.49 s
    # it has (deadline - DEADLINE_PAD), however long the site takes to start or to answer (SH-10).
    got, meta, _, calls, _ = run(site, deadline_in=0.79)
    check("reset deadline: issue is not sent without time reserved for redeem",
          got is None and len(calls) == 3 and meta.get("issue_requests") == 0
          and meta.get("redeem_requests") == 0, (calls, meta))

    site = Site()
    got, meta, _, calls, _ = run(site, deadline_in=-1)
    check("reset deadline: zero requests", got is None and not calls and meta.get("requests") == 0, (calls, meta))

    old = os.environ.get("CTF_WEB_RESET_REBIND")
    os.environ["CTF_WEB_RESET_REBIND"] = "off"
    try:
        site = Site()
        got, meta, _, calls, _ = run(site)
        check("reset kill switch: zero requests", got is None and not calls and meta.get("stopped") == "off",
              (calls, meta))
    finally:
        if old is None:
            os.environ.pop("CTF_WEB_RESET_REBIND", None)
        else:
            os.environ["CTF_WEB_RESET_REBIND"] = old


def test_solve_targets_contract():
    one, two = Site(p=proof("one")), Site(p=proof("two"))
    with served(one) as u1, served(two) as u2:
        meta = {}
        got = RR.solve_targets([{"answer_id": "proof-1", "url": u1},
                                {"answer_id": "proof-2", "url": u2}],
                               {"deadline": time.time() + 5, "max_requests": 8, "result_sink": meta})
    check("reset solve_targets: both independent targets", got == {"proof-1": one.p, "proof-2": two.p}, got)
    check("reset solve_targets: per-target request bound", all(v.get("requests") == 5 for v in meta.values()), meta)


if __name__ == "__main__":
    for test in (test_happy_and_transport, test_contract_variants_and_preload, test_fail_closed_contracts,
                 test_issue_and_redeem_rejections, test_proof_policy, test_bounds_and_switch,
                 test_solve_targets_contract):
        test()
    if FAILS:
        print(f"FAIL: {len(FAILS)} reset-rebind regression(s)")
        raise SystemExit(1)
    print("PASS: reset-rebind local fake (5 standalone requests; 3 after proof_hunt recon)")
