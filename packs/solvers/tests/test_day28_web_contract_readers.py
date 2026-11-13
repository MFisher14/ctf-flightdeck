#!/usr/bin/env python3
"""Offline Day-28 regressions for the remote-policy and audit-report readers.

No Game Master call, target request, token or network is used.  Tiny in-memory
apps implement only the target-authored contracts and log every wire method.
"""

import event_pin  # noqa: E402  (tests/event_pin.py)
event_pin.pin(globals(), "huntress")  # Huntress web tests: proof_<32 hex> payoffs (events/huntress [proof])

import base64
import json
import os
import sys
import time
import urllib.parse
import uuid
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "solvers" / "web"))
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))

import post_chain as PC  # noqa: E402
import proof_hunt as PH  # noqa: E402
import remote_policy as RP  # noqa: E402


FAILURES = []
CHECKS = [0]


def check(label, condition, detail=""):
    CHECKS[0] += 1
    print(("ok   " if condition else "FAIL ") + label
          + ("" if condition or not detail else f"  [{str(detail)[:1500]}]"))
    if not condition:
        FAILURES.append(label)


def proof():
    return "proof_" + uuid.uuid4().hex


def response(status, body, path="/", headers=None):
    if not isinstance(body, (bytes, bytearray)):
        body = json.dumps(body, separators=(",", ":")) if isinstance(body, (dict, list)) else str(body)
        body = body.encode("utf-8")
    pairs = [("Content-Type", "application/json" if bytes(body).lstrip()[:1] in (b"{", b"[")
              else "text/plain; charset=utf-8")]
    pairs.extend(list((headers or {}).items()))
    return {"status": status, "body": bytes(body), "response_header_pairs": pairs,
            "response_headers": dict(pairs), "final_url": "http://fake.local" + path}


def target():
    return {"answer_id": "proof-1", "url": "http://fake.local/", "index": 1}


class FakeBase:
    def __init__(self):
        self.base = "http://fake.local/"
        self.application_base = self.base
        self.timeout = 8.0
        self.log = []

    def request(self, method, path, data=None, headers=None, allow_redirects=True):
        self.log.append({"method": method, "path": path, "data": data,
                         "headers": dict(headers or {}), "redirects": allow_redirects})
        return self.handle(method, path, data, dict(headers or {}))

    def handle(self, method, path, data, headers):
        raise NotImplementedError

    @property
    def posts(self):
        return [row for row in self.log if row["method"] == "POST"]


class PolicyServer(FakeBase):
    def __init__(self, *, answer=None, clues=None, bad_format=False,
                 control_failopen=False, control_doc=None, wrong_effect=False, sibling_proof=None):
        super().__init__()
        self.answer = answer or proof()
        self.feature = "/submit-a1b2c3"
        self.format_route = "/api/policy-format"
        self.clues = clues if clues is not None else {
            "feature_route": self.feature,
            "policy_format_route": self.format_route,
            "current_role": "analyst",
            "expected_behavior": "deny access when the policy service is unavailable",
        }
        sample = json.dumps({"Scope": "public", "Allow": True}, separators=(",", ":")).encode()
        self.sample = base64.urlsafe_b64encode(sample).decode().rstrip("=")
        self.prefix = "remote:0123456789ab:"
        self.bad_format = bad_format
        self.control_failopen = control_failopen
        self.control_doc = control_doc
        self.wrong_effect = wrong_effect
        self.sibling_proof = sibling_proof

    def clue_response(self):
        return response(200, self.clues, "/api/clues")

    def handle(self, method, path, data, headers):
        split = urllib.parse.urlsplit(path)
        if method != "GET":
            return response(405, {"error": "method_not_allowed"}, path)
        if split.path == "/":
            return response(200, "<title>Remote Policy</title>", path)
        if split.path == "/robots.txt":
            return response(404, "not found", path)
        if split.path == "/openapi.json":
            return response(404, {"error": "not_found"}, path)
        if split.path == "/api/clues":
            return self.clue_response()
        if split.path == self.format_route:
            if self.bad_format:
                return response(200, {"query_parameter": "policy", "prefix": self.prefix,
                                      "encoding": "base64 JSON", "sample_encoded": self.sample}, path)
            return response(200, {"query_parameter": "policy", "prefix": self.prefix,
                                  "encoding": "base64url UTF-8 JSON",
                                  "sample_decision": {"scope": "public", "allow": True},
                                  "sample_encoded": self.sample}, path)
        if split.path == self.feature:
            value = dict(urllib.parse.parse_qsl(split.query, keep_blank_values=True)).get("policy", "")
            if value == self.prefix + self.sample and self.control_doc is not None:
                return response(200, self.control_doc, path)
            if value == self.prefix + self.sample and not self.control_failopen:
                return response(200, {"ok": True, "policy": "standard"}, path)
            if value == self.prefix + self.sample and self.control_failopen:
                return response(200, {"ok": True, "effect": "exceptional_condition_fail_open",
                                      "evidence": self.answer}, path)
            if value == self.prefix + "!":
                effect = "decoder_exception" if self.wrong_effect else "exceptional_condition_fail_open"
                return response(200, {"ok": True, "effect": effect, "evidence": self.answer}, path,
                                {"X-Other-Proof": self.sibling_proof} if self.sibling_proof else None)
            return response(400, {"error": "remote_policy_required"}, path)
        return response(404, {"error": "not_found"}, path)


class AuditServer(FakeBase):
    def __init__(self, *, answer=None, fields=None, report_method="POST", wrong_effect=False,
                 event_mode="normal", action_decoy=None, initial_events=None):
        super().__init__()
        self.answer = answer or proof()
        self.feature = "/process-c6f50d"
        self.secondary = "/status-40896a"
        self.export_id = "aabbccddeeff001122334455"
        self.fields = fields if fields is not None else ["export_id", "missing_event", "observed_event"]
        self.report_method = report_method
        self.wrong_effect = wrong_effect
        self.event_mode = event_mode
        self.action_decoy = action_decoy
        self.initial_events = list(initial_events or [])
        self.did_export = False

    @property
    def clues(self):
        return {"feature_route": self.feature, "secondary_route": self.secondary,
                "current_role": "analyst"}

    def _events(self):
        rows = list(self.initial_events)
        if not self.did_export:
            return rows
        if self.event_mode == "wrong_id":
            return rows + [{"export_id": "different", "event": "page_view"}]
        if self.event_mode == "ambiguous":
            return rows + [{"export_id": self.export_id, "event": "page_view", "event_type": "download"}]
        return rows + [{"export_id": self.export_id, "event": "page_view"}]

    def handle(self, method, path, data, headers):
        split = urllib.parse.urlsplit(path)
        if method == "GET" and split.path == "/":
            return response(200, "<title>Audit Forest</title>", path)
        if method == "GET" and split.path == "/robots.txt":
            return response(404, "not found", path)
        if method == "GET" and split.path == "/openapi.json":
            return response(404, {"error": "not_found"}, path)
        if method == "GET" and split.path == "/api/clues":
            return response(200, self.clues, path)
        if method == "GET" and split.path == self.feature:
            return response(405, {"error": "post_required"}, path)
        if method == "GET" and split.path == self.secondary:
            return response(200, {"ok": True, "events": self._events(),
                                  "report": {"method": self.report_method, "fields": self.fields}}, path)
        if method == "POST" and split.path == self.feature:
            try:
                doc = json.loads(data or "{}")
            except Exception:
                doc = None
            if doc != {}:
                return response(400, {"error": "invalid_body"}, path)
            self.did_export = True
            body = {"ok": True, "operation": "protected_export", "export_id": self.export_id}
            if self.action_decoy:
                body["evidence"] = self.action_decoy
            return response(200, body, path)
        if method == "POST" and split.path == self.secondary:
            try:
                doc = json.loads(data or "{}")
            except Exception:
                doc = None
            wanted = {"export_id": self.export_id, "missing_event": "protected_export",
                      "observed_event": "page_view"}
            if doc != wanted:
                return response(400, {"error": "report_mismatch"}, path)
            effect = "report_received" if self.wrong_effect else "decisive_security_event_missing"
            return response(200, {"ok": True, "effect": effect, "evidence": self.answer}, path)
        return response(404, {"error": "not_found"}, path)


def policy_ctx(server, **extra):
    ctx = {"client": server, "preloaded": {"/api/clues": server.clue_response()},
           "max_requests": 8, "result_sink": {}}
    ctx.update(extra)
    return ctx


def test_remote_policy_reader():
    server = PolicyServer()
    ctx = policy_ctx(server)
    got = RP.solve(target(), ctx)
    check("remote policy: exact contract returns the malformed-decoder proof", got == server.answer, (got, server.log))
    check("remote policy: only three GETs leave after cached clues",
          len(server.log) == 3 and {row["method"] for row in server.log} == {"GET"}, server.log)
    check("remote policy: valid sample control precedes exactly one malformed value",
          server.log[-2]["path"].endswith(urllib.parse.quote(server.prefix + server.sample, safe=""))
          and server.log[-1]["path"].endswith(urllib.parse.quote(server.prefix + "!", safe="")), server.log)
    meta = ctx["result_sink"]["proof-1"]
    check("remote policy: summary names the durable class and no POST", meta["class"] == "remote_policy_fail_open"
          and meta["posts"] == 0 and meta["success"] is True, meta)

    unrelated = PolicyServer(clues={"feature_route": "/read", "current_role": "analyst"})
    got = RP.solve(target(), policy_ctx(unrelated))
    check("remote policy negative: unrelated cached clues cost zero wire requests",
          got is None and unrelated.log == [], unrelated.log)

    bad = PolicyServer(bad_format=True)
    got = RP.solve(target(), policy_ctx(bad))
    check("remote policy negative: an inexact encoding never reaches the feature",
          got is None and [r["path"] for r in bad.log] == [bad.format_route], bad.log)

    control = PolicyServer(control_failopen=True)
    got = RP.solve(target(), policy_ctx(control))
    check("remote policy negative: a fail-open/proof-bearing valid control is never promoted",
          got is None and len(control.log) == 2, control.log)

    for label, control_doc in (
            ("explicit false", {"ok": False, "policy": "standard"}),
            ("denied status", {"ok": True, "status": "denied"})):
        denied = PolicyServer(control_doc=control_doc)
        got = RP.solve(target(), policy_ctx(denied))
        check(f"remote policy negative: {label} is not an affirmative allowed control",
              got is None and len(denied.log) == 2, denied.log)

    wrong = PolicyServer(wrong_effect=True)
    got = RP.solve(target(), policy_ctx(wrong))
    check("remote policy negative: a proof without the exact fail-open effect is refused",
          got is None and len(wrong.log) == 3, wrong.log)

    sibling = proof()
    ambiguous = PolicyServer(sibling_proof=sibling)
    got = RP.solve(target(), policy_ctx(ambiguous))
    check("remote policy negative: a second proof in a response header keeps the payoff ambiguous",
          got is None and len(ambiguous.log) == 3, (got, ambiguous.log))

    unsafe = PolicyServer(clues={"feature_route": "https://evil.invalid/read",
                                  "policy_format_route": "/api/policy-format",
                                  "current_role": "analyst",
                                  "expected_behavior": "deny access when policy service is unavailable"})
    got = RP.solve(target(), policy_ctx(unsafe))
    check("remote policy negative: an off-origin feature route costs zero requests",
          got is None and unsafe.log == [], unsafe.log)


def test_audit_report_chain():
    server = AuditServer()
    meta = {}
    got = PC.solve(target(), {"client": server, "max_requests": 20, "result_sink": meta})
    check("audit chain: exact schema derives operation/event and returns the proof",
          got == server.answer, (got, server.log))
    check("audit chain: bounded sequence is one operation POST, one fresh GET, one report POST",
          len(server.log) == 7 and [r["method"] for r in server.log[-3:]] == ["POST", "GET", "POST"], server.log)
    check("audit chain: the report body is entirely response-derived",
          json.loads(server.posts[-1]["data"]) == {"export_id": server.export_id,
                                                   "missing_event": "protected_export",
                                                   "observed_event": "page_view"}, server.posts)
    check("audit chain: summary names the class and counts two POSTs",
          meta["proof-1"]["class"] == "audit_report_chain" and meta["proof-1"]["posts"] == 2,
          meta["proof-1"])

    prior = AuditServer(initial_events=[{"export_id": "older-export", "event": "login"}])
    got = PC.solve(target(), {"client": prior, "max_requests": 20})
    check("audit chain: an unrelated pre-existing event does not hide the new correlated row",
          got == prior.answer and len(prior.posts) == 2, (got, prior.log))

    reused = AuditServer(initial_events=[{
        "export_id": "aabbccddeeff001122334455", "event": "page_view",
    }])
    got = PC.solve(target(), {"client": reused, "max_requests": 20})
    check("audit chain negative: a reused export id cannot correlate a pre-existing event",
          got is None and len(reused.posts) == 1
          and all(row["path"] != reused.secondary for row in reused.posts), reused.log)

    for label, variant in (
            ("missing report field", AuditServer(fields=["export_id", "missing_event"])),
            ("wrong report method", AuditServer(report_method="GET")),
            ("extra report field", AuditServer(fields=["export_id", "missing_event", "observed_event", "note"]))):
        got = PC.solve(target(), {"client": variant, "max_requests": 20})
        check(f"audit chain negative: {label} authorizes zero mutations",
              got is None and not variant.posts, variant.log)

    wrong_id = AuditServer(event_mode="wrong_id")
    got = PC.solve(target(), {"client": wrong_id, "max_requests": 20})
    check("audit chain negative: an uncorrelated event stops after the operation POST",
          got is None and len(wrong_id.posts) == 1, wrong_id.log)

    ambiguous = AuditServer(event_mode="ambiguous")
    got = PC.solve(target(), {"client": ambiguous, "max_requests": 20})
    check("audit chain negative: conflicting event labels stop before the report POST",
          got is None and len(ambiguous.posts) == 1, ambiguous.log)

    wrong_effect = AuditServer(wrong_effect=True)
    got = PC.solve(target(), {"client": wrong_effect, "max_requests": 20})
    check("audit chain negative: a proof without the exact missing-event effect is refused",
          got is None and len(wrong_effect.posts) == 2, wrong_effect.log)

    repeated = proof()
    decoy = AuditServer(answer=repeated, action_decoy=repeated)
    got = PC.solve(target(), {"client": decoy, "max_requests": 20})
    check("audit chain negative: an action-ack proof repeated by the final report is a baseline decoy",
          got is None and len(decoy.posts) == 2, decoy.log)

    short = AuditServer()
    got = PC.solve(target(), {
        "client": short,
        "max_requests": 20,
        "deadline": time.time() + PC.AUDIT_SEQUENCE_RESERVE - 1.0,
        "result_sink": {},
    })
    check("audit chain budget: less than three full request windows authorizes zero mutations",
          got is None and not short.posts and PC.AUDIT_SEQUENCE_RESERVE >= 3 * PC.REQUEST_TIMEOUT,
          (PC.AUDIT_SEQUENCE_RESERVE, short.log))


def _proof_hunt(server):
    original = PH._web.WebClient
    PH._web.WebClient = lambda url, timeout=8.0: server
    try:
        return PH.solve_targets([target()], {"max_requests": 30, "deadline": None})
    finally:
        PH._web.WebClient = original


def test_proof_hunt_wiring():
    policy = PolicyServer()
    got = _proof_hunt(policy)
    check("proof_hunt wiring: remote-policy peer solves before generic waves",
          got == {"proof-1": policy.answer} and len(policy.log) <= 8, (got, policy.log))
    check("proof_hunt wiring: remote-policy target emitted no POST",
          not policy.posts, policy.log)

    audit = AuditServer()
    got = _proof_hunt(audit)
    check("proof_hunt wiring: secondary-route dispatch reaches the audit post-chain reader",
          got == {"proof-1": audit.answer} and len(audit.posts) == 2, (got, audit.log))


def main():
    old = dict(os.environ)
    try:
        for name in ("CTF_WEB_REMOTE_POLICY", "CTF_WEB_POST_CHAIN"):
            os.environ.pop(name, None)
        test_remote_policy_reader()
        test_audit_report_chain()
        test_proof_hunt_wiring()
    finally:
        os.environ.clear()
        os.environ.update(old)
    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} of {CHECKS[0]} checks")
        return 1
    print(f"PASS: {CHECKS[0]} checks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
