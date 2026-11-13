#!/usr/bin/env python3
"""Offline regressions for the strict queued-owner binding Web reader.

Every request terminates in an in-memory client.  No Game Master code, socket,
token, challenge delivery, or native executable is touched.
"""

import event_pin  # noqa: E402  (tests/event_pin.py)
event_pin.pin(globals(), "huntress")  # Huntress web tests: proof_<32 hex> payoffs (events/huntress [proof])

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

import proof_hunt as PH  # noqa: E402
import queued_owner as QO  # noqa: E402


FAILURES = []
CHECKS = [0]


def check(label, condition, detail=""):
    CHECKS[0] += 1
    print(("ok   " if condition else "FAIL ") + label
          + ("" if condition or not detail else f"  [{str(detail)[:1400]}]"))
    if not condition:
        FAILURES.append(label)


def proof():
    return "proof_" + uuid.uuid4().hex


def response(status, body, path="/", headers=None, *, raw=False, truncated=False):
    if raw:
        payload = str(body).encode("utf-8")
    elif not isinstance(body, (bytes, bytearray)):
        payload = json.dumps(body, separators=(",", ":")).encode("utf-8")
    else:
        payload = bytes(body)
    pairs = [("Content-Type", "application/json")]
    pairs.extend(list((headers or {}).items()))
    return {"status": status, "body": payload, "response_header_pairs": pairs,
            "response_headers": dict(pairs), "final_url": "http://fake.local" + path,
            "truncated": truncated}


def target():
    return {"answer_id": "proof-1", "url": "http://fake.local/", "index": 1}


class Site:
    def __init__(self, *, answer=None, feature="/process-d9aca9",
                 directory_route="/api/owners", secondary="/audit-bff05e",
                 current="analyst", restricted="executive", clues=None,
                 directory=None, feature_status=405, feature_error="post_required",
                 request_fields=None, audit_status=400, audit_error="job_id_required",
                 query_parameter="id", receipt_status=201, receipt_owner=None,
                 receipt_id="1", receipt_values=None, receipt_truncated=False,
                 raise_on_post=False, payoff_effect="queue_owner_binding_bypassed",
                 payoff_error=None, payoff_values=None, payoff_headers=None,
                 raw_clues=None, raw_directory=None):
        self.base = "http://fake.local/"
        self.application_base = self.base
        self.timeout = 8.0
        self.feature = feature
        self.directory_route = directory_route
        self.secondary = secondary
        self.current = current
        self.restricted = restricted
        self.answer = answer or proof()
        self.clues = clues if clues is not None else {
            "framework": "Pyramid", "feature_route": feature,
            "secondary_route": secondary, "owner_directory_route": directory_route,
            "current_role": current,
        }
        self.directory = directory if directory is not None else {
            "caller": current, "restricted_owner": restricted,
        }
        self.feature_status = feature_status
        self.feature_error = feature_error
        self.request_fields = ["owner"] if request_fields is None else request_fields
        self.audit_status = audit_status
        self.audit_error = audit_error
        self.query_parameter = query_parameter
        self.receipt_status = receipt_status
        self.receipt_owner = restricted if receipt_owner is None else receipt_owner
        self.receipt_id = receipt_id
        self.receipt_values = dict(receipt_values or {})
        self.receipt_truncated = receipt_truncated
        self.raise_on_post = raise_on_post
        self.payoff_effect = payoff_effect
        self.payoff_error = payoff_error
        self.payoff_values = dict(payoff_values or {})
        self.payoff_headers = dict(payoff_headers or {})
        self.raw_clues = raw_clues
        self.raw_directory = raw_directory
        self.jobs = {}
        self.log = []

    def clue_response(self):
        if self.raw_clues is not None:
            return response(200, self.raw_clues, "/api/clues", raw=True)
        return response(200, self.clues, "/api/clues")

    def directory_response(self):
        if self.raw_directory is not None:
            return response(200, self.raw_directory, self.directory_route, raw=True)
        return response(200, self.directory, self.directory_route)

    @property
    def posts(self):
        return [row for row in self.log if row["method"] == "POST"]

    def request(self, method, path, data=None, headers=None, allow_redirects=True):
        row = {"method": method, "path": path, "data": data,
               "headers": dict(headers or {}), "redirects": allow_redirects}
        self.log.append(row)
        split = urllib.parse.urlsplit(path)
        if method == "GET" and split.path == "/":
            return response(200, {"service": "job queue"}, path)
        if method == "GET" and split.path in ("/robots.txt", "/openapi.json"):
            return response(404, {"error": "not_found"}, path)
        if method == "GET" and split.path == "/api/clues":
            return self.clue_response()
        if method == "GET" and split.path == self.directory_route:
            return self.directory_response()
        if method == "GET" and split.path == self.feature:
            return response(self.feature_status,
                            {"error": self.feature_error, "request_fields": self.request_fields}, path)
        if method == "GET" and split.path == self.secondary and not split.query:
            return response(self.audit_status,
                            {"error": self.audit_error, "query_parameter": self.query_parameter}, path)
        if method == "POST" and split.path == self.feature:
            if self.raise_on_post:
                raise TimeoutError("simulated ambiguous transport")
            try:
                doc = json.loads(data or "null")
            except Exception:
                doc = None
            if not isinstance(doc, dict) or set(doc) != {"owner"}:
                return response(400, {"error": "invalid_body"}, path)
            self.jobs[str(self.receipt_id)] = doc["owner"]
            body = {"ok": True, self.query_parameter: self.receipt_id,
                    "queued_owner": self.receipt_owner, **self.receipt_values}
            return response(self.receipt_status, body, path, truncated=self.receipt_truncated)
        if method == "GET" and split.path == self.secondary:
            values = urllib.parse.parse_qs(split.query, keep_blank_values=True)
            ids = values.get(self.query_parameter, [])
            job_id = ids[0] if len(ids) == 1 else None
            if job_id is None or job_id not in self.jobs:
                return response(404, {"error": "job_not_found"}, path)
            if self.jobs[job_id] != self.restricted:
                return response(403, {"error": "job_not_authorized"}, path)
            body = {"ok": True, "effect": self.payoff_effect,
                    "evidence": self.answer, **self.payoff_values}
            if self.payoff_error is not None:
                body["error"] = self.payoff_error
            return response(200, body, path, self.payoff_headers)
        return response(404, {"error": "not_found"}, path)


def direct(site, *, preloaded=None, max_requests=5, deadline=None,
           baseline_texts=(), route_allowed=None):
    ctx = {
        "client": site,
        "preloaded": preloaded if preloaded is not None else {"/api/clues": site.clue_response()},
        "max_requests": max_requests,
        "deadline": deadline if deadline is not None else time.time() + 15,
        "baseline_texts": list(baseline_texts),
        "result_sink": {},
    }
    if route_allowed is not None:
        ctx["route_allowed"] = route_allowed
    got = QO.solve(target(), ctx)
    return got, ctx["result_sink"]["proof-1"]


def cached_controls(site):
    return {
        "/api/clues": site.clue_response(),
        site.directory_route: site.directory_response(),
        site.feature: response(405, {"error": "post_required", "request_fields": ["owner"]},
                               site.feature),
        site.secondary: response(400, {"error": "job_id_required", "query_parameter": "id"},
                                 site.secondary),
    }


def test_exact_contract():
    site = Site()
    got, meta = direct(site)
    check("exact contract: correlated audit returns the byte-proven proof",
          got == site.answer, (got, site.log))
    check("exact contract: three GET controls precede one POST and one audit GET",
          [(row["method"], urllib.parse.urlsplit(row["path"]).path) for row in site.log] == [
              ("GET", site.directory_route), ("GET", site.feature),
              ("GET", site.secondary), ("POST", site.feature),
              ("GET", site.secondary),
          ], site.log)
    check("exact contract: the sole mutation body is the directory-derived owner",
          len(site.posts) == 1 and site.posts[0]["data"] == '{"owner":"executive"}'
          and site.posts[0]["headers"] == {"Content-Type": "application/json"}, site.posts)
    check("exact contract: the audit query uses only the receipt-derived id",
          urllib.parse.parse_qs(urllib.parse.urlsplit(site.log[-1]["path"]).query) == {"id": ["1"]},
          site.log[-1])
    check("exact contract: redirects are disabled and no Authorization header is synthesized",
          all(row["redirects"] is False and
              not any(key.lower() == "authorization" for key in row["headers"])
              for row in site.log), site.log)
    check("exact contract: summary marks one successful terminal mutation",
          meta["class"] == "queued_owner_binding" and meta["success"] is True
          and meta["terminal"] is True and meta["mutation_started"] is True
          and meta["ambiguous_mutation"] is False and meta["posts"] == 1
          and meta["requests"] == 5, meta)

    variant = Site(feature="/submit-a6340d", directory_route="/directory-123abc",
                   secondary="/audit-16cbe7", current="reader-7",
                   restricted="records.owner@corp", receipt_id="job-A.7")
    got, _meta = direct(variant)
    check("variant: routes, owner and opaque job id are re-derived",
          got == variant.answer and variant.posts[0]["data"] ==
          '{"owner":"records.owner@corp"}' and
          urllib.parse.parse_qs(urllib.parse.urlsplit(variant.log[-1]["path"]).query) == {
              "id": ["job-A.7"]}, variant.log)

    cached = Site()
    got, meta = direct(cached, preloaded=cached_controls(cached), max_requests=2)
    check("cached controls: exactly the reserved POST/readback pair goes on wire",
          got == cached.answer and len(cached.log) == 2 and meta["requests"] == 2, cached.log)


def test_zero_mutation_gates():
    for label, clues in (
            ("missing owner directory", {"feature_route": "/process-d9aca9",
                                         "secondary_route": "/audit-bff05e",
                                         "current_role": "analyst"}),
            ("duplicate routes", {"feature_route": "/process-d9aca9",
                                  "secondary_route": "/process-d9aca9",
                                  "owner_directory_route": "/api/owners",
                                  "current_role": "analyst"}),
            ("off-origin directory", {"feature_route": "/process-d9aca9",
                                      "secondary_route": "/audit-bff05e",
                                      "owner_directory_route": "https://evil.invalid/owners",
                                      "current_role": "analyst"}),
            ("unsafe current role", {"feature_route": "/process-d9aca9",
                                     "secondary_route": "/audit-bff05e",
                                     "owner_directory_route": "/api/owners",
                                     "current_role": "analyst\r\nX-Evil: 1"}),
            ("fatal action route", {"feature_route": "/delete-account",
                                    "secondary_route": "/audit-bff05e",
                                    "owner_directory_route": "/api/owners",
                                    "current_role": "analyst"})):
        site = Site(clues=clues)
        got, _meta = direct(site)
        check(f"zero-mutation gate: {label}", got is None and not site.posts, site.log)

    duplicate_clue = Site()
    cache = {"/api/clues": duplicate_clue.clue_response(),
             "http://fake.local/api/clues": duplicate_clue.clue_response()}
    got, _meta = direct(duplicate_clue, preloaded=cache)
    check("zero-mutation gate: duplicate canonical clue documents are ambiguous",
          got is None and duplicate_clue.log == [], duplicate_clue.log)

    malformed = Site(raw_clues='{"feature_route":"/process-d9aca9",'
                               '"feature_route":"/other",'
                               '"secondary_route":"/audit-bff05e",'
                               '"owner_directory_route":"/api/owners",'
                               '"current_role":"analyst"}')
    got, _meta = direct(malformed)
    check("zero-mutation gate: duplicate JSON clue keys fail closed",
          got is None and malformed.log == [], malformed.log)

    short = Site()
    got, meta = direct(short, max_requests=4)
    check("zero-mutation gate: insufficient full-sequence budget sends nothing",
          got is None and short.log == [] and meta["requests"] == 0, (meta, short.log))

    refused = Site()
    got, _meta = direct(refused, route_allowed=lambda _route: False)
    check("zero-mutation gate: caller route policy refusal sends nothing",
          got is None and refused.log == [], refused.log)


def test_read_only_preconditions():
    cases = [
        ("directory caller mismatch", Site(directory={"caller": "guest",
                                                       "restricted_owner": "executive"}), 1),
        ("restricted owner equals caller", Site(directory={"caller": "analyst",
                                                           "restricted_owner": "analyst"}), 1),
        ("feature wrong status", Site(feature_status=200), 2),
        ("feature wrong error", Site(feature_error="method_not_allowed"), 2),
        ("feature extra field", Site(request_fields=["owner", "priority"]), 2),
        ("feature alternate field", Site(request_fields=["assignee"]), 2),
        ("audit wrong status", Site(audit_status=404), 3),
        ("audit wrong error", Site(audit_error="id_required"), 3),
        ("audit alternate parameter", Site(query_parameter="job_id"), 3),
    ]
    for label, site, expected in cases:
        got, meta = direct(site)
        check(f"read-only precondition: {label} prevents mutation",
              got is None and len(site.log) == expected and not site.posts
              and meta["mutation_started"] is False, (meta, site.log))

    collision = Site(raw_directory='{"caller":"analyst",'
                                   '"restricted_owner":"executive",'
                                   '"restricted-owner":"other"}')
    got, _meta = direct(collision)
    check("read-only precondition: snake-equivalent owner keys are ambiguous",
          got is None and len(collision.log) == 1 and not collision.posts, collision.log)

    late = Site()
    got, meta = direct(late, deadline=time.time() + QO.READBACK_RESERVE_SECONDS)
    check("read-only precondition: short deadline never crosses the mutation boundary",
          got is None and not late.posts and meta["mutation_started"] is False, (meta, late.log))


def test_terminal_boundary():
    rejected = Site(receipt_status=409)
    got, meta = direct(rejected)
    check("terminal boundary: explicit POST rejection is not retried or read back",
          got is None and len(rejected.posts) == 1 and len(rejected.log) == 4
          and meta["terminal"] is True and meta["ambiguous_mutation"] is False, (meta, rejected.log))

    mismatched = Site(receipt_owner="analyst")
    got, meta = direct(mismatched)
    check("terminal boundary: receipt owner mismatch stops after the one POST",
          got is None and len(mismatched.posts) == 1 and len(mismatched.log) == 4
          and meta["terminal"] is True, (meta, mismatched.log))

    bad_id = Site(receipt_id="../other?id=7")
    got, meta = direct(bad_id)
    check("terminal boundary: unsafe receipt id never reaches an audit URL",
          got is None and len(bad_id.posts) == 1 and len(bad_id.log) == 4, (meta, bad_id.log))

    raised = Site(raise_on_post=True)
    got, meta = direct(raised)
    check("terminal boundary: ambiguous POST transport gets no retry/readback",
          got is None and len(raised.posts) == 1 and len(raised.log) == 4
          and meta["terminal"] is True and meta["ambiguous_mutation"] is True, (meta, raised.log))

    unavailable = Site(receipt_status=503)
    got, meta = direct(unavailable)
    check("terminal boundary: POST 5xx is ambiguous and suppresses readback",
          got is None and len(unavailable.posts) == 1 and len(unavailable.log) == 4
          and meta["ambiguous_mutation"] is True, (meta, unavailable.log))

    truncated = Site(receipt_truncated=True)
    got, meta = direct(truncated)
    check("terminal boundary: truncated POST receipt is ambiguous and suppresses readback",
          got is None and len(truncated.posts) == 1 and len(truncated.log) == 4
          and meta["ambiguous_mutation"] is True, (meta, truncated.log))


def test_payoff_bright_line():
    wrong = Site(payoff_effect="owner_binding_checked")
    got, meta = direct(wrong)
    check("bright line: a proof without the exact final effect is None",
          got is None and meta["success"] is False, meta)

    errored = Site(payoff_error="partial_failure")
    got, meta = direct(errored)
    check("bright line: exact effect plus error is None",
          got is None and meta["success"] is False, meta)

    ambiguous = Site(payoff_values={"objective": proof()})
    got, meta = direct(ambiguous)
    check("bright line: two proof-like payoff values are candidate-only",
          got is None and meta["success"] is True and meta["candidates"], meta)

    sibling = Site(payoff_headers={"X-Evidence": proof()})
    got, meta = direct(sibling)
    check("bright line: a sibling-header proof makes the payoff unsure",
          got is None and meta["success"] is True and meta["candidates"], meta)

    repeated = Site()
    repeated.receipt_values = {"evidence": repeated.answer}
    got, meta = direct(repeated)
    check("bright line: a proof repeated from the mutation receipt is baseline, never plain",
          got is None and meta["success"] is True, meta)

    prior = Site()
    got, meta = direct(prior, baseline_texts=[prior.answer])
    check("bright line: a proof already present in earlier bytes is never plain",
          got is None and meta["success"] is True, meta)

    uppercase = Site(answer="PROOF_" + uuid.uuid4().hex.upper())
    got, meta = direct(uppercase)
    check("bright line: a non-wire proof spelling is candidate-only",
          got is None and meta["success"] is True and meta["candidates"], meta)


def test_proof_hunt_wiring():
    site = Site()
    original = PH._web.WebClient
    PH._web.WebClient = lambda url, timeout=8.0: site
    try:
        got = PH.solve_targets([target()], {"max_requests": 20, "deadline": None})
    finally:
        PH._web.WebClient = original
    check("proof_hunt wiring: exact queue contract dispatches before broad waves",
          got == {"proof-1": site.answer} and len(site.log) <= 9, (got, site.log))
    check("proof_hunt wiring: integrated execution has exactly one POST",
          len(site.posts) == 1, site.log)


def main():
    old = dict(os.environ)
    try:
        os.environ.pop("CTF_WEB_QUEUED_OWNER", None)
        test_exact_contract()
        test_zero_mutation_gates()
        test_read_only_preconditions()
        test_terminal_boundary()
        test_payoff_bright_line()
        test_proof_hunt_wiring()
    finally:
        os.environ.clear()
        os.environ.update(old)
    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} of {CHECKS[0]} checks")
        return 1
    print(f"PASS: {CHECKS[0]} queued-owner checks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
