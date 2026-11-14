#!/usr/bin/env python3
"""Offline regressions for the strict delegated-identity Web reader.

All requests terminate in an in-memory fake client.  The test never imports a
Game Master session, opens a socket, executes a delivery, or reads a token.
"""

import event_pin  # noqa: E402  (tests/event_pin.py)
event_pin.pin(globals(), "huntress")  # Huntress web tests: proof_<32 hex> payoffs (events/huntress [proof])

import json
import os
import sys
import time
import uuid
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "solvers" / "web"))
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))

import delegated_identity as DI  # noqa: E402
import proof_hunt as PH  # noqa: E402


FAILURES = []
CHECKS = [0]


def check(label, condition, detail=""):
    CHECKS[0] += 1
    print(("ok   " if condition else "FAIL ") + label
          + ("" if condition or not detail else f"  [{str(detail)[:1200]}]"))
    if not condition:
        FAILURES.append(label)


def proof():
    return "proof_" + uuid.uuid4().hex


def response(status, body, path="/", headers=None, *, raw=False):
    if raw:
        payload = str(body).encode("utf-8")
    elif not isinstance(body, (bytes, bytearray)):
        payload = json.dumps(body, separators=(",", ":")).encode("utf-8")
    else:
        payload = bytes(body)
    pairs = [("Content-Type", "application/json")]
    pairs.extend(list((headers or {}).items()))
    return {"status": status, "body": payload, "response_header_pairs": pairs,
            "response_headers": dict(pairs), "final_url": "http://fake.local" + path}


def target():
    return {"answer_id": "proof-1", "url": "http://fake.local/", "index": 1}


class Site:
    def __init__(self, *, answer=None, clues=None, directory=None,
                 feature_status=403, feature_error="delegated_identity_rejected",
                 feature_vary="x-delegated-user", secondary_status=403,
                 secondary_error="delegated_identity_rejected",
                 payoff_effect="delegated_identity_trusted", payoff_error=None,
                 payoff_headers=None, payoff_values=None, raw_clues=None,
                 raw_directory=None):
        self.base = "http://fake.local/"
        self.application_base = self.base
        self.timeout = 8.0
        self.feature = "/execute-a1b2c3"
        self.directory_route = "/api/identities"
        self.secondary = "/result-d4e5f6"
        self.answer = answer or proof()
        self.clues = clues if clues is not None else {
            "feature_route": self.feature,
            "identity_directory_route": self.directory_route,
            "secondary_route": self.secondary,
            "current_role": "analyst",
        }
        self.directory = directory if directory is not None else {
            "caller": "analyst", "records_owner": "executive",
        }
        self.feature_status = feature_status
        self.feature_error = feature_error
        self.feature_vary = feature_vary
        self.secondary_status = secondary_status
        self.secondary_error = secondary_error
        self.payoff_effect = payoff_effect
        self.payoff_error = payoff_error
        self.payoff_headers = dict(payoff_headers or {})
        self.payoff_values = dict(payoff_values or {})
        self.raw_clues = raw_clues
        self.raw_directory = raw_directory
        self.log = []

    def clue_response(self):
        if self.raw_clues is not None:
            return response(200, self.raw_clues, "/api/clues", raw=True)
        return response(200, self.clues, "/api/clues")

    def directory_response(self):
        if self.raw_directory is not None:
            return response(200, self.raw_directory, self.directory_route, raw=True)
        return response(200, self.directory, self.directory_route)

    def request(self, method, path, data=None, headers=None, allow_redirects=True):
        row = {"method": method, "path": path, "data": data,
               "headers": dict(headers or {}), "redirects": allow_redirects}
        self.log.append(row)
        if method != "GET":
            return response(405, {"error": "method_not_allowed"}, path)
        if path == "/":
            return response(200, {"service": "delegated identity"}, path)
        if path in ("/robots.txt", "/openapi.json"):
            return response(404, {"error": "not_found"}, path)
        if path == "/api/clues":
            return self.clue_response()
        if path == self.directory_route:
            return self.directory_response()
        if path == self.feature:
            owner = str(self.directory.get("records_owner") or "") if isinstance(self.directory, dict) else ""
            if row["headers"].get(DI.DELEGATED_HEADER) == owner and owner:
                body = {"effect": self.payoff_effect, "evidence": self.answer,
                        **self.payoff_values}
                if self.payoff_error is not None:
                    body["error"] = self.payoff_error
                return response(200, body, path, self.payoff_headers)
            headers_out = ({"Vary": self.feature_vary}
                           if self.feature_vary is not None else {})
            return response(self.feature_status, {"error": self.feature_error}, path, headers_out)
        if path == self.secondary:
            return response(self.secondary_status, {"error": self.secondary_error}, path)
        return response(404, {"error": "not_found"}, path)


def direct(site, *, preloaded=None, max_requests=4, baseline_texts=(), route_allowed=None):
    ctx = {
        "client": site,
        "preloaded": preloaded if preloaded is not None else {"/api/clues": site.clue_response()},
        "max_requests": max_requests,
        "deadline": time.time() + 10,
        "baseline_texts": list(baseline_texts),
        "result_sink": {},
    }
    if route_allowed is not None:
        ctx["route_allowed"] = route_allowed
    got = DI.solve(target(), ctx)
    return got, ctx["result_sink"]["proof-1"]


def test_exact_contract():
    site = Site()
    got, meta = direct(site)
    check("exact contract: derived owner header returns the byte-proven proof",
          got == site.answer, (got, site.log))
    check("exact contract: directory + two controls + one payoff are GET-only",
          len(site.log) == 4 and {row["method"] for row in site.log} == {"GET"}, site.log)
    check("exact contract: controls precede exactly one owner-header replay",
          [row["path"] for row in site.log] == [
              site.directory_route, site.feature, site.secondary, site.feature,
          ] and site.log[-1]["headers"] == {DI.DELEGATED_HEADER: "executive"}, site.log)
    check("exact contract: redirects are disabled and no Authorization header is synthesized",
          all(row["redirects"] is False and
              not any(key.lower() == "authorization" for key in row["headers"])
              for row in site.log), site.log)
    check("exact contract: summary is successful, read-only and class-specific",
          meta["class"] == "delegated_identity" and meta["success"] is True
          and meta["posts"] == 0 and meta["requests"] == 4, meta)

    variant = Site(
        clues={"feature_route": "/inspect-112233",
               "identity_directory_route": "/directory-445566",
               "secondary_route": "/status-778899", "current_role": "reader-7"},
        directory={"caller": "reader-7", "records_owner": "records.owner@corp"},
    )
    variant.feature = "/inspect-112233"
    variant.directory_route = "/directory-445566"
    variant.secondary = "/status-778899"
    got, _meta = direct(variant)
    check("variant: routes and identities are re-derived, never fixed to analyst/executive",
          got == variant.answer and variant.log[-1]["headers"] == {
              DI.DELEGATED_HEADER: "records.owner@corp"}, variant.log)

    cached = Site()
    cache = {"/api/clues": cached.clue_response(),
             cached.directory_route: cached.directory_response(),
             cached.feature: response(403, {"error": "delegated_identity_rejected"},
                                      cached.feature, {"Vary": "x-delegated-user"}),
             cached.secondary: response(403, {"error": "delegated_identity_rejected"},
                                        cached.secondary)}
    got, meta = direct(cached, preloaded=cache, max_requests=1)
    check("cached controls: one fresh owner replay is sufficient",
          got == cached.answer and len(cached.log) == 1 and meta["requests"] == 1, cached.log)


def test_zero_wire_gates():
    for label, clues in (
            ("missing identity directory", {"feature_route": "/execute-a1b2c3",
                                             "secondary_route": "/result-d4e5f6",
                                             "current_role": "analyst"}),
            ("duplicate routes", {"feature_route": "/execute-a1b2c3",
                                  "identity_directory_route": "/execute-a1b2c3",
                                  "secondary_route": "/result-d4e5f6",
                                  "current_role": "analyst"}),
            ("off-origin directory", {"feature_route": "/execute-a1b2c3",
                                      "identity_directory_route": "https://evil.invalid/identities",
                                      "secondary_route": "/result-d4e5f6",
                                      "current_role": "analyst"}),
            ("unsafe identity value", {"feature_route": "/execute-a1b2c3",
                                       "identity_directory_route": "/api/identities",
                                       "secondary_route": "/result-d4e5f6",
                                       "current_role": "analyst\r\nX-Evil: 1"})):
        site = Site(clues=clues)
        got, _meta = direct(site)
        check(f"zero-wire gate: {label}", got is None and site.log == [], site.log)

    duplicate_clue = Site()
    cache = {"/api/clues": duplicate_clue.clue_response(),
             "http://fake.local/api/clues": duplicate_clue.clue_response()}
    got, _meta = direct(duplicate_clue, preloaded=cache)
    check("zero-wire gate: duplicate canonical clue documents are ambiguous",
          got is None and duplicate_clue.log == [], duplicate_clue.log)

    malformed = Site(raw_clues='{"feature_route":"/execute-a1b2c3",'
                               '"feature_route":"/other",'
                               '"identity_directory_route":"/api/identities",'
                               '"secondary_route":"/result-d4e5f6",'
                               '"current_role":"analyst"}')
    got, _meta = direct(malformed)
    check("zero-wire gate: duplicate JSON clue keys fail closed",
          got is None and malformed.log == [], malformed.log)

    short = Site()
    got, meta = direct(short, max_requests=3)
    check("zero-wire gate: the full four-request sequence is reserved before first send",
          got is None and short.log == [] and meta["requests"] == 0, (meta, short.log))

    refused = Site()
    got, _meta = direct(refused, route_allowed=lambda _route: False)
    check("zero-wire gate: caller route policy refusal sends nothing",
          got is None and refused.log == [], refused.log)


def test_control_failures():
    cases = []
    cases.append(("directory caller mismatch", Site(directory={"caller": "guest",
                                                               "records_owner": "executive"}), 1))
    cases.append(("owner equals caller", Site(directory={"caller": "analyst",
                                                         "records_owner": "analyst"}), 1))
    cases.append(("feature wrong error", Site(feature_error="access_denied"), 2))
    cases.append(("feature missing Vary", Site(feature_vary=None), 2))
    cases.append(("feature ambiguous Vary", Site(feature_vary="x-delegated-user, cookie"), 2))
    cases.append(("feature not forbidden", Site(feature_status=401), 2))
    cases.append(("secondary wrong error", Site(secondary_error="not_found"), 3))
    cases.append(("secondary not forbidden", Site(secondary_status=404), 3))
    for label, site, expected in cases:
        got, _meta = direct(site)
        check(f"control failure: {label} never reaches an owner replay",
              got is None and len(site.log) == expected
              and not any(DI.DELEGATED_HEADER in row["headers"] for row in site.log), site.log)

    alias_collision = Site(raw_directory='{"caller":"analyst",'
                                         '"records_owner":"executive",'
                                         '"records-owner":"other"}')
    got, _meta = direct(alias_collision)
    check("control failure: snake-equivalent directory keys are ambiguous",
          got is None and len(alias_collision.log) == 1, alias_collision.log)


def test_payoff_bright_line():
    wrong = Site(payoff_effect="identity_trusted")
    got, meta = direct(wrong)
    check("bright line: a 2xx proof without the exact trusted effect is None",
          got is None and meta["success"] is False, meta)

    errored = Site(payoff_error="partial_failure")
    got, meta = direct(errored)
    check("bright line: an exact effect carrying an error is None",
          got is None and meta["success"] is False, meta)

    ambiguous = Site(payoff_values={"objective": proof()})
    got, meta = direct(ambiguous)
    check("bright line: two proof-like payoff values are surfaced but never plain",
          got is None and meta["success"] is True and meta["candidates"], meta)

    sibling = Site(payoff_headers={"X-Evidence": proof()})
    got, meta = direct(sibling)
    check("bright line: proof in a sibling header makes the coherent payoff unsure",
          got is None and meta["success"] is True and meta["candidates"], meta)

    repeated = Site()
    got, meta = direct(repeated, baseline_texts=[repeated.answer])
    check("bright line: a proof already present in baseline bytes is never plain",
          got is None and meta["success"] is True, meta)

    uppercase = Site(answer="PROOF_" + uuid.uuid4().hex.upper())
    got, meta = direct(uppercase)
    check("bright line: a non-wire spelling is candidate-only, never plain",
          got is None and meta["success"] is True and meta["candidates"], meta)


def test_proof_hunt_wiring():
    site = Site()
    original = PH._web.WebClient
    PH._web.WebClient = lambda url, timeout=8.0: site
    try:
        got = PH.solve_targets([target()], {"max_requests": 20, "deadline": None})
    finally:
        PH._web.WebClient = original
    check("proof_hunt wiring: exact clue contract dispatches the new peer before broad waves",
          got == {"proof-1": site.answer} and len(site.log) <= 8, (got, site.log))
    check("proof_hunt wiring: the integrated solver remains GET-only",
          {row["method"] for row in site.log} == {"GET"}, site.log)


def main():
    old = dict(os.environ)
    try:
        os.environ.pop("CTF_WEB_DELEGATED_IDENTITY", None)
        test_exact_contract()
        test_zero_wire_gates()
        test_control_failures()
        test_payoff_bright_line()
        test_proof_hunt_wiring()
    finally:
        os.environ.clear()
        os.environ.update(old)
    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} of {CHECKS[0]} checks")
        return 1
    print(f"PASS: {CHECKS[0]} delegated-identity checks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
