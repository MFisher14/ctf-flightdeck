#!/usr/bin/env python3
"""A hostile carrier in a control must not erase an unrelated decoy."""

from __future__ import annotations

import event_pin  # noqa: E402  (tests/event_pin.py)
event_pin.pin(globals(), "huntress")  # Huntress web tests: proof_<32 hex> payoffs (events/huntress [proof])

import json
import sys
import threading
import time
import urllib.parse
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
WEB = REPO / "solvers" / "web"
TOOLKITS = REPO / "solvers" / "toolkits"
sys.path[:0] = [str(WEB), str(TOOLKITS)]
sys.dont_write_bytecode = True

import forge_event as forge  # noqa: E402
import graphql_read as graphql  # noqa: E402
import post_chain as post  # noqa: E402
import proof_hunt as hunt  # noqa: E402


HOST = "target.test"
BASE = "https://target.test/"
DECOY = "proof_0123456789abcdef0123456789abcdef"
NEW = "proof_fedcba9876543210fedcba9876543210"
CARRIER_PROOF = "proof_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
FUTURE = "HUNTRESS{baseline-decoy}"


def deep(value, rounds=6):
    for _ in range(rounds):
        value = urllib.parse.quote(value, safe="")
    return value


def baseline(*values):
    carrier = deep("https://evil.invalid/" + CARRIER_PROOF)
    return "external=" + carrier + " ordinary=" + " ".join(values)


def response(key, value):
    return {"status": 200, "body": json.dumps({"success": True, key: value}).encode()}


def module_extractors(value, controls):
    return {
        "forge": forge.extract_success(response("proof", value), controls, host=HOST),
        "post": post.extract_anchored(response("proof", value), controls, anchored=True, host=HOST),
        "graphql": graphql._result_evidence({"proof": value}, controls, host=HOST),
    }


class Client:
    base = BASE
    timeout = 8

    def __init__(self, plain, payoff):
        self.plain = plain
        self.payoff = payoff
        self.log = []

    def request(self, method, path, **_kwargs):
        self.log.append((method, path))
        body = self.plain if path == "/control" else self.payoff
        content_type = ("application/json" if body.lstrip()[:1] in ("{", "[")
                        else "text/plain")
        return {"status": 200, "body": body.encode(),
                "response_headers": {"Content-Type": content_type},
                "final_url": BASE.rstrip("/") + path}


def hunted(plain, payoff):
    client = Client(plain, payoff)
    hunter = hunt._Hunter(BASE, deadline=time.time() + 5, max_requests=2,
                          stop=threading.Event(), prompt="")
    hunter.client = client
    hunter.fetch("/control", "plain", False, "control")
    hunter.fetch("/payoff", "test", True, "payoff")
    return hunter.answer(), hunter.candidates, hunter


def test_repeated_wire_decoy_stays_baseline():
    control = baseline(DECOY)
    results = module_extractors(DECOY, [control])
    assert all(row.get("auto") is None for row in results.values()), results
    assert all(DECOY not in row.get("wire", []) for row in results.values()), results

    answer, candidates, hunter = hunted(control, json.dumps({"success": True, "proof": DECOY}))
    assert answer is None and not candidates and DECOY in hunter.plain, (
        answer, candidates, hunter.plain, hunter.payoff)


def test_distinct_payoff_still_returns():
    control = baseline(DECOY)
    results = module_extractors(NEW, [control])
    assert all(row.get("auto") == NEW for row in results.values()), results

    answer, candidates, hunter = hunted(control, json.dumps({"success": True, "proof": NEW}))
    assert answer == NEW and not candidates, (answer, candidates, hunter.plain, hunter.payoff)


def test_repeated_future_candidate_is_not_resurfaced():
    control = baseline(FUTURE)
    forge_result = forge.extract_success(response("evidence", FUTURE), [control], host=HOST)
    post_result = post.extract_anchored(response("evidence", FUTURE), [control], anchored=True, host=HOST)
    graph_result = graphql._result_evidence({"evidence": FUTURE}, [control], host=HOST)
    assert all(FUTURE not in row.get("candidates", [])
               for row in (forge_result, post_result, graph_result)), (
                   forge_result, post_result, graph_result)

    answer, candidates, _hunter = hunted(
        control, json.dumps({"success": True, "evidence": FUTURE}))
    assert answer is None and all(row.get("value") != FUTURE for row in candidates), candidates


def test_external_asset_and_entity_do_not_blank_real_payoff():
    """An unrelated CDN asset plus HTML entity must not erase a real proof.

    Canonicalizing ``&amp;`` changes the whole representation.  That does not
    make a separate literal off-host script URL an ambiguous carrier for every
    other token in the document; only tokens inside that URL are removed.
    """
    markup = '<script src="https://static.example.invalid/beacon.js"></script>A&amp;B'
    body = json.dumps({"success": True, "proof": NEW, "html": markup}).encode()
    response_value = {"status": 200, "body": body}
    results = (
        forge.extract_success(response_value, [], host=HOST),
        post.extract_anchored(response_value, [], anchored=True, host=HOST),
        graphql._result_evidence({"note": NEW + " " + markup}, [], host=HOST),
    )
    assert all(row.get("auto") == NEW for row in results), results

    answer, candidates, hunter = hunted("plain control", NEW + " " + markup)
    assert answer == NEW and not candidates, (answer, candidates, hunter.plain, hunter.payoff)


def main():
    tests = (test_repeated_wire_decoy_stays_baseline,
             test_distinct_payoff_still_returns,
             test_repeated_future_candidate_is_not_resurfaced,
             test_external_asset_and_entity_do_not_blank_real_payoff)
    failed = []
    for test in tests:
        try:
            test()
            print("ok  ", test.__name__)
        except Exception as exc:  # noqa: BLE001 - standalone regression reports every failure
            failed.append(test.__name__)
            print("FAIL", test.__name__, type(exc).__name__, str(exc)[:1000])
    print(("FAIL" if failed else "PASS"), "test_web_baseline_decoys", len(failed), "failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
