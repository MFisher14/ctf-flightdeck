#!/usr/bin/env python3
"""Focused fake-server tests for the exact read-only HPP peer."""

import event_pin  # noqa: E402  (tests/event_pin.py)
event_pin.pin(globals(), "huntress")  # Huntress web tests: proof_<32 hex> payoffs (events/huntress [proof])

import json
import os
import sys
import threading
import time
import urllib.parse
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "solvers" / "web"))
os.environ["CTF_WEB_HPP_READ"] = "on"
import hpp_read as H  # noqa: E402


TARGET = "https://hpp-unit.2026.huntress.ctf.games/"
PRIVATE_TARGET = "http://10.23.0.4:9090/app/"
PUBLIC = "case-public-7"
PROTECTED = "case-protected-9"
PROOF = "proof_0123456789ab4def8abc0123456789ab"
PROOF_TWO = "proof_fedcba9876544def8abcfedcba987654"
DECOY = "proof_aaaaaaaaaaaa4aaa8aaaaaaaaaaaaaaa"


def page(value, status=200, headers=None):
    if isinstance(value, bytes):
        body = value
    elif isinstance(value, str):
        body = value.encode()
    else:
        body = json.dumps(value, separators=(",", ":")).encode()
    return {"status": status, "body": body, "response_headers": dict(headers or {})}


class HPPClient:
    def __init__(self, *, base=TARGET, public_response=None, protected_response=None,
                 forward_response=None, reverse_response=None):
        self.base = base
        self.timeout = 5
        self.calls = []
        self.public_response = public_response or page({"ok": True, "record": "public"})
        self.protected_response = protected_response or page({"error": "forbidden"}, 403)
        self.forward_response = forward_response or page({"ok": True, "proof": PROOF})
        self.reverse_response = reverse_response or page({"error": "forbidden"}, 403)

    def request(self, method, path, data=None, headers=None, allow_redirects=True):
        self.calls.append((method, path, data, dict(headers or {}), allow_redirects))
        parts = urllib.parse.urlsplit(path)
        if parts.path == "/api/hpp-inventory" and not parts.query:
            return page(clues())
        values = [value for key, value in urllib.parse.parse_qsl(
            parts.query, keep_blank_values=True) if key == "case"]
        if values == [PUBLIC]:
            return dict(self.public_response)
        if values == [PROTECTED]:
            return dict(self.protected_response)
        if values == [PUBLIC, PROTECTED]:
            return dict(self.forward_response)
        if values == [PROTECTED, PUBLIC]:
            return dict(self.reverse_response)
        return page({"error": "unexpected query"}, 400)


def clues(**updates):
    value = {
        "hpp_route": "/api/cases-91",
        "hpp_parameter": "case",
        "public_reference": PUBLIC,
        "protected_reference": PROTECTED,
        "hpp_semantics": "duplicate query parameter; first value wins",
    }
    value.update(updates)
    return value


def run(*, clue=None, preloaded=None, client=None, max_requests=8, target=TARGET,
        stop=None, baseline_texts=None, clue_status=200, route_allowed=None):
    client = client or HPPClient(base=target)
    cached = {
        "/": page({"service": "records", "decoy": DECOY}),
        "/api/clues": page(clues() if clue is None else clue, clue_status),
    } if preloaded is None else dict(preloaded)
    sink, evidence = {}, []
    ctx = {
        "client": client,
        "deadline": time.time() + 10,
        "max_requests": max_requests,
        "preloaded": cached,
        "baseline_texts": list(baseline_texts or []),
        "result_sink": sink,
        "evidence": evidence,
        "stop": stop,
    }
    if route_allowed is not None:
        ctx["route_allowed"] = route_allowed
    proof = H.solve({"url": target, "answer_id": "answer"}, ctx)
    return proof, sink["answer"], client.calls, evidence


def check(name, condition, detail=None):
    if not condition:
        raise AssertionError(f"{name}: {detail!r}")
    print("PASS", name)


def test_exact_hpp_happy_path():
    proof, summary, calls, _ = run()
    check("exact HPP contract returns duplicate-read proof", proof == PROOF, summary)
    check("HPP uses two controls then exactly two orderings",
          summary["requests"] == 4 and summary["duplicate_requests"] == 2
          and len(calls) == 4, (summary, calls))
    queries = [urllib.parse.parse_qsl(urllib.parse.urlsplit(row[1]).query,
                                      keep_blank_values=True) for row in calls]
    check("HPP ordering is public, protected, public+protected, protected+public",
          queries == [[("case", PUBLIC)], [("case", PROTECTED)],
                      [("case", PUBLIC), ("case", PROTECTED)],
                      [("case", PROTECTED), ("case", PUBLIC)]], queries)
    check("HPP has no write/auth transport",
          summary["posts"] == 0 and all(row[0] == "GET" and row[2] is None
                                        and row[4] is False for row in calls), calls)
    check("public/denied controls confirm duplicate read transition",
          summary["confirmed"] is True and summary["success"] is True, summary)


def test_generic_contract_requires_get_or_openapi():
    generic = {
        "feature": "HTTP parameter pollution with duplicate query parameters",
        "feature_route": "/api/cases-91",
        "query_parameter": "case",
        "public_reference": PUBLIC,
        "protected_reference": PROTECTED,
    }
    proof, summary, calls, _ = run(clue=generic)
    check("generic route and parameter without GET authority are zero-wire",
          proof is None and summary["requests"] == 0 and calls == [], summary)

    proof, summary, calls, _ = run(clue={**generic, "request_method": "GET"})
    check("explicit GET makes generic exact HPP contract usable",
          proof == PROOF and len(calls) == 4, summary)

    spec = {
        "openapi": "3.1.0",
        "paths": {
            "/api/cases-91": {
                "get": {"parameters": [{"name": "case", "in": "query", "required": True}]}
            }
        },
    }
    proof, summary, calls, _ = run(preloaded={
        "/api/clues": page(generic),
        "/openapi.json": page(spec),
    })
    check("exact OpenAPI GET query member corroborates generic clue contract",
          proof == PROOF and len(calls) == 4, summary)

    protected_spec = dict(spec)
    protected_spec["security"] = [{"bearerAuth": []}]
    proof, summary, calls, _ = run(preloaded={
        "/api/clues": page(generic), "/openapi.json": page(protected_spec)})
    check("inherited OpenAPI security cannot authorize the generic HPP route",
          proof is None and summary["requests"] == 0 and calls == [], summary)

    ref_spec = {
        "openapi": "3.1.0",
        "paths": {"/api/cases-91": {"get": {"parameters": [
            {"$ref": "#/components/parameters/Case"},
            {"$ref": "#/components/parameters/Auth"},
        ]}}},
        "components": {"parameters": {
            "Case": {"name": "case", "in": "query", "required": True},
            "Auth": {"name": "X-API-Key", "in": "header", "required": True},
        }},
    }
    proof, summary, calls, _ = run(preloaded={
        "/api/clues": page(generic), "/openapi.json": page(ref_spec)})
    check("a required local-ref OpenAPI peer parameter blocks HPP authority",
          proof is None and summary["requests"] == 0 and calls == [], summary)


def test_linked_inventory_contract():
    proof, summary, calls, _ = run(preloaded={
        "/api/clues": page({
            "feature": "HPP duplicate parameter read",
            "inventory_route": "/api/hpp-inventory",
        }),
    })
    check("clue-linked exact inventory is fetched and may provide HPP facts",
          proof == PROOF and len(calls) == 5 and calls[0][1] == "/api/hpp-inventory"
          and summary["requests"] == 5, (summary, calls))


def test_authority_documents_are_coherent_and_strict():
    # A route/parameter clue and a separate controls object are not one grant
    # of authority, even when each is linked and HPP-labelled.
    partial_clue = {
        "feature": "HPP duplicate query parameter read",
        "hpp_route": "/api/cases-91",
        "hpp_parameter": "case",
        "inventory_route": "/api/hpp-inventory",
    }
    partial_inventory = {
        "feature": "HPP duplicate query parameter read",
        "public_reference": PUBLIC,
        "protected_reference": PROTECTED,
        "hpp_method": "GET",
    }
    proof, summary, calls, _ = run(preloaded={
        "/api/clues": page(partial_clue),
        "/api/hpp-inventory": page(partial_inventory),
    })
    check("HPP contract facts cannot be synthesized across two JSON objects",
          proof is None and summary["requests"] == 0 and calls == [], summary)

    # Two independently complete but different grants are ambiguous.
    proof, summary, calls, _ = run(preloaded={
        "/api/clues": page(clues(inventory_route="/api/hpp-inventory")),
        "/api/hpp-inventory": page(clues(hpp_route="/api/other-cases")),
    })
    check("competing complete HPP contracts are zero-wire",
          proof is None and summary["requests"] == 0 and calls == [], summary)

    # A valid JSON sibling cannot survive a malformed MIME sibling when the
    # response is being used as a live-request authority source.
    payload = json.dumps(clues(), separators=(",", ":")).encode()
    mime = (b"--B\r\nContent-Type: application/json\r\n\r\n" + payload
            + b"\r\n--B\r\nContent-Type: text/plain\r\n"
              b"Content-Transfer-Encoding: base64\r\n\r\n%%%%\r\n--B--\r\n")
    proof, summary, calls, _ = run(preloaded={
        "/api/clues": page(mime, headers={"Content-Type": "multipart/mixed; boundary=B"}),
    })
    check("malformed MIME sibling poisons an otherwise valid HPP authority document",
          proof is None and summary["requests"] == 0 and calls == [], summary)

    for conflicting in (
            clues(feature_route="/api/other"),
            clues(query_parameter="other"),
            clues(allowed_reference="different-public"),
            clues(private_reference="different-protected"),
            clues(request_method="POST")):
        proof, summary, calls, _ = run(clue=conflicting)
        check("contradictory aliases in one HPP authority object are zero-wire",
              proof is None and summary["requests"] == 0 and calls == [], summary)


def test_query_specific_and_colliding_cache_entries_are_not_authority():
    proof, summary, calls, _ = run(preloaded={
        "/api/clues?mode=privileged": page(clues()),
    })
    check("query-specific cached HPP clues cannot stand in for query-free authority",
          proof is None and summary["requests"] == 0 and calls == [], summary)

    proof, summary, calls, _ = run(preloaded={
        "/api/clues": page(clues()),
        "/%61pi/clues": page(clues()),
    })
    check("normalized HPP cache-key collisions poison both authority aliases",
          proof is None and summary["requests"] == 0 and calls == [], summary)

    late = {"/api/clues": page(clues())}
    late.update({f"/filler-{index}": page({"ordinary": index}) for index in range(59)})
    late["/%61pi/clues"] = page(clues())
    proof, summary, calls, _ = run(preloaded=late)
    check("an HPP cache collision after the old 60-entry prefix is zero-wire",
          proof is None and summary["requests"] == 0 and calls == [], summary)


def test_unsafe_or_inexact_contracts_are_zero_wire():
    cases = [
        ({"feature_route": "/api/cases-91", "query_parameter": "case",
          "public_reference": PUBLIC, "protected_reference": PROTECTED,
          "request_method": "GET"}, 200, TARGET, HPPClient()),
        (clues(hpp_method="POST"), 200, TARGET, HPPClient()),
        (clues(hpp_route="/api/login/session"), 200, TARGET, HPPClient()),
        (clues(hpp_route="/api/reset"), 200, TARGET, HPPClient()),
        (clues(hpp_route="/api/submit-record"), 200, TARGET, HPPClient()),
        (clues(hpp_route="/api/deleteUser"), 200, TARGET, HPPClient()),
        (clues(hpp_route="/api/transferFunds"), 200, TARGET, HPPClient()),
        (clues(hpp_route="/api/cases/{id}"), 200, TARGET, HPPClient()),
        (clues(hpp_parameter="role"), 200, TARGET, HPPClient()),
        (clues(hpp_parameter="token"), 200, TARGET, HPPClient()),
        (clues(protected_reference=PUBLIC), 200, TARGET, HPPClient()),
        (clues(), 403, TARGET, HPPClient()),
        (clues(), 200, "file:///tmp/not-a-target", HPPClient(base="file:///tmp/not-a-target")),
    ]
    for clue, status, target, client in cases:
        proof, summary, calls, _ = run(
            clue=clue, clue_status=status, target=target, client=client)
        check("unsafe/inexact HPP contract sends nothing",
              proof is None and summary["requests"] == 0 and calls == [], summary)


def test_public_protected_controls_gate_duplicates():
    cases = [
        HPPClient(public_response=page({"error": "forbidden"}, 403)),
        HPPClient(public_response=page({"error": "forbidden"}, 200)),
        HPPClient(protected_response=page({"record": "not found"}, 404)),
        HPPClient(protected_response=page({"ok": True, "record": "protected"}, 200)),
    ]
    for client in cases:
        proof, summary, calls, _ = run(client=client)
        check("failed scalar boundary stops before duplicate parameters",
              proof is None and len(calls) == 2 and summary["duplicate_requests"] == 0,
              (summary, calls))


def test_novelty_and_ambiguity_never_guess():
    public_with_proof = page({"ok": True, "record": "public", "proof": PROOF})
    client = HPPClient(public_response=public_with_proof)
    proof, summary, calls, _ = run(client=client)
    check("proof already on public control is not returned from duplicate response",
          proof is None and len(calls) == 4 and summary["proof"] is None, summary)

    client = HPPClient(
        forward_response=page({"ok": True, "proof": PROOF}),
        reverse_response=page({"ok": True, "proof": PROOF_TWO}),
    )
    proof, summary, calls, _ = run(client=client)
    check("different proofs in the two orderings are surfaced, never chosen",
          proof is None and len(calls) == 4 and set(summary["candidates"]) == {PROOF, PROOF_TWO},
          summary)


def test_shared_budget_stop_scope_and_route_guard():
    proof, summary, calls, _ = run(max_requests=3)
    check("incomplete four-call HPP budget sends nothing",
          proof is None and summary["requests"] == 0 and calls == [], summary)

    stopped = threading.Event()
    stopped.set()
    proof, summary, calls, _ = run(stop=stopped)
    check("shared stop event sends nothing",
          proof is None and summary["requests"] == 0 and calls == [], summary)

    mismatched = HPPClient(base="https://other.2026.huntress.ctf.games/")
    proof, summary, calls, _ = run(client=mismatched)
    check("mismatched scoped client sends nothing",
          proof is None and summary["requests"] == 0 and calls == [], summary)

    proof, summary, calls, _ = run(route_allowed=lambda _route: False)
    check("caller route policy denial sends nothing",
          proof is None and summary["requests"] == 0 and calls == [], summary)

    private = HPPClient(base=PRIVATE_TARGET)
    proof, summary, calls, _ = run(client=private, target=PRIVATE_TARGET)
    check("scope-matched GM private-IP target is accepted",
          proof == PROOF and len(calls) == 4, summary)


def test_uppercase_baseline_proof_is_recorded_in_baseline_proofs():
    # R-06: the baseline scan is the any-case payoff (flagfmt.PAYOFF_ANYCASE), so an uppercase proof on a
    # public page is recorded as a baseline proof; an exact lowercase scan would miss it.
    upper = DECOY.upper()
    cached = {"/": page({"service": "records", "decoy": upper}), "/api/clues": page(clues())}
    proof, summary, _calls, _ = run(preloaded=cached)
    check("uppercase baseline proof is listed in baseline_proofs",
          upper in summary["baseline_proofs"], summary)
    check("the novel lowercase proof is still the answer", proof == PROOF, summary)


def main():
    test_exact_hpp_happy_path()
    test_generic_contract_requires_get_or_openapi()
    test_linked_inventory_contract()
    test_authority_documents_are_coherent_and_strict()
    test_query_specific_and_colliding_cache_entries_are_not_authority()
    test_unsafe_or_inexact_contracts_are_zero_wire()
    test_public_protected_controls_gate_duplicates()
    test_novelty_and_ambiguity_never_guess()
    test_shared_budget_stop_scope_and_route_guard()
    test_uppercase_baseline_proof_is_recorded_in_baseline_proofs()
    print("PASS all web HPP reader tests")


if __name__ == "__main__":
    main()
