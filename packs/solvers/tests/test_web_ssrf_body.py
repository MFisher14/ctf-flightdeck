#!/usr/bin/env python3
"""Offline adversarial tests for the exact POST-body SSRF peer."""

import event_pin  # noqa: E402  (tests/event_pin.py)
event_pin.pin(globals(), "huntress")  # Huntress web tests: proof_<32 hex> payoffs (events/huntress [proof])

import json
import io
import os
import sys
import threading
import time
import urllib.parse
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "solvers" / "web"))
os.environ["CTF_WEB_SSRF_BODY"] = "on"
import ssrf_body as S  # noqa: E402


TARGET = "https://post-ssrf-unit.2026.huntress.ctf.games/"
PRIVATE_TARGET = "http://10.42.0.7:8088/app/"
PROOF = "proof_0123456789abcdef0123456789abcdef"
PROOF_TWO = "proof_fedcba9876543210fedcba9876543210"
DECOY = "proof_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"


def page(value, status=200, headers=None):
    if isinstance(value, bytes):
        body = value
    elif isinstance(value, str):
        body = value.encode()
    else:
        body = json.dumps(value, separators=(",", ":")).encode()
    return {"status": status, "body": body, "response_headers": dict(headers or {})}


def clues(**updates):
    value = {
        "post_ssrf_route": "/api/preview-41",
        "post_ssrf_field": "request.target_url",
        "post_ssrf_content_type": "application/json",
        "post_ssrf_method": "POST",
        "post_ssrf_internal_url": "http://127.0.0.1:8111/internal/proof",
        "feature": "server-side URL fetch preview",
    }
    value.update(updates)
    return value


class Client:
    def __init__(self, base=TARGET, *, control=None, payoff=None, inventory=None):
        self.base = base
        self.timeout = 5
        self.calls = []
        self.control = control or page(
            {"ok": False, "error": "DNS resolution failed for ssrf-control.invalid"}, 502)
        self.payoff = payoff or page({"ok": True, "effect": "internal_resource_read", "proof": PROOF})
        self.inventory = inventory

    def request(self, method, path, data=None, headers=None, allow_redirects=True):
        self.calls.append((method, path, data, dict(headers or {}), allow_redirects))
        if method == "GET" and self.inventory is not None:
            return page(self.inventory)
        text = str(data or "")
        return dict(self.control if "ssrf-control.invalid" in urllib.parse.unquote_plus(text) else self.payoff)


def run(*, clue=None, preloaded=None, client=None, target=TARGET, max_requests=4,
        deadline=None, stop=None, baseline_texts=None, route_allowed=None):
    client = client or Client(base=target)
    cached = {
        "/": page({"service": "preview", "decoy": DECOY}),
        "/api/clues": page(clues() if clue is None else clue),
    } if preloaded is None else dict(preloaded)
    sink, evidence = {}, []
    ctx = {
        "client": client,
        "deadline": time.time() + 10 if deadline is None else deadline,
        "max_requests": max_requests,
        "preloaded": cached,
        "baseline_texts": list(baseline_texts or []),
        "result_sink": sink,
        "evidence": evidence,
        "stop": stop,
    }
    if route_allowed is not None:
        ctx["route_allowed"] = route_allowed
    proof = S.solve({"url": target, "answer_id": "answer"}, ctx)
    return proof, sink["answer"], client.calls, evidence


def test_exact_nested_json_contract_and_wire_shape():
    proof, summary, calls, _ = run()
    assert proof == PROOF, summary
    assert summary["requests"] == summary["posts"] == 2 and summary["terminal"] is True
    assert [row[0] for row in calls] == ["POST", "POST"]
    assert all(row[1] == "/api/preview-41" and row[4] is False for row in calls)
    assert all(row[3] == {"Content-Type": "application/json"} for row in calls)
    assert json.loads(calls[0][2]) == {"request": {"target_url": "http://ssrf-control.invalid/"}}
    assert json.loads(calls[1][2]) == {
        "request": {"target_url": "http://127.0.0.1:8111/internal/proof"}}
    assert summary["confirmed"] is True and summary["success"] is True


def test_exact_form_and_constructed_internal_route():
    clue = {
        "ssrf_route": "/api/url-reader",
        "ssrf_field": "url",
        "ssrf_content_type": "application/x-www-form-urlencoded; charset=UTF-8",
        "ssrf_method": "POST",
        "secondary_route": "/internal/evidence",
        "internal_port": 5000,
        "internal_host": "[::1]",
        "feature": "SSRF URL reader",
    }
    # Bracketed host values are deliberately refused as host fields; brackets
    # are transport syntax, not an address. The direct URL form is accepted.
    proof, summary, calls, _ = run(clue=clue)
    assert proof is None and calls == [] and summary["requests"] == 0
    clue["internal_host"] = "::1"
    proof, summary, calls, _ = run(clue=clue)
    assert proof == PROOF and len(calls) == 2, summary
    assert urllib.parse.parse_qs(calls[0][2]) == {"url": ["http://ssrf-control.invalid/"]}
    assert urllib.parse.parse_qs(calls[1][2]) == {"url": ["http://[::1]:5000/internal/evidence"]}
    assert calls[1][3] == {"Content-Type": "application/x-www-form-urlencoded"}


def test_generic_keys_need_explicit_transport_or_openapi():
    generic = {
        "feature": "server-side fetch of a URL for read-only preview",
        "feature_route": "/api/preview-41",
        "url_field": "url",
        "content_type": "application/json",
        "internal_url": "http://127.1:8111/internal/proof",
    }
    proof, summary, calls, _ = run(clue=generic)
    assert proof is None and calls == [] and summary["requests"] == 0
    proof, summary, calls, _ = run(clue={**generic, "request_method": "POST"})
    assert proof == PROOF and len(calls) == 2

    spec = {
        "openapi": "3.1.0",
        "paths": {"/api/preview-41": {"post": {"requestBody": {
            "required": True,
            "content": {"application/json": {"schema": {
                "type": "object", "required": ["url"],
                "properties": {"url": {"type": "string", "format": "uri"}},
            }}},
        }}}},
    }
    proof, summary, calls, _ = run(clue=generic, preloaded={
        "/api/clues": page(generic), "/openapi.json": page(spec)})
    assert proof == PROOF and len(calls) == 2 and summary["findings"][0]["contract_source"] == "openapi"


def test_exact_linked_inventory_can_supply_contract_once():
    clue = {"feature": "server-side URL fetch preview", "inventory_route": "/api/fetch-contract"}
    inventory = clues()
    client = Client(inventory=inventory)
    proof, summary, calls, _ = run(clue=clue, client=client)
    assert proof == PROOF and [row[0] for row in calls] == ["GET", "POST", "POST"], (summary, calls)
    assert calls[0][1] == "/api/fetch-contract" and calls[0][4] is False
    assert summary["requests"] == 3 and summary["posts"] == 2

    proof, summary, calls, _ = run(clue=clue, client=Client(inventory=inventory), max_requests=2)
    assert proof is None and calls == [] and summary["requests"] == 0


def test_contract_authority_never_cross_synthesizes_documents():
    clue = {
        "feature": "server-side URL fetch preview",
        "post_ssrf_route": "/api/preview-41",
        "inventory_route": "/api/fetch-contract",
    }
    partial_inventory = {
        "post_ssrf_field": "url",
        "post_ssrf_content_type": "application/json",
        "post_ssrf_method": "POST",
        "post_ssrf_internal_url": "http://127.0.0.1:8111/internal/proof",
        "feature": "SSRF URL reader",
    }
    proof, summary, calls, _ = run(preloaded={
        "/api/clues": page(clue),
        "/api/fetch-contract": page(partial_inventory),
    })
    assert proof is None and calls == [] and summary["requests"] == 0, summary


def test_same_document_aliases_and_destination_representations_must_agree():
    conflicts = (
        clues(ssrf_route="/api/different"),
        clues(ssrf_field="other_url"),
        clues(ssrf_content_type="application/x-www-form-urlencoded"),
        clues(ssrf_method="GET"),
        clues(internal_url="http://127.0.0.1:8111/other"),
        clues(secondary_route="/other", internal_port=8111),
        clues(secondary_route="/internal/proof", internal_port="9" * 5000),
    )
    for clue in conflicts:
        proof, summary, calls, _ = run(clue=clue)
        assert proof is None and calls == [] and summary["requests"] == 0, (clue, summary)

    equivalent = clues(secondary_route="/internal/proof", internal_port=8111,
                       internal_host="127.0.0.1", internal_scheme="http")
    proof, summary, calls, _ = run(clue=equivalent)
    assert proof == PROOF and len(calls) == 2, summary

    # Two individually complete but conflicting contracts are ambiguous too.
    other = clues(post_ssrf_route="/api/other-preview")
    proof, summary, calls, _ = run(preloaded={
        "/api/clues": page(clues(inventory_route="/api/fetch-contract")),
        "/api/fetch-contract": page(other),
    })
    assert proof is None and calls == [] and summary["requests"] == 0, summary


def test_authority_document_requires_clean_carrier_integrity():
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr("clues.json", json.dumps(clues()))
        bundle.writestr("../ambiguous.json", "{}")
    proof, summary, calls, _ = run(preloaded={
        "/api/clues": page(archive.getvalue(), headers={"Content-Type": "application/zip"}),
    })
    assert proof is None and calls == [] and summary["requests"] == 0, summary


def test_query_specific_and_colliding_cache_entries_are_not_authority():
    for cached in (
            {"/api/clues?mode=privileged": page(clues())},
            {"/api/clues": page(clues()), "/%61pi/clues": page(clues())}):
        proof, summary, calls, _ = run(preloaded=cached)
        assert proof is None and calls == [] and summary["requests"] == 0, summary
    late = {"/api/clues": page(clues())}
    late.update({f"/filler-{index}": page({"ordinary": index})
                 for index in range(S.MAX_DOCS - 1)})
    late["/%61pi/clues"] = page(clues())
    proof, summary, calls, _ = run(preloaded=late)
    assert proof is None and calls == [] and summary["requests"] == 0, summary


def test_contract_rejections_are_zero_wire():
    cases = [
        clues(post_ssrf_method="GET"),
        clues(post_ssrf_content_type="multipart/form-data"),
        clues(post_ssrf_route="https://evil.invalid/api/preview"),
        clues(post_ssrf_route="/api/reset-preview"),
        clues(post_ssrf_route="/deleteUser"),
        clues(post_ssrf_route="/transferFunds"),
        clues(post_ssrf_route="/deleteuser"),
        clues(post_ssrf_route="/resetpassword"),
        clues(post_ssrf_route="/createjob"),
        clues(post_ssrf_route="/transferfunds"),
        clues(post_ssrf_route="/delete;foo"),
        clues(post_ssrf_route="/reset,confirm"),
        clues(post_ssrf_route="/logout+now"),
        clues(post_ssrf_field="callback"),
        clues(post_ssrf_field="headers.url"),
        clues(post_ssrf_internal_url="https://example.com/proof"),
        clues(post_ssrf_internal_url="http://127.0.0.1/delete/all"),
        clues(post_ssrf_internal_url="http://user@127.0.0.1/internal/proof"),
        clues(post_ssrf_internal_url="http://127.0.0.1/internal/proof#x"),
        clues(post_ssrf_internal_url="gopher://127.0.0.1/_x"),
        clues(post_ssrf_internal_url="file:///etc/passwd"),
        clues(post_ssrf_internal_url="file://localhost/etc/passwd"),
        clues(post_ssrf_internal_url="http://127.0.0.1:99999/x"),
        clues(post_ssrf_internal_url="http://127.0.0.1/%252e%252e/delete"),
        clues(post_ssrf_internal_url="http://127.0.0.1/internal\\proof"),
        clues(post_ssrf_internal_url="http://127.0.0.1/deleteUser"),
        clues(post_ssrf_internal_url="http://127.0.0.1/deleteuser"),
        clues(post_ssrf_internal_url="http://127.0.0.1/resetpassword"),
        clues(post_ssrf_internal_url="http://127.0.0.1/createjob"),
        clues(post_ssrf_internal_url="http://127.0.0.1/transferfunds"),
        clues(post_ssrf_internal_url="http://127.0.0.1/delete;foo"),
        clues(post_ssrf_internal_url="http://127.0.0.1/reset,confirm"),
        clues(post_ssrf_internal_url="http://127.0.0.1/logout+now"),
        clues(post_ssrf_internal_url="http://169.254.169.254/latest/meta-data/iam/security-credentials/role"),
        clues(post_ssrf_internal_url="http://169.254.170.2/v2/credentials/task"),
        clues(post_ssrf_internal_url="http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"),
        clues(post_ssrf_internal_url="http://127.0.0.1/internal/accessToken"),
    ]
    for clue in cases:
        proof, summary, calls, _ = run(clue=clue)
        assert proof is None and calls == [] and summary["requests"] == 0, (clue, summary, calls)


def test_openapi_unresolved_peers_cycles_and_security_decline():
    generic = {
        "feature": "URL fetch preview", "feature_route": "/api/preview-41",
        "url_field": "url", "content_type": "application/json",
        "internal_url": "http://127.0.0.1:8111/internal/proof",
    }

    def with_schema(schema, **operation):
        return {"openapi": "3.1.0", "paths": {"/api/preview-41": {"post": {
            "requestBody": {"required": True, "content": {"application/json": {"schema": schema}}},
            **operation,
        }}}}

    schemas = [
        {"type": "object", "required": ["url", "tenant"],
         "properties": {"url": {"type": "string"}, "tenant": {"type": "string"}}},
        {"oneOf": [{"type": "object", "properties": {"url": {"type": "string"}}}]},
        {"$ref": "#/components/schemas/A"},
    ]
    specs = [with_schema(schemas[0]), with_schema(schemas[1]), {
        **with_schema(schemas[2]),
        "components": {"schemas": {"A": {"$ref": "#/components/schemas/B"},
                                   "B": {"$ref": "#/components/schemas/A"}}},
    }, with_schema({"type": "object", "required": ["url"],
                    "properties": {"url": {"type": "string"}}},
                   security=[{"bearerAuth": []}])]
    for spec in specs:
        proof, summary, calls, _ = run(preloaded={
            "/api/clues": page(generic), "/openapi.json": page(spec)})
        assert proof is None and calls == [] and summary["requests"] == 0, summary

    root_security = with_schema(
        {"type": "object", "required": ["url"],
         "properties": {"url": {"type": "string"}}})
    root_security["security"] = [{"bearerAuth": []}]
    proof, summary, calls, _ = run(preloaded={
        "/api/clues": page(generic), "/openapi.json": page(root_security)})
    assert proof is None and calls == [] and summary["requests"] == 0, summary

    referenced_parameter = with_schema(
        {"type": "object", "required": ["url"],
         "properties": {"url": {"type": "string"}}},
        parameters=[{"$ref": "#/components/parameters/Auth"}])
    referenced_parameter["components"] = {"parameters": {
        "Auth": {"in": "header", "name": "X-API-Key", "required": True,
                 "schema": {"type": "string"}}
    }}
    proof, summary, calls, _ = run(preloaded={
        "/api/clues": page(generic), "/openapi.json": page(referenced_parameter)})
    assert proof is None and calls == [] and summary["requests"] == 0, summary


def test_invalid_control_must_prove_network_fetch_and_is_terminal():
    for control in (
        page({"error": "invalid URL"}, 400),
        page({"error": "blocked by policy"}, 403),
        page({"ok": True, "value": "http://ssrf-control.invalid/"}, 200),
        page({"error": "upstream fetch timed out"}, 504),
        page("WAF", 502),
    ):
        client = Client(control=control)
        proof, summary, calls, _ = run(client=client)
        assert proof is None and len(calls) == 1 and summary["terminal"] is True, summary
    client = Client(control=page({"error": "getaddrinfo ENOTFOUND ssrf-control.invalid"}, 200))
    proof, summary, calls, _ = run(client=client)
    assert proof == PROOF and len(calls) == 2


def test_novelty_redirect_ambiguity_and_credentials_never_guess():
    client = Client(payoff=page({"ok": True, "proof": PROOF}, headers={"Location": "/elsewhere"}, status=302))
    proof, summary, calls, _ = run(client=client)
    assert proof is None and len(calls) == 2 and all(row[4] is False for row in calls)

    client = Client(payoff=page({"ok": True, "proof": PROOF, "evidence": PROOF_TWO}))
    proof, summary, calls, evidence = run(client=client)
    assert proof is None and summary["success"] is True and evidence, summary

    client = Client(payoff=page({"ok": True, "AccessKeyId": "AKIAABCDEFGHIJKLMNOP",  # secret-scan: allow
                                 "SecretAccessKey": "top-secret", "Token": "session-token"}))
    proof, summary, calls, evidence = run(client=client)
    assert proof is None and summary["candidates"] == [] and evidence == [], summary

    client = Client(payoff=page({"ok": True, "proof": PROOF}))
    proof, summary, calls, _ = run(client=client, baseline_texts=[f"landing {PROOF}"])
    assert proof is None and len(calls) == 2, summary


def test_budget_stop_deadline_scope_and_private_target():
    for kwargs in ({"max_requests": 1}, {"deadline": time.time() - 1},
                   {"stop": type("Stop", (), {"is_set": lambda self: True})()}):
        proof, summary, calls, _ = run(**kwargs)
        assert proof is None and calls == [] and summary["requests"] == 0, summary

    mismatch = Client(base="https://other.2026.huntress.ctf.games/")
    proof, summary, calls, _ = run(client=mismatch)
    assert proof is None and calls == [] and "scope mismatch" in str(summary["stopped"])

    clue = clues(post_ssrf_internal_url="http://10.1.2.3:9000/internal/proof")
    private = Client(base=PRIVATE_TARGET)
    proof, summary, calls, _ = run(clue=clue, client=private, target=PRIVATE_TARGET)
    assert proof == PROOF and len(calls) == 2, summary


def test_route_policy_and_target_headers_cannot_escape_contract():
    clue = clues(headers={"Authorization": "Bearer target-token", "X-Method": "DELETE"})
    proof, summary, calls, _ = run(clue=clue)
    assert proof == PROOF and all(set(row[3]) == {"Content-Type"} for row in calls)

    proof, summary, calls, _ = run(route_allowed=lambda _path: False)
    assert proof is None and calls == [] and summary["requests"] == 0


def test_near_miss_payoffs_are_candidates_never_the_answer():
    # R-06: a payoff-shaped near miss (flagfmt.PAYOFF_SHAPE: the proof's lead with another body, or the
    # exact proof in another case) is surfaced as an SSRF candidate and never returned.
    for near in ("proof_future-format-x", "PROOF_" + PROOF[len("proof_"):].upper()):
        client = Client(payoff=page({"ok": True, "effect": "internal_resource_read", "proof": near}))
        proof, summary, calls, _ = run(client=client)
        assert proof is None and summary["proof"] is None, (near, summary)
        assert near in summary["candidates"], (near, summary)
        assert summary["success"] is True and len(calls) == 2, (near, summary)


if __name__ == "__main__":
    funcs = [value for name, value in sorted(globals().items()) if name.startswith("test_") and callable(value)]
    for func in funcs:
        func()
        print("PASS", func.__name__)
    print(f"PASS all {len(funcs)} POST-body SSRF tests")
