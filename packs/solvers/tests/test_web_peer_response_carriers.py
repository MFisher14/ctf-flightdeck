#!/usr/bin/env python3
"""Every narrow web peer shares bounded response decoding (no network)."""

from __future__ import annotations

import gzip
import importlib
import json
import sys
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path[:0] = [str(REPO / "solvers" / "web"), str(REPO / "solvers" / "toolkits")]


PROOF = "proof_0123456789abcdef0123456789abcdef"
SECOND = "proof_fedcba9876543210fedcba9876543210"


def encoded(value, *, malformed=False):
    raw = json.dumps(value, separators=(",", ":")).encode()
    body = (b"not-gzip " + raw) if malformed else gzip.compress(raw)
    return {
        "status": 200,
        "body": body,
        "response_headers": {"Content-Type": "application/json", "Content-Encoding": "gzip"},
        "response_header_pairs": [
            ("Content-Type", "application/json"), ("Content-Encoding", "gzip"),
            ("X-Control", PROOF), ("X-Control", SECOND),
        ],
    }


def multipart(*parts):
    boundary = "huntress-policy-boundary"
    body = bytearray()
    for content_type, value in parts:
        raw = value if isinstance(value, bytes) else str(value).encode()
        body.extend(f"--{boundary}\r\nContent-Type: {content_type}\r\n\r\n".encode())
        body.extend(raw)
        body.extend(b"\r\n")
    body.extend(f"--{boundary}--\r\n".encode())
    return {
        "status": 200,
        "body": bytes(body),
        "response_headers": {"Content-Type": f'multipart/mixed; boundary="{boundary}"'},
    }


def test_every_json_peer_reads_gzip_and_fails_closed_on_malformed_encoding():
    document = {"ok": True, "effect": "read", "proof": PROOF}
    modules = {
        "double_spend": "_json",
        "graphql_read": "_json",
        "hpp_read": "_json",
        "passive_checks": "_json",
        "realtime_read": "_json",
        "reset_rebind": "_json",
        "ssrf_body": "_json",
        "xxe_read": "_json",
    }
    for name, helper in modules.items():
        module = importlib.import_module(name)
        got = getattr(module, helper)(encoded(document))
        assert got == document, (name, got)
        bad = getattr(module, helper)(encoded(document, malformed=True))
        assert bad is None, (name, bad)

    post = importlib.import_module("post_chain")
    assert post._json_document(encoded(document)) == document
    assert post._json_document(encoded(document, malformed=True)) is None


def test_ordered_duplicate_headers_are_controls_for_legacy_peer_families():
    response = encoded({"ok": False, "error": "control"})
    for name in ("double_spend", "graphql_read", "post_chain"):
        module = importlib.import_module(name)
        baseline = module._baseline_text(response)
        assert PROOF in baseline and SECOND in baseline, (name, baseline)


def test_every_json_peer_finds_one_later_sibling_without_joining_or_choosing():
    document = {"ok": True, "effect": "read", "proof": PROOF}
    later = multipart(("text/plain", "diagnostic only"),
                      ("application/json", json.dumps(document, separators=(",", ":"))))
    ambiguous = multipart(
        ("application/json", json.dumps({"ok": False, "effect": "denied"})),
        ("application/json", json.dumps(document, separators=(",", ":"))),
    )
    modules = {
        "double_spend": "_json",
        "graphql_read": "_json",
        "hpp_read": "_json",
        "passive_checks": "_json",
        "realtime_read": "_json",
        "reset_rebind": "_json",
        "ssrf_body": "_json",
        "xxe_read": "_json",
    }
    for name, helper in modules.items():
        module = importlib.import_module(name)
        assert getattr(module, helper)(later) == document, name
        assert getattr(module, helper)(ambiguous) is None, name

    post = importlib.import_module("post_chain")
    assert post._json_document(later) == document
    assert post._json_document(ambiguous) is None


def test_endpoint_inventory_parses_compressed_openapi_but_not_malformed_source():
    inventory = importlib.import_module("endpoint_inventory")
    spec = {"openapi": "3.1.0", "paths": {"/compressed": {"get": {}}}}
    loaded = inventory._load_api_document("/openapi.json", encoded(spec))
    assert loaded and loaded[0] == spec and loaded[1].startswith("openapi-3.1"), loaded
    assert inventory._load_api_document("/openapi.json", encoded(spec, malformed=True)) is None


def test_incomplete_baseline_disables_custom_peer_auto_proofs():
    forge = importlib.import_module("forge_event")
    baseline = forge.response_baseline_text({
        "status": 200,
        "body": b"visible control prefix",
        "response_headers": {"Content-Type": "text/plain"},
        "truncated": True,
    })
    assert forge.baseline_set_incomplete([baseline])

    graphql = importlib.import_module("graphql_read")
    graph = graphql._result_evidence({"proof": PROOF}, [baseline], host="target.test")
    assert graph["auto"] is None and graph["baseline_incomplete"] is True, graph

    post = importlib.import_module("post_chain")
    payoff = {"status": 200,
              "body": json.dumps({"ok": True, "proof": PROOF}).encode()}
    chained = post.extract_anchored(
        payoff, [baseline], anchored=True, host="target.test")
    assert chained["auto"] is None and chained["baseline_incomplete"] is True, chained


def main():
    tests = [value for name, value in sorted(globals().items())
             if name.startswith("test_") and callable(value)]
    for test in tests:
        test()
        print("PASS", test.__name__)
    print(f"PASS all {len(tests)} peer response-carrier tests")


if __name__ == "__main__":
    main()
