#!/usr/bin/env python3
"""Offline regressions for peer-client scope and coherent Federation gates."""

from __future__ import annotations

import importlib
import json
import sys
import time
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path[:0] = [str(REPO / "solvers" / "web"), str(REPO / "solvers" / "toolkits")]

G = importlib.import_module("graphql_read")
S = importlib.import_module("ssrf_body")
P = importlib.import_module("post_chain")
D = importlib.import_module("double_spend")
C = importlib.import_module("passive_checks")
R = importlib.import_module("reset_rebind")
T = importlib.import_module("realtime_read")


BASE = "https://target.test/"


class NeverClient:
    def __init__(self, base):
        self.base = base
        self.timeout = 1.0
        self.calls = []

    def request(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        raise AssertionError("scope-invalid peer attempted a request")


def _context(client):
    return {"client": client, "deadline": time.time() + 5, "max_requests": 4,
            "preloaded": {}, "baseline_texts": [], "evidence": [], "result_sink": {}}


def _runners(target_url, client):
    target = {"url": target_url, "answer_id": "answer", "question": "Recover the proof."}
    ctx = _context(client)
    return [
        G._Reader(target, dict(ctx)),
        S._Runner(target, dict(ctx)),
        P._Runner(target, dict(ctx)),
        D._DoubleSpend(target, dict(ctx)),
        C._Checks(target, dict(ctx)),
        R._ResetRebind(target, dict(ctx)),
        T._Reader(target, dict(ctx)),
    ]


def test_malformed_or_credentialed_none_origins_never_accept_an_injected_client():
    modules = (G, S, P, D, C, R, T)
    invalid = ("not a URL", "https://user:secret@target.test/",
               "https://target.test/path#fragment")
    for value in invalid:
        for module in modules:
            assert module._origin(value) is None, (module.__name__, value)
        client = NeverClient(value)
        for runner in _runners(value, client):
            # The SSRF reader intentionally constructs its client lazily.
            accepted = runner._client() if isinstance(runner, S._Runner) else runner.client
            assert accepted is None, (type(runner).__name__, value)
        assert client.calls == []


def test_exact_valid_origin_still_accepts_the_injected_client():
    client = NeverClient(BASE)
    for runner in _runners(BASE, client):
        accepted = runner._client() if isinstance(runner, S._Runner) else runner.client
        assert accepted is client, type(runner).__name__
    assert client.calls == []


class SplitFederationClient:
    """Each response names only one Federation concept; none is a contract."""

    base = BASE
    timeout = 1.0

    def __init__(self):
        self.calls = []

    @staticmethod
    def response(status, value, content_type="application/json"):
        body = value if isinstance(value, bytes) else json.dumps(value, separators=(",", ":")).encode()
        return {"status": status, "body": body,
                "response_headers": {"Content-Type": content_type}}

    def request(self, method, path, data=None, headers=None, allow_redirects=None):
        self.calls.append((method, path, data, allow_redirects))
        if method == "GET" and path == "/":
            return self.response(200, b"GraphQL Apollo Federation", "text/plain")
        if method == "GET" and path == "/api/clues":
            return self.response(200, {
                "feature_route": "/graphql",
                "protected_reference": "42",
                "note": "GraphQL resolver authorization through _service",
            })
        if method == "GET" and path == "/graphql":
            return self.response(405, {"error": "SDL transport requires a query"})
        payload = json.loads(data if isinstance(data, str) else bytes(data or b"").decode())
        document = payload.get("query")
        if document == G.INTROSPECTION_QUERY:
            return self.response(200, {"errors": [{"message": "GraphQL introspection disabled"}]})
        if document == G.FEDERATION_SDL_QUERY:
            return self.response(200, {"data": {"_service": {
                "sdl": "type Query { record(id: ID!): String } scalar ID",
            }}})
        return self.response(200, {"errors": [{"message": "unexpected query"}]})


def test_federation_advertisement_must_be_one_coherent_control():
    assert not G._advertises_federation(
        "Apollo Federation", "the _service field", "its SDL")
    assert G._advertises_federation(
        "Apollo Federation exposes the _service SDL")

    client = SplitFederationClient()
    ctx = _context(client)
    result = G.solve({"url": BASE, "answer_id": "answer", "question": "Recover it."}, ctx)
    assert result is None
    documents = []
    for method, _path, data, redirects in client.calls:
        assert redirects is False
        if method == "POST":
            documents.append(json.loads(data)["query"])
    assert documents == [G.INTROSPECTION_QUERY]
    assert G.FEDERATION_SDL_QUERY not in documents


if __name__ == "__main__":
    class ScopeHardeningTests(unittest.TestCase):
        def test_invalid_origins(self):
            test_malformed_or_credentialed_none_origins_never_accept_an_injected_client()

        def test_valid_origin(self):
            test_exact_valid_origin_still_accepts_the_injected_client()

        def test_coherent_federation_advertisement(self):
            test_federation_advertisement_must_be_one_coherent_control()

    unittest.main(verbosity=2)
