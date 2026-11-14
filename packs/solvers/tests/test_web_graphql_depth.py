#!/usr/bin/env python3
"""No-network adversarial coverage for safe GraphQL GET/Federation/APQ depth."""

from __future__ import annotations

import event_pin  # noqa: E402  (tests/event_pin.py)
event_pin.pin(globals(), "huntress")  # Huntress web tests: proof_<32 hex> payoffs (events/huntress [proof])

import hashlib
import importlib.util
import json
import re
import sys
import threading
import time
import unittest
import urllib.parse
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
MODULE = REPO / "solvers" / "web" / "graphql_read.py"
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("graphql_read_depth", MODULE)
if spec is None or spec.loader is None:
    raise RuntimeError(f"cannot load {MODULE}")
G = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = G
spec.loader.exec_module(G)

BASE = "https://target.test/"
PROOF = "proof_0123456789abcdef0123456789abcdef"
SECOND = "proof_fedcba9876543210fedcba9876543210"
DECOY = "proof_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"


def scalar(name):
    return {"kind": "SCALAR", "name": name, "ofType": None}


def nonnull(node):
    return {"kind": "NON_NULL", "name": None, "ofType": node}


def object_type(name):
    return {"kind": "OBJECT", "name": name, "ofType": None}


def introspection_schema(fields=None):
    fields = fields or [{
        "name": "case",
        "args": [{"name": "id", "defaultValue": None, "type": nonnull(scalar("ID"))}],
        "type": object_type("Record"),
    }]
    return {"data": {"__schema": {
        "queryType": {"name": "Query"},
        "types": [
            {"kind": "OBJECT", "name": "Query", "fields": fields},
            {"kind": "OBJECT", "name": "Record", "fields": [
                {"name": "id", "args": [], "type": scalar("ID")},
                {"name": "note", "args": [], "type": scalar("String")},
            ]},
            {"kind": "SCALAR", "name": "ID", "fields": None},
            {"kind": "SCALAR", "name": "String", "fields": None},
        ],
    }}}


SAFE_SDL = """
  type Query { case(id: ID!): Record }
  type Record @key(fields: "id") { id: ID note: String }
  scalar ID
  scalar String
"""


class FakeClient:
    """Scope-compatible WebClient stand-in; it never opens a socket."""

    def __init__(self, *, clues=None, schema=None, sdl=None, landing="GraphQL endpoint",
                 feature=(405, {"error": "query_required"}), require_apq=False,
                 introspection_disabled=False, manifest=None, read=None,
                 redirect_introspection=False):
        self.base = BASE
        self.timeout = 2.0
        self.clues = dict(clues or {
            "feature_route": "/graphql", "protected_reference": "42",
            "note": "GraphQL resolver field-level authorization",
        })
        self.schema = schema or introspection_schema()
        self.sdl = sdl
        self.landing = landing
        self.feature = feature
        self.require_apq = require_apq
        self.introspection_disabled = introspection_disabled
        self.manifest = manifest
        self.read = read
        self.redirect_introspection = redirect_introspection
        self.calls = []
        self.lock = threading.Lock()

    @staticmethod
    def response(status, value, headers=None):
        body = value if isinstance(value, bytes) else json.dumps(value, separators=(",", ":")).encode()
        return {"status": status, "body": body,
                "response_headers": {"Content-Type": "application/json", **(headers or {})}}

    @staticmethod
    def payload(method, path, data):
        if method == "GET":
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query, keep_blank_values=True)
            if "query" not in query:
                return None
            try:
                out = {"query": query["query"][0],
                       "variables": json.loads(query.get("variables", ["{}"]) [0])}
                if "extensions" in query:
                    out["extensions"] = json.loads(query["extensions"][0])
                return out
            except Exception:
                return None
        try:
            return json.loads((data or b"").decode() if isinstance(data, bytes) else str(data or ""))
        except Exception:
            return None

    def request(self, method, path, *, data=None, headers=None, allow_redirects=None):
        call = {"method": method, "path": path, "data": data, "headers": dict(headers or {}),
                "allow_redirects": allow_redirects}
        with self.lock:
            self.calls.append(call)
        parsed = urllib.parse.urlsplit(path)
        if method == "GET" and parsed.path == "/" and not parsed.query:
            return self.response(200, self.landing.encode(), {"Content-Type": "text/html"})
        if method == "GET" and parsed.path == "/api/clues" and not parsed.query:
            return self.response(200, self.clues)
        if method == "GET" and parsed.path == "/apq-manifest.json" and not parsed.query:
            return self.response(200, self.manifest if self.manifest is not None else {})
        route = urllib.parse.urlsplit(str(self.clues.get("feature_route") or "/none")).path
        if parsed.path != route:
            return self.response(404, {"error": "not_found"})
        payload = self.payload(method, path, data)
        if payload is None:
            return self.response(*self.feature)
        document = payload.get("query") if isinstance(payload, dict) else None
        extension = ((payload.get("extensions") or {}).get("persistedQuery")
                     if isinstance(payload, dict) else None)
        if self.require_apq:
            wanted = hashlib.sha256(str(document or "").encode()).hexdigest()
            if not isinstance(extension, dict) or extension.get("version") != 1 \
                    or extension.get("sha256Hash") != wanted:
                return self.response(200, {"errors": [{"message": "PersistedQueryRequired",
                                                        "extensions": {"code": "PERSISTED_QUERY_NOT_FOUND"}}]})
        if "__schema" in str(document):
            if self.redirect_introspection:
                return self.response(302, b"redirect", {"Location": "https://evil.invalid/graphql"})
            if self.introspection_disabled:
                return self.response(200, {"errors": [{"message": "GraphQL introspection disabled"}]})
            return self.response(200, self.schema)
        if document == G.FEDERATION_SDL_QUERY:
            if self.sdl is None:
                return self.response(200, {"errors": [{"message": "unknown field _service"}]})
            return self.response(200, {"data": {"_service": {"sdl": self.sdl}}})
        match = re.search(r"\b(r\d+)\s*:\s*([_A-Za-z][_0-9A-Za-z]*)\s*\(", str(document or ""))
        if not match:
            return self.response(200, {"errors": [{"message": "bad generated query"}]})
        alias, field = match.groups()
        if callable(self.read):
            return self.response(200, self.read(alias, field, payload))
        return self.response(200, {"data": {alias: {"id": "42", "note": PROOF}}})


def target():
    return {"answer_id": "proof-1", "url": BASE, "index": 1,
            "question": "Recover the proof."}


def context(client, **values):
    out = {"client": client, "deadline": time.time() + 5,
           "max_requests": 12, "evidence": [], "result_sink": {}}
    out.update(values)
    return out


def payload_calls(client):
    return [(call, client.payload(call["method"], call["path"], call["data"]))
            for call in client.calls if client.payload(call["method"], call["path"], call["data"]) is not None]


class GraphQLDepthTests(unittest.TestCase):
    def assert_query_only(self, client):
        for call, payload in payload_calls(client):
            self.assertIsInstance(payload, dict)
            document = payload.get("query")
            self.assertTrue(G._query_only(document), (call, payload))
            self.assertNotRegex(document, r"(?i)\b(?:mutation|subscription)\b")
            self.assertFalse(call["allow_redirects"])

    def test_exact_get_only_transport_encodes_query_and_injection_as_one_variable(self):
        reference = "alpha&query=mutation Evil{deleteAll}&variables={bad}#fragment"
        client = FakeClient(clues={
            "feature_route": "/graphql", "protected_reference": reference,
            "graphql_transport": "GET only", "note": "GraphQL resolver field-level authorization",
        }, landing="GraphQL " + DECOY,
            feature=(405, {"error": "GET query required", "decoy": SECOND}))
        ctx = context(client)
        answer = G.solve(target(), ctx)
        self.assertEqual(answer, PROOF)
        self.assertTrue(client.calls)
        self.assertTrue(all(call["method"] == "GET" for call in client.calls))
        self.assertTrue(all(call["allow_redirects"] is False for call in client.calls))
        graph_calls = payload_calls(client)
        self.assertEqual(len(graph_calls), 2)
        read_payload = graph_calls[-1][1]
        self.assertEqual(read_payload["variables"], {"ref": reference})
        self.assertNotIn(reference, read_payload["query"])
        parsed = urllib.parse.parse_qs(urllib.parse.urlsplit(graph_calls[-1][0]["path"]).query)
        self.assertEqual(set(parsed), {"query", "variables"})
        self.assertNotIn("#fragment", urllib.parse.urlsplit(graph_calls[-1][0]["path"]).fragment)
        summary = ctx["result_sink"]["proof-1"]
        self.assertEqual(summary["transport"], "GET")
        self.assertCountEqual(summary["baseline_proofs"], [DECOY, SECOND])
        self.assertNotIn(PROOF, summary["baseline_proofs"])
        self.assert_query_only(client)

    def test_get_apq_hashes_exact_generated_documents_and_never_posts(self):
        client = FakeClient(clues={
            "feature_route": "/graphql", "protected_reference": "77",
            "method": "only GET", "note": "GraphQL resolver field-level authorization",
        }, require_apq=True)
        ctx = context(client)
        self.assertEqual(G.solve(target(), ctx), PROOF)
        self.assertFalse(any(call["method"] == "POST" for call in client.calls))
        operations = payload_calls(client)
        self.assertEqual(len(operations), 3)
        self.assertNotIn("extensions", operations[0][1])
        for _call, payload in operations[1:]:
            persisted = payload["extensions"]["persistedQuery"]
            self.assertEqual(persisted["version"], 1)
            self.assertEqual(persisted["sha256Hash"],
                             hashlib.sha256(payload["query"].encode()).hexdigest())
        self.assertTrue(ctx["result_sink"]["proof-1"]["persisted_queries"])
        self.assert_query_only(client)

    def test_get_url_cap_and_redirects_fail_closed(self):
        huge = "x" * G.MAX_GET_URL_BYTES
        client = FakeClient(clues={
            "feature_route": "/graphql", "protected_reference": huge,
            "method": "GET only", "note": "GraphQL resolver field-level authorization",
        })
        ctx = context(client)
        self.assertIsNone(G.solve(target(), ctx))
        self.assertTrue(all(len(call["path"].encode()) <= G.MAX_GET_URL_BYTES for call in client.calls))
        self.assertEqual(len(payload_calls(client)), 1, "only bounded introspection may leave")
        self.assertIn("oversized", ctx["result_sink"]["proof-1"]["stopped"])

        redirect = FakeClient(redirect_introspection=True)
        redirect_ctx = context(redirect)
        self.assertIsNone(G.solve(target(), redirect_ctx))
        self.assertEqual(len(redirect.calls), 4)
        self.assertTrue(all(call["allow_redirects"] is False for call in redirect.calls))
        self.assertFalse(any("evil.invalid" in call["path"] for call in redirect.calls))

    def test_introspection_disabled_has_no_federation_fallback_without_explicit_gate(self):
        client = FakeClient(introspection_disabled=True, sdl=SAFE_SDL)
        ctx = context(client)
        self.assertIsNone(G.solve(target(), ctx))
        operations = [payload["query"] for _call, payload in payload_calls(client)]
        self.assertEqual(operations, [G.INTROSPECTION_QUERY])
        self.assertNotIn(G.FEDERATION_SDL_QUERY, operations)

    def test_explicit_federation_sdl_is_control_then_drives_one_safe_read(self):
        client = FakeClient(clues={
            "feature_route": "/graphql", "protected_reference": "fed-7",
            "note": "GraphQL resolver authorization; Apollo Federation exposes _service SDL",
        }, introspection_disabled=True, sdl=SAFE_SDL)
        ctx = context(client)
        self.assertEqual(G.solve(target(), ctx), PROOF)
        operations = [payload for _call, payload in payload_calls(client)]
        self.assertEqual(operations[1]["query"], G.FEDERATION_SDL_QUERY)
        self.assertEqual(operations[2]["variables"], {"ref": "fed-7"})
        summary = ctx["result_sink"]["proof-1"]
        self.assertEqual(summary["schema_source"], "federation-sdl")
        self.assert_query_only(client)

    def test_malicious_sdl_constructs_are_never_generated(self):
        sdl = '''
          """mutation Fake { deleteEverything } proof_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"""
          # subscription Evil { stream: String }
          schema { query: Query mutation: Mutation }
          type Query @tag(config: {name: "safe", nested: [1, 2]}) {
            case(id: ID!, tenant: String!): Record
            lookup(id: ID!): Record
            _entities(representations: [String!]!): _Entity
            deleteRecord(id: ID!): String
            unionRead(id: ID!): Search
          }
          type Record @key(fields: "id") {
            id: ID
            note: String
            recursive: Record
            directed: String @requires(fields: "secret")
            sibling(arg: String!): String
          }
          union Search = Record | Other
          type Other { note: String }
          type Mutation { deleteEverything: String }
          scalar ID
          scalar String
        '''
        schema = G._sdl_schema(sdl)
        self.assertIsNotNone(schema)
        rows = G._query_candidates(schema, "9")
        self.assertEqual(len(rows), 1)
        document = rows[0]["document"]
        self.assertIn("lookup(id: $ref)", document)
        for forbidden in ("case(", "_entities", "deleteRecord", "unionRead", "recursive",
                          "directed", "sibling", "Mutation", "subscription"):
            self.assertNotIn(forbidden, document)
        self.assertTrue(G._query_only(document))

        client = FakeClient(clues={
            "feature_route": "/graphql", "protected_reference": "9",
            "note": "GraphQL Apollo Federation _service SDL resolver",
        }, introspection_disabled=True, sdl=sdl)
        ctx = context(client)
        self.assertEqual(G.solve(target(), ctx), PROOF)
        self.assert_query_only(client)

    def test_federation_reads_are_bounded_to_three_and_errors_are_controls(self):
        fields = "\n".join(f"record{i}(id: ID!): Record" for i in range(8))
        sdl = f"type Query {{ {fields} }} type Record {{ id: ID note: String }} scalar ID scalar String"

        def ordinary(alias, _field, _payload):
            return {"data": {alias: {"id": "1"}}}

        client = FakeClient(clues={
            "feature_route": "/graphql", "protected_reference": "1",
            "note": "GraphQL Apollo Federation _service SDL resolver",
        }, introspection_disabled=True, sdl=sdl, read=ordinary)
        ctx = context(client, max_requests=12)
        self.assertIsNone(G.solve(target(), ctx))
        reads = [payload for _call, payload in payload_calls(client)
                 if "GraphQLProtectedRead" in payload["query"]]
        self.assertEqual(len(reads), 3)

        def errored(alias, _field, _payload):
            return {"errors": [{"message": "denied " + PROOF}],
                    "data": {alias: {"note": PROOF}}}

        error_client = FakeClient(read=errored)
        error_ctx = context(error_client)
        self.assertIsNone(G.solve(target(), error_ctx))
        self.assertIn(PROOF, error_ctx["result_sink"]["proof-1"]["baseline_proofs"])
        self.assertFalse(error_ctx["evidence"])

    def test_baseline_decoys_two_payoff_proofs_and_same_baseline_are_never_wrong(self):
        distinct = FakeClient(landing="GraphQL " + DECOY)
        distinct_ctx = context(distinct)
        self.assertEqual(G.solve(target(), distinct_ctx), PROOF)
        self.assertIn(DECOY, distinct_ctx["result_sink"]["proof-1"]["baseline_proofs"])

        def two(alias, _field, _payload):
            return {"data": {alias: {"note": PROOF + " " + SECOND}}}

        ambiguous = FakeClient(read=two)
        ambiguous_ctx = context(ambiguous)
        self.assertIsNone(G.solve(target(), ambiguous_ctx))
        self.assertNotIn(PROOF, ambiguous_ctx["result_sink"]["proof-1"]["baseline_proofs"],
                         "a payoff response must not poison the shared baseline")
        self.assertIn(PROOF, "\n".join(ambiguous_ctx["evidence"]))
        self.assertIn(SECOND, "\n".join(ambiguous_ctx["evidence"]))

        same = FakeClient(landing="GraphQL " + PROOF)
        same_ctx = context(same)
        self.assertIsNone(G.solve(target(), same_ctx))
        self.assertIn(PROOF, same_ctx["result_sink"]["proof-1"]["baseline_proofs"])

    def test_local_manifest_is_findings_only_and_never_sends_target_operations(self):
        intro_hash = hashlib.sha256(G.INTROSPECTION_QUERY.encode()).hexdigest()
        mutation = "mutation Evil { deleteEverything }"
        mutation_hash = hashlib.sha256(mutation.encode()).hexdigest()
        manifest = {"operations": [
            {"id": intro_hash, "body": G.INTROSPECTION_QUERY},
            {"id": mutation_hash, "body": mutation},
            {"id": "0" * 64, "body": "query Mismatch { viewer { id } }"},
        ], "decoy": DECOY}
        client = FakeClient(landing='<link rel="preload" href="/apq-manifest.json"> GraphQL',
                            manifest=manifest)
        ctx = context(client)
        self.assertEqual(G.solve(target(), ctx), PROOF)
        sent = [payload["query"] for _call, payload in payload_calls(client)]
        self.assertNotIn(mutation, sent)
        self.assertTrue(all(G._query_only(document) for document in sent))
        summary = ctx["result_sink"]["proof-1"]
        self.assertEqual(summary["manifest_query_matches"], [intro_hash])
        finding = summary["findings"][0]
        self.assertEqual((finding["valid_queries"], finding["unsafe_operations"]), (1, 1))
        self.assertIn(DECOY, summary["baseline_proofs"])

        off_origin = FakeClient(landing='<script src="https://evil.invalid/apq-manifest.json"></script> GraphQL')
        off_ctx = context(off_origin)
        self.assertEqual(G.solve(target(), off_ctx), PROOF)
        self.assertFalse(any("manifest" in call["path"] for call in off_origin.calls))

    def test_request_budget_deadline_and_off_origin_feature_route(self):
        budget = FakeClient(clues={
            "feature_route": "/graphql", "protected_reference": "1", "method": "GET only",
            "note": "GraphQL resolver field-level authorization",
        })
        budget_ctx = context(budget, max_requests=4)
        self.assertIsNone(G.solve(target(), budget_ctx))
        self.assertEqual(len(budget.calls), 4)
        self.assertEqual(budget_ctx["result_sink"]["proof-1"]["stopped"], "max_requests")

        expired = FakeClient()
        expired_ctx = context(expired, deadline=time.time() - 1)
        self.assertIsNone(G.solve(target(), expired_ctx))
        self.assertFalse(expired.calls)

        off = FakeClient(clues={
            "feature_route": "https://evil.invalid/graphql", "protected_reference": "1",
            "method": "GET only", "note": "GraphQL resolver field-level authorization",
        })
        off_ctx = context(off)
        self.assertIsNone(G.solve(target(), off_ctx))
        self.assertEqual([call["path"] for call in off.calls], ["/", "/api/clues"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
