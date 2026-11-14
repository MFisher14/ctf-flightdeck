#!/usr/bin/env python3
"""Integration checks for proof_hunt's observed POST-class and passive-recon dispatch."""

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
import types
import urllib.parse
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
WEB = REPO / "solvers" / "web"
sys.path[:0] = [str(WEB), str(REPO / "solvers" / "toolkits"), str(REPO / "tests")]
sys.dont_write_bytecode = True


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


PH = load("proof_hunt_dispatch_test", WEB / "proof_hunt.py")
PC_TEST = load("post_chain_dispatch_fakes", REPO / "tests" / "test_web_post_chain.py")
RR_TEST = load("reset_dispatch_fakes", REPO / "tests" / "test_web_reset_rebind.py")


# Synthetic query-only GraphQL site for dispatch D18. Carried verbatim from Huntress
# tests/test_web_graphql_read.py, which the merge archived because it also loads saved
# day-18 attempts; only the self-contained fake and its schema helpers are kept here.
def proof_for(label: str, *, v4=True):
    chars = list(hashlib.sha256(label.encode()).hexdigest()[:32])
    chars[12] = "4" if v4 else "1"
    chars[16] = "8" if v4 else "2"
    return "proof_" + "".join(chars)


HISTORICAL_PROOF = proof_for("resolver-revolt", v4=False)


def type_ref(name, kind="SCALAR", required=False):
    node = {"kind": kind, "name": name, "ofType": None}
    return {"kind": "NON_NULL", "name": None, "ofType": node} if required else node


def object_ref(name):
    return {"kind": "OBJECT", "name": name, "ofType": None}


def schema_document(*, field="case", argument="id", argument_type="ID", result_type="Case",
                    result_fields=("id", "title", "note"), unsafe_field=None):
    root_field = unsafe_field or field
    query_fields = [
        {"name": "caseIndex", "args": [],
         "type": {"kind": "LIST", "name": None, "ofType": object_ref(result_type)}},
        {"name": root_field,
         "args": [{"name": argument, "defaultValue": None,
                   "type": type_ref(argument_type, "SCALAR", required=True)}],
         "type": object_ref(result_type)},
    ]
    scalar_fields = [
        {"name": name, "args": [], "type": type_ref("String")} for name in result_fields
    ]
    return {"data": {"__schema": {
        "queryType": {"name": "Query"},
        "types": [
            {"kind": "OBJECT", "name": "Query", "fields": query_fields},
            {"kind": "OBJECT", "name": result_type, "fields": scalar_fields},
            {"kind": "SCALAR", "name": "String", "fields": None},
            {"kind": "SCALAR", "name": "ID", "fields": None},
        ],
    }}}


def decode_call(call):
    try:
        value = json.loads(call.get("body", b"").decode("utf-8"))
        return value if isinstance(value, dict) else None
    except Exception:
        return None


class GraphQLSite:
    def __init__(self, *, route="/inspect-a18f00", clues=None, landing="Graph Garden · GraphQL.js",
                 schema=None, result=None, feature_control=None, introspection=None, clues_status=200,
                 require_persisted=False, proof=HISTORICAL_PROOF):
        self.route = route
        self.clues = dict(clues or {
            "current_user": "analyst", "feature_route": route, "protected_reference": "16400",
            "note": "Collection labels are filtered, but individual resolvers still need field-level checks.",
        })
        self.landing = landing
        self.schema = schema or schema_document()
        self.result = result
        self.feature_control = feature_control or (404, {"error": "not_found"})
        self.introspection = introspection
        self.clues_status = clues_status
        self.require_persisted = require_persisted
        self.proof = proof
        self.calls: list[dict] = []
        self.lock = threading.Lock()

    @staticmethod
    def response(status, value, content_type="application/json"):
        if isinstance(value, bytes):
            body = value
        elif isinstance(value, str) and content_type.startswith("text/"):
            body = value.encode("utf-8")
        else:
            body = json.dumps(value, separators=(",", ":")).encode("utf-8")
        return status, body, {"Content-Type": content_type}

    def _read_result(self, payload):
        query = payload.get("query") if isinstance(payload, dict) else None
        variables = payload.get("variables") if isinstance(payload, dict) else None
        match = re.search(
            r"\b(r\d+)\s*:\s*([_A-Za-z][_0-9A-Za-z]*)\s*\(\s*"
            r"([_A-Za-z][_0-9A-Za-z]*)\s*:\s*\$ref\s*\)", str(query or ""))
        if not match or not isinstance(variables, dict) or "ref" not in variables:
            return self.response(200, {"errors": [{"message": "bad generated query"}]})
        alias, field, argument = match.groups()
        if callable(self.result):
            value = self.result(alias, field, argument, variables["ref"], payload)
            if isinstance(value, tuple):
                return self.response(*value)
            return self.response(200, value)
        if self.result is not None:
            return self.response(200, self.result)
        return self.response(200, {"data": {alias: {
            "id": str(variables["ref"]), "title": "restricted reference", "note": self.proof,
        }}})

    def handle(self, method, raw_path, body, headers):
        call = {"method": method, "path": raw_path, "body": body, "headers": headers}
        with self.lock:
            self.calls.append(call)
        path = urllib.parse.urlsplit(raw_path).path
        if method == "GET" and path == "/":
            if isinstance(self.landing, tuple):
                return self.response(*self.landing)
            return self.response(200, self.landing, "text/html")
        if method == "GET" and path == "/api/clues":
            return self.response(self.clues_status, self.clues)
        route_path = urllib.parse.urlsplit(self.route).path if isinstance(self.route, str) else "/never"
        if path == route_path and method == "GET":
            return self.response(*self.feature_control)
        if path == route_path and method == "POST":
            payload = decode_call(call)
            query = payload.get("query") if isinstance(payload, dict) else ""
            if self.require_persisted:
                persisted = ((payload.get("extensions") or {}).get("persistedQuery")
                             if isinstance(payload, dict) else None)
                expected = hashlib.sha256(str(query or "").encode()).hexdigest()
                if (not isinstance(persisted, dict) or persisted.get("version") != 1
                        or persisted.get("sha256Hash") != expected):
                    return self.response(200, {"errors": [{"message": "PersistedQueryRequired",
                                                            "extensions": {
                                                                "code": "PERSISTED_QUERY_NOT_FOUND"}}]})
            if "__schema" in str(query):
                value = self.introspection if self.introspection is not None else self.schema
                if isinstance(value, tuple):
                    return self.response(*value)
                return self.response(200, value)
            return self._read_result(payload)
        return self.response(404, {"error": "not_found"})


GQL_TEST = types.SimpleNamespace(GraphQLSite=GraphQLSite, HISTORICAL_PROOF=HISTORICAL_PROOF)


FAILS = []


def check(name, ok, detail=""):
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f" [{str(detail)[:900]}]"))
    if not ok:
        FAILS.append(name)


class TupleAdapter:
    """Turn the two loopback-test site contracts into an in-memory WebClient-compatible object."""

    base = "http://fake.local/"

    def __init__(self, site, kind):
        self.site = site
        self.kind = kind
        self.timeout = 8.0
        self.log = []

    def request(self, method, path, data=None, headers=None, allow_redirects=True):
        raw = data.encode() if isinstance(data, str) else bytes(data or b"")
        hdrs = dict(headers or {})
        self.log.append({"method": method, "path": path, "data": data, "headers": hdrs,
                         "redirects": allow_redirects})
        if self.kind == "graphql":
            status, body, response_headers = self.site.handle(method, path, raw, hdrs)
        else:
            status, body, response_headers = self.site.handle(method, path, hdrs)
        return {"status": status, "body": body, "response_headers": response_headers,
                "final_url": self.base.rstrip("/") + path}


def hunter(client, prompt, max_requests=80):
    target = {"answer_id": "proof-1", "url": "http://fake.local/", "index": 1,
              "question": "Recover the proof from Target 1."}
    h = PH._Hunter(target["url"], deadline=time.time() + 10, max_requests=max_requests,
                   stop=threading.Event(), prompt=prompt)
    h.client = client
    h.forge_target = target
    h.forge_ctx = {}
    return h


def test_post_chain_dispatch():
    cases = (
        ("D11", PC_TEST.TemplateServer(),
         "The template engine evaluates everything it hears; whisper an expression.", 7, 2, "post_ssti"),
        ("D12", PC_TEST.SecondOrderServer(),
         "Plant your question inside the data and come back later.", 8, 1, "second_order_sqli"),
        ("D13", PC_TEST.MassAssignmentServer(),
         "The profile binder binds whatever property it receives; hand it a promotion.", 8, 1, "mass_assignment"),
    )
    for label, client, prompt, requests, posts, cls in cases:
        h = hunter(client, prompt)
        got = h.run()
        check(f"dispatch {label}: proof_hunt closes cold", got == client.answer, (got, client.answer, h.peer_meta))
        check(f"dispatch {label}: exact integrated request/POST count",
              h.requests == requests and len(client.posts) == posts, (h.requests, len(client.posts), client.log))
        check(f"dispatch {label}: correct sibling classification",
              h.peer_meta.get("post-chain", {}).get("class") == cls and h.shape == "post-chain", h.peer_meta)
        check(f"dispatch {label}: only GET/POST, redirects off, no Authorization",
              all(row["method"] in {"GET", "POST"} and row["redirects"] is False
                  and "authorization" not in {k.lower() for k in row["headers"]} for row in client.log), client.log)


def test_post_chain_beats_noisy_crawl():
    class NoisyMassAssignment(PC_TEST.MassAssignmentServer):
        def handle(self, method, path, data, headers):
            result = super().handle(method, path, data, headers)
            if method == "GET" and path == "/":
                result = dict(result)
                result["body"] = ("<title>Profile Binder</title>" + "".join(
                    f'<a href="/ordinary-{index}">ordinary</a>' for index in range(12)
                )).encode()
            return result

    client = NoisyMassAssignment()
    h = hunter(client, "The profile binder binds whatever property it receives; hand it a promotion.",
               max_requests=8)
    got = h.run()
    check("dispatch priority: D13 closes inside eight requests before twelve unrelated crawl links",
          got == client.answer and h.requests == 8 and len(client.posts) == 1
          and not any("/ordinary-" in row["path"] for row in client.log),
          (got, h.requests, client.log, h.peer_meta))


def test_reset_dispatch():
    site = RR_TEST.Site()
    client = TupleAdapter(site, "reset")
    h = hunter(client, "Walk the synthetic recovery process sideways.")
    got = h.run()
    check("dispatch D17: proof_hunt closes reset-token rebinding cold", got == site.p, (got, h.peer_meta))
    check("dispatch D17: wave1 + guide/issue/redeem is exactly seven requests",
          h.requests == 7 and h.peer_meta.get("reset-rebind", {}).get("issue_requests") == 1
          and h.peer_meta.get("reset-rebind", {}).get("redeem_requests") == 1, (h.requests, h.peer_meta))
    check("dispatch D17: one issue and one redeem, GET only",
          len(client.log) == 7 and all(row["method"] == "GET" for row in client.log), client.log)


def test_graphql_dispatch():
    site = GQL_TEST.GraphQLSite()
    client = TupleAdapter(site, "graphql")
    h = hunter(client, "Inspect the protected GraphQL resolver field.")
    got = h.run()
    check("dispatch D18: proof_hunt closes query-only GraphQL cold", got == GQL_TEST.HISTORICAL_PROOF,
          (got, h.peer_meta))
    check("dispatch D18: wave1 + control/introspection/read is exactly seven requests",
          h.requests == 7 and h.peer_meta.get("graphql-post-read", {}).get("posts") == 2,
          (h.requests, h.peer_meta))
    bodies = [str(row.get("data") or "") for row in client.log if row["method"] == "POST"]
    check("dispatch D18: every POST is Query-only",
          len(bodies) == 2 and all("mutation" not in body.lower() and "subscription" not in body.lower()
                                   for body in bodies), bodies)


class InventoryClient:
    base = "http://fake.local/"

    def __init__(self):
        self.answer = PC_TEST.proof()
        self.timeout = 8.0
        self.log = []

    def request(self, method, path, data=None, headers=None, allow_redirects=True):
        self.log.append({"method": method, "path": path, "data": data, "headers": dict(headers or {}),
                         "redirects": allow_redirects})
        bodies = {
            "/": (200, "text/html", '<script src="/static/app.js"></script>'),
            "/robots.txt": (404, "text/plain", "not found"),
            "/api/clues": (404, "application/json", '{"error":"not_found"}'),
            "/openapi.json": (404, "application/json", '{"error":"not_found"}'),
            "/sitemap.xml": (404, "application/xml", "not found"),
            "/static/app.js": (200, "application/javascript",
                               "fetch('/api/hidden-objective'); fetch('/proxy?url=http%3A%2F%2F169.254.169.254%2Flatest')"),
            "/api/hidden-objective": (200, "application/json", json.dumps({"evidence": self.answer})),
        }
        status, ctype, body = bodies.get(path, (404, "text/plain", "not found"))
        return {"status": status, "body": body.encode(), "response_headers": {"Content-Type": ctype},
                "final_url": self.base.rstrip("/") + path}


def test_endpoint_inventory_dispatch():
    client = InventoryClient()
    h = hunter(client, "Recover the target proof.")
    got = h.run()
    check("dispatch passive inventory: exact linked JS route becomes a bounded payoff", got == client.answer,
          (got, h.endpoint_inventory, h.findings))
    check("dispatch passive inventory: script is read but never executed",
          "/static/app.js" in [row["path"] for row in client.log]
          and "/api/hidden-objective" in [row["path"] for row in client.log]
          and not any(row["path"].startswith("/proxy?") for row in client.log), client.log)
    check("dispatch passive inventory: GET-only and within twelve incremental recon requests",
          all(row["method"] == "GET" for row in client.log)
          and h.endpoint_inventory and h.endpoint_inventory["phase_requests"] <= PH.ENDPOINT_PHASE_MAX_REQUESTS
          and h.endpoint_inventory["phase_max_requests"] == PH.ENDPOINT_PHASE_MAX_REQUESTS,
          (h.requests, h.endpoint_inventory))

    tight = InventoryClient()
    tight_hunter = hunter(tight, "Recover the target proof.", max_requests=8)
    tight_got = tight_hunter.run()
    check("dispatch passive inventory: exact linked JS retains one request for its route at budget eight",
          tight_got == tight.answer and tight_hunter.requests <= 8
          and "/static/app.js" in [row["path"] for row in tight.log]
          and "/api/hidden-objective" in [row["path"] for row in tight.log],
          (tight_got, tight_hunter.requests, tight.log, tight_hunter.endpoint_inventory))


def test_endpoint_inventory_baseline_and_signal_priority():
    class DecoyInventoryClient(InventoryClient):
        def request(self, method, path, data=None, headers=None, allow_redirects=True):
            result = super().request(method, path, data, headers, allow_redirects)
            if path == "/static/app.js":
                result = dict(result)
                result["body"] = (
                    "const alreadyVisible='" + self.answer + "'; fetch('/api/hidden-objective')"
                ).encode()
            return result

    client = DecoyInventoryClient()
    h = hunter(client, "Recover the target proof.")
    got = h.run()
    check("inventory baseline: a proof in linked JS echoed by its discovered route is never novel",
          got is None and client.answer in h.plain
          and "/api/hidden-objective" in [row["path"] for row in client.log],
          (got, h.plain, client.log, h.endpoint_inventory))

    class NoWire:
        base = "http://fake.local/"
        timeout = 8.0

    probe = hunter(NoWire(), "")

    def indicated(path, text):
        probe.pages = {path: {"status": 200, "path": path, "text": text, "tag": None}}
        return probe._endpoint_inventory_indicated()

    check("inventory signal: generic methods/paths JSON does not trigger early descriptor fallback",
          not indicated("/state", '{"methods":["card","wire"],"paths":["/home","/about"]}'), "")
    check("inventory signal: exact rel=service-desc link triggers early depth",
          indicated("/", '<link rel="service-desc" href="/contracts/events.json">'), "")
    check("inventory signal: robots Sitemap directive triggers early depth",
          indicated("/robots.txt", "User-agent: *\nSitemap: /sitemap.xml\n"), "")
    check("inventory signal: versioned OpenAPI document triggers early depth",
          indicated("/openapi.json", '{"openapi":"3.2.0","paths":{}}'), "")


def test_endpoint_phase_shared_cap():
    class SaturatingInventory:
        @staticmethod
        def discover(_target, ctx):
            for index in range(PH.ENDPOINT_DISCOVERY_MAX_REQUESTS):
                ctx["client"].request("GET", f"/metadata-{index}", allow_redirects=False)
            return {
                "requests": PH.ENDPOINT_DISCOVERY_MAX_REQUESTS,
                "routes": [{"path": f"/api/route-{index}", "methods": ["GET"],
                            "requestable": True, "sources": ["openapi:/openapi.json"]}
                           for index in range(30)],
                "operations": [], "findings": [],
            }

    client = InventoryClient()
    h = hunter(client, "Recover the target proof.")
    phase_start = h.requests
    h.request_ceiling = phase_start + PH.ENDPOINT_PHASE_MAX_REQUESTS
    old_inventory = PH._endpoint_inventory
    try:
        PH._endpoint_inventory = SaturatingInventory()
        items = h._run_endpoint_inventory()
        h.wave(items)
    finally:
        PH._endpoint_inventory = old_inventory
        h.request_ceiling = None
    check("endpoint phase bound: discovery plus contract/routes share one ceiling",
          h.requests - phase_start == PH.ENDPOINT_PHASE_MAX_REQUESTS
          and len(client.log) == PH.ENDPOINT_PHASE_MAX_REQUESTS,
          (h.requests, len(client.log), items))


class VersionedApiClient:
    base = "http://fake.local/"

    def __init__(self, swagger=False, parameterized=False, linked=False):
        self.answer = PC_TEST.proof()
        self.timeout = 8.0
        self.log = []
        self.linked = linked
        if swagger:
            self.spec = {
                "swagger": "2.0", "basePath": "/api", "produces": ["application/vnd.huntress.v2+json"],
                "paths": {"/case": {"get": {"parameters": [
                    {"name": "X-API-Version", "in": "header", "required": True,
                     "type": "string", "enum": ["2026-10-31"]},
                ], "responses": {"200": {"description": "ok"}}}}},
            }
            self.wanted_path = "/api/case"
            self.wanted_header = ("X-API-Version", "2026-10-31")
        else:
            media_type = ("application/vnd.huntress.case+json;version=2"
                          if parameterized else "application/vnd.huntress.case+json")
            self.spec = {
                "openapi": "3.1.0", "paths": {"/api/case": {"get": {"parameters": [
                    {"name": "api-version", "in": "query", "required": True,
                     "schema": {"type": "string", "enum": ["2026-10-31"]}},
                ], "responses": {"200": {"description": "ok", "content": {
                    media_type: {"schema": {"type": "object"}}
                }}}}}},
            }
            self.wanted_path = "/api/case?api-version=2026-10-31"
            self.wanted_header = ("Accept", media_type)

    def request(self, method, path, data=None, headers=None, allow_redirects=True):
        headers = dict(headers or {})
        self.log.append({"method": method, "path": path, "headers": headers,
                         "redirects": allow_redirects})
        if path == "/":
            link = '<a href="/api/case">case</a>' if self.linked else ""
            status, body, ctype = 200, "<html>" + link + "</html>", "text/html"
        elif path == "/robots.txt":
            status, body, ctype = 404, "not found", "text/plain"
        elif path == "/api/clues":
            status, body, ctype = 404, '{"error":"not_found"}', "application/json"
        elif path == "/openapi.json":
            status, body, ctype = 200, json.dumps(self.spec), "application/json"
        elif path == "/sitemap.xml":
            status, body, ctype = 404, "not found", "application/xml"
        elif path == self.wanted_path and headers.get(self.wanted_header[0]) == self.wanted_header[1]:
            status, body, ctype = 200, json.dumps({"proof": self.answer}), "application/json"
        elif path.split("?", 1)[0] == "/api/case":
            status, body, ctype = 400, '{"error":"version_required"}', "application/json"
        else:
            status, body, ctype = 404, "not found", "text/plain"
        return {"status": status, "body": body.encode(), "response_headers": {"Content-Type": ctype},
                "final_url": self.base.rstrip("/") + path}


def test_versioned_contract_get_dispatch():
    for label, client in (("OpenAPI query + vendor Accept", VersionedApiClient()),
                          ("Swagger version header + produces", VersionedApiClient(swagger=True)),
                          ("media-type parameter", VersionedApiClient(parameterized=True)),
                          ("cached route + version header", VersionedApiClient(swagger=True, linked=True))):
        h = hunter(client, "Recover the exact proof from the documented API.")
        got = h.run()
        matching = [row for row in client.log if row["path"] == client.wanted_path
                    and row["headers"].get(client.wanted_header[0]) == client.wanted_header[1]]
        check(f"contract GET {label}: closes from explicit version metadata", got == client.answer,
              (got, h.endpoint_inventory, client.log))
        check(f"contract GET {label}: sends one exact negotiated payoff behind a bare control",
              len(matching) == 1 and sum(row["path"] == "/api/case" and not row["headers"]
                                         for row in client.log) == 1
              and all(row["method"] == "GET" and row["redirects"] is False for row in client.log),
              client.log)


class DefaultProofApiClient:
    """An ordinary documented GET whose 200 schema explicitly names `proof`."""

    base = "http://fake.local/"

    def __init__(self):
        self.answer = PC_TEST.proof()
        self.timeout = 8.0
        self.log = []
        self.spec = {"openapi": "3.2.0", "paths": {"/api/default-proof": {"get": {
            "responses": {"200": {"description": "ok", "content": {"application/json": {
                "schema": {"type": "object", "properties": {"proof": {"type": "string"}}}
            }}}}
        }}}}

    def request(self, method, path, data=None, headers=None, allow_redirects=True):
        headers = dict(headers or {})
        self.log.append({"method": method, "path": path, "headers": headers,
                         "redirects": allow_redirects})
        if path == "/":
            status, body, ctype = 200, "<html></html>", "text/html"
        elif path == "/robots.txt":
            status, body, ctype = 404, "not found", "text/plain"
        elif path == "/api/clues":
            status, body, ctype = 404, '{"error":"not_found"}', "application/json"
        elif path == "/openapi.json":
            status, body, ctype = 200, json.dumps(self.spec), "application/json"
        elif path == "/sitemap.xml":
            status, body, ctype = 404, "not found", "application/xml"
        elif path == "/api/default-proof":
            status, body, ctype = 200, json.dumps({"proof": self.answer}), "application/json"
        else:
            status, body, ctype = 404, "not found", "text/plain"
        return {"status": status, "body": body.encode(), "response_headers": {"Content-Type": ctype},
                "final_url": self.base.rstrip("/") + path}


def test_default_contract_get_dispatch():
    client = DefaultProofApiClient()
    h = hunter(client, "Recover the exact proof from the documented API.")
    got = h.run()
    calls = [row for row in client.log if row["path"] == "/api/default-proof"]
    check("contract GET default 200: explicit proof response closes cold", got == client.answer,
          (got, h.endpoint_inventory, client.log))
    check("contract GET default 200: deterministic single payoff request",
          len(calls) == 1 and calls[0]["headers"] == {}, calls)


def test_contract_get_fail_closed_and_bounds():
    client = InventoryClient()
    h = hunter(client, "Recover the target proof.")
    proof_response = [{"name": "proof"}]
    bad = [
        {"method": "POST", "path": "/api/case", "params": [],
         "response_content_types": ["application/vnd.test+json"]},
        {"method": "GET", "path": "https://evil.invalid/api", "params": [],
         "response_content_types": ["application/vnd.test+json"]},
        {"method": "GET", "path": "/api/{id}", "params": [
            {"name": "id", "in": "path", "required": True, "values": []}]},
        {"method": "GET", "path": "/api/case", "params": [
            {"name": "X-Tenant", "in": "header", "required": True, "values": ["blue"]}]},
        {"method": "GET", "path": "/api/case", "params": [
            {"name": "session", "in": "cookie", "required": True, "values": ["admin"]}]},
        {"method": "GET", "path": "/api/case", "params": [
            {"name": "api_key", "in": "query", "required": True, "values": ["target-secret"]}]},
        {"method": "GET", "path": "/keyed", "params": [
            {"name": "key", "in": "query", "required": True, "values": ["target-secret"]}],
         "response_content_types": ["application/vnd.test+json"]},
        {"method": "GET", "path": "/fetch", "params": [
            {"name": "url", "in": "query", "required": True,
             "values": ["169.254.169.254/latest/meta-data"]}],
         "response_content_types": ["application/vnd.test+json"]},
        {"method": "GET", "path": "/api/case?api-version=old", "params": [
            {"name": "api-version", "in": "query", "required": True, "values": ["new"]}]},
        {"method": "GET", "path": "/api/{version}", "params": [
            {"name": "version", "in": "path", "required": True, "values": ["v1"], "style": "matrix"}]},
        {"method": "GET", "path": "/api/case", "params": [
            {"name": "api-version", "in": "query", "required": True, "values": ["v1"],
             "content_types": ["application/json"]}]},
        {"method": "GET", "path": "/proxy?next=http%3A%2F%2Finternal", "params": [],
         "response_content_types": ["application/vnd.test+json"]},
        {"method": "GET", "path": "/api/case", "params": [
            {"name": "X-API-Version", "in": "header", "required": True,
             "values": ["v1\r\nHost: evil.invalid"]}]},
        {"method": "GET", "path": "/proxy/http://169.254.169.254/meta", "params": [],
         "response_fields": proof_response},
        {"method": "GET", "path": "/proxy/http%3A%2F%2F169.254.169.254/meta", "params": [],
         "response_fields": proof_response},
        {"method": "GET", "path": "/proxy/http%253A%252F%252F169.254.169.254/meta", "params": [],
         "response_fields": proof_response},
        {"method": "GET", "path": r"/proxy/http:\u002f\u002f169.254.169.254/meta", "params": [],
         "response_fields": proof_response},
        {"method": "GET", "path": "/proxy/%26%2347%3B%26%2347%3Bevil.invalid/meta", "params": [],
         "response_fields": proof_response},
        {"method": "GET", "path": "/api/incomplete", "params": [], "contract_complete": False,
         "response_fields": proof_response},
        {"method": "GET", "path": "/api/body", "params": [], "has_required_body": True,
         "response_fields": proof_response},
        {"method": "GET", "path": "/api/{versions}", "params": [
            {"name": "versions", "in": "path", "required": True, "schema_type": "array",
             "values": ["v1"]}], "response_fields": proof_response},
        {"method": "GET", "path": "/api/query-array", "params": [
            {"name": "api-version", "in": "query", "required": True, "schema_type": "array",
             "values": ["v1"]}], "response_fields": proof_response},
        {"method": "GET", "path": "/api/header-object", "params": [
            {"name": "X-API-Version", "in": "header", "required": True, "schema_type": "object",
             "values": ["v1"]}], "response_fields": proof_response},
        {"method": "GET", "path": "/api/mixed", "params": [
            {"name": "api-version", "in": "query", "required": True, "schema_type": "mixed",
             "values": ["v1"]}], "response_fields": proof_response},
        {"method": "GET", "path": "/api/header-collision", "params": [
            {"name": "X-API-Version", "in": "header", "required": True, "values": ["v1"]},
            {"name": "x-api-version", "in": "header", "required": True, "values": ["v2"]}],
         "response_fields": proof_response},
        {"method": "QUERY", "path": "/api/query-method", "params": [],
         "response_fields": proof_response},
        {"method": "GET", "path": "/api/bad-accept", "params": [],
         "response_content_types": ["application/vnd.case+json;version=2\r\nX-Evil: 1"]},
    ]
    items = h._spec_get_items(bad)
    h.wave(items)
    check("contract GET safety: writes, off-origin, unresolved, credentials and controls send zero",
          items == [] and client.log == [], (items, client.log))

    resolved = h._spec_get_items([{"method": "GET", "path": "/v/{version}/case/{id}", "params": [
        {"name": "version", "in": "path", "required": True, "values": ["2026-10-31"]},
        {"name": "id", "in": "path", "required": True, "values": ["alpha", "beta"]},
    ]}])
    check("contract GET path depth: explicit examples resolve every template with two variants",
          [row[0] for row in resolved] == [
              "/v/2026-10-31/case/alpha", "/v/2026-10-31/case/beta"], resolved)

    many = [{"method": "GET", "path": f"/v{i}/case", "params": [
        {"name": "api-version", "in": "query", "required": True, "values": ["1", "2", "3"]}],
        "response_content_types": ["application/vnd.test+json"]} for i in range(20)]
    capped = h._spec_get_items(many)
    check("contract GET bounds: at most two variants per operation and six requests total",
          len(capped) == PH.SPEC_GET_MAX_REQUESTS
          and sum(1 for row in capped if row[2]) <= 2 * len({row[3] for row in capped}), capped)

    multi_axis = h._spec_get_items([{"method": "GET", "path": "/api/versioned", "params": [
        {"name": "api-version", "in": "query", "required": True, "values": ["old", "new"]},
        {"name": "X-API-Version", "in": "header", "required": True,
         "values": ["legacy", "current", "wanted"]},
    ]}])
    payoff_rows = [row for row in multi_axis if row[2]]
    check("contract GET combinations: two axes use coherent first/last tuples",
          len(payoff_rows) == 2 and payoff_rows[0][0].endswith("api-version=old")
          and payoff_rows[0][5].get("X-API-Version") == "legacy"
          and payoff_rows[1][0].endswith("api-version=new")
          and payoff_rows[1][5].get("X-API-Version") == "wanted", payoff_rows)

    preferred = h._spec_get_items([{"method": "GET", "path": "/api/preferred", "params": [
        {"name": "api-version", "in": "query", "required": True, "example": "documented",
         "values": ["enum-first", "enum-second"]},
    ]}])
    check("contract GET provenance: explicit example outranks enum order",
          any(row[2] and row[0].endswith("api-version=documented") for row in preferred), preferred)

    crowded = [{"method": "GET", "path": f"/ordinary/{index}", "params": [
        {"name": "api-version", "in": "query", "required": True, "values": ["1"]}],
        "response_content_types": ["application/vnd.ordinary+json"]} for index in range(20)]
    crowded.append({"method": "GET", "path": "/late/objective", "params": [],
                    "response_fields": proof_response})
    ranked = h._spec_get_items(crowded)
    check("contract GET ranking: late proof operation survives six-request cap",
          ranked and ranked[0][0] == "/late/objective" and len(ranked) <= PH.SPEC_GET_MAX_REQUESTS, ranked)

    expired_client = InventoryClient()
    expired = hunter(expired_client, "Recover the target proof.")
    expired.deadline = time.time() - 1
    expired.wave(capped)
    check("contract GET deadline: expired run sends zero requests", expired_client.log == [], expired_client.log)


class CorsClient:
    base = "http://fake.local/"

    def __init__(self, answer=None):
        self.answer = answer or PC_TEST.proof()
        self.timeout = 8.0
        self.log = []

    def request(self, method, path, data=None, headers=None, allow_redirects=True):
        headers = dict(headers or {})
        self.log.append({"method": method, "path": path, "data": data, "headers": headers,
                         "redirects": allow_redirects})
        if path == "/":
            value, rh = {"service": "cors fake"}, {}
        elif path in ("/robots.txt", "/openapi.json"):
            return {"status": 404, "body": b"not found", "response_headers": {},
                    "final_url": self.base.rstrip("/") + path}
        elif path == "/api/clues":
            value, rh = {"cors_route": "/api/private"}, {}
        elif path == "/api/private" and headers.get("Origin"):
            value, rh = {"proof": self.answer}, {
                "Access-Control-Allow-Origin": headers["Origin"],
                "Access-Control-Allow-Credentials": "true",
            }
        elif path == "/api/private":
            value, rh = {"role": "user"}, {}
        else:
            return {"status": 404, "body": b"not found", "response_headers": {},
                    "final_url": self.base.rstrip("/") + path}
        return {"status": 200, "body": json.dumps(value).encode(), "response_headers": rh,
                "final_url": self.base.rstrip("/") + path}


def test_passive_protocol_dispatch():
    client = CorsClient()
    h = hunter(client, "Recover the proof through the target's CORS policy.")
    got = h.run()
    check("dispatch passive protocols: credentialed CORS closes cold", got == client.answer,
          (got, h.peer_meta, h.findings))
    check("dispatch passive protocols: four recon plus control/origin is six GETs",
          h.requests == 6 and len(client.log) == 6 and all(row["method"] == "GET" for row in client.log),
          (h.requests, client.log))
    check("dispatch passive protocols: exact .invalid Origin and no redirect follow",
          client.log[-1]["headers"].get("Origin", "").endswith(".cors.huntress.invalid")
          and all(row["redirects"] is False for row in client.log), client.log)
    check("dispatch passive protocols: confirmed CORS finding is logged",
          any(row.get("class") == "cors" and row.get("confirmed") for row in h.findings), h.findings)

    future = "HUNTRESS{future-cors-proof}"
    candidate_client = CorsClient(future)
    candidate_hunter = hunter(candidate_client, "Recover the proof through the target's CORS policy.")
    candidate = candidate_hunter.run()
    check("dispatch passive protocols: future-shaped CORS success is terminal but never auto-returned",
          candidate is None and candidate_hunter.peer_meta.get("passive-checks", {}).get("success") is True
          and any(item.get("value") == future for item in candidate_hunter.candidates),
          (candidate, candidate_hunter.peer_meta, candidate_hunter.candidates))
    check("dispatch passive protocols: terminal future shape does not fall through to inventory/generic waves",
          len(candidate_client.log) == 6 and candidate_hunter.endpoint_inventory is None,
          (candidate_client.log, candidate_hunter.endpoint_inventory))


def test_payoff_status_and_offered_inner_url_guards():
    class ErrorClient:
        base = "http://fake.local/"

        def __init__(self):
            self.timeout = 8
            self.log = []
            self.value = PC_TEST.proof()

        def request(self, method, path, data=None, headers=None, allow_redirects=True):
            self.log.append((method, path))
            return {"status": 404, "body": json.dumps({"proof": self.value}).encode(),
                    "response_headers": {"Content-Type": "application/json"},
                    "final_url": self.base.rstrip("/") + path}

    client = ErrorClient()
    h = hunter(client, "Recover the proof.")
    page = h.fetch("/missing", "promptroute", True, "missing", offered=False)
    check("payoff gate: a tagged 404 proof-looking error body is never auto-returned",
          page and page.get("payoff") is False and h.answer() is None and client.value in h.plain,
          (page, h.answer(), h.plain))
    check("offered route guard: inventory/link query cannot activate an encoded inner URL",
          not h.allowed("/proxy?url=http%253A%252F%252F169.254.169.254%252Flatest", offered=True), "")


def main():
    for test in (test_post_chain_dispatch, test_post_chain_beats_noisy_crawl,
                 test_reset_dispatch, test_graphql_dispatch,
                 test_endpoint_inventory_dispatch, test_endpoint_inventory_baseline_and_signal_priority,
                 test_endpoint_phase_shared_cap,
                 test_versioned_contract_get_dispatch, test_default_contract_get_dispatch,
                 test_contract_get_fail_closed_and_bounds, test_passive_protocol_dispatch,
                 test_payoff_status_and_offered_inner_url_guards):
        try:
            test()
        except Exception as exc:
            check(test.__name__, False, f"{type(exc).__name__}: {exc}")
    print(("PASS" if not FAILS else "FAIL"), "test_web_cold_dispatch", len(FAILS), "failed")
    return 1 if FAILS else 0


if __name__ == "__main__":
    raise SystemExit(main())
