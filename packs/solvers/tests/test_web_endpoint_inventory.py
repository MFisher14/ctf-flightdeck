#!/usr/bin/env python3
"""Offline/local regression for the passive endpoint inventory.

The only network is a local fake target. The assertions prove GET-only scope,
hard budgets, Swagger 2/OpenAPI 3.0/3.1/3.2 JSON/YAML depth, local refs, schema
composition, server/base paths, parameter/body/response/security metadata,
adversarial fail-closed parsing, sitemap parsing, linked-JS/source-map recon,
never-submit secret lead metadata, and the solve_targets fail-closed answer contract.
"""

import json
import sys
import time
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "web"))
import endpoint_inventory as ei  # noqa: E402


def offline_spec(spec, *, path="/openapi.json", raw=None, content_type="application/json"):
    """Drive the public inventory with preloaded bytes only; any missing request is budget-refused."""
    link = f'<link rel="alternate" href="{path}">' if path != "/openapi.json" else ""
    body = raw if raw is not None else json.dumps(spec).encode()
    if isinstance(body, str):
        body = body.encode()
    preloaded = {
        "/": {"status": 200, "body": ("<html>" + link + "</html>").encode(),
              "response_headers": {"Content-Type": "text/html"}},
        "/robots.txt": {"status": 200, "body": b"", "response_headers": {}},
        "/sitemap.xml": {"status": 200, "body": b"<urlset></urlset>",
                         "response_headers": {"Content-Type": "application/xml"}},
        path: {"status": 200, "body": body, "response_headers": {"Content-Type": content_type}},
    }
    if path != "/openapi.json":
        preloaded["/openapi.json"] = {"status": 404, "body": b"not found", "response_headers": {}}
    return ei.discover("https://target.test/", {"preloaded": preloaded, "max_requests": 0,
                                                 "deadline": time.time() + 10})


class FakeClient:
    base = "https://target.test/"

    def __init__(self):
        self.timeout = 10
        self.seen = []

    def _body(self, path):
        origin = self.base.rstrip("/")
        if path == "/":
            return "text/html", (f"""
                    <html><head>
                      <link rel="sitemap" href="/map.xml">
                      <link rel="alternate" href="/swagger.json">
                      <script src="/static/app.js"></script>
                      <script src="https://off-origin.test/off-origin.js"></script>
                      <script src="/logout.js"></script>
                      <script src="/static/loader.js?url=https%3A%2F%2Foff-origin.test%2Fx"></script>
                    </head></html>
                """).encode()
        if path == "/robots.txt":
            return "text/plain", (f"Sitemap: {origin}/sitemap.xml\nDisallow: /hidden/archive\n").encode()
        if path == "/openapi.json":
            return "application/json", json.dumps({
                    "openapi": "3.0.0",
                    "components": {"schemas": {"Profile": {
                        "type": "object", "required": ["display_name"], "properties": {
                            "display_name": {"type": "string"},
                            "role": {"type": "string", "enum": ["analyst", "administrator"]},
                        }
                    }}},
                    "paths": {
                        "/api/users/{id}": {"get": {"operationId": "readUser", "parameters": [
                            {"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}},
                            {"name": "expand", "in": "query", "schema": {"enum": ["profile", "audit"]}},
                        ]}},
                        "/api/profile": {"post": {"requestBody": {"content": {
                            "application/json": {"schema": {"$ref": "#/components/schemas/Profile"}}
                        }}}},
                    },
            }).encode()
        if path == "/swagger.json":
            return "application/json", json.dumps({
                    "swagger": "2.0", "paths": {"/api/swaggered": {"get": {}}}
            }).encode()
        if path == "/sitemap.xml":
            return "application/xml", (f"""<?xml version="1.0"?>
                    <urlset><url><loc>{origin}/public/a</loc></url>
                    <url><loc>https://off-origin.test/off-origin</loc></url></urlset>
                """).encode()
        if path == "/map.xml":
            return "application/xml", b"<urlset><url><loc>/public/b?view=full</loc></url></urlset>"
        if path == "/static/app.js":
            return "application/javascript", b"""
                    fetch('/api/hidden?token=x');
                    const ws_url = 'wss://target.test/socket?channel=alerts';
                    const AWS = 'AKIAIOSFODNN7EXAMPLE';  // secret-scan: allow
                    //# sourceMappingURL=app.js.map
                """
        if path == "/static/app.js.map":
            return "application/json", json.dumps({
                    "version": 3, "file": "app.js", "sources": ["webpack:///src/api.js"],
                    "sourcesContent": ["fetch('/api/from-map?mode=full'); "
                                       "const x='proof_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'; "
                                       "const f='flag{inventory_source_map_lead}';"],
                    "names": [], "mappings": "AAAA",
            }).encode()
        return "text/plain", b"not found"

    def request(self, method, path, **kwargs):
        assert method == "GET"
        assert path.startswith("/") and not path.startswith("//")
        assert kwargs.get("allow_redirects") is False
        self.seen.append((method, path))
        ctype, body = self._body(path)
        return {"status": 200 if body != b"not found" else 404, "body": body,
                "response_headers": {"Content-Type": ctype}}


def test_full_inventory():
    client = FakeClient()
    result = ei.discover(client.base, {"client": client, "max_requests": 12, "deadline": time.time() + 10})
    seen = client.seen

    paths = set(result["route_paths"])
    assert result["flag"] is None
    assert "/api/users/{id}" in paths and "/api/profile" in paths and "/api/swaggered" in paths
    assert "/public/a" in paths and "/public/b?view=full" in paths
    assert "/api/hidden?token=x" in paths and "/api/from-map?mode=full" in paths
    assert "/hidden/archive" in paths
    assert {"id", "expand", "display_name", "role", "token", "mode", "view"} <= set(result["params"])

    users = next(x for x in result["operations"] if x["path"] == "/api/users/{id}")
    profile = next(x for x in result["operations"] if x["path"] == "/api/profile")
    assert users["method"] == "GET" and {p["name"] for p in users["params"]} == {"id", "expand"}
    assert users["params"][1]["values"] == ["profile", "audit"]
    assert profile["method"] == "POST" and {f["name"] for f in profile["fields"]} == {"display_name", "role"}
    assert "application/json" in profile["content_types"]
    assert result["scripts"] == ["/static/app.js"]
    assert result["source_maps"] == ["/static/app.js.map"]
    assert result["websockets"] == ["/socket?channel=alerts"]
    leads = {(row["kind"], row["value"], row["via"]) for row in result["secret_leads"]}
    assert ("aws_access_key_id", "AKIAIOSFODNN7EXAMPLE", "/static/app.js") in leads  # secret-scan: allow
    assert ("flag", "flag{inventory_source_map_lead}", "/static/app.js.map") in leads
    assert all(row["auto_submit"] is False and row["note"] == result["secret_leads_policy"]
               for row in result["secret_leads"])
    assert result["flag"] is None and "never auto-submit" in result["secret_leads_policy"]
    assert any(row.get("evidence") == "client_secret_leads" for row in result["findings"])
    assert result["requests"] <= 12
    assert seen and {method for method, _path in seen} == {"GET"}
    requested = {path for _method, path in seen}
    assert not any(path.startswith("/api/") for path in requested)  # inventory never drives app routes
    assert "/off-origin.js" not in requested and "/off-origin" not in requested and "/logout.js" not in requested
    assert not any(path.startswith("/static/loader.js") for path in requested)
    assert any(path.startswith("/static/loader.js") for path in result["refused"])
    assert not any("proof_" in json.dumps(value) for key, value in result.items() if key != "external_urls")


def test_deadline_and_request_budget():
    class BombClient:
        base = "http://127.0.0.1:1/"
        timeout = 10

        def request(self, *_args, **_kwargs):
            raise AssertionError("deadline should prevent every request")

    result = ei.discover(BombClient.base, {"client": BombClient(), "deadline": time.time() - 1,
                                           "max_requests": 99})
    assert result["requests"] == 0 and result["stopped"] == "deadline"

    client = FakeClient()
    limited = ei.discover(client.base, {"client": client, "max_requests": 3, "deadline": time.time() + 10})
    seen = client.seen
    assert limited["requests"] == 3 and limited["stopped"] == "max_requests"
    assert len(seen) == 3 and {method for method, _path in seen} == {"GET"}


def test_preloaded_and_solver_contract():
    spec = {"openapi": "3.0.0", "paths": {"/api/preloaded": {"get": {}}}}
    preloaded = {
        "/": {"status": 200, "text": "<html></html>", "headers": {}},
        "/robots.txt": {"status": 200, "text": "", "headers": {}},
        "/openapi.json": {"status": 200, "text": json.dumps(spec), "headers": {}},
        "/sitemap.xml": {"status": 200, "text": "<urlset></urlset>", "headers": {}},
    }
    sink, evidence = {}, []
    answers = ei.solve_targets(
        [{"answer_id": "proof-1", "url": "http://127.0.0.1:1/"}],
        {"preloaded": preloaded, "max_requests": 0, "inventory_sink": sink, "evidence": evidence},
    )
    assert answers == {"proof-1": None}
    assert "/api/preloaded" in sink["proof-1"]["route_paths"]
    assert sink["proof-1"]["requests"] == 0
    assert evidence and evidence[0].startswith("WEB ENDPOINT INVENTORY proof-1:")


def test_injected_client_scope_mismatch_is_inert():
    client = FakeClient()
    client.base = "https://other.test/"
    result = ei.discover("https://target.test/", {"client": client, "max_requests": 12,
                                                   "deadline": time.time() + 10})
    assert result["requests"] == 0 and client.seen == []
    assert result["stopped"] == "client_scope_mismatch"


def test_swagger2_refs_forms_responses_and_security():
    spec = {
        "swagger": "2.0", "host": "target.test", "schemes": ["http", "https"],
        "basePath": "/v2", "consumes": ["application/json"], "produces": ["application/json"],
        "securityDefinitions": {
            "ApiKey": {"type": "apiKey", "in": "header", "name": "X-API-Key"},
            "OAuth": {"type": "oauth2", "flow": "accessCode",
                      "authorizationUrl": "https://identity.invalid/authorize",
                      "tokenUrl": "https://identity.invalid/token"},
        },
        "parameters": {
            "Trace": {"$ref": "#/parameters/TraceReal"},
            "TraceReal": {"name": "X-Trace", "in": "header", "required": False,
                          "type": "string", "enum": ["brief", "full"]},
        },
        "definitions": {
            "Profile/Admin": {"type": "object", "required": ["role"], "properties": {
                "role": {"type": "string", "enum": ["analyst", "administrator"]},
            }},
            "Wrapped": {"allOf": [
                {"$ref": "#/definitions/Profile~1Admin"},
                {"type": "object", "properties": {"enabled": {"type": "boolean", "const": True}}},
            ]},
            "Result": {"type": "object", "properties": {
                "evidence": {"type": "string"}, "status": {"enum": ["ok"]},
            }},
        },
        "paths": {
            "/users/{id}": {
                "parameters": [{"name": "id", "in": "path", "type": "integer"}],
                "post": {"operationId": "updateProfile", "security": [{"ApiKey": []}],
                         "produces": ["application/vnd.huntress.profile+json"],
                         "parameters": [{"$ref": "#/parameters/Trace"},
                                        {"name": "payload", "in": "body", "required": True,
                                         "schema": {"$ref": "#/definitions/Wrapped"}}],
                         "responses": {"200": {"schema": {"$ref": "#/definitions/Result"}}}},
            },
            "/upload": {"post": {"consumes": ["multipart/form-data"], "parameters": [
                {"name": "file", "in": "formData", "type": "file", "required": True},
                {"name": "mode", "in": "formData", "type": "string", "enum": ["scan", "preview"]},
            ], "responses": {"204": {"description": "ok"}}}},
        },
    }
    result = offline_spec(spec)
    assert {"/v2/users/{id}", "/v2/upload"} <= set(result["route_paths"])
    user = next(row for row in result["operations"] if row["path"] == "/v2/users/{id}")
    assert user["spec_version"] == "swagger-2.0" and user["method"] == "POST"
    assert {(p["name"], p["in"]) for p in user["params"]} == {("id", "path"), ("X-Trace", "header")}
    assert next(p for p in user["params"] if p["name"] == "X-Trace")["values"] == ["brief", "full"]
    fields = {row["name"]: row for row in user["fields"]}
    assert fields["role"]["required"] and fields["role"]["values"] == ["analyst", "administrator"]
    assert fields["enabled"]["values"] == [True]
    assert {row["name"] for row in user["response_fields"]} == {"evidence", "status"}
    assert user["response_content_types"] == ["application/vnd.huntress.profile+json"]
    assert user["security"] == ["ApiKey"] and user["content_types"] == ["application/json"]
    upload = next(row for row in result["operations"] if row["path"] == "/v2/upload")
    assert {row["name"] for row in upload["fields"]} == {"file", "mode"}
    assert next(row for row in upload["fields"] if row["name"] == "mode")["values"] == ["scan", "preview"]
    assert upload["content_types"] == ["multipart/form-data"]
    assert upload["response_content_types"] == ["application/json"]
    schemes = {row["name"]: row for row in result["security_schemes"]}
    assert schemes["ApiKey"]["parameter"] == "X-API-Key" and schemes["OAuth"]["type"] == "oauth2"


def test_ref_siblings_follow_openapi_dialect_and_object_context():
    def openapi(version):
        return {
            "openapi": version,
            "components": {
                "schemas": {"Base": {"type": "object", "properties": {
                    "base_field": {"type": "string", "enum": ["base"]},
                }}},
                "parameters": {"Mode": {"name": "mode", "in": "query",
                                           "schema": {"type": "string", "enum": ["safe"]}}},
            },
            "paths": {"/refs": {"post": {
                "parameters": [{"$ref": "#/components/parameters/Mode",
                                "name": "forged", "in": "header",
                                "schema": {"enum": ["forged"]}}],
                "requestBody": {"content": {"application/json": {"schema": {
                    "$ref": "#/components/schemas/Base",
                    "properties": {"sibling_field": {"type": "string", "enum": ["sibling"]}},
                }}}},
                "responses": {"204": {"description": "ok"}},
            }}},
        }

    oas30 = next(row for row in offline_spec(openapi("3.0.3"))["operations"]
                 if row["path"] == "/refs")
    assert {field["name"] for field in oas30["fields"]} == {"base_field"}
    assert [(param["name"], param["in"], param["values"]) for param in oas30["params"]] == [
        ("mode", "query", ["safe"])]

    oas31 = next(row for row in offline_spec(openapi("3.1.1"))["operations"]
                 if row["path"] == "/refs")
    assert {field["name"] for field in oas31["fields"]} == {"base_field", "sibling_field"}
    assert [(param["name"], param["in"], param["values"]) for param in oas31["params"]] == [
        ("mode", "query", ["safe"])]

    swagger = offline_spec({
        "swagger": "2.0",
        "definitions": {"Base": {"type": "object", "properties": {
            "base_field": {"type": "string", "enum": ["base"]},
        }}},
        "parameters": {"Mode": {"name": "mode", "in": "query", "type": "string",
                                  "enum": ["safe"]}},
        "paths": {"/refs": {"post": {
            "parameters": [
                {"$ref": "#/parameters/Mode", "name": "forged", "in": "header", "enum": ["forged"]},
                {"name": "body", "in": "body", "schema": {
                    "$ref": "#/definitions/Base",
                    "properties": {"sibling_field": {"type": "string", "enum": ["sibling"]}},
                }},
            ],
            "responses": {"204": {"description": "ok"}},
        }}},
    })
    swagger_op = next(row for row in swagger["operations"] if row["path"] == "/refs")
    assert {field["name"] for field in swagger_op["fields"]} == {"base_field"}
    assert [(param["name"], param["in"], param["values"]) for param in swagger_op["params"]] == [
        ("mode", "query", ["safe"])]


def test_swagger_explicit_empty_media_types_do_not_inherit_or_infer():
    result = offline_spec({
        "swagger": "2.0",
        "consumes": ["application/json"],
        "produces": ["application/json"],
        "paths": {
            "/inherit": {"post": {
                "parameters": [{"name": "mode", "in": "formData", "type": "string"}],
                "responses": {"204": {"description": "ok"}},
            }},
            "/empty": {"post": {
                "consumes": [], "produces": [],
                "parameters": [{"name": "mode", "in": "formData", "type": "string"}],
                "responses": {"204": {"description": "ok"}},
            }},
        },
    })
    inherit = next(row for row in result["operations"] if row["path"] == "/inherit")
    empty = next(row for row in result["operations"] if row["path"] == "/empty")
    assert inherit["content_types"] == ["application/json"]
    assert inherit["response_content_types"] == ["application/json"]
    assert empty["content_types"] == []
    assert empty["response_content_types"] == []
    assert {field["name"] for field in empty["fields"]} == {"mode"}


def test_openapi31_servers_composition_locations_and_content():
    spec = {
        "openapi": "3.1.1",
        "servers": [{"url": "/api/{stage}", "variables": {"stage": {"default": "v3"}}}],
        "security": [{"Bearer": []}],
        "components": {
            "securitySchemes": {"Bearer": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"},
                                "Oidc": {"type": "openIdConnect",
                                         "openIdConnectUrl": "https://identity.invalid/.well-known/openid"}},
            "parameters": {
                "FilterAlias": {"$ref": "#/components/parameters/Filter"},
                "Filter": {"name": "filter", "in": "query", "schema": {
                    "oneOf": [{"enum": ["mine"]}, {"enum": ["all"]}]}},
                "Session": {"name": "session_hint", "in": "cookie", "schema": {"type": ["string", "null"]}},
                "Trace": {"name": "X-Trace", "in": "header", "schema": {"example": "compact"}},
            },
            "schemas": {
                "Base": {"type": "object", "required": ["name"],
                         "properties": {"name": {"type": "string"}}},
                "Privilege": {"oneOf": [
                    {"type": "object", "properties": {"is_admin": {"const": True}}},
                    {"type": "object", "properties": {"role": {"enum": ["administrator"]}}},
                ]},
                "Payload": {"allOf": [{"$ref": "#/components/schemas/Base"},
                                         {"$ref": "#/components/schemas/Privilege"}]},
                "Envelope": {"type": "array", "items": {"$ref": "#/components/schemas/Payload"}},
            },
            "requestBodies": {
                "Alias": {"$ref": "#/components/requestBodies/Actual"},
                "Actual": {"required": True, "content": {
                    "application/json": {"schema": {"$ref": "#/components/schemas/Envelope"}},
                    "application/x-www-form-urlencoded": {"schema": {"$ref": "#/components/schemas/Payload"},
                                                           "example": {"role": "administrator"}},
                    "multipart/form-data": {"schema": {"type": "object", "properties": {
                        "attachment": {"type": "string", "format": "binary"}}}},
                }},
            },
            "responses": {"Case": {"description": "ok", "content": {"application/json": {"schema": {
                "type": "object", "properties": {"proof": {"type": "string"}, "note": {"type": "string"}}
            }}}}},
        },
        "paths": {
            "/cases/{id}": {
                "parameters": [{"name": "id", "in": "path", "required": True,
                                "schema": {"type": "integer"}}],
                "post": {"operationId": "inspectCase", "parameters": [
                    {"$ref": "#/components/parameters/FilterAlias"},
                    {"$ref": "#/components/parameters/Session"},
                    {"$ref": "#/components/parameters/Trace"},
                ], "requestBody": {"$ref": "#/components/requestBodies/Alias"},
                    "responses": {"200": {"$ref": "#/components/responses/Case"}}},
            },
            "/health": {"get": {"servers": [{"url": "/override"}], "security": [],
                                  "responses": {"204": {"description": "ok"}}}},
        },
    }
    result = offline_spec(spec)
    assert {"/api/v3/cases/{id}", "/override/health"} <= set(result["route_paths"])
    case = next(row for row in result["operations"] if row["operation_id"] == "inspectCase")
    assert case["spec_version"] == "openapi-3.1.1"
    assert {(p["name"], p["in"]) for p in case["params"]} == {
        ("id", "path"), ("filter", "query"), ("session_hint", "cookie"), ("X-Trace", "header")}
    assert next(p for p in case["params"] if p["name"] == "filter")["values"] == ["mine", "all"]
    assert next(p for p in case["params"] if p["name"] == "X-Trace")["values"] == ["compact"]
    fields = {row["name"]: row for row in case["fields"]}
    assert {"name", "is_admin", "role", "attachment"} <= set(fields)
    assert fields["role"]["values"] == ["administrator"] and fields["is_admin"]["values"] == [True]
    assert set(case["content_types"]) == {
        "application/json", "application/x-www-form-urlencoded", "multipart/form-data"}
    assert {row["name"] for row in case["response_fields"]} == {"proof", "note"}
    assert case["response_content_types"] == ["application/json"] and case["security"] == ["Bearer"]
    health = next(row for row in result["operations"] if row["path"] == "/override/health")
    assert health["security"] == []
    schemes = {row["name"]: row for row in result["security_schemes"]}
    assert schemes["Bearer"]["scheme"] == "bearer" and schemes["Bearer"]["bearer_format"] == "JWT"
    assert schemes["Oidc"]["openid_connect_url"].endswith("/.well-known/openid")


def test_openapi_parameter_examples_content_and_conventional_paths():
    spec = {
        "openapi": "3.1.0",
        "components": {"examples": {"Admin": {"value": "administrator"}}},
        "paths": {"/parameter-depth": {"get": {"parameters": [
            {"name": "mode", "in": "query", "schema": {"type": "string"}, "example": "full"},
            {"name": "role", "in": "header", "schema": {"type": "string"}, "examples": {
                "viewer": {"value": "viewer"}, "admin": {"$ref": "#/components/examples/Admin"},
            }},
            {"name": "filter", "in": "query", "content": {"application/json": {
                "schema": {"oneOf": [{"enum": ["mine"]}, {"enum": ["all"]}]},
                "examples": {"default": {"value": "mine"}},
            }}},
        ], "responses": {"200": {"description": "ok"}}}}},
    }
    result = offline_spec(spec)
    operation = next(row for row in result["operations"] if row["path"] == "/parameter-depth")
    params = {row["name"]: row for row in operation["params"]}
    assert params["mode"]["values"] == ["full"]
    assert params["role"]["values"] == ["viewer", "administrator"]
    assert params["filter"]["values"] == ["mine", "all"]
    assert params["filter"]["content_types"] == ["application/json"]

    class ConventionalClient:
        base = "https://target.test/"

        def __init__(self, document_path, document, content_type):
            self.document_path = document_path
            self.document = document.encode() if isinstance(document, str) else json.dumps(document).encode()
            self.content_type = content_type
            self.timeout = 10
            self.seen = []

        def request(self, method, path, **kwargs):
            assert method == "GET" and kwargs.get("allow_redirects") is False
            self.seen.append(path)
            if path == "/":
                return {"status": 200, "body": b"<html></html>", "response_headers": {}}
            if path == "/robots.txt":
                return {"status": 200, "body": b"", "response_headers": {}}
            if path == "/sitemap.xml":
                return {"status": 200, "body": b"<urlset></urlset>", "response_headers": {}}
            if path == self.document_path:
                return {"status": 200, "body": self.document,
                        "response_headers": {"Content-Type": self.content_type}}
            return {"status": 404, "body": b"not found", "response_headers": {}}

    documents = (
        ("/swagger.yaml", "swagger: '2.0'\npaths:\n  /from-swagger-yaml:\n    get: {}\n", "application/yaml",
         "/from-swagger-yaml"),
        ("/swagger.yml", "swagger: '2.0'\npaths:\n  /from-swagger-yml:\n    get: {}\n", "application/yaml",
         "/from-swagger-yml"),
        ("/v3/api-docs", {"openapi": "3.0.3", "paths": {"/from-v3-docs": {"get": {}}}},
         "application/json", "/from-v3-docs"),
        ("/api-docs", {"swagger": "2.0", "paths": {"/from-api-docs": {"get": {}}}},
         "application/json", "/from-api-docs"),
    )
    for path, document, content_type, expected_route in documents:
        client = ConventionalClient(path, document, content_type)
        found = ei.discover(client.base, {"client": client, "max_requests": 12,
                                          "deadline": time.time() + 10})
        assert path in found["openapi_docs"], (path, client.seen, found)
        assert expected_route in found["route_paths"], (path, found)
        assert found["requests"] <= 12 and path in client.seen


def test_js_disclosed_openapi_precedes_fallback_guesses():
    class Client:
        base = "https://target.test/"
        timeout = 10

        def __init__(self):
            self.seen = []

        def request(self, method, path, **kwargs):
            assert method == "GET" and kwargs.get("allow_redirects") is False
            self.seen.append(path)
            if path == "/":
                body, ctype, status = b'<script src="/static/app.js"></script>', "text/html", 200
            elif path == "/robots.txt":
                body, ctype, status = b"", "text/plain", 200
            elif path == "/static/app.js":
                body, ctype, status = (b"fetch('/contracts/internal-openapi.yaml')",
                                       "application/javascript", 200)
            elif path == "/contracts/internal-openapi.yaml":
                body, ctype, status = (b"openapi: 3.1.0\npaths:\n  /from-js-spec:\n    get: {}\n",
                                       "application/yaml", 200)
            elif path == "/sitemap.xml":
                body, ctype, status = b"<urlset></urlset>", "application/xml", 200
            else:
                body, ctype, status = b"not found", "text/plain", 404
            return {"status": status, "body": body, "response_headers": {"Content-Type": ctype}}

    client = Client()
    found = ei.discover(client.base, {"client": client, "max_requests": 6,
                                      "deadline": time.time() + 10})
    assert "/contracts/internal-openapi.yaml" in found["openapi_docs"], (client.seen, found)
    assert "/from-js-spec" in found["route_paths"]
    assert client.seen.index("/contracts/internal-openapi.yaml") < len(client.seen)
    assert not any(path in client.seen for path in ("/openapi.yaml", "/swagger.json", "/v3/api-docs"))


def test_openapi_callbacks_and_webhooks_are_metadata_only():
    callback_item = {
        "post": {
            "operationId": "receiveAudit",
            "parameters": [{"name": "X-Signature", "in": "header",
                            "schema": {"enum": ["sha256", "sha512"]}}],
            "requestBody": {"content": {"application/json": {"schema": {
                "type": "object", "required": ["event"], "properties": {
                    "event": {"enum": ["case.changed"]}, "evidence": {"type": "string"},
                }}}}},
            "responses": {"200": {"content": {"application/json": {"schema": {
                "type": "object", "properties": {"accepted": {"type": "boolean"}},
            }}}}},
        },
    }
    spec30 = {
        "openapi": "3.0.3",
        "security": [{"CallbackKey": []}],
        "components": {"callbacks": {"Audit": {
            "{$request.body#/callbackUrl}": callback_item,
            "/literal-callback": callback_item,
            "https://evil.invalid/callback": callback_item,
        }}},
        "paths": {"/cases": {"post": {
            "callbacks": {"audit": {"$ref": "#/components/callbacks/Audit"}},
            "responses": {"202": {"description": "queued"}},
        }}},
    }
    result30 = offline_spec(spec30)
    callbacks = [row for row in result30["event_operations"] if row.get("surface") == "callback"]
    assert len(callbacks) == 3 and all(row["requestable"] is False for row in callbacks), callbacks
    dynamic = next(row for row in callbacks if row["expression"].startswith("{$request"))
    assert dynamic["target"] is None and dynamic["parent_path"] == "/cases"
    assert {(row["name"], row["in"]) for row in dynamic["params"]} == {("X-Signature", "header")}
    assert next(row for row in dynamic["params"] if row["name"] == "X-Signature")["values"] == [
        "sha256", "sha512"]
    assert {row["name"] for row in dynamic["fields"]} == {"event", "evidence"}
    assert {row["name"] for row in dynamic["response_fields"]} == {"accepted"}
    assert dynamic["security"] == ["CallbackKey"]
    literal = next(row for row in callbacks if row["expression"] == "/literal-callback")
    assert literal["target"] == "/literal-callback"
    offhost = next(row for row in callbacks if "evil.invalid" in row["expression"])
    assert offhost["target"] is None and any("evil.invalid" in url for url in result30["external_urls"])
    assert "/literal-callback" not in result30["route_paths"]
    assert not any("evil.invalid" in route for route in result30["route_paths"])

    spec31 = {
        "openapi": "3.1.0",
        "components": {"pathItems": {"CaseHook": callback_item}},
        "paths": {},
        "webhooks": {
            "caseChanged": {"$ref": "#/components/pathItems/CaseHook"},
            "/literal-webhook": callback_item,
            "https://evil.invalid/webhook": callback_item,
        },
    }
    result31 = offline_spec(spec31)
    webhooks = [row for row in result31["event_operations"] if row.get("surface") == "webhook"]
    assert len(webhooks) == 3 and all(row["requestable"] is False for row in webhooks), webhooks
    named = next(row for row in webhooks if row["name"] == "caseChanged")
    assert named["target"] is None and named["operation_id"] == "receiveAudit"
    literal = next(row for row in webhooks if row["name"] == "/literal-webhook")
    assert literal["target"] == "/literal-webhook"
    assert "/literal-webhook" not in result31["route_paths"]
    assert any("evil.invalid/webhook" in url for url in result31["external_urls"])
    assert all(row in result31["operations"] for row in webhooks)


def test_openapi32_json_yaml_and_query_webhooks_are_metadata_only():
    spec32 = {
        "openapi": "3.2.1",
        "components": {
            "schemas": {"BaseEvent": {"type": "object", "properties": {
                "case_id": {"type": "string", "enum": ["case-7"]},
            }}},
            "pathItems": {"CaseHook": {"query": {
                "operationId": "queryCaseHook",
                "requestBody": {"content": {"application/json": {"schema": {
                    "$ref": "#/components/schemas/BaseEvent",
                    "properties": {"event": {"enum": ["case.changed"]}},
                }}}},
                "responses": {"200": {"description": "ok"}},
            }}},
        },
        # A webhook-only entry document is valid in the 3.2 feature set. It is
        # still metadata: even a literal target never becomes an inventory route.
        "webhooks": {"/case-hook": {"$ref": "#/components/pathItems/CaseHook"}},
    }
    result32 = offline_spec(spec32)
    assert result32["openapi_docs"] == ["/openapi.json"]
    assert result32["route_paths"] == []
    hooks = [row for row in result32["event_operations"] if row.get("surface") == "webhook"]
    assert len(hooks) == 1 and hooks[0]["method"] == "QUERY"
    assert hooks[0]["spec_version"] == "openapi-3.2.1" and hooks[0]["requestable"] is False
    assert hooks[0]["target"] == "/case-hook" and hooks[0]["operation_id"] == "queryCaseHook"
    assert {field["name"] for field in hooks[0]["fields"]} == {"case_id", "event"}

    yaml32 = """openapi: 3.2.0
webhooks:
  /yaml-hook:
    post:
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                event: {enum: [audit.ready]}
      responses:
        '204': {description: accepted}
"""
    yaml_result = offline_spec({}, path="/openapi.yaml", raw=yaml32, content_type="application/yaml")
    assert yaml_result["openapi_docs"] == ["/openapi.yaml"]
    yaml_hooks = [row for row in yaml_result["event_operations"] if row.get("surface") == "webhook"]
    assert len(yaml_hooks) == 1 and yaml_hooks[0]["method"] == "POST"
    assert yaml_hooks[0]["target"] == "/yaml-hook" and yaml_hooks[0]["requestable"] is False
    assert next(field for field in yaml_hooks[0]["fields"] if field["name"] == "event")["values"] == [
        "audit.ready"]

    malformed = offline_spec({"openapi": "3.2.0", "webhooks": []})
    future = offline_spec({"openapi": "3.3.0", "paths": {"/not-supported": {"get": {}}}})
    assert malformed["openapi_docs"] == [] and malformed["event_operations"] == []
    assert future["openapi_docs"] == [] and "/not-supported" not in future["route_paths"]


def test_client_secret_leads_are_bounded_metadata_never_answers():
    inv = ei._Inventory("https://target.test/")
    raw = [{"kind": "assigned_token", "value": "v" + str(index), "source": "bundle.js",
            "note": "target-controlled note must not survive"}
           for index in range(ei.MAX_SECRET_LEADS + 20)]
    raw.insert(0, {"kind": "private_key", "value": "K" * (ei.MAX_SECRET_VALUE_BYTES + 100),
                   "source": "src/key.js"})
    raw.extend((raw[1], {"kind": "bad kind", "value": "ignored", "source": "bundle.js"},
                {"kind": "flag", "value": "bad\x00value", "source": "bundle.js"}))
    ei._merge_secret_leads(inv, "/static/app.js.map", {"secrets": raw})
    assert len(inv.secret_leads) == ei.MAX_SECRET_LEADS
    first = inv.secret_leads[0]
    assert first["kind"] == "private_key" and first["truncated"] is True
    assert len(first["value"].encode()) <= ei.MAX_SECRET_VALUE_BYTES
    assert all(row["auto_submit"] is False and row["note"] == ei.SECRET_LEADS_POLICY
               for row in inv.secret_leads)
    assert all(row["via"] == "/static/app.js.map" for row in inv.secret_leads)


def test_yaml_openapi_and_adversarial_documents_fail_closed():
    yaml_doc = """openapi: 3.0.3
paths:
  /yaml/items:
    post:
      parameters:
        - name: mode
          in: query
          schema:
            enum: [brief, full]
      requestBody:
        content:
          application/json:
            schema:
              type: object
              required: [name]
              properties:
                name: {type: string}
                role: {type: string, enum: [analyst, administrator]}
      responses:
        200:
          description: ok
"""
    result = offline_spec({}, path="/openapi.yaml", raw=yaml_doc, content_type="application/yaml")
    assert result["openapi_docs"] == ["/openapi.yaml"]
    op = next(row for row in result["operations"] if row["path"] == "/yaml/items")
    assert op["spec_version"] == "openapi-3.0.3"
    assert next(p for p in op["params"] if p["name"] == "mode")["values"] == ["brief", "full"]
    assert {row["name"] for row in op["fields"]} == {"name", "role"}

    unsafe = """openapi: 3.0.0
paths: !!python/object/apply:os.system ['id']
"""
    result = offline_spec({}, path="/openapi.yaml", raw=unsafe, content_type="application/yaml")
    assert result["openapi_docs"] == [] and result["operations"] == []

    for ambiguous in (
        """openapi: 3.0.0
paths: {/safe: {get: {}}}
paths: {/last-wins: {get: {}}}
""",
        """openapi: 3.0.0
paths: {/safe: {get: {}}}
Paths: {/case-collision: {get: {}}}
""",
        """openapi: 3.0.0
base: &base {paths: {/merged: {get: {}}}}
<<: *base
paths: {/explicit: {get: {}}}
""",
        """openapi: 3.0.0
paths:
  1: {/numeric: {get: {}}}
  true: {/boolean-collides-with-one: {get: {}}}
""",
    ):
        rejected = offline_spec({}, path="/openapi.yaml", raw=ambiguous,
                                content_type="application/yaml")
        assert rejected["openapi_docs"] == [] and rejected["operations"] == []

    # Reject attacker-sized numeric lexemes while they are still cheap scalar
    # text.  This protects Python 3.9, whose int conversion has no digit cap,
    # for both mapping keys and ordinary values passed to SafeLoader.
    enormous = "9" * 100_000
    for numeric_bomb in (
        "openapi: 3.0.0\npaths:\n  " + enormous + ": {}\n",
        "openapi: 3.0.0\npaths: {}\nx-number: " + enormous + "\n",
    ):
        started = time.monotonic()
        rejected = offline_spec({}, path="/openapi.yaml", raw=numeric_bomb,
                                content_type="application/yaml")
        assert rejected["openapi_docs"] == [] and rejected["operations"] == []
        assert time.monotonic() - started < 0.5

    recursive = """openapi: 3.0.0
paths:
  /safe: &loop
    get:
      responses: {'200': {description: ok}}
x-cycle: {next: *loop}
"""
    # Shared non-recursive aliases are safe; a truly recursive alias is rejected below.
    accepted = offline_spec({}, path="/openapi.yaml", raw=recursive, content_type="application/yaml")
    assert "/safe" in accepted["route_paths"]
    cyclic = """openapi: 3.0.0
paths: &paths
  /cycle:
    get: {responses: {'200': {description: ok}}}
x-cycle: {self: *paths}
"""
    # This is shared but not recursive; build an actual recursive alias as a top-level side field.
    cyclic += "x-recursive: &node {next: *node}\n"
    rejected = offline_spec({}, path="/openapi.yaml", raw=cyclic, content_type="application/yaml")
    assert rejected["openapi_docs"] == [] and rejected["operations"] == []


def test_ref_cycles_unknown_versions_and_global_bounds():
    cycle = {
        "openapi": "3.1.0",
        "components": {"schemas": {"A": {"$ref": "#/components/schemas/B"},
                                      "B": {"$ref": "#/components/schemas/A"}}},
        "paths": {"/cycle": {"post": {"requestBody": {"content": {"application/json": {
            "schema": {"$ref": "#/components/schemas/A"}}}}, "responses": {"204": {"description": "ok"}}}}},
    }
    result = offline_spec(cycle)
    op = next(row for row in result["operations"] if row["path"] == "/cycle")
    assert op["fields"] == []

    unsupported = offline_spec({"openapi": "4.0.0", "paths": {"/must-not-land": {"get": {}}}})
    assert unsupported["openapi_docs"] == [] and "/must-not-land" not in unsupported["route_paths"]

    offhost = offline_spec({"openapi": "3.0.0", "servers": [{"url": "https://evil.invalid/api"}],
                            "paths": {"/must-stay-offhost": {"get": {}}}})
    assert "/must-stay-offhost" not in offhost["route_paths"]
    assert any("evil.invalid" in value for value in offhost["external_urls"])

    swagger_offhost = offline_spec({"swagger": "2.0", "host": "evil.invalid", "basePath": "/v2",
                                    "paths": {"/also-offhost": {"get": {}}}})
    assert not swagger_offhost["route_paths"]
    assert any("evil.invalid" in value for value in swagger_offhost["external_urls"])

    many = {"openapi": "3.0.0", "paths": {
        f"/r/{index}": {"get": {"responses": {"200": {"description": "ok"}}}}
        for index in range(ei.MAX_OPERATIONS + 80)
    }}
    bounded = offline_spec(many)
    assert len(bounded["operations"]) == ei.MAX_OPERATIONS
    assert len(bounded["routes"]) <= ei.MAX_ROUTES

    huge_path = "/" + "x" * (ei.MAX_ROUTE_BYTES + 1)
    oversized = offline_spec({"openapi": "3.1.0", "paths": {
        huge_path: {"get": {"responses": {"200": {"description": "never driven"}}}},
        "/bounded": {"get": {"responses": {"200": {"description": "ok"}}}},
    }})
    assert huge_path not in oversized["route_paths"]
    assert not any(row.get("path") == huge_path for row in oversized["operations"])
    assert "/bounded" in oversized["route_paths"]

    for unsafe in (
        "/proxy/http://evil.invalid/x", "/proxy/dict:evil", "/proxy/ldap:evil",
        "/proxy/ws:evil", "/proxy/wss:evil", "/proxy/custom+tcp:evil",
        "/proxy?url=%2F%2Fevil.invalid%2Fx", "/proxy?url=dict%3A%2F%2Fevil.invalid%2Fx",
    ):
        normalized = ei._safe_path("https://target.test/", unsafe)
        assert normalized is not None and ei._contains_inner_url(normalized), unsafe
        assert not ei._safe_to_fetch(normalized), unsafe
        assert ei._Inventory("https://target.test/").route(unsafe, "test") is None, unsafe

    for unsafe in ("/deleteUser/app.js", "/runTask/openapi.json",
                   "/assets/app.js?action=transferFunds", "/assets/app.js?deleteUser=1"):
        normalized = ei._safe_path("https://target.test/", unsafe)
        assert normalized is not None and not ei._safe_to_fetch(normalized), unsafe


def test_api_specs_use_one_unique_coherent_carrier_document():
    boundary = "inventory-parts"

    def multipart(parts):
        rows = []
        for content_type, body in parts:
            rows.append(f"--{boundary}\r\nContent-Type: {content_type}\r\n\r\n{body}\r\n")
        rows.append(f"--{boundary}--\r\n")
        return "".join(rows).encode()

    spec = json.dumps({"openapi": "3.1.0", "paths": {"/later": {"get": {}}}})
    later = offline_spec(
        {}, raw=multipart((("text/plain", "diagnostic"), ("application/json", spec))),
        content_type=f"multipart/mixed; boundary={boundary}")
    assert "/later" in later["route_paths"], later

    second = json.dumps({"openapi": "3.1.0", "paths": {"/other": {"get": {}}}})
    ambiguous = offline_spec(
        {}, raw=multipart((("application/json", spec), ("application/json", second))),
        content_type=f"multipart/mixed; boundary={boundary}")
    assert ambiguous["openapi_docs"] == []
    assert "/later" not in ambiguous["route_paths"] and "/other" not in ambiguous["route_paths"]

    duplicate = ('{"openapi":"3.1.0","paths":{"/safe":{"get":{}}},'
                 '"paths":{"/last-wins":{"get":{}}}}')
    rejected = offline_spec({}, raw=duplicate, content_type="application/json")
    assert rejected["openapi_docs"] == []
    assert "/safe" not in rejected["route_paths"] and "/last-wins" not in rejected["route_paths"]

    poisoned = (f"--{boundary}\r\nContent-Type: application/json\r\n\r\n{spec}\r\n"
                f"--{boundary}\r\nContent-Type: text/plain\r\n"
                "Content-Type: application/json\r\n\r\ndecoy\r\n"
                f"--{boundary}--\r\n").encode()
    rejected = offline_spec({}, raw=poisoned,
                            content_type=f"multipart/mixed; boundary={boundary}")
    assert rejected["openapi_docs"] == [] and "/later" not in rejected["route_paths"]


def test_openapi_rejected_inner_url_paths_never_leave_operations():
    paths = {
        "/proxy/http://evil.invalid/x": {"get": {"responses": {"200": {"description": "bad"}}}},
        "/proxy/http%3A%2F%2Fevil.invalid/x": {"get": {"responses": {"200": {"description": "bad"}}}},
        "/proxy/http%253A%252F%252Fevil.invalid/x": {"get": {"responses": {"200": {"description": "bad"}}}},
        "/safe": {"get": {"responses": {"200": {"description": "ok"}}}},
    }
    result = offline_spec({"openapi": "3.1.0", "paths": paths})
    operation_paths = {row["path"] for row in result["operations"]
                       if not row.get("surface")}
    assert result["route_paths"] == ["/safe"], result["route_paths"]
    assert operation_paths == {"/safe"}, operation_paths


def test_parameter_override_types_and_contract_completeness():
    oas = offline_spec({
        "openapi": "3.2.0",
        "components": {"parameters": {
            "External": {"name": "external", "in": "query", "required": True,
                         "schema": {"type": "string"}},
        }},
        "paths": {
            "/complete": {"parameters": [
                {"name": "X-API-Version", "in": "header", "schema": {"type": "string", "enum": ["1"]}},
            ], "get": {"parameters": [
                {"name": "x-api-version", "in": "header", "required": True,
                 "schema": {"type": "string", "enum": ["1", "2"], "default": "2"}},
                {"name": "versions", "in": "query", "schema": {"type": "array",
                 "items": {"type": "string"}, "example": ["1", "2"]}},
                {"name": "filter", "in": "query", "schema": {"type": "object",
                 "properties": {"state": {"type": "string"}}}},
            ], "responses": {"200": {"description": "ok"}}}},
            "/querystring": {"get": {"parameters": [
                {"name": "query", "in": "querystring", "required": True,
                 "content": {"application/x-www-form-urlencoded": {"schema": {"type": "object"}}}},
            ], "responses": {"200": {"description": "ok"}}}},
            "/external": {"get": {"parameters": [
                {"$ref": "https://evil.invalid/parameter.json"},
            ], "responses": {"200": {"description": "ok"}}}},
            "/body": {"get": {"requestBody": {"required": True, "content": {
                "application/json": {"schema": {"type": "object"}}
            }}, "responses": {"200": {"description": "ok"}}}},
        },
    })
    complete = next(row for row in oas["operations"] if row["path"] == "/complete")
    assert [row["name"] for row in complete["params"]].count("x-api-version") == 1, complete["params"]
    params = {row["name"]: row for row in complete["params"]}
    assert params["x-api-version"]["values"] == ["1", "2"]
    assert params["x-api-version"]["preferred_values"] == ["2"]
    assert params["x-api-version"]["schema_type"] == "string"
    assert params["versions"]["schema_type"] == "array"
    assert params["filter"]["schema_type"] == "object"
    assert complete["contract_complete"] is True and complete["has_required_body"] is False
    assert next(row for row in oas["operations"] if row["path"] == "/querystring")["contract_complete"] is False
    assert next(row for row in oas["operations"] if row["path"] == "/external")["contract_complete"] is False
    body = next(row for row in oas["operations"] if row["path"] == "/body")
    assert body["has_required_body"] is True and body["contract_complete"] is False

    swagger = offline_spec({
        "swagger": "2.0", "paths": {"/v2": {"parameters": [
            {"name": "X-Mode", "in": "header", "type": "string", "enum": ["path"]},
        ], "get": {"parameters": [
            {"name": "x-mode", "in": "header", "required": True,
             "type": "string", "enum": ["legacy", "operation"], "default": "operation"},
            {"name": "ids", "in": "query", "type": "array", "items": {"type": "string"}},
        ], "responses": {"200": {"description": "ok"}}}}},
    })
    operation = next(row for row in swagger["operations"] if row["path"] == "/v2")
    assert [row["name"] for row in operation["params"]] == ["x-mode", "ids"], operation["params"]
    assert operation["params"][0]["values"] == ["legacy", "operation"]
    assert operation["params"][0]["preferred_values"] == ["operation"]
    assert operation["params"][1]["schema_type"] == "array"


class ServiceDescriptorClient:
    base = "https://target.test/"

    def __init__(self, *, source_map=False):
        self.timeout = 10
        self.seen = []
        self.source_map = source_map

    def request(self, method, path, **kwargs):
        assert method == "GET" and kwargs.get("allow_redirects") is False
        self.seen.append((method, path))
        if path == "/":
            body = (b'<script src="/static/app.js"></script>' if self.source_map else
                    b'<a href="/contracts/cases.wsdl">WSDL</a>'
                    b'<link href="/idl/greeter.proto">'
                    b'<script src="/static/api_grpc_web_pb.js"></script>')
            return {"status": 200, "body": body, "response_headers": {"Content-Type": "text/html"}}
        if path == "/robots.txt":
            return {"status": 200, "body": b"", "response_headers": {}}
        if path in {"/contracts/cases.wsdl", "/contracts/query?wsdl", "/static/contracts/cases.wsdl"}:
            body = b'''<definitions xmlns="http://schemas.xmlsoap.org/wsdl/"
              xmlns:tns="urn:cases" xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
              targetNamespace="urn:cases">
              <import namespace="urn:common" location="/contracts/common.wsdl"/>
              <portType name="CasePort"><operation name="GetCase"/></portType>
              <binding name="CaseBinding" type="tns:CasePort"><operation name="GetCase">
                <soap:operation soapAction="urn:cases/GetCase"/></operation></binding>
              <service name="Cases"><port name="case" binding="tns:CaseBinding">
                <soap:address location="/soap/cases"/></port></service>
            </definitions>'''
            return {"status": 200, "body": body, "response_headers": {"Content-Type": "text/xml"}}
        if path == "/idl/greeter.proto":
            body = b'''syntax = "proto3";
              package acme.v1;
              import "common.proto";
              message In {} message Out {}
              service Greeter { rpc Hello (In) returns (Out); }'''
            return {"status": 200, "body": body,
                    "response_headers": {"Content-Type": "text/plain"}}
        generated = b'''const d = new grpc.web.MethodDescriptor(
          '/acme.v1.Greeter/Hello', grpc.web.MethodType.UNARY,
          proto.acme.v1.In, proto.acme.v1.Out);'''
        if path == "/static/api_grpc_web_pb.js":
            return {"status": 200, "body": generated,
                    "response_headers": {"Content-Type": "application/javascript"}}
        if path == "/static/app.js":
            return {"status": 200,
                    "body": b"const contract = './contracts/cases.wsdl';\n//# sourceMappingURL=app.js.map",
                    "response_headers": {"Content-Type": "application/javascript"}}
        if path == "/static/app.js.map":
            body = json.dumps({"version": 3, "file": "app.js", "sources": ["src/generated.js"],
                               "sourcesContent": [generated.decode()], "names": [], "mappings": "AAAA"}).encode()
            return {"status": 200, "body": body,
                    "response_headers": {"Content-Type": "application/json"}}
        return {"status": 404, "body": b"not found", "response_headers": {"Content-Type": "text/plain"}}


def test_exact_service_descriptors_are_metadata_only():
    client = ServiceDescriptorClient()
    result = ei.discover(client.base, {"client": client, "max_requests": 12,
                                       "deadline": time.time() + 10})
    kinds = {row["kind"] for row in result["descriptor_docs"]}
    assert kinds == {"wsdl", "protobuf", "grpc-web"}, result["descriptor_docs"]
    surfaces = {row.get("surface") for row in result["event_operations"]}
    assert {"soap_wsdl", "grpc_web"} <= surfaces, result["event_operations"]
    assert all(row.get("requestable") is False for row in result["event_operations"])
    wsdl = next(row for row in result["descriptor_docs"] if row["kind"] == "wsdl")
    proto = next(row for row in result["descriptor_docs"] if row["kind"] == "protobuf")
    assert wsdl["imports"][0]["fetched"] is False and wsdl["imports"][0]["requestable"] is False
    assert proto["imports"][0]["fetched"] is False and proto["imports"][0]["requestable"] is False
    assert result["descriptor_servers"][0]["endpoint"] == "https://target.test/soap/cases"
    assert result["descriptor_servers"][0]["requestable"] is False
    requested = {path for _method, path in client.seen}
    assert "/contracts/cases.wsdl" in requested and "/idl/greeter.proto" in requested
    assert "/static/api_grpc_web_pb.js" in requested
    assert not ({"/contracts/common.wsdl", "/soap/cases", "/acme.v1.Greeter/Hello"} & requested)
    assert "/acme.v1.Greeter/Hello" not in result["route_paths"]
    assert all(row.get("path") != "/acme.v1.Greeter/Hello" for row in result["operations"]
               if not row.get("surface"))
    assert result["requests"] <= 12 and {method for method, _path in client.seen} == {"GET"}


def test_prompt_query_wsdl_and_sourcemap_grpc_are_exact_and_offline():
    prompt_client = ServiceDescriptorClient()
    prompt = ei.discover({"url": prompt_client.base, "prompt": "Inspect /contracts/query?wsdl"},
                         {"client": prompt_client, "max_requests": 5, "deadline": time.time() + 10})
    assert any(row["kind"] == "wsdl" for row in prompt["descriptor_docs"]), prompt
    assert "/contracts/query?wsdl" in {path for _method, path in prompt_client.seen}
    assert "/soap/cases" not in {path for _method, path in prompt_client.seen}

    map_client = ServiceDescriptorClient(source_map=True)
    mapped = ei.discover(map_client.base, {"client": map_client, "max_requests": 8,
                                           "deadline": time.time() + 10})
    grpc = [row for row in mapped["descriptor_docs"] if row["kind"] == "grpc-web"]
    assert grpc and grpc[0]["path"].startswith("/static/app.js.map#"), mapped["descriptor_docs"]
    assert "/static/contracts/cases.wsdl" in {path for _method, path in map_client.seen}
    assert "/acme.v1.Greeter/Hello" not in mapped["route_paths"]
    assert "/acme.v1.Greeter/Hello" not in {path for _method, path in map_client.seen}


def main():
    tests = (test_full_inventory, test_deadline_and_request_budget, test_preloaded_and_solver_contract,
             test_injected_client_scope_mismatch_is_inert,
             test_swagger2_refs_forms_responses_and_security,
             test_ref_siblings_follow_openapi_dialect_and_object_context,
             test_swagger_explicit_empty_media_types_do_not_inherit_or_infer,
             test_openapi31_servers_composition_locations_and_content,
             test_openapi_parameter_examples_content_and_conventional_paths,
             test_js_disclosed_openapi_precedes_fallback_guesses,
             test_openapi_callbacks_and_webhooks_are_metadata_only,
             test_openapi32_json_yaml_and_query_webhooks_are_metadata_only,
             test_client_secret_leads_are_bounded_metadata_never_answers,
             test_yaml_openapi_and_adversarial_documents_fail_closed,
             test_ref_cycles_unknown_versions_and_global_bounds,
             test_api_specs_use_one_unique_coherent_carrier_document,
             test_openapi_rejected_inner_url_paths_never_leave_operations,
             test_parameter_override_types_and_contract_completeness,
             test_exact_service_descriptors_are_metadata_only,
             test_prompt_query_wsdl_and_sourcemap_grpc_are_exact_and_offline)
    failed = []
    for test in tests:
        try:
            test()
            print("ok  ", test.__name__)
        except Exception as exc:  # noqa: BLE001 - standalone regression prints every failing case
            failed.append(test.__name__)
            print("FAIL", test.__name__, type(exc).__name__, str(exc)[:500])
    print(("FAIL" if failed else "PASS"), "test_web_endpoint_inventory", len(failed), "failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
