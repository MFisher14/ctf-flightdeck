"""Deterministic tests for lexical REST/OpenAPI abuse analysis."""

from __future__ import annotations

import ast
from pathlib import Path
import sys

import pytest


REPO = Path(__file__).resolve().parents[1]
WEB = REPO / "solvers" / "web"
sys.path.insert(0, str(WEB))

import rest_schema_abuse as rest  # noqa: E402


SCHEMA = r'''
openapi: 3.1.0
security:
  - bearerAuth: []
paths:
  /api/v1/users/{id}:
    get:
      operationId: getUserV1
      security: []
      parameters:
        - name: limit
          in: query
          schema:
            type: integer
    patch:
      operationId: patchUserV1
      security:
        - bearerAuth: []
      requestBody:
        content:
          application/json:
            schema: {}
          text/plain:
            schema: {}
  /api/v2/users/{id}:
    get:
      operationId: getUserV2
      security:
        - bearerAuth: []
  /admin/users:
    delete:
      operationId: deleteUsers
      security: []
components:
  schemas:
    UserUpdate:
      type: object
      additionalProperties: true
      properties:
        role:
          type: string
        ownerId:
          type: string
        displayName:
          type: string
      x-header: X-HTTP-Method-Override
'''

SOURCE = r'''
router.get("/internal/audit", auditHandler)
router.patch("/api/v1/users/:id", (request, response) => {
  const permissions = request.body.permissions;
  Object.assign(user, request.body);
  return user.save();
});
app.use(methodOverride("X-HTTP-Method-Override"));
'''


def _ids(findings):
    return {item.finding_id for item in findings}


def test_openapi_lexical_extractor_preserves_operation_security_and_content_types():
    operations = rest.extract_openapi_operations(SCHEMA)
    assert {(item.method, item.path) for item in operations} >= {
        ("get", "/api/v1/users/{id}"),
        ("patch", "/api/v1/users/{id}"),
        ("get", "/api/v2/users/{id}"),
        ("delete", "/admin/users"),
    }
    v1_get = next(item for item in operations
                  if item.method == "get" and item.path == "/api/v1/users/{id}")
    assert v1_get.operation_id == "getUserV1"
    assert v1_get.security_state == "explicit-empty"
    assert "limit" in v1_get.parameter_names
    patch = next(item for item in operations if item.method == "patch")
    assert set(patch.content_types) == {"application/json", "text/plain"}


def test_schema_analysis_covers_all_requested_rest_abuse_families():
    findings = rest.analyze_openapi_schema(SCHEMA, source=SOURCE)
    ids = _ids(findings)
    assert {
        "openapi-object-routes", "openapi-function-security", "openapi-mass-assignment",
        "openapi-additional-properties", "openapi-method-override",
        "openapi-content-type-differential", "openapi-version-security",
        "openapi-pagination-bound", "openapi-hidden-surface",
    } <= ids
    assert {item.family for item in findings} >= {
        "BOLA", "BFLA", "mass-assignment", "method-override", "content-type",
        "api-versioning", "pagination", "hidden-fields",
    }
    assert all(item.evidence and item.remediation for item in findings)


def test_schema_findings_distinguish_evidence_from_claims():
    findings = rest.analyze_openapi_schema(SCHEMA, source=SOURCE)
    bola = next(item for item in findings if item.finding_id == "openapi-object-routes")
    assert bola.title.endswith("require per-object authorization")
    assert bola.confidence == "medium"
    hidden = next(item for item in findings if item.finding_id == "openapi-hidden-surface")
    assert hidden.confidence == "medium"
    assert any("/internal/audit" in evidence for evidence in hidden.evidence)
    assert any("permissions" in evidence for evidence in hidden.evidence)
    assert not any("/api/v1/users/:id" in evidence for evidence in hidden.evidence)


def test_read_only_sensitive_field_and_bounded_pagination_avoid_mass_assignment_leads():
    safe = r'''
openapi: 3.0.0
security:
  - bearer: []
paths:
  /reports:
    get:
      parameters:
        - name: limit
          schema:
            type: integer
            maximum: 100
  /profile:
    patch:
      requestBody:
        content:
          application/json:
            schema: {}
components:
  schemas:
    Profile:
      properties:
        role:
          readOnly: true
          type: string
'''
    ids = _ids(rest.analyze_openapi_schema(safe))
    assert "openapi-mass-assignment" not in ids
    assert "openapi-pagination-bound" not in ids
    assert "openapi-content-type-differential" not in ids


def test_json_style_openapi_lines_are_extracted_without_json_deserialisation():
    schema = r'''
{
  "paths": {
    "/objects/{id}": {
      "get": {
        "operationId": "getObject",
        "security": []
      }
    }
  }
}
'''
    operations = rest.extract_openapi_operations(schema)
    assert len(operations) == 1
    assert operations[0].path == "/objects/{id}"
    assert operations[0].method == "get"
    assert operations[0].security_state == "explicit-empty"


def test_component_method_named_get_is_not_mistaken_for_a_path_operation():
    schema = r'''
paths:
  /items:
    get:
      operationId: listItems
components:
  schemas:
    OddObject:
      properties:
        get:
          type: string
'''
    operations = rest.extract_openapi_operations(schema)
    assert [(item.method, item.path) for item in operations] == [("get", "/items")]


def test_readonly_on_a_sibling_does_not_hide_a_writable_sensitive_field():
    schema = r'''
paths:
  /profile:
    patch:
      requestBody:
        content:
          application/json: {}
components:
  schemas:
    Profile:
      properties:
        role:
          type: string
        displayName:
          readOnly: true
          type: string
'''
    assert "openapi-mass-assignment" in _ids(rest.analyze_openapi_schema(schema))


def test_saved_rest_capture_detects_duplicate_parsers_override_bola_and_mass_assignment():
    body = '{"role":"user","role":"admin","ownerId":"7"}'
    request = (
        "PATCH /api/v1/users/12345?limit=99999&_method=DELETE HTTP/1.1\r\n"
        "Host: app.test\r\nContent-Type: application/json\r\n"
        "Content-Type: text/plain\r\nX-HTTP-Method-Override: PUT\r\n"
        f"Content-Length: {len(body)}\r\n\r\n{body}"
    )
    findings = rest.analyze_rest_capture(
        request,
        response="HTTP/1.1 200 OK\r\nSunset: tomorrow\r\n\r\ndeprecated legacy API",
    )
    ids = _ids(findings)
    assert {
        "rest-duplicate-content-type", "rest-method-override", "rest-object-identifier",
        "rest-sensitive-body-fields", "rest-pagination-bound", "rest-legacy-version",
    } <= ids
    mass = next(item for item in findings if item.finding_id == "rest-sensitive-body-fields")
    assert any("role" in evidence and "duplicate" in evidence for evidence in mass.evidence)


@pytest.mark.parametrize(
    ("content_type", "body"),
    [("application/json", "<root/>"), ("application/xml", '{"x":1}'),
     ("application/x-www-form-urlencoded", "[1,2]")],
)
def test_rest_capture_content_type_shape_mismatches(content_type, body):
    request = (
        f"POST /items HTTP/1.1\r\nHost: app.test\r\nContent-Type: {content_type}\r\n"
        f"Content-Length: {len(body)}\r\n\r\n{body}"
    )
    assert "rest-body-parser-mismatch" in _ids(rest.analyze_rest_capture(request))


def test_rest_capture_safe_control_has_no_findings():
    body = '{"displayName":"R5D"}'
    request = (
        f"PATCH /profile HTTP/1.1\r\nHost: app.test\r\nContent-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n\r\n{body}"
    )
    assert rest.analyze_rest_capture(request) == ()


def test_rest_variant_matrix_is_stable_inert_and_complete():
    rows = rest.build_rest_variants("/api/v1/items/{id}", method="PATCH", marker="R5D_INERT")
    assert rows == rest.build_rest_variants("/api/v1/items/{id}", method="PATCH", marker="R5D_INERT")
    assert [row.rank for row in rows] == list(range(1, len(rows) + 1))
    assert {row.family for row in rows} == {
        "BOLA", "BFLA", "mass-assignment", "method-override", "content-type",
        "api-versioning", "pagination", "hidden-fields",
    }
    assert all("r5d-probe.invalid" in row.request for row in rows)
    assert all(row.offline and row.network_requests == 0 and row.hypothesis for row in rows)
    assert any("R5D_OTHER_OBJECT_ID" in row.request for row in rows if row.family == "BOLA")


def test_rest_inputs_are_bounded_and_reject_controls():
    with pytest.raises(rest.RESTAnalysisError, match="exceeds"):
        rest.analyze_openapi_schema("x" * (rest.MAX_SCHEMA_CHARS + 1))
    with pytest.raises(rest.RESTAnalysisError, match="request line"):
        rest.analyze_rest_capture("not a request")
    with pytest.raises(rest.RESTAnalysisError, match="path"):
        rest.build_rest_variants("relative")
    with pytest.raises(rest.RESTAnalysisError, match="marker"):
        rest.build_rest_variants(marker="bad\r\nmarker")
    query = "&".join(f"x{i}=1" for i in range(513))
    request = f"GET /items?{query} HTTP/1.1\r\nHost: app.test\r\n\r\n"
    with pytest.raises(rest.RESTAnalysisError, match="query field count"):
        rest.analyze_rest_capture(request)


def test_rest_module_never_deserialises_schema_or_opens_transports_processes():
    tree = ast.parse((WEB / "rest_schema_abuse.py").read_text(encoding="utf-8"))
    imports: set[str] = set()
    calls: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module)
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                calls.add(node.func.id)
            elif isinstance(node.func, ast.Attribute):
                calls.add(node.func.attr)
    assert not imports.intersection({
        "json", "yaml", "ruamel", "pickle", "marshal", "socket", "requests",
        "http.client", "urllib.request", "subprocess", "websocket",
    })
    assert not calls.intersection({
        "loads", "load", "safe_load", "eval", "exec", "connect", "request",
        "send", "sendall", "urlopen", "Popen", "run",
    })
