#!/usr/bin/env python3
"""Exact-contract, read-only HTTP parameter-pollution peer.

This module never sprays duplicate parameters.  Cached target-local clues must
identify all four facts before it sends anything:

* an exact GET/read route;
* one exact query-parameter name;
* one public/owned scalar control value;
* one distinct protected scalar control value;
* explicit duplicate-parameter/HPP semantics.

It GETs the public and protected controls first, requires the public control to
be readable and the protected control to be denied, then sends exactly the two
duplicate orderings ``public,protected`` and ``protected,public``.  Routes or
parameters associated with authentication, recovery, reset, roles, payments,
or writes are refused.  No POST or non-GET method exists in this module.

Requests use the caller's scope-locked ``WebClient`` and share its deadline,
budget and stop event.  A proof is returned only when it is the single novel
exact payoff token (a proof under a proof event, else a flag; ctf.flagfmt) on a duplicate-parameter payoff.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import re
import sys
import threading
import time
import urllib.parse
from pathlib import Path


# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import env as ctf_env, paths as ctf_paths, flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import env as ctf_env, paths as ctf_paths, flagfmt

HERE = Path(__file__).resolve().parent
_TK = HERE.parent / "toolkits"
if str(_TK) not in sys.path:
    sys.path.insert(0, str(_TK))
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import web as _web  # noqa: E402 -- sole production transport and route guard
import security_json as _security_json  # noqa: E402 -- fail-closed policy JSON

try:
    import forge_event as _proofs  # noqa: E402 -- proof novelty/rejection policy
except Exception:  # pragma: no cover
    _proofs = None

BASELINE_INCOMPLETE = getattr(
    _proofs, "BASELINE_STRICT_INCOMPLETE",
    "<!-- csctf-baseline-strict-set:incomplete -->",
)


REQUEST_TIMEOUT = 8.0
DEFAULT_SECONDS = 25.0
DEFAULT_MAX_REQUESTS = 8
DEADLINE_PAD = 0.3
MAX_TEXT = 400_000
MAX_ROUTE_BYTES = 1024
MAX_SCALAR = 128

_PARAM = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,63}$")
# The event's payoff token in any case (a proof under a proof event, else a flag): ctf.flagfmt.
_PAYOFF_SEEN = flagfmt.PAYOFF_ANYCASE
_HPP_WORDS = re.compile(
    r"(?i)\b(?:http[ _-]?parameter[ _-]?pollution|parameter[ _-]?pollution|duplicate[ _-]?query|"
    r"duplicate[ _-]?parameter|first[ _-]?value|last[ _-]?value|first[ _-]?wins|last[ _-]?wins|hpp)\b"
)
_ROUTE_KEYS = ("hpp_route", "parameter_pollution_route", "duplicate_query_route",
               "read_route", "object_route", "feature_route")
_PARAM_KEYS = ("hpp_parameter", "duplicate_parameter", "query_parameter", "input_parameter",
               "reference_parameter", "id_parameter")
_PUBLIC_KEYS = ("public_reference", "public_value", "allowed_reference", "owned_reference",
                "own_reference", "sample_reference")
_PROTECTED_KEYS = ("protected_reference", "protected_value", "private_reference", "target_reference")
_METHOD_KEYS = ("hpp_method", "request_method", "feature_method", "http_method", "method")

_BLOCKED_ROUTE = re.compile(
    r"(?i)(?:^|[/_.-])(?:login|signin|signon|auth|oauth|token|session|password|passwd|reset|recover|"
    r"recovery|redeem|issue|register|signup|role|admin|privilege|delete|destroy|drop|wipe|purge|"
    r"remove|truncate|erase|revoke|logout|disable|deactivate|kill|shutdown|ban|suspend|cancel|"
    r"transfer|pay|purchase|checkout|refund|approve|reject|create|insert|upload|import|write|"
    r"save|submit|update|edit|execute|exec|run)(?=$|[/_.-]|\d)"
)
_BLOCKED_PARAM = re.compile(
    r"(?i)(?:^|[_.-])(?:login|auth|oauth|token|session|password|passwd|reset|recovery|csrf|role|"
    r"admin|privilege|permission|price|amount|payment|transfer|destination|email|username|user|"
    r"method|action)(?:$|[_.-])"
)


def enabled() -> bool:
    raw = ctf_env.get("CTF_WEB_HPP_READ")
    if raw is not None:
        return raw.strip().lower() in ("on", "1", "true", "yes")
    try:
        root = ctf_paths.workdir()
        return not (root / "_hpp_read.off").exists()
    except Exception:
        return False


def _snake(value) -> str:
    value = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(value or ""))
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")


def _origin(value):
    try:
        p = urllib.parse.urlsplit(str(value or ""))
        if p.scheme not in ("http", "https") or not p.hostname:
            return None
        return p.scheme, p.hostname.lower().rstrip("."), p.port or (443 if p.scheme == "https" else 80)
    except Exception:
        return None


def _response(raw):
    if not isinstance(raw, dict):
        return None
    if "body" in raw:
        return raw
    if "text" in raw:
        out = dict(raw)
        out["body"] = str(raw.get("text") or "").encode()
        return out
    return None


def _text(response) -> str:
    if not isinstance(response, dict):
        return ""
    if _proofs is not None and hasattr(_proofs, "response_text_views"):
        try:
            views = _proofs.response_text_views(response)
            return str(views[0])[:MAX_TEXT] if views else ""
        except Exception:
            return ""
    body = response.get("body", response.get("text", ""))
    if isinstance(body, (bytes, bytearray)):
        return bytes(body[:MAX_TEXT]).decode("utf-8", "replace")
    return str(body or "")[:MAX_TEXT]


def _baseline_text(response) -> str:
    if _proofs is not None and hasattr(_proofs, "response_baseline_text"):
        return _proofs.response_baseline_text(response)
    text = _text(response)
    raw = response.get("response_headers", response.get("headers", {})) if isinstance(response, dict) else {}
    headers = "\n".join(str(value)[:4096] for value in raw.values()) if isinstance(raw, dict) else ""
    return (text + (("\n" + headers) if headers else ""))[:MAX_TEXT]


def _json(response, *, strict=True):
    views = None
    if _proofs is not None and hasattr(_proofs, "response_text_views"):
        try:
            views = _proofs.response_text_views(response, strict=strict)
        except Exception:
            return None
    try:
        value = _security_json.loads_unique(
            views if views is not None else [_text(response)], max_chars=MAX_TEXT)
        return value if isinstance(value, dict) else None
    except Exception:
        return None


def _flatten(value, depth=0):
    out = []
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            pairs = list(item.items())
            out.extend(str(key) for key, _child in pairs)
            stack.extend(child for _key, child in reversed(pairs))
        elif isinstance(item, list):
            stack.extend(reversed(item))
        elif isinstance(item, (str, int, float, bool)):
            out.append(str(item))
    return out


def _safe_route(value, base_url):
    try:
        route = _web.safe_same_origin_route(
            value, base_url, allow_query=False, guard_query=True, max_bytes=MAX_ROUTE_BYTES)
        if route is None:
            return None
        path = urllib.parse.urlsplit(route).path or "/"
        if any(ch in path for ch in "{}*"):
            return None
        layers = _web.canonical_route_layers(path, max_bytes=MAX_ROUTE_BYTES) or ()
        guarded_layers = []
        for layer in layers:
            guarded_layers.append(layer)
            guarded_layers.append(re.sub(r"([a-z0-9])([A-Z])", r"\1/\2", layer))
        if (any(_BLOCKED_ROUTE.search(layer) for layer in guarded_layers)
                or any(_web.route_has_destructive_action(layer) for layer in layers)):
            return None
        return route
    except Exception:
        return None


def _safe_scalar(value):
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        return None
    text = str(value)
    if not 1 <= len(text) <= MAX_SCALAR or any(ord(ch) < 0x20 for ch in text):
        return None
    # A scalar control is an identifier/value, never a nested URL or syntax.
    if ("://" in text or text.startswith("//") or any(ch in text for ch in "&#;%?\\\r\n")):
        return None
    return text


def _preloaded_docs(preloaded, base_url):
    out = {}
    raw_keys = {}
    collided = set()
    items = list((preloaded or {}).items())
    if len(items) > 60:
        return {}
    for path, response in items:
        if not isinstance(path, str):
            continue
        route = _web.safe_preloaded_route_key(path, base_url, max_bytes=MAX_ROUTE_BYTES)
        if route is None or route in collided:
            continue
        if route in raw_keys and raw_keys[route] != path:
            out.pop(route, None)
            collided.add(route)
            continue
        raw_keys[route] = path
        normalized = _response(response)
        if (normalized is None or not isinstance(normalized.get("status"), int)
                or not 200 <= normalized["status"] < 300):
            continue
        # This document can authorize duplicate live GETs.  Treat every
        # framing/carrier defect (including an unsafe archive/MIME sibling) as
        # invalid authority rather than salvaging one convenient JSON leaf.
        doc = _json(normalized, strict=True)
        if isinstance(doc, dict):
            out[route] = doc
    return out


def _first(documents, keys):
    for doc in documents:
        if not isinstance(doc, dict):
            continue
        for key in keys:
            value = doc.get(key)
            if isinstance(value, (str, int)) and not isinstance(value, bool):
                return value, key
    return None, None


_MISSING = object()
_CONFLICT = object()


def _coherent(document, keys, normalizer, *, types=(str, int)):
    values = []
    present = []
    for key in keys:
        if key not in document:
            continue
        present.append(key)
        raw = document.get(key)
        if not isinstance(raw, types) or isinstance(raw, bool):
            return _CONFLICT, present
        try:
            value = normalizer(raw)
        except Exception:
            return _CONFLICT, present
        if value is None:
            return _CONFLICT, present
        if value not in values:
            values.append(value)
    if not values:
        return _MISSING, present
    return (values[0] if len(values) == 1 else _CONFLICT), present


def _local_ref(document, value, seen=None):
    if not isinstance(value, dict):
        return None
    if "$ref" not in value:
        return value
    if set(value) != {"$ref"}:
        return None
    ref = value.get("$ref")
    if not isinstance(ref, str) or not ref.startswith("#/") or len(ref) > 512:
        return None
    seen = set(seen or ())
    if ref in seen or len(seen) >= 8:
        return None
    seen.add(ref)
    node = document
    try:
        for raw in ref[2:].split("/"):
            token = raw.replace("~1", "/").replace("~0", "~")
            if not isinstance(node, dict) or token not in node:
                return None
            node = node[token]
    except Exception:
        return None
    return _local_ref(document, node, seen)


def _oas_get(doc, route, param):
    """True only when an OpenAPI document corroborates this exact GET query member."""
    if not isinstance(doc, dict) or not isinstance(doc.get("paths"), dict):
        return False
    raw = urllib.parse.urlsplit(route).path
    item = doc["paths"].get(raw)
    operation = item.get("get") if isinstance(item, dict) else None
    if not isinstance(operation, dict):
        return False
    security = operation.get("security", doc.get("security", []))
    if not isinstance(security, list) or security:
        return False
    params = []
    for owner in (item, operation):
        if "parameters" not in owner:
            continue
        rows = owner.get("parameters")
        if not isinstance(rows, list):
            return False
        for row in rows:
            resolved = _local_ref(doc, row)
            if not isinstance(resolved, dict):
                return False
            params.append(resolved)
    identities = [(row.get("in"), row.get("name")) for row in params]
    if len(identities) != len(set(identities)):
        return False
    if any(row.get("required") is True
           and not (row.get("in") == "query" and row.get("name") == param) for row in params):
        return False
    return any(row.get("in") == "query" and row.get("name") == param
               for row in params)


def _contract(docs, base_url):
    clues = docs.get("/api/clues")
    if not isinstance(clues, dict):
        return None
    sources = [("clues", clues)]
    inventory = clues.get("inventory_route")
    if isinstance(inventory, str):
        inventory_route = _safe_route(inventory, base_url)
        if inventory_route is not None and isinstance(docs.get(inventory_route), dict):
            sources.append(("linked-inventory", docs[inventory_route]))

    # Route, parameter, both controls and method semantics are one authority
    # object.  Combining a route-only clue with controls from another response
    # lets unrelated target text synthesize permission for live requests.
    # OpenAPI may corroborate a *complete* object's GET shape, but supplies no
    # missing control value.  Distinct complete contracts are ambiguous.
    contracts = []
    for source_name, authority in sources:
        prose = " ".join(_flatten(authority))[:100_000]
        explicit_key = any(_snake(key).startswith(
            ("hpp_", "parameter_pollution", "duplicate_")) for key in authority)
        if not explicit_key and not _HPP_WORDS.search(prose):
            continue

        route, route_keys = _coherent(
            authority, _ROUTE_KEYS, lambda value: _safe_route(str(value), base_url))
        param, param_keys = _coherent(authority, _PARAM_KEYS, lambda value: str(value))
        public, _public_keys = _coherent(authority, _PUBLIC_KEYS, _safe_scalar)
        protected, _protected_keys = _coherent(authority, _PROTECTED_KEYS, _safe_scalar)
        if (route in (_MISSING, _CONFLICT) or param in (_MISSING, _CONFLICT)
                or public in (_MISSING, _CONFLICT) or protected in (_MISSING, _CONFLICT)
                or not _PARAM.fullmatch(param) or _BLOCKED_PARAM.search(param)
                or public == protected):
            continue

        method, method_keys = _coherent(
            authority, _METHOD_KEYS, lambda value: str(value).strip().upper())
        if method is _CONFLICT or (method is not _MISSING and method != "GET"):
            continue
        exact_keys = any(key.startswith(("hpp_", "parameter_pollution", "duplicate_"))
                         for key in route_keys) \
            and any(key.startswith(("hpp_", "duplicate_")) for key in param_keys)
        openapi_get = any(_oas_get(doc, route, param) for doc in docs.values())
        if not (exact_keys or method == "GET" or openapi_get):
            continue
        contracts.append({
            "route": route, "param": param, "public": public, "protected": protected,
            "source": "hpp-keys" if exact_keys else ("openapi" if openapi_get else source_name),
        })

    unique = {}
    for contract in contracts:
        key = (contract["route"], contract["param"], contract["public"], contract["protected"])
        unique.setdefault(key, contract)
    return next(iter(unique.values())) if len(unique) == 1 else None


def _linked_inventory(docs, base_url):
    """One exact safe inventory route, only when clues already identify HPP semantics."""
    clues = docs.get("/api/clues")
    if not isinstance(clues, dict):
        return None
    prose = " ".join(_flatten(clues))[:50_000]
    explicit_key = any(_snake(key).startswith(("hpp_", "parameter_pollution", "duplicate_"))
                       for key in clues)
    if not explicit_key and not _HPP_WORDS.search(prose):
        return None
    route = _safe_route(clues.get("inventory_route"), base_url)
    return route if route and route not in docs else None


def _with_values(route, param, values):
    parts = urllib.parse.urlsplit(route)
    if parts.query or parts.fragment:
        return None
    query = urllib.parse.urlencode([(param, value) for value in values])
    return urllib.parse.urlunsplit(("", "", parts.path or "/", query, ""))


def _ok(response):
    return isinstance(response, dict) and isinstance(response.get("status"), int) \
        and 200 <= response["status"] < 300


def _denied(response):
    if not isinstance(response, dict):
        return False
    if response.get("status") in (401, 403):
        return True
    # A 2xx JSON/application denial is accepted only when the shared rejection
    # classifier recognizes it.  A 404 is not authorization evidence.
    return bool(_proofs is not None and _proofs.rejection_signal(response)
                and isinstance(response.get("status"), int) and 200 <= response["status"] < 300)


class _Runner:
    def __init__(self, target, ctx):
        self.target = dict(target) if isinstance(target, dict) else {"url": str(target)}
        self.url = str(self.target.get("url") or "")
        self.ctx = dict(ctx or {})
        try:
            self.deadline = float(self.ctx["deadline"]) if self.ctx.get("deadline") is not None \
                else time.time() + DEFAULT_SECONDS
        except (TypeError, ValueError):
            self.deadline = time.time() + DEFAULT_SECONDS
        try:
            self.max_requests = max(0, int(self.ctx.get("max_requests", DEFAULT_MAX_REQUESTS)))
        except (TypeError, ValueError):
            self.max_requests = DEFAULT_MAX_REQUESTS
        self.external_stop = self.ctx.get("stop")
        self.preloaded = dict(self.ctx.get("preloaded") or {})
        supplied_baselines = list(self.ctx.get("baseline_texts") or [])
        self.baselines = [str(value or "")[:MAX_TEXT] for value in supplied_baselines[:60]]
        if len(supplied_baselines) > 60 and BASELINE_INCOMPLETE not in self.baselines:
            self.baselines.append(BASELINE_INCOMPLETE)
        for response in list(self.preloaded.values())[:60]:
            normalized = _response(response)
            if normalized is not None:
                self.baselines.append(_baseline_text(normalized))
        self.requests = 0
        self.posts = 0
        self.duplicate_requests = 0
        self.success = False
        self.confirmed = False
        self.uuid4 = False
        self.candidates = []
        self.findings = []
        self.responses = []
        self.where = None
        self.stopped = None
        self.t0 = time.time()
        self.client = None
        self._gate = threading.Lock()
        self._stopped = False

    def _may_send(self):
        if self._stopped or (hasattr(self.external_stop, "is_set") and self.external_stop.is_set()):
            self.stopped = self.stopped or "stopped"
            return False
        if self.requests >= self.max_requests:
            self.stopped = self.stopped or "max_requests"
            return False
        if self.deadline is not None and self.deadline - time.time() <= DEADLINE_PAD:
            self.stopped = self.stopped or "deadline"
            return False
        return True

    def _client(self):
        if self.client is not None:
            return self.client
        wanted = _origin(self.url)
        if wanted is None:
            self.stopped = "invalid target origin"
            return None
        try:
            candidate = self.ctx.get("client")
            if candidate is None and callable(self.ctx.get("client_factory")):
                candidate = self.ctx["client_factory"](self.url, REQUEST_TIMEOUT)
            if candidate is None:
                candidate = _web.WebClient(self.url, timeout=REQUEST_TIMEOUT)
            if _origin(getattr(candidate, "base", None)) != wanted:
                self.stopped = "client scope mismatch"
                return None
            self.client = candidate
            return candidate
        except Exception as exc:
            self.stopped = f"no scoped client: {type(exc).__name__}"
            return None

    def stop_now(self):
        with self._gate:
            self._stopped = True

    def get(self, path, role, *, duplicate=False):
        route = _web.safe_same_origin_route(
            path, self.url, allow_query=True, guard_query=True, max_bytes=MAX_ROUTE_BYTES)
        if route is None:
            self.stopped = self.stopped or "unsafe HPP request"
            return None
        with self._gate:
            client = self._client()
            if client is None or not self._may_send():
                return None
            try:
                left = self.deadline - time.time() if self.deadline is not None else None
                client.timeout = REQUEST_TIMEOUT if left is None else max(0.2, min(REQUEST_TIMEOUT, left - 0.1))
            except Exception:
                pass
            self.requests += 1
            if duplicate:
                self.duplicate_requests += 1
            try:
                response = client.request("GET", route, allow_redirects=False)
            except Exception as exc:
                self.responses.append({"role": role, "path": route.split("?", 1)[0], "status": None,
                                       "error": type(exc).__name__})
                self.stopped = self.stopped or f"transport: {type(exc).__name__}"
                self._stopped = True
                return None
            response = _response(response)
            self.responses.append({"role": role, "path": route.split("?", 1)[0],
                                   "status": response.get("status") if response else None})
            return response

    def run(self):
        if not enabled():
            self.stopped = "off"
            return None
        if _proofs is None:
            self.stopped = "shared proof classifier unavailable"
            return None
        docs = _preloaded_docs(self.preloaded, self.url)
        contract = _contract(docs, self.url)
        linked = _linked_inventory(docs, self.url) if contract is None else None
        if linked is not None:
            # One inventory GET plus the complete four-request control/payoff sequence must fit before the
            # peer spends anything.  The inventory is recon, but a short budget should not leave a half-run.
            if self.max_requests - self.requests < 5 or not self._may_send():
                self.stopped = self.stopped or "insufficient budget for HPP inventory and controls"
                return None
            route_allowed = self.ctx.get("route_allowed")
            if callable(route_allowed):
                try:
                    if not route_allowed(linked):
                        self.stopped = "caller route policy refused HPP inventory"
                        return None
                except Exception:
                    self.stopped = "caller route policy failed closed"
                    return None
            inventory = self.get(linked, "contract-inventory")
            inventory_doc = _json(inventory)
            if not _ok(inventory) or not isinstance(inventory_doc, dict):
                self.stopped = self.stopped or "linked HPP inventory was not usable JSON"
                return None
            self.baselines.append(_baseline_text(inventory))
            docs[linked] = inventory_doc
            contract = _contract(docs, self.url)
        if contract is None:
            self.stopped = "no exact read-only HPP contract"
            return None
        route_allowed = self.ctx.get("route_allowed")
        if callable(route_allowed):
            try:
                if not route_allowed(contract["route"]):
                    self.stopped = "caller route policy refused HPP route"
                    return None
            except Exception:
                self.stopped = "caller route policy failed closed"
                return None
        if self.max_requests - self.requests < 4 or not self._may_send():
            self.stopped = self.stopped or "insufficient budget for HPP controls"
            return None
        if self._client() is None:
            return None

        public_path = _with_values(contract["route"], contract["param"], [contract["public"]])
        protected_path = _with_values(contract["route"], contract["param"], [contract["protected"]])
        public = self.get(public_path, "public-control")
        protected = self.get(protected_path, "protected-control")
        if public is None or protected is None:
            self.stopped = self.stopped or "HPP controls failed"
            return None
        self.baselines.extend((_baseline_text(public), _baseline_text(protected)))
        if not _ok(public) or _denied(public) or not _denied(protected):
            self.stopped = "public/protected read controls did not establish authorization boundary"
            return None

        orders = ((contract["public"], contract["protected"]),
                  (contract["protected"], contract["public"]))
        responses = []
        for index, values in enumerate(orders):
            path = _with_values(contract["route"], contract["param"], values)
            response = self.get(path, f"duplicate-{index + 1}", duplicate=True)
            if response is None:
                self.stopped = self.stopped or "duplicate ordering failed"
                return None
            responses.append(response)

        outcomes = []
        for response in responses:
            outcome = (_proofs.extract_success(
                response, self.baselines, host=urllib.parse.urlsplit(self.url).hostname)
                if _proofs is not None else {})
            outcomes.append(outcome)
        readable = [index for index, response in enumerate(responses) if _ok(response) and not _denied(response)]
        self.confirmed = bool(readable)
        self.findings.append({"class": "parameter_pollution", "confirmed": self.confirmed,
                              "evidence": "duplicate_read_transition" if self.confirmed else "not_confirmed",
                              "path": contract["route"], "param": contract["param"],
                              "readable_orderings": readable})

        autos = list(dict.fromkeys(outcome.get("auto") for outcome in outcomes if outcome.get("auto")))
        candidates = []
        for outcome in outcomes:
            candidates += list(outcome.get("candidates") or [])
            if outcome.get("auto") is None:
                candidates += list(outcome.get("wire") or [])
        self.candidates = list(dict.fromkeys(str(value)[:256] for value in candidates))[:12]
        self.success = bool(autos or self.candidates)
        self.where = "hpp-duplicate-get"
        if len(autos) == 1 and not self.candidates:
            self.uuid4 = bool(any(outcome.get("uuid4") for outcome in outcomes
                                  if outcome.get("auto") == autos[0]))
            return autos[0]
        if len(autos) > 1:
            self.candidates = list(dict.fromkeys(self.candidates + autos))[:12]
            self.success = True
            self.stopped = "duplicate orderings returned ambiguous proofs"
        elif self.candidates:
            self.stopped = "HPP response surfaced candidate evidence"
        else:
            self.stopped = "HPP not confirmed with a proof"
        return None

    def summary(self, proof):
        return {"proof": proof, "class": "parameter_pollution", "success": self.success,
                "confirmed": self.confirmed,
                "candidates": list(dict.fromkeys(self.candidates))[:12], "uuid4": self.uuid4,
                "baseline_proofs": list(dict.fromkeys(
                    match.group(0) for text in self.baselines
                    for match in _PAYOFF_SEEN.finditer(str(text or ""))
                ))[:24],
                "requests": self.requests, "posts": 0,
                "duplicate_requests": self.duplicate_requests,
                "seconds": round(time.time() - self.t0, 3), "where": self.where,
                "stopped": self.stopped, "findings": self.findings[:8],
                "responses": self.responses[:12]}


def _surface(runner, ctx):
    evidence = ctx.get("evidence") if isinstance(ctx, dict) else None
    if not isinstance(evidence, list):
        return
    aid = runner.target.get("answer_id") or "target"
    for value in list(dict.fromkeys(runner.candidates))[:6]:
        line = _web.safe_display_text(
            f"WEB HPP CANDIDATE {aid}: {value} (duplicate GET response; not auto-submitted)", 600)
        if line not in evidence:
            evidence.append(line)


def solve(target, ctx=None):
    """Solve one target; never raises and never submits."""
    ctx = dict(ctx or {})
    runner = _Runner(target, ctx)
    proof = None
    try:
        proof = runner.run()
    except Exception as exc:
        runner.stopped = runner.stopped or f"error: {type(exc).__name__}"
    finally:
        runner.stop_now()
    _surface(runner, ctx)
    summary = runner.summary(proof)
    aid = runner.target.get("answer_id") or "target"
    sink = ctx.get("result_sink")
    if isinstance(sink, dict):
        sink[aid] = summary
    _write_log(ctx.get("log_dir"), ctx.get("challenge"), aid, summary)
    return proof


def solve_targets(targets, ctx=None):
    out = {}
    for index, target in enumerate(list(targets or [])):
        if not isinstance(target, dict):
            continue
        item = dict(target)
        aid = str(item.get("answer_id") or item.get("id") or f"target-{index + 1}")
        item["answer_id"] = aid
        out[aid] = solve(item, ctx)
    return out


def _write_log(log_dir, challenge, aid, summary):
    if not log_dir:
        return
    try:
        folder = Path(log_dir)
        folder.mkdir(parents=True, exist_ok=True)
        row = {"at": _dt.datetime.now().astimezone().isoformat(timespec="seconds"),
               "challenge": challenge, "answer_id": aid, **summary}
        with (folder / "hpp_read.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, separators=(",", ":"), default=str) + "\n")
    except Exception:
        pass
