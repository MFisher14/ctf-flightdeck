#!/usr/bin/env python3
"""Bounded passive endpoint inventory for a live web target.

This is recon, not an exploit and not an answer reader.  It fetches only a small
set of inert, same-origin documents with GET through ``web.WebClient``:

* the landing page, robots.txt, /openapi.json and /sitemap.xml;
* same-origin OpenAPI or sitemap documents explicitly linked by those pages;
* same-origin JavaScript files referenced by ``<script src>``; and
* same-origin source maps explicitly named by those JavaScript files.
* exact same-origin AsyncAPI/OpenRPC/WSDL/protobuf service-description links
  named by HTML, target-local prompt text, linked JavaScript, or its explicit
  source map; and generated gRPC-web metadata already present in fetched JS.

Swagger 2.0 and OpenAPI 3.0/3.1/3.2 JSON or safely loaded YAML are normalized across
local reference chains, server/base paths, parameters, composed request schemas,
response fields and security schemes. OAS 3 callbacks and OAS 3.1/3.2 webhooks are
normalized as explicitly non-requestable operation metadata. OpenAPI path keys, sitemap locations and
routes/parameters found by the existing ``js_recon`` and ``sourcemap`` offline
readers are returned as *findings*. Their bounded secret-shaped strings are separate
metadata leads explicitly marked never-auto-submit. No discovered application route is requested,
AsyncAPI channels, OpenRPC methods, SOAP addresses and gRPC RPCs are
metadata-only and never invoked,
no response is executed or imported, redirects are not followed, and this module
never returns a proof or flag.

Public API:

``discover(target, ctx=None)``
    Inventory one target. ``target`` is a URL or a target dict carrying ``url``.
    ``ctx`` may provide an existing scope-locked ``client``, recon-supplied
    ``preloaded`` pages, ``max_requests``, ``max_bytes``, ``deadline`` and a
    threading ``stop`` event.

``discover_targets(targets, ctx=None)``
    Return ``{answer_id: inventory}`` for recon-shaped target dicts.

``solve_targets(targets, ctx=None)``
    Compatibility shim: put inventories in ``ctx['inventory_sink']`` (or
    ``ctx['result_sink']``), append one diagnostic to ``ctx['evidence']``, and
    return ``{answer_id: None}``.  Recon can therefore never become a submitted
    answer by accidental registration as a solver.
"""

from __future__ import annotations

import base64
import html
import importlib.util
import json
import re
import threading
import time
import urllib.parse
from pathlib import Path

try:  # Optional at runtime; JSON remains fully supported when PyYAML is absent.
    import yaml as _yaml
except Exception:  # pragma: no cover - exercised by deployments without the optional package
    _yaml = None


HERE = Path(__file__).resolve().parent
TOOLKITS = HERE.parent / "toolkits"

DEFAULT_MAX_REQUESTS = 12
DEFAULT_MAX_BYTES = 6 * 1024 * 1024
MAX_DOCUMENT = 2 * 1024 * 1024
MAX_SCRIPTS = 4
MAX_SOURCE_MAPS = 2
MAX_OPENAPI_DOCS = 2
MAX_OPENAPI_ATTEMPTS = 8
MAX_DESCRIPTOR_DOCS = 3
MAX_DESCRIPTOR_ATTEMPTS = 4
MAX_SITEMAPS = 2
MAX_ROUTES = 256
MAX_PARAMS = 256
MAX_OPERATIONS = 256
MAX_EVENT_OPERATIONS = 64
MAX_SECRET_LEADS = 16
MAX_SECRET_VALUE_BYTES = 16 * 1024
MAX_VALUES = 8
MAX_SCHEMA_DEPTH = 12
MAX_DOCUMENT_NODES = 20_000
MAX_YAML_ALIASES = 64
MAX_ROUTE_BYTES = 1024
DEADLINE_PAD = 0.20
REQUEST_TIMEOUT = 2.0  # passive fallbacks run only after exact routes miss; keep their worst case finale-fast
SECRET_LEADS_POLICY = "metadata-only; never auto-submit and never replay to a target"

HTTP_METHODS = ("get", "post", "put", "patch", "delete", "options", "head", "trace")
OAS32_HTTP_METHODS = HTTP_METHODS + ("query",)
PARAM_LOCATIONS = ("path", "query", "header", "cookie")
ASSET_SUFFIXES = (".js", ".mjs")
DESTRUCTIVE_PATH = re.compile(
    r"(?i)(?:^|[/_.-])(?:delete|remove|destroy|reset|logout|signout|drop|wipe|purge|revoke|disable|"
    r"deactivate|truncate|flush|clear|erase|uninstall|shutdown|restart|reboot|ban|suspend|unregister|"
    r"cancel|rollback|restore|update|transfer|pay|approve|reject|edit|create|insert|upload|import|write|"
    r"save|submit|exec|execute|run|cmd|command|shell|eval)(?:$|[/_.-])"
)
SCRIPT_TAG = re.compile(r"(?is)<script\b([^>]*)>")
LINK_TAG = re.compile(r"(?is)<link\b([^>]*)>")
ANCHOR_TAG = re.compile(r"(?is)<a\b([^>]*)>")
ATTR = re.compile(r'''(?is)\b([a-z_:][-a-z0-9_:.]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))''')
SERVICE_DESCRIPTOR_TOKEN = re.compile(
    r'''(?ix)(?:
        https?://[^\s"'<>]+
        |
        (?:\.?/)?[a-z0-9_~.!$&()*+,;=:@%-][a-z0-9_~.!$&()*+,;=:@%/?#-]*
        (?:\.wsdl|\.proto|_grpc_web_pb\.js|grpc[-_]web\.js)
        (?:\?[a-z0-9_~.!$&()*+,;=:@%/?#-]*)?
        |
        (?:\.?/)?[a-z0-9_~.!$&()*+,;=:@%-][a-z0-9_~.!$&()*+,;=:@%/#-]*
        \?wsdl(?:=[^\s"'<>]*)?
    )'''
)
SITEMAP_LOC = re.compile(r"(?is)<(?:[a-z0-9_.-]+:)?loc\b[^>]*>(.*?)</(?:[a-z0-9_.-]+:)?loc\s*>")
ROBOTS_SITEMAP = re.compile(r"(?im)^\s*Sitemap\s*:\s*(\S+)\s*$")
ROBOTS_ROUTE = re.compile(r"(?im)^\s*(?:Allow|Disallow)\s*:\s*([^#\s]+)")


def _load(name, path):
    try:
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    except Exception:
        return None


_web = _load("csctf_endpoint_inventory_web", TOOLKITS / "web.py")
_js = _load("csctf_endpoint_inventory_js", HERE / "js_recon.py")
_sourcemap = _load("csctf_endpoint_inventory_sourcemap", HERE / "sourcemap.py")
_descriptors = _load("csctf_endpoint_inventory_descriptors", HERE / "descriptor_inventory.py")
_responses = _load("csctf_endpoint_inventory_responses", HERE / "forge_event.py")
_services = _load("csctf_endpoint_inventory_services", HERE / "service_descriptors.py")
_security_json = _load("csctf_endpoint_inventory_security_json", HERE / "security_json.py")


def _attrs(raw):
    out = {}
    for match in ATTR.finditer(str(raw or "")[:16_000]):
        value = next((v for v in match.groups()[1:] if v is not None), "")
        out[match.group(1).lower()] = html.unescape(value.strip())
    return out


def _origin(url):
    try:
        p = urllib.parse.urlsplit(str(url or ""))
        if p.scheme not in ("http", "https") or not p.hostname:
            return None
        return p.scheme.lower(), p.hostname.lower(), p.port or (443 if p.scheme.lower() == "https" else 80)
    except (TypeError, ValueError):
        return None


def _safe_path(base_url, raw, at=None):
    """A clean same-scheme/host/port path, or None.  It is safe to *name* in findings.

    The caller separately applies the asset/document allow-list before fetching it.
    Encoded traversal, credentials, controls and ambiguous scheme-relative URLs fail
    closed.  Fragments are discarded because they are never sent over HTTP.
    """
    if _web is None or not isinstance(raw, str):
        return None
    try:
        stripped = raw.strip()
        if (stripped != raw or not stripped or len(stripped.encode("utf-8", "replace")) > MAX_ROUTE_BYTES
                or raw.startswith(("#", "//")) or "\\" in raw
                or any(ord(char) < 0x20 or char.isspace() for char in raw)):
            return None
        raw = stripped
        base = (base_url.rstrip("/") + "/" if at is None
                else urllib.parse.urljoin(base_url.rstrip("/") + "/", at or "/"))
        absolute = urllib.parse.urljoin(base, raw)
        parsed = urllib.parse.urlsplit(absolute)
        if (_origin(absolute) != _origin(base_url) or parsed.username is not None
                or parsed.password is not None or parsed.fragment):
            return None
        # `_safe_path` may retain an inner URL so it can be named in refused
        # findings; `_safe_to_fetch` is the authority that prevents the GET.
        # It still requires fixed-point decoding and rejects traversal/query
        # smuggling in the path itself.
        layers = _web.canonical_route_layers(parsed.path or "/", max_bytes=MAX_ROUTE_BYTES)
        if not layers:
            return None
        for layer in layers:
            if (not layer.startswith("/") or layer.startswith("//") or "\\" in layer
                    or any(ch in layer for ch in ("?", "#"))
                    or any(ord(ch) < 0x20 or ch.isspace() for ch in layer)
                    or any(part in (".", "..") for part in layer.split("/"))):
                return None
        for key, value in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True):
            if (_web.canonical_route_layers(key, plus=True, max_bytes=MAX_ROUTE_BYTES) is None
                    or _web.canonical_route_layers(value, plus=True, max_bytes=MAX_ROUTE_BYTES) is None):
                return None
        result = (parsed.path or "/") + (("?" + parsed.query) if parsed.query else "")
        return result if len(result.encode("utf-8", "replace")) <= MAX_ROUTE_BYTES else None
    except Exception:
        return None


def _contains_inner_url(path):
    """True when a site-relative route embeds another URL or URL scheme."""
    try:
        layers = _web.canonical_route_layers(str(path or ""), max_bytes=MAX_ROUTE_BYTES)
        if not layers:
            return True
        for decoded in layers:
            parts = urllib.parse.urlsplit(decoded)
            if ("//" in parts.path[1:] or re.search(
                    r"(?i)(?:^|[/=])[a-z][a-z0-9+.-]{0,31}:", parts.path)):
                return True
            for key, value in urllib.parse.parse_qsl(parts.query, keep_blank_values=True):
                if (not _web.safe_route_query_component(key, max_bytes=MAX_ROUTE_BYTES)
                        or not _web.safe_route_query_component(value, max_bytes=MAX_ROUTE_BYTES)):
                    return True
        return False
    except (TypeError, ValueError, AttributeError):
        return True


def _safe_to_fetch(path):
    """Whether an advertised document/asset path is inert enough to GET.

    Inventory may *report* destructive application routes, but it never drives
    one.  Apply the same rule to a query after bounded URL decoding, and refuse
    an inner URL value so a target-authored asset link cannot turn this passive
    reader into an SSRF trigger.
    """
    try:
        if _contains_inner_url(path):
            return False
        layers = _web.canonical_route_layers(str(path or ""), max_bytes=MAX_ROUTE_BYTES)
        if not layers:
            return False
        for decoded in layers:
            words = re.sub(r"[?&=+,;:]", "/", decoded)
            camel_words = re.sub(r"([a-z0-9])([A-Z])", r"\1/\2", words)
            if (DESTRUCTIVE_PATH.search(words) or DESTRUCTIVE_PATH.search(camel_words)
                    or _web.route_has_destructive_action(decoded)):
                return False
            for key, value in urllib.parse.parse_qsl(
                    urllib.parse.urlsplit(decoded).query, keep_blank_values=True):
                key_path, value_path = "/" + key + "/", "/" + value + "/"
                camel_key = re.sub(r"([a-z0-9])([A-Z])", r"\1/\2", key_path)
                camel_value = re.sub(r"([a-z0-9])([A-Z])", r"\1/\2", value_path)
                if (DESTRUCTIVE_PATH.search(key_path) or DESTRUCTIVE_PATH.search(value_path)
                        or DESTRUCTIVE_PATH.search(camel_key)
                        or DESTRUCTIVE_PATH.search(camel_value)):
                    return False
        return True
    except (TypeError, ValueError, AttributeError):
        return False


def _ws_path(base_url, raw):
    """A same-host WebSocket URL as a finding.  It is never connected to."""
    try:
        p = urllib.parse.urlsplit(str(raw or ""))
        if p.scheme.lower() not in ("ws", "wss") or not p.hostname or p.username or p.password:
            return None
        b = urllib.parse.urlsplit(base_url)
        want_scheme = "wss" if b.scheme.lower() == "https" else "ws"
        bp = b.port or (443 if b.scheme.lower() == "https" else 80)
        pp = p.port or (443 if p.scheme.lower() == "wss" else 80)
        if p.scheme.lower() != want_scheme or p.hostname.lower() != b.hostname.lower() or pp != bp:
            return None
        path = p.path or "/"
        return path + (("?" + p.query) if p.query else "")
    except (TypeError, ValueError):
        return None


def _body(page):
    if isinstance(page, dict) and _responses is not None \
            and hasattr(_responses, "response_text_views"):
        try:
            views = _responses.response_text_views(page)
            if views:
                return str(views[0]).encode("utf-8", "replace")[:MAX_DOCUMENT]
            # A declared encoded/container response that did not yield a
            # coherent text leaf is not raw source/spec evidence.
            return b""
        except Exception:
            return b""
    value = page.get("body") if isinstance(page, dict) else b""
    if value in (None, b"") and isinstance(page, dict):
        value = page.get("text") or ""
    if isinstance(value, str):
        value = value.encode("utf-8", "replace")
    if not isinstance(value, (bytes, bytearray)):
        value = str(value or "").encode("utf-8", "replace")
    return bytes(value[:MAX_DOCUMENT])


def _text(page):
    return _body(page).decode("utf-8", "replace")


def _headers(page):
    raw = (page.get("response_headers") or page.get("headers") or {}) if isinstance(page, dict) else {}
    return {str(k).lower(): str(v) for k, v in raw.items()}


def _status(page):
    try:
        return int(page.get("status"))
    except (AttributeError, TypeError, ValueError):
        return None


class _Getter:
    """The only wire path: scope-locked GET, redirects off, hard budget/deadline."""

    def __init__(self, base_url, ctx):
        self.base_url = base_url
        self.deadline = None
        try:
            if ctx.get("deadline") is not None:
                self.deadline = float(ctx["deadline"])
        except (TypeError, ValueError):
            pass
        try:
            self.max_requests = max(0, int(ctx.get("max_requests", DEFAULT_MAX_REQUESTS)))
        except (TypeError, ValueError):
            self.max_requests = DEFAULT_MAX_REQUESTS
        try:
            self.max_bytes = max(0, int(ctx.get("max_bytes", DEFAULT_MAX_BYTES)))
        except (TypeError, ValueError):
            self.max_bytes = DEFAULT_MAX_BYTES
        self.stop = ctx.get("stop")
        self.requests = 0
        self.bytes = 0
        self.stopped = None
        self.errors = []
        self.refused = []
        self.pages = {}
        self.page_sink = ctx.get("_page_sink") if isinstance(ctx.get("_page_sink"), dict) else None
        # paths the caller already sent as one parallel wave before calling.  Each is charged once
        # to this getter's request budget at the moment it is first asked for (where it used to be sent), so
        # the budget left for later documents is what it was; the charge is never reported as a request.
        try:
            self.prefetched = {str(p) for p in (ctx.get("prefetched") or ())}
        except TypeError:
            self.prefetched = set()
        self.charged = 0
        preloaded = ctx.get("preloaded") or {}
        if isinstance(preloaded, dict):
            for key, page in preloaded.items():
                path = str(key).split("\x00", 1)[0]
                if isinstance(page, dict) and path.startswith("/"):
                    self.pages[path] = page
        client = ctx.get("client")
        try:
            if client is not None:
                if _origin(getattr(client, "base", None)) == _origin(base_url):
                    self.client = client
                else:
                    self.client = None
                    self.stopped = "client_scope_mismatch"
            elif _web is not None:
                self.client = _web.WebClient(base_url, timeout=REQUEST_TIMEOUT)
            else:
                self.client = None
                self.stopped = "no_client"
        except Exception as exc:
            self.client = None
            self.stopped = "no_client:" + type(exc).__name__

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
        if self.requests + self.charged >= self.max_requests:
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

    def get(self, path, kind="document"):
        if path in self.pages:
            if path in self.prefetched:
                self.prefetched.discard(path)
                if self.may_send():
                    self.charged += 1
            return self.pages[path]
        clean = _safe_path(self.base_url, path)
        if clean is None or clean != path:
            self.refused.append(str(path)[:240])
            return None
        if not _safe_to_fetch(clean):
            self.refused.append(clean[:240])
            return None
        if not self.may_send():
            return None
        self.requests += 1
        left = self._left()
        old_timeout = getattr(self.client, "timeout", None)
        try:
            if hasattr(self.client, "timeout"):
                self.client.timeout = REQUEST_TIMEOUT if left is None else max(
                    0.01, min(REQUEST_TIMEOUT, left - DEADLINE_PAD)
                )
            page = self.client.request("GET", clean, allow_redirects=False)
        except Exception as exc:
            self.errors.append({"path": clean, "error": type(exc).__name__})
            page = None
        finally:
            if old_timeout is not None and hasattr(self.client, "timeout"):
                self.client.timeout = old_timeout
        if not isinstance(page, dict):
            self.pages[clean] = None
            return None
        raw = _body(page)
        self.bytes += len(raw)
        if self.bytes > self.max_bytes:
            self.stopped = self.stopped or "max_bytes"
            over = self.bytes - self.max_bytes
            if over >= len(raw):
                raw = b""
            else:
                raw = raw[:len(raw) - over]
            page = dict(page)
            page["body"] = raw
            page.pop("text", None)
        self.pages[clean] = page
        if self.page_sink is not None:
            # Private in-memory handoff to proof_hunt. It is deliberately not
            # part of result(): standalone inventory remains proof-blind and
            # JSON-safe, while the caller can still subtract every fetched
            # document/asset as baseline before driving a discovered route.
            self.page_sink[clean] = page
        return page


class _Inventory:
    def __init__(self, base_url):
        self.base_url = base_url
        self.routes = {}
        self.params = set()
        self.operations = []
        self.event_operations = []
        self.scripts = []
        self.source_maps = []
        self.sitemaps = []
        self.openapi_docs = []
        self.descriptor_docs = []
        self.descriptor_servers = []
        self.security_schemes = []
        self.websockets = []
        self.external_urls = []
        self.secret_leads = []
        self.findings = []

    def route(self, raw, source, *, methods=(), params=(), fields=()):
        path = _safe_path(self.base_url, raw)
        if path is None or _contains_inner_url(path):
            if isinstance(raw, str) and raw.startswith(("http://", "https://", "ws://", "wss://")):
                self.external_urls.append(raw[:500])
            return None
        key = path
        row = self.routes.setdefault(key, {"path": path, "sources": set(), "methods": set(), "params": set(),
                                           "fields": set(), "requestable": not bool(re.search(r"[<{][^>}]+[>}]", path))})
        row["sources"].add(str(source)[:160])
        row["methods"].update(str(x).upper() for x in methods if str(x).lower() in OAS32_HTTP_METHODS)
        row["params"].update(str(x)[:80] for x in params if _param_name(x))
        row["fields"].update(str(x)[:80] for x in fields if _param_name(x))
        try:
            row["params"].update(k for k, _v in urllib.parse.parse_qsl(path.partition("?")[2], keep_blank_values=True)
                                 if _param_name(k))
        except ValueError:
            pass
        self.params.update(row["params"])
        self.params.update(row["fields"])
        return path

    def finding(self, evidence, **extra):
        row = {"class": "endpoint_inventory", "confirmed": True, "evidence": evidence}
        for key, value in extra.items():
            if value not in (None, [], {}, ""):
                row[key] = value
        self.findings.append(row)

    def result(self, getter):
        rows = []
        for row in list(self.routes.values())[:MAX_ROUTES]:
            rows.append({"path": row["path"], "sources": sorted(row["sources"]),
                         "methods": sorted(row["methods"]), "params": sorted(row["params"]),
                         "fields": sorted(row["fields"]), "requestable": bool(row["requestable"])})
        return {
            "flag": None,
            "routes": rows,
            "route_paths": [r["path"] for r in rows],
            "params": sorted(self.params)[:MAX_PARAMS],
            "operations": (self.operations + self.event_operations)[:MAX_OPERATIONS],
            "event_operations": self.event_operations[:MAX_EVENT_OPERATIONS],
            "scripts": self.scripts[:MAX_SCRIPTS],
            "source_maps": self.source_maps[:MAX_SOURCE_MAPS],
            "sitemaps": self.sitemaps[:MAX_SITEMAPS],
            "openapi_docs": self.openapi_docs[:MAX_OPENAPI_DOCS],
            "descriptor_docs": self.descriptor_docs[:MAX_DESCRIPTOR_DOCS],
            "descriptor_servers": self.descriptor_servers[:32],
            "security_schemes": self.security_schemes[:32],
            "websockets": list(dict.fromkeys(self.websockets))[:32],
            "external_urls": list(dict.fromkeys(self.external_urls))[:32],
            "secret_leads": self.secret_leads[:MAX_SECRET_LEADS],
            "secret_leads_policy": SECRET_LEADS_POLICY,
            "findings": self.findings[:24],
            "requests": getter.requests,
            "bytes": getter.bytes,
            "stopped": getter.stopped,
            "errors": getter.errors[:12],
            "refused": list(dict.fromkeys(getter.refused))[:24],
        }


def _param_name(value):
    return isinstance(value, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,79}", value) is not None


def _pointer_target(doc, ref):
    """Resolve one bounded local RFC-6901/URI-fragment pointer; external refs are never fetched."""
    if not isinstance(ref, str) or not ref.startswith("#/") or len(ref) > 1_000:
        return None
    cur = doc
    try:
        parts = ref[2:].split("/")
        if len(parts) > 20:
            return None
        for raw in parts:
            part = urllib.parse.unquote(raw).replace("~1", "/").replace("~0", "~")
            if isinstance(cur, dict):
                cur = cur[part]
            elif isinstance(cur, list) and part.isdigit() and int(part) < len(cur):
                cur = cur[int(part)]
            else:
                return None
        return cur
    except (KeyError, TypeError, ValueError, IndexError):
        return None


def _oas31_schema_dialect(doc):
    marker = doc.get("openapi") if isinstance(doc, dict) else None
    # OAS 3.2 deliberately keeps the OAS 3.1 JSON Schema dialect.
    return isinstance(marker, str) and re.fullmatch(r"3\.(?:1|2)(?:\.\d+)?", marker.strip()) is not None


def _document_http_methods(doc):
    marker = doc.get("openapi") if isinstance(doc, dict) else None
    if isinstance(marker, str) and re.fullmatch(r"3\.2(?:\.\d+)?", marker.strip()):
        return OAS32_HTTP_METHODS
    return HTTP_METHODS


def _local_ref(doc, value, depth=0, seen=None, *, schema=False):
    """Resolve one bounded local ``$ref`` chain with dialect-correct siblings.

    Swagger 2.0 and OpenAPI 3.0 Reference Objects ignore sibling fields.  In
    OpenAPI 3.1 a Reference Object admits only its annotation siblings, while a
    Schema Object uses JSON Schema semantics and evaluates every sibling beside
    the referenced schema.  Represent the latter as ``allOf`` so a shallow
    dictionary update cannot erase properties from either side.
    """
    if not isinstance(value, dict) or depth > 8:
        return value if isinstance(value, dict) else {}
    ref = value.get("$ref")
    if not isinstance(ref, str):
        return value
    if not ref.startswith("#/"):
        return {}  # remote/file refs are findings at most; never fetched or trusted as schemas
    seen = set(seen or ())
    if ref in seen:
        return {}
    seen.add(ref)
    target = _pointer_target(doc, ref)
    if not isinstance(target, dict):
        return {}
    resolved = _local_ref(doc, target, depth + 1, seen, schema=schema)
    if not isinstance(resolved, dict):
        return {}
    siblings = {key: child for key, child in value.items() if key != "$ref"}
    if not siblings or not _oas31_schema_dialect(doc):
        return resolved
    if schema:
        return {"allOf": [resolved, siblings]}
    annotations = {key: child for key, child in siblings.items() if key in ("summary", "description")}
    return {**resolved, **annotations} if annotations else resolved


def _bounded_document(value):
    """Reject parser output with cycles, extreme depth/fanout or non-scalar mapping keys."""
    count = 0
    active = set()

    def visit(node, depth):
        nonlocal count
        count += 1
        if count > MAX_DOCUMENT_NODES or depth > 40:
            return False
        if isinstance(node, (dict, list)):
            ident = id(node)
            if ident in active:  # YAML recursive alias
                return False
            active.add(ident)
            try:
                if isinstance(node, dict):
                    if len(node) > MAX_DOCUMENT_NODES:
                        return False
                    for key, child in node.items():
                        if not isinstance(key, (str, int, float, bool)) or not visit(child, depth + 1):
                            return False
                else:
                    if len(node) > MAX_DOCUMENT_NODES:
                        return False
                    for child in node:
                        if not visit(child, depth + 1):
                            return False
            finally:
                active.discard(ident)
        return True

    return visit(value, 0)


def _yaml_load_unique(text):
    """Safely load one YAML tree after rejecting ambiguous mapping keys.

    PyYAML normally applies last-wins semantics to duplicate mapping members,
    and merge keys can make that choice less visible. API descriptions are
    contracts, so inspect the composed node graph first and reject exact,
    case/punctuation/camel collisions, merge keys, complex keys, cycles, and
    over-limit graphs before SafeLoader constructs ordinary data.
    """
    if _yaml is None or _security_json is None:
        raise ValueError("YAML policy parser unavailable")
    root = _yaml.compose(text, Loader=_yaml.SafeLoader)
    if root is None:
        raise ValueError("empty YAML")
    count = [0]
    active = set()

    def inspect(node, depth):
        count[0] += 1
        if count[0] > MAX_DOCUMENT_NODES or depth > 40:
            raise ValueError("YAML structure limit")
        # PyYAML's SafeLoader ultimately calls ``int``/``float`` on implicit
        # numeric scalars.  On Python 3.9 a very long decimal integer has no
        # interpreter digit limit and can consume seconds of CPU.  Reject it
        # while the composed node still contains the cheap raw lexeme.  This
        # covers values as well as response-status mapping keys.
        if (isinstance(node, _yaml.nodes.ScalarNode)
                and node.tag in ("tag:yaml.org,2002:int", "tag:yaml.org,2002:float")
                and len(str(node.value)) > _security_json.DEFAULT_MAX_NUMBER_CHARS):
            raise ValueError("YAML number character limit")
        ident = id(node)
        if ident in active:
            raise ValueError("recursive YAML alias")
        if isinstance(node, (_yaml.nodes.MappingNode, _yaml.nodes.SequenceNode)):
            active.add(ident)
            try:
                if isinstance(node, _yaml.nodes.MappingNode):
                    seen = set()
                    for key_node, value_node in node.value:
                        if not isinstance(key_node, _yaml.nodes.ScalarNode):
                            raise ValueError("complex YAML mapping key")
                        # SafeLoader turns ``true`` into bool and ``1`` into
                        # int; those compare/hash equal in Python and one can
                        # silently overwrite the other after our lexical
                        # duplicate check.  API object keys are strings.  Keep
                        # the widespread unquoted decimal response-status
                        # spelling as a narrow compatibility exception, but
                        # reject every other implicit scalar-key type.
                        if key_node.tag == "tag:yaml.org,2002:str":
                            key = str(key_node.value)
                        elif (key_node.tag == "tag:yaml.org,2002:int"
                              and re.fullmatch(r"0|[1-9][0-9]*", str(key_node.value))):
                            key = str(_security_json.parse_int_lexeme(str(key_node.value)))
                        else:
                            raise ValueError("non-string YAML mapping key")
                        if key == "<<":
                            raise ValueError("YAML merge key")
                        canonical = _security_json.canonical_key(key)
                        if canonical in seen:
                            raise ValueError("duplicate or colliding YAML mapping key")
                        seen.add(canonical)
                        inspect(value_node, depth + 1)
                else:
                    for child in node.value:
                        inspect(child, depth + 1)
            finally:
                active.discard(ident)

    inspect(root, 0)
    return _yaml.safe_load(text)


def _parse_api_document_text(path, page, text):
    """Parse one coherent candidate API document."""
    text = str(text or "")[:MAX_DOCUMENT].lstrip()
    if not text:
        return None
    encoding = "json"
    try:
        if _security_json is None:
            return None
        doc = _security_json.loads(text, max_chars=MAX_DOCUMENT,
                                   max_members=MAX_DOCUMENT_NODES,
                                   max_nodes=MAX_DOCUMENT_NODES, max_depth=40)
    except Exception:
        # A JSON-looking document that is malformed, duplicate-keyed or
        # canonically ambiguous must not be reinterpreted by YAML last-wins
        # rules as an API contract.
        if text[:1] in ("{", "["):
            return None
        encoding = "yaml"
        # Do not hand arbitrary HTML/text to a YAML parser. SafeLoader forbids object construction;
        # the alias and tree bounds additionally reject expansion/cycle tricks.
        ctype = _headers(page).get("content-type", "").lower()
        looks_yaml = (str(path).lower().split("?", 1)[0].endswith((".yaml", ".yml"))
                      or "yaml" in ctype
                      or re.search(r"(?m)^(?:openapi|swagger)\s*:\s*['\"]?[23]", text[:4096]))
        aliases = len(re.findall(r"(?m)(?<![A-Za-z0-9_])[*&][A-Za-z_][A-Za-z0-9_-]*", text))
        if not looks_yaml or _yaml is None or aliases > MAX_YAML_ALIASES:
            return None
        try:
            doc = _yaml_load_unique(text)
        except Exception:
            return None
    if not isinstance(doc, dict) or not _bounded_document(doc):
        return None
    marker = doc.get("openapi")
    if isinstance(marker, str) and re.fullmatch(r"3\.(?:0|1|2)(?:\.\d+)?", marker.strip()):
        version = "openapi-" + marker.strip()
    else:
        marker = doc.get("swagger")
        if str(marker).strip() != "2.0":
            return None
        version = "swagger-2.0"
    if version.startswith(("openapi-3.1", "openapi-3.2")):
        # These feature sets allow a webhook- or components-only entry document.
        # Every declared structural map must still have the right JSON type.
        structural = [(name, doc.get(name)) for name in ("paths", "webhooks", "components") if name in doc]
        if not structural or any(not isinstance(value, dict) for _name, value in structural):
            return None
    elif not isinstance(doc.get("paths"), dict):
        return None
    return doc, version, encoding


def _load_api_document(path, page):
    """Return one unambiguous supported JSON/YAML spec, else ``None``.

    A response may carry a diagnostic text sibling and a later spec.  Inspect
    every coherent member independently, but never choose between two specs or
    combine their fields.  Although discovery is recon, a parsed API operation
    can later authorize contract-driven requests.  Therefore any carrier,
    framing, archive or MIME ambiguity poisons the whole authority response;
    the parser below separately applies its own 20k-node structural cap.
    """
    if _status(page) != 200:
        return None
    if _responses is not None and hasattr(_responses, "response_text_views"):
        try:
            views = _responses.response_text_views(page, strict=True)
            if not views:
                # A wide but otherwise coherent JSON document can exhaust only
                # the carrier decoder's optional scalar-leaf export after its
                # complete json-document leaf has already been retained.  Our
                # parser below has independent byte/node/depth bounds, so make
                # exactly that exception.  Any other issue (MIME/archive/header
                # ambiguity, malformed encoding, truncation, charset loss,
                # work/ratio cap, etc.) still poisons the authority response.
                integrity = {}
                relaxed = _responses.response_text_views(
                    page, strict=False, _integrity=integrity)
                issues = set(integrity.get("issue_codes", ()))
                if (relaxed and not integrity.get("transport_incomplete") and issues
                        and issues <= {"leaf_count_limit", "node_count_limit"}):
                    views = relaxed
        except Exception:
            return None
    else:
        raw = _body(page)
        views = [raw.decode("utf-8", "replace")] if raw else []
    loaded = []
    for view in list(views or [])[:256]:
        candidate = _parse_api_document_text(path, page, view)
        if candidate is not None and candidate not in loaded:
            loaded.append(candidate)
            if len(loaded) > 1:
                return None
    return loaded[0] if len(loaded) == 1 else None


def _add_scalar(out, value):
    if (isinstance(value, (str, int, float, bool)) and len(str(value)) <= 160
            and value not in out):
        out.append(value)


def _schema_values(doc, schema, depth=0, refs=None, objects=None):
    if not isinstance(schema, dict) or depth > MAX_SCHEMA_DEPTH:
        return []
    refs, objects = set(refs or ()), set(objects or ())
    ref = schema.get("$ref")
    if isinstance(ref, str):
        if ref in refs:
            return []
        refs.add(ref)
    schema = _local_ref(doc, schema, schema=True)
    if not isinstance(schema, dict) or id(schema) in objects:
        return []
    objects.add(id(schema))
    out = []
    for value in schema.get("enum") if isinstance(schema.get("enum"), list) else []:
        _add_scalar(out, value)
    for key in ("example", "default", "const"):
        if key in schema:
            _add_scalar(out, schema[key])
    for value in schema.get("examples") if isinstance(schema.get("examples"), list) else []:
        _add_scalar(out, value)
    children = []
    for key in ("allOf", "anyOf", "oneOf", "prefixItems"):
        if isinstance(schema.get(key), list):
            children.extend(schema[key][:16])
    if isinstance(schema.get("items"), dict):
        children.append(schema["items"])
    for child in children:
        for value in _schema_values(doc, child, depth + 1, refs, objects):
            _add_scalar(out, value)
    return out[:MAX_VALUES]


def _schema_preferred_values(doc, schema, depth=0, refs=None, objects=None):
    """Explicit scalar examples/defaults/consts, before broad enum sweeps."""
    if not isinstance(schema, dict) or depth > MAX_SCHEMA_DEPTH:
        return []
    refs, objects = set(refs or ()), set(objects or ())
    ref = schema.get("$ref")
    if isinstance(ref, str):
        if ref in refs:
            return []
        refs.add(ref)
    schema = _local_ref(doc, schema, schema=True)
    if not isinstance(schema, dict) or id(schema) in objects:
        return []
    objects.add(id(schema))
    out = []
    for key in ("example", "default", "const"):
        if key in schema:
            _add_scalar(out, schema[key])
    for value in schema.get("examples") if isinstance(schema.get("examples"), list) else []:
        _add_scalar(out, value)
    children = []
    for key in ("allOf", "anyOf", "oneOf", "prefixItems"):
        if isinstance(schema.get(key), list):
            children.extend(schema[key][:16])
    if isinstance(schema.get("items"), dict):
        children.append(schema["items"])
    for child in children:
        for value in _schema_preferred_values(doc, child, depth + 1, refs, objects):
            _add_scalar(out, value)
    return out[:MAX_VALUES]


def _schema_wire_type(doc, schema, depth=0, objects=None):
    """Best bounded wire type for a parameter schema.

    Keeping ``array`` and ``object`` distinct lets the cold dispatcher refuse
    serialization it cannot reproduce instead of stringifying a container.
    """
    if not isinstance(schema, dict) or depth > MAX_SCHEMA_DEPTH:
        return None
    objects = set(objects or ())
    schema = _local_ref(doc, schema, schema=True)
    if not isinstance(schema, dict) or id(schema) in objects:
        return None
    objects.add(id(schema))
    raw_type = schema.get("type")
    if isinstance(raw_type, str):
        return raw_type[:40]
    if isinstance(raw_type, list):
        values = [str(value)[:40] for value in raw_type if isinstance(value, str) and value != "null"]
        if len(set(values)) == 1:
            return values[0]
        if "array" in values:
            return "array"
        if "object" in values:
            return "object"
    if isinstance(schema.get("items"), dict) or isinstance(schema.get("prefixItems"), list):
        return "array"
    if isinstance(schema.get("properties"), dict) or "additionalProperties" in schema:
        return "object"
    child_types = []
    for key in ("allOf", "anyOf", "oneOf"):
        for child in schema.get(key) if isinstance(schema.get(key), list) else []:
            value = _schema_wire_type(doc, child, depth + 1, objects)
            if value and value not in child_types:
                child_types.append(value)
    if "array" in child_types:
        return "array"
    if "object" in child_types:
        return "object"
    return child_types[0] if len(child_types) == 1 else None


def _merge_field(out, item):
    old = next((row for row in out if row.get("name") == item.get("name")), None)
    if old is None:
        out.append(item)
        return
    old["required"] = bool(old.get("required") or item.get("required"))
    for value in item.get("values") or []:
        if value not in old["values"] and len(old["values"]) < MAX_VALUES:
            old["values"].append(value)


def _schema_fields(doc, schema, depth=0, refs=None, objects=None):
    """Top-level wire fields, through refs/combinators and array item schemas, bounded and cycle-safe."""
    if not isinstance(schema, dict) or depth > MAX_SCHEMA_DEPTH:
        return []
    refs, objects = set(refs or ()), set(objects or ())
    ref = schema.get("$ref")
    if isinstance(ref, str):
        if ref in refs:
            return []
        refs.add(ref)
    schema = _local_ref(doc, schema, schema=True)
    if not isinstance(schema, dict) or id(schema) in objects:
        return []
    objects.add(id(schema))
    out = []
    children = []
    for key in ("allOf", "anyOf", "oneOf", "prefixItems"):
        if isinstance(schema.get(key), list):
            children.extend(schema[key][:16])
    if isinstance(schema.get("items"), dict):
        children.append(schema["items"])
    for child in children:
        for row in _schema_fields(doc, child, depth + 1, refs, objects):
            _merge_field(out, row)
    props = schema.get("properties")
    if isinstance(props, dict):
        required = {str(value) for value in (schema.get("required") or [])}
        for name, child in list(props.items())[:128]:
            if not _param_name(name):
                continue
            _merge_field(out, {"name": name, "required": name in required,
                               "values": _schema_values(doc, child, depth + 1, refs, objects)})
    return out[:128]


def _operation_params(doc, path_item, operation, *, with_contract=False):
    """Path/query/header/cookie parameters; operation declarations override path-level ones.

    ``with_contract`` also returns whether every potentially required
    parameter was represented.  Unknown/external refs and OpenAPI 3.2's
    whole-query-string form fail closed rather than silently producing a
    dispatchable-looking partial contract.
    """
    merged = {}
    complete = True
    for owner in (path_item, operation):
        raw_params = (owner.get("parameters") if isinstance(owner, dict)
                      and isinstance(owner.get("parameters"), list) else [])
        if len(raw_params) > 256:
            complete = False
        for raw in raw_params[:256]:
            row = _local_ref(doc, raw)
            location = str(row.get("in") or "").lower() if isinstance(row, dict) else ""
            unresolved = isinstance(raw, dict) and isinstance(raw.get("$ref"), str) and not row
            if unresolved:
                complete = False
                continue
            if not isinstance(row, dict):
                continue
            required = bool(row.get("required") or location == "path")
            if location == "querystring":
                # OAS 3.2 serialized/data query-string parameters are a whole
                # query representation, not a scalar key=value pair.
                complete = False
                continue
            if location not in PARAM_LOCATIONS or not _param_name(row.get("name")):
                if required:
                    complete = False
                continue
            schema = row.get("schema") if isinstance(row.get("schema"), dict) else row
            values = _schema_values(doc, schema)
            preferred = []
            if "example" in row:
                _add_scalar(preferred, row.get("example"))
            row_examples = row.get("examples")
            if isinstance(row_examples, dict):
                for raw_example in list(row_examples.values())[:16]:
                    example = _local_ref(doc, raw_example) if isinstance(raw_example, dict) else raw_example
                    if isinstance(example, dict) and "value" in example:
                        example = example.get("value")
                    _add_scalar(preferred, example)
            for value in _schema_preferred_values(doc, schema):
                _add_scalar(preferred, value)
            schema_types = []
            schema_type = _schema_wire_type(doc, schema)
            if schema_type:
                schema_types.append(schema_type)
            content_types = []
            content = row.get("content")
            if isinstance(content, dict):
                for ctype, media in list(content.items())[:4]:
                    if not isinstance(ctype, str) or not isinstance(media, dict):
                        continue
                    content_types.append(ctype[:100])
                    media_schema = media.get("schema") or {}
                    for value in _schema_values(doc, media_schema):
                        _add_scalar(values, value)
                    if "example" in media:
                        _add_scalar(values, media.get("example"))
                        _add_scalar(preferred, media.get("example"))
                    examples = media.get("examples")
                    if isinstance(examples, dict):
                        for raw_example in list(examples.values())[:16]:
                            example = _local_ref(doc, raw_example) if isinstance(raw_example, dict) else raw_example
                            if isinstance(example, dict) and "value" in example:
                                example = example.get("value")
                            _add_scalar(values, example)
                            _add_scalar(preferred, example)
                    for value in _schema_preferred_values(doc, media_schema):
                        _add_scalar(preferred, value)
                    media_type = _schema_wire_type(doc, media_schema)
                    if media_type and media_type not in schema_types:
                        schema_types.append(media_type)
            if "example" in row:
                _add_scalar(values, row.get("example"))
            examples = row.get("examples")
            if isinstance(examples, dict):
                for raw_example in list(examples.values())[:16]:
                    example = _local_ref(doc, raw_example) if isinstance(raw_example, dict) else raw_example
                    if isinstance(example, dict) and "value" in example:
                        example = example.get("value")
                    _add_scalar(values, example)
            item = {"name": row["name"], "in": location,
                    "required": required,
                    "values": values[:MAX_VALUES]}
            if preferred:
                item["preferred_values"] = preferred[:MAX_VALUES]
            if "array" in schema_types:
                item["schema_type"] = "array"
            elif "object" in schema_types:
                item["schema_type"] = "object"
            elif len(schema_types) == 1:
                item["schema_type"] = schema_types[0]
            elif schema_types:
                item["schema_type"] = "mixed"
            if content_types:
                item["content_types"] = content_types[:4]
            style = row.get("style") or row.get("collectionFormat")
            if isinstance(style, str):
                item["style"] = style[:40]
            if isinstance(row.get("explode"), bool):
                item["explode"] = row["explode"]
            key_name = row["name"].casefold() if location == "header" else row["name"]
            key = (location, key_name)
            if key not in merged and len(merged) >= 128:
                if required:
                    complete = False
                continue
            merged[key] = item
    result = list(merged.values())[:128]
    return (result, complete) if with_contract else result


def _has_required_body(doc, path_item, operation):
    """Whether an operation declares a required request entity."""
    raw_body = operation.get("requestBody") if isinstance(operation, dict) else None
    if isinstance(raw_body, dict):
        body = _local_ref(doc, raw_body)
        if (isinstance(raw_body.get("$ref"), str) and not body
                or isinstance(body, dict) and bool(body.get("required"))):
            return True
    for owner in (path_item, operation):
        raw_params = (owner.get("parameters") if isinstance(owner, dict)
                      and isinstance(owner.get("parameters"), list) else [])
        for raw in raw_params[:256]:
            row = _local_ref(doc, raw)
            if isinstance(row, dict) and row.get("in") == "body" and bool(row.get("required")):
                return True
    return False


def _media_examples(spec):
    out = []
    if not isinstance(spec, dict):
        return out
    values = [spec.get("example")]
    examples = spec.get("examples")
    if isinstance(examples, dict):
        for item in list(examples.values())[:16]:
            item = item.get("value") if isinstance(item, dict) and "value" in item else item
            values.append(item)
    for value in values:
        if isinstance(value, dict):
            out.append(value)
    return out[:16]


def _merge_example_values(fields, examples):
    by_name = {row["name"]: row for row in fields}
    for example in examples:
        for name, value in list(example.items())[:128]:
            if name in by_name:
                _add_scalar(by_name[name]["values"], value)


def _request_fields(doc, path_item, operation):
    out, content_types = [], []
    if not isinstance(operation, dict):
        return out, content_types
    body = _local_ref(doc, operation.get("requestBody") or {})
    content = body.get("content") if isinstance(body, dict) else None
    if isinstance(content, dict):
        for ctype, spec in list(content.items())[:12]:
            if not isinstance(ctype, str) or len(ctype) > 100:
                continue
            content_types.append(ctype)
            schema = _local_ref(doc, spec.get("schema") if isinstance(spec, dict) else {}, schema=True)
            fields = _schema_fields(doc, schema)
            _merge_example_values(fields, _media_examples(spec))
            for field in fields:
                _merge_field(out, field)
    # Swagger 2 body/formData shapes may live at path or operation level.
    for owner in (path_item, operation):
        for raw in owner.get("parameters") if isinstance(owner, dict) and isinstance(owner.get("parameters"), list) else []:
            row = _local_ref(doc, raw)
            if not isinstance(row, dict):
                continue
            if row.get("in") == "body":
                for field in _schema_fields(doc, row.get("schema") or {}):
                    _merge_field(out, field)
            elif row.get("in") == "formData" and _param_name(row.get("name")):
                _merge_field(out, {"name": row["name"], "required": bool(row.get("required")),
                                   "values": _schema_values(doc, row)})
    consumes_declared = False
    consumes = None
    for owner in (operation, path_item, doc):
        if isinstance(owner, dict) and "consumes" in owner:
            consumes, consumes_declared = owner.get("consumes"), True
            break
    if isinstance(consumes, list):
        for ctype in consumes[:12]:
            if isinstance(ctype, str) and len(ctype) <= 100 and ctype not in content_types:
                content_types.append(ctype)
    if any(row.get("in") == "formData" for owner in (path_item, operation) if isinstance(owner, dict)
           for row in (_local_ref(doc, x) for x in (owner.get("parameters") or [])) if isinstance(row, dict)) \
           and not content_types and not consumes_declared:
        content_types.append("application/x-www-form-urlencoded")
    return out[:128], content_types[:12]


def _response_fields(doc, path_item, operation):
    fields, content_types = [], []
    responses = operation.get("responses") if isinstance(operation, dict) else None
    if not isinstance(responses, dict):
        return fields, content_types
    # Swagger 2 response media types live on `produces` rather than each
    # Response Object. Operation wins; tolerate path-level metadata before the
    # document default for generator compatibility.
    produces = None
    for owner in (operation, path_item, doc):
        if isinstance(owner, dict) and "produces" in owner:
            produces = owner.get("produces")
            break
    if isinstance(produces, list):
        for ctype in produces[:12]:
            if isinstance(ctype, str) and len(ctype) <= 100 and ctype not in content_types:
                content_types.append(ctype)
    ranked = sorted(responses.items(), key=lambda item: (0 if re.match(r"^2", str(item[0])) else 1,
                                                         str(item[0])))[:12]
    for status, raw in ranked:
        if not (re.match(r"^2", str(status)) or str(status).lower() == "default"):
            continue
        response = _local_ref(doc, raw)
        if not isinstance(response, dict):
            continue
        content = response.get("content")
        if isinstance(content, dict):
            for ctype, spec in list(content.items())[:8]:
                if isinstance(ctype, str) and ctype not in content_types:
                    content_types.append(ctype[:100])
                for field in _schema_fields(doc, spec.get("schema") if isinstance(spec, dict) else {}):
                    _merge_field(fields, field)
        for field in _schema_fields(doc, response.get("schema") or {}):  # Swagger 2
            _merge_field(fields, field)
    return fields[:128], content_types[:12]


def _security_requirements(doc, operation):
    value = operation.get("security") if isinstance(operation, dict) and "security" in operation else doc.get("security")
    out = []
    if isinstance(value, list):
        for requirement in value[:16]:
            if isinstance(requirement, dict):
                for name in requirement:
                    if _param_name(name) and name not in out:
                        out.append(name)
    return out[:32]


def _security_schemes(doc):
    sources = []
    components = doc.get("components")
    if isinstance(components, dict) and isinstance(components.get("securitySchemes"), dict):
        sources.append(components["securitySchemes"])
    if isinstance(doc.get("securityDefinitions"), dict):
        sources.append(doc["securityDefinitions"])
    out = []
    for source in sources:
        for name, raw in list(source.items())[:64]:
            row = _local_ref(doc, raw)
            if not _param_name(name) or not isinstance(row, dict):
                continue
            item = {"name": name, "type": str(row.get("type") or "")[:40]}
            for src, dst in (("scheme", "scheme"), ("bearerFormat", "bearer_format"),
                             ("in", "in"), ("name", "parameter"),
                             ("openIdConnectUrl", "openid_connect_url"),
                             ("authorizationUrl", "authorization_url"), ("tokenUrl", "token_url")):
                if isinstance(row.get(src), str):
                    item[dst] = row[src][:500]
            flows = row.get("flows")
            if isinstance(flows, dict):
                item["flows"] = sorted(str(key)[:40] for key in list(flows)[:16])
            out.append(item)
    return out[:32]


def _expand_server(raw, variables):
    if not isinstance(raw, str) or len(raw) > 500:
        return None
    values = variables if isinstance(variables, dict) else {}

    def replace(match):
        item = values.get(match.group(1))
        if not isinstance(item, dict):
            raise ValueError("missing server variable")
        value = item.get("default")
        if not isinstance(value, (str, int, float)) or len(str(value)) > 100:
            raise ValueError("unsafe server variable")
        return urllib.parse.quote(str(value), safe="-._~")

    try:
        return re.sub(r"\{([A-Za-z_][A-Za-z0-9_.-]{0,79})\}", replace, raw)
    except (ValueError, TypeError):
        return None


def _server_prefix(inv, doc, path_item, operation):
    for owner in (operation, path_item, doc):
        servers = owner.get("servers") if isinstance(owner, dict) else None
        if not isinstance(servers, list):
            continue
        for server in servers[:8]:
            if not isinstance(server, dict):
                continue
            expanded = _expand_server(server.get("url"), server.get("variables"))
            path = _safe_path(inv.base_url, expanded) if expanded else None
            if path is not None and not urllib.parse.urlsplit(path).query:
                return urllib.parse.urlsplit(path).path.rstrip("/")
            if isinstance(expanded, str) and expanded.startswith(("http://", "https://")):
                inv.external_urls.append(expanded[:500])
        return None  # an explicit but unusable server list must not become a same-origin route
    host = doc.get("host")
    if isinstance(host, str) and host.strip():  # Swagger 2 host + schemes + basePath
        target_scheme = urllib.parse.urlsplit(inv.base_url).scheme.lower()
        schemes = [str(value).lower() for value in (doc.get("schemes") or [])
                   if str(value).lower() in ("http", "https")]
        scheme = target_scheme if target_scheme in schemes else (schemes[0] if schemes else target_scheme)
        base_path = doc.get("basePath") if isinstance(doc.get("basePath"), str) else "/"
        absolute = f"{scheme}://{host.strip()}{base_path}"
        path = _safe_path(inv.base_url, absolute)
        if path is None:
            inv.external_urls.append(absolute[:500])
            return None
        return urllib.parse.urlsplit(path).path.rstrip("/")
    base_path = doc.get("basePath")
    if isinstance(base_path, str):
        path = _safe_path(inv.base_url, base_path)
        if path is not None and not urllib.parse.urlsplit(path).query:
            return urllib.parse.urlsplit(path).path.rstrip("/")
    return ""


def _join_route(inv, prefix, raw_path):
    if prefix is None or not isinstance(raw_path, str) or not raw_path.startswith("/"):
        return None
    combined = (str(prefix or "").rstrip("/") + "/" + raw_path.lstrip("/")) or "/"
    return _safe_path(inv.base_url, combined)


def _event_label(value, limit=500):
    """Bounded printable callback/webhook metadata, never a request target."""
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value or len(value.encode("utf-8", "replace")) > limit \
            or any(ord(char) < 0x20 for char in value):
        return None
    return value


def _event_target(inv, value):
    """Return a same-origin literal target hint; dynamic/off-host values remain metadata only."""
    raw = _event_label(value)
    if raw is None or raw.startswith(("$", "{")):
        return None
    if not raw.startswith(("/", "http://", "https://")):
        return None
    path = _safe_path(inv.base_url, raw)
    if path is not None and not _contains_inner_url(path):
        return path
    if raw.startswith(("http://", "https://", "ws://", "wss://")):
        inv.external_urls.append(raw[:500])
    return None


def _event_operation(inv, doc, version, *, surface, name, expression, parent_path,
                     path_item, method, operation):
    """Normalize one callback/webhook Operation Object without adding an inv.route entry."""
    if len(inv.event_operations) >= MAX_EVENT_OPERATIONS:
        return
    path_item = _local_ref(doc, path_item)
    operation = _local_ref(doc, operation)
    label = _event_label(name, 160)
    expr = _event_label(expression)
    if not isinstance(path_item, dict) or not isinstance(operation, dict) or label is None or expr is None:
        return
    params = _operation_params(doc, path_item, operation)
    fields, content_types = _request_fields(doc, path_item, operation)
    response_fields, response_content_types = _response_fields(doc, path_item, operation)
    target = _event_target(inv, expr)
    row = {"path": target or "-", "method": method.upper(), "params": params,
           "fields": fields, "content_types": content_types,
           "response_fields": response_fields,
           "response_content_types": response_content_types,
           "security": _security_requirements(doc, operation),
           "operation_id": str(operation.get("operationId") or "")[:160],
           "spec_version": version, "surface": surface, "name": label,
           "expression": expr, "target": target, "requestable": False}
    if parent_path:
        row["parent_path"] = str(parent_path)[:MAX_ROUTE_BYTES]
    inv.event_operations.append(row)
    inv.params.update(item["name"] for item in params if _param_name(item.get("name")))
    inv.params.update(item["name"] for item in fields if _param_name(item.get("name")))


def _parse_callbacks(inv, doc, version, parent_path, operation):
    callbacks = operation.get("callbacks") if isinstance(operation, dict) else None
    if not isinstance(callbacks, dict):
        return
    for callback_name, raw_callback in list(callbacks.items())[:32]:
        callback = _local_ref(doc, raw_callback)
        if not isinstance(callback, dict):
            continue
        for expression, raw_item in list(callback.items())[:16]:
            item = _local_ref(doc, raw_item)
            if not isinstance(item, dict):
                continue
            for method in _document_http_methods(doc):
                if method in item:
                    _event_operation(inv, doc, version, surface="callback", name=callback_name,
                                     expression=expression, parent_path=parent_path,
                                     path_item=item, method=method, operation=item.get(method) or {})


def _parse_webhooks(inv, doc, version):
    webhooks = doc.get("webhooks") if isinstance(doc, dict) else None
    if not isinstance(webhooks, dict):
        return
    for webhook_name, raw_item in list(webhooks.items())[:64]:
        item = _local_ref(doc, raw_item)
        if not isinstance(item, dict):
            continue
        for method in _document_http_methods(doc):
            if method in item:
                _event_operation(inv, doc, version, surface="webhook", name=webhook_name,
                                 expression=webhook_name, parent_path=None,
                                 path_item=item, method=method, operation=item.get(method) or {})


def _parse_openapi(inv, path, page):
    loaded = _load_api_document(path, page)
    if loaded is None:
        return False
    doc, version, encoding = loaded
    paths = doc.get("paths") or {}
    before = len(inv.operations)
    for scheme in _security_schemes(doc):
        if scheme not in inv.security_schemes:
            inv.security_schemes.append(scheme)
    for raw_path, raw_item in list(paths.items())[:MAX_ROUTES]:
        item = _local_ref(doc, raw_item)
        if not isinstance(item, dict):
            continue
        any_method = False
        for method in _document_http_methods(doc):
            if method not in item:
                continue
            operation = _local_ref(doc, item.get(method) or {})
            if not isinstance(operation, dict):
                continue
            route = _join_route(inv, _server_prefix(inv, doc, item, operation), raw_path)
            if route is None:
                continue
            params, contract_complete = _operation_params(doc, item, operation, with_contract=True)
            has_required_body = _has_required_body(doc, item, operation)
            if has_required_body:
                contract_complete = False
            fields, content_types = _request_fields(doc, item, operation)
            response_fields, response_content_types = _response_fields(doc, item, operation)
            pnames = [p["name"] for p in params]
            fnames = [f["name"] for f in fields]
            # The route guard is authoritative for both inventory views.  Do
            # not leave a normalized operation behind when an embedded URL,
            # traversal or authority confusion caused the route itself to be
            # rejected: proof_hunt consumes operations as well as route rows.
            if inv.route(route, "openapi:" + path, methods=[method],
                         params=pnames, fields=fnames) is None:
                continue
            any_method = True
            inv.operations.append({"path": route, "method": method.upper(), "params": params,
                                   "fields": fields, "content_types": content_types,
                                   "response_fields": response_fields,
                                   "response_content_types": response_content_types,
                                   "security": _security_requirements(doc, operation),
                                   "operation_id": str(operation.get("operationId") or "")[:160],
                                   "spec_version": version,
                                   "contract_complete": bool(contract_complete),
                                   "has_required_body": bool(has_required_body)})
            _parse_callbacks(inv, doc, version, route, operation)
            if len(inv.operations) >= MAX_OPERATIONS:
                break
        if not any_method:
            route = _join_route(inv, _server_prefix(inv, doc, item, {}), raw_path)
            if route:
                inv.route(route, "openapi:" + path)
        if len(inv.operations) >= MAX_OPERATIONS:
            break
    if version.startswith(("openapi-3.1", "openapi-3.2")):
        _parse_webhooks(inv, doc, version)
    if path not in inv.openapi_docs:
        inv.openapi_docs.append(path)
    inv.finding("openapi_paths", path=path, version=version, encoding=encoding,
                operations=len(inv.operations) - before, event_operations=len(inv.event_operations))
    return True


def _parse_sitemap(inv, path, page):
    if _status(page) != 200:
        return False
    text = _text(page)
    found = 0
    for match in SITEMAP_LOC.finditer(text[:MAX_DOCUMENT]):
        raw = re.sub(r"\s+", "", html.unescape(match.group(1)))
        if inv.route(raw, "sitemap:" + path) is not None:
            found += 1
        elif raw.startswith(("http://", "https://")):
            inv.external_urls.append(raw[:500])
        if found >= MAX_ROUTES:
            break
    if not found and "<urlset" not in text.lower() and "<sitemapindex" not in text.lower():
        return False
    inv.sitemaps.append(path)
    inv.finding("sitemap_routes", path=path, routes=found)
    return True


def _html_links(base_url, at, text):
    scripts, sitemaps, openapi = [], [], []
    for match in SCRIPT_TAG.finditer(text[:MAX_DOCUMENT]):
        attrs = _attrs(match.group(1))
        path = _safe_path(base_url, attrs.get("src"), at)
        if path and path not in scripts:
            scripts.append(path)
    for match in LINK_TAG.finditer(text[:MAX_DOCUMENT]):
        attrs = _attrs(match.group(1))
        rel = set(re.split(r"\s+", attrs.get("rel", "").lower()))
        path = _safe_path(base_url, attrs.get("href"), at)
        if not path:
            continue
        low = path.lower().split("?", 1)[0]
        if "sitemap" in rel or "sitemap" in low:
            if path not in sitemaps:
                sitemaps.append(path)
        if re.search(r"openapi|swagger|api-docs", low) and path not in openapi:
            openapi.append(path)
    return scripts, sitemaps, openapi


def _inline_source_map(value):
    prefix = "data:application/json;base64,"
    if not isinstance(value, str) or not value.startswith(prefix):
        return None
    encoded = value[len(prefix):]
    if len(encoded) > MAX_DOCUMENT * 2:
        return None
    try:
        raw = base64.b64decode(encoded, validate=True)
        return raw[:MAX_DOCUMENT]
    except Exception:
        return None


def _bounded_lead_text(value, limit, *, multiline=False):
    if not isinstance(value, str) or not value:
        return None, False
    allowed = "\t\r\n" if multiline else ""
    if any(ord(char) < 0x20 and char not in allowed for char in value):
        return None, False
    raw = value.encode("utf-8", "replace")
    if len(raw) <= limit:
        return value, False
    return raw[:limit].decode("utf-8", "ignore"), True


def _merge_secret_leads(inv, via, result):
    """Copy scanner secret *leads* into bounded metadata, never an answer path."""
    raw_leads = result.get("secrets") if isinstance(result, dict) else None
    if not isinstance(raw_leads, list):
        return
    via_text, _ = _bounded_lead_text(str(via or "asset"), 500)
    for raw in raw_leads[:MAX_SECRET_LEADS * 4]:
        if len(inv.secret_leads) >= MAX_SECRET_LEADS:
            break
        if not isinstance(raw, dict):
            continue
        kind, _ = _bounded_lead_text(raw.get("kind"), 80)
        value, truncated = _bounded_lead_text(raw.get("value"), MAX_SECRET_VALUE_BYTES, multiline=True)
        source, _ = _bounded_lead_text(raw.get("source"), 500)
        if kind is None or value is None or source is None or not re.fullmatch(r"[a-z][a-z0-9_.-]{0,79}", kind):
            continue
        key = (kind, value, source)
        if any((row["kind"], row["value"], row["source"]) == key for row in inv.secret_leads):
            continue
        lead = {"kind": kind, "value": value, "source": source, "via": via_text or "asset",
                "auto_submit": False, "note": SECRET_LEADS_POLICY}
        if truncated:
            lead["truncated"] = True
        inv.secret_leads.append(lead)


def _merge_js(inv, source, result):
    if not isinstance(result, dict):
        return
    for raw in list(result.get("api_paths") or []) + list(result.get("routes") or []):
        inv.route(raw, "js:" + source)
    for raw in result.get("urls") or []:
        ws = _ws_path(inv.base_url, raw)
        if ws:
            inv.websockets.append(ws)
            continue
        if _safe_path(inv.base_url, raw) is not None:
            inv.route(raw, "js:" + source)
        else:
            inv.external_urls.append(str(raw)[:500])
    inv.params.update(x for x in (result.get("params") or []) if _param_name(x))
    _merge_secret_leads(inv, source, result)


def _merge_map(inv, source, result):
    if not isinstance(result, dict):
        return
    for raw in list(result.get("api_paths") or []) + list(result.get("routes") or []):
        inv.route(raw, "sourcemap:" + source)
    for raw in result.get("urls") or []:
        ws = _ws_path(inv.base_url, raw)
        if ws:
            inv.websockets.append(ws)
        elif _safe_path(inv.base_url, raw) is not None:
            inv.route(raw, "sourcemap:" + source)
        else:
            inv.external_urls.append(str(raw)[:500])
    inv.params.update(x for x in (result.get("params") or []) if _param_name(x))
    _merge_secret_leads(inv, source, result)


def _service_descriptor_name(path):
    """Whether an exact path names WSDL, protobuf, or generated gRPC-web metadata."""
    try:
        parsed = urllib.parse.urlsplit(html.unescape(str(path or "")))
        decoded = urllib.parse.unquote(parsed.path).lower()
        if decoded.endswith((".wsdl", ".proto", "_grpc_web_pb.js", "grpc-web.js", "grpc_web.js")):
            return True
        return any(str(key).lower() == "wsdl" for key, _value in
                   urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
    except (TypeError, ValueError):
        return False


def _service_descriptor_leads(base_url, at, text, *, html_page=False):
    """Exact service-description paths; never a conventional-path guess."""
    out = []
    source = str(text or "")[:MAX_DOCUMENT]
    raws = []
    if html_page:
        for pattern in (LINK_TAG, ANCHOR_TAG):
            for match in pattern.finditer(source):
                attrs = _attrs(match.group(1))
                if attrs.get("href"):
                    raws.append(attrs["href"])
    else:
        raws.extend(match.group(0).rstrip(".,;)]}") for match in SERVICE_DESCRIPTOR_TOKEN.finditer(source))
    for raw in raws:
        if not _service_descriptor_name(raw):
            continue
        path = _safe_path(base_url, raw, at)
        if path and _safe_to_fetch(path) and path not in out:
            out.append(path)
        if len(out) >= MAX_DESCRIPTOR_DOCS:
            break
    return out


def _descriptor_leads(base_url, at, text, *, html_page=False):
    """Exact descriptor links only; parser siblings own no network capability."""
    out = []
    try:
        # HTML is authoritative for generic JSON/YAML descriptors only through
        # rel=service-desc. WSDL/proto/generated names are self-identifying.
        if _descriptors is not None:
            found = (_descriptors.html_leads(base_url, at, text, _safe_path) if html_page else
                     _descriptors.text_leads(base_url, at, text, _safe_path))
            for path in found:
                if path not in out:
                    out.append(path)
    except Exception:
        pass
    if _services is not None:
        for path in _service_descriptor_leads(base_url, at, text, html_page=html_page):
            if path not in out:
                out.append(path)
    return out[:MAX_DESCRIPTOR_DOCS]


def _service_result(inv, path, result):
    """Normalize one transport-free WSDL/protobuf/gRPC-web parse.

    Addresses, imports and RPC paths deliberately remain descriptor metadata.
    In particular, this function never calls ``inv.route``.
    """
    kind = str(result.get("kind") or "")
    if kind not in {"wsdl", "protobuf", "grpc-web"}:
        return False
    dialect = str(result.get("dialect") or kind)[:80]
    operations = list(result.get("operations") or result.get("rpcs") or [])[:MAX_EVENT_OPERATIONS]
    imports = []
    for value in list(result.get("imports") or [])[:32]:
        if not isinstance(value, dict):
            continue
        item = dict(value)
        item["requestable"] = False
        if "fetched" in item:
            item["fetched"] = False
        imports.append(item)
    row = {
        "path": path, "kind": kind, "version": dialect,
        "encoding": "xml" if kind == "wsdl" else "proto" if kind == "protobuf" else "javascript",
        "requestable": False, "operations": len(operations), "imports": imports,
    }
    if result.get("target_namespace"):
        row["target_namespace"] = str(result.get("target_namespace"))[:512]
    if row not in inv.descriptor_docs:
        inv.descriptor_docs.append(row)

    surface = "soap_wsdl" if kind == "wsdl" else "grpc_web"
    spec_version = ("wsdl-" + dialect.removeprefix("wsdl-") if kind == "wsdl"
                    else "grpc-" + dialect.removeprefix("grpc-"))
    for operation in operations:
        if not isinstance(operation, dict):
            continue
        name = str(operation.get("name") or "")[:256]
        if not name:
            continue
        normalized = {
            "surface": surface, "method": "SOAP" if kind == "wsdl" else "RPC",
            "action": "invoke" if kind == "wsdl" else "call", "path": "-",
            "name": name, "operation_id": name, "spec_version": spec_version,
            "params": [], "fields": [], "response_fields": [], "content_types": [],
            "security": [], "requestable": False,
        }
        for key in ("interface", "binding", "soap_action", "package", "service", "input", "output",
                    "client_streaming", "server_streaming"):
            if operation.get(key) not in (None, "", [], {}):
                normalized[key] = operation.get(key)
        # A generated gRPC-web path is useful evidence, but is not an HTTP
        # inventory route and can never be selected by the contract GET driver.
        if operation.get("path"):
            normalized["rpc_path"] = str(operation.get("path"))[:512]
        if normalized not in inv.event_operations:
            inv.event_operations.append(normalized)

    for address in list(result.get("addresses") or [])[:16]:
        if not isinstance(address, dict):
            continue
        endpoint = address.get("resolved") or address.get("location")
        item = {
            "name": str(address.get("service") or address.get("port") or
                        address.get("endpoint") or "soap")[:160],
            "protocol": "soap", "endpoint": str(endpoint or "")[:2048],
            "same_origin": address.get("same_origin"), "off_origin": bool(address.get("off_origin")),
            "source": path, "requestable": False,
        }
        for key in ("port", "binding"):
            if address.get(key):
                item[key] = str(address.get(key))[:256]
        if item not in inv.descriptor_servers:
            inv.descriptor_servers.append(item)

    cls = "soap_wsdl" if kind == "wsdl" else "grpc_web"
    finding = {
        "class": cls, "confirmed": True,
        "evidence": {"wsdl": "wsdl_descriptor", "protobuf": "protobuf_descriptor",
                     "grpc-web": "grpc_web_descriptor"}[kind],
        "path": path, "version": dialect, "operations": len(operations),
        "requestable": False,
    }
    if finding not in inv.findings:
        inv.findings.append(finding)
    return True


def _parse_descriptor(inv, path, page):
    """Merge metadata only.  Never add a channel, server, or RPC method as a route."""
    if not isinstance(page, dict) or _status(page) != 200:
        return False
    result = None
    if _descriptors is not None:
        try:
            result = _descriptors.parse_page(inv.base_url, path, page)
        except Exception:
            result = None
    if isinstance(result, dict):
        row = {key: result.get(key) for key in ("path", "kind", "version", "encoding", "requestable")}
        if row not in inv.descriptor_docs:
            inv.descriptor_docs.append(row)
        for operation in list(result.get("operations") or [])[:MAX_EVENT_OPERATIONS]:
            if isinstance(operation, dict) and operation not in inv.event_operations:
                inv.event_operations.append(operation)
        for server in list(result.get("servers") or [])[:16]:
            if isinstance(server, dict) and server not in inv.descriptor_servers:
                inv.descriptor_servers.append(server)
        finding = result.get("finding")
        if isinstance(finding, dict) and finding not in inv.findings:
            inv.findings.append(dict(finding))
        return True
    if _services is None:
        return False
    try:
        result = _services.parse(
            _body(page), path=path, content_type=_headers(page).get("content-type", ""),
            base_url=inv.base_url, source_url=path,
        )
    except Exception:
        return False
    return _service_result(inv, path, result) if isinstance(result, dict) else False


def _empty(stopped="bad_target"):
    return {"flag": None, "routes": [], "route_paths": [], "params": [], "operations": [], "scripts": [],
            "event_operations": [],
            "source_maps": [], "sitemaps": [], "openapi_docs": [], "descriptor_docs": [],
            "descriptor_servers": [], "security_schemes": [],
            "websockets": [], "external_urls": [], "secret_leads": [],
            "secret_leads_policy": SECRET_LEADS_POLICY,
            "findings": [], "requests": 0, "bytes": 0, "stopped": stopped, "errors": [], "refused": []}


def discover(target, ctx=None):
    """Return a passive inventory for one target.  Never raises and never returns an answer."""
    ctx = dict(ctx or {})
    url = target.get("url") if isinstance(target, dict) else target
    if _origin(url) is None:
        return _empty()
    getter = _Getter(str(url), ctx)
    inv = _Inventory(str(url))
    try:
        app_root = urllib.parse.urlsplit(str(url)).path or "/"
        app_prefix = app_root if app_root.endswith("/") else app_root + "/"
        robots_path = app_prefix + "robots.txt"
        openapi_path = app_prefix + "openapi.json"
        sitemap_path = app_prefix + "sitemap.xml"
        root = getter.get(app_root)
        if root is not None and _status(root) == 410:
            getter.stopped = "completed"
            return inv.result(getter)
        robots = getter.get(robots_path)
        openapi_paths = [openapi_path]
        explicit_openapi = []
        descriptor_paths = []
        attempted_descriptors = set()
        sitemap_paths = [sitemap_path]
        scripts = []

        def read_descriptors(paths):
            for descriptor_path in paths:
                if (len(attempted_descriptors) >= MAX_DESCRIPTOR_ATTEMPTS
                        or len(inv.descriptor_docs) >= MAX_DESCRIPTOR_DOCS):
                    break
                if descriptor_path in attempted_descriptors:
                    continue
                attempted_descriptors.add(descriptor_path)
                _parse_descriptor(inv, descriptor_path, getter.get(descriptor_path, "service-desc"))

        prompt_text = "\n".join(
            str(value)[:20_000] for value in (
                [target.get(key) for key in ("question", "prompt", "description", "hint")]
                if isinstance(target, dict) else []
            ) + [ctx.get("prompt")]
            if isinstance(value, str) and value
        )
        descriptor_paths.extend(_descriptor_leads(str(url), app_root, prompt_text))

        if root is not None:
            js, maps, specs = _html_links(str(url), app_root, _text(root))
            scripts.extend(js[:MAX_SCRIPTS])
            sitemap_paths.extend(x for x in maps if x not in sitemap_paths)
            explicit_openapi.extend(x for x in specs if x not in explicit_openapi)
            openapi_paths.extend(x for x in specs if x not in openapi_paths)
            for path in _descriptor_leads(str(url), app_root, _text(root), html_page=True):
                if path not in descriptor_paths:
                    descriptor_paths.append(path)

        if robots is not None:
            rtext = _text(robots)
            for match in ROBOTS_SITEMAP.finditer(rtext[:MAX_DOCUMENT]):
                path = _safe_path(str(url), match.group(1), robots_path)
                if path and path not in sitemap_paths:
                    sitemap_paths.append(path)
            for match in ROBOTS_ROUTE.finditer(rtext[:MAX_DOCUMENT]):
                inv.route(match.group(1), "robots")

        # One conventional JSON probe remains the fastest path, followed by
        # exact documents linked from HTML.  Do not spend the entire request
        # budget on guessed Swagger spellings before inspecting exact linked
        # JavaScript/source maps: those assets can disclose the real spec URL.
        attempted_specs = set()
        successful_goal = 2 if explicit_openapi else 1
        for spec_path in openapi_paths:
            if len(attempted_specs) >= MAX_OPENAPI_ATTEMPTS \
                    or len(inv.openapi_docs) >= min(MAX_OPENAPI_DOCS, successful_goal):
                break
            attempted_specs.add(spec_path)
            _parse_openapi(inv, spec_path, getter.get(spec_path, "openapi"))

        # Descriptor fetches have no guessed defaults.  Every path above was
        # named by this target's own question or exact HTML service-desc link.
        read_descriptors(descriptor_paths)

        map_jobs = []
        js_openapi = []
        for script in scripts[:MAX_SCRIPTS]:
            page = getter.get(script, "script")
            if page is None or _status(page) != 200:
                continue
            inv.scripts.append(script)
            # A linked generated gRPC-web bundle is already in hand.  Parse
            # its MethodDescriptor declarations offline; never issue a
            # second request and never turn an RPC path into an HTTP route.
            parsed_service_script = (len(inv.descriptor_docs) < MAX_DESCRIPTOR_DOCS
                                     and _parse_descriptor(inv, script, page))
            if parsed_service_script:
                attempted_descriptors.add(script)
            result = _js.scan_text(script, _body(page)) if _js is not None else {}
            if parsed_service_script and isinstance(result, dict):
                # Generic string recon also sees `/package.Service/Method` in
                # generated bundles.  Keep that evidence solely in the
                # non-requestable descriptor operation, not route_paths.
                rpc_paths = {str(row.get("rpc_path")) for row in inv.event_operations
                             if row.get("surface") == "grpc_web" and row.get("rpc_path")}
                result = dict(result)
                for key in ("api_paths", "routes", "urls"):
                    values = result.get(key)
                    if isinstance(values, list):
                        result[key] = [value for value in values if str(value) not in rpc_paths]
            _merge_js(inv, script, result)
            exact_descriptors = _descriptor_leads(str(url), script, _text(page))
            for path in exact_descriptors:
                if path not in descriptor_paths:
                    descriptor_paths.append(path)
            for raw in result.get("sourcemap_urls") or []:
                inline = _inline_source_map(raw)
                if inline is not None:
                    map_jobs.append((script + "#inline-map", inline))
                    continue
                path = _safe_path(str(url), raw, script)
                if path and path not in [p for p, _b in map_jobs]:
                    map_jobs.append((path, None))
                elif raw:
                    getter.refused.append(str(raw)[:240])
            # An exact JS-disclosed OpenAPI document can be read after the conventional one.
            for raw in list(result.get("api_paths") or []) + list(result.get("routes") or []):
                path = _safe_path(str(url), raw, script)
                if path and re.search(r"openapi|swagger|api-docs", path, re.I) and path not in openapi_paths:
                    openapi_paths.append(path)
                    js_openapi.append(path)

        read_descriptors(descriptor_paths)

        for spec_path in js_openapi:
            if len(inv.openapi_docs) >= MAX_OPENAPI_DOCS or len(attempted_specs) >= MAX_OPENAPI_ATTEMPTS:
                break
            if spec_path in attempted_specs:
                continue
            attempted_specs.add(spec_path)
            _parse_openapi(inv, spec_path, getter.get(spec_path, "openapi"))

        map_openapi = []
        for path, inline in map_jobs[:MAX_SOURCE_MAPS]:
            page = None if inline is not None else getter.get(path, "map")
            raw = inline if inline is not None else (_body(page) if page is not None and _status(page) == 200 else None)
            if raw is None:
                continue
            inv.source_maps.append(path)
            result = _sourcemap.reconstruct(raw, path) if _sourcemap is not None else {}
            # Source-map contents are bytes the exact linked map already
            # supplied.  Generated gRPC-web descriptors in those sources are
            # metadata-only and cost no target request.
            for source in list(result.get("sources") or [])[:32] if isinstance(result, dict) else []:
                if len(inv.descriptor_docs) >= MAX_DESCRIPTOR_DOCS or not isinstance(source, dict):
                    break
                content = source.get("content")
                if not isinstance(content, str) or "MethodDescriptor" not in content:
                    continue
                source_name = str(source.get("name") or "source.js")[:512]
                _parse_descriptor(inv, path + "#" + source_name, {
                    "status": 200, "body": content.encode("utf-8", "replace"),
                    "response_headers": {"Content-Type": "application/javascript"},
                })
            if isinstance(result, dict):
                rpc_paths = {str(row.get("rpc_path")) for row in inv.event_operations
                             if row.get("surface") == "grpc_web" and row.get("rpc_path")}
                result = dict(result)
                for key in ("api_paths", "routes", "urls"):
                    values = result.get(key)
                    if isinstance(values, list):
                        result[key] = [value for value in values if str(value) not in rpc_paths]
            _merge_map(inv, path, result)
            for descriptor_path in _descriptor_leads(str(url), path, raw.decode("utf-8", "replace")):
                if descriptor_path not in descriptor_paths:
                    descriptor_paths.append(descriptor_path)
            for candidate in list(result.get("api_paths") or []) + list(result.get("routes") or []):
                spec_path = _safe_path(str(url), candidate, path)
                if (spec_path and re.search(r"openapi|swagger|api-docs", spec_path, re.I)
                        and spec_path not in attempted_specs and spec_path not in map_openapi):
                    map_openapi.append(spec_path)

        read_descriptors(descriptor_paths)

        for spec_path in map_openapi:
            if len(inv.openapi_docs) >= MAX_OPENAPI_DOCS or len(attempted_specs) >= MAX_OPENAPI_ATTEMPTS:
                break
            attempted_specs.add(spec_path)
            _parse_openapi(inv, spec_path, getter.get(spec_path, "openapi"))

        for path in sitemap_paths[:MAX_SITEMAPS]:
            _parse_sitemap(inv, path, getter.get(path, "sitemap"))

        # Only now spend spare budget on a small conventional-version ladder.
        # This covers Swagger 2 and OAS 3 deployments without starving exact
        # target-local evidence discovered above.
        fallbacks = tuple(app_prefix + name for name in (
            "openapi.yaml", "openapi.yml", "swagger.json", "swagger.yaml", "swagger.yml",
            "v3/api-docs", "api-docs"))
        goal = min(MAX_OPENAPI_DOCS, successful_goal)
        for spec_path in fallbacks:
            if len(attempted_specs) >= MAX_OPENAPI_ATTEMPTS or len(inv.openapi_docs) >= goal:
                break
            if spec_path in attempted_specs:
                continue
            attempted_specs.add(spec_path)
            _parse_openapi(inv, spec_path, getter.get(spec_path, "openapi"))


        if inv.scripts:
            inv.finding("javascript_routes", scripts=len(inv.scripts))
        if inv.source_maps:
            inv.finding("source_map_routes", maps=len(inv.source_maps))
        if inv.websockets:
            inv.finding("websocket_urls", urls=list(dict.fromkeys(inv.websockets))[:8])
        if inv.secret_leads:
            inv.findings.append({"class": "client_disclosure", "confirmed": True,
                                 "evidence": "client_secret_leads", "leads": len(inv.secret_leads),
                                 "policy": SECRET_LEADS_POLICY})
        return inv.result(getter)
    except Exception as exc:
        getter.errors.append({"path": "<inventory>", "error": type(exc).__name__})
        getter.stopped = getter.stopped or "error"
        return inv.result(getter)


def discover_targets(targets, ctx=None):
    """Proof-hunt-shaped batch input, inventories keyed by answer id.  Sequential and bounded per target."""
    out = {}
    for index, target in enumerate(list(targets or [])):
        if not isinstance(target, dict):
            continue
        aid = str(target.get("answer_id") or target.get("id") or f"target-{index + 1}")
        out[aid] = discover(target, ctx)
    return out


def solve_targets(targets, ctx=None):
    """Compatibility shim which can never provide an auto-submitted answer.

    The mutable sink/evidence objects are captured before copying the context, so a
    proof_hunt caller can receive findings without granting this detector an answer path.
    """
    original = ctx if isinstance(ctx, dict) else {}
    sink = original.get("inventory_sink")
    if not isinstance(sink, dict):
        sink = original.get("result_sink")
    evidence = original.get("evidence")
    inventories = discover_targets(targets, original)
    if isinstance(sink, dict):
        sink.update(inventories)
    if isinstance(evidence, list):
        for aid, row in inventories.items():
            evidence.append("WEB ENDPOINT INVENTORY %s: routes=%d operations=%d descriptors=%d scripts=%d maps=%d "
                            "secret_leads=%d(metadata-only/never-auto-submit) requests=%d" %
                            (aid, len(row["routes"]), len(row["operations"]),
                             len(row.get("descriptor_docs") or []), len(row["scripts"]), len(row["source_maps"]),
                             len(row.get("secret_leads") or []), row["requests"]))
    return {aid: None for aid in inventories}


__all__ = ["discover", "discover_targets", "solve_targets"]
