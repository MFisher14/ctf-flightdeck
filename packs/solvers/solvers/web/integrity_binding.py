#!/usr/bin/env python3
"""Integrity-binding-gap (partial-signature TOCTOU) engine: diff a documented covered-set against the mutable fields (B-106).

The bug class: an application binds an approval, signature or hash to *some* fields of a record
(``covered_fields``) and checks that binding before a security decision (release, payout, checkout),
but lets a field *outside* the covered set be amended after approval. The amendment leaves the
binding valid, so the decision runs on data nobody approved (time-of-check/time-of-use). The
csctf 9144 shape: an approval hash covers ``ref, origin, destination, ... lineitems[].quantity`` but
not ``lineitems[].hs_code``; a ``PATCH .../lineitems/0 {hs_code}`` after approval clears the embargo
check while the hash and the approval stay valid.

Three layers, the first two offline and mechanical, the third live and event-gated:

1. **Spec parse** (``parse_spec``): read a documented hash/signature spec as *data* -- JSON (through
   the fail-closed ``security_json`` parser), YAML (duplicate keys rejected) or plain text -- and pull
   out every binding (covered-field list, algorithm, the field that stores the digest), every
   documented endpoint (OpenAPI/Swagger ``paths``, ad-hoc ``{method, path, body}`` entries,
   ``"PATCH /x/{id}"`` keys, text lines) and the decision prose (release/approval/embargo wording).
2. **Diff** (``find_gaps``): normalise field paths (``lineItems[*].hsCode`` == ``lineitems[].hs_code``),
   compute the fields a write endpoint can change that no covered path reaches, and rank them. The
   ranking is a rules library, not a verdict: a field the decision prose names, a field whose name is a
   known gate class (classification, price, party, authz, lifecycle) and a field a documented write
   endpoint accepts score higher; request metadata (justification, csrf) is set aside. Which gap is
   security-relevant stays the agent's call -- the engine hands it a ranked list with the evidence.
   ``recompute_binding`` checks a sample record's stored digest against the documented covered set
   under a few canonical forms, so a reproduced digest confirms the covered set empirically.
3. **Probe** (``probe_gap``): through the scope-locked ``WebClient`` only, and only when the event
   profile's ``rules.web_state_changing`` is true (Open O-2): read the record, amend the one uncovered
   field, read it back, and report whether the field changed while the binding value and the approval
   status did not. The readback is reserved before the write is sent; a transport failure or an
   unstructured 5xx after the write is a terminal ``ambiguous_mutation`` (no further request). Only
   with an explicit ``decision_route`` and a confirmed gap does it fire the decision and scan the
   answer for a flag. Nothing here submits.

``solve(challenge_dir, profile, **opts)`` is the contract entry: offline over spec files in the
challenge folder (or ``--opt spec=...``), or with ``--opt target=URL`` it GETs the spec from the
target (read-only, no O-2 needed) and, given ``field``/``value``/``write_route``, runs the probe.
"""

from __future__ import annotations

import argparse
import copy
import dataclasses
import hashlib
import base64
import json
import re
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:  # flat sibling import of the fail-closed JSON parser
    sys.path.insert(0, str(HERE))

import security_json as _sj  # noqa: E402

ENGINE_ID = "web.integrity_binding"

MAX_SPEC_CHARS = 2_000_000
MAX_PATH_CHARS = 256
MAX_PATH_SEGMENTS = 16
MAX_WALK_NODES = 60_000
MAX_DECISION_LINES = 200
MAX_REF_DEPTH = 8
MAX_SPEC_FILES = 200

# ----------------------------------------------------------------------------------- vocabulary
# Keys (canonical_key form) whose value is the list of fields a binding covers.
COVERED_KEYS = frozenset({
    "covered_fields", "covers", "covered", "signed_fields", "fields_signed", "hashed_fields",
    "fields_hashed", "hash_fields", "hash_covers", "hash_input_fields", "hash_inputs",
    "signature_fields", "signature_covers", "signs", "bound_fields", "binding_fields",
    "fields_bound", "integrity_fields", "canonical_fields", "digest_fields", "mac_fields",
    "protected_fields", "approval_covers", "approval_fields",
})
# Keys whose value lists fields the spec says the binding does NOT cover.
EXCLUDED_KEYS = frozenset({
    "excluded_fields", "unsigned_fields", "unhashed_fields", "not_covered", "uncovered_fields",
    "fields_excluded", "unbound_fields", "exempt_fields",
})
# Keys whose value lists fields the spec says may be changed.
MUTABLE_KEYS = frozenset({
    "mutable_fields", "editable_fields", "amendable_fields", "writable_fields",
    "updatable_fields", "patchable_fields", "modifiable_fields",
})
ALGORITHM_KEYS = frozenset({
    "algorithm", "alg", "hash", "hash_algorithm", "digest", "digest_algorithm", "scheme",
    "signature_algorithm", "hash_alg", "mac",
})
BINDING_FIELD_KEYS = frozenset({
    "field", "stored_in", "stored_as", "hash_field", "digest_field", "signature_field",
    "bound_to", "binding_field", "value_field", "output_field", "store", "target_field",
})
BODY_KEYS = frozenset({
    "body", "fields", "params", "parameters", "accepts", "request", "request_body", "payload",
    "json", "input", "writable", "editable", "mutable", "amendable", "properties", "schema",
})
ROUTE_KEYS = ("path", "route", "url", "endpoint", "uri")
HTTP_METHODS = ("GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE")
WRITE_METHODS = frozenset({"POST", "PUT", "PATCH"})
# Last literal path segment that makes a non-GET endpoint a *decision* (an action), not an edit.
ACTION_VERBS = frozenset({
    "release", "approve", "approval", "reject", "submit", "sign", "finalize", "finalise",
    "confirm", "clear", "clearance", "checkout", "pay", "ship", "dispatch", "execute", "publish",
    "verify", "validate", "commit", "complete", "close", "settle", "redeem", "transfer",
    "purchase", "order", "authorize", "authorise", "issue", "certify", "lock", "seal",
})
DECISION_WORDS = re.compile(
    r"(?i)\b(?:releas\w*|approv\w*|clear\w*|embargo\w*|sanction\w*|authori[sz]\w*|checkout|"
    r"refund\w*|ship\w*|block\w*|deny|denied|allow\w*|forbid\w*|reject\w*|hold|held|interdict\w*|"
    r"verif\w*|valid\w*|unchanged|must|requires?|only if|limit\w*|price\w*|payout|withdraw\w*)\b")
DIGEST_NAME = re.compile(r"\b([A-Za-z][A-Za-z0-9_]{0,48}_(?:hash|signature|sig|digest|mac|hmac|checksum))\b")
# Request metadata a write endpoint accepts that is not a field of the bound record.
META_FIELDS = frozenset({
    "justification", "reason", "comment", "comments", "note", "notes", "memo", "remark", "remarks",
    "csrf", "csrf_token", "csrfmiddlewaretoken", "token", "nonce", "idempotency_key", "_method",
    "authenticity_token", "xsrf", "xsrf_token",
})
# Gate-class rules library: leaf-name fragments that commonly gate a security decision.
GATE_CLASSES = (
    ("classification", ("hs_code", "hscode", "hts", "tariff", "eccn", "classification", "commodity",
                        "category", "sku", "product_code", "class_code", "un_number", "cas")),
    ("price", ("price", "amount", "value", "cost", "total", "discount", "fee", "rate", "currency",
               "quantity", "qty", "balance", "credit", "tax", "weight")),
    ("party", ("owner", "recipient", "beneficiary", "account", "iban", "destination", "origin",
               "country", "address", "consignee", "carrier", "vendor", "payee", "user_id", "email")),
    ("authz", ("role", "permission", "scope", "group", "tier", "plan", "admin", "is_admin",
               "privilege", "level", "clearance", "verified", "trusted")),
    ("lifecycle", ("status", "state", "approved", "expires", "expiry", "expiration", "valid_until",
                   "deadline", "limit", "embargo", "hold", "flag")),
)


class SpecError(ValueError):
    """A spec that cannot be read as data (ambiguous JSON/YAML, over a cap). The message names why."""


# StateChangeRefused (below the toolkit loader) is a subclass of the web toolkit's OutOfScope.


# ----------------------------------------------------------------------------------- field paths

_SEG_SPLIT = re.compile(r"[./]")
_SEG = re.compile(r"^([^\[\]]*)((?:\[[^\[\]]*\])*)$")


def norm_path(raw) -> str | None:
    """Canonical form of a documented field path, or None when it is not one.

    ``$.lineItems[*].hsCode``, ``lineitems[0].hs_code``, ``lineitems.*.hs-code`` and
    ``/lineitems/0/hs_code`` all become ``lineitems[].hs_code``: each name is ``canonical_key``-ed, any
    index, wildcard or numeric segment marks the preceding name as an array (``[]``).
    """
    if not isinstance(raw, str):
        return None
    text = raw.strip().strip("`'\"")
    if not text or len(text) > MAX_PATH_CHARS:
        return None
    if text.startswith("$"):
        text = text[1:]
    text = text.strip("./")
    if not text:
        return None
    out: list[str] = []
    for part in _SEG_SPLIT.split(text):
        if part == "":
            return None
        if part in ("*", "[]", "[*]") or part.isdigit():
            if not out:
                return None
            if not out[-1].endswith("[]"):
                out[-1] += "[]"
            continue
        m = _SEG.match(part)
        if not m:
            return None
        name = _sj.canonical_key(m.group(1))
        if not name:
            return None
        out.append(name + ("[]" if m.group(2) else ""))
        if len(out) > MAX_PATH_SEGMENTS:
            return None
    return ".".join(out) if out else None


def _bare(path: str) -> list[str]:
    return [seg[:-2] if seg.endswith("[]") else seg for seg in path.split(".")]


def _match_key(path: str) -> list[str]:
    """Segments for comparison: array marks and word separators dropped, so a spec's ``lineItems``
    (``line_items``) and a route's ``/lineitems/`` name the same field."""
    return [seg.replace("_", "") for seg in _bare(path)]


def covers(covered: str, field: str) -> bool:
    """True when covered path ``covered`` reaches ``field``: equal, or a whole-subtree prefix
    (``lineitems`` and ``lineitems[]`` both cover ``lineitems[].hs_code``)."""
    c, f = _match_key(covered), _match_key(field)
    return len(c) <= len(f) and f[:len(c)] == c


def leaf(path: str) -> str:
    return _bare(path)[-1]


# ----------------------------------------------------------------------------------- spec model

@dataclasses.dataclass(frozen=True)
class Binding:
    covered: tuple[str, ...]          # normalised covered paths, in documented order
    raw_covered: tuple[str, ...]      # as written
    algorithm: str | None
    binding_field: str | None         # the field that stores the digest/signature, when documented
    source: str                       # where in the spec it was found


@dataclasses.dataclass(frozen=True)
class Endpoint:
    method: str
    path: str
    kind: str                         # read | write | action | delete
    prefix: str                       # field-path prefix the body fields land under ("" = root)
    body_fields: tuple[str, ...]      # normalised body field names (relative to prefix)

    def describe(self) -> str:
        return f"{self.method} {self.path}"


@dataclasses.dataclass
class SpecDoc:
    bindings: list[Binding] = dataclasses.field(default_factory=list)
    endpoints: list[Endpoint] = dataclasses.field(default_factory=list)
    excluded: list[str] = dataclasses.field(default_factory=list)
    declared_mutable: list[str] = dataclasses.field(default_factory=list)
    decision_text: list[str] = dataclasses.field(default_factory=list)
    digest_names: list[str] = dataclasses.field(default_factory=list)
    form: str = "text"


def _field_list(value) -> list[str] | None:
    """A covered/excluded/mutable list: a list of strings, or one comma/space separated string."""
    items: list[str]
    if isinstance(value, list):
        if not value or not all(isinstance(v, str) for v in value):
            return None
        items = value
    elif isinstance(value, str):
        items = [p for p in re.split(r"[,\s;]+", value) if p]
    else:
        return None
    out = [p for p in (norm_path(i) for i in items) if p]
    return out if out and len(out) == len(items) else None


# ----------------------------------------------------------------------------------- parsing

def _load_yaml(text: str):
    try:
        import yaml  # pyyaml, pinned in requirements.in
    except ImportError as exc:  # no silent fallback: a YAML spec needs the parser
        raise SpecError("YAML spec needs the pyyaml package (requirements.in pins it)") from exc

    class _NoDupLoader(yaml.SafeLoader):
        pass

    def _mapping(loader, node, deep=False):
        seen = set()
        for key_node, _ in node.value:
            key = loader.construct_object(key_node, deep=deep)
            canon = _sj.canonical_key(key)
            if canon in seen:
                raise SpecError(f"YAML spec has a duplicate or colliding key {str(key)[:60]!r}")
            seen.add(canon)
        return yaml.SafeLoader.construct_mapping(loader, node, deep=deep)

    _NoDupLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)
    try:
        return yaml.load(text, Loader=_NoDupLoader)  # noqa: S506 - SafeLoader subclass
    except SpecError:
        raise
    except yaml.YAMLError as exc:
        raise SpecError(f"malformed YAML spec: {type(exc).__name__}") from exc


def parse_spec(text: str, name: str = "") -> SpecDoc:
    """Parse a documented hash/signature spec (JSON, YAML or plain text) into a ``SpecDoc``.

    The spec is untrusted data: JSON goes through the fail-closed parser (duplicate or colliding keys
    and over-cap documents raise ``SpecError``, never a last-wins read), YAML rejects duplicate keys,
    and anything else is read line by line. Nothing in it is executed or followed.
    """
    if not isinstance(text, str):
        raise SpecError("spec is not text")
    if len(text) > MAX_SPEC_CHARS:
        raise SpecError(f"spec over the {MAX_SPEC_CHARS}-character cap")
    stripped = text.lstrip()
    lname = name.lower()
    if stripped[:1] in ("{", "["):
        try:
            data = _sj.loads(stripped, max_chars=MAX_SPEC_CHARS)
        except ValueError as exc:
            raise SpecError(f"ambiguous or malformed JSON spec: {exc}") from exc
        doc = _parse_structured(data)
        doc.form = "json"
        return doc
    if lname.endswith((".yaml", ".yml")) or re.match(r"(?m)^(?:openapi|swagger)\s*:", stripped):
        data = _load_yaml(text)
        if isinstance(data, (dict, list)):
            doc = _parse_structured(data)
            doc.form = "yaml"
            return doc
    doc = _parse_text(text)
    doc.form = "text"
    return doc


def _walk(data):
    """Yield (pointer, container, key, value) for every dict member, bounded."""
    stack = [("", data)]
    seen = 0
    while stack:
        ptr, node = stack.pop()
        seen += 1
        if seen > MAX_WALK_NODES:
            raise SpecError("spec structure over the walk cap")
        if isinstance(node, dict):
            for key, value in node.items():
                child = f"{ptr}/{key}"
                yield child, node, key, value
                if isinstance(value, (dict, list)):
                    stack.append((child, value))
        elif isinstance(node, list):
            for i, value in enumerate(node):
                if isinstance(value, (dict, list)):
                    stack.append((f"{ptr}/{i}", value))


def _strings(data):
    """Every string (values and keys) in a structured doc, bounded."""
    stack = [data]
    n = 0
    while stack:
        node = stack.pop()
        n += 1
        if n > MAX_WALK_NODES:
            return
        if isinstance(node, str):
            yield node
        elif isinstance(node, dict):
            for k, v in node.items():
                yield str(k)
                stack.append(v)
        elif isinstance(node, list):
            stack.extend(node)


def _parse_structured(data) -> SpecDoc:
    doc = SpecDoc()
    explicit_mutable: list[str] = []
    for ptr, container, key, value in _walk(data):
        canon = _sj.canonical_key(key)
        if canon in COVERED_KEYS:
            fields = _field_list(value)
            if fields:
                raw = tuple(value if isinstance(value, list) else
                            [p for p in re.split(r"[,\s;]+", value) if p])
                doc.bindings.append(Binding(tuple(fields), raw, _sibling_algorithm(container),
                                            _sibling_binding_field(container, key), f"json:{ptr}"))
        elif canon in EXCLUDED_KEYS:
            doc.excluded.extend(_field_list(value) or [])
        elif canon in MUTABLE_KEYS:
            explicit_mutable.extend(_field_list(value) or [])
    doc.declared_mutable = list(dict.fromkeys(explicit_mutable))
    doc.endpoints = _structured_endpoints(data)
    lines = []
    digest_names = []
    for s in _strings(data):
        digest_names.extend(m.group(1) for m in DIGEST_NAME.finditer(s))
        if len(s) <= 2000 and DECISION_WORDS.search(s):
            lines.append(s.strip()[:500])
    doc.decision_text = list(dict.fromkeys(lines))[:MAX_DECISION_LINES]
    doc.digest_names = _rank_names(digest_names)
    _fill_binding_fields(doc)
    return doc


def _sibling_algorithm(container) -> str | None:
    for k, v in container.items():
        if _sj.canonical_key(k) in ALGORITHM_KEYS and isinstance(v, str) and 0 < len(v) <= 64:
            return v.strip()
    return None


def _sibling_binding_field(container, covered_key) -> str | None:
    for k, v in container.items():
        if k == covered_key:
            continue
        if _sj.canonical_key(k) in BINDING_FIELD_KEYS and isinstance(v, str):
            p = norm_path(v)
            if p:
                return p
    return None


def _rank_names(names) -> list[str]:
    counts: dict[str, int] = {}
    order: dict[str, int] = {}
    for i, n in enumerate(names):
        c = _sj.canonical_key(n)
        if c in COVERED_KEYS or c in EXCLUDED_KEYS:
            continue
        counts[c] = counts.get(c, 0) + 1
        order.setdefault(c, i)
    return sorted(counts, key=lambda c: (-counts[c], order[c]))


def _fill_binding_fields(doc: SpecDoc) -> None:
    """A binding with no documented store field takes the most-mentioned ``*_hash``-style name."""
    if not doc.digest_names:
        return
    doc.bindings = [b if b.binding_field else dataclasses.replace(b, binding_field=doc.digest_names[0])
                    for b in doc.bindings]


# ---- endpoints

_ROUTE_LINE = re.compile(r"\b(GET|HEAD|OPTIONS|POST|PUT|PATCH|DELETE)\s+(/[^\s`'\"]*)")
_PARAM_SEG = re.compile(r"^(?:\{[^{}]+\}|:[A-Za-z_]\w*|<[^<>]+>)$")
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_.\[\]*-]{0,80}")


def classify_route(method: str, path: str, body_fields) -> Endpoint:
    """Turn ``PATCH /consignments/{ref}/lineitems/{idx}`` + ``[hs_code]`` into an Endpoint whose
    body fields land under prefix ``lineitems[]``. The first literal segment followed by a
    parameter is the root collection; later ``literal/{param}`` pairs are arrays of the record."""
    method = method.upper()
    route = path.split("?", 1)[0]
    segs = [s for s in route.split("/") if s]
    is_param = [bool(_PARAM_SEG.match(s)) for s in segs]
    root = None
    for i in range(len(segs) - 1):
        if not is_param[i] and is_param[i + 1]:
            root = i
            break
    prefix_parts: list[str] = []
    last_literal = None
    if root is not None:
        i = root + 2
        while i < len(segs):
            if is_param[i]:
                i += 1
                continue
            name = _sj.canonical_key(segs[i])
            last_literal = name
            if i + 1 < len(segs) and is_param[i + 1]:
                prefix_parts.append(name + "[]")
                i += 2
            else:
                prefix_parts.append(name)
                i += 1
    elif segs:
        last_literal = _sj.canonical_key(segs[-1])
    fields = tuple(dict.fromkeys(p for p in (norm_path(f) for f in body_fields or ()) if p))
    if method in ("GET", "HEAD", "OPTIONS"):
        kind = "read"
    elif method == "DELETE":
        kind = "delete"
    elif last_literal in ACTION_VERBS and (not prefix_parts or prefix_parts[-1] == last_literal):
        kind = "action"
        if prefix_parts and prefix_parts[-1] == last_literal:
            prefix_parts.pop()
    else:
        kind = "write"
        # POST to a bare collection (``/items``) appends an element of it.
        if method == "POST" and prefix_parts and not prefix_parts[-1].endswith("[]") and \
                not (len(segs) and is_param[-1]):
            prefix_parts[-1] += "[]"
    return Endpoint(method, path, kind, ".".join(prefix_parts), fields)


def _body_names(value, depth=0) -> list[str]:
    """Field names a documented request body names: a list, a dict's keys, or ``{a, b}`` text."""
    if depth > 3:
        return []
    if isinstance(value, list):
        out = []
        for v in value:
            if isinstance(v, str):
                out.extend(_body_names(v, depth + 1))
            elif isinstance(v, dict):
                nm = v.get("name") or v.get("field")
                if isinstance(nm, str):
                    out.append(nm)
        return out
    if isinstance(value, dict):
        props = value.get("properties")
        if isinstance(props, dict):
            return [str(k) for k in props]
        if isinstance(value.get("type"), str) and value.get("type") != "object":
            return []
        return [str(k) for k in value if _sj.canonical_key(k) not in ("type", "required",
                                                                      "description", "example")]
    if isinstance(value, str):
        inner = value
        m = re.search(r"\{([^{}]*)\}", value)
        if m:
            inner = m.group(1)
            return [x.split(":")[0].strip().strip("'\"") for x in inner.split(",")
                    if _IDENT.fullmatch(x.split(":")[0].strip().strip("'\""))]
        return [x for x in re.split(r"[,\s;]+", inner) if _IDENT.fullmatch(x)]
    return []


def _resolve_ref(data, node, depth=0):
    if not isinstance(node, dict) or depth > MAX_REF_DEPTH:
        return node
    ref = node.get("$ref")
    if isinstance(ref, str) and ref.startswith("#/"):
        cur = data
        for part in ref[2:].split("/"):
            if not isinstance(cur, dict) or part not in cur:
                return node
            cur = cur[part]
        return _resolve_ref(data, cur, depth + 1)
    return node


def _openapi_body(data, op) -> list[str]:
    names: list[str] = []
    rb = _resolve_ref(data, op.get("requestBody"))
    if isinstance(rb, dict) and isinstance(rb.get("content"), dict):
        for media in rb["content"].values():
            schema = _resolve_ref(data, media.get("schema") if isinstance(media, dict) else None)
            if isinstance(schema, dict):
                names.extend(_schema_props(data, schema))
    for p in op.get("parameters") or []:
        p = _resolve_ref(data, p)
        if not isinstance(p, dict):
            continue
        if p.get("in") == "body":
            names.extend(_schema_props(data, _resolve_ref(data, p.get("schema"))))
        elif p.get("in") == "formData" and isinstance(p.get("name"), str):
            names.append(p["name"])
    return names


def _schema_props(data, schema, prefix="", depth=0) -> list[str]:
    schema = _resolve_ref(data, schema)
    if not isinstance(schema, dict) or depth > 3:
        return []
    out = []
    props = schema.get("properties")
    if isinstance(props, dict):
        for k, v in props.items():
            name = f"{prefix}{k}"
            v = _resolve_ref(data, v)
            sub = _schema_props(data, v, name + ".", depth + 1) if isinstance(v, dict) else []
            out.extend(sub or [name])
    return out


def _structured_endpoints(data) -> list[Endpoint]:
    eps: list[Endpoint] = []
    paths = data.get("paths") if isinstance(data, dict) else None
    if isinstance(paths, dict):  # OpenAPI 3 / Swagger 2
        for route, ops in paths.items():
            if not isinstance(route, str) or not route.startswith("/") or not isinstance(ops, dict):
                continue
            for method, op in ops.items():
                if str(method).upper() in HTTP_METHODS and isinstance(op, dict):
                    eps.append(classify_route(str(method), route, _openapi_body(data, op)))
    for _ptr, container, key, value in _walk(data):
        # "PATCH /consignments/{ref}/lineitems/{idx}": {...}
        m = _ROUTE_LINE.fullmatch(str(key).strip()) if isinstance(key, str) else None
        if m:
            body = value
            if isinstance(value, dict):
                for k, v in value.items():
                    if _sj.canonical_key(k) in BODY_KEYS:
                        body = v
                        break
                else:
                    body = [] if any(_sj.canonical_key(k) in ("description", "summary", "returns")
                                     for k in value) else value
            eps.append(classify_route(m.group(1), m.group(2), _body_names(body)))
    for node in _dicts(data):  # {"method": "PATCH", "path": "...", "body": {...}}
        method = node.get("method")
        route = next((node[k] for k in ROUTE_KEYS if isinstance(node.get(k), str)), None)
        if isinstance(method, str) and method.upper() in HTTP_METHODS and route and route.startswith("/"):
            body = next((node[k] for k in node if _sj.canonical_key(k) in BODY_KEYS), [])
            eps.append(classify_route(method, route, _body_names(body)))
        elif isinstance(node.get("endpoint") or node.get("route"), str):
            m = _ROUTE_LINE.fullmatch(str(node.get("endpoint") or node.get("route")).strip())
            if m:
                body = next((node[k] for k in node if _sj.canonical_key(k) in BODY_KEYS), [])
                eps.append(classify_route(m.group(1), m.group(2), _body_names(body)))
    for s in _strings(data):  # "PATCH /x/{id} body {a, b}" written as one string value
        if isinstance(s, str) and len(s) <= 2000:
            for m in _ROUTE_LINE.finditer(s):
                if m.group(0).strip() == s.strip():
                    continue  # a bare key already handled above
                tail = s[m.end():].split("\n", 1)[0]
                eps.append(classify_route(m.group(1), m.group(2), _body_names(tail) if "{" in tail else []))
    return _dedupe_endpoints(eps)


def _dicts(data):
    stack = [data]
    n = 0
    while stack:
        node = stack.pop()
        n += 1
        if n > MAX_WALK_NODES:
            return
        if isinstance(node, dict):
            yield node
            stack.extend(v for v in node.values() if isinstance(v, (dict, list)))
        elif isinstance(node, list):
            stack.extend(v for v in node if isinstance(v, (dict, list)))


def _dedupe_endpoints(eps) -> list[Endpoint]:
    merged: dict[tuple[str, str], Endpoint] = {}
    for ep in eps:
        key = (ep.method, ep.path)
        prev = merged.get(key)
        if prev is None:
            merged[key] = ep
        else:
            fields = tuple(dict.fromkeys(prev.body_fields + ep.body_fields))
            merged[key] = dataclasses.replace(prev, body_fields=fields)
    return list(merged.values())


def _parse_text(text: str) -> SpecDoc:
    doc = SpecDoc()
    lines = text.splitlines()
    cov_re = re.compile(
        r"(?i)\b(covered[_ ]fields|signed[_ ]fields|hashed[_ ]fields|bound[_ ]fields|"
        r"signature covers|hash covers|digest covers|approval covers|fields covered|"
        r"binds?\s+(?:[\w-]+\s+){0,3}over|hash(?:ed)?\s+over|signed\s+over|computed\s+over)"
        r"\s*[:=]?\s*(?:fields?\s*[:=]?\s*)?(.+)$")
    exc_re = re.compile(r"(?i)\b(excluded[_ ]fields|unsigned[_ ]fields|not covered|uncovered[_ ]fields)"
                        r"\s*[:=]\s*(.+)$")
    mut_re = re.compile(r"(?i)\b(mutable|editable|amendable|writable|updatable)[_ ]fields\s*[:=]\s*(.+)$")
    algo_re = re.compile(r"(?i)\b(sha-?(?:1|224|256|384|512)|sha3-\d+|md5|hmac[-_ ]?sha-?\d+|blake2[bs]?|"
                         r"ed25519|rsa|ecdsa)\b")
    digest_names = []
    for n, line in enumerate(lines, 1):
        digest_names.extend(m.group(1) for m in DIGEST_NAME.finditer(line))
        if DECISION_WORDS.search(line):
            doc.decision_text.append(line.strip()[:500])
        m = exc_re.search(line)
        if m:
            doc.excluded.extend(_text_fields(m.group(2)))
            continue
        m = mut_re.search(line)
        if m:
            doc.declared_mutable.extend(_text_fields(m.group(2)))
            continue
        m = cov_re.search(line)
        if m:
            fields = _text_fields(m.group(2))
            if fields:
                a = algo_re.search(line)
                doc.bindings.append(Binding(tuple(norm_path(f) for f in fields), tuple(fields),
                                            a.group(1) if a else None, None, f"text:line {n}"))
    doc.decision_text = list(dict.fromkeys(doc.decision_text))[:MAX_DECISION_LINES]
    eps = []
    for line in lines:
        for m in _ROUTE_LINE.finditer(line):
            tail = line[m.end():]
            eps.append(classify_route(m.group(1), m.group(2), _body_names(tail) if "{" in tail else []))
    doc.endpoints = _dedupe_endpoints(eps)
    doc.excluded = [p for p in (norm_path(f) for f in doc.excluded) if p]
    doc.declared_mutable = list(dict.fromkeys(p for p in (norm_path(f) for f in doc.declared_mutable) if p))
    doc.digest_names = _rank_names(digest_names)
    _fill_binding_fields(doc)
    return doc


def _text_fields(tail: str) -> list[str]:
    """Field paths from the rest of a prose line: ``ref, origin, lineitems[].quantity -- but ...``.
    Reading stops at the first token that is not a field path (the prose resumes)."""
    tail = re.sub(r"[(){}=:]", " ", tail)
    out = []
    for tok in re.split(r"\s*[,;]\s*|\s+", tail.strip()):
        tok = tok.strip("`'\". ")
        if not tok or tok.lower() == "and":
            continue
        canon = _sj.canonical_key(tok)
        if canon in COVERED_KEYS or canon in ("fields", "field", "the", "of", "over", "a", "an"):
            continue  # the list's own label or filler before the first field
        if canon in _PROSE_STOP or not _FIELD_TOKEN.fullmatch(tok):
            if out:
                break  # the prose resumes: the list is over
            continue
        if norm_path(tok):
            out.append(tok)
    return out


_FIELD_TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\[\*?\d*\]|\.[A-Za-z_*][A-Za-z0-9_]*)*")
_PROSE_STOP = frozenset({
    "but", "not", "or", "except", "excluding", "is", "are", "only", "also", "with", "which", "that",
    "while", "when", "so", "then", "including", "using", "as", "in", "to", "from", "by", "for",
})


# ----------------------------------------------------------------------------------- the diff

@dataclasses.dataclass(frozen=True)
class Gap:
    path: str                         # normalised field path outside every covered path
    score: int
    gate_classes: tuple[str, ...]
    via: tuple[str, ...]              # write endpoints (or "declared" / "sample") that make it mutable
    decision_mentions: tuple[str, ...]
    reasons: tuple[str, ...]

    def to_dict(self):
        return dataclasses.asdict(self)


@dataclasses.dataclass
class GapReport:
    binding: Binding | None
    gaps: list[Gap]
    covered_writable: list[str]       # mutable AND covered (changing them should break the binding)
    meta_ignored: list[str]           # request metadata set aside
    action_endpoints: list[str]       # decision endpoints (release/approve/...)
    notes: list[str]

    def to_dict(self):
        return {"binding": dataclasses.asdict(self.binding) if self.binding else None,
                "gaps": [g.to_dict() for g in self.gaps], "covered_writable": self.covered_writable,
                "meta_ignored": self.meta_ignored, "action_endpoints": self.action_endpoints,
                "notes": self.notes}


def gate_classes(path: str) -> tuple[str, ...]:
    name = leaf(path)
    toks = set(name.split("_")) | {name}
    out = []
    for cls, words in GATE_CLASSES:
        if any(w == name or w in toks or (len(w) > 4 and w in name) for w in words):
            out.append(cls)
    return tuple(out)


def _mentions(path: str, lines) -> tuple[str, ...]:
    name = leaf(path)
    spaced = name.replace("_", " ")
    camel = re.sub(r"_([a-z0-9])", lambda m: m.group(1).upper(), name)
    pats = {name, spaced, camel, name.replace("_", "-")}
    rx = re.compile(r"(?i)(?<![A-Za-z0-9_])(?:" + "|".join(re.escape(p) for p in pats) + r")(?![A-Za-z0-9_])")
    return tuple(line for line in lines if rx.search(line))[:5]


def sample_paths(obj, prefix="", depth=0) -> list[str]:
    """Normalised leaf paths of a sample record (``lineitems[].hs_code``)."""
    out: list[str] = []
    if depth > MAX_PATH_SEGMENTS:
        return out
    if isinstance(obj, dict):
        for k, v in obj.items():
            name = _sj.canonical_key(k)
            if not name:
                continue
            p = f"{prefix}.{name}" if prefix else name
            if isinstance(v, (dict, list)) and v:
                out.extend(sample_paths(v, p, depth + 1))
            else:
                out.append(p)
    elif isinstance(obj, list):
        base = prefix + "[]" if prefix and not prefix.endswith("[]") else prefix
        for item in obj[:50]:
            out.extend(sample_paths(item, base, depth + 1))
        if not obj and prefix:
            out.append(base)
    return list(dict.fromkeys(out))


def find_gaps(doc: SpecDoc, *, binding: int = 0, sample=None) -> GapReport:
    """Diff one binding's covered set against every mutable field the spec documents.

    Mutable fields come from write endpoints (body fields under the route's prefix), the spec's
    explicit mutable-field lists, and -- with lower weight, mutability unknown -- the leaf paths of a
    sample record. A gap is a mutable field no covered path reaches; request metadata and the binding
    field itself are set aside. Gaps are ranked by the rules library (see the module docstring).
    """
    notes: list[str] = []
    actions = [ep.describe() for ep in doc.endpoints if ep.kind == "action"]
    if not doc.bindings:
        return GapReport(None, [], [], [], actions, ["no covered-field list found in the spec"])
    if binding >= len(doc.bindings):
        raise IndexError(f"spec has {len(doc.bindings)} binding(s), not {binding + 1}")
    if len(doc.bindings) > 1:
        notes.append(f"spec documents {len(doc.bindings)} bindings; diffing #{binding} "
                     f"({doc.bindings[binding].source})")
    b = doc.bindings[binding]
    mutable: dict[str, list[str]] = {}
    for ep in doc.endpoints:
        if ep.kind != "write":
            continue
        for f in ep.body_fields:
            p = f"{ep.prefix}.{f}" if ep.prefix else f
            mutable.setdefault(p, []).append(ep.describe())
    for p in doc.declared_mutable:
        mutable.setdefault(p, []).append("declared mutable")
    for p in doc.excluded:
        mutable.setdefault(p, []).append("declared uncovered")
    if sample is not None:
        for p in sample_paths(sample):
            mutable.setdefault(p, []).append("sample record (mutability unknown)")
    if not any(ep.kind == "write" for ep in doc.endpoints) and not doc.declared_mutable:
        notes.append("no documented write endpoint: mutability of the gaps is unknown")
    bind_field = b.binding_field
    gaps, covered_writable, meta = [], [], []
    for p, via in mutable.items():
        if bind_field and _match_key(p) == _match_key(bind_field):
            continue
        if leaf(p) in META_FIELDS:
            meta.append(p)
            continue
        if any(covers(c, p) for c in b.covered):
            if any(v != "sample record (mutability unknown)" for v in via):
                covered_writable.append(p)
            continue
        score, reasons = 0, []
        mentions = _mentions(p, doc.decision_text)
        if mentions:
            score += 50
            reasons.append("named by the spec's decision wording")
        classes = gate_classes(p)
        if classes:
            score += 25
            reasons.append("gate class: " + ", ".join(classes))
        writers = [v for v in via if v != "sample record (mutability unknown)"]
        if any(v not in ("declared mutable", "declared uncovered") for v in writers):
            score += 15
            reasons.append("a documented write endpoint accepts it")
        elif writers:
            score += 10
            reasons.append("the spec lists it as " + "/".join(sorted(set(writers))))
        else:
            reasons.append("seen only in a sample record: mutability unknown")
        if p in doc.excluded:
            score += 10
            reasons.append("the spec says the binding does not cover it")
        gaps.append(Gap(p, score, classes, tuple(dict.fromkeys(via)), mentions, tuple(reasons)))
    gaps.sort(key=lambda g: (-g.score, g.path))
    return GapReport(b, gaps, sorted(set(covered_writable)), sorted(set(meta)), actions, notes)


# ----------------------------------------------------------------------------------- recompute

def _key_for(d: dict, name: str):
    """The one key of ``d`` that names canonical field ``name``: an exact ``canonical_key`` match,
    else the single key equal once word separators are dropped (``lineItems`` for ``lineitems``).
    Two candidates are ambiguous and match nothing (fail closed)."""
    exact = [k for k in d if _sj.canonical_key(k) == name]
    if len(exact) == 1:
        return exact[0]
    if exact:
        return None
    squashed = name.replace("_", "")
    loose = [k for k in d if _sj.canonical_key(k).replace("_", "") == squashed]
    return loose[0] if len(loose) == 1 else None


def _project(obj, covered: tuple[str, ...]):
    """The sub-record a binding over ``covered`` hashes, in documented field order."""
    out: dict = {}
    for path in covered:
        _project_one(obj, path.split("."), out)
    return out


def _project_one(src, segs, dst):
    if not segs or not isinstance(src, dict):
        return
    seg = segs[0]
    arr = seg.endswith("[]")
    name = seg[:-2] if arr else seg
    key = _key_for(src, name)
    if key is None:
        return
    val = src[key]
    if len(segs) == 1:
        dst[key] = copy.deepcopy(val)
        return
    if isinstance(val, list):
        tgt = dst.setdefault(key, [{} for _ in val])
        for i, item in enumerate(val):
            if i < len(tgt) and isinstance(tgt[i], dict):
                _project_one(item, segs[1:], tgt[i])
    elif isinstance(val, dict):
        _project_one(val, segs[1:], dst.setdefault(key, {}))


def _flat_values(obj, covered):
    vals = []
    for path in covered:
        vals.extend(_values_at(obj, path.split(".")))
    return vals


def _values_at(src, segs):
    if not segs:
        return [src]
    if not isinstance(src, dict):
        return []
    seg = segs[0]
    name = seg[:-2] if seg.endswith("[]") else seg
    key = _key_for(src, name)
    if key is None:
        return []
    val = src[key]
    if isinstance(val, list) and len(segs) > 1:
        out = []
        for item in val:
            out.extend(_values_at(item, segs[1:]))
        return out
    return _values_at(val, segs[1:])


_HASHES = ("sha256", "sha1", "sha512", "sha384", "sha224", "md5", "sha3_256")


def canonical_forms(obj, covered: tuple[str, ...]) -> dict[str, bytes]:
    proj = _project(obj, covered)
    flat = ["" if v is None else (json.dumps(v, separators=(",", ":"), sort_keys=True)
                                  if isinstance(v, (dict, list)) else str(v))
            for v in _flat_values(obj, covered)]
    return {
        "json-sorted-compact": json.dumps(proj, sort_keys=True, separators=(",", ":"),
                                          ensure_ascii=False).encode(),
        "json-sorted": json.dumps(proj, sort_keys=True, ensure_ascii=False).encode(),
        "json-ordered-compact": json.dumps(proj, separators=(",", ":"), ensure_ascii=False).encode(),
        "json-ordered": json.dumps(proj, ensure_ascii=False).encode(),
        "pipe-joined": "|".join(flat).encode(),
        "newline-joined": "\n".join(flat).encode(),
        "concat": "".join(flat).encode(),
    }


def recompute_binding(obj, binding: Binding, stored: str | None = None) -> dict:
    """Try to reproduce a sample record's stored digest from its covered fields alone.

    Returns ``{"reproduced": bool, "scheme": "<hash>/<form>" | None, "reason": ...}``. A reproduced
    digest confirms empirically that the binding covers exactly the documented fields, so any field
    outside them can change without moving it. A keyed scheme (HMAC, signatures) cannot be
    recomputed without the key and says so.
    """
    if stored is None and binding.binding_field:
        vals = _values_at(obj, binding.binding_field.split("."))
        if len(vals) != 1:  # not at that path: search for the leaf anywhere in the record
            want = leaf(binding.binding_field)
            vals = [v for p, v in _leaves(obj) if leaf(p) == want]
        stored = vals[0] if len(vals) == 1 and isinstance(vals[0], str) else None
    if not isinstance(stored, str) or not stored.strip():
        return {"reproduced": False, "scheme": None, "reason": "no stored digest in the record"}
    algo = (binding.algorithm or "").lower()
    if re.search(r"hmac|rsa|ecdsa|ed25519|sign", algo):
        return {"reproduced": False, "scheme": None,
                "reason": f"keyed scheme {binding.algorithm!r}: cannot recompute without the key"}
    want = stored.strip()
    want_l = want.lower().split(":", 1)[-1]
    forms = canonical_forms(obj, binding.covered)
    algos = [a for a in _HASHES if a.replace("_", "") in algo.replace("-", "").replace("_", "")] or list(_HASHES)
    for a in algos:
        for form, data in forms.items():
            d = hashlib.new(a, data).digest()
            if want_l in (d.hex(), base64.b64encode(d).decode().lower(),
                          base64.urlsafe_b64encode(d).decode().rstrip("=").lower()):
                return {"reproduced": True, "scheme": f"{a}/{form}", "reason": "stored digest reproduced"}
    return {"reproduced": False, "scheme": None,
            "reason": "stored digest not reproduced by any tried canonical form"}


def _leaves(obj, prefix=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = f"{prefix}.{_sj.canonical_key(k)}" if prefix else _sj.canonical_key(k)
            if isinstance(v, (dict, list)):
                yield from _leaves(v, p)
            else:
                yield p, v
    elif isinstance(obj, list):
        for v in obj[:50]:
            yield from _leaves(v, prefix + "[]")


# ----------------------------------------------------------------------------------- live probe

_CONCRETE = re.compile(r"([^.\[\]]+)|\[(\d+)\]")


def get_concrete(obj, path: str):
    """Value at a concrete path (``lineitems[0].hs_code`` / ``approval.status``); KeyError if absent.
    Names match by ``canonical_key`` so ``hsCode`` finds ``hs_code``."""
    cur = obj
    for name, idx in _CONCRETE.findall(path.replace("/", ".")):
        if idx or name.isdigit():
            i = int(idx or name)
            if not isinstance(cur, list) or i >= len(cur):
                raise KeyError(path)
            cur = cur[i]
        else:
            if not isinstance(cur, dict):
                raise KeyError(path)
            key = _key_for(cur, _sj.canonical_key(name))
            if key is None:
                raise KeyError(path)
            cur = cur[key]
    return cur


def _web_toolkit():
    """The web toolkit module that holds the scope-locked ``WebClient`` (solvers/toolkits/web.py).

    A flat ``import web`` can resolve to solvers/web itself when solvers/ is on sys.path, so a
    module without ``WebClient`` is not accepted: the toolkit is then loaded by file."""
    try:
        import web as mod  # flat owner on the engine sys.path: solvers/toolkits/web.py
        if hasattr(mod, "WebClient"):
            return mod
    except ImportError:
        pass
    import importlib.util
    name = "_integrity_binding_web"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, HERE.parent / "toolkits" / "web.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


class StateChangeRefused(_web_toolkit().OutOfScope):
    """The active event profile does not authorise state-changing web actions (rules.web_state_changing,
    Open O-2). Raised before any request is sent. A subclass of the web toolkit's OutOfScope (itself a
    ``ctf.scope.OutOfScope``), as flow_recorder's is, so ``except ctf.scope.OutOfScope`` catches it."""


def _ctf_modules():
    """``(ctf.event, ctf.scope)`` from this checkout."""
    try:
        from ctf import event as ev, scope as sc
    except ImportError:  # direct solver-directory run: put the checkout root on sys.path
        root = str(HERE.parents[1])
        if root not in sys.path:
            sys.path.insert(0, root)
        from ctf import event as ev, scope as sc
    return ev, sc


def _active_profile():
    """The event profile in force: the one scope pinned (tests, a pinned run), else event.current().
    The same rule flow_recorder uses, so the active profile is the only O-2 switch."""
    ev, sc = _ctf_modules()
    prof = sc.pinned()
    return prof if prof is not None else ev.current()


def _wsc(profile) -> bool:
    return bool(getattr(getattr(profile, "rules", None), "web_state_changing", False))


def o2_gate(profile=None) -> tuple[bool, str]:
    """``(allowed, reason)`` for state-changing web actions (rules.web_state_changing, Open O-2).

    Decided by the *active* event profile only (``scope.pinned()`` else ``event.current()``); a caller's
    ``profile`` argument cannot widen it. A passed profile whose switch disagrees with the active one is
    refused outright, and no loadable active profile fails closed with a named reason."""
    try:
        active = _active_profile()
    except Exception as exc:
        return False, f"no active event profile ({type(exc).__name__}): state-changing web refused"
    slug = getattr(active, "slug", "?")
    if profile is not None and _wsc(profile) != _wsc(active):
        return False, (f"the profile passed in ({getattr(profile, 'slug', '?')!r}, web_state_changing="
                       f"{_wsc(profile)}) disagrees with the active event profile {slug!r} "
                       f"(web_state_changing={_wsc(active)}): refused")
    if not _wsc(active):
        return False, (f"event {slug!r} has rules.web_state_changing = false (Open O-2): the binding-gap "
                       f"probe writes to the target, so it is refused; set it in events/<slug>/event.toml "
                       f"to allow")
    return True, f"event {slug!r} sets web_state_changing = true"


def state_changes_allowed(profile=None) -> bool:
    """Whether the active event profile authorises state-changing web actions (see ``o2_gate``)."""
    return o2_gate(profile)[0]


@dataclasses.dataclass
class ProbeResult:
    verdict: str            # gap_confirmed | rebound | reopened | not_applied | write_rejected | refused
                            # | ambiguous_mutation | precondition | budget
    requests: int = 0
    before: dict = dataclasses.field(default_factory=dict)
    after: dict = dataclasses.field(default_factory=dict)
    write_status: int | None = None
    decision_status: int | None = None
    flags: list = dataclasses.field(default_factory=list)
    notes: list = dataclasses.field(default_factory=list)

    def to_dict(self):
        return dataclasses.asdict(self)


def _doc_of(resp) -> dict | None:
    if not isinstance(resp, dict) or resp.get("truncated"):
        return None
    body = resp.get("body", b"")
    text = body.decode("utf-8", "replace") if isinstance(body, (bytes, bytearray)) else str(body or "")
    try:
        val = _sj.loads(text.strip())
    except ValueError:
        return None
    return val if isinstance(val, dict) else None


def _body_text(resp) -> str:
    body = resp.get("body", b"") if isinstance(resp, dict) else b""
    return body.decode("utf-8", "replace") if isinstance(body, (bytes, bytearray)) else str(body or "")


def probe_gap(client, profile, *, resource_route: str, field: str, value, write_route: str,
              binding_field: str, status_field: str | None = None, write_method: str = "PATCH",
              body_extra: dict | None = None, decision_route: str | None = None,
              decision_method: str = "POST", max_requests: int = 6, find_flags=None) -> ProbeResult:
    """Amend one uncovered field after approval and check the binding stays valid.

    ``client`` is a scope-locked ``WebClient`` (``request(method, route, data=, headers=,
    allow_redirects=)`` returning a response dict). ``field`` is the concrete path on the record
    (``lineitems[0].hs_code``); the write body is ``{<leaf>: value, **body_extra}`` sent as JSON.
    Refused, with no request sent, unless the *active* event profile (``scope.pinned()`` else
    ``event.current()``) sets ``rules.web_state_changing`` and ``profile`` agrees with it. The whole
    group (read, write, readback[, decision]) is reserved against ``max_requests`` before the first
    request; after the write is sent a transport failure, 408/425/429 or a 5xx ends the probe as
    ``ambiguous_mutation`` with no further request.
    """
    res = ProbeResult("refused")
    allowed, why = o2_gate(profile)
    if not allowed:
        raise StateChangeRefused(why)
    write_method = str(write_method).upper()
    decision_method = str(decision_method).upper()
    if write_method not in WRITE_METHODS or (decision_route and decision_method not in WRITE_METHODS):
        raise ValueError(f"write/decision method must be one of {sorted(WRITE_METHODS)}")
    needed = 3 + (1 if decision_route else 0)
    if max_requests < needed:
        res.verdict = "budget"
        res.notes.append(f"the probe needs {needed} requests reserved up front; max_requests={max_requests}")
        return res
    leaf_name = _CONCRETE.findall(field.replace("/", "."))[-1][0]
    if not leaf_name:
        raise ValueError(f"field {field!r} does not end in a field name")

    def send(method, route, data=None):
        res.requests += 1
        headers = {"Content-Type": "application/json"} if data is not None else {}
        return client.request(method, route, data=data, headers=headers, allow_redirects=False)

    def snapshot(doc):
        snap = {}
        for label, path in (("binding", binding_field), ("field", field), ("status", status_field)):
            if path:
                try:
                    snap[label] = get_concrete(doc, path)
                except KeyError:
                    snap[label] = None
        return snap

    try:
        r0 = send("GET", resource_route)
    except Exception as exc:  # nothing mutated yet: a plain stop
        res.verdict = "precondition"
        res.notes.append(f"record read failed: {type(exc).__name__}")
        return res
    d0 = _doc_of(r0)
    if not (isinstance(r0.get("status"), int) and 200 <= r0["status"] < 300) or d0 is None:
        res.verdict = "precondition"
        res.notes.append("record read did not return an unambiguous JSON object")
        return res
    res.before = snapshot(d0)
    if res.before.get("binding") in (None, ""):
        res.verdict = "precondition"
        res.notes.append(f"binding field {binding_field!r} absent from the record: nothing to hold constant")
        return res
    if res.before.get("field") == value:
        res.verdict = "precondition"
        res.notes.append("the field already holds the probe value: choose a different value")
        return res
    body = dict(body_extra or {})
    body[leaf_name] = value
    try:
        r1 = send(write_method, write_route, json.dumps(body, separators=(",", ":")))
    except Exception as exc:
        res.verdict = "ambiguous_mutation"
        res.notes.append(f"write transport failed after send ({type(exc).__name__}): state unknown, stopped")
        return res
    st = r1.get("status") if isinstance(r1, dict) else None
    res.write_status = st
    if not isinstance(st, int) or st in (408, 425, 429) or st >= 500 or r1.get("truncated"):
        res.verdict = "ambiguous_mutation"
        res.notes.append(f"write answered {st!r}: state unknown, stopped with no further request")
        return res
    if not 200 <= st < 300:
        res.verdict = "write_rejected"
        res.notes.append(f"the target refused the amendment ({st}): the field is not mutable here")
        return res
    try:
        r2 = send("GET", resource_route)
    except Exception as exc:
        res.verdict = "ambiguous_mutation"
        res.notes.append(f"readback failed after the write ({type(exc).__name__})")
        return res
    d2 = _doc_of(r2)
    if d2 is None:
        res.verdict = "ambiguous_mutation"
        res.notes.append("readback did not return an unambiguous JSON object")
        return res
    res.after = snapshot(d2)
    if res.after.get("field") != value:
        res.verdict = "not_applied"
        res.notes.append("the write was accepted but the readback does not show the new value")
        return res
    if res.after.get("binding") != res.before.get("binding"):
        res.verdict = "rebound"
        res.notes.append("the binding value moved with the amendment: the server re-binds this field")
        return res
    if status_field and res.after.get("status") != res.before.get("status"):
        res.verdict = "reopened"
        res.notes.append("the approval status changed on amendment: the server re-opens approval")
        return res
    res.verdict = "gap_confirmed"
    res.notes.append("field amended after approval; binding value and status unchanged")
    if decision_route:
        try:
            r3 = send(decision_method, decision_route, json.dumps(body_extra or {}))
        except Exception as exc:
            res.notes.append(f"decision request failed ({type(exc).__name__})")
            return res
        res.decision_status = r3.get("status") if isinstance(r3, dict) else None
        if find_flags is not None:
            res.flags = list(dict.fromkeys(find_flags(_body_text(r3))))
    return res


# ----------------------------------------------------------------------------------- contract entry

_SPEC_NAME = re.compile(r"(?i)(schema|openapi|swagger|spec|api|signing|integrity|binding|approval)")
_SPEC_EXT = (".json", ".yaml", ".yml", ".txt", ".md", ".html", ".htm")
DEFAULT_SCHEMA_ROUTES = ("/schema", "/openapi.json", "/swagger.json", "/api/schema", "/api/openapi.json")
_TOKEN_HINT = re.compile(r"(?i)covered[_ ]fields|signed[_ ]fields|hashed[_ ]fields|bound[_ ]fields|"
                         r"signature covers|hash covers|binds? .{0,40} over")


def find_spec_files(challenge_dir: Path) -> list[Path]:
    """Files in the challenge folder that look like a binding spec (name or a covered-set token)."""
    out = []
    if not challenge_dir.is_dir():
        return out
    for i, p in enumerate(sorted(challenge_dir.rglob("*"))):
        if i > 5000 or len(out) >= MAX_SPEC_FILES:
            break
        if not p.is_file() or p.is_symlink() or p.suffix.lower() not in _SPEC_EXT:
            continue
        try:
            if p.stat().st_size > MAX_SPEC_CHARS:
                continue
            head = p.read_text("utf-8", "replace")
        except OSError:
            continue
        if _TOKEN_HINT.search(head) or (_SPEC_NAME.search(p.name) and p.suffix.lower() in (".json", ".yaml", ".yml")):
            out.append(p)
    return out


def _evidence_for(report: GapReport, source: str, Evidence):
    ev = []
    b = report.binding
    ev.append(Evidence("binding-spec",
                       f"{b.algorithm or 'unknown algorithm'} -> {b.binding_field or '?'} over "
                       f"{', '.join(b.covered)} ({b.source})", path=source))
    for g in report.gaps[:12]:
        detail = (f"{g.path} score={g.score}: not covered; mutable via {'; '.join(g.via)}; "
                  f"{'; '.join(g.reasons)}")
        if g.decision_mentions:
            detail += f"; decision text: {g.decision_mentions[0][:160]!r}"
        ev.append(Evidence("binding-gap", detail[:900], path=source))
    return ev


def _plan_note(report: GapReport) -> str:
    if not report.gaps:
        return ""
    top = report.gaps[0]
    writer = next((v for v in top.via if v[:1].isupper()), None)
    return (f"next: confirm {top.path} gates the decision, then probe with --opt target=URL "
            f"--opt resource=/<record> --opt field=<concrete path> --opt value=<value> "
            f"--opt write_route={writer.split(' ', 1)[1] if writer else '<route>'} "
            f"(needs rules.web_state_changing = true). Decisions: {', '.join(report.action_endpoints) or 'none documented'}")


def _load_json_opt(value, what):
    if value is None or isinstance(value, (dict, list)):
        return value
    if isinstance(value, str):
        try:
            return _sj.loads(value)
        except ValueError as exc:
            raise SpecError(f"{what} is not unambiguous JSON: {exc}") from exc
    raise SpecError(f"{what} must be a JSON object")


def solve(challenge_dir, profile, *, spec=None, sample=None, target=None, schema_route=None,
          resource=None, field=None, value=None, write_route=None, write_method="PATCH",
          binding_field=None, status_field=None, decision_route=None, extra=None, binding=0,
          max_requests=6, **_opts):
    """Find (and optionally probe) mutable fields outside a documented signature/hash covered set.

    Offline: ``spec`` (a path) or every spec-like file in ``challenge_dir``; ``sample`` a record JSON
    path for the digest recompute. With ``target``: GET the spec from ``schema_route`` (or the
    usual schema routes) and the record from ``resource`` -- reads only. With ``field``, ``value`` and
    ``write_route`` as well, run ``probe_gap`` (O-2 gated). Returns ``unsure`` with ranked gap
    evidence (the agent judges relevance), ``solved`` when a probed decision yields a flag,
    ``none`` when no binding or no gap is found, ``blocked`` naming what is missing or refused.
    """
    from ctf.result import SolverResult, Evidence, Cost
    from ctf import flagfmt

    started = time.process_time()
    challenge_dir = Path(challenge_dir)

    def cost():
        return Cost(seconds=round(time.process_time() - started, 3))

    texts: list[tuple[str, str]] = []
    client = None
    if spec is not None:
        p = Path(spec)
        if not p.is_absolute():
            p = challenge_dir / p
        if not p.is_file():
            return SolverResult(status="blocked", engine=ENGINE_ID, cost=cost(),
                                notes=f"spec file not found: {spec}")
        texts.append((str(p), p.read_text("utf-8", "replace")))
    if target:
        # Read-only unless a probe was asked for and the active profile allows it (O-2): the client
        # itself then refuses any non-GET, so analysis never depends on probe_gap refusing first.
        read_only = field is None or not state_changes_allowed(profile)
        try:
            client = _web_toolkit().WebClient(target, get_only=read_only)
        except Exception as exc:
            return SolverResult(status="blocked", engine=ENGINE_ID, cost=cost(),
                                notes=f"no scope-locked client for {target!r}: {type(exc).__name__}: {exc}")
        if spec is None:
            routes = [schema_route] if schema_route else list(DEFAULT_SCHEMA_ROUTES)
            misses = []
            for route in routes:
                try:
                    r = client.request("GET", route, allow_redirects=False)
                except Exception as exc:
                    if schema_route:
                        return SolverResult(status="blocked", engine=ENGINE_ID, cost=cost(),
                                            notes=f"GET {route} failed: {type(exc).__name__}: {exc}")
                    misses.append(f"{route}: {type(exc).__name__}")
                    continue
                if isinstance(r.get("status"), int) and 200 <= r["status"] < 300 and not r.get("truncated"):
                    texts.append((f"{target.rstrip('/')}{route}", _body_text(r)))
                    break
                misses.append(f"{route}: {r.get('status')!r}" + (" truncated" if r.get("truncated") else ""))
            if not texts:
                return SolverResult(status="blocked", engine=ENGINE_ID, cost=cost(),
                                    notes=f"no spec served ({'; '.join(misses)}): pass --opt schema_route=")
    if not texts:
        files = find_spec_files(challenge_dir)
        texts = [(str(p), p.read_text("utf-8", "replace")) for p in files]
    if not texts:
        return SolverResult(status="none", engine=ENGINE_ID, cost=cost(),
                            notes="no binding spec found (pass --opt spec=PATH or --opt target=URL)")

    errors, chosen = [], None
    for source, text in texts:
        try:
            doc = parse_spec(text, source)
        except SpecError as exc:
            errors.append(f"{source}: {exc}")
            continue
        if doc.bindings:
            chosen = (source, doc)
            break
    if chosen is None:
        why = "; ".join(errors) if errors else "no covered-field list in any spec read"
        return SolverResult(status="none", engine=ENGINE_ID, cost=cost(), notes=why[:900])
    source, doc = chosen
    try:
        if isinstance(sample, str) and not sample.lstrip().startswith(("{", "[")):
            sp = Path(sample) if Path(sample).is_absolute() else challenge_dir / sample
            if not sp.is_file():
                raise SpecError(f"sample file not found: {sample}")
            sample = sp.read_text("utf-8", "replace")
        sample_obj = _load_json_opt(sample, "sample")
    except (SpecError, OSError) as exc:
        return SolverResult(status="blocked", engine=ENGINE_ID, cost=cost(), notes=str(exc))
    sample_notes = []
    if sample_obj is None and client is not None and resource:
        try:
            r = client.request("GET", resource, allow_redirects=False)
        except Exception as exc:
            sample_notes.append(f"record GET {resource} failed ({type(exc).__name__}): analysed without "
                                f"a sample record")
        else:
            st = r.get("status") if isinstance(r, dict) else None
            sample_obj = _doc_of(r) if isinstance(st, int) and 200 <= st < 300 else None
            if sample_obj is None:
                sample_notes.append(f"record GET {resource} answered {st!r} without an unambiguous JSON "
                                    f"object: analysed without a sample record")
    report = find_gaps(doc, binding=int(binding), sample=sample_obj)
    evidence = _evidence_for(report, source, Evidence)
    notes = sample_notes + list(report.notes)
    if sample_obj is not None:
        rc = recompute_binding(sample_obj, report.binding)
        notes.append(f"recompute: {rc['reason']}" + (f" ({rc['scheme']})" if rc["scheme"] else ""))
        if rc["reproduced"]:
            evidence.append(Evidence("binding-reproduced", f"stored digest = {rc['scheme']} over the "
                                                           f"documented covered set", path=source))

    if field is not None:
        if client is None or not (resource and write_route) or value is None:
            return SolverResult(status="blocked", engine=ENGINE_ID, cost=cost(), evidence=tuple(evidence),
                                notes="a probe needs target, resource, field, value and write_route")
        bfield = binding_field or report.binding.binding_field
        if not bfield:
            return SolverResult(status="blocked", engine=ENGINE_ID, cost=cost(), evidence=tuple(evidence),
                                notes="no binding field documented: pass --opt binding_field=")
        ff = flagfmt.for_profile(profile)
        try:
            pr = probe_gap(client, profile, resource_route=resource, field=field, value=value,
                           write_route=write_route, binding_field=bfield, status_field=status_field,
                           write_method=write_method, body_extra=_load_json_opt(extra, "extra"),
                           decision_route=decision_route, max_requests=int(max_requests),
                           find_flags=ff.find_flags)
        except StateChangeRefused as exc:
            return SolverResult(status="blocked", engine=ENGINE_ID, cost=cost(), evidence=tuple(evidence),
                                notes=str(exc))
        evidence.append(Evidence("binding-probe", json.dumps(pr.to_dict(), default=str)[:900]))
        if pr.flags:
            return SolverResult(status="solved", flags=tuple(pr.flags), evidence=tuple(evidence),
                                engine=ENGINE_ID, cost=cost(), notes=f"probe {pr.verdict}; decision answered")
        status = "unsure" if pr.verdict == "gap_confirmed" else "none"
        return SolverResult(status=status, evidence=tuple(evidence), engine=ENGINE_ID, cost=cost(),
                            notes=f"probe {pr.verdict}: " + "; ".join(pr.notes + sample_notes))

    if not report.gaps:
        return SolverResult(status="none", evidence=tuple(evidence), engine=ENGINE_ID, cost=cost(),
                            notes="; ".join(notes + ["every documented mutable field is covered"])[:900])
    notes.append(_plan_note(report))
    return SolverResult(status="unsure", evidence=tuple(evidence), engine=ENGINE_ID, cost=cost(),
                        notes="; ".join(n for n in notes if n)[:1500])


# ----------------------------------------------------------------------------------- CLI

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Diff a documented signature/hash covered set against "
                                             "the spec's mutable fields (offline; reads data only).")
    ap.add_argument("spec", help="spec file (JSON, YAML or text)")
    ap.add_argument("--sample", help="a record JSON, to recompute its stored digest")
    ap.add_argument("--binding", type=int, default=0, help="which documented binding to diff")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    try:
        doc = parse_spec(Path(a.spec).read_text("utf-8", "replace"), a.spec)
        sample = _load_json_opt(Path(a.sample).read_text("utf-8", "replace"), "sample") if a.sample else None
        report = find_gaps(doc, binding=a.binding, sample=sample)
    except (SpecError, OSError, IndexError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    out = report.to_dict()
    if sample is not None and report.binding:
        out["recompute"] = recompute_binding(sample, report.binding)
    if a.json:
        print(json.dumps(out, indent=2, default=str))
        return 0
    if report.binding is None:
        print("no covered-field list found")
        return 0
    b = report.binding
    print(f"binding: {b.algorithm or '?'} -> {b.binding_field or '?'} over {', '.join(b.covered)}")
    for g in report.gaps:
        print(f"  GAP {g.score:3d} {g.path}  via {'; '.join(g.via)}  [{'; '.join(g.reasons)}]")
    if report.meta_ignored:
        print(f"  (request metadata set aside: {', '.join(report.meta_ignored)})")
    if report.action_endpoints:
        print(f"decisions: {', '.join(report.action_endpoints)}")
    if "recompute" in out:
        print(f"recompute: {out['recompute']['reason']} {out['recompute']['scheme'] or ''}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
