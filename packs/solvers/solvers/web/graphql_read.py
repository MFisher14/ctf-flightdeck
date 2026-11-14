#!/usr/bin/env python3
"""Bounded, query-only GraphQL authorization reader for a live web target.

This module covers one deliberately narrow class: a target-local clue document
advertises a feature route and a protected reference, and that same target says
that the route is GraphQL/resolver/schema/field-level related.  The reader:

1. records a GET control for the advertised route;
2. sends a generated Query-root introspection operation to that route; and
3. sends a generated Query-root read using the advertised reference.

POST remains the default transport.  GET is used only when the target-local clue
document explicitly says that GraphQL is GET-only; its generated query,
variables and optional APQ extension are independently URL-encoded under a hard
URL cap.  If introspection is disabled, a generated Federation ``_service`` SDL
control is allowed only when the clues/control explicitly advertise Apollo
Federation, ``_service`` and SDL.  The returned SDL is subtraction-only and a
small non-executing parser may derive at most three safe Query-root reads.

It never constructs a mutation, subscription, batch, upload, login, credential
replay, or target-supplied query document.  Every identifier comes from a parsed
schema and is validated as a GraphQL name; the protected value travels in JSON
``variables`` rather than being interpolated into the query.  Every live request
uses ``solvers/toolkits/web.py``'s scope-locked ``WebClient`` and is bounded by a
single absolute deadline, a per-target request count, and an optional shared stop
event.

Contract::

    solve(target, ctx=None) -> the event's payoff token | None  (ctf.flagfmt.payoff_kind)
    solve_targets(targets, ctx=None) -> {answer_id: proof | None}

``ctx`` accepts ``deadline``, ``max_requests``, ``log_dir``, ``challenge``,
``evidence`` (a mutable list), ``result_sink`` (a mutable dict), and, for tests or
future proof-hunt integration, ``client``/``client_factory``, ``preloaded`` GET
responses, ``baseline_texts`` and ``stop``.

Never-wrong proof rule.  A value is returned only from ``data.<generated alias>``
of a successful, error-free generated read, when it is the sole *novel* lowercase
exact payoff token (a proof under a proof event, else a flag) after subtracting values already present in the plain
pages, endpoint control, or introspection control.  A distinct baseline decoy does
not hide the novel payoff; the same value in baseline and payoff is ineligible,
and two novel payoff values are ambiguous.  UUID-v4 nibbles are diagnostic only.
A different-shaped novel flag-format value is surfaced to the agent through
``ctx['evidence']`` and the log, but is never returned or submitted.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import html
import json
import math
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
_TOOLKITS = HERE.parent / "toolkits"
if str(_TOOLKITS) not in sys.path:
    sys.path.insert(0, str(_TOOLKITS))
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import web as _web  # noqa: E402 -- the scope-locked live-target client
import security_json as _security_json  # noqa: E402 -- fail-closed policy JSON

try:
    import forge_event as _proof_policy  # noqa: E402 -- shared bounded response decoding
except Exception:  # pragma: no cover - partial exports retain the historical raw path
    _proof_policy = None


REQUEST_TIMEOUT = 8.0
DEADLINE_PAD = 0.3
DEFAULT_SECONDS = 30.0
DEFAULT_MAX_REQUESTS = 8
MAX_BODY = 400_000
MAX_ROUTE_BYTES = 1024
MAX_REQUEST_BODY_BYTES = 32 * 1024
MAX_GET_URL_BYTES = 12 * 1024
MAX_SCHEMA_TYPES = 500
MAX_FIELDS = 12
MAX_CANDIDATE_QUERIES = 3
MAX_ABSTRACT_TYPES = 4
MAX_SELECTION_DEPTH = 5
MAX_SELECTION_NODES = 48
MAX_INPUT_DEPTH = 4
MAX_INPUT_FIELDS = 24
MAX_LIST_LIMIT = 8
MAX_SDL_BYTES = 128 * 1024
MAX_SDL_TOKENS = 12_000
MAX_SDL_FIELDS = 2_000
MAX_MANIFEST_BYTES = 256 * 1024
MAX_MANIFEST_ENTRIES = 512
MAX_BASELINE_TEXTS = 40
MAX_BASELINE_SCAN_CHARS = 1 << 20
MAX_NUMERIC_REFERENCE_CHARS = 256

GRAPHQL_NAME = re.compile(r"^[_A-Za-z][_0-9A-Za-z]{0,127}$")
GRAPHQL_LOCAL_EVIDENCE = re.compile(
    r"(?i)\b(?:graphql(?:\.js)?|graph[ -]?garden|resolver|query[ -]?root|"
    r"schema introspection|field[- ]level(?: authorization| checks?)?)\b"
)
FORBIDDEN_OPERATION = re.compile(r"(?i)\b(?:mutation|subscription)\b")
GET_ONLY_HINT = re.compile(r"(?i)(?:\bGET\b.{0,32}\bONLY\b|\bONLY\b.{0,32}\bGET\b|^\s*GET\s*$)")
FEDERATION_WORD = re.compile(r"(?i)\b(?:apollo[ -]?federation|federated[ -]?graphql)\b")
FEDERATION_SERVICE = re.compile(r"(?i)(?:\b_service\b|[\"']_service[\"'])")
FEDERATION_SDL = re.compile(r"(?i)\bSDL\b")
PERSISTED_QUERY_REQUIRED = re.compile(
    r"(?i)(?:persisted[ _-]?query|persistedquery).{0,80}(?:required|missing|not[ _-]?found|only)|"
    r"(?:required|missing).{0,80}(?:persisted[ _-]?query|persistedquery)|PERSISTED_QUERY_NOT_FOUND"
)
INTROSPECTION_DISABLED = re.compile(
    r"(?i)(?:introspection.{0,48}(?:disabled|forbidden|not[ _-]?allowed|denied)|"
    r"(?:disabled|forbidden|denied).{0,48}introspection)"
)
DESTRUCTIVE_NAME = re.compile(
    r"(?i)(?:^|_)(?:create|write|update|delete|destroy|drop|remove|reset|redeem|"
    r"login|logout|signout|submit|approve|promote|mutate|mutation|subscription|execute|run|upload|"
    r"transfer|pay|issue|revoke|disable|cancel)(?:$|_)"
)
DESTRUCTIVE_PATH = re.compile(
    r"(?i)(?:^|[/_.-])(?:create|write|update|delete|destroy|drop|wipe|purge|remove|truncate|erase|"
    r"reset|redeem|revoke|approve|promote|mutate|execute|run|upload|issue|logout|signout|disable|"
    r"deactivate|uninstall|kill|shutdown|reboot|ban|suspend|cancel|rollback|restore|transfer|pay)"
    r"(?=$|[/_.-]|\d)"
)

# The event's payoff token (ctf.flagfmt): a proof under a proof event, else a flag.
PAYOFF_WIRE = flagfmt.PAYOFF_TEXT     # exact: the only value returned
PAYOFF_LIKE = flagfmt.PAYOFF_SHAPE    # payoff-shaped near misses, any case: seen, never returned
OTHER_LIKE = flagfmt.PAYOFF_OTHER     # the other family's shapes: seen, never returned
# A proof carried only inside a URL for another host is a reference/decoy, not
# target-returned answer material.  Match every hierarchical URI scheme and
# protocol-relative URL, not only HTTP(S).  Encoded authority URLs are handled
# separately in ``_strip_offhost_urls`` below.
ABSOLUTE_URL = re.compile(
    r"(?i)(?<![A-Za-z0-9+.-])(?:[A-Za-z][A-Za-z0-9+.-]{0,31}:)?//[^\s<>'\"\\{}\[\]]{1,2048}"
)
ENCODED_ABSOLUTE_URL = re.compile(
    r"(?i)(?<![A-Za-z0-9%+.-])(?:[A-Za-z][A-Za-z0-9+.-]{0,31}(?::|%3A))?"
    r"(?:(?:/|%2F){2})[^\s<>'\"\\{}\[\]]{1,4096}"
)
PAYOFF_V4 = flagfmt.PAYOFF_UUID4
STRONG_LABEL = re.compile(
    r"(?i)(?:^|[_-])(?:proof|evidence|flag|objective|answer|submission|secret|token|value|success)(?:$|[_-])"
)
SOFT_LABELS = {"note", "message", "content", "body", "result"}
BASELINE_INCOMPLETE_MARKER = getattr(
    _proof_policy, "BASELINE_STRICT_INCOMPLETE",
    "<!-- csctf-baseline-strict-set:incomplete -->",
)

# Words which, together with punctuation, can only describe an already-found
# wire proof.  This deliberately stays narrow: any other residual text makes a
# soft-labelled scalar a distinct candidate and therefore suppresses PLAIN.
_WIRE_WRAPPER_WORDS = {
    "a", "accepted", "an", "answer", "body", "content", "evidence", "equals",
    "flag", "found", "here", "is", "message", "note", "objective", "ok", "proof",
    "result", "returned", "secret", "submission", "success", "successful", "that",
    "the", "this", "token", "value", "was", "your",
}

ROUTE_KEYS = ("graphql_route", "query_route", "feature_route", "endpoint")
REFERENCE_KEYS = ("protected_reference", "protected_id", "reference_id", "target_reference")
ARG_RANK = ("id", "reference", "reference_id", "ref", "case_id", "record_id", "object_id", "key", "identifier")
FIELD_RANK = ("case", "record", "object", "item", "entry", "reference", "detail", "inspect", "lookup", "node")
SCALAR_RANK = ("proof", "evidence", "objective", "note", "flag", "secret", "value", "content",
               "message", "body", "result", "id", "title", "name")
OBJECT_RANK = ("evidence", "proof", "objective", "flag", "details", "detail", "payload", "result",
               "record", "case", "item", "node", "edges", "nodes", "connection")
METHOD_KEYS = ("graphql_method", "graphql_transport", "transport_method", "http_method",
               "request_method", "method")
INPUT_KEYS = ("graphql_input", "query_input", "protected_input", "input_object")
INPUT_REFERENCE_FIELD_KEYS = ("graphql_input_reference_field", "input_reference_field")
LIST_LIMIT_KEYS = ("graphql_list_limit", "query_list_limit", "page_size")


# This is generated by this module, never copied from a target.  It intentionally
# asks for Query only; mutationType/subscriptionType are absent.
INTROSPECTION_QUERY = """query GraphQLReadSchema {
  __schema {
    queryType { name }
    types {
      kind
      name
      fields(includeDeprecated: true) {
        name
        args {
          name
          defaultValue
          type { kind name ofType { kind name ofType { kind name ofType { kind name } } } }
        }
        type { kind name ofType { kind name ofType { kind name ofType { kind name } } } }
      }
      inputFields {
        name
        defaultValue
        type { kind name ofType { kind name ofType { kind name ofType { kind name } } } }
      }
      possibleTypes { kind name }
    }
  }
}"""

FEDERATION_SDL_QUERY = "query FederationSDL { _service { sdl } }"


def enabled() -> bool:
    """Default-on read-only class with an environment/file kill switch."""
    raw = ctf_env.get("CTF_WEB_GRAPHQL_READ")
    if raw is not None:
        return raw.strip().lower() not in ("off", "0", "false", "no")
    try:
        root = ctf_paths.workdir()
        return not (root / "_web_graphql_read.off").exists()
    except Exception:
        return False


def _text(response) -> str:
    if not isinstance(response, dict):
        return ""
    if _proof_policy is not None and hasattr(_proof_policy, "response_text_views"):
        try:
            views = _proof_policy.response_text_views(response)
            return str(views[0])[:MAX_BODY] if views else ""
        except Exception:
            return ""
    value = response.get("body")
    if value is None:
        value = response.get("text")
    if isinstance(value, (bytes, bytearray)):
        return bytes(value[:MAX_BODY]).decode("utf-8", "replace")
    return str(value or "")[:MAX_BODY]


def _coherent_texts(response):
    """Independent target-authored body views for control predicates.

    Federation authorization must not be assembled from unrelated responses or
    MIME/archive siblings.  Keep this separate from ``_baseline_text``: joined
    baseline evidence is intentionally conservative for subtraction, but is not
    a positive protocol contract.
    """
    if not isinstance(response, dict):
        return []
    if _proof_policy is not None and hasattr(_proof_policy, "response_text_views"):
        try:
            return [str(value)[:MAX_BODY]
                    for value in list(_proof_policy.response_text_views(response))[:256]]
        except Exception:
            return []
    value = response.get("body")
    if value is None:
        value = response.get("text")
    if isinstance(value, (bytes, bytearray)):
        try:
            text = bytes(value[:MAX_BODY]).decode("utf-8", "strict")
        except UnicodeDecodeError:
            return []
    else:
        text = str(value or "")[:MAX_BODY]
    return [text] if text else []


def _baseline_text(response) -> str:
    if _proof_policy is not None and hasattr(_proof_policy, "response_baseline_text"):
        try:
            return _proof_policy.response_baseline_text(response)
        except Exception:
            return ""
    text = _text(response)
    raw = response.get("response_headers", response.get("headers", {})) if isinstance(response, dict) else {}
    headers = "\n".join(str(value)[:4096] for value in raw.values()) if isinstance(raw, dict) else ""
    return (text + ("\n" + headers if headers else ""))[:MAX_BODY]


def _json(response):
    views = None
    if _proof_policy is not None and hasattr(_proof_policy, "response_text_views"):
        try:
            views = _proof_policy.response_text_views(response)
        except Exception:
            return None
    try:
        return _security_json.loads_unique(
            views if views is not None else [_text(response)], max_chars=MAX_BODY)
    except Exception:
        return None


def _response(raw):
    if not isinstance(raw, dict):
        return None
    if "body" in raw:
        return raw
    if "text" in raw:
        out = dict(raw)
        out["body"] = str(raw.get("text") or "").encode("utf-8")
        return out
    return None


def _walk_scalars(value, path=(), depth=0, *, state=None, active=None):
    """Walk a parsed GraphQL result without silently accepting a prefix.

    ``security_json`` already rejects response documents beyond these global
    limits.  Mirror those limits here because tests and future callers can pass
    an already-built value directly.  Older per-container slices (200 members)
    and the depth-10 return were unsafe: a target could put a second labelled
    answer just beyond the scanned prefix and make the first proof look unique.
    When a non-JSON cyclic/over-limit value is supplied, mark the scan
    incomplete so ``_result_evidence`` can still surface bounded candidates but
    can never auto-return one.
    """
    if state is None:
        state = {"nodes": 0, "members": 0, "incomplete": False}
    if active is None:
        active = set()

    state["nodes"] += 1
    if (state["nodes"] > _security_json.DEFAULT_MAX_NODES
            or depth > _security_json.DEFAULT_MAX_DEPTH):
        state["incomplete"] = True
        return

    if isinstance(value, (dict, list)):
        identity = id(value)
        if identity in active:
            state["incomplete"] = True
            return
        active.add(identity)
        try:
            if isinstance(value, dict):
                state["members"] += len(value)
                if state["members"] > _security_json.DEFAULT_MAX_MEMBERS:
                    state["incomplete"] = True
                    return
                for key, child in value.items():
                    yield from _walk_scalars(
                        child, path + (str(key),), depth + 1,
                        state=state, active=active)
                    if state["incomplete"]:
                        return
            else:
                for index, child in enumerate(value):
                    yield from _walk_scalars(
                        child, path + (str(index),), depth + 1,
                        state=state, active=active)
                    if state["incomplete"]:
                        return
        finally:
            active.remove(identity)
    elif isinstance(value, (str, int, float)) and not isinstance(value, bool):
        yield path, str(value)


def _same_origin_route(value, base_url):
    """Return a same-origin site-relative route, or None on any ambiguous path."""
    try:
        path = _web.safe_same_origin_route(
            value, base_url, allow_query=False, max_bytes=MAX_ROUTE_BYTES)
        if path is None:
            return None
        for layer in _web.canonical_route_layers(path, max_bytes=MAX_ROUTE_BYTES) or ():
            folded = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", layer)
            if (DESTRUCTIVE_PATH.search(folded)
                    or _web.route_has_destructive_action(layer)):
                return None
        return path
    except Exception:
        return None


def _coherent_alias(clues, keys, normalizer, *, scalar_types=(str,)):
    """Return one normalized alias value; reject malformed or conflicting peers."""
    if not isinstance(clues, dict):
        return None, False
    values = []
    present = False
    for key in keys:
        if key not in clues:
            continue
        present = True
        raw = clues.get(key)
        if isinstance(raw, bool) or not isinstance(raw, scalar_types):
            return None, False
        try:
            value = normalizer(raw)
        except Exception:
            return None, False
        if value is None:
            return None, False
        if value not in values:
            values.append(value)
    if not present:
        return None, True
    return (values[0], True) if len(values) == 1 else (None, False)


def _coherent_reference(clues):
    values = []
    identities = []
    for key in REFERENCE_KEYS:
        if key not in clues:
            continue
        value = clues.get(key)
        if value is None or isinstance(value, (dict, list)):
            return None, False
        identity = (type(value), value)
        if identity not in identities:
            identities.append(identity)
            values.append(value)
    if not values:
        return None, True
    return (values[0], True) if len(values) == 1 else (None, False)


def _coherent_transport(clues):
    methods = []
    for key in METHOD_KEYS:
        if key not in clues:
            continue
        value = clues.get(key)
        if not isinstance(value, str):
            return None, False
        named = set(re.findall(r"\b(?:GET|POST|PUT|PATCH|DELETE)\b", value.upper()))
        if len(named) != 1:
            return None, False
        method = next(iter(named))
        if method not in methods:
            methods.append(method)
    if not methods:
        return "POST", True
    if len(methods) != 1 or methods[0] not in ("GET", "POST"):
        return None, False
    return methods[0], True


def _coherent_input_contract(clues):
    """Return one explicit input-object value and optional reference-field hint.

    Input objects are authority-bearing request data.  Do not merge aliases or
    borrow sibling values: one coherent clue document must spell one mapping.
    ``security_json`` has already rejected duplicate/canonical-colliding keys.
    """
    mappings = []
    for key in INPUT_KEYS:
        if key not in clues:
            continue
        value = clues.get(key)
        if not isinstance(value, dict) or len(value) > MAX_INPUT_FIELDS:
            return None, None, False
        if value not in mappings:
            mappings.append(value)
    hints = []
    for key in INPUT_REFERENCE_FIELD_KEYS:
        if key not in clues:
            continue
        value = clues.get(key)
        if not isinstance(value, str) or not GRAPHQL_NAME.fullmatch(value):
            return None, None, False
        if value not in hints:
            hints.append(value)
    if len(mappings) > 1 or len(hints) > 1:
        return None, None, False
    return (mappings[0] if mappings else None), (hints[0] if hints else None), True


def _coherent_list_limit(clues):
    values = []
    for key in LIST_LIMIT_KEYS:
        if key not in clues:
            continue
        value = clues.get(key)
        if isinstance(value, bool) or not isinstance(value, int) \
                or not 1 <= value <= MAX_LIST_LIMIT:
            return None, False
        if value not in values:
            values.append(value)
    if len(values) > 1:
        return None, False
    return (values[0] if values else MAX_LIST_LIMIT), True


def _query_only(document) -> bool:
    """A final belt-and-braces gate immediately before every POST."""
    if not isinstance(document, str) or not document or len(document) > 50_000:
        return False
    stripped = document.lstrip()
    if not (stripped.startswith("query ") or stripped.startswith("query{") or stripped.startswith("{")):
        return False
    return FORBIDDEN_OPERATION.search(document) is None


def _origin(value):
    try:
        parts = urllib.parse.urlsplit(str(value or ""))
        if (parts.scheme not in ("http", "https") or not parts.hostname
                or parts.username is not None or parts.password is not None
                or parts.fragment or "@" in parts.netloc):
            return None
        port = parts.port or (443 if parts.scheme == "https" else 80)
        return parts.scheme, parts.hostname.lower(), port
    except Exception:
        return None


def _client_matches_target(client, target_url) -> bool:
    """Injected clients must carry the same scope as this exact target origin."""
    client_origin = _origin(getattr(client, "base", None)) if client is not None else None
    target_origin = _origin(target_url)
    return client_origin is not None and target_origin is not None and client_origin == target_origin


def _type_expr(type_node, depth=0):
    if not isinstance(type_node, dict) or depth > 6:
        return None
    kind = type_node.get("kind")
    if kind == "NON_NULL":
        inner = _type_expr(type_node.get("ofType"), depth + 1)
        return inner + "!" if inner and not inner.endswith("!") else None
    if kind == "LIST":
        inner = _type_expr(type_node.get("ofType"), depth + 1)
        return "[" + inner + "]" if inner else None
    name = type_node.get("name")
    if kind in ("SCALAR", "ENUM", "INPUT_OBJECT") \
            and isinstance(name, str) and GRAPHQL_NAME.fullmatch(name):
        return name
    return None


def _base_type(type_node, depth=0):
    if not isinstance(type_node, dict) or depth > 6:
        return None, None
    kind = type_node.get("kind")
    if kind in ("NON_NULL", "LIST"):
        return _base_type(type_node.get("ofType"), depth + 1)
    name = type_node.get("name")
    return (kind, name) if isinstance(name, str) and GRAPHQL_NAME.fullmatch(name) else (None, None)


def _contains_type_kind(type_node, wanted, depth=0):
    if not isinstance(type_node, dict) or depth > 6:
        return False
    if type_node.get("kind") == wanted:
        return True
    return _contains_type_kind(type_node.get("ofType"), wanted, depth + 1)


def _is_required(arg) -> bool:
    return (isinstance(arg, dict) and isinstance(arg.get("type"), dict)
            and arg["type"].get("kind") == "NON_NULL" and arg.get("defaultValue") is None)


def _rank_name(name, ordered):
    low = str(name or "").lower()
    if low in ordered:
        return ordered.index(low)
    for index, word in enumerate(ordered):
        if word in low:
            return len(ordered) + index
    return len(ordered) * 3


def _destructive_identifier(name) -> bool:
    """Match both snake_case and camelCase action names from an untrusted schema."""
    folded = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(name or ""))
    return bool(DESTRUCTIVE_NAME.search(folded))


def _numeric_reference_value(reference, scalar_name):
    """Coerce one numeric clue value with a Python-3.9-safe work bound.

    A target controls the reference string and may publish hundreds of
    identifier-looking schema arguments.  Reject an oversized decimal lexeme
    before ``int``/``float`` and let ``_query_candidates`` cache this result
    once for each numeric scalar.
    """
    if scalar_name not in ("Int", "Float"):
        return None, False
    try:
        if isinstance(reference, bool):
            value = int(reference) if scalar_name == "Int" else float(reference)
        elif isinstance(reference, int):
            if scalar_name == "Int":
                value = reference
            else:
                # Conversion of an already-materialized million-bit integer is
                # unnecessary work and can only overflow a GraphQL Float.
                if reference.bit_length() > 1024:
                    return None, False
                value = float(reference)
        elif isinstance(reference, float):
            if not math.isfinite(reference):
                return None, False
            value = int(reference) if scalar_name == "Int" else reference
        else:
            if isinstance(reference, (bytes, bytearray)):
                if len(reference) > MAX_NUMERIC_REFERENCE_CHARS:
                    return None, False
                raw = bytes(reference).decode("ascii", "strict")
            else:
                raw = reference if isinstance(reference, str) else str(reference)
                if len(raw) > MAX_NUMERIC_REFERENCE_CHARS:
                    return None, False
            if len(raw) > MAX_NUMERIC_REFERENCE_CHARS:
                return None, False
            if scalar_name == "Int":
                value = _security_json.parse_int_lexeme(
                    raw, max_chars=MAX_NUMERIC_REFERENCE_CHARS)
            else:
                value = _security_json.parse_float_lexeme(
                    raw, max_chars=MAX_NUMERIC_REFERENCE_CHARS)
    except (ArithmeticError, TypeError, ValueError, UnicodeError):
        return None, False
    if scalar_name == "Int":
        return value, -(2 ** 31) <= value < 2 ** 31
    return value, math.isfinite(value)


def _variable_value(reference, type_node, numeric_cache=None):
    kind, name = _base_type(type_node)
    if kind not in ("SCALAR", "ENUM"):
        return None, False
    if name in ("Int", "Float"):
        if numeric_cache is None:
            return _numeric_reference_value(reference, name)
        if name not in numeric_cache:
            numeric_cache[name] = _numeric_reference_value(reference, name)
        return numeric_cache[name]
    if name == "Boolean":
        if reference is True or str(reference).lower() == "true":
            return True, True
        if reference is False or str(reference).lower() == "false":
            return False, True
        return None, False
    if isinstance(reference, (dict, list)) or reference is None:
        return None, False
    # ID, String, custom scalar and an explicitly advertised enum/reference.
    return str(reference), True


def _input_value(schema, type_node, reference, explicit, reference_field=None,
                 *, depth=0, active=(), numeric_cache=None):
    """Build one variables-only GraphQL input value from explicit clue bytes.

    Lists are deliberately refused: their ordering and multiplicity are
    authority, not a safe inference.  Nested input objects are accepted only
    when every supplied key exists in the introspected type and every required
    member is established.  A scalar protected reference may fill exactly one
    identifier-shaped member; an explicit field hint is required when several
    members could own it.  Cycles and excessive depth fail the whole value.
    """
    if depth > MAX_INPUT_DEPTH or _contains_type_kind(type_node, "LIST"):
        return None, False
    kind, name = _base_type(type_node)
    if kind in ("SCALAR", "ENUM"):
        return _variable_value(explicit, type_node, numeric_cache)
    if kind != "INPUT_OBJECT" or name in active:
        return None, False
    type_def = schema.get("by_name", {}).get(name)
    fields = type_def.get("inputFields") if isinstance(type_def, dict) else None
    if not isinstance(fields, list) or not fields or len(fields) > MAX_INPUT_FIELDS:
        return None, False
    supplied = explicit if isinstance(explicit, dict) else {}
    if any(not isinstance(key, str) or not GRAPHQL_NAME.fullmatch(key) for key in supplied):
        return None, False
    by_name = {}
    for field in fields:
        field_name = field.get("name") if isinstance(field, dict) else None
        if (not isinstance(field_name, str) or not GRAPHQL_NAME.fullmatch(field_name)
                or field_name in by_name):
            return None, False
        by_name[field_name] = field
    if set(supplied) - set(by_name):
        return None, False

    eligible = []
    for field_name, field in by_name.items():
        rank = _rank_name(field_name, ARG_RANK)
        base_kind, _base_name = _base_type(field.get("type"))
        if (rank < len(ARG_RANK) * 3 and base_kind in ("SCALAR", "ENUM")
                and not _contains_type_kind(field.get("type"), "LIST")):
            eligible.append(field_name)
    if depth > 0:
        owner = None
    elif reference_field is not None:
        if reference_field not in eligible:
            return None, False
        owner = reference_field
    elif len(eligible) == 1:
        owner = eligible[0]
    elif len(eligible) == 0:
        owner = None
    else:
        # Two plausible reference owners would make the generated request an
        # arbitrary schema-order choice.
        return None, False

    out = {}
    for field_name, field in by_name.items():
        present = field_name in supplied
        source = supplied.get(field_name)
        if field_name == owner:
            if present and not _same_scalar_value(source, reference):
                return None, False
            source, present = reference, True
        if not present:
            if _is_required(field):
                return None, False
            continue
        value, valid = _input_value(
            schema, field.get("type"), reference, source, None,
            depth=depth + 1, active=active + (name,), numeric_cache=numeric_cache)
        if not valid:
            return None, False
        out[field_name] = value
    return out, bool(out)


def _same_scalar_value(left, right):
    if isinstance(left, (dict, list)) or isinstance(right, (dict, list)):
        return False
    if type(left) is type(right):
        return left == right
    return str(left) == str(right)


def _schema(response):
    """Return a structurally validated introspection schema, else None."""
    if not isinstance(response, dict) or not isinstance(response.get("status"), int) \
            or not 200 <= response["status"] < 300:
        return None
    doc = _json(response)
    if not isinstance(doc, dict) or doc.get("errors"):
        return None
    data = doc.get("data")
    schema = data.get("__schema") if isinstance(data, dict) else None
    if not isinstance(schema, dict):
        return None
    query_name = (schema.get("queryType") or {}).get("name")
    types = schema.get("types")
    if not isinstance(query_name, str) or not GRAPHQL_NAME.fullmatch(query_name) \
            or not isinstance(types, list) or not types or len(types) > MAX_SCHEMA_TYPES:
        return None
    clean = [item for item in types if isinstance(item, dict) and isinstance(item.get("name"), str)
             and GRAPHQL_NAME.fullmatch(item["name"])]
    # Silently dropping malformed types or keeping the last duplicate lets an
    # untrusted introspection response choose a different schema than the one
    # the planner validated.
    names = [item["name"] for item in clean]
    if len(clean) != len(types) or len(set(names)) != len(names):
        return None
    by_name = {item["name"]: item for item in clean}
    query_type = by_name.get(query_name)
    if not isinstance(query_type, dict) or not isinstance(query_type.get("fields"), list):
        return None
    return {"query_name": query_name, "types": clean, "by_name": by_name, "query": query_type}


def _field_rows(type_def):
    fields = type_def.get("fields") if isinstance(type_def, dict) else None
    if not isinstance(fields, list) or len(fields) > MAX_SELECTION_NODES:
        return None
    seen, rows = set(), []
    for field in fields:
        if not isinstance(field, dict):
            return None
        name = field.get("name")
        if (not isinstance(name, str) or not GRAPHQL_NAME.fullmatch(name)
                or name.startswith("__") or name in seen):
            return None
        seen.add(name)
        args = field.get("args") or []
        if not isinstance(args, list) or any(not isinstance(arg, dict) for arg in args):
            return None
        if any(_is_required(arg) for arg in args):
            continue
        kind, _type_name = _base_type(field.get("type"))
        scalar_rank = _rank_name(name, SCALAR_RANK)
        object_rank = _rank_name(name, OBJECT_RANK)
        rows.append(((0 if kind in ("SCALAR", "ENUM") else 1,
                      min(scalar_rank, object_rank), name), field))
    return [row for _rank, row in sorted(rows, key=lambda item: item[0])]


def _selection_for_type(schema, type_name, *, depth=0, active=(), list_allowed=False,
                        state=None):
    """Return a bounded recursive selection body (without outer braces)."""
    if state is None:
        state = {"nodes": 0, "cycle": False, "list_refused": False}
    if depth > MAX_SELECTION_DEPTH or type_name in active:
        state["cycle"] = True
        return None
    type_def = schema.get("by_name", {}).get(type_name)
    if not isinstance(type_def, dict):
        return None
    kind = type_def.get("kind")
    if kind in ("INTERFACE", "UNION"):
        possible = type_def.get("possibleTypes")
        if (not isinstance(possible, list) or not possible
                or len(possible) > MAX_ABSTRACT_TYPES):
            return None
        names = []
        for row in possible:
            name = row.get("name") if isinstance(row, dict) else None
            if (not isinstance(name, str) or not GRAPHQL_NAME.fullmatch(name)
                    or name in names):
                return None
            names.append(name)
        parts = ["__typename"]
        for name in sorted(names):
            concrete = schema.get("by_name", {}).get(name)
            if not isinstance(concrete, dict) or concrete.get("kind") != "OBJECT":
                return None
            child = _selection_for_type(
                schema, name, depth=depth + 1, active=active + (type_name,),
                list_allowed=list_allowed, state=state)
            if child:
                parts.append(f"... on {name} {{ {child} }}")
        return " ".join(parts) if len(parts) > 1 else None
    if kind != "OBJECT":
        return None
    rows = _field_rows(type_def)
    if rows is None:
        return None
    parts = []
    for field in rows:
        if len(parts) >= MAX_FIELDS or state["nodes"] >= MAX_SELECTION_NODES:
            break
        field_name = field["name"]
        field_type = field.get("type")
        contains_list = _contains_type_kind(field_type, "LIST")
        # A root pagination argument bounds only the Relay collection it
        # directly owns.  It does not authorize arbitrary lists nested under
        # a node (comments, attachments, related objects, ...).
        relay_list = bool(contains_list and list_allowed
                          and field_name.lower() in ("edges", "nodes"))
        if contains_list and not relay_list:
            state["list_refused"] = True
            continue
        # A list of lists has no unambiguous bounded Relay meaning here.
        if contains_list:
            inner = field_type
            list_count = 0
            for _ in range(7):
                if not isinstance(inner, dict):
                    break
                if inner.get("kind") == "LIST":
                    list_count += 1
                inner = inner.get("ofType")
            if list_count != 1:
                state["list_refused"] = True
                continue
        child_kind, child_name = _base_type(field_type)
        state["nodes"] += 1
        if child_kind in ("SCALAR", "ENUM"):
            parts.append(field_name)
            continue
        if child_kind not in ("OBJECT", "INTERFACE", "UNION"):
            continue
        child = _selection_for_type(
            schema, child_name, depth=depth + 1, active=active + (type_name,),
            list_allowed=False, state=state)
        if child:
            parts.append(f"{field_name} {{ {child} }}")
    return " ".join(parts) if parts else None


def _pagination_arg(args):
    found = []
    for arg in args:
        name = arg.get("name") if isinstance(arg, dict) else None
        kind, scalar_name = _base_type(arg.get("type")) if isinstance(arg, dict) else (None, None)
        if (name in ("first", "limit", "page_size", "pageSize")
                and kind == "SCALAR" and scalar_name == "Int"
                and not _contains_type_kind(arg.get("type"), "LIST")):
            found.append(arg)
    return found[0] if len(found) == 1 else None


def _query_candidates(schema, reference, *, explicit_input=None, reference_field=None,
                      list_limit=MAX_LIST_LIMIT):
    """Generated query rows: document, variables, alias and provenance."""
    out = []
    numeric_cache = {}
    for field in schema["query"].get("fields") or []:
        if not isinstance(field, dict):
            continue
        field_name = field.get("name")
        if not isinstance(field_name, str) or not GRAPHQL_NAME.fullmatch(field_name) \
                or field_name.startswith("__") or field_name in ("_entities", "_service") \
                or _destructive_identifier(field_name):
            continue
        args = [arg for arg in (field.get("args") or []) if isinstance(arg, dict)]
        required = [arg for arg in args if _is_required(arg)]
        # We supply exactly one identifier-like argument.  Any other required
        # argument would make the operation speculative, so this field is skipped.
        possible = []
        for arg in args:
            name = arg.get("name")
            if not isinstance(name, str) or not GRAPHQL_NAME.fullmatch(name) or _destructive_identifier(name):
                continue
            arg_rank = _rank_name(name, ARG_RANK)
            arg_kind, _arg_type_name = _base_type(arg.get("type"))
            # The protected reference must go only to an identifier/reference
            # argument, never an arbitrary required string such as `search`.
            input_named = name.lower() in ("input", "where", "selector", "request")
            if ((arg_rank >= len(ARG_RANK) * 3 and not (input_named and arg_kind == "INPUT_OBJECT"))
                    or _contains_type_kind(arg.get("type"), "LIST")):
                continue
            expr = _type_expr(arg.get("type"))
            if arg_kind == "INPUT_OBJECT":
                value, valid = _input_value(
                    schema, arg.get("type"), reference, explicit_input, reference_field,
                    numeric_cache=numeric_cache)
            else:
                value, valid = _variable_value(reference, arg.get("type"), numeric_cache)
            if expr and valid:
                possible.append((arg_rank, arg, expr, value))
        if not possible:
            continue
        _arg_rank, chosen, type_expr, variable = min(possible, key=lambda item: (item[0], item[1]["name"]))
        pagination = _pagination_arg(args)
        if any(arg is not chosen and arg is not pagination for arg in required):
            continue
        return_kind, return_name = _base_type(field.get("type"))
        contains_list = _contains_type_kind(field.get("type"), "LIST")
        list_allowed = pagination is not None and not contains_list
        # Relay wrappers expose the list below the root object, so the root's
        # explicit pagination argument is the bound for edges/nodes too.
        if return_kind in ("SCALAR", "ENUM"):
            selection = ""
        elif return_kind in ("OBJECT", "INTERFACE", "UNION") and return_name in schema["by_name"]:
            state = {"nodes": 0, "cycle": False, "list_refused": False}
            selected = _selection_for_type(
                schema, return_name, list_allowed=list_allowed, state=state)
            if not selected or (contains_list and not list_allowed):
                continue
            selection = " { " + selected + " }"
        else:
            continue
        alias = "r" + str(len(out))
        declarations = [f"$ref: {type_expr}"]
        call_args = [f"{chosen['name']}: $ref"]
        variables = {"ref": variable}
        if pagination is not None and pagination is not chosen:
            declarations.append("$limit: Int!")
            call_args.append(f"{pagination['name']}: $limit")
            variables["limit"] = int(list_limit)
        document = (f"query GraphQLProtectedRead({', '.join(declarations)}) {{ "
                    f"{alias}: {field_name}({', '.join(call_args)}){selection} }}")
        if not _query_only(document):
            continue
        rank = (_rank_name(field_name, FIELD_RANK), _arg_rank, field_name)
        out.append((rank, {"document": document, "variables": variables, "alias": alias,
                           "field": field_name, "argument": chosen["name"]}))
    return [row for _rank, row in sorted(out, key=lambda item: item[0])[:MAX_CANDIDATE_QUERIES]]


def _strip_offhost_urls(text, host=None):
    value = str(text or "")[:MAX_BODY]
    wanted = str(host or "").lower().rstrip(".")
    if not wanted:
        return value

    def canonical_layers(raw):
        current = str(raw or "")[:MAX_BODY]
        layers = []
        stable = False
        for _ in range(13):
            normalized = html.unescape(current)
            normalized = re.sub(r"\\+(?:/|u002f|x2f)", "/", normalized, flags=re.I)
            normalized = re.sub(r"\\+(?:u003a|x3a)", ":", normalized, flags=re.I)
            normalized = re.sub(r"(?i)([a-z][a-z0-9+.-]{0,31}:)\\+", r"\1//", normalized)
            normalized = re.sub(r"(?<![A-Za-z0-9])\\{2,}", "//", normalized)
            if (re.search(r"(?i)(?:https?|ftp|wss?|file):[\\/]", normalized)
                    or re.search(r"(?<![A-Za-z0-9])//", normalized)
                    or normalized.lstrip().startswith("\\\\")):
                normalized = normalized.replace("\\", "/")
            normalized = re.sub(r"(?i)((?:https?|ftp|wss?|file):)/+", r"\1//", normalized)
            normalized = normalized[:MAX_BODY]
            if not layers or normalized != layers[-1]:
                layers.append(normalized)
            nxt = urllib.parse.unquote_plus(normalized)[:MAX_BODY]
            if nxt == normalized:
                stable = True
                break
            current = nxt
        return layers, stable

    def url_host(raw):
        try:
            candidate = str(raw or "")
            if candidate.startswith("//"):
                candidate = "http:" + candidate
            found = (urllib.parse.urlsplit(candidate).hostname or "").lower().rstrip(".")
            if not found and re.match(r"(?i)^(?:(?:https?|ftp|wss?|file):/+|//+)", candidate):
                return "!ambiguous-authority"
            return found
        except ValueError:
            return ""

    def replace(match):
        found = url_host(match.group(0))
        return match.group(0) if found == wanted else ""

    cleaned = ABSOLUTE_URL.sub(replace, value)

    def replace_encoded(match):
        layers, stable = canonical_layers(match.group(0))
        hosts = [url_host(item) for item in layers]
        if not stable:
            return ""
        return match.group(0) if not any(found and found != wanted for found in hosts) else ""

    cleaned = ENCODED_ABSOLUTE_URL.sub(replace_encoded, cleaned)

    # HTML/spec/GraphQL wrappers sometimes percent-encode only the URL's
    # authority delimiters while leaving a proof token readable.  Decode a few
    # bounded layers solely to identify off-host URL carriers, then remove from
    # the ORIGINAL text only the flag-format tokens proven to be inside those
    # carriers.  This preserves unrelated baseline text and never turns decoded
    # bytes into a candidate.
    offhost_tokens = set()
    whole_offhost = False
    layers, stable = canonical_layers(value)
    for decoded in layers:
        whole = ABSOLUTE_URL.fullmatch(decoded.strip())
        if whole is not None and url_host(whole.group(0)) not in ("", wanted):
            whole_offhost = True
        for match in ABSOLUTE_URL.finditer(decoded):
            found = url_host(match.group(0))
            if found and found != wanted:
                carrier = match.group(0)
                for pattern in (PAYOFF_LIKE, OTHER_LIKE):
                    offhost_tokens.update(item.group(0) for item in pattern.finditer(carrier))
    if not stable or whole_offhost:
        return ""
    for token in sorted(offhost_tokens, key=len, reverse=True):
        cleaned = re.sub(re.escape(token), "", cleaned, flags=re.I)
    return cleaned


def _bounded_baseline_texts(texts):
    """Return a bounded baseline snapshot and whether any input was omitted.

    Count and character overflow are observed *before* slicing.  An incomplete
    subtraction set may still be used to suppress/surface candidates, but can
    never justify an automatic answer.
    """
    out = []
    incomplete = False
    used = 0
    try:
        iterator = iter(texts or ())
        for index, item in enumerate(iterator):
            if index >= MAX_BASELINE_TEXTS:
                incomplete = True
                break
            try:
                value = str(item or "")
            except Exception:
                incomplete = True
                continue
            if len(value) > MAX_BODY:
                value = value[:MAX_BODY]
                incomplete = True
            remaining = MAX_BASELINE_SCAN_CHARS - used
            if len(value) > max(0, remaining):
                value = value[:max(0, remaining)]
                incomplete = True
            out.append(value)
            used += len(value)
    except Exception:
        incomplete = True
    return out, incomplete


def _baseline_policy_for(texts, host=None):
    """Normalize each bounded baseline once for one result-evidence decision."""
    raw, incomplete = _bounded_baseline_texts(texts)
    wire, proofish = set(), set()
    folded = []
    for value in raw:
        try:
            filtered = _strip_offhost_urls(value, host)
        except Exception:
            filtered = ""
            incomplete = True
        # A baseline/control is subtraction-only.  Include both its raw token
        # set and its carrier-filtered view.  Store case-folded views now so a
        # large control is never normalized anew for every result candidate.
        for view in (value, filtered):
            casefolded = view.casefold()
            if casefolded not in folded:
                folded.append(casefolded)
            wire.update(match.group(0).casefold() for match in PAYOFF_WIRE.finditer(view))
            proofish.update(match.group(0).casefold() for match in PAYOFF_LIKE.finditer(view))
            proofish.update(match.group(0).casefold() for match in OTHER_LIKE.finditer(view))
    if _proof_policy is not None and hasattr(_proof_policy, "baseline_set_incomplete"):
        try:
            incomplete = incomplete or bool(_proof_policy.baseline_set_incomplete(raw))
        except Exception:
            incomplete = True
    else:
        incomplete = incomplete or any(BASELINE_INCOMPLETE_MARKER in value for value in raw)
    return {"raw": tuple(raw), "folded": tuple(folded), "wire": wire,
            "proofish": proofish, "incomplete": incomplete}


def _baseline_contains(policy, value):
    folded = str(value or "").strip().casefold()
    return bool(folded) and any(folded in text for text in policy["folded"])


def _baseline_marks(texts, host=None):
    policy = _baseline_policy_for(texts, host)
    return policy["wire"], policy["proofish"]


def _baselines_incomplete(texts):
    raw, incomplete = _bounded_baseline_texts(texts)
    if _proof_policy is not None and hasattr(_proof_policy, "baseline_set_incomplete"):
        try:
            return incomplete or bool(_proof_policy.baseline_set_incomplete(raw))
        except Exception:
            return True
    return incomplete or any(BASELINE_INCOMPLETE_MARKER in value for value in raw)


def _wire_wrapper(value, wires):
    """True only when a scalar is an equivalent/wrapper of one wire proof."""
    text = str(value or "").strip()
    if not text or not wires:
        return False
    folded = text.casefold()
    matched = [wire for wire in wires if wire.casefold() in folded]
    if len({wire.casefold() for wire in matched}) != 1:
        return False
    wanted = matched[0].casefold()
    proofish = [match.group(0) for pattern in (PAYOFF_LIKE, OTHER_LIKE)
                for match in pattern.finditer(text)]
    if any(token.casefold() != wanted for token in proofish):
        return False
    # A whole same/off-host URI carrying only this wire is another spelling of
    # that wire, not a distinct answer.  Off-host carriers have normally been
    # removed already; this also handles an allowed same-host URI.
    if ABSOLUTE_URL.fullmatch(text) is not None:
        return True
    residual = re.sub(re.escape(matched[0]), " ", html.unescape(text), flags=re.I)
    words = [word.casefold() for word in re.findall(r"[A-Za-z0-9]+", residual)]
    if all(word in _WIRE_WRAPPER_WORDS for word in words):
        return True
    # An unrelated empty HTML wrapper (commonly an off-host asset stripped by
    # ``_strip_offhost_urls``) and one-character entity text do not describe a
    # second answer. Strip tags only for this equivalence check; inline text
    # such as ``objective-v3-91af`` remains and therefore stays ambiguous.
    without_tags = re.sub(r"<[^>\r\n]{0,2048}>", " ", residual)
    visible_words = re.findall(r"[A-Za-z0-9]+", without_tags)
    return bool("<" in residual) and all(len(word) <= 1 for word in visible_words)


def _result_evidence(result, baseline_texts, host=None):
    """Extract only from the generated alias's parsed GraphQL result node."""
    scan_state = {"nodes": 0, "members": 0, "incomplete": False}
    scalar_rows = [(path, clean) for path, value in _walk_scalars(result, state=scan_state)
                   if (clean := _strip_offhost_urls(value, host).strip())]
    joined = "\n".join(value for _path, value in scalar_rows)
    wires = list(dict.fromkeys(match.group(0) for match in PAYOFF_WIRE.finditer(joined)))
    proof_tokens = list(dict.fromkeys(match.group(0) for match in PAYOFF_LIKE.finditer(joined)))
    flags = list(dict.fromkeys(match.group(0) for match in OTHER_LIKE.finditer(joined)))
    baseline_policy = _baseline_policy_for(baseline_texts, host)
    baseline_proofish = baseline_policy["proofish"]
    novel_wires = [value for value in wires if value.casefold() not in baseline_proofish]
    novel_proof_tokens = [value for value in proof_tokens if value.casefold() not in baseline_proofish]
    novel_flags = [value for value in flags if value.casefold() not in baseline_proofish]

    candidates = []

    def add(value):
        value = str(value or "").strip()
        if _baseline_contains(baseline_policy, value):
            return
        folded = value.casefold()
        if (3 <= len(value) <= 256
                and all(folded != candidate.casefold() for candidate in candidates)
                and all(folded != wire.casefold() for wire in wires)):
            candidates.append(value)

    for token in novel_proof_tokens + novel_flags:
        add(token)
    for path, value in scalar_rows:
        key = path[-1] if path else ""
        if STRONG_LABEL.search(key):
            if not _wire_wrapper(value, wires):
                add(value)
        elif key.lower() in SOFT_LABELS:
            # A compact future value in `note`/`message` remains ambiguity even
            # beside one wire proof.  Exclude only an equal/wrapped rendering of
            # that same wire, never every soft value merely because a wire exists.
            if not _wire_wrapper(value, wires):
                add(value)
        elif not path and len(scalar_rows) == 1 and not wires:
            # A Query-root scalar has no child field name to label it; the
            # successful generated resolver read is still enough to surface a
            # future-shaped value, never to auto-return it.
            add(value)

    # Baselines are subtraction, not poison: a distinct plain-page decoy does
    # not hide one new exploit payoff.  A repeated baseline value is excluded,
    # while a second novel proof/flag/labelled value keeps the answer ambiguous.
    wire_folds = {wire.casefold() for wire in novel_wires}
    non_wire_proof = [token for token in novel_proof_tokens
                      if token.casefold() not in wire_folds]
    baseline_incomplete = bool(baseline_policy["incomplete"])
    scan_incomplete = bool(scan_state["incomplete"])
    auto = novel_wires[0] if len(novel_wires) == 1 and not non_wire_proof \
        and not novel_flags and not candidates and not scan_incomplete else None
    if baseline_incomplete:
        auto = None
    if auto is not None:
        # The exact value must be novel, even if a future baseline scanner is
        # relaxed to allow an unrelated decoy.
        if _baseline_contains(baseline_policy, auto):
            auto = None
    return {"auto": auto, "uuid4": bool(auto and PAYOFF_V4.fullmatch(auto)),
            "candidates": candidates[:12], "wire": novel_wires[:12],
            "baseline_incomplete": baseline_incomplete,
            "scan_incomplete": scan_incomplete}


def _graphql_result(response, alias, baseline_texts, host=None):
    if not isinstance(response, dict) or not isinstance(response.get("status"), int) \
            or not 200 <= response["status"] < 300:
        return {"success": False, "auto": None, "uuid4": False, "candidates": [], "wire": []}
    doc = _json(response)
    if not isinstance(doc, dict) or doc.get("errors"):
        return {"success": False, "auto": None, "uuid4": False, "candidates": [], "wire": []}
    data = doc.get("data")
    if not isinstance(data, dict) or alias not in data or data[alias] is None:
        return {"success": False, "auto": None, "uuid4": False, "candidates": [], "wire": []}
    out = _result_evidence(data[alias], baseline_texts, host)
    out["success"] = True
    return out


def _get_only_transport(clues):
    """Require an exact target-local GET-only statement, never a generic GET mention."""
    if not isinstance(clues, dict):
        return False
    for key in METHOD_KEYS:
        value = clues.get(key)
        if not isinstance(value, str):
            continue
        upper = value.upper()
        if GET_ONLY_HINT.search(value) and not re.search(r"\b(?:POST|PUT|PATCH|DELETE)\b", upper):
            return True
    return False


def _advertises_federation(*texts):
    """One coherent target-local clue/control must contain all three concepts."""
    for text in texts:
        bounded = str(text or "")[:MAX_BODY]
        if (FEDERATION_WORD.search(bounded) and FEDERATION_SERVICE.search(bounded)
                and FEDERATION_SDL.search(bounded)):
            return True
    return False


def _baseline_proofs(texts):
    """Stable, bounded flag-format values observed in subtraction/control material."""
    out = []
    bounded, _incomplete = _bounded_baseline_texts(texts)
    for text in bounded:
        for match in PAYOFF_LIKE.finditer(text):
            value = match.group(0)
            if value.casefold() not in {item.casefold() for item in out}:
                out.append(value)
            if len(out) >= 128:
                return out
    return out


_LINK_ATTR = re.compile(r"(?is)\b(?:href|src)\s*=\s*([\"'])(.{1,2048}?)\1")


def _manifest_routes(clues, landing_text, base_url):
    """Return the first exact same-origin APQ/persisted-manifest link.

    One recon request preserves the eight-request default budget even when APQ
    and Federation both need a control/retry before the protected read.
    """
    raw = []
    if isinstance(clues, dict):
        # ``security_json`` already bounds the complete clue document.  A
        # second first-200 prefix here made a late, exact manifest route
        # invisible while earlier filler still influenced applicability.
        for key, value in clues.items():
            label = str(key).lower()
            if isinstance(value, str) and "manifest" in label \
                    and any(word in label for word in ("apq", "persisted", "query", "graphql")):
                raw.append(value)
    for match in _LINK_ATTR.finditer(str(landing_text or "")[:MAX_BODY]):
        value = html.unescape(match.group(2)).strip()
        low = value.lower().split("?", 1)[0]
        if "manifest" in low and any(word in low for word in ("apq", "persisted", "graphql", "query")):
            raw.append(value)
    out = []
    for value in raw:
        route = _same_origin_route(value, base_url)
        if route and route not in out:
            out.append(route)
        if len(out) >= 1:
            break
    return out


def _manifest_queries(response):
    """Parse validated hash->query pairs for findings only.

    Target-supplied documents are never returned to a transport caller.  The
    map contains only query-only documents whose *own bytes* hash to the stated
    SHA-256 key, so a later local document can be compared byte-for-byte.
    """
    if not isinstance(response, dict) or not isinstance(response.get("status"), int) \
            or not 200 <= response["status"] < 300:
        return {}, {"entries": 0, "valid_queries": 0, "unsafe_operations": 0}
    text = _text(response)
    if len(text.encode("utf-8", "replace")) > MAX_MANIFEST_BYTES:
        return {}, {"entries": 0, "valid_queries": 0, "unsafe_operations": 0,
                    "stopped": "size"}
    try:
        doc = _security_json.loads(text, max_chars=MAX_MANIFEST_BYTES)
    except Exception:
        return {}, {"entries": 0, "valid_queries": 0, "unsafe_operations": 0,
                    "stopped": "malformed"}
    valid, stats, seen = {}, {"entries": 0, "valid_queries": 0, "unsafe_operations": 0}, 0

    def consider(digest, document):
        nonlocal seen
        if seen >= MAX_MANIFEST_ENTRIES:
            return
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", digest) \
                or not isinstance(document, str) or len(document.encode("utf-8", "replace")) > 50_000:
            return
        seen += 1
        stats["entries"] += 1
        actual = hashlib.sha256(document.encode("utf-8")).hexdigest()
        if actual != digest.lower():
            return
        if not _query_only(document):
            stats["unsafe_operations"] += 1
            return
        valid[actual] = document
        stats["valid_queries"] += 1

    # The parser has already enforced its 40k-node/64-level structure caps.
    # Traverse that whole accepted tree iteratively: per-container 512-item and
    # depth-7 prefixes could hide a valid late manifest entry without ever
    # setting ``entry_limit`` because filler does not increment ``seen``.
    stack = [doc]
    while stack and seen < MAX_MANIFEST_ENTRIES:
        value = stack.pop()
        if isinstance(value, dict):
            digest = next((value.get(key) for key in ("sha256Hash", "sha256", "hash", "id")
                           if isinstance(value.get(key), str)), None)
            document = next((value.get(key) for key in ("body", "query", "document", "text")
                             if isinstance(value.get(key), str)), None)
            if digest is not None and document is not None:
                consider(digest, document)
            for key, child in reversed(list(value.items())):
                if isinstance(key, str) and isinstance(child, str):
                    consider(key, child)
                    if seen >= MAX_MANIFEST_ENTRIES:
                        break
                if isinstance(child, (dict, list)):
                    stack.append(child)
        elif isinstance(value, list):
            stack.extend(reversed([child for child in value if isinstance(child, (dict, list))]))

    if seen >= MAX_MANIFEST_ENTRIES:
        stats["stopped"] = "entry_limit"
    return valid, stats


def _sdl_tokens(sdl):
    """Small non-executing lexer; descriptions/comments are discarded."""
    if not isinstance(sdl, str) or len(sdl.encode("utf-8", "replace")) > MAX_SDL_BYTES:
        return None
    out, i, size = [], 0, len(sdl)
    punctuation = frozenset("!$():=@[]{|}&")
    while i < size:
        char = sdl[i]
        if char.isspace() or char == ",":
            i += 1
            continue
        if char == "#":
            end = sdl.find("\n", i + 1)
            i = size if end < 0 else end + 1
            continue
        if sdl.startswith('"""', i):
            i += 3
            while True:
                end = sdl.find('"""', i)
                if end < 0:
                    return None
                if end == 0 or sdl[end - 1] != "\\":
                    i = end + 3
                    break
                i = end + 3
            continue
        if char == '"':
            i += 1
            escaped = False
            while i < size:
                current = sdl[i]
                i += 1
                if escaped:
                    escaped = False
                elif current == "\\":
                    escaped = True
                elif current == '"':
                    break
                elif current in "\r\n":
                    return None
            else:
                return None
            out.append(("VALUE", "string"))
        elif char.isalpha() or char == "_":
            end = i + 1
            while end < size and (sdl[end].isalnum() or sdl[end] == "_"):
                end += 1
            name = sdl[i:end]
            if len(name) > 128:
                return None
            out.append(("NAME", name))
            i = end
        elif char in punctuation:
            out.append(("PUNCT", char))
            i += 1
        elif char.isdigit() or char in "+-.":
            end = i + 1
            while end < size and (sdl[end].isalnum() or sdl[end] in "+-.eE"):
                end += 1
            out.append(("VALUE", sdl[i:end]))
            i = end
        else:
            return None
        if len(out) > MAX_SDL_TOKENS:
            return None
    return out


def _sdl_type(tokens, index):
    if index >= len(tokens):
        return None, index
    if tokens[index] == ("PUNCT", "["):
        inner, index = _sdl_type(tokens, index + 1)
        if inner is None or index >= len(tokens) or tokens[index] != ("PUNCT", "]"):
            return None, index
        node, index = ("list", inner), index + 1
    elif tokens[index][0] == "NAME" and GRAPHQL_NAME.fullmatch(tokens[index][1]):
        node, index = ("named", tokens[index][1]), index + 1
    else:
        return None, index
    if index < len(tokens) and tokens[index] == ("PUNCT", "!"):
        node, index = ("nonnull", node), index + 1
    return node, index


def _sdl_skip_group(tokens, index, opening="(", closing=")"):
    if index >= len(tokens) or tokens[index] != ("PUNCT", opening):
        return None
    depth = 0
    for pos in range(index, len(tokens)):
        if tokens[pos] == ("PUNCT", opening):
            depth += 1
        elif tokens[pos] == ("PUNCT", closing):
            depth -= 1
            if depth == 0:
                return pos + 1
    return None


def _sdl_skip_directives(tokens, index):
    seen = False
    while index < len(tokens) and tokens[index] == ("PUNCT", "@"):
        seen = True
        index += 1
        if index >= len(tokens) or tokens[index][0] != "NAME":
            return None, seen
        index += 1
        if index < len(tokens) and tokens[index] == ("PUNCT", "("):
            index = _sdl_skip_group(tokens, index)
            if index is None:
                return None, seen
    return index, seen


def _sdl_args(tokens, index):
    args = []
    if index >= len(tokens) or tokens[index] != ("PUNCT", "("):
        return args, index, False
    index += 1
    unsafe = False
    while index < len(tokens) and tokens[index] != ("PUNCT", ")"):
        if tokens[index][0] != "NAME" or index + 1 >= len(tokens) \
                or tokens[index + 1] != ("PUNCT", ":"):
            return None, index, True
        name, index = tokens[index][1], index + 2
        expr, index = _sdl_type(tokens, index)
        if expr is None:
            return None, index, True
        default = None
        if index < len(tokens) and tokens[index] == ("PUNCT", "="):
            default = "present"
            index += 1
            stack = []
            while index < len(tokens):
                token = tokens[index]
                if not stack and (token == ("PUNCT", ")")
                                  or (token[0] == "NAME" and index + 1 < len(tokens)
                                      and tokens[index + 1] == ("PUNCT", ":"))):
                    break
                if token in (("PUNCT", "["), ("PUNCT", "{"), ("PUNCT", "(")):
                    stack.append(token[1])
                elif token in (("PUNCT", "]"), ("PUNCT", "}"), ("PUNCT", ")")):
                    if not stack:
                        break
                    stack.pop()
                index += 1
        index, directed = _sdl_skip_directives(tokens, index)
        if index is None:
            return None, 0, True
        unsafe = unsafe or directed
        args.append({"name": name, "expr": expr, "default": default})
    if index >= len(tokens) or tokens[index] != ("PUNCT", ")"):
        return None, index, True
    return args, index + 1, unsafe


def _sdl_fields(tokens):
    fields, index = [], 0
    while index < len(tokens):
        if tokens[index][0] != "NAME":
            return None
        name, index = tokens[index][1], index + 1
        args, index, arg_directive = _sdl_args(tokens, index)
        if args is None or index >= len(tokens) or tokens[index] != ("PUNCT", ":"):
            return None
        expr, index = _sdl_type(tokens, index + 1)
        if expr is None:
            return None
        index, field_directive = _sdl_skip_directives(tokens, index)
        if index is None:
            return None
        if not arg_directive and not field_directive:
            fields.append({"name": name, "args": args, "expr": expr})
            if len(fields) > MAX_SDL_FIELDS:
                return None
    return fields


def _sdl_schema(sdl):
    """Conservatively translate SDL into the introspection subset used above."""
    tokens = _sdl_tokens(sdl)
    if tokens is None:
        return None
    objects, scalars, enums, unions = {}, {"Int", "Float", "String", "Boolean", "ID"}, set(), set()
    query_name, index, total_fields = "Query", 0, 0
    definition_words = {"type", "scalar", "enum", "union", "interface", "input", "schema", "directive"}
    while index < len(tokens):
        extended = tokens[index] == ("NAME", "extend")
        if extended:
            index += 1
        if index >= len(tokens) or tokens[index][0] != "NAME":
            return None
        kind, index = tokens[index][1], index + 1
        if kind == "schema":
            index, _directed = _sdl_skip_directives(tokens, index)
            if index is None:
                return None
            end = _sdl_skip_group(tokens, index, "{", "}")
            if end is None:
                return None
            block = tokens[index + 1:end - 1]
            for pos in range(len(block) - 2):
                if block[pos] == ("NAME", "query") and block[pos + 1] == ("PUNCT", ":") \
                        and block[pos + 2][0] == "NAME":
                    query_name = block[pos + 2][1]
            index = end
            continue
        if kind in ("scalar", "enum", "union", "interface", "input"):
            if index >= len(tokens) or tokens[index][0] != "NAME":
                return None
            name, index = tokens[index][1], index + 1
            if kind == "scalar":
                scalars.add(name)
            elif kind == "enum":
                enums.add(name)
            elif kind == "union":
                unions.add(name)
            # Braced definitions are irrelevant to safe object/scalar selections.
            while index < len(tokens) and tokens[index] != ("PUNCT", "{") \
                    and not (tokens[index][0] == "NAME" and tokens[index][1] in definition_words):
                index += 1
            if index < len(tokens) and tokens[index] == ("PUNCT", "{"):
                end = _sdl_skip_group(tokens, index, "{", "}")
                if end is None:
                    return None
                index = end
            continue
        if kind == "directive":
            while index < len(tokens) and not (tokens[index][0] == "NAME"
                                               and tokens[index][1] in definition_words):
                index += 1
            continue
        if kind != "type" or index >= len(tokens) or tokens[index][0] != "NAME":
            return None
        name, index = tokens[index][1], index + 1
        while index < len(tokens) and tokens[index] != ("PUNCT", "{"):
            if tokens[index] == ("PUNCT", "@"):
                index, _directed = _sdl_skip_directives(tokens, index)
                if index is None:
                    return None
                continue
            # A missing object body must not consume the following definition.
            if tokens[index][0] == "NAME" and tokens[index][1] in definition_words:
                return None
            if tokens[index][0] == "NAME" or tokens[index] == ("PUNCT", "&"):
                index += 1
                continue
            return None
        end = _sdl_skip_group(tokens, index, "{", "}")
        if end is None:
            return None
        parsed = _sdl_fields(tokens[index + 1:end - 1])
        if parsed is None:
            return None
        total_fields += len(parsed)
        if total_fields > MAX_SDL_FIELDS or len(objects) > MAX_SCHEMA_TYPES:
            return None
        objects.setdefault(name, []).extend(parsed)
        index = end

    if query_name not in objects or _destructive_identifier(query_name) \
            or query_name.lower() in ("mutation", "subscription"):
        return None

    def node(expr):
        kind, value = expr
        if kind == "nonnull":
            inner = node(value)
            return {"kind": "NON_NULL", "name": None, "ofType": inner} if inner else None
        if kind == "list":
            inner = node(value)
            return {"kind": "LIST", "name": None, "ofType": inner} if inner else None
        if value in scalars:
            resolved = "SCALAR"
        elif value in enums:
            resolved = "ENUM"
        elif value in objects:
            resolved = "OBJECT"
        elif value in unions:
            resolved = "UNION"
        else:
            return None
        return {"kind": resolved, "name": value, "ofType": None}

    types = []
    for name, raw_fields in objects.items():
        fields = []
        for raw in raw_fields:
            field_type = node(raw["expr"])
            args = []
            for arg in raw["args"]:
                arg_type = node(arg["expr"])
                if arg_type is None:
                    args = None
                    break
                args.append({"name": arg["name"], "defaultValue": arg["default"], "type": arg_type})
            if field_type is not None and args is not None:
                fields.append({"name": raw["name"], "args": args, "type": field_type})
        types.append({"kind": "OBJECT", "name": name, "fields": fields})
    for name in sorted(scalars):
        types.append({"kind": "SCALAR", "name": name, "fields": None})
    for name in sorted(enums):
        types.append({"kind": "ENUM", "name": name, "fields": None})
    for name in sorted(unions):
        types.append({"kind": "UNION", "name": name, "fields": None, "possibleTypes": []})
    by_name = {row["name"]: row for row in types}
    return {"query_name": query_name, "types": types, "by_name": by_name,
            "query": by_name[query_name], "source": "federation-sdl"}


def _federation_schema(response):
    if not isinstance(response, dict) or not isinstance(response.get("status"), int) \
            or not 200 <= response["status"] < 300:
        return None
    doc = _json(response)
    if not isinstance(doc, dict) or doc.get("errors"):
        return None
    data = doc.get("data")
    service = data.get("_service") if isinstance(data, dict) else None
    sdl = service.get("sdl") if isinstance(service, dict) else None
    return _sdl_schema(sdl)


def _persisted_required(response):
    """True only for an explicit GraphQL/APQ persisted-query transport error."""
    return bool(PERSISTED_QUERY_REQUIRED.search(_text(response)))


class _Reader:
    def __init__(self, target, ctx):
        self.target = dict(target) if isinstance(target, dict) else {"url": str(target)}
        self.url = str(self.target.get("url") or "")
        self.ctx = ctx
        try:
            self.deadline = float(ctx["deadline"]) if ctx.get("deadline") is not None \
                else time.time() + DEFAULT_SECONDS
        except (TypeError, ValueError):
            self.deadline = time.time() + DEFAULT_SECONDS
        try:
            self.max_requests = max(0, int(ctx.get("max_requests", DEFAULT_MAX_REQUESTS)))
        except (TypeError, ValueError):
            self.max_requests = DEFAULT_MAX_REQUESTS
        self.requests = 0
        self.posts = 0
        self.responses = []
        self.baseline_texts = []
        initial_baselines, baseline_overflow = _bounded_baseline_texts(
            ctx.get("baseline_texts") or ())
        for value in initial_baselines:
            if value and value not in self.baseline_texts:
                self.baseline_texts.append(value)
        if baseline_overflow and BASELINE_INCOMPLETE_MARKER not in self.baseline_texts:
            self.baseline_texts.append(BASELINE_INCOMPLETE_MARKER)
        self.candidates = []
        self.uuid4 = False
        self.success = False
        self.persisted_queries = False
        self.transport = "POST"
        self.schema_source = None
        self.manifest_queries = {}
        self.manifest_matches = []
        self.findings = []
        self.where = None
        self.stopped = None
        self.t0 = time.time()
        self._gate = threading.Lock()
        self._stopped = False
        self.external_stop = ctx.get("stop")
        self.preloaded = dict(ctx.get("preloaded") or {})
        self.client = None
        try:
            if ctx.get("client") is not None:
                candidate = ctx["client"]
            elif callable(ctx.get("client_factory")):
                candidate = ctx["client_factory"](self.url, REQUEST_TIMEOUT)
            else:
                candidate = _web.WebClient(self.url, timeout=REQUEST_TIMEOUT)
            if not _client_matches_target(candidate, self.url):
                raise _web.OutOfScope("injected client scope does not match target origin")
            self.client = candidate
        except Exception as exc:
            self.stopped = f"no scoped client: {type(exc).__name__}"

    def left(self):
        return None if self.deadline is None else self.deadline - time.time()

    def stop_now(self):
        with self._gate:
            self._stopped = True

    def _may_send_locked(self):
        if self._stopped or (hasattr(self.external_stop, "is_set") and self.external_stop.is_set()):
            self.stopped = self.stopped or "stopped"
            return False
        if self.requests >= self.max_requests:
            self.stopped = self.stopped or "max_requests"
            return False
        left = self.left()
        if left is not None and left <= DEADLINE_PAD:
            self.stopped = self.stopped or "deadline"
            return False
        return True

    def _request(self, method, path, *, data=None, headers=None, role="plain", generated_base=None):
        method = str(method).upper()
        if method not in ("GET", "POST"):
            self.stopped = self.stopped or f"refused verb {method}"
            return None
        if generated_base is not None:
            safe_base = _same_origin_route(generated_base, self.url)
            parsed = urllib.parse.urlsplit(str(path or ""))
            if method != "GET" or safe_base is None or parsed.scheme or parsed.netloc or parsed.fragment \
                    or parsed.path != safe_base or not parsed.query \
                    or len(str(path).encode("utf-8", "replace")) > MAX_GET_URL_BYTES:
                self.stopped = self.stopped or "refused malformed/oversized generated GET"
                return None
            safe_path = str(path)
        else:
            safe_path = _same_origin_route(path, self.url)
            if safe_path is None:
                self.stopped = self.stopped or "refused unsafe/off-host route"
                return None
        if data is not None:
            encoded = data if isinstance(data, bytes) else str(data).encode("utf-8", "replace")
            if len(encoded) > MAX_REQUEST_BODY_BYTES:
                self.stopped = self.stopped or "refused oversized request body"
                return None
        path = safe_path
        with self._gate:
            if self.client is None or not self._may_send_locked():
                return None
            left = self.left()
            try:
                self.client.timeout = REQUEST_TIMEOUT if left is None else max(
                    0.2, min(REQUEST_TIMEOUT, left - 0.1))
            except Exception:
                pass
            self.requests += 1
            if method == "POST":
                self.posts += 1
            try:
                response = self.client.request(method, path, data=data, headers=dict(headers or {}),
                                               allow_redirects=False)
            except Exception as exc:
                self.responses.append({"method": method, "path": str(path).split("?", 1)[0],
                                       "status": None, "role": role, "error": type(exc).__name__})
                self.stopped = self.stopped or f"transport: {type(exc).__name__}"
                self._stopped = True
                return None
        self.responses.append({"method": method, "path": str(path).split("?", 1)[0],
                               "status": response.get("status") if isinstance(response, dict) else None,
                               "role": role})
        return response

    def get(self, path, role="plain"):
        if path in self.preloaded:
            response = _response(self.preloaded[path])
            if response is not None:
                self._add_baseline(_baseline_text(response))
                return response
        response = self._request("GET", path, role=role)
        if response is not None:
            self._add_baseline(_baseline_text(response))
        return response

    def _add_baseline(self, text):
        try:
            raw = str(text or "")
        except Exception:
            raw = ""
            overflow = True
        else:
            overflow = len(raw) > MAX_BODY
        value = raw[:MAX_BODY]
        if value and value not in self.baseline_texts:
            ordinary = [item for item in self.baseline_texts
                        if item != BASELINE_INCOMPLETE_MARKER]
            if len(ordinary) < MAX_BASELINE_TEXTS:
                self.baseline_texts.append(value)
            else:
                overflow = True
        if overflow and BASELINE_INCOMPLETE_MARKER not in self.baseline_texts:
            self.baseline_texts.append(BASELINE_INCOMPLETE_MARKER)

    def _remember_baseline(self, response):
        if response is None:
            return
        self._add_baseline(_baseline_text(response))

    def post_query(self, route, document, variables, role, *, persisted=False):
        """Compatibility wrapper for the historical POST-only tests/callers."""
        return self._send_query(route, document, variables, role, persisted=persisted, transport="POST")

    def _manifest_match(self, document):
        digest = hashlib.sha256(document.encode("utf-8")).hexdigest()
        if self.manifest_queries.get(digest) == document and digest not in self.manifest_matches:
            self.manifest_matches.append(digest)

    def _send_query(self, route, document, variables, role, *, persisted=False, transport=None):
        if not _query_only(document):
            self.stopped = self.stopped or "refused non-query operation"
            return None
        payload = {"query": document, "variables": variables or {}}
        self._manifest_match(document)
        if persisted:
            payload["extensions"] = {"persistedQuery": {
                "version": 1, "sha256Hash": hashlib.sha256(document.encode("utf-8")).hexdigest(),
            }}
        selected = transport or self.transport
        if selected == "GET":
            params = [("query", document),
                      ("variables", json.dumps(payload["variables"], separators=(",", ":")))]
            if "extensions" in payload:
                params.append(("extensions", json.dumps(payload["extensions"], separators=(",", ":"))))
            query = urllib.parse.urlencode(params, doseq=False, quote_via=urllib.parse.quote, safe="")
            path = route + "?" + query
            if len(path.encode("utf-8", "replace")) > MAX_GET_URL_BYTES:
                self.stopped = self.stopped or "refused oversized GraphQL GET URL"
                return None
            return self._request("GET", path, role=role, generated_base=route)
        body = json.dumps(payload, separators=(",", ":"))
        return self._request("POST", route, data=body,
                             headers={"Content-Type": "application/json"}, role=role)

    def query(self, route, document, variables, role, *, persisted=False):
        return self._send_query(route, document, variables, role, persisted=persisted)

    def read_manifests(self, clues, landing_text):
        for route in _manifest_routes(clues, landing_text, self.url):
            response = self.get(route, "apq-manifest-control")
            valid, stats = _manifest_queries(response)
            self.findings.append({"class": "apq-manifest", "route": route, **stats})
            # A target document can influence only a byte-identical locally generated
            # query, checked again in _manifest_match; it is never transported itself.
            self.manifest_queries.update(valid)

    def run(self):
        if not enabled():
            self.stopped = "off"
            return None
        if self.client is None or self.max_requests <= 0:
            self.stopped = self.stopped or "max_requests"
            return None
        if self.left() is not None and self.left() <= DEADLINE_PAD:
            self.stopped = "deadline"
            return None

        root = self.get("/", "landing-control")
        if isinstance(root, dict) and root.get("status") == 410:
            self.stopped = "target completed"
            return None
        clue_response = self.get("/api/clues", "clues")
        if isinstance(clue_response, dict) and clue_response.get("status") == 410:
            self.stopped = "target completed"
            return None
        clues = _json(clue_response)
        if (not isinstance(clue_response, dict) or not isinstance(clue_response.get("status"), int)
                or not 200 <= clue_response["status"] < 300 or not isinstance(clues, dict)):
            self.stopped = "no target-local clue document"
            return None

        route, route_ok = _coherent_alias(
            clues, ROUTE_KEYS, lambda value: _same_origin_route(value, self.url))
        reference, reference_ok = _coherent_reference(clues)
        transport, transport_ok = _coherent_transport(clues)
        explicit_input, reference_field, input_ok = _coherent_input_contract(clues)
        list_limit, list_limit_ok = _coherent_list_limit(clues)
        # Deliberately ignore ctx.prompt and target.question.  A shared Mastery
        # prompt cannot authorize POSTing another target's feature_route.
        local_text = _text(root) + "\n" + _text(clue_response)
        if (not route_ok or not reference_ok or not transport_ok or not input_ok or not list_limit_ok
                or not route or reference is None
                or not GRAPHQL_LOCAL_EVIDENCE.search(local_text)):
            self.stopped = "not a target-described GraphQL reference class"
            return None
        self.transport = transport

        # Endpoint-local control: a proof visible without the GraphQL exploit
        # poisons automatic extraction.
        feature_control = self.get(route, "feature-control")
        if isinstance(feature_control, dict) and feature_control.get("status") == 410:
            self.stopped = "target completed"
            return None
        self.read_manifests(clues, _text(root))

        introspection = self.query(route, INTROSPECTION_QUERY, {}, "graphql-introspection")
        if introspection is not None:
            self._remember_baseline(introspection)
        schema = _schema(introspection)
        if schema is None and _persisted_required(introspection):
            self.persisted_queries = True
            introspection = self.query(route, INTROSPECTION_QUERY, {},
                                       "graphql-introspection-persisted", persisted=True)
            if introspection is not None:
                self._remember_baseline(introspection)
            schema = _schema(introspection)
        introspection_views = _coherent_texts(introspection)
        federation_controls = [
            view for response in (root, clue_response, feature_control, introspection)
            for view in _coherent_texts(response)
        ]
        if schema is not None:
            self.schema_source = "introspection"
        elif _persisted_required(introspection):
            self.stopped = self.stopped or "APQ requirement remained unsatisfied"
            return None
        elif any(INTROSPECTION_DISABLED.search(view) for view in introspection_views) \
                and _advertises_federation(*federation_controls):
            federation = self.query(route, FEDERATION_SDL_QUERY, {}, "graphql-federation-sdl",
                                    persisted=self.persisted_queries)
            if federation is not None:
                self._remember_baseline(federation)
            if not self.persisted_queries and _persisted_required(federation):
                self.persisted_queries = True
                federation = self.query(route, FEDERATION_SDL_QUERY, {},
                                        "graphql-federation-sdl-persisted", persisted=True)
                if federation is not None:
                    self._remember_baseline(federation)
            schema = _federation_schema(federation)
            if schema is not None:
                self.schema_source = "federation-sdl"
        if schema is None:
            self.stopped = self.stopped or "no validated Query schema"
            return None

        candidates = _query_candidates(
            schema, reference, explicit_input=explicit_input,
            reference_field=reference_field, list_limit=list_limit)
        if not candidates:
            self.stopped = "no safe protected Query field"
            return None
        for row in candidates:
            response = self.query(route, row["document"], row["variables"], "graphql-read",
                                  persisted=self.persisted_queries)
            if not self.persisted_queries and _persisted_required(response):
                self._remember_baseline(response)
                self.persisted_queries = True
                response = self.query(route, row["document"], row["variables"],
                                      "graphql-read-persisted", persisted=True)
            info = _graphql_result(response, row["alias"], self.baseline_texts,
                                   urllib.parse.urlsplit(self.url).hostname)
            if not info["success"]:
                self._remember_baseline(response)
                if self._stopped or self.stopped in ("deadline", "max_requests", "stopped"):
                    break
                continue
            # A valid Query result with no flag-format evidence is only another
            # read control; try the next (bounded) schema-ranked candidate.
            if not info["auto"] and not info["candidates"] and not info.get("wire"):
                self._remember_baseline(response)
                continue
            self.success = True
            self.where = f"{row['field']}({row['argument']})"
            self.uuid4 = bool(info["uuid4"])
            self.candidates = list(info["candidates"])
            if info["auto"] is None:
                self.candidates += [value for value in info.get("wire", []) if value not in self.candidates]
            # A successful resolver response is terminal even when its token has
            # a future format.  Do not query sibling fields after success.
            self.stopped = "successful query; candidate surfaced" if info["auto"] is None else None
            return info["auto"]
        self.stopped = self.stopped or "no successful protected read"
        return None

    def summary(self, proof):
        return {"proof": proof, "success": self.success,
                "candidates": list(dict.fromkeys(self.candidates))[:12], "uuid4": self.uuid4,
                "requests": self.requests, "posts": self.posts,
                "transport": self.transport, "schema_source": self.schema_source,
                "persisted_queries": self.persisted_queries,
                "baseline_proofs": _baseline_proofs(self.baseline_texts),
                "baseline_incomplete": _baselines_incomplete(self.baseline_texts),
                "findings": self.findings[:8],
                "manifest_query_matches": self.manifest_matches[:8],
                "seconds": round(time.time() - self.t0, 3), "where": self.where,
                "stopped": self.stopped, "responses": self.responses[:24]}


def _append_evidence(ctx, line):
    evidence = ctx.get("evidence")
    if not isinstance(evidence, list):
        return
    lock = ctx.get("_evidence_lock")
    if hasattr(lock, "__enter__"):
        with lock:
            evidence.append(line)
    else:
        evidence.append(line)


def _surface(runner, ctx):
    if not runner.candidates:
        return
    aid = runner.target.get("answer_id") or "target"
    for value in list(dict.fromkeys(runner.candidates))[:6]:
        safe = re.sub(r"[\x00-\x1f\x7f]+", " ", str(value)).strip()[:256]
        _append_evidence(ctx, f"WEB GRAPHQL CANDIDATE {aid}: {safe} "
                              f"(successful query response; not auto-submitted)")


def solve(target, ctx=None):
    """Solve one target.  Never raises and never submits."""
    ctx = dict(ctx or {})
    runner = _Reader(target, ctx)
    proof = None
    try:
        proof = runner.run()
    except Exception as exc:
        runner.stopped = runner.stopped or f"error: {type(exc).__name__}"
    finally:
        runner.stop_now()
    summary = runner.summary(proof)
    _surface(runner, ctx)
    sink = ctx.get("result_sink")
    if isinstance(sink, dict):
        sink[runner.target.get("answer_id") or "target"] = summary
    logged = dict(runner.target)
    logged.setdefault("answer_id", "target")
    _write_log(ctx.get("log_dir"), ctx.get("challenge"), [logged], {logged["answer_id"]: summary})
    return proof


def solve_targets(targets, ctx=None):
    """Run targets concurrently; no request can begin after this function returns."""
    try:
        ctx = dict(ctx or {})
        valid = [dict(target) for target in list(targets or []) if isinstance(target, dict)
                 and target.get("answer_id") and target.get("url")]
    except Exception:
        return {}
    results, summaries, runners = {}, {}, {}
    lock = threading.Lock()
    ctx["_evidence_lock"] = threading.Lock()

    def one(target):
        aid = target["answer_id"]
        local = dict(ctx)
        runner = _Reader(target, local)
        with lock:
            runners[aid] = runner
        try:
            proof = runner.run()
        except Exception as exc:
            runner.stopped = runner.stopped or f"error: {type(exc).__name__}"
            proof = None
        with lock:
            results[aid] = proof
            summaries[aid] = runner.summary(proof)
        _surface(runner, ctx)

    threads = [threading.Thread(target=one, args=(target,), name=f"graphql-read-{target['answer_id']}", daemon=True)
               for target in valid]
    for thread in threads:
        thread.start()
    try:
        deadline = float(ctx["deadline"]) if ctx.get("deadline") is not None else None
    except (TypeError, ValueError):
        deadline = None
    for thread in threads:
        thread.join(timeout=None if deadline is None else max(0.0, deadline - time.time()))
    for runner in list(runners.values()):
        runner.stop_now()
    for thread in threads:
        thread.join(timeout=REQUEST_TIMEOUT + 0.5)
    for target in valid:
        aid = target["answer_id"]
        results.setdefault(aid, None)
        if aid in runners:
            summaries[aid] = runners[aid].summary(results[aid])
    _write_log(ctx.get("log_dir"), ctx.get("challenge"), valid, summaries)
    sink = ctx.get("result_sink")
    if isinstance(sink, dict):
        sink.update(summaries)
    return results


def _write_log(log_dir, challenge, targets, summaries):
    if not log_dir:
        return
    try:
        folder = Path(log_dir)
        folder.mkdir(parents=True, exist_ok=True)
        at = _dt.datetime.now().astimezone().isoformat(timespec="seconds")
        with (folder / "graphql_read.jsonl").open("a", encoding="utf-8") as handle:
            for target in targets:
                aid = target["answer_id"]
                row = {"at": at, "challenge": challenge, "answer_id": aid, "index": target.get("index")}
                row.update(summaries.get(aid) or {"proof": None, "stopped": "no result"})
                handle.write(json.dumps(row, separators=(",", ":"), default=str) + "\n")
    except Exception:
        pass


__all__ = ["enabled", "solve", "solve_targets", "INTROSPECTION_QUERY"]
