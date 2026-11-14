#!/usr/bin/env python3
"""Stateful WebSocket client core + offline client-trust recon (B-049).

Two things live here, both offline and both reused by the bounded real-time proof reader
(``realtime_read.py``) and, later, by the proof-replay / mesh-protocol chains (B-107, B-123):

1. A **stateful WebSocket client core**.  Stateful WS protocols (an RTU command channel, a
   turn-sequenced game socket) reject any frame whose sequence/nonce counter is wrong.  This module
   keeps that counter (:class:`SequenceState`) and renders a bounded, pre-planned set of application
   messages from one exact frame schema (:func:`build_sequenced_messages`).  It opens no socket; the
   wire work stays in the target-pinned ``web.WebClient.websocket_conversation``.  The counter is
   explicit and injectable so a test drives it with a fixed clock/nonce, never wall-clock randomness.

2. A **client-trust recon rule** over already-fetched ``app.js`` (:func:`flag_client_trust`).  It
   flags geofence / eligibility / entitlement decisions that the application makes **in the browser**
   and then trusts -- the client-side trust boundary a server must re-check.  It also mines the
   bundle for WebSocket frame layouts (:func:`mine_frame_schemas`) by reusing ``js_recon`` (endpoint /
   param leads) and ``api_protocols`` (the lexical JSON-key reader and saved-frame parser), and reuses
   ``client_side_depth`` for the surrounding DOM/postMessage review.  It is a LEAD generator: it
   derives no answer, submits nothing, and never opens a browser, parses a DOM, or evaluates JS.

CLI (offline triage of one or more saved JS bundles):

    python -m ctf run web.ws_client_trust            # refused: library engine
    python solvers/web/ws_client_trust.py app.js [more.js ...] [--json]

Public API:
    SequenceState(start=, step=, nonce_factory=, nonce_bytes=)
    build_sequenced_messages(static_fields, sequence_field, count, state, nonce_field=) -> list[str]
    mine_frame_schemas(app_js) -> {"schemas": list[dict], "ws_endpoints": list[str], "ws_scan_error": str|None}
    flag_client_trust(app_js) -> list[dict]
    analyze_app_js(app_js, package_manifest="", saved_frames="") -> dict
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import api_protocols as _api  # noqa: E402  -- lexical JSON keys + saved-frame parser (offline)
import client_side_depth as _csd  # noqa: E402  -- JS masking + DOM/postMessage review (offline)
import js_recon as _jsr  # noqa: E402  -- endpoint / param / config leads (offline)

# A conservative JSON-object field name (shared with realtime_read's PARAM).
FIELD = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}")
MAX_SOURCE = 2 * 1024 * 1024
MAX_MESSAGES = 4                 # the WebClient conversation bound; a stateful read stays small
MAX_SCHEMAS = 24
MAX_FINDINGS = 64
MAX_BLOCK = 4096                 # bytes of an if/handler body scanned for a gated action


class WSClientTrustError(ValueError):
    """Raised for a malformed schema, counter, or oversize artifact."""


# ======================================================================================
#  1. Stateful client core: the sequence / nonce counter and the message renderer
# ======================================================================================
class SequenceState:
    """A monotonic sequence counter with an optional fresh-nonce source.

    ``start``/``step`` define the arithmetic the server expects (an RTU channel that wants
    1, 2, 3 is ``start=1, step=1``; one that wants even frames is ``start=2, step=2``).
    ``next_sequence`` issues the next value; ``next_nonce`` issues a fresh token.  The nonce
    source is injectable (``nonce_factory``: a callable taking the 1-based issue index and
    returning a field-safe string) so a test is deterministic; the default draws
    ``nonce_bytes`` of ``os.urandom`` as hex, which is genuinely unpredictable on the wire.
    State is explicit: ``snapshot`` and ``issued`` expose it for an audit trail.
    """

    def __init__(self, *, start=1, step=1, nonce_factory=None, nonce_bytes=8):
        if isinstance(start, bool) or not isinstance(start, int):
            raise WSClientTrustError("sequence start must be an int")
        if isinstance(step, bool) or not isinstance(step, int) or step == 0:
            raise WSClientTrustError("sequence step must be a non-zero int")
        if isinstance(nonce_bytes, bool) or not isinstance(nonce_bytes, int) \
                or not 1 <= nonce_bytes <= 64:
            raise WSClientTrustError("nonce_bytes must be an int in 1..64")
        if nonce_factory is not None and not callable(nonce_factory):
            raise WSClientTrustError("nonce_factory must be callable")
        self._start = start
        self._step = step
        self._nonce_factory = nonce_factory
        self._nonce_bytes = nonce_bytes
        self._issued = 0
        self._nonces = 0
        self._value = start - step   # so the first next_sequence() returns start

    @property
    def issued(self):
        return self._issued

    @property
    def current_sequence(self):
        """The last value handed out, or None before the first issue."""
        return None if self._issued == 0 else self._value

    def next_sequence(self):
        self._value += self._step
        self._issued += 1
        return self._value

    def next_nonce(self):
        self._nonces += 1
        index = self._nonces     # 1-based nonce issue count, independent of the sequence
        if self._nonce_factory is not None:
            token = self._nonce_factory(index)
            if not isinstance(token, str) or not FIELD.fullmatch(token):
                raise WSClientTrustError("nonce_factory must return a field-safe token")
            return token
        # Prefix a letter so the token is field-safe even when the random hex starts with a digit.
        return "n" + os.urandom(self._nonce_bytes).hex()

    def snapshot(self):
        return {"start": self._start, "step": self._step, "issued": self._issued,
                "nonces": self._nonces, "current_sequence": self.current_sequence}


def build_sequenced_messages(static_fields, sequence_field, count, state, *, nonce_field=None):
    """Render ``count`` JSON application messages, each carrying the next sequence (and nonce).

    ``static_fields`` is the constant part of every frame (id, operation, reference);
    ``sequence_field`` and the optional ``nonce_field`` are filled from ``state`` per message, so
    message i gets the i-th issued sequence and a fresh nonce.  The result is a list of compact
    JSON strings ready for ``WebClient.websocket_conversation``.  Nothing is sent here.
    """
    if not isinstance(static_fields, dict):
        raise WSClientTrustError("static_fields must be a dict")
    if not isinstance(state, SequenceState):
        raise WSClientTrustError("state must be a SequenceState")
    if isinstance(count, bool) or not isinstance(count, int) or not 1 <= count <= MAX_MESSAGES:
        raise WSClientTrustError(f"count must be an int in 1..{MAX_MESSAGES}")
    names = [sequence_field] + ([nonce_field] if nonce_field is not None else []) + list(static_fields)
    for name in names:
        if not isinstance(name, str) or not FIELD.fullmatch(name):
            raise WSClientTrustError(f"field name {name!r} is not a conservative token")
    if len(set(names)) != len(names):
        raise WSClientTrustError("sequence/nonce/static field names must be distinct")
    for value in static_fields.values():
        if isinstance(value, (dict, list)):
            raise WSClientTrustError("static field values must be scalars")
    messages = []
    for _ in range(count):
        frame = dict(static_fields)
        frame[sequence_field] = state.next_sequence()
        if nonce_field is not None:
            frame[nonce_field] = state.next_nonce()
        messages.append(json.dumps(frame, separators=(",", ":"), ensure_ascii=False))
    return messages


# ======================================================================================
#  2a. Recon: mine app.js for WebSocket frame layouts
# ======================================================================================
_SEND_CALL = re.compile(
    r"(?:\b(?:ws|socket|sock|conn|connection|client)\w*\s*\.\s*send|\.send)\s*\(", re.I)
_SEQ_HINT = re.compile(r"(?i)^(?:seq(?:uence|no|num)?|msg_?(?:id|no|num|seq)|message_?(?:id|seq)|"
                       r"counter|frame_?(?:id|no)|index|idx|ordinal|tick|serial)$")
_NONCE_HINT = re.compile(r"(?i)^(?:nonce|challenge|rand(?:om)?|salt|csrf|token|otp|iv|request_?id|"
                         r"req_?id|replay_?(?:id|guard))$")
# An object-literal key, quoted (JSON) or bare (a JS identifier key): ``key:`` after ``{`` or ``,``.
_OBJECT_KEY = re.compile(
    r"""(?:^|[{,])\s*(?:"([A-Za-z_][\w.$-]{0,63})"|'([A-Za-z_][\w.$-]{0,63})'|([A-Za-z_$][\w$]{0,63}))\s*:""")


def _object_keys(literal):
    """Field names of one object literal, quoted or bare, in order and de-duplicated."""
    keys = []
    for match in _OBJECT_KEY.finditer(literal):
        key = next((g for g in match.groups() if g), None)
        if key and key not in keys:
            keys.append(key)
    return keys


def _object_literals(masked):
    """Yield (start, end) spans of top-level ``{...}`` object literals, bounded and non-nested-tracked."""
    spans = []
    i = 0
    n = len(masked)
    while i < n and len(spans) < 512:
        if masked[i] != "{":
            i += 1
            continue
        depth = 0
        start = i
        while i < n and i - start < MAX_BLOCK:
            if masked[i] == "{":
                depth += 1
            elif masked[i] == "}":
                depth -= 1
                if depth == 0:
                    spans.append((start, i + 1))
                    break
            i += 1
        i = max(i + 1, start + 1)
    return spans


def mine_frame_schemas(app_js):
    """Infer candidate WebSocket frame field layouts from ``app.js``.

    A lead, never a claim: it finds the object literals passed to a ``.send(...)`` call (and the
    keys of any ``JSON.stringify({...})`` nearby), reads their field names with ``api_protocols``'
    lexical JSON-key reader, and labels sequence-like and nonce-like fields a stateful client would
    have to maintain.  It also surfaces ``ws://``/``wss://`` endpoints via ``js_recon``.
    """
    text = _csd._text(app_js, "app_js", MAX_SOURCE)
    # Preserve string literals (region names, field names) but blank comments.
    masked = _csd._mask_javascript(text, preserve_strings=True)
    schemas = []
    for match in _SEND_CALL.finditer(masked):
        window = masked[match.end(): match.end() + MAX_BLOCK]
        brace = window.find("{")
        if brace < 0 or brace > 200:
            continue
        spans = _object_literals(window[brace:])
        if not spans:
            continue
        start, end = spans[0]
        literal = text[match.end() + brace + start: match.end() + brace + end]
        # Bare JS identifier keys are common in source (quoted keys appear in captured JSON); take both.
        keys = _object_keys(literal)
        if not keys:
            continue
        seq_fields = [k for k in keys if _SEQ_HINT.fullmatch(k)]
        nonce_fields = [k for k in keys if _NONCE_HINT.fullmatch(k)]
        line = text.count("\n", 0, match.start()) + 1
        schemas.append({
            "fields": keys[:32],
            "sequence_fields": seq_fields,
            "nonce_fields": nonce_fields,
            "stateful": bool(seq_fields or nonce_fields),
            "evidence": literal[:300],
            "line": line,
        })
        if len(schemas) >= MAX_SCHEMAS:
            break
    # Dedup identical field sets, keeping the first evidence.
    seen = set()
    unique = []
    for schema in schemas:
        key = (tuple(schema["fields"]), tuple(schema["sequence_fields"]), tuple(schema["nonce_fields"]))
        if key in seen:
            continue
        seen.add(key)
        unique.append(schema)
    # ``js_recon`` is best-effort recon enrichment on top of the schemas we already have, so a fault
    # here must not sink the whole miner -- but it must not vanish either (Rule 6: no silent fallback).
    # Record a named reason beside an empty endpoint list instead of swallowing the error wordlessly.
    ws_scan_error = None
    try:
        leads = _jsr.scan_text("<app.js>", text)
        ws_endpoints = sorted(u for u in leads.get("urls", []) if u.startswith(("ws://", "wss://")))
    except Exception as exc:  # noqa: BLE001 -- enrichment only; the reason is surfaced, not hidden
        ws_endpoints = []
        ws_scan_error = f"js_recon endpoint scan failed: {type(exc).__name__}: {exc}"
    return {"schemas": unique, "ws_endpoints": ws_endpoints, "ws_scan_error": ws_scan_error}


# ======================================================================================
#  2b. Recon rule: client-side trust boundaries (geofence / eligibility in the browser)
# ======================================================================================
# A browser-only signal that must never decide access on its own.
_CLIENT_SIGNALS = (
    ("geolocation", re.compile(r"\bnavigator\s*\.\s*geolocation\b")),
    ("navigator_language", re.compile(r"\bnavigator\s*\.\s*languages?\b")),
    ("resolved_timezone", re.compile(r"\.resolvedOptions\s*\(\s*\)\s*\.\s*timeZone\b")),
    ("navigator_platform", re.compile(r"\bnavigator\s*\.\s*(?:platform|userAgentData|userAgent)\b")),
    ("client_storage_flag", re.compile(
        r"(?i)(?:localStorage|sessionStorage)\s*\.\s*getItem\s*\(\s*['\"][^'\"]*"
        r"(?:eligib|entitl|allow|premium|region|country|geo|tier|unlock|verified|feature)")),
    ("cookie_flag", re.compile(
        r"(?i)document\s*\.\s*cookie\b[^;\n]{0,80}(?:eligib|entitl|allow|premium|region|geo)")),
)
# An eligibility / geofence identifier: the name of a decision the client is making.
_ELIGIBILITY = re.compile(
    r"(?i)\b(?:is|has|can|check|verify|within|in)?_?"
    r"(?:eligib\w*|entitl\w*|allow(?:ed|list)?|allowlist|whitelist|geofenc\w*|geo_?gate|"
    r"cordon\w*|perimeter|in_?region|region_?(?:allow|ok|check|gate)|country_?(?:allow|ok|gate)|"
    r"access(?:_?granted|_?allowed)?|premium|unlocked|entitlement|license[d]?|kyc|age_?gate|"
    r"restricted|withinbounds)\w*\b")
# A literal string comparison in the browser (``=== 'US'``, ``.startsWith('en')``).
_REGION_LITERAL = re.compile(
    r"(?i)(?:===?|!==?|\.(?:startsWith|includes|indexOf|test|match))\s*\(?\s*"
    r"['\"][A-Za-z]{2,32}['\"]")
# A geo/region/locale-named identifier: only then is a bare string comparison a geofence signal
# (otherwise ``role === 'admin'`` -- a normal server-derived authz check -- would be a false positive).
_GEO_NAME = re.compile(
    r"(?i)\b(?:region|countr(?:y|ies)|country_?code|locale|languages?|lang|geo\w*|time_?zone|tz|"
    r"nation|territor(?:y|ies)|continent|coords?|latitude|longitude|postal|zip_?code)\b")
# What a client-side decision gates (a privileged action that reaches the server or unlocks UI).
_GATE_ACTION = re.compile(
    r"(?i)(?:\bfetch\s*\(|\bXMLHttpRequest\b|new\s+WebSocket\b|\.send\s*\(|\.submit\s*\(|"
    r"\b(?:window\.)?location\s*(?:\.href\s*=|\.(?:assign|replace)\s*\()|\bwindow\.open\s*\(|"
    r"\.removeAttribute\s*\(\s*['\"]disabled['\"]|\.disabled\s*=\s*(?:false|!1)\b|"
    r"\.classList\s*\.\s*(?:remove|add)\s*\(\s*['\"](?:hidden|disabled|locked|blur)|"
    r"\.hidden\s*=\s*(?:false|!1)\b|\brender\w*\s*\(|\bnavigate\s*\()")
# A block that refuses when ineligible (the negative gate).
_BLOCK_ACTION = re.compile(
    r"(?i)\b(?:return\b|throw\b|redirect\s*\(|location\s*\.\s*(?:href|assign|replace)|"
    r"alert\s*\(|disabled\s*=\s*(?:true|!0))")
_ASSIGN = re.compile(r"(?:\b(?:const|let|var)\s+)?([A-Za-z_$][A-Za-z0-9_$]{0,63})\s*=\s*([^;\n]{1,2048})")
_IF = re.compile(r"\bif\s*\(")


def _matching_block(masked, open_paren):
    """Return the span (after the if-condition) of the controlled block, bounded to MAX_BLOCK."""
    depth = 0
    i = open_paren
    n = len(masked)
    # Walk the condition parentheses.
    while i < n and i - open_paren < MAX_BLOCK:
        if masked[i] == "(":
            depth += 1
        elif masked[i] == ")":
            depth -= 1
            if depth == 0:
                break
        i += 1
    cond_end = i
    j = i + 1
    while j < n and masked[j] in " \t\r\n":
        j += 1
    if j < n and masked[j] == "{":
        depth = 0
        start = j
        while j < n and j - start < MAX_BLOCK:
            if masked[j] == "{":
                depth += 1
            elif masked[j] == "}":
                depth -= 1
                if depth == 0:
                    return open_paren, cond_end, (start, j + 1)
            j += 1
        return open_paren, cond_end, (start, min(n, start + MAX_BLOCK))
    # Single-statement body (no braces): bound to the statement/line.
    return open_paren, cond_end, (j, min(n, j + 256))


def _signals_in(text):
    return [name for name, pattern in _CLIENT_SIGNALS if pattern.search(text)]


def flag_client_trust(app_js):
    """Flag geofence / eligibility / entitlement decisions decided in the browser.

    Returns a list of lead findings (never answers).  Each finding names the client-side signal, the
    thing it gates, an evidence slice and line, and the server-side re-check the fix requires, plus an
    inert bypass hint for the player to reason about -- the client decision is attacker-controlled.
    """
    text = _csd._text(app_js, "app_js", MAX_SOURCE)
    masked = _csd._mask_javascript(text, preserve_strings=True)
    findings = []
    seen = set()

    def add(name, severity, signal, gated, offset, note, bypass_hint, confidence):
        key = (name, offset // 8)
        if key in seen:
            return
        seen.add(key)
        findings.append({
            "family": "client_side_trust",
            "name": name,
            "severity": severity,
            "signal": signal,
            "gated": gated[:160],
            "evidence": text[max(0, offset - 50): offset + 150][:300],
            "line": text.count("\n", 0, offset) + 1,
            "note": note,
            "inert_bypass_hint": bypass_hint,
            "confidence": confidence,
            "offline": True, "browser_started": False, "network_requests": 0,
        })

    # Tier 1: an if-condition that reads an eligibility signal and gates a privileged action.
    for match in _IF.finditer(masked):
        if len(findings) >= MAX_FINDINGS:
            break
        _open, cond_end, (bstart, bend) = _matching_block(masked, match.end() - 1)
        condition = masked[match.end(): cond_end]
        body = masked[bstart: bend]
        signals = _signals_in(condition + " " + body)
        eligibility_named = bool(_ELIGIBILITY.search(condition))
        region_literal = bool(_REGION_LITERAL.search(condition)) and bool(_GEO_NAME.search(condition))
        if not (signals or eligibility_named or region_literal):
            continue
        gate = _GATE_ACTION.search(body)
        block = _BLOCK_ACTION.search(body)
        signal = signals[0] if signals else ("region_literal" if region_literal
                                             else "eligibility_variable")
        if gate:
            gated = text[bstart + gate.start(): bstart + gate.end()]
            add("client_side_trust_gate", "high", signal, gated, match.start(),
                "A privileged action is unlocked by a decision the browser made; the server must "
                "re-derive eligibility and re-authorize the action, never trust this gate.",
                "the condition is attacker-controlled -- force it true (set the flag / spoof the "
                "region/timezone) to see whether the server independently enforces the boundary",
                "high")
        elif block:
            add("client_side_eligibility_block", "medium", signal, "ineligible-path block",
                match.start(),
                "The browser blocks ineligible users here; if the server does not repeat the check, "
                "skipping the client block reaches the protected behaviour.",
                "bypass the client refusal (edit/disable the check) and send the request the block "
                "guards; a server that re-checks will still refuse",
                "medium")

    # Tier 2: an eligibility variable assigned from a client-side signal or a region literal.
    for match in _ASSIGN.finditer(masked):
        if len(findings) >= MAX_FINDINGS:
            break
        name, expr = match.group(1), match.group(2)
        if not _ELIGIBILITY.search(name):
            continue
        signals = _signals_in(expr)
        region_literal = bool(_REGION_LITERAL.search(expr)) and bool(_GEO_NAME.search(expr))
        if not (signals or region_literal):
            continue
        signal = signals[0] if signals else "region_literal"
        add("client_side_eligibility_decision", "medium", signal, f"{name} = ...",
            match.start(),
            f"The browser computes '{name}' from a client-controlled signal; any later use of it as "
            "an authorization input is a trust boundary the server must not rely on.",
            f"'{name}' is computed client-side and can be set to any value before it is used or sent",
            "medium")

    return findings[:MAX_FINDINGS]


# ======================================================================================
#  2c. Combined offline report (the library entry)
# ======================================================================================
def analyze_app_js(app_js, package_manifest="", saved_frames=""):
    """The combined offline client-trust + WS-frame report for one saved bundle.

    ``saved_frames`` (optional) are raw RFC 6455 bytes from a capture; they are parsed and reviewed by
    ``api_protocols`` without opening a socket.  Returns only leads.
    """
    report = {
        "client_trust": flag_client_trust(app_js),
        "frame_schemas": mine_frame_schemas(app_js),
        "client_side": None,
        "saved_frame_findings": [],
        "offline": True, "browser_started": False, "network_requests": 0,
    }
    try:
        report["client_side"] = _csd.analyze_client_side(app_js, package_manifest=package_manifest)
    except _csd.ClientDepthInputError as exc:
        report["client_side"] = {"error": str(exc)}
    if saved_frames:
        try:
            findings = _api.analyze_websocket_frames(saved_frames, direction="server", source=app_js)
            report["saved_frame_findings"] = [
                {"id": f.finding_id, "title": f.title, "severity": f.severity,
                 "confidence": f.confidence, "evidence": list(f.evidence)} for f in findings]
        except _api.APIProtocolError as exc:
            report["saved_frame_findings"] = [{"error": str(exc)}]
    return report


# ======================================================================================
#  CLI
# ======================================================================================
def _main(argv):
    args = [a for a in argv if a != "--json"]
    as_json = "--json" in argv
    if not args:
        print(__doc__)
        return 64
    reports = {}
    for path in args:
        try:
            # Read untrusted JS as bytes; analysis never executes it.
            data = Path(path).read_bytes()
        except OSError as exc:
            print(f"skip {path}: {exc}", file=sys.stderr)
            continue
        reports[Path(path).name] = analyze_app_js(data)
    if as_json:
        print(json.dumps(reports, indent=2, default=str))
        return 0
    for name, report in reports.items():
        trust = report["client_trust"]
        schemas = report["frame_schemas"]["schemas"]
        ws = report["frame_schemas"]["ws_endpoints"]
        print(f"WS CLIENT-TRUST {name}: trust_flags={len(trust)} frame_schemas={len(schemas)} "
              f"ws_endpoints={len(ws)} (leads only -- never an answer)")
        for finding in trust:
            print(f"  [{finding['severity']}] {finding['name']} via {finding['signal']} "
                  f"(line {finding['line']}): gates {finding['gated']}")
        for schema in schemas:
            tag = "stateful" if schema["stateful"] else "stateless"
            print(f"  frame ({tag}) line {schema['line']}: fields={schema['fields']} "
                  f"seq={schema['sequence_fields']} nonce={schema['nonce_fields']}")
        for endpoint in ws:
            print(f"  ws endpoint: {endpoint}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
