#!/usr/bin/env python3
"""Bounded, offline browser and Content-Security-Policy reconnaissance.

``analyze`` accepts already-downloaded HTML, JavaScript and response headers.  It
never opens a URL, imports target code, evaluates JavaScript, or constructs an
exploit.  Its output is JSON-serializable evidence for a human/web agent.

The JavaScript pass is deliberately a small intra-scope data-flow recognizer,
not a JavaScript parser.  It follows direct sources and simple aliases only.
Unknown calls, conditional assignments, object aliases and cross-function flows
are declined so that a regex coincidence is never presented as a proved flow.
"""

from __future__ import annotations

import copy
import re
import time
import urllib.parse
from bisect import bisect_left, bisect_right
from html.parser import HTMLParser
from itertools import islice


VERSION = 1

# Hard limits are part of the public result so callers can distinguish "not
# found" from "not inspected past the cap".
MAX_HTML = 512 * 1024
MAX_JS = 768 * 1024
MAX_HEADERS = 128
MAX_HEADER_VALUE = 16 * 1024
MAX_POLICIES = 32
MAX_DIRECTIVES = 64
MAX_SOURCE_TOKENS = 128
MAX_INLINE_SCRIPTS = 32
MAX_SCRIPT_LEADS = 64
MAX_SCOPES = 64
MAX_STATEMENTS = 4096
MAX_STATEMENT_CHARS = 64 * 1024
# ``analyze`` caps JavaScript by characters.  Four bytes per character is the
# largest UTF-8 representation, so preprocessing can never silently allocate
# or scan an unbounded target-controlled string.
MAX_PREPROCESS_BYTES = MAX_JS * 4
MAX_PREPARED_CHARS = MAX_JS + MAX_SCOPES
MAX_STATE = 256
MAX_FINDINGS = 160
MAX_SAFE_FLOWS = 80
MAX_UNRESOLVED = 80

_DIRECTIVE = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
_IDENT = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")
_NONCE = re.compile(r"^'nonce-([A-Za-z0-9+/_-]{1,512}={0,2})'$", re.I)
_HASH = re.compile(r"^'(sha256|sha384|sha512)-([A-Za-z0-9+/_-]{8,1024}={0,2})'$", re.I)
_CSP_KEYWORDS = {
    "'none'", "'self'", "'strict-dynamic'", "'unsafe-inline'", "'unsafe-eval'",
    "'wasm-unsafe-eval'", "'unsafe-hashes'", "'report-sample'", "'inline-speculation-rules'",
}
_META_UNSUPPORTED = {"frame-ancestors", "sandbox", "report-uri", "report-to"}
_EFFECTIVE_DIRECTIVES = (
    "script-src", "script-src-elem", "script-src-attr", "connect-src",
    "frame-ancestors", "form-action", "base-uri",
)
_FALLBACKS = {
    "script-src": ("script-src", "default-src"),
    "script-src-elem": ("script-src-elem", "script-src", "default-src"),
    "script-src-attr": ("script-src-attr", "script-src", "default-src"),
    "connect-src": ("connect-src", "default-src"),
    "frame-ancestors": ("frame-ancestors",),
    "form-action": ("form-action",),
    "base-uri": ("base-uri",),
}

_GLOBAL_NAMES = {
    "window", "document", "location", "globalThis", "localStorage", "sessionStorage",
    "URLSearchParams", "DOMParser", "DOMPurify", "trustedTypes", "navigator",
    "WebSocket", "EventSource", "BroadcastChannel",
}
_RESERVED = {
    "const", "let", "var", "new", "return", "if", "else", "for", "while", "switch",
    "case", "break", "continue", "function", "async", "await", "true", "false", "null",
    "undefined", "this", "typeof", "instanceof", "void", "delete", "throw", "try", "catch",
    "finally", "class", "extends", "static", "get", "set", "of", "in", "yield", "import",
    "export", "default",
}


def _halted(deadline=None, stop=None):
    """Cooperative offline deadline/stop check; never owns or changes a timer."""
    try:
        if hasattr(stop, "is_set") and stop.is_set():
            return True
        return deadline is not None and time.time() >= float(deadline)
    except (TypeError, ValueError):
        return True


def _bounded_text(value, limit):
    if value is None:
        return "", False
    if isinstance(value, bytes):
        text = value.decode("utf-8", "replace")
    else:
        text = str(value)
    return text[:limit], len(text) > limit


def _clean_display(value, limit=240):
    return re.sub(r"[\x00-\x1f\x7f-\x9f]+", " ", str(value or "")).strip()[:limit]


def _ordered_headers(headers):
    """Return ordered ``(lower-name, value)`` pairs without inventing duplicates."""
    if headers is None:
        return [], False
    raw = None
    try:
        if hasattr(headers, "raw_items"):
            raw = list(islice(headers.raw_items(), MAX_HEADERS + 1))
        elif isinstance(headers, dict) or hasattr(headers, "items"):
            raw = []
            for key, value in islice(headers.items(), MAX_HEADERS + 1):
                if isinstance(value, (list, tuple)):
                    room = MAX_HEADERS + 1 - len(raw)
                    raw.extend((key, item) for item in value[:room])
                    if len(value) > room:
                        raw.append((key, None))
                else:
                    raw.append((key, value))
                if len(raw) > MAX_HEADERS:
                    break
        else:
            raw = list(islice(headers, MAX_HEADERS + 1))
    except Exception:
        return [], True
    out = []
    truncated = len(raw) > MAX_HEADERS
    for item in raw[:MAX_HEADERS]:
        if not isinstance(item, (list, tuple)) or len(item) != 2:
            continue
        name, value = str(item[0]).strip().lower(), str(item[1])
        if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9a-z-]+", name):
            continue
        if any(ch in value for ch in ("\r", "\n", "\x00")):
            out.append((name, None))
            continue
        if len(value) > MAX_HEADER_VALUE:
            out.append((name, None))
            truncated = True
            continue
        out.append((name, value.strip()))
    return out, truncated


class _HTMLInventory(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.meta = []
        self.meta_truncated = False
        self.inline_scripts = []
        self.script_leads = []
        self.template_sinks = []
        self.javascript_urls = []
        self._script = None
        self._script_line = None

    def handle_starttag(self, tag, attrs):
        attrs = {str(k).lower(): ("" if v is None else str(v)) for k, v in attrs[:64]}
        low = tag.lower()
        if low == "meta":
            equiv = attrs.get("http-equiv", "").strip().lower()
            if equiv in ("content-security-policy", "content-security-policy-report-only"):
                if len(self.meta) < MAX_POLICIES * 2:
                    self.meta.append({"http_equiv": equiv, "content": attrs.get("content", ""),
                                      "line": self.getpos()[0]})
                else:
                    self.meta_truncated = True
        if low == "script":
            src = attrs.get("src")
            typ = attrs.get("type", "").strip().lower()
            if src and len(self.script_leads) < MAX_SCRIPT_LEADS:
                self.script_leads.append({"src": _clean_display(src, 500), "line": self.getpos()[0]})
            self._script = [] if not src and typ not in (
                "application/json", "application/ld+json", "importmap", "speculationrules") else None
            self._script_line = self.getpos()[0]
        for name in ("href", "src", "action", "formaction", "xlink:href"):
            value = attrs.get(name, "").lstrip()
            if value.lower().startswith("javascript:") and len(self.javascript_urls) < MAX_FINDINGS:
                self.javascript_urls.append({"tag": low, "attribute": name, "line": self.getpos()[0]})
        if "v-html" in attrs and len(self.template_sinks) < MAX_UNRESOLVED:
            self.template_sinks.append({"sink": "vue_v_html", "expression": attrs["v-html"],
                                        "line": self.getpos()[0]})

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        if tag.lower() == "script" and self._script is not None:
            if len(self.inline_scripts) < MAX_INLINE_SCRIPTS:
                self.inline_scripts.append({"text": "".join(self._script), "line": self._script_line or 1})
            self._script = None
            self._script_line = None

    def handle_data(self, data):
        if self._script is not None:
            self._script.append(data)
        if "{@html" in data:
            for match in re.finditer(r"\{@html\s+([^{}]{1,500})\}", data):
                if len(self.template_sinks) >= MAX_UNRESOLVED:
                    break
                self.template_sinks.append({"sink": "svelte_html", "expression": match.group(1).strip(),
                                            "line": self.getpos()[0]})


def _parse_policy(value, *, policy_id, disposition, source, order, line=None):
    directives = {}
    duplicates = []
    invalid = []
    ignored = []
    parts = str(value or "").split(";")
    truncated = len(parts) > MAX_DIRECTIVES
    token_count = 0
    for raw in parts[:MAX_DIRECTIVES]:
        words = raw.strip().split()
        if not words:
            continue
        name = words[0].lower()
        if not _DIRECTIVE.fullmatch(name):
            invalid.append(_clean_display(raw))
            continue
        if name in directives:
            duplicates.append(name)
            continue  # CSP: the first occurrence wins.
        values = words[1:]
        room = max(0, MAX_SOURCE_TOKENS - token_count)
        if len(values) > room:
            values = values[:room]
            truncated = True
        token_count += len(values)
        normalized = []
        for token in values:
            low = token.lower()
            # Keyword spellings are ASCII-insensitive. Nonce and hash payloads
            # are base64-like and case-sensitive, so preserve their bytes.
            normalized.append(low if low in _CSP_KEYWORDS else token)
        if source == "meta" and name in _META_UNSUPPORTED:
            ignored.append(name)
            continue
        directives[name] = normalized
    features = {
        "nonces": [], "hashes": [], "strict_dynamic": False, "unsafe_inline": False,
        "unsafe_eval": False, "wasm_unsafe_eval": False, "trusted_types": [],
        "require_trusted_types_for_script": False,
    }
    for name, values in directives.items():
        for token in values:
            nonce = _NONCE.match(token)
            digest = _HASH.match(token)
            if nonce:
                features["nonces"].append({"directive": name, "length": len(nonce.group(1))})
            if digest:
                features["hashes"].append({"directive": name, "algorithm": digest.group(1).lower(),
                                            "length": len(digest.group(2))})
            low = token.lower()
            features["strict_dynamic"] |= low == "'strict-dynamic'"
            features["unsafe_inline"] |= low == "'unsafe-inline'"
            features["unsafe_eval"] |= low == "'unsafe-eval'"
            features["wasm_unsafe_eval"] |= low == "'wasm-unsafe-eval'"
        if name == "trusted-types":
            features["trusted_types"] = values[:32]
        if name == "require-trusted-types-for" and "'script'" in [v.lower() for v in values]:
            features["require_trusted_types_for_script"] = True
    return {
        "id": policy_id, "disposition": disposition, "source": source, "order": order,
        "line": line, "directives": directives, "duplicates_ignored": duplicates,
        "invalid_segments": invalid[:16], "meta_ignored_directives": ignored,
        "meta_applies_after_tag": source == "meta", "truncated": truncated, "features": features,
    }


def _effective_csp(enforced):
    result = {}
    for wanted in _EFFECTIVE_DIRECTIVES:
        clauses = []
        unrestricted = []
        for policy in enforced:
            selected = None
            for candidate in _FALLBACKS[wanted]:
                if candidate in policy["directives"]:
                    selected = candidate
                    break
            if selected is None:
                unrestricted.append(policy["id"])
            else:
                clauses.append({"policy": policy["id"], "via": selected,
                                "tokens": list(policy["directives"][selected])})
        common = None
        for clause in clauses:
            tokens = set(clause["tokens"])
            common = tokens if common is None else common & tokens
        result[wanted] = {
            "semantics": "all_policy_clauses_must_allow",
            "clauses": clauses,
            "unrestricted_policies": unrestricted,
            "unrestricted": not clauses,
            # Diagnostic only: different source-expression kinds can both match
            # one load, so this is deliberately not called the effective allowlist.
            "exact_common_tokens": sorted(common or ()),
        }
    return result


def _csp_result(header_pairs, meta_rows, *, source_incomplete=False):
    enforced, report_only, ignored = [], [], []
    order = 0
    for name, value in header_pairs:
        if name not in ("content-security-policy", "content-security-policy-report-only"):
            continue
        if value is None:
            ignored.append({"source": "header", "name": name, "reason": "invalid_or_oversized"})
            continue
        if len(enforced) + len(report_only) >= MAX_POLICIES:
            ignored.append({"source": "header", "name": name, "reason": "policy_cap"})
            continue
        disposition = "report-only" if name.endswith("report-only") else "enforce"
        target = report_only if disposition == "report-only" else enforced
        target.append(_parse_policy(value, policy_id=f"header-{order + 1}", disposition=disposition,
                                    source="header", order=order))
        order += 1
    for meta in meta_rows:
        equiv = meta.get("http_equiv")
        if equiv == "content-security-policy-report-only":
            ignored.append({"source": "meta", "line": meta.get("line"),
                            "reason": "report_only_not_supported_in_meta"})
            continue
        value = meta.get("content", "")
        if any(ch in value for ch in ("\r", "\n", "\x00")) or len(value) > MAX_HEADER_VALUE:
            ignored.append({"source": "meta", "line": meta.get("line"),
                            "reason": "invalid_or_oversized"})
            continue
        if len(enforced) + len(report_only) >= MAX_POLICIES:
            ignored.append({"source": "meta", "line": meta.get("line"), "reason": "policy_cap"})
            continue
        enforced.append(_parse_policy(value, policy_id=f"meta-{order + 1}", disposition="enforce",
                                      source="meta", order=order, line=meta.get("line")))
        order += 1
    input_incomplete = (
        bool(source_incomplete)
        or any(row.get("reason") in {"invalid_or_oversized", "policy_cap"}
            for row in ignored)
        or any(policy.get("truncated") for policy in enforced + report_only)
    )
    findings = []
    # Absence is a high-confidence statement only when every supplied policy
    # was inspected.  In particular, a cap-full prefix of report-only headers
    # must not hide a later enforcing header and become "CSP absent".
    if not enforced and not input_incomplete:
        findings.append({"kind": "csp_absent", "confidence": "high"})
    if report_only and not enforced and not input_incomplete:
        findings.append({"kind": "csp_report_only_without_enforcement", "confidence": "high"})
    for policy in enforced + report_only:
        for duplicate in policy["duplicates_ignored"]:
            findings.append({"kind": "csp_duplicate_directive", "policy": policy["id"],
                             "directive": duplicate, "rule": "first_wins"})
        for directive in policy["meta_ignored_directives"]:
            findings.append({"kind": "csp_meta_ignored_directive", "policy": policy["id"],
                             "directive": directive})
        features = policy["features"]
        for keyword, present in (("'unsafe-inline'", features["unsafe_inline"]),
                                 ("'unsafe-eval'", features["unsafe_eval"]),
                                 ("'wasm-unsafe-eval'", features["wasm_unsafe_eval"]),
                                 ("'strict-dynamic'", features["strict_dynamic"])):
            if present:
                findings.append({"kind": "csp_keyword", "policy": policy["id"],
                                 "disposition": policy["disposition"], "keyword": keyword})
        if features["require_trusted_types_for_script"]:
            findings.append({"kind": "trusted_types_required_for_script", "policy": policy["id"],
                             "disposition": policy["disposition"]})
    return {"enforced": enforced, "report_only": report_only,
            "effective_after_last_meta": _effective_csp(enforced),
            "ignored": ignored[:32], "input_incomplete": input_incomplete,
            "findings": findings[:MAX_FINDINGS]}


def _mask_javascript(text, should_stop=None):
    """Return aligned ``(code, comments_only)`` views.

    Strings, comments, template literal text and likely regular-expression
    literals are blanked in ``code``.  ``comments_only`` retains strings for
    identifying event names around a real call site.  This is intentionally
    conservative: template expressions are not followed.
    """
    code = list(text)
    comments_only = list(text)
    n, i = len(text), 0
    checked = -4096

    def blank(buf, start, end):
        nonlocal checked
        for at in range(start, min(end, len(buf))):
            if at - checked >= 4096 and callable(should_stop) and should_stop():
                return False
            if at - checked >= 4096:
                checked = at
            if buf[at] not in "\r\n":
                buf[at] = " "
        return True

    previous = ""
    while i < n:
        if i - checked >= 4096:
            checked = i
            if callable(should_stop) and should_stop():
                return "", "", True
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if ch == "/" and nxt == "/":
            end = text.find("\n", i + 2)
            end = n if end < 0 else end
            if not blank(code, i, end) or not blank(comments_only, i, end):
                return "", "", True
            i = end
            continue
        if ch == "/" and nxt == "*":
            end = text.find("*/", i + 2)
            end = n if end < 0 else end + 2
            if not blank(code, i, end) or not blank(comments_only, i, end):
                return "", "", True
            i = end
            continue
        if ch in ("'", '"', "`"):
            quote, start = ch, i
            i += 1
            escaped = False
            while i < n:
                if i - checked >= 4096:
                    checked = i
                    if callable(should_stop) and should_stop():
                        return "", "", True
                cur = text[i]
                if escaped:
                    escaped = False
                elif cur == "\\":
                    escaped = True
                elif cur == quote:
                    i += 1
                    break
                i += 1
            if not blank(code, start, i):
                return "", "", True
            previous = quote
            continue
        if ch == "/":
            # Mask a regex literal only in expression-start positions.  A
            # division operator remains code.
            tail = text[max(0, i - 32):i].rstrip()
            word = re.search(r"([A-Za-z_$][\w$]*)$", tail)
            regex_pos = not tail or previous in "=(:,![{;?" or (
                word and word.group(1) in ("return", "case", "throw"))
            if regex_pos:
                start, i, escaped, in_class = i, i + 1, False, False
                while i < n:
                    if i - checked >= 4096:
                        checked = i
                        if callable(should_stop) and should_stop():
                            return "", "", True
                    cur = text[i]
                    if escaped:
                        escaped = False
                    elif cur == "\\":
                        escaped = True
                    elif cur == "[":
                        in_class = True
                    elif cur == "]":
                        in_class = False
                    elif cur == "/" and not in_class:
                        i += 1
                        while i < n and text[i].isalpha():
                            i += 1
                        break
                    elif cur in "\r\n":
                        break
                    i += 1
                if not blank(code, start, i):
                    return "", "", True
                previous = "/"
                continue
        if not ch.isspace():
            previous = ch
        i += 1
    return "".join(code), "".join(comments_only), False


def _brace_pairs(code, should_stop=None):
    """Pair every unmasked brace in one left-to-right pass."""
    stack, pairs = [], {}
    for at, char in enumerate(code):
        if not at % 4096 and callable(should_stop) and should_stop():
            return {}, True
        if char == "{":
            stack.append(at)
        elif char == "}" and stack:
            pairs[stack.pop()] = at
    return pairs, False


def _message_kind(prefix, receiver, constructors):
    clean = receiver.replace("?.", ".") if receiver else ""
    base = clean.split(".")[0]
    if "serviceWorker" in clean:
        return "service_worker_message"
    if base in constructors:
        return constructors[base] + "_message"
    if clean in ("window", "globalThis", "self", ""):
        return "postmessage_data"
    if "BroadcastChannel" in prefix:
        return "broadcast_channel_message"
    return "generic_message_data"


def _visible_segments(start, end, exclusions):
    """Subtract sorted child spans from one scope without copying its body."""
    cursor, out = max(0, start), []
    for left, right in sorted(exclusions):
        left, right = max(cursor, left), min(end, right)
        if right <= cursor:
            continue
        if left > cursor:
            out.append((cursor, left))
        cursor = max(cursor, right)
        if cursor >= end:
            break
    if cursor < end:
        out.append((cursor, end))
    return out


def _scopes(code, comments_only, limit=MAX_SCOPES, should_stop=None):
    if limit <= 0:
        return [], bool(code.strip()), False
    brace_pairs, stopped = _brace_pairs(code, should_stop)
    if stopped:
        return [], True, True
    constructors = {}
    for match in re.finditer(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]{0,127})\s*=\s*new\s+"
                             r"(WebSocket|EventSource|BroadcastChannel)\b", code):
        if callable(should_stop) and should_stop():
            return [], True, True
        constructors[match.group(1)] = {"WebSocket": "websocket", "EventSource": "sse",
                                        "BroadcastChannel": "broadcast_channel"}[match.group(2)]
    candidates = []
    overflow = False
    patterns = []
    if "function" in code:
        patterns.append(("function", re.compile(
            r"\bfunction\s*([A-Za-z_$][\w$]{0,127})?\s*\(([^()]{0,2000})\)\s*\{")))
    if "=>" in code:
        patterns.append(("arrow", re.compile(
            r"(?:\(([^()]{0,2000})\)|([A-Za-z_$][\w$]{0,127}))\s*=>\s*\{")))
    for kind, rx in patterns:
        if overflow:
            break
        for match in rx.finditer(code):
            if callable(should_stop) and should_stop():
                return [], True, True
            # Both braced patterns end at their opening brace.  Taking that
            # exact character avoids confusing a destructuring/default-value
            # brace in the parameter text for the function body.
            opening = match.end() - 1
            closing = brace_pairs.get(opening) if opening >= 0 else None
            if closing is None:
                continue
            if kind == "function":
                name = match.group(1) or "anonymous"
                params = match.group(2)
            else:
                name = "arrow"
                params = match.group(1) if match.group(1) is not None else match.group(2)
            prefix = comments_only[max(0, match.start() - 260):match.start()]
            receiver = None
            message = False
            add = re.search(r"([A-Za-z_$][\w$]*(?:\s*\?*\.\s*[A-Za-z_$][\w$]*)*)\s*\?*\.\s*"
                            r"addEventListener\s*(?:\?\.\s*)?\(\s*['\"]message['\"]\s*,\s*$", prefix)
            on = re.search(r"([A-Za-z_$][\w$]*(?:\s*\?*\.\s*[A-Za-z_$][\w$]*)*)\s*\?*\.\s*"
                           r"onmessage\s*=\s*$", prefix)
            if add or on:
                receiver = re.sub(r"\s+", "", (add or on).group(1))
                message = True
            param_names = [x.strip() for x in params.split(",") if _IDENT.fullmatch(x.strip())]
            candidates.append({"name": name, "match_start": match.start(),
                               "start": opening + 1, "end": closing,
                               "span_end": closing + 1,
                               "params": param_names, "message_kind": _message_kind(prefix, receiver, constructors)
                               if message else None,
                               "event_param": param_names[0] if message and param_names else None})
            if len(candidates) >= limit * 2:
                overflow = True
                break
    # Concise arrow handlers have no braces. Support them only when the call
    # site itself proves message-handler semantics; generic concise arrows do
    # not create a cross-function analysis surface.
    concise = re.compile(r"(?:\(([^()]{0,200})\)|([A-Za-z_$][\w$]{0,127}))\s*=>\s*(?!\{)([^;\r\n]{1,1000})")
    if "=>" in code and not overflow:
        for match in concise.finditer(code):
            if callable(should_stop) and should_stop():
                return [], True, True
            prefix = comments_only[max(0, match.start() - 260):match.start()]
            add = re.search(r"([A-Za-z_$][\w$]*(?:\s*\?*\.\s*[A-Za-z_$][\w$]*)*)\s*\?*\.\s*"
                            r"addEventListener\s*(?:\?\.\s*)?\(\s*['\"]message['\"]\s*,\s*$", prefix)
            on = re.search(r"([A-Za-z_$][\w$]*(?:\s*\?*\.\s*[A-Za-z_$][\w$]*)*)\s*\?*\.\s*"
                           r"onmessage\s*=\s*$", prefix)
            if not (add or on):
                continue
            receiver = re.sub(r"\s+", "", (add or on).group(1))
            params = match.group(1) if match.group(1) is not None else match.group(2)
            param_names = [x.strip() for x in params.split(",") if _IDENT.fullmatch(x.strip())]
            candidates.append({"name": "arrow", "match_start": match.start(),
                               "start": match.start(3), "end": match.end(3),
                               "span_end": match.end(3),
                               "params": param_names, "message_kind": _message_kind(prefix, receiver, constructors),
                               "event_param": param_names[0] if param_names else None,
                               })
            if len(candidates) >= limit * 2:
                overflow = True
                break
    # De-duplicate arrow/function regexes that identify the same body.
    unique = {}
    for row in sorted(candidates, key=lambda x: (x["start"], x["end"] - x["start"])):
        unique.setdefault((row["start"], row["end"]), row)
    all_found = list(unique.values())
    if overflow or len(all_found) > max(0, limit - 1):
        # Partial scope extraction could make an unmasked nested function look
        # like same-scope data flow. Decline the file rather than weaken the
        # cross-function invariant at the cap.
        return [], True, False
    found = all_found
    # Assign each nested scope to its smallest containing parent.  A parent's
    # visible intervals exclude only direct children; those children apply the
    # same rule recursively.  Consequently every source character is copied
    # into at most one prepared body instead of once per nesting level.
    parents = []
    for index, row in enumerate(found):
        containing = [
            (other["end"] - other["start"], other_index)
            for other_index, other in enumerate(found)
            if other_index != index and other["start"] <= row["match_start"]
            and row["span_end"] <= other["end"]
        ]
        parents.append(min(containing)[1] if containing else None)
    top_exclusions = [(row["match_start"], row["span_end"])
                      for index, row in enumerate(found) if parents[index] is None]
    top = {"name": "<top-level>", "match_start": 0, "start": 0, "end": len(code), "params": [],
           "message_kind": None, "event_param": None,
           "segments": _visible_segments(0, len(code), top_exclusions)}
    for index, row in enumerate(found):
        child_spans = [(child["match_start"], child["span_end"])
                       for child_index, child in enumerate(found) if parents[child_index] == index]
        row["segments"] = _visible_segments(row["start"], row["end"], child_spans)
    return [top] + found, False, False


def _statements(body, limit=MAX_STATEMENTS, should_stop=None):
    if limit <= 0:
        return [], bool(body.strip()), False
    out, start = [], 0
    paren = bracket = 0
    for i, ch in enumerate(body):
        if not i % 4096 and callable(should_stop) and should_stop():
            return out, True, True
        if ch == "(": paren += 1
        elif ch == ")": paren = max(0, paren - 1)
        elif ch == "[": bracket += 1
        elif ch == "]": bracket = max(0, bracket - 1)
        if (ch == ";" and paren == 0 and bracket == 0) or ch in "\r\n":
            raw = body[start:i]
            value = raw.strip()
            if value:
                if len(value) > MAX_STATEMENT_CHARS:
                    return out, True, False
                out.append((start + len(raw) - len(raw.lstrip()), value))
                if len(out) >= limit:
                    return out, True, False
            start = i + 1
    raw = body[start:]
    value = raw.strip()
    if value and len(out) < limit:
        if len(value) > MAX_STATEMENT_CHARS:
            return out, True, False
        out.append((start + len(raw) - len(raw.lstrip()), value))
    return out, len(out) >= limit, False


def _copy_flow(flow):
    return {"sources": copy.deepcopy(flow.get("sources", [])),
            "safe_for": set(flow.get("safe_for", set())),
            "transforms": list(flow.get("transforms", [])),
            "ambiguous": bool(flow.get("ambiguous"))}


def _merge_flows(flows):
    result = {"sources": [], "safe_for": set(), "transforms": [], "ambiguous": False}
    first = True
    for flow in flows:
        if not flow:
            continue
        for source in flow.get("sources", []):
            key = (source.get("kind"), source.get("expression"), source.get("line"))
            if key not in {(x.get("kind"), x.get("expression"), x.get("line")) for x in result["sources"]}:
                result["sources"].append(copy.deepcopy(source))
        safe = set(flow.get("safe_for", set()))
        result["safe_for"] = safe if first else result["safe_for"] & safe
        first = False
        result["transforms"] += [x for x in flow.get("transforms", []) if x not in result["transforms"]]
        result["ambiguous"] |= bool(flow.get("ambiguous"))
    return result if result["sources"] else None


def _direct_sources(expr, scope, line):
    shadowed = scope["shadowed"]
    found = []

    def add(kind, expression):
        row = {"kind": kind, "expression": _clean_display(expression, 120), "line": line}
        if row not in found:
            found.append(row)

    patterns = (
        ("location_search", r"(?:(?:window|globalThis|document)\s*\?*\.\s*)?location\s*\?*\.\s*search\b", "location"),
        ("location_hash", r"(?:(?:window|globalThis|document)\s*\?*\.\s*)?location\s*\?*\.\s*hash\b", "location"),
        ("location_href", r"(?:(?:window|globalThis|document)\s*\?*\.\s*)?location\s*\?*\.\s*href\b", "location"),
        ("window_name", r"(?:window|globalThis)\s*\?*\.\s*name\b", "window"),
        ("local_storage", r"\blocalStorage\s*\?*\.\s*(?:getItem\s*(?:\?\.\s*)?\(|[A-Za-z_$][\w$]*)", "localStorage"),
        ("session_storage", r"\bsessionStorage\s*\?*\.\s*(?:getItem\s*(?:\?\.\s*)?\(|[A-Za-z_$][\w$]*)", "sessionStorage"),
        ("document_cookie", r"\bdocument\s*\?*\.\s*cookie\b", "document"),
        ("document_referrer", r"\bdocument\s*\?*\.\s*referrer\b", "document"),
    )
    for kind, pattern, base in patterns:
        if base in shadowed:
            continue
        for match in re.finditer(pattern, expr):
            # ``window.location`` also depends on an unshadowed window.
            prefix = match.group(0).lstrip()
            owner = re.match(r"(window|globalThis|document)\b", prefix)
            if owner and owner.group(1) in shadowed:
                continue
            add(kind, match.group(0))
    event = scope.get("event_param")
    if event and re.search(rf"\b{re.escape(event)}\s*\?*\.\s*data\b", expr):
        add(scope.get("message_kind") or "message_data", f"{event}.data")
    if "URLSearchParams" not in shadowed and re.search(r"\b(?:new\s+)?URLSearchParams\s*\(", expr):
        # URLSearchParams is a transform; its input still has to be a source.
        if found:
            for item in found:
                item["kind"] = "url_search_params:" + item["kind"]
    return found


_KNOWN_SANITIZERS = {
    "html": re.compile(r"\b(?:DOMPurify\s*\?*\.\s*sanitize|escapeHTML|escapeHtml|htmlEscape|encodeForHTML)\s*\("),
    "url_component": re.compile(r"\bencodeURIComponent\s*\("),
    "trusted_html": re.compile(r"\b[A-Za-z_$][\w$]*\s*\?*\.\s*createHTML\s*\("),
}


def _flow_expr(expr, state, scope, line):
    expr = expr.strip()
    if not expr:
        return None
    direct = _direct_sources(expr, scope, line)
    flows = [{"sources": direct, "safe_for": set(), "transforms": [], "ambiguous": False}] if direct else []
    for match in _IDENT.finditer(expr):
        name = match.group(0)
        before = expr[:match.start()].rstrip()
        if before.endswith((".", "?.")) or name in _RESERVED:
            continue
        if name in state:
            flows.append(_copy_flow(state[name]))
    flow = _merge_flows(flows)
    if not flow:
        return None
    # Conditional selection or short-circuiting makes a simple alias
    # path-dependent; decline rather than claim it is always tainted.
    if re.search(r"\?(?!\.)|&&|\|\||\?\?", expr):
        flow["ambiguous"] = True
    sanitizer = None
    for context, pattern in _KNOWN_SANITIZERS.items():
        if pattern.search(expr):
            sanitizer = context
            flow["safe_for"].add(context)
            flow["transforms"].append(context)
    # A get() on an already-tainted URLSearchParams alias is transparent.
    transparent_get = bool(re.fullmatch(r"\s*[A-Za-z_$][\w$]*\s*\?*\.\s*get\s*(?:\?\.\s*)?\([^)]*\)\s*", expr))
    # Unknown function calls may sanitize, validate or replace their input. A
    # direct-source call is retained only for the source constructors above.
    calls = [m.group(1) for m in re.finditer(r"\b([A-Za-z_$][\w$]*)\s*\(", expr)]
    known = {"URLSearchParams", "getItem", "sanitize", "escapeHTML", "escapeHtml", "htmlEscape",
             "encodeForHTML", "encodeURIComponent", "createHTML"}
    if calls and not transparent_get and any(name not in known for name in calls) and sanitizer is None:
        flow["ambiguous"] = True
    return flow


def _call_arguments(text, open_at):
    depth, bracket, brace = 0, 0, 0
    start, parts = open_at + 1, []
    for i in range(open_at + 1, len(text)):
        ch = text[i]
        if ch == "(": depth += 1
        elif ch == ")":
            if depth == 0:
                parts.append(text[start:i].strip())
                return parts
            depth -= 1
        elif ch == "[": bracket += 1
        elif ch == "]": bracket = max(0, bracket - 1)
        elif ch == "{": brace += 1
        elif ch == "}": brace = max(0, brace - 1)
        elif ch == "," and depth == 0 and bracket == 0 and brace == 0:
            parts.append(text[start:i].strip()); start = i + 1
    return []


def _origin_guard_before(body, event_param, relative_at):
    if not event_param:
        return False
    prefix = body[:max(0, relative_at)]
    ep = re.escape(event_param)
    guards = (
        rf"if\s*\([^)]*\b{ep}\s*\?*\.\s*origin\b[^)]*(?:!==|!=)[^)]*\)\s*(?:\{{\s*)?(?:return|throw)\b",
        rf"if\s*\(\s*!\s*[A-Za-z_$][\w$]*\s*\?*\.\s*includes\s*\(\s*{ep}\s*\?*\.\s*origin\s*\)\s*\)\s*(?:\{{\s*)?(?:return|throw)\b",
    )
    return any(re.search(pattern, prefix, re.S) for pattern in guards)


def _sink_candidates(statement):
    """Yield ``(sink, context, expression, offset)`` from one masked statement."""
    out = []
    assignments = (
        ("innerHTML", "html", r"\.\s*innerHTML\s*=\s*(.+)$"),
        ("outerHTML", "html", r"\.\s*outerHTML\s*=\s*(.+)$"),
        ("srcdoc", "html", r"\.\s*srcdoc\s*=\s*(.+)$"),
        ("url_navigation", "url", r"(?:\b(?:window\s*\?*\.\s*)?location(?:\s*\?*\.\s*href)?|\.\s*(?:href|src|action))\s*=\s*(.+)$"),
    )
    for sink, context, pattern in assignments:
        match = re.search(pattern, statement, re.S)
        if match:
            out.append((sink, context, match.group(1), match.start(1)))
    calls = (
        ("insertAdjacentHTML", "html", r"\binsertAdjacentHTML\s*(?:\?\.\s*)?\(" , -1),
        ("document.write", "html", r"\bdocument\s*\?*\.\s*write(?:ln)?\s*(?:\?\.\s*)?\(", 0),
        ("eval", "code", r"(?<![.\w$])eval\s*\(", 0),
        ("Function", "code", r"\b(?:new\s+)?Function\s*\(", -1),
        ("string_timer", "code", r"\b(?:setTimeout|setInterval)\s*\(", 0),
        ("jquery_html", "html", r"(?:\$|jQuery)\s*\([^;\r\n]{0,300}\)\s*\.\s*html\s*(?:\?\.\s*)?\(", 0),
        ("DOMParser.parseFromString", "html", r"\.\s*parseFromString\s*(?:\?\.\s*)?\(", 0),
        ("Range.createContextualFragment", "html", r"\.\s*createContextualFragment\s*(?:\?\.\s*)?\(", 0),
    )
    for sink, context, pattern, index in calls:
        for match in re.finditer(pattern, statement):
            opening = (statement.rfind("(", match.start(), match.end() + 1)
                       if sink == "jquery_html" else statement.find("(", match.start(), match.end() + 1))
            args = _call_arguments(statement, opening)
            if args:
                chosen = args[index] if -len(args) <= index < len(args) else None
                if chosen:
                    out.append((sink, context, chosen, match.start()))
    react = re.search(r"\bdangerouslySetInnerHTML\b[\s\S]{0,200}?\b__html\s*:\s*([^,}\n]+)", statement)
    if react:
        out.append(("react_dangerouslySetInnerHTML", "html", react.group(1), react.start(1)))
    svelte = re.search(r"\{@html\s+([^}]+)\}", statement)
    if svelte:
        out.append(("svelte_html", "html", svelte.group(1), svelte.start(1)))
    return out


def _safe_sink_candidates(statement):
    out = []
    match = re.search(r"\.\s*textContent\s*=\s*(.+)$", statement, re.S)
    if match:
        out.append(("textContent", match.group(1), match.start(1)))
    for match in re.finditer(r"\b(?:document\s*\?*\.\s*)?createTextNode\s*\(", statement):
        opening = statement.find("(", match.start(), match.end() + 1)
        args = _call_arguments(statement, opening)
        if args:
            out.append(("createTextNode", args[0], match.start()))
    return out


def _sink_is_shadowed(sink, statement, scope):
    """Global-looking sinks are trusted only when their binding is global."""
    declared = scope.get("declared", set())
    if sink == "document.write":
        return "document" in scope.get("shadowed", set())
    if sink == "eval":
        return "eval" in declared
    if sink == "Function":
        return "Function" in declared
    if sink == "string_timer":
        name = next((value for value in ("setTimeout", "setInterval")
                     if re.search(rf"\b{value}\s*\(", statement)), None)
        return bool(name and name in declared)
    if sink == "jquery_html":
        return bool(("$" in declared and re.search(r"\$\s*\(", statement))
                    or ("jQuery" in declared and re.search(r"\bjQuery\s*\(", statement)))
    if sink == "DOMParser.parseFromString":
        return "DOMParser" in scope.get("shadowed", set())
    if sink == "url_navigation":
        stripped = statement.lstrip()
        if re.search(r"\b(?:window\s*\?*\.\s*)?location\b", stripped):
            return "location" in scope.get("shadowed", set()) or "window" in scope.get("shadowed", set())
    return False


_ASSIGN = re.compile(
    r"(?:\b(?:const|let|var)\s+|(?<![.\w$]))([A-Za-z_$][\w$]*)\s*(\+=|=(?!=|>))\s*(.*)$",
    re.S,
)


def _analyze_javascript(js, line_offset=0, max_scopes=MAX_SCOPES,
                        max_statements=MAX_STATEMENTS, should_stop=None):
    js, input_truncated = _bounded_text(js, MAX_JS)
    preprocessing_truncated = input_truncated
    findings, safe_flows, declined = [], [], []
    statements_truncated = False
    stopped_early = False

    def result(scopes_analyzed=0, statements_analyzed=0, scopes_truncated=False):
        return {
            "findings": findings[:MAX_FINDINGS],
            "safe_flows": safe_flows[:MAX_SAFE_FLOWS],
            "declined": declined[:MAX_UNRESOLVED],
            "scopes_analyzed": scopes_analyzed,
            "statements_analyzed": statements_analyzed,
            "scopes_truncated": bool(scopes_truncated),
            "statements_truncated": bool(statements_truncated),
            "preprocessing_truncated": bool(preprocessing_truncated),
            "stopped_early": bool(stopped_early),
        }

    if callable(should_stop) and should_stop():
        stopped_early = True
        statements_truncated = bool(js)
        return result(scopes_truncated=bool(js))

    # This guard is intentionally explicit even though the character cap and
    # UTF-8's four-byte maximum imply it.  It documents and enforces a byte
    # ceiling for callers that use this private entry point directly.
    encoded = js.encode("utf-8", "replace")
    if len(encoded) > MAX_PREPROCESS_BYTES:
        js = encoded[:MAX_PREPROCESS_BYTES].decode("utf-8", "ignore")
        preprocessing_truncated = True

    code, comments_only, stopped = _mask_javascript(js, should_stop)
    if stopped:
        stopped_early = True
        statements_truncated = True
        return result(scopes_truncated=True)
    scopes, scopes_truncated, stopped = _scopes(
        code, comments_only, max_scopes, should_stop)
    if stopped:
        stopped_early = True
        statements_truncated = True
        return result(scopes_truncated=True)

    # Record newline offsets once.  Re-counting the prefix for every statement
    # made minified/adversarial input quadratic even after scope extraction.
    newline_offsets = []
    for at, char in enumerate(js):
        if not at % 4096 and callable(should_stop) and should_stop():
            stopped_early = True
            statements_truncated = True
            return result(scopes_truncated=scopes_truncated)
        if char == "\n":
            newline_offsets.append(at)

    # Materialize the mutually-exclusive visible intervals once.  Direct child
    # functions are replaced by a newline boundary, so declarations and taint
    # can never leak between functions.  Copying is chunked for cooperative
    # cancellation and the sum of all prepared bodies has an explicit cap.
    prepared = []
    prepared_chars = 0
    for scope in scopes:
        if callable(should_stop) and should_stop():
            stopped_early = True
            statements_truncated = True
            return result(scopes_truncated=scopes_truncated)
        parts, mappings = [], []
        local_at = 0
        have_segment = False
        for segment_start, segment_end in scope.get("segments", []):
            if segment_end <= segment_start:
                continue
            if have_segment:
                if prepared_chars + 1 > MAX_PREPARED_CHARS:
                    preprocessing_truncated = True
                    statements_truncated = True
                    return result(scopes_truncated=True)
                parts.append("\n")
                local_at += 1
                prepared_chars += 1
            cursor = segment_start
            while cursor < segment_end:
                if callable(should_stop) and should_stop():
                    stopped_early = True
                    statements_truncated = True
                    return result(scopes_truncated=scopes_truncated)
                chunk_end = min(segment_end, cursor + 16384)
                length = chunk_end - cursor
                if prepared_chars + length > MAX_PREPARED_CHARS:
                    preprocessing_truncated = True
                    statements_truncated = True
                    return result(scopes_truncated=True)
                parts.append(code[cursor:chunk_end])
                mappings.append((local_at, local_at + length, cursor))
                local_at += length
                prepared_chars += length
                cursor = chunk_end
            have_segment = True
        body = "".join(parts)
        declared = set(scope.get("params") or [])
        for match in re.finditer(
                r"\b(?:const|let|var|class|function)\s+([A-Za-z_$][\w$]*)", body):
            if callable(should_stop) and should_stop():
                stopped_early = True
                statements_truncated = True
                return result(scopes_truncated=scopes_truncated)
            declared.add(match.group(1))
        prepared.append({
            "scope": scope,
            "body": body,
            "declared": declared,
            "mappings": mappings,
            "mapping_starts": [row[0] for row in mappings],
        })

    statements_seen = 0
    for entry in prepared:
        scope = entry["scope"]
        body = entry["body"]
        declared = entry["declared"]
        if statements_seen >= max_statements:
            statements_truncated = True
            break
        if callable(should_stop) and should_stop():
            statements_truncated = True
            stopped_early = True
            break
        inherited_globals = set()
        for parent_entry in prepared:
            parent = parent_entry["scope"]
            parent_declared = parent_entry["declared"]
            if parent is scope or parent["name"] == "<top-level>":
                continue
            if parent["start"] <= scope["match_start"] and scope["end"] <= parent["end"]:
                inherited_globals |= parent_declared & _GLOBAL_NAMES
        scope["declared"] = declared
        scope["shadowed"] = (declared & _GLOBAL_NAMES) | inherited_globals
        state = {}
        statements, was_truncated, stopped = _statements(
            body, max(0, max_statements - statements_seen), should_stop)
        statements_seen += len(statements)
        statements_truncated |= was_truncated
        if stopped:
            stopped_early = True
            statements_truncated = True
            break

        def absolute_for(local):
            mappings = entry["mappings"]
            starts = entry["mapping_starts"]
            index = bisect_right(starts, local) - 1
            if index >= 0:
                body_start, body_end, source_start = mappings[index]
                if local < body_end:
                    return source_start + local - body_start
            index = bisect_left(starts, local)
            if index < len(mappings):
                return mappings[index][2]
            return scope["start"]

        for relative, statement in statements:
            if callable(should_stop) and should_stop():
                statements_truncated = True
                stopped_early = True
                break
            absolute = absolute_for(relative)
            line = line_offset + bisect_left(newline_offsets, absolute) + 1
            for sink, context, expression, at in _sink_candidates(statement):
                if _sink_is_shadowed(sink, statement, scope):
                    continue
                flow = _flow_expr(expression, state, scope, line)
                if not flow or flow.get("ambiguous"):
                    continue
                safe = context in flow["safe_for"] or (context == "html" and "html" in flow["safe_for"])
                record = {
                    "kind": "source_to_sink", "sink": sink, "context": context,
                    "sources": flow["sources"][:12], "transforms": flow["transforms"][:12],
                    "sanitizer_mismatch": bool(flow["safe_for"] and not safe),
                    "scope": scope["name"], "line": line,
                    "message_origin_checked": _origin_guard_before(
                        body, scope.get("event_param"), max(0, relative + at)),
                    "confidence": "high",
                }
                if safe:
                    record["kind"] = "sanitized_source_to_safe_sink"
                    if len(safe_flows) < MAX_SAFE_FLOWS:
                        safe_flows.append(record)
                elif len(findings) < MAX_FINDINGS:
                    findings.append(record)
            for sink, expression, at in _safe_sink_candidates(statement):
                flow = _flow_expr(expression, state, scope, line)
                if flow and not flow.get("ambiguous") and len(safe_flows) < MAX_SAFE_FLOWS:
                    safe_flows.append({"kind": "text_only_sink", "sink": sink,
                                       "sources": flow["sources"][:12], "scope": scope["name"],
                                       "line": line, "confidence": "high"})

            assignment = _ASSIGN.search(statement)
            if assignment:
                name, operator, expression = assignment.groups()
                conditional = bool(re.match(r"\s*(?:if|for|while|switch|catch)\b", statement))
                flow = _flow_expr(expression, state, scope, line)
                if operator == "+=" and name in state:
                    flow = _merge_flows([state[name], flow])
                if conditional or not flow or flow.get("ambiguous"):
                    state.pop(name, None)
                    if conditional and flow and len(declined) < MAX_UNRESOLVED:
                        declined.append({"kind": "conditional_assignment", "variable": name,
                                         "scope": scope["name"], "line": line})
                else:
                    if len(state) >= MAX_STATE and name not in state:
                        continue
                    state[name] = flow
        if stopped_early:
            break
    return result(scopes_analyzed=len(scopes), statements_analyzed=statements_seen,
                  scopes_truncated=scopes_truncated)


def _template_findings(rows, should_stop=None):
    findings, unresolved = [], []
    dummy = {"shadowed": set(), "event_param": None, "message_kind": None, "name": "<template>"}
    for row in rows[:MAX_UNRESOLVED]:
        if callable(should_stop) and should_stop():
            break
        expression, line = str(row.get("expression") or ""), int(row.get("line") or 1)
        masked, _, stopped = _mask_javascript(expression, should_stop)
        if stopped:
            break
        flow = _flow_expr(masked, {}, dummy, line)
        if flow and not flow.get("ambiguous"):
            findings.append({"kind": "source_to_sink", "sink": row.get("sink"), "context": "html",
                             "sources": flow["sources"][:12], "transforms": flow["transforms"][:12],
                             "sanitizer_mismatch": False, "scope": "<template>", "line": line,
                             "message_origin_checked": False, "confidence": "high"})
        else:
            unresolved.append({"kind": "unresolved_template_sink", "sink": row.get("sink"),
                               "expression": _clean_display(expression), "line": line})
    return findings[:MAX_FINDINGS], unresolved[:MAX_UNRESOLVED]


def analyze(html="", js="", headers=None, base_url=None, *, deadline=None, stop=None):
    """Analyze already-fetched browser material and return bounded findings.

    ``headers`` should be an ordered sequence of pairs when duplicate headers
    matter.  A mapping is accepted, including list values.  ``base_url`` is
    parsed only to report the origin; it is never contacted.
    """
    should_stop = lambda: _halted(deadline, stop)
    stopped_early = should_stop()
    html_text, html_truncated = _bounded_text("" if stopped_early else html, MAX_HTML)
    js_input_truncated = False
    if stopped_early:
        js_value = ""
    elif isinstance(js, (list, tuple)):
        pieces = []
        remaining = MAX_JS
        selected = js[:MAX_INLINE_SCRIPTS]
        js_input_truncated = len(js) > len(selected)
        for index, item in enumerate(selected):
            value = item.decode("utf-8", "replace") if isinstance(item, bytes) else str(item)
            pieces.append(value[:remaining])
            js_input_truncated |= len(value) > remaining
            remaining -= len(pieces[-1])
            if remaining <= 0:
                js_input_truncated |= index + 1 < len(selected)
                break
        js_value = "\n".join(pieces)
    else:
        js_value = js
    js_text, js_truncated = _bounded_text(js_value, MAX_JS)
    js_truncated |= js_input_truncated
    header_pairs, headers_truncated = _ordered_headers(None if stopped_early else headers)

    parser = _HTMLInventory()
    if not stopped_early:
        try:
            parser.feed(html_text)
            parser.close()
        except Exception:
            # HTMLParser is forgiving, but malformed adversarial input must never
            # escape the offline analyzer.
            pass
    stopped_early |= should_stop()
    csp = _csp_result(
        header_pairs if not stopped_early else [],
        parser.meta if not stopped_early else [],
        source_incomplete=(stopped_early or headers_truncated or parser.meta_truncated),
    )

    combined = [js_text]
    line_offsets = [0]
    lines = js_text.count("\n") + 1
    for script in parser.inline_scripts:
        remaining = MAX_JS - sum(len(part) for part in combined)
        if remaining <= 0:
            js_truncated = True
            break
        combined.append(script["text"][:remaining])
        line_offsets.append(lines + int(script.get("line") or 1))
        lines += combined[-1].count("\n") + 1
        js_truncated |= len(script["text"]) > remaining

    js_findings, js_safe, js_declined = [], [], []
    scopes = 0
    statements = 0
    scopes_truncated = False
    statements_truncated = False
    preprocessing_truncated = False
    for index, part in enumerate(combined):
        if not part:
            continue
        if should_stop():
            stopped_early = True
            statements_truncated = True
            break
        if scopes >= MAX_SCOPES or statements >= MAX_STATEMENTS:
            statements_truncated = True
            break
        result = _analyze_javascript(
            part, line_offset=line_offsets[index],
            max_scopes=MAX_SCOPES - scopes,
            max_statements=MAX_STATEMENTS - statements,
            should_stop=should_stop)
        js_findings += result["findings"]
        js_safe += result["safe_flows"]
        js_declined += result["declined"]
        scopes += result["scopes_analyzed"]
        statements += result["statements_analyzed"]
        scopes_truncated |= result["scopes_truncated"]
        statements_truncated |= result["statements_truncated"]
        preprocessing_truncated |= result.get("preprocessing_truncated", False)
        stopped_early |= result.get("stopped_early", False)
        if len(js_findings) >= MAX_FINDINGS:
            break
    if stopped_early:
        template_findings, unresolved = [], []
    else:
        template_findings, unresolved = _template_findings(parser.template_sinks, should_stop=should_stop)
    stopped_early |= should_stop()
    js_findings = (js_findings + template_findings)[:MAX_FINDINGS]
    if not stopped_early:
        for row in parser.javascript_urls[:MAX_FINDINGS - len(js_findings)]:
            js_findings.append({"kind": "static_javascript_url", "sink": "javascript_url",
                                "tag": row["tag"], "attribute": row["attribute"], "line": row["line"],
                                "confidence": "high"})

    origin = None
    if base_url:
        try:
            parsed = urllib.parse.urlsplit(str(base_url))
            if parsed.scheme.lower() in ("http", "https") and parsed.hostname and not parsed.username:
                port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
                origin = {"scheme": parsed.scheme.lower(), "host": parsed.hostname.lower(), "port": port}
        except Exception:
            origin = None

    combined_findings = (csp["findings"] + js_findings)[:MAX_FINDINGS]
    return {
        "version": VERSION,
        "offline": True,
        "stopped_early": stopped_early,
        "base_origin": origin,
        "limits": {
            "max_html": MAX_HTML, "max_js": MAX_JS, "max_headers": MAX_HEADERS,
            "max_policies": MAX_POLICIES, "max_scopes": MAX_SCOPES,
            "max_statements": MAX_STATEMENTS, "max_findings": MAX_FINDINGS,
            "max_statement_chars": MAX_STATEMENT_CHARS,
            "max_preprocess_bytes": MAX_PREPROCESS_BYTES,
            "max_prepared_chars": MAX_PREPARED_CHARS,
        },
        "truncated": {"html": html_truncated, "javascript": js_truncated,
                      "headers": headers_truncated, "scopes": scopes_truncated,
                      "statements": statements_truncated,
                      "preprocessing": preprocessing_truncated,
                      "csp": bool(csp.get("input_incomplete"))},
        "csp": csp,
        "javascript": {
            "findings": js_findings,
            "safe_flows": js_safe[:MAX_SAFE_FLOWS],
            "declined": (js_declined + unresolved)[:MAX_UNRESOLVED],
            "external_script_leads": parser.script_leads[:MAX_SCRIPT_LEADS],
            "scopes_analyzed": min(scopes, MAX_SCOPES),
        },
        "findings": combined_findings,
    }


__all__ = ["analyze", "VERSION"]
