#!/usr/bin/env python3
"""Offline client-side taint, gadget, postMessage, and framing analysis.

This complements the existing prototype-pollution/CSP candidate generator: it
adds bounded source-to-sink tracking, a metadata-only prototype gadget catalog,
message-origin review, and clickjacking header correlation.  It never launches
a browser, parses a DOM, evaluates JavaScript, or contacts an origin.  All
candidate values are inert markers under the reserved ``.invalid`` domain.

The server-side counterpart, a static prototype-pollution sink scanner for Node
bundles with a flatted ``__proto__``-reference payload, is
``pp_number_differential`` (engine ``web.pp_number_differential``, B-047).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import re
from typing import Iterable
import urllib.parse


MAX_SOURCE = 2 * 1024 * 1024
MAX_HEADERS = 128 * 1024
MAX_ASSIGNMENTS = 2048
MAX_SINKS = 512
MAX_FLOWS = 512
MAX_HANDLER = 16 * 1024


class ClientDepthInputError(ValueError):
    """Raised for malformed or unbounded supplied artifacts."""


@dataclass(frozen=True, slots=True)
class CatalogEntry:
    name: str
    syntax: str
    context: str
    note: str


@dataclass(frozen=True, slots=True)
class DOMFlow:
    source: str
    source_evidence: str
    variables: tuple[str, ...]
    transforms: tuple[str, ...]
    sanitizers: tuple[str, ...]
    sink: str
    sink_context: str
    sink_evidence: str
    line: int
    confidence: str
    mitigated: bool

    def to_dict(self) -> dict[str, object]:
        row = asdict(self)
        row.update({"offline": True, "browser_started": False, "network_requests": 0})
        return row


@dataclass(frozen=True, slots=True)
class PrototypeGadget:
    name: str
    ecosystem: str
    polluted_property: str
    sink_signature: str
    impact: str
    requirements: tuple[str, ...]
    source_patterns: tuple[str, ...]
    package_names: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class GadgetMatch:
    gadget: str
    polluted_property: str
    evidence: tuple[str, ...]
    package_hints: tuple[str, ...]
    confidence: str
    requirements: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ClientFinding:
    family: str
    name: str
    severity: str
    evidence: str
    offset: int
    precondition: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class InertClientCandidate:
    family: str
    name: str
    value: str
    purpose: str
    requirement: str

    def to_dict(self) -> dict[str, object]:
        row = asdict(self)
        row.update({"inert": True, "offline": True, "browser_started": False, "network_requests": 0})
        return row


def _text(value: str | bytes | bytearray, label: str, maximum: int) -> str:
    if isinstance(value, str):
        text = value
    elif isinstance(value, (bytes, bytearray)):
        text = bytes(value).decode("utf-8", "replace")
    else:
        raise ClientDepthInputError(f"{label} must be text or bytes")
    if len(text.encode("utf-8", "replace")) > maximum:
        raise ClientDepthInputError(f"{label} exceeds {maximum} bytes")
    return text


def _mask_javascript(source: str, *, preserve_strings: bool = False) -> str:
    """Blank comments, and optionally strings, while preserving offsets/newlines."""

    out = list(source)
    state = "code"
    quote = ""
    index = 0
    while index < len(source):
        char = source[index]
        nxt = source[index + 1] if index + 1 < len(source) else ""
        if state == "code":
            if char == "/" and nxt == "/":
                out[index] = out[index + 1] = " "
                state = "line_comment"
                index += 2
                continue
            if char == "/" and nxt == "*":
                out[index] = out[index + 1] = " "
                state = "block_comment"
                index += 2
                continue
            if char in "'\"`":
                quote = char
                state = "string"
                if not preserve_strings:
                    out[index] = " "
                index += 1
                continue
        elif state == "line_comment":
            if char == "\n":
                state = "code"
            else:
                out[index] = " "
            index += 1
            continue
        elif state == "block_comment":
            if char == "*" and nxt == "/":
                out[index] = out[index + 1] = " "
                state = "code"
                index += 2
                continue
            if char != "\n":
                out[index] = " "
            index += 1
            continue
        elif state == "string":
            if char == "\\":
                if not preserve_strings:
                    out[index] = " "
                    if index + 1 < len(source) and source[index + 1] != "\n":
                        out[index + 1] = " "
                index += 2
                continue
            if char == quote:
                if not preserve_strings:
                    out[index] = " "
                state = "code"
                index += 1
                continue
            if not preserve_strings and char != "\n":
                out[index] = " "
            index += 1
            continue
        index += 1
    return "".join(out)


_SOURCE_META: tuple[tuple[CatalogEntry, re.Pattern[str]], ...] = (
    (CatalogEntry("location_search", "location.search", "URL query", "Attacker-controlled navigation input."), re.compile(r"\b(?:window\.)?location\.search\b")),
    (CatalogEntry("location_hash", "location.hash", "URL fragment", "Fragment content is not sent to the server."), re.compile(r"\b(?:window\.)?location\.hash\b")),
    (CatalogEntry("document_url", "document.URL/documentURI", "document URL", "Full current document URL."), re.compile(r"\bdocument\.(?:URL|documentURI)\b")),
    (CatalogEntry("document_referrer", "document.referrer", "referrer", "May be influenced by a referring page."), re.compile(r"\bdocument\.referrer\b")),
    (CatalogEntry("window_name", "window.name", "cross-navigation state", "Persists across navigations in the same browsing context."), re.compile(r"\bwindow\.name\b")),
    (CatalogEntry("message_data", "MessageEvent.data", "cross-origin message", "Requires an untrusted message sender."), re.compile(r"\b(?:event|evt|message|e)\.data\b")),
    (CatalogEntry("storage", "localStorage/sessionStorage", "client storage", "Requires an attacker-controlled write path."), re.compile(r"\b(?:localStorage|sessionStorage)(?:\.getItem|\[)")),
    (CatalogEntry("cookie", "document.cookie", "cookie text", "Only non-HttpOnly cookies are visible."), re.compile(r"\bdocument\.cookie\b")),
    (CatalogEntry("url_search_params", "URLSearchParams.get", "parsed URL parameter", "Input comes from the URL or supplied constructor value."), re.compile(r"\b(?:new\s+)?URLSearchParams\s*\([^)]*\)\.get\s*\(")),
    (CatalogEntry("websocket_data", "WebSocket message data", "socket message", "Requires control of a message accepted by the client."), re.compile(r"\b(?:socket|ws|messageEvent)\.onmessage\b|\bMessageEvent\.data\b")),
)


_SINK_META: tuple[tuple[CatalogEntry, re.Pattern[str]], ...] = (
    (CatalogEntry("innerHTML", ".innerHTML = value", "html", "HTML parser sink."), re.compile(r"(?:\.innerHTML|\[['\"]innerHTML['\"]\])\s*=\s*([^;\n]{1,2048})")),
    (CatalogEntry("outerHTML", ".outerHTML = value", "html", "HTML parser sink."), re.compile(r"(?:\.outerHTML|\[['\"]outerHTML['\"]\])\s*=\s*([^;\n]{1,2048})")),
    (CatalogEntry("srcdoc", ".srcdoc = value", "html", "Iframe document sink."), re.compile(r"(?:\.srcdoc|\[['\"]srcdoc['\"]\])\s*=\s*([^;\n]{1,2048})")),
    (CatalogEntry("insertAdjacentHTML", "insertAdjacentHTML(position, value)", "html", "HTML parser sink."), re.compile(r"\.insertAdjacentHTML\s*\([^,]{0,256},\s*([^)]{1,2048})\)")),
    (CatalogEntry("document_write", "document.write(value)", "html", "Document parser sink."), re.compile(r"\bdocument\.(?:write|writeln)\s*\(\s*([^)]{1,2048})\)")),
    (CatalogEntry("contextual_fragment", "createContextualFragment(value)", "html", "Range HTML parser sink."), re.compile(r"\.createContextualFragment\s*\(\s*([^)]{1,2048})\)")),
    (CatalogEntry("domparser", "DOMParser.parseFromString(value, ...)", "html", "Parser result becomes risky when inserted."), re.compile(r"\.parseFromString\s*\(\s*([^,)]{1,2048})")),
    (CatalogEntry("eval", "eval(value)", "script", "JavaScript execution sink."), re.compile(r"\beval\s*\(\s*([^)]{1,2048})\)")),
    (CatalogEntry("function_constructor", "Function(value)", "script", "JavaScript compilation sink."), re.compile(r"\b(?:new\s+)?Function\s*\(\s*([^)]{1,2048})\)")),
    (CatalogEntry("timer_string", "setTimeout/setInterval(value, ...)", "script", "Only string callbacks compile code."), re.compile(r"\bset(?:Timeout|Interval)\s*\(\s*([^,)]{1,2048})")),
    (CatalogEntry("location_navigation", "location/assign/replace", "url", "Navigation sink; scheme and origin matter."), re.compile(r"(?:\b(?:window\.)?location(?:\.href)?\s*=|\b(?:window\.)?location\.(?:assign|replace)\s*\()\s*([^;)\n]{1,2048})")),
    (CatalogEntry("script_src", "script.src = value", "url", "Script URL sink when receiver is a script element."), re.compile(r"\.src\s*=\s*([^;\n]{1,2048})")),
    (CatalogEntry("jquery_html", ".html/.append(value)", "html", "jQuery HTML parser sink."), re.compile(r"\.(?:html|append|prepend|before|after)\s*\(\s*([^)]{1,2048})\)")),
    (CatalogEntry("react_html", "dangerouslySetInnerHTML.__html", "html", "React explicit raw-HTML sink."), re.compile(r"dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*([^}\n]{1,2048})")),
)


def dom_source_catalog() -> tuple[CatalogEntry, ...]:
    return tuple(item for item, _pattern in _SOURCE_META)


def dom_sink_catalog() -> tuple[CatalogEntry, ...]:
    return tuple(item for item, _pattern in _SINK_META)


_TRANSFORMS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("decodeURIComponent", re.compile(r"\bdecodeURIComponent\s*\(")),
    ("decodeURI", re.compile(r"\bdecodeURI\s*\(")),
    ("atob", re.compile(r"\batob\s*\(")),
    ("JSON.parse", re.compile(r"\bJSON\.parse\s*\(")),
    ("replace", re.compile(r"\.replace\s*\(")),
    ("trim", re.compile(r"\.trim\s*\(")),
)


_SANITIZERS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    ("DOMPurify", "html", re.compile(r"\bDOMPurify\.sanitize\s*\(")),
    ("TrustedTypes", "html", re.compile(r"\b(?:trustedTypes|createHTML|TrustedHTML)\b")),
    ("escapeHtml", "html", re.compile(r"\b(?:escapeHtml|htmlEncode|encodeForHTML)\s*\(")),
    ("encodeURIComponent", "url", re.compile(r"\bencodeURIComponent\s*\(")),
    ("URL_constructor", "url", re.compile(r"\bnew\s+URL\s*\(")),
)


@dataclass(frozen=True, slots=True)
class _Taint:
    source: str
    evidence: str
    variables: tuple[str, ...]
    transforms: tuple[str, ...]
    sanitizers: tuple[tuple[str, str], ...]


_ASSIGNMENT = re.compile(
    r"(?:\b(?:const|let|var)\s+)?([A-Za-z_$][A-Za-z0-9_$]{0,127})\s*=\s*([^;\n]{1,4096})"
)


def _source_in(expression: str) -> tuple[str, str] | None:
    for meta, pattern in _SOURCE_META:
        match = pattern.search(expression)
        if match:
            return meta.name, match.group(0)[:240]
    return None


def _expression_metadata(expression: str) -> tuple[tuple[str, ...], tuple[tuple[str, str], ...]]:
    transforms = tuple(label for label, pattern in _TRANSFORMS if pattern.search(expression))
    sanitizers = tuple((label, context) for label, context, pattern in _SANITIZERS if pattern.search(expression))
    return transforms, sanitizers


def _taint_before(masked: str, assignments: tuple[re.Match[str], ...], offset: int) -> dict[str, _Taint]:
    state: dict[str, _Taint] = {}
    for match in assignments:
        if match.start() >= offset:
            break
        name, expression = match.group(1), match.group(2)
        direct = _source_in(expression)
        if direct:
            transforms, sanitizers = _expression_metadata(expression)
            taint = _Taint(direct[0], direct[1], (name,), transforms, sanitizers)
        else:
            references = [item for item in state if re.search(rf"\b{re.escape(item)}\b", expression)]
            if not references:
                state.pop(name, None)
                continue
            parent = state[references[0]]
            transforms = tuple(
                dict.fromkeys((*parent.transforms, *(label for label, pattern in _TRANSFORMS if pattern.search(expression))))
            )
            sanitizers = tuple(
                dict.fromkeys((*parent.sanitizers, *((label, context) for label, context, pattern in _SANITIZERS if pattern.search(expression))))
            )
            taint = _Taint(parent.source, parent.evidence, (*parent.variables, name), transforms, sanitizers)
        state[name] = taint
    return state


def analyze_dom_flows(source: str | bytes | bytearray) -> tuple[DOMFlow, ...]:
    """Track simple bounded identifier flows from browser inputs to DOM/script/URL sinks."""

    original = _text(source, "source", MAX_SOURCE)
    masked = _mask_javascript(original)
    assignments = tuple(_ASSIGNMENT.finditer(masked))
    if len(assignments) > MAX_ASSIGNMENTS:
        raise ClientDepthInputError(f"assignment count exceeds {MAX_ASSIGNMENTS}")
    sinks: list[tuple[CatalogEntry, re.Match[str]]] = []
    for meta, pattern in _SINK_META:
        sinks.extend((meta, match) for match in pattern.finditer(masked))
        if len(sinks) > MAX_SINKS:
            raise ClientDepthInputError(f"sink count exceeds {MAX_SINKS}")
    flows: list[DOMFlow] = []
    for meta, match in sorted(sinks, key=lambda row: (row[1].start(), row[0].name)):
        expression = match.group(1)
        direct = _source_in(expression)
        taint = None
        if direct:
            transforms, sanitizers = _expression_metadata(expression)
            taint = _Taint(direct[0], direct[1], (), transforms, sanitizers)
        else:
            state = _taint_before(masked, assignments, match.start())
            references = [name for name in state if re.search(rf"\b{re.escape(name)}\b", expression)]
            if references:
                taint = state[references[0]]
        if taint is None:
            continue
        sanitizers = tuple(label for label, _context in taint.sanitizers)
        mitigated = any(context == meta.context for _label, context in taint.sanitizers)
        confidence = "low" if mitigated else "high" if meta.context in {"html", "script"} else "medium"
        flows.append(
            DOMFlow(
                taint.source,
                taint.evidence,
                taint.variables,
                taint.transforms,
                sanitizers,
                meta.name,
                meta.context,
                original[match.start() : match.end()][:300],
                original.count("\n", 0, match.start()) + 1,
                confidence,
                mitigated,
            )
        )
        if len(flows) >= MAX_FLOWS:
            break
    return tuple(flows)


_GADGETS: tuple[PrototypeGadget, ...] = (
    PrototypeGadget("webpack_public_path", "webpack", "publicPath", "__webpack_require__.p", "influence dynamically loaded script/chunk origins", ("a prototype-unsafe merge precedes the property read", "the property is inherited rather than an own value"), (r"__webpack_require__\.p", r"publicPath"), ("webpack",)),
    PrototypeGadget("webpack_chunk_name", "webpack", "chunkFilename", "__webpack_require__.u", "influence a dynamic chunk path", ("dynamic chunk loading is reachable", "the property read accepts inherited configuration"), (r"__webpack_require__\.u", r"chunkFilename"), ("webpack",)),
    PrototypeGadget("jquery_ajax_url", "jquery", "url", "$.ajax", "influence a request destination", ("an options object inherits the property", "the call does not replace it with an own value"), (r"\$\.(?:ajax|getScript)", r"(?:ajaxSetup|url\s*:)") , ("jquery",)),
    PrototypeGadget("jquery_html_option", "jquery", "html", ".html", "reach jQuery HTML parsing", ("a gadget copies inherited options into an HTML sink",), (r"\.(?:html|append|prepend)\s*\(",), ("jquery",)),
    PrototypeGadget("vue_template_option", "vue", "template", "createApp/new Vue", "influence a runtime-compiled template", ("the runtime compiler build is present", "configuration accepts an inherited template"), (r"\b(?:new\s+Vue|createApp)\s*\(", r"template\s*:") , ("vue",)),
    PrototypeGadget("react_raw_html_prop", "react", "dangerouslySetInnerHTML", "dangerouslySetInnerHTML", "reach React raw HTML rendering through a spread/default object", ("attacker-controlled polluted defaults are spread into props",), (r"dangerouslySetInnerHTML", r"\.\.\.\s*[A-Za-z_$]") , ("react", "react-dom")),
    PrototypeGadget("dompurify_config", "dompurify", "ALLOWED_TAGS", "DOMPurify.sanitize", "alter sanitizer configuration", ("configuration is merged without own-property checks", "the polluted value survives DOMPurify's config normalization"), (r"DOMPurify\.sanitize", r"ALLOWED_TAGS|RETURN_DOM|ADD_TAGS"), ("dompurify",)),
    PrototypeGadget("sanitize_html_config", "sanitize-html", "allowedTags", "sanitizeHtml", "alter sanitizer allowlists", ("options inherit polluted properties",), (r"\bsanitizeHtml\s*\(", r"allowedTags|allowedAttributes"), ("sanitize-html",)),
    PrototypeGadget("script_element_src", "browser", "src", "createElement('script')", "influence a generated script URL", ("the code reads inherited configuration into script.src",), (r"createElement\s*\(\s*['\"]script['\"]", r"\.src\s*=") , ()),
    PrototypeGadget("iframe_srcdoc", "browser", "srcdoc", "iframe.srcdoc", "influence an iframe document", ("the code reads inherited configuration into srcdoc",), (r"\.srcdoc\s*=",), ()),
)


def prototype_gadget_catalog() -> tuple[PrototypeGadget, ...]:
    return _GADGETS


def _package_hints(manifest: str, names: tuple[str, ...]) -> tuple[str, ...]:
    hints: list[str] = []
    for name in names:
        pattern = re.compile(rf"(?i)['\"]{re.escape(name)}['\"]\s*:\s*['\"]([^'\"]{{1,64}})['\"]")
        match = pattern.search(manifest)
        if match:
            hints.append(f"{name}@{match.group(1)}")
    return tuple(hints)


def match_prototype_gadgets(
    source: str | bytes | bytearray,
    package_manifest: str | bytes | bytearray = "",
) -> tuple[GadgetMatch, ...]:
    """Match gadget signatures; results are leads, never version/vulnerability claims."""

    text = _text(source, "source", MAX_SOURCE)
    manifest = _text(package_manifest, "package_manifest", MAX_HEADERS)
    masked = _mask_javascript(text, preserve_strings=True)
    rows: list[GadgetMatch] = []
    for gadget in _GADGETS:
        evidence = []
        for raw_pattern in gadget.source_patterns:
            match = re.search(raw_pattern, masked, re.I)
            if match:
                evidence.append(text[match.start() : match.end()][:240])
        if len(evidence) == len(gadget.source_patterns):
            packages = _package_hints(manifest, gadget.package_names)
            rows.append(
                GadgetMatch(
                    gadget.name,
                    gadget.polluted_property,
                    tuple(evidence),
                    packages,
                    "medium" if packages or not gadget.package_names else "low",
                    gadget.requirements,
                )
            )
    return tuple(rows)


def _safe_token(value: str, label: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$.-]{0,63}", value):
        raise ClientDepthInputError(f"{label} must be a conservative identifier")
    return value


def prototype_marker_candidates(
    property_name: str, marker: str = "R5D_PP_MARKER"
) -> tuple[InertClientCandidate, ...]:
    prop = _safe_token(property_name, "property_name")
    marker = _safe_token(marker, "marker")
    encoded_prop = urllib.parse.quote(prop, safe="")
    encoded_marker = urllib.parse.quote(marker, safe="")
    return (
        InertClientCandidate("prototype_pollution", "query_proto", f"__proto__[{encoded_prop}]={encoded_marker}", "mark an inherited property without active content", "the parser preserves nested __proto__ keys"),
        InertClientCandidate("prototype_pollution", "query_constructor", f"constructor[prototype][{encoded_prop}]={encoded_marker}", "compare constructor.prototype path handling", "the parser expands bracket notation recursively"),
        InertClientCandidate("prototype_pollution", "json_text", f'{{"__proto__":{{"{prop}":"{marker}"}}}}', "review JSON-like own-key handling as text", "the application parser preserves __proto__ as an own key"),
    )


def _finding(
    family: str, name: str, severity: str, text: str, match: re.Match[str], precondition: str
) -> ClientFinding:
    return ClientFinding(
        family,
        name,
        severity,
        text[max(0, match.start() - 60) : min(len(text), match.end() + 120)],
        match.start(),
        precondition,
    )


def analyze_postmessage(source: str | bytes | bytearray) -> tuple[ClientFinding, ...]:
    """Review saved JavaScript for sender/receiver origin and data-flow hazards."""

    text = _text(source, "source", MAX_SOURCE)
    visible = _mask_javascript(text, preserve_strings=True)
    findings: list[ClientFinding] = []
    wildcard = re.compile(r"\.postMessage\s*\([^,]{1,4096},\s*(['\"])\*\1\s*\)", re.I)
    for match in wildcard.finditer(visible):
        findings.append(_finding("postmessage", "wildcard_target_origin", "high", text, match, "sensitive data reaches this sender or an attacker can navigate the target window"))

    listeners = list(re.finditer(r"(?i)(?:addEventListener\s*\(\s*['\"]message['\"]|\.onmessage\s*=)", visible))
    for index, listener in enumerate(listeners[:128]):
        end = listeners[index + 1].start() if index + 1 < len(listeners) else min(len(text), listener.start() + MAX_HANDLER)
        block = visible[listener.start() : end]
        original_block = text[listener.start() : end]
        origin_name = r"(?:event|evt|message|e)\.origin"
        strong_origin = (
            re.search(
                rf"(?is)if\s*\(\s*{origin_name}\s*!==?\s*['\"]https?://[^'\"]+['\"]\s*\)\s*(?:return\b|\{{[^}}]{{0,256}}\breturn\b)",
                block,
            )
            or re.search(
                rf"(?is)if\s*\(\s*!\s*(?:allowedOrigins?|trustedOrigins?)\.(?:includes|has)\s*\(\s*{origin_name}\s*\)\s*\)\s*(?:return\b|\{{[^}}]{{0,256}}\breturn\b)",
                block,
            )
            or re.search(
                rf"(?is)if\s*\(\s*{origin_name}\s*(?:===|==)\s*['\"]https?://[^'\"]+['\"]\s*\)\s*\{{[^}}]{{0,8192}}\b(?:event|evt|message|e)\.data\b[^}}]*\}}",
                block,
            )
        )
        weak_origin = re.search(r"(?i)\.origin\s*\.?(?:indexOf|includes|endsWith|startsWith)\s*\(", block)
        dangerous_flows = analyze_dom_flows(original_block)
        privileged_action = re.search(
            r"(?i)\b(?:fetch|XMLHttpRequest|sendBeacon|window\.open|location\.(?:assign|replace)|localStorage\.setItem|sessionStorage\.setItem)\b",
            block,
        )
        risky_handler = bool(dangerous_flows or privileged_action)
        if not strong_origin and risky_handler:
            severity = "high" if dangerous_flows else "medium"
            findings.append(_finding("postmessage", "receiver_without_exact_origin", severity, text, listener, "an untrusted window can obtain a reference to the receiver"))
        if weak_origin:
            shifted = _ShiftedMatch(weak_origin, listener.start())
            findings.append(_finding("postmessage", "weak_origin_substring_check", "medium", text, shifted, "an attacker origin can satisfy the substring/suffix rule"))
        if re.search(r"(?i)\bJSON\.parse\s*\(\s*(?:event|evt|message|e)\.data", block) and not re.search(r"(?i)\b(?:schema|validate|safeParse|isMessage)\b", block):
            parse_match = re.search(r"(?i)\bJSON\.parse", original_block)
            if parse_match:
                findings.append(_finding("postmessage", "unvalidated_message_shape", "medium", text, _ShiftedMatch(parse_match, listener.start()), "parsed message fields control a privileged action"))
    return tuple(sorted(findings, key=lambda row: (row.offset, row.name)))


class _ShiftedMatch:
    """Minimal match facade for evidence offsets inside a bounded handler slice."""

    def __init__(self, match: re.Match[str], shift: int):
        self._match = match
        self._shift = shift

    def start(self) -> int:
        return self._match.start() + self._shift

    def end(self) -> int:
        return self._match.end() + self._shift


def postmessage_marker_candidates(
    marker_origin: str = "https://message.r5d.invalid", marker: str = "R5D_MESSAGE_MARKER"
) -> tuple[InertClientCandidate, ...]:
    try:
        parsed = urllib.parse.urlsplit(marker_origin)
    except ValueError as exc:
        raise ClientDepthInputError("marker_origin must be a reserved HTTPS origin") from exc
    if parsed.scheme != "https" or not parsed.hostname or not parsed.hostname.endswith(".invalid") or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ClientDepthInputError("marker_origin must be a reserved HTTPS .invalid origin")
    marker = _safe_token(marker, "marker")
    return (
        InertClientCandidate("postmessage", "string_marker", marker, "trace string message handling", "the reviewed receiver accepts string data"),
        InertClientCandidate("postmessage", "object_text_marker", f'{{"type":"r5d-marker","value":"{marker}"}}', "trace typed-message dispatch as inert text", "the reviewed receiver parses a typed object"),
        InertClientCandidate("postmessage", "target_origin", marker_origin, "replace wildcard sender origins with an exact review origin", "the receiver is expected at this exact origin"),
    )


def _header_pairs(raw: str) -> tuple[tuple[str, str, int], ...]:
    normalized = raw.replace("\r\n", "\n")
    head = normalized.split("\n\n", 1)[0]
    rows = []
    for line_number, line in enumerate(head.split("\n"), 1):
        if ":" not in line or line[:1] in " \t":
            continue
        name, value = line.split(":", 1)
        clean = name.strip().lower()
        if re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", clean):
            rows.append((clean, value.strip()[:4096], line_number))
            if len(rows) > 512:
                raise ClientDepthInputError("header count exceeds 512")
    return tuple(rows)


def analyze_clickjacking(
    saved_headers: str | bytes | bytearray,
    document_source: str | bytes | bytearray = "",
) -> tuple[ClientFinding, ...]:
    """Correlate X-Frame-Options, CSP frame-ancestors, cookies, and script fallbacks."""

    raw = _text(saved_headers, "saved_headers", MAX_HEADERS)
    document = _text(document_source, "document_source", MAX_SOURCE)
    pairs = _header_pairs(raw)
    xfo = tuple(value for name, value, _line in pairs if name == "x-frame-options")
    csp = tuple(value for name, value, _line in pairs if name == "content-security-policy")
    frame_values = []
    for policy in csp:
        match = re.search(r"(?i)(?:^|;)\s*frame-ancestors\s+([^;]+)", policy)
        if match:
            frame_values.append(match.group(1).strip())
    combined = raw + "\n" + document
    findings: list[ClientFinding] = []

    if len({value.lower() for value in xfo}) > 1:
        match = re.search(r"(?im)^X-Frame-Options\s*:", raw)
        if match:
            findings.append(_finding("clickjacking", "conflicting_x_frame_options", "high", combined, match, "intermediaries or browsers select different duplicate values"))
    for value in xfo:
        if value.lower().startswith("allow-from"):
            match = re.search(r"(?im)^X-Frame-Options\s*:\s*ALLOW-FROM", raw)
            if match:
                findings.append(_finding("clickjacking", "obsolete_allow_from", "medium", combined, match, "the browser ignores the obsolete directive"))
        elif value.lower() not in {"deny", "sameorigin"}:
            match = re.search(r"(?im)^X-Frame-Options\s*:", raw)
            if match:
                findings.append(_finding("clickjacking", "invalid_x_frame_options", "medium", combined, match, "the browser does not recognize the supplied value"))
    for value in frame_values:
        if value == "*" or re.search(r"(?:^|\s)https?:($|\s)", value):
            match = re.search(r"(?i)frame-ancestors\s+[^;]+", raw)
            if match:
                findings.append(_finding("clickjacking", "permissive_frame_ancestors", "medium", combined, match, "an attacker-controlled origin matches the source list"))

    protected = bool(frame_values) or any(value.lower() in {"deny", "sameorigin"} for value in xfo)
    if not protected:
        anchor = re.search(r"\S", combined)
        if anchor:
            findings.append(_finding("clickjacking", "missing_frame_protection", "medium", combined, anchor, "a sensitive state-changing UI is rendered with ambient credentials"))
    meta = re.search(r"(?i)<meta[^>]+http-equiv\s*=\s*['\"]?X-Frame-Options", document)
    if meta:
        findings.append(_finding("clickjacking", "meta_x_frame_options_ineffective", "medium", combined, _ShiftedMatch(meta, len(raw) + 1), "the response lacks an effective header or CSP frame-ancestors policy"))
    framebuster = re.search(r"(?i)(?:top|parent)\s*!==?\s*(?:self|window)|if\s*\(\s*self\s*!=\s*top", document)
    if framebuster and not protected:
        findings.append(_finding("clickjacking", "script_only_framebuster", "low", combined, _ShiftedMatch(framebuster, len(raw) + 1), "script is disabled, sandboxed, raced, or rewritten"))
    session_cookie = any(
        name == "set-cookie" and re.search(r"(?i)\b(?:session|auth|token|sid)=", value)
        for name, value, _line in pairs
    )
    if session_cookie and not protected:
        match = re.search(r"(?im)^Set-Cookie\s*:", raw)
        if match:
            findings.append(_finding("clickjacking", "ambient_session_cookie", "medium", combined, match, "the framed endpoint performs a sensitive action with ambient cookie authentication"))
    return tuple(sorted(findings, key=lambda row: (row.offset, row.name)))


def analyze_client_side(
    source: str | bytes | bytearray,
    saved_headers: str | bytes | bytearray = "",
    package_manifest: str | bytes | bytearray = "",
) -> dict[str, object]:
    """Return the combined offline client-side report."""

    return {
        "dom_flows": tuple(row.to_dict() for row in analyze_dom_flows(source)),
        "prototype_gadgets": tuple(row.to_dict() for row in match_prototype_gadgets(source, package_manifest)),
        "postmessage": tuple(row.to_dict() for row in analyze_postmessage(source)),
        "clickjacking": tuple(row.to_dict() for row in analyze_clickjacking(saved_headers, source)),
        "offline": True,
        "browser_started": False,
        "network_requests": 0,
    }


def rows_as_dicts(
    rows: Iterable[DOMFlow | GadgetMatch | ClientFinding | InertClientCandidate],
) -> tuple[dict[str, object], ...]:
    return tuple(row.to_dict() for row in rows)
