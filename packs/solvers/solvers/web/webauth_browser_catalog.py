#!/usr/bin/env python3
"""Offline browser trust-boundary catalogs for DOM clobbering, CSP, and CSPP.

The module consumes caller-supplied HTML, JavaScript, CSP text, and package
metadata.  It never launches a browser, evaluates source, resolves a URL, or
contacts an origin.  Findings are structural leads with explicit preconditions;
catalog entries are historical evidence, not a claim that a live endpoint still
behaves as documented.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import sys
from typing import Sequence
from urllib.parse import unquote_to_bytes, urlsplit


MAX_HTML_BYTES = 2 * 1024 * 1024
MAX_JS_BYTES = 2 * 1024 * 1024
MAX_CSP_BYTES = 128 * 1024
MAX_MANIFEST_BYTES = 512 * 1024
MAX_ELEMENTS = 4096
MAX_ATTRIBUTES = 64
MAX_DEPTH = 128
MAX_POLICIES = 16
MAX_DIRECTIVES = 256
MAX_VALUES = 256
MAX_FINDINGS = 512


class WebauthBrowserError(ValueError):
    """Malformed or over-limit browser artifact supplied to this module."""


def _text(value: str | bytes | bytearray, label: str, maximum: int) -> str:
    if isinstance(value, str):
        text = value
    elif isinstance(value, (bytes, bytearray)):
        try:
            text = bytes(value).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise WebauthBrowserError(f"{label} is not UTF-8") from exc
    else:
        raise WebauthBrowserError(f"{label} must be text or bytes")
    try:
        size = len(text.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise WebauthBrowserError(f"{label} is not valid Unicode text") from exc
    if size > maximum:
        raise WebauthBrowserError(f"{label} exceeds {maximum} bytes")
    if "\x00" in text:
        raise WebauthBrowserError(f"{label} contains NUL")
    return text


def _json_ready(value: object) -> object:
    if hasattr(value, "__dataclass_fields__"):
        return asdict(value)  # type: ignore[arg-type]
    if isinstance(value, tuple):
        return [_json_ready(item) for item in value]
    if isinstance(value, list):
        return [_json_ready(item) for item in value]
    if isinstance(value, dict):
        return {key: _json_ready(item) for key, item in value.items()}
    return value


# ---------------------------------------------------------------------------
# DOM clobbering


_VOID_TAGS = frozenset({
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link",
    "meta", "param", "source", "track", "wbr",
})
_WINDOW_NAME_TAGS = frozenset({"embed", "form", "iframe", "img", "object"})
_CONTROL_TAGS = frozenset({"button", "fieldset", "input", "object", "output", "select", "textarea", "img"})
_REASSOCIATEABLE_TAGS = frozenset({"button", "fieldset", "input", "object", "output", "select", "textarea"})
_JS_IDENTIFIER = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*$")


@dataclass(frozen=True, slots=True)
class NamedElement:
    index: int
    tag: str
    element_id: str | None
    name: str | None
    form_owner: str | None
    form_attribute: str | None
    parent: int | None
    line: int


@dataclass(frozen=True, slots=True)
class NamedChain:
    chain: str
    mechanism: str
    element_indexes: tuple[int, ...]
    precondition: str


@dataclass(frozen=True, slots=True)
class DOMClobberFinding:
    chain: str
    access: str
    sink: str
    evidence: str
    line: int
    confidence: str
    precondition: str


class _InventoryParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.elements: list[NamedElement] = []
        self._stack: list[tuple[str, int | None, str | None]] = []

    def _add(self, tag: str, attrs: list[tuple[str, str | None]], *, push: bool) -> None:
        if len(self.elements) >= MAX_ELEMENTS:
            raise WebauthBrowserError(f"HTML element count exceeds {MAX_ELEMENTS}")
        if len(attrs) > MAX_ATTRIBUTES:
            raise WebauthBrowserError(f"HTML attribute count exceeds {MAX_ATTRIBUTES} on one element")
        if len(self._stack) >= MAX_DEPTH:
            raise WebauthBrowserError(f"HTML nesting exceeds {MAX_DEPTH}")
        lowered = tag.casefold()
        attr_map: dict[str, str] = {}
        for key, value in attrs:
            clean = key.casefold()
            if clean not in attr_map:
                attr_map[clean] = value or ""
        parent = self._stack[-1][1] if self._stack else None
        form_owner = next((form for _tag, _index, form in reversed(self._stack) if form), None)
        form_attribute = attr_map.get("form") if "form" in attr_map else None
        element_id = attr_map.get("id") or None
        name = attr_map.get("name") or None
        index: int | None = None
        if element_id is not None or name is not None:
            index = len(self.elements)
            self.elements.append(NamedElement(
                index, lowered, element_id, name, form_owner, form_attribute,
                parent, self.getpos()[0]
            ))
        next_form = form_owner
        if lowered == "form":
            next_form = element_id or name
        if push and lowered not in _VOID_TAGS:
            self._stack.append((lowered, index, next_form))

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._add(tag, attrs, push=True)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._add(tag, attrs, push=False)

    def handle_endtag(self, tag: str) -> None:
        wanted = tag.casefold()
        for offset in range(len(self._stack) - 1, -1, -1):
            if self._stack[offset][0] == wanted:
                del self._stack[offset:]
                break


def _html_inventory(html: str) -> tuple[NamedElement, ...]:
    parser = _InventoryParser()
    try:
        parser.feed(html)
        parser.close()
    except WebauthBrowserError:
        raise
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError, MemoryError) as exc:
        raise WebauthBrowserError(f"cannot parse HTML: {exc}") from exc
    return tuple(parser.elements)


def _named_chains(elements: tuple[NamedElement, ...]) -> tuple[NamedChain, ...]:
    rows: list[NamedChain] = []
    groups: dict[str, list[NamedElement]] = {}
    for element in elements:
        keys: list[str] = []
        if element.element_id:
            keys.append(element.element_id)
        if element.name and element.tag in _WINDOW_NAME_TAGS:
            keys.append(element.name)
        for key in dict.fromkeys(keys):
            groups.setdefault(key, []).append(element)
            rows.append(NamedChain(
                key,
                "window/document named access",
                (element.index,),
                "the browser exposes this eligible id/name for named access",
            ))

    # Duplicate IDs/names can yield an HTMLCollection.  A named member of that
    # collection provides the documented two-level x.y clobbering primitive.
    for root, members in groups.items():
        unique = {member.index: member for member in members}
        if len(unique) < 2:
            continue
        rows.append(NamedChain(
            root,
            "duplicate named elements / HTMLCollection",
            tuple(sorted(unique)),
            "duplicate eligible named elements can resolve to a collection",
        ))
        for member in unique.values():
            child = member.name
            if child and child != root:
                rows.append(NamedChain(
                    f"{root}.{child}",
                    "duplicate named elements / HTMLCollection",
                    tuple(sorted(unique)),
                    "duplicate named elements form a collection with a named member",
                ))

    # Form owners expose controls by id/name (HTMLFormControlsCollection).
    first_by_id: dict[str, NamedElement] = {}
    for element in elements:
        if element.element_id:
            first_by_id.setdefault(element.element_id, element)

    forms: dict[str, list[NamedElement]] = {}
    for element in elements:
        if element.tag not in _CONTROL_TAGS:
            continue
        owner = element.form_owner
        if element.form_attribute is not None and element.tag in _REASSOCIATEABLE_TAGS:
            # A present form= attribute suppresses ancestor association.  It
            # resolves only to the first form whose ID is exactly the value.
            target = first_by_id.get(element.form_attribute)
            owner = (
                (target.element_id or target.name)
                if target is not None and target.tag == "form"
                else None
            )
        if owner:
            forms.setdefault(owner, []).append(element)
    for form_name, controls in forms.items():
        for control in controls:
            for child in (control.name, control.element_id):
                if child:
                    rows.append(NamedChain(
                        f"{form_name}.{child}",
                        "form named-property access",
                        (control.index,),
                        "the named control remains associated with the named form",
                    ))

    # Nested named forms/iframes are useful evidence for deeper chains, but are
    # marked as candidates because browsing-context creation is runtime-specific.
    by_index = {element.index: element for element in elements}
    for element in elements:
        if element.parent is None:
            continue
        parent = by_index.get(element.parent)
        if not parent or parent.tag not in {"form", "iframe"}:
            continue
        if parent.tag == "form" and element.tag in _CONTROL_TAGS:
            # The form-owner branch above models controls precisely, including
            # a form= attribute that overrides or suppresses ancestor ownership.
            continue
        parent_name = parent.element_id or parent.name
        child_name = element.name or element.element_id
        if parent_name and child_name:
            rows.append(NamedChain(
                f"{parent_name}.{child_name}",
                "nested named element",
                (parent.index, element.index),
                "the parent collection or browsing context exposes the nested name",
            ))

    # Keep the strongest structural explanation for a chain.  A form control is
    # more precise than the generic parent/child observation, while a duplicate
    # collection is more precise than a single named-property observation.
    priority = {
        "duplicate named elements / HTMLCollection": 3,
        "form named-property access": 3,
        "nested named element": 2,
        "window/document named access": 1,
    }
    deduped: dict[str, NamedChain] = {}
    for row in rows:
        previous = deduped.get(row.chain)
        if previous is None or priority[row.mechanism] > priority[previous.mechanism]:
            deduped[row.chain] = row
    return tuple(sorted(deduped.values(), key=lambda row: (row.chain, row.mechanism)))


_SENSITIVE_JS = (
    ("script_or_resource_url", re.compile(r"(?i)(?:\.src\s*=|import\s*\(|new\s+(?:Shared)?Worker\s*\(|serviceWorker\.register\s*\()")),
    ("html_parser", re.compile(r"(?i)(?:innerHTML|outerHTML|srcdoc|insertAdjacentHTML)\s*(?:=|\()")),
    ("navigation", re.compile(r"(?i)(?:\blocation(?:\.href)?\s*=|location\.(?:assign|replace)\s*\(|window\.open\s*\()")),
    ("code_execution", re.compile(r"(?i)(?:\beval\s*\(|\bFunction\s*\(|set(?:Timeout|Interval)\s*\()")),
)


def _chain_pattern(chain: str) -> re.Pattern[str] | None:
    parts = chain.split(".")
    if not parts or any(not _JS_IDENTIFIER.fullmatch(part) for part in parts):
        return None
    dotted = r"\.".join(re.escape(part) for part in parts)
    if len(parts) == 1:
        root = re.escape(parts[0])
        return re.compile(rf"(?<![\w$])(?:(?:window|document)\.)?{root}(?![\w$])")
    return re.compile(rf"(?<![\w$])(?:(?:window|document)\.)?{dotted}(?![\w$])")


def _statement(text: str, offset: int) -> tuple[str, int]:
    start = max(text.rfind(";", 0, offset), text.rfind("\n", 0, offset)) + 1
    semicolon = text.find(";", offset)
    newline = text.find("\n", offset)
    ends = [item for item in (semicolon, newline) if item >= 0]
    end = min(ends) + 1 if ends else min(len(text), offset + 1024)
    return text[start:end][:2048], text.count("\n", 0, start) + 1


def _correlate_named_reads(chains: tuple[NamedChain, ...], javascript: str) -> tuple[DOMClobberFinding, ...]:
    findings: list[DOMClobberFinding] = []
    for chain in chains:
        pattern = _chain_pattern(chain.chain)
        if pattern is None:
            continue
        for match in pattern.finditer(javascript):
            statement, line = _statement(javascript, match.start())
            sink = next((name for name, detector in _SENSITIVE_JS if detector.search(statement)), None)
            if sink:
                findings.append(DOMClobberFinding(
                    chain.chain,
                    match.group(0),
                    sink,
                    statement.strip(),
                    line,
                    "high" if chain.mechanism.startswith(("duplicate", "form")) else "medium",
                    chain.precondition,
                ))
            if len(findings) >= MAX_FINDINGS:
                return tuple(findings)

        # One-hop aliases cover the common `const cfg = window.config; s.src = cfg.url` shape.
        alias_pattern = re.compile(
            rf"(?:\b(?:const|let|var)\s+)([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*{pattern.pattern}"
        )
        for alias in alias_pattern.finditer(javascript):
            name = alias.group(1)
            tail = javascript[alias.end(): alias.end() + 16384]
            for use in re.finditer(rf"(?<![\w$]){re.escape(name)}(?:\.[A-Za-z_$][\w$]*)?", tail):
                statement, line = _statement(javascript, alias.end() + use.start())
                sink = next((kind for kind, detector in _SENSITIVE_JS if detector.search(statement)), None)
                if sink:
                    findings.append(DOMClobberFinding(
                        chain.chain,
                        f"{alias.group(0)} -> {use.group(0)}",
                        sink,
                        statement.strip(),
                        line,
                        "medium",
                        chain.precondition,
                    ))
                    break
    unique: dict[tuple[str, str, int, str], DOMClobberFinding] = {}
    for row in findings:
        unique.setdefault((row.chain, row.sink, row.line, row.evidence), row)
    return tuple(sorted(unique.values(), key=lambda row: (row.line, row.chain, row.sink)))


@dataclass(frozen=True, slots=True)
class CurrentScriptEntry:
    library: str
    package: str
    cve: str
    affected: str
    fixed: str
    marker: str
    provenance: str
    automatic_rule: str | None = None
    required_access: str = "document.currentScript"
    clobber_name: str = "currentScript"
    minimum_named_elements: int = 1


_CURRENT_SCRIPT_CATALOG = (
    CurrentScriptEntry(
        "Webpack", "webpack", "CVE-2024-43788",
        "Webpack >=5.0.0-alpha.0 and <5.94.0", "5.94.0",
        "__webpack_require__", "https://github.com/advisories/GHSA-4vvj-4cpr-p986",
        ">=5.0.0-alpha.0,<5.94.0",
    ),
    CurrentScriptEntry(
        "Vite", "vite", "CVE-2024-45812", "multiple maintained branches before advisory fixes",
        "5.4.6 plus fixes on maintained older branches", "__vite__",
        "https://github.com/advisories/GHSA-64vr-g452-qvp3",
    ),
    CurrentScriptEntry(
        "Rollup", "rollup", "CVE-2024-47068",
        "<2.79.2; >=3.0.0,<3.29.5; >=4.0.0,<4.22.4",
        "2.79.2, 3.29.5, or 4.22.4 on the corresponding branch",
        "ROLLUP_FILE_URL", "https://github.com/advisories/GHSA-gcx4-mw62-g8wm",
        "<2.79.2 || >=3.0.0,<3.29.5 || >=4.0.0,<4.22.4",
    ),
    CurrentScriptEntry(
        "Astro", "astro", "CVE-2024-47885", ">=3.0.0,<4.16.1",
        "4.16.1", "astroExec", "https://github.com/advisories/GHSA-m85w-3h95-hcf9",
        ">=3.0.0,<4.16.1", "document.scripts", "scripts", 2,
    ),
    CurrentScriptEntry(
        "layui", "layui", "CVE-2024-47075", "<2.9.17",
        "2.9.17", "layui", "https://github.com/advisories/GHSA-j827-6rgf-9629",
        "<2.9.17",
    ),
)


def current_script_catalog() -> tuple[CurrentScriptEntry, ...]:
    """Return provenance-tagged runtime DOM-clobbering entries."""

    return _CURRENT_SCRIPT_CATALOG


def analyze_dom_clobbering(
    html: str | bytes | bytearray,
    javascript: str | bytes | bytearray = "",
    package_manifest: str | bytes | bytearray = "",
) -> dict[str, object]:
    """Inventory named HTML properties and correlate them with supplied JS reads."""

    document = _text(html, "HTML", MAX_HTML_BYTES)
    script = _text(javascript, "JavaScript", MAX_JS_BYTES)
    manifest = _text(package_manifest, "package manifest", MAX_MANIFEST_BYTES)
    elements = _html_inventory(document)
    chains = _named_chains(elements)
    findings = _correlate_named_reads(chains, script)
    dependencies = _manifest_versions(manifest) if manifest else {}
    current_script: list[dict[str, object]] = []
    for entry in _CURRENT_SCRIPT_CATALOG:
        access_pattern = r"\s*\.\s*".join(
            re.escape(part) for part in entry.required_access.split(".")
        )
        if not re.search(rf"\b{access_pattern}\b", script):
            continue
        version = dependencies.get(entry.package)
        marker_seen = entry.marker.casefold() in script.casefold()
        if not (version or marker_seen):
            continue
        matching = tuple(row for row in chains if row.chain == entry.clobber_name)
        if entry.minimum_named_elements == 1:
            has_clobber = bool(matching)
        else:
            has_clobber = any(
                row.mechanism == "duplicate named elements / HTMLCollection"
                and len(row.element_indexes) >= entry.minimum_named_elements
                for row in matching
            )
        current_script.append({
            **asdict(entry),
            "observed_version": version,
            "declared_version": version,
            "version_source": "package manifest declaration" if version else None,
            "version_status": _current_script_version_status(entry, version),
            "required_access_present": True,
            "clobber_shape_present": has_clobber,
            # Compatibility for callers that already consume this field.
            "named_currentScript_present": (
                has_clobber if entry.clobber_name == "currentScript" else False
            ),
            "precondition": (
                f"attacker HTML creates at least {entry.minimum_named_elements} eligible "
                f"named element(s) for {entry.clobber_name!r}, and the runtime reaches "
                f"{entry.required_access}"
            ),
        })
    return {
        "named_elements": [_json_ready(row) for row in elements],
        "chains": [_json_ready(row) for row in chains],
        "findings": [_json_ready(row) for row in findings],
        "current_script_catalog_matches": current_script,
        "offline": True,
        "executed": False,
        "browser_started": False,
        "network_requests": 0,
    }


# ---------------------------------------------------------------------------
# CSP policy parsing and offline allowlist gadgets


@dataclass(frozen=True, slots=True)
class CSPDirective:
    name: str
    values: tuple[str, ...]
    occurrence: int


@dataclass(frozen=True, slots=True)
class CSPPolicy:
    index: int
    raw: str
    directives: tuple[CSPDirective, ...]

    def first(self, name: str) -> tuple[str, ...] | None:
        wanted = name.casefold()
        return next((row.values for row in self.directives if row.name == wanted), None)


@dataclass(frozen=True, slots=True)
class CSPGadget:
    name: str
    family: str
    url: str
    provenance: str
    preconditions: tuple[str, ...]
    stale_warning: str = "historical pinned catalog entry; endpoint behavior was not probed"


_CSP_EVALUATOR_COMMIT = "ad530f3ae5473f9e03c8bf500ee0ada8d9e9b822"
_CSP_JSONP_PROVENANCE = (
    "google/csp-evaluator@" + _CSP_EVALUATOR_COMMIT
    + ":allowlist_bypasses/json/jsonp.json"
)
_CSP_ANGULAR_PROVENANCE = (
    "google/csp-evaluator@" + _CSP_EVALUATOR_COMMIT
    + ":allowlist_bypasses/json/angular.json"
)


_CSP_GADGETS = (
    CSPGadget(
        "google_complete_jsonp", "jsonp",
        "https://clients1.google.com/complete/search",
        _CSP_JSONP_PROVENANCE,
        ("the endpoint accepts an attacker-controlled callback", "a parser-inserted external script is allowed"),
    ),
    CSPGadget(
        "google_cse_jsonp", "jsonp",
        "https://cse.google.com/api/007627024705277327428/cse/r3vs7b0fcli/queries/js",
        _CSP_JSONP_PROVENANCE,
        ("the pinned historical endpoint still emits callback-wrapped JavaScript",),
    ),
    CSPGadget(
        "googleapis_angular", "angular",
        "https://ajax.googleapis.com/ajax/libs/angularjs/1.2.0rc1/angular-route.min.js",
        _CSP_ANGULAR_PROVENANCE,
        ("attacker-controlled markup can bootstrap AngularJS", "a compatible expression gadget is present"),
    ),
    CSPGadget(
        "cdnjs_angular", "angular",
        "https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.2.16/angular.min.js",
        _CSP_ANGULAR_PROVENANCE,
        ("the allowlist path covers the AngularJS asset", "attacker-controlled Angular markup is accepted"),
    ),
    CSPGadget(
        "jsdelivr_angular", "angular",
        "https://cdn.jsdelivr.net/angularjs/1.1.2/angular.min.js",
        _CSP_ANGULAR_PROVENANCE,
        ("the allowlist covers the cataloged CDN path", "attacker-controlled Angular markup is accepted"),
    ),
)


def csp_gadget_catalog() -> tuple[CSPGadget, ...]:
    return _CSP_GADGETS


def parse_csp_policies(policies: str | Sequence[str]) -> tuple[CSPPolicy, ...]:
    """Parse one or more independently enforced CSP policies, preserving duplicates."""

    if isinstance(policies, str):
        supplied = (policies,)
    elif isinstance(policies, Sequence) and not isinstance(policies, (bytes, bytearray)):
        supplied = tuple(policies)
    else:
        raise WebauthBrowserError("CSP policies must be text or a sequence of text policies")
    if not supplied or len(supplied) > MAX_POLICIES:
        raise WebauthBrowserError(f"CSP policy count must be 1..{MAX_POLICIES}")

    rows: list[CSPPolicy] = []
    total = 0
    for index, raw in enumerate(supplied):
        policy = _text(raw, f"CSP policy {index}", MAX_CSP_BYTES)
        total += len(policy.encode("utf-8"))
        if total > MAX_CSP_BYTES:
            raise WebauthBrowserError(f"combined CSP exceeds {MAX_CSP_BYTES} bytes")
        if any(ord(char) < 32 and char != "\t" for char in policy):
            raise WebauthBrowserError(f"CSP policy {index} contains a control character")
        directives: list[CSPDirective] = []
        occurrences: dict[str, int] = {}
        for part in policy.split(";"):
            tokens = part.strip().split()
            if not tokens:
                continue
            name = tokens[0].casefold()
            if not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", name):
                raise WebauthBrowserError(f"invalid CSP directive {tokens[0]!r}")
            if len(tokens) - 1 > MAX_VALUES:
                raise WebauthBrowserError(f"too many values for CSP directive {name}")
            occurrences[name] = occurrences.get(name, 0) + 1
            directives.append(CSPDirective(name, tuple(tokens[1:]), occurrences[name]))
            if len(directives) > MAX_DIRECTIVES:
                raise WebauthBrowserError(f"CSP directive count exceeds {MAX_DIRECTIVES}")
        rows.append(CSPPolicy(index, policy, tuple(directives)))
    return tuple(rows)


def _effective(policy: CSPPolicy, destination: str) -> tuple[str, tuple[str, ...] | None]:
    fallbacks = {
        "script-src-elem": ("script-src-elem", "script-src", "default-src"),
        "script-src-attr": ("script-src-attr", "script-src", "default-src"),
        "object-src": ("object-src", "default-src"),
    }
    for name in fallbacks.get(destination, (destination, "default-src")):
        values = policy.first(name)
        if values is not None:
            return name, values
    return destination, None


_BASE64_VALUE = r"[A-Za-z0-9+/_-]+={0,2}"
_NONCE_SOURCE = re.compile(rf"'nonce-{_BASE64_VALUE}'", re.I)
_HASH_SOURCE = re.compile(rf"'sha(?:256|384|512)-{_BASE64_VALUE}'", re.I)
_HOST_SOURCE = re.compile(
    r"(?:(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*):\/\/)?"
    r"(?P<host>\*|\*\.(?:[A-Za-z0-9-]+\.)*[A-Za-z0-9-]+|(?:[A-Za-z0-9-]+\.)*[A-Za-z0-9-]+)"
    r"(?::(?P<port>\*|[0-9]+))?"
    r"(?P<path>\/[^\s?#]*)?"
)


def _is_nonce_source(value: str) -> bool:
    return _NONCE_SOURCE.fullmatch(value) is not None


def _is_hash_source(value: str) -> bool:
    return _HASH_SOURCE.fullmatch(value) is not None


def _nonce_or_hash(values: tuple[str, ...]) -> bool:
    return any(_is_nonce_source(item) or _is_hash_source(item) for item in values)


def _strict_dynamic(values: tuple[str, ...]) -> bool:
    return "'strict-dynamic'" in {item.casefold() for item in values} and _nonce_or_hash(values)


def _scheme_matches(source: str, target: str) -> bool:
    left, right = source.casefold(), target.casefold()
    return (
        left == right
        or (left == "http" and right == "https")
        or (left == "ws" and right in {"wss", "http", "https"})
        or (left == "wss" and right == "https")
    )


def _default_port(scheme: str) -> int | None:
    return {"http": 80, "https": 443, "ws": 80, "wss": 443}.get(scheme.casefold())


def _serialized_port(parsed: object) -> int | None:
    try:
        port = parsed.port  # type: ignore[attr-defined]
        scheme = parsed.scheme  # type: ignore[attr-defined]
    except ValueError as exc:
        raise WebauthBrowserError("URL port is malformed") from exc
    return None if port == _default_port(scheme) else port


def _port_matches(
    source_port: str | None, target: object, source_scheme: str | None = None
) -> bool:
    if source_port == "*":
        return True
    target_port = _serialized_port(target)
    if source_port is None:
        return target_port is None
    if len(source_port) > 5:
        raise WebauthBrowserError("CSP source port is over limit")
    try:
        numeric = int(source_port, 10)
    except ValueError as exc:  # Defensive: the source grammar admits digits only.
        raise WebauthBrowserError("CSP source port is malformed") from exc
    if numeric > 65535:
        raise WebauthBrowserError("CSP source port is outside 0..65535")
    if target_port is not None:
        return numeric == target_port
    target_default = _default_port(target.scheme)  # type: ignore[attr-defined]
    if numeric == target_default:
        return True
    return bool(
        source_scheme
        and source_scheme.casefold() != target.scheme.casefold()  # type: ignore[attr-defined]
        and _scheme_matches(source_scheme, target.scheme)  # type: ignore[attr-defined]
        and numeric == _default_port(source_scheme)
    )


def _path_matches(source: str, target: str) -> bool:
    if not source:
        return True
    if source == "/" and target == "":
        return True
    exact = not source.endswith("/")
    source_parts = source.split("/")
    target_parts = target.split("/")
    if len(source_parts) > len(target_parts):
        return False
    if exact and len(source_parts) != len(target_parts):
        return False
    if not exact:
        source_parts = source_parts[:-1]
    return all(
        unquote_to_bytes(left) == unquote_to_bytes(right)
        for left, right in zip(source_parts, target_parts)
    )


def _source_allows_url(source: str, target: str, document_origin: str | None) -> bool:
    token = source.strip()
    folded = token.casefold()
    try:
        parsed_target = urlsplit(target)
        target_port = _serialized_port(parsed_target)
    except (TypeError, ValueError, UnicodeError) as exc:
        raise WebauthBrowserError("catalog URL is malformed") from exc
    del target_port  # Validation is intentional; helpers recompute it when needed.
    if folded == "*":
        return parsed_target.scheme in {"http", "https"}
    if folded in {"'none'", "'strict-dynamic'", "'unsafe-inline'", "'unsafe-eval'", "'report-sample'"}:
        return False
    if folded.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")):
        return False
    if folded == "'self'":
        if not document_origin:
            return False
        try:
            origin = urlsplit(document_origin)
            origin_port = _serialized_port(origin)
            target_port = _serialized_port(parsed_target)
        except (TypeError, ValueError, UnicodeError) as exc:
            raise WebauthBrowserError("document origin is malformed") from exc
        if not origin.hostname or not parsed_target.hostname:
            return False
        same_host = origin.hostname.casefold() == parsed_target.hostname.casefold()
        if not same_host or origin_port != target_port:
            return False
        return _scheme_matches(origin.scheme, parsed_target.scheme)
    if re.fullmatch(r"[a-z][a-z0-9+.-]*:", folded):
        return _scheme_matches(folded[:-1], parsed_target.scheme)

    source_match = _HOST_SOURCE.fullmatch(token)
    if source_match is None:
        return False
    scheme_required = source_match.group("scheme")
    source_scheme: str
    if scheme_required:
        if not _scheme_matches(scheme_required, parsed_target.scheme):
            return False
        source_scheme = scheme_required
    else:
        if not document_origin:
            return False
        try:
            origin = urlsplit(document_origin)
        except (TypeError, ValueError, UnicodeError) as exc:
            raise WebauthBrowserError("document origin is malformed") from exc
        if not _scheme_matches(origin.scheme, parsed_target.scheme):
            return False
        source_scheme = origin.scheme

    host_part = source_match.group("host").casefold()
    target_host = (parsed_target.hostname or "").casefold()
    if not target_host:
        return False
    if not _port_matches(source_match.group("port"), parsed_target, source_scheme):
        return False
    if host_part == "*":
        pass
    elif host_part.startswith("*."):
        # CSP removes only the '*', leaving a leading dot.  Consequently the
        # wildcard matches subdomains but never the bare registrable host.
        if not target_host.endswith(host_part[1:]):
            return False
    elif host_part != target_host:
        return False
    return _path_matches(source_match.group("path") or "", parsed_target.path)


def _policy_allows_gadget(
    policy: CSPPolicy, gadget: CSPGadget, document_origin: str | None
) -> tuple[bool, dict[str, object]]:
    directive, values = _effective(policy, "script-src-elem")
    if values is None:
        return True, {
            "policy": policy.index,
            "directive": directive,
            "values": None,
            "unrestricted": True,
            "reason": "no effective script directive; the CSP3 request check does not execute",
        }
    if _strict_dynamic(values):
        return False, {
            "policy": policy.index,
            "directive": directive,
            "values": values,
            "reason": "nonce/hash plus strict-dynamic ignores host allowlists in CSP3 for parser-inserted scripts",
        }
    allowed_by = tuple(item for item in values if _source_allows_url(item, gadget.url, document_origin))
    return bool(allowed_by), {
        "policy": policy.index,
        "directive": directive,
        "values": values,
        "allowed_by": allowed_by,
        "reason": "host/path source match" if allowed_by else "no source expression matches the catalog URL",
    }


def analyze_csp(
    policies: str | Sequence[str],
    document: str | bytes | bytearray = "",
    *,
    document_origin: str | None = None,
) -> dict[str, object]:
    """Evaluate saved policies and match conservative offline allowlist gadgets."""

    parsed = parse_csp_policies(policies)
    html = _text(document, "document", MAX_HTML_BYTES)
    if document_origin is not None:
        origin = _text(document_origin, "document origin", 2048)
        try:
            split = urlsplit(origin)
            # Accessing .port performs the standard library's range/syntax
            # validation and can otherwise raise later during a 'self' check.
            _ = split.port
            hostname = split.hostname
            username = split.username
            password = split.password
        except (ValueError, TypeError, UnicodeError) as exc:
            raise WebauthBrowserError("document origin is malformed") from exc
        if (
            split.scheme not in {"http", "https"}
            or not hostname
            or username is not None
            or password is not None
            or split.path not in {"", "/"}
            or split.query
            or split.fragment
        ):
            raise WebauthBrowserError(
                "document origin must be an HTTP(S) origin without credentials/path/query/fragment"
            )
        document_origin = origin

    policy_rows: list[dict[str, object]] = []
    findings: list[dict[str, object]] = []
    for policy in parsed:
        elem_name, elem_values = _effective(policy, "script-src-elem")
        attr_name, attr_values = _effective(policy, "script-src-attr")
        object_name, object_values = _effective(policy, "object-src")
        script_values = elem_values or ()
        duplicates = tuple(sorted({row.name for row in policy.directives if row.occurrence > 1}))
        nonces = tuple(item for item in script_values if _is_nonce_source(item))
        hashes = tuple(item for item in script_values if _is_hash_source(item))
        strict = _strict_dynamic(script_values)
        trusted = policy.first("trusted-types")
        require_tt = policy.first("require-trusted-types-for")
        base = policy.first("base-uri")
        row = {
            "index": policy.index,
            "directives": [_json_ready(item) for item in policy.directives],
            "duplicate_directives_ignored_after_first": duplicates,
            "effective_script_src_elem": {"directive": elem_name, "values": elem_values},
            "effective_script_src_attr": {"directive": attr_name, "values": attr_values},
            "effective_object_src": {"directive": object_name, "values": object_values},
            "strict_dynamic_active": strict,
            "nonces": nonces,
            "hashes": hashes,
            "base_uri": base,
            "trusted_types": trusted,
            "require_trusted_types_for_script": bool(require_tt and "'script'" in {item.casefold() for item in require_tt}),
        }
        policy_rows.append(row)
        if duplicates:
            findings.append({"policy": policy.index, "name": "duplicate_directive", "severity": "medium", "evidence": duplicates, "note": "later duplicate occurrences do not replace the first directive"})
        if (strict or nonces or hashes) and base is None:
            findings.append({"policy": policy.index, "name": "missing_base_uri", "severity": "high", "note": "an injected base element may retarget relative trusted loader URLs"})
        if object_values is None or ("'none'" not in {item.casefold() for item in object_values}):
            findings.append({"policy": policy.index, "name": "object_src_not_none", "severity": "medium", "effective_values": object_values})
        folded = {item.casefold() for item in script_values}
        if "'unsafe-eval'" in folded:
            findings.append({"policy": policy.index, "name": "unsafe_eval", "severity": "high"})
        if "'unsafe-inline'" in folded:
            findings.append({
                "policy": policy.index,
                "name": "unsafe_inline",
                "severity": "medium" if _nonce_or_hash(script_values) else "high",
                "note": "ignored by CSP2/3 when a nonce/hash is active" if _nonce_or_hash(script_values) else "inline script is allowed",
            })
        if require_tt is None:
            findings.append({"policy": policy.index, "name": "trusted_types_not_required", "severity": "info"})

    catalog_matches: list[dict[str, object]] = []
    catalog_candidates: list[dict[str, object]] = []
    for gadget in _CSP_GADGETS:
        decisions = [_policy_allows_gadget(policy, gadget, document_origin) for policy in parsed]
        candidate = {
            **asdict(gadget),
            "policy_decisions": [decision for _allowed, decision in decisions],
            "allowed_by_all_policies": all(allowed for allowed, _decision in decisions),
        }
        catalog_candidates.append(candidate)
        if candidate["allowed_by_all_policies"]:
            catalog_matches.append(candidate)

    # Static document evidence only: nonce reuse and obvious permissive TT policies.
    document_nonces = re.findall(r"(?i)\bnonce\s*=\s*['\"]([^'\"]{1,512})['\"]", html)
    repeated = tuple(sorted({item for item in document_nonces if document_nonces.count(item) > 1}))
    if repeated:
        findings.append({"policy": "document", "name": "repeated_nonce", "severity": "high", "evidence": repeated})
    if re.search(r"(?is)createPolicy\s*\([^,]+,\s*\{.{0,4096}createHTML\s*:\s*(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>\s*[A-Za-z_$][\w$]*", html):
        findings.append({"policy": "document", "name": "trusted_types_passthrough_policy", "severity": "high"})

    return {
        "csp_model": "Content Security Policy Level 3",
        "policies": policy_rows,
        "findings": findings[:MAX_FINDINGS],
        "catalog_matches": catalog_matches,
        "catalog_candidates": catalog_candidates,
        "multiple_policies_intersect": len(parsed) > 1,
        "offline": True,
        "endpoint_probes": 0,
        "network_requests": 0,
    }


# ---------------------------------------------------------------------------
# Versioned prototype-pollution source/gadget catalog


@dataclass(frozen=True, slots=True)
class PrototypeCatalogEntry:
    name: str
    library: str
    package: str | None
    polluted_properties: tuple[str, ...]
    terminal_sink: str
    impact: str
    cve: str | None
    affected: str
    provenance: str
    source_patterns: tuple[str, ...]
    min_version: str | None = None
    max_version_exclusive: str | None = None
    stale_warning: str = "static historical catalog entry; inspect the supplied build before concluding exploitability"


_PROTOTYPE_CATALOG = (
    PrototypeCatalogEntry(
        "jquery_deep_extend", "jQuery", "jquery", ("__proto__",), "prototype-unsafe deep extend",
        "arbitrary Object.prototype properties", "CVE-2019-11358", "jQuery before 3.4.0",
        "https://nvd.nist.gov/vuln/detail/CVE-2019-11358",
        (r"(?:\$|jQuery)\.extend\s*\(\s*true\s*,",), max_version_exclusive="3.4.0",
    ),
    PrototypeCatalogEntry(
        "lodash_zip_object_deep", "Lodash", "lodash", ("__proto__", "constructor.prototype"),
        "zipObjectDeep path assignment", "arbitrary Object.prototype properties", "CVE-2020-8203",
        "Lodash >=3.7.0 and <4.17.19", "https://github.com/advisories/GHSA-p6mc-m468-83gw",
        (r"(?:_|lodash)\.zipObjectDeep\s*\(",),
        min_version="3.7.0", max_version_exclusive="4.17.19",
    ),
    PrototypeCatalogEntry(
        "google_analytics_hit_callback", "Google Analytics", None, ("hitCallback",), "string setTimeout",
        "DOM script execution", None, "historical affected analytics runtime",
        "https://portswigger.net/research/widespread-prototype-pollution-gadgets",
        (r"hitCallback", r"setTimeout\s*\("),
    ),
    PrototypeCatalogEntry(
        "google_tag_manager_sequence", "Google Tag Manager", None, ("sequence",), "eval",
        "DOM script execution", None, "historical affected tag-manager runtime",
        "https://portswigger.net/research/widespread-prototype-pollution-gadgets",
        (r"\bsequence\b", r"\beval\s*\("),
    ),
    PrototypeCatalogEntry(
        "google_tag_manager_event_callback", "Google Tag Manager", None, ("event_callback",), "string setTimeout",
        "DOM script execution", None, "historical affected tag-manager runtime",
        "https://portswigger.net/research/widespread-prototype-pollution-gadgets",
        (r"event_callback", r"setTimeout\s*\("),
    ),
    PrototypeCatalogEntry(
        "adobe_dtm_csp_nonce", "Adobe DTM", None, ("cspNonce",), "innerHTML",
        "HTML injection", None, "historical Adobe dynamic-tag-management runtime",
        "https://portswigger.net/research/widespread-prototype-pollution-gadgets",
        (r"cspNonce", r"innerHTML\s*="),
    ),
    PrototypeCatalogEntry(
        "adobe_dtm_body_hidden_style", "Adobe DTM", None, ("bodyHiddenStyle",), "innerHTML after style context",
        "HTML/style-context injection", None, "historical Adobe dynamic-tag-management runtime",
        "https://portswigger.net/research/widespread-prototype-pollution-gadgets",
        (r"bodyHiddenStyle", r"innerHTML\s*="),
    ),
    PrototypeCatalogEntry(
        "adobe_dtm_tracking_server", "Adobe DTM", None, ("trackingServerSecure",), "script.src host",
        "external script loading", None, "historical Adobe dynamic-tag-management runtime",
        "https://portswigger.net/research/widespread-prototype-pollution-gadgets",
        (r"trackingServerSecure", r"\.src\s*="),
    ),
    PrototypeCatalogEntry(
        "recaptcha_srcdoc", "Google reCAPTCHA", None, ("srcdoc",), "iframe.srcdoc",
        "HTML/script injection in iframe", None, "cataloged client-side reCAPTCHA gadget",
        "https://github.com/BlackFan/client-side-prototype-pollution",
        (r"(?:grecaptcha|recaptcha)", r"srcdoc"),
    ),
    PrototypeCatalogEntry(
        "closure_base_path", "Google Closure", "google-closure-library", ("CLOSURE_BASE_PATH",), "script source base",
        "external script loading", None, "cataloged Closure loader gadget",
        "https://github.com/BlackFan/client-side-prototype-pollution",
        (r"CLOSURE_BASE_PATH", r"(?:\.src\s*=|document\.write\s*\()"),
    ),
    PrototypeCatalogEntry(
        "vue_template", "Vue", "vue", ("template", "v-if", "attrs", "is"), "runtime template compiler",
        "DOM script execution when a compatible compiler/gadget is present", None,
        "multiple cataloged Vue 2/3 runtime gadgets; version-specific preconditions apply",
        "https://github.com/BlackFan/client-side-prototype-pollution",
        (r"(?:new\s+Vue|createApp)\s*\(", r"(?:template|v-if|v-bind|innerHTML)"),
    ),
    PrototypeCatalogEntry(
        "zepto_html_onerror", "Zepto", "zepto", ("html", "onerror"), "HTML construction/event handler",
        "DOM script execution", None, "cataloged Zepto gadget",
        "https://github.com/BlackFan/client-side-prototype-pollution",
        (r"\bZepto\b|\$\s*\(", r"(?:onerror|\.html\s*\()"),
    ),
    PrototypeCatalogEntry(
        "dompurify_config", "DOMPurify", "dompurify", ("ALLOWED_TAGS", "ADD_TAGS", "RETURN_DOM"),
        "inherited sanitizer configuration", "sanitizer policy weakening", None,
        "cataloged through 2.0.12; exact gadget depends on configuration",
        "https://github.com/BlackFan/client-side-prototype-pollution",
        (r"DOMPurify\.sanitize\s*\(", r"(?:ALLOWED_TAGS|ADD_TAGS|RETURN_DOM)"),
        max_version_exclusive="2.0.13",
    ),
)


def prototype_gadget_catalog() -> tuple[PrototypeCatalogEntry, ...]:
    return _PROTOTYPE_CATALOG


def _manifest_versions(manifest: str) -> dict[str, str]:
    if not manifest:
        return {}

    def no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise WebauthBrowserError(f"package manifest has duplicate key {key!r}")
            result[key] = value
        return result

    try:
        root = json.loads(manifest, object_pairs_hook=no_duplicates)
    except WebauthBrowserError:
        raise
    except (json.JSONDecodeError, TypeError, ValueError, RecursionError, OverflowError, MemoryError) as exc:
        raise WebauthBrowserError(f"package manifest is not valid bounded JSON: {exc}") from exc
    if not isinstance(root, dict):
        raise WebauthBrowserError("package manifest root must be an object")
    versions: dict[str, tuple[str, str]] = {}
    for section in ("dependencies", "devDependencies", "optionalDependencies", "resolutions"):
        values = root.get(section, {})
        if values is None:
            continue
        if not isinstance(values, dict):
            raise WebauthBrowserError(f"package manifest {section} must be an object")
        for name, version in values.items():
            if not isinstance(name, str) or not isinstance(version, str):
                raise WebauthBrowserError(f"package manifest {section} entries must be string pairs")
            if len(name) > 256 or len(version) > 256:
                raise WebauthBrowserError("package manifest dependency entry is over limit")
            folded = name.casefold()
            previous = versions.get(folded)
            if previous is not None and previous[0] != version:
                raise WebauthBrowserError(
                    f"package manifest has conflicting versions for {name!r} "
                    f"in {previous[1]} ({previous[0]!r}) and {section} ({version!r})"
                )
            versions.setdefault(folded, (version, section))
    return {name: version for name, (version, _section) in versions.items()}


def _semver(value: str) -> tuple[int, int, int, tuple[str, ...]] | None:
    match = re.fullmatch(r"v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?", value.strip())
    if not match:
        return None
    numbers = tuple(int(match.group(index)) for index in (1, 2, 3))
    if any(item > 1_000_000 for item in numbers):
        return None
    prerelease = tuple((match.group(4) or "").split(".")) if match.group(4) else ()
    return numbers[0], numbers[1], numbers[2], prerelease


def _cmp_version(left: tuple[int, int, int, tuple[str, ...]], right: tuple[int, int, int, tuple[str, ...]]) -> int:
    if left[:3] != right[:3]:
        return -1 if left[:3] < right[:3] else 1
    if left[3] == right[3]:
        return 0
    if not left[3]:
        return 1
    if not right[3]:
        return -1
    for left_part, right_part in zip(left[3], right[3]):
        if left_part == right_part:
            continue
        left_numeric, right_numeric = left_part.isdigit(), right_part.isdigit()
        if left_numeric and right_numeric:
            return -1 if int(left_part) < int(right_part) else 1
        if left_numeric != right_numeric:
            return -1 if left_numeric else 1
        return -1 if left_part < right_part else 1
    return -1 if len(left[3]) < len(right[3]) else 1


def _version_status(entry: PrototypeCatalogEntry, observed: str | None) -> str:
    if not entry.package or not observed:
        return "not-observed"
    parsed = _semver(observed)
    if parsed is None:
        return "range-or-non-semver-not-evaluated"
    if entry.min_version:
        minimum = _semver(entry.min_version)
        if minimum and _cmp_version(parsed, minimum) < 0:
            return "outside-catalog-range"
    if entry.max_version_exclusive:
        maximum = _semver(entry.max_version_exclusive)
        if maximum and _cmp_version(parsed, maximum) < 0:
            return "affected-version"
        if maximum:
            return "fixed-boundary-or-newer"
    return "catalog-only-no-reliable-bound"


def _current_script_version_status(entry: CurrentScriptEntry, observed: str | None) -> str:
    if not observed:
        return "not-observed"
    parsed = _semver(observed)
    if not parsed:
        return "range-or-non-semver-not-evaluated"
    if entry.package == "webpack":
        if parsed[0] != 5:
            return "outside-advisory-major"
        maximum = _semver("5.94.0")
        return "affected-version" if maximum and _cmp_version(parsed, maximum) < 0 else "fixed-boundary-or-newer"
    if entry.package == "rollup":
        maximum = {
            2: _semver("2.79.2"),
            3: _semver("3.29.5"),
            4: _semver("4.22.4"),
        }.get(parsed[0])
        if parsed[0] < 2:
            return "affected-version"
        if maximum is None:
            return "fixed-boundary-or-newer"
        return "affected-version" if _cmp_version(parsed, maximum) < 0 else "fixed-boundary-or-newer"
    if entry.package == "astro":
        minimum, maximum = _semver("3.0.0"), _semver("4.16.1")
        if minimum and _cmp_version(parsed, minimum) < 0:
            return "outside-advisory-range"
        return "affected-version" if maximum and _cmp_version(parsed, maximum) < 0 else "fixed-boundary-or-newer"
    if entry.package == "layui":
        maximum = _semver("2.9.17")
        return "affected-version" if maximum and _cmp_version(parsed, maximum) < 0 else "fixed-boundary-or-newer"
    return "branch-specific-bound-not-automated"


def match_prototype_gadgets(
    source: str | bytes | bytearray,
    package_manifest: str | bytes | bytearray = "",
) -> tuple[dict[str, object], ...]:
    """Match documented source/gadget signatures and exact dependency versions."""

    script = _text(source, "JavaScript", MAX_JS_BYTES)
    manifest = _text(package_manifest, "package manifest", MAX_MANIFEST_BYTES)
    dependencies = _manifest_versions(manifest) if manifest else {}
    rows: list[dict[str, object]] = []
    for entry in _PROTOTYPE_CATALOG:
        evidence: list[str] = []
        patterns_match = True
        for raw in entry.source_patterns:
            match = re.search(raw, script, re.I)
            if not match:
                patterns_match = False
                break
            evidence.append(match.group(0)[:240])
        observed = dependencies.get(entry.package.casefold()) if entry.package else None
        version_status = _version_status(entry, observed)
        dependency_lead = version_status == "affected-version"
        if not patterns_match and not dependency_lead:
            continue
        rows.append({
            **asdict(entry),
            "evidence": tuple(evidence),
            "source_signature_match": patterns_match,
            "observed_version": observed,
            "declared_version": observed,
            "version_source": "package manifest declaration" if observed else None,
            "version_status": version_status,
            "confidence": "high" if patterns_match and dependency_lead else "medium" if patterns_match else "low",
            "precondition": "a prototype-pollution source controls the named inherited property and this gadget path is reachable",
            "offline": True,
        })
        if len(rows) >= MAX_FINDINGS:
            break
    return tuple(rows)


def analyze_prototype_catalog(
    source: str | bytes | bytearray,
    package_manifest: str | bytes | bytearray = "",
) -> dict[str, object]:
    return {
        "matches": list(match_prototype_gadgets(source, package_manifest)),
        "catalog_size": len(_PROTOTYPE_CATALOG),
        "offline": True,
        "executed": False,
        "network_requests": 0,
    }


# ---------------------------------------------------------------------------
# Guarded CLI


def _read(path: str, label: str, maximum: int) -> str:
    try:
        item = Path(path)
        if not item.is_file() or item.stat().st_size > maximum:
            raise WebauthBrowserError(f"{label} is absent or exceeds {maximum} bytes")
        with item.open("rb") as handle:
            raw = handle.read(maximum + 1)
    except WebauthBrowserError:
        raise
    except OSError as exc:
        raise WebauthBrowserError(f"cannot read {label}: {exc}") from exc
    if len(raw) > maximum:
        raise WebauthBrowserError(f"{label} exceeds {maximum} bytes")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise WebauthBrowserError(f"{label} is not UTF-8") from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    dom = sub.add_parser("dom", help="analyze HTML named properties and supplied JavaScript")
    dom.add_argument("html")
    dom.add_argument("--javascript")
    dom.add_argument("--manifest")

    csp = sub.add_parser("csp", help="analyze one or more literal CSP policies")
    csp.add_argument("--policy", action="append", required=True)
    csp.add_argument("--document")
    csp.add_argument("--origin")

    prototype = sub.add_parser("prototype", help="match the versioned prototype gadget catalog")
    prototype.add_argument("javascript")
    prototype.add_argument("--manifest")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        try:
            args = build_parser().parse_args(argv)
        except SystemExit as exc:
            return exc.code if isinstance(exc.code, int) else 2

        if args.command == "dom":
            result = analyze_dom_clobbering(
                _read(args.html, "HTML", MAX_HTML_BYTES),
                _read(args.javascript, "JavaScript", MAX_JS_BYTES) if args.javascript else "",
                _read(args.manifest, "package manifest", MAX_MANIFEST_BYTES) if args.manifest else "",
            )
        elif args.command == "csp":
            result = analyze_csp(
                args.policy,
                _read(args.document, "document", MAX_HTML_BYTES) if args.document else "",
                document_origin=args.origin,
            )
        elif args.command == "prototype":
            result = analyze_prototype_catalog(
                _read(args.javascript, "JavaScript", MAX_JS_BYTES),
                _read(args.manifest, "package manifest", MAX_MANIFEST_BYTES) if args.manifest else "",
            )
        else:  # argparse's required subparser makes this defensive only.
            raise WebauthBrowserError("unknown command")
        print(json.dumps(_json_ready(result), indent=2, sort_keys=True))
        return 0
    except WebauthBrowserError as exc:
        print(f"webauth_browser_catalog: {exc}", file=sys.stderr)
        return 2
    except (OSError, UnicodeError, ValueError, TypeError, RecursionError, OverflowError, MemoryError) as exc:
        # Public CLI boundary: no stdlib/parser exception is allowed to escape.
        print(f"webauth_browser_catalog: malformed input: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = [
    "CSPDirective", "CSPGadget", "CSPPolicy", "CurrentScriptEntry",
    "DOMClobberFinding", "NamedChain", "NamedElement", "PrototypeCatalogEntry",
    "WebauthBrowserError", "analyze_csp", "analyze_dom_clobbering",
    "analyze_prototype_catalog", "csp_gadget_catalog", "current_script_catalog",
    "main", "match_prototype_gadgets", "parse_csp_policies",
    "prototype_gadget_catalog",
]
