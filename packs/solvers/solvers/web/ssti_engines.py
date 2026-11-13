#!/usr/bin/env python3
"""Offline, inert SSTI probe builders and saved-evidence detectors.

The module deliberately has no HTTP client and never renders a template.  It
only returns benign probe *strings* for a player to place into an assigned CTF
request, or inspects response/source text that has already been saved.  The
probes perform arithmetic, string conversion, or a constant conditional; none
read files, invoke commands, access objects, or deserialize input.

Nine template families are covered: Jinja2, Twig, FreeMarker, Velocity, ERB,
Smarty, Handlebars, Pug, and Mako.  Exact wrapped results are stronger evidence
than engine-named exceptions, while passive source signatures remain leads.
Raw reflected probes never count as evaluated results because every expected
marker only becomes contiguous after template evaluation.
"""

from __future__ import annotations

import argparse
import html
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Sequence
from urllib.parse import quote, unquote


ENGINES: tuple[str, ...] = (
    "jinja2",
    "twig",
    "freemarker",
    "velocity",
    "erb",
    "smarty",
    "handlebars",
    "pug",
    "mako",
)

CONTEXTS: tuple[str, ...] = (
    "raw",
    "html_text",
    "html_attr_double",
    "html_attr_single",
    "json_string",
    "url_component",
    "template_single_quote",
    "template_double_quote",
)

DEFAULT_MARKER = "R5D_SSTI"
MAX_SAVED_BYTES = 8 * 1024 * 1024
MAX_CONTEXT_PAYLOAD_CHARS = 64 * 1024

_ALIASES = {
    "jinja": "jinja2",
    "jinja-2": "jinja2",
    "free-marker": "freemarker",
    "free_marker": "freemarker",
    "apache-velocity": "velocity",
    "ruby": "erb",
    "ruby-erb": "erb",
    "handlebars.js": "handlebars",
    "hbs": "handlebars",
    "pugjs": "pug",
}

_MARKER_RE = re.compile(r"\A[A-Za-z][A-Za-z0-9_-]{3,39}\Z")


@dataclass(frozen=True)
class ExpectedRender:
    """One engine-specific result for a probe."""

    engine: str
    rendered: str


@dataclass(frozen=True)
class Probe:
    """A benign raw template probe and its exact wrapped result(s)."""

    probe_id: str
    engines: tuple[str, ...]
    payload: str
    expected: tuple[ExpectedRender, ...]
    primitive: str
    note: str
    inert: bool = True

    def as_dict(self) -> dict[str, object]:
        row = asdict(self)
        row["engines"] = list(self.engines)
        row["expected"] = [asdict(item) for item in self.expected]
        return row


@dataclass(frozen=True)
class PayloadVariant:
    """A context-encoded representation of an inert :class:`Probe`."""

    engine: str
    probe_id: str
    context: str
    payload: str
    raw_payload: str
    expected_render: str
    primitive: str
    note: str
    inert: bool = True
    offline: bool = True

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class Detection:
    """A ranked engine lead derived solely from supplied text."""

    engine: str
    score: int
    confidence: str
    evidence: tuple[str, ...]
    probe_ids: tuple[str, ...]
    offline: bool = True

    def as_dict(self) -> dict[str, object]:
        row = asdict(self)
        row["evidence"] = list(self.evidence)
        row["probe_ids"] = list(self.probe_ids)
        return row


@dataclass(frozen=True)
class _ProbeSpec:
    probe_id: str
    engines: tuple[str, ...]
    expression: str
    results: tuple[tuple[str, str], ...]
    primitive: str
    note: str
    # Text that must precede the wrapped expression on its source line. Pug
    # treats a line that begins with text as a tag declaration, so a buffered
    # text interpolation at line start requires the leading ``|`` text marker.
    line_prefix: str = ""


# The Jinja/Twig expression intentionally has different semantics: Python
# repeats a string while Twig coerces it to a number.  All other expressions
# use a language-specific delimiter/operator or control structure.
_PROBE_SPECS: tuple[_ProbeSpec, ...] = (
    _ProbeSpec(
        "curly_string_multiply",
        ("jinja2", "twig"),
        "{{7*'7'}}",
        (("jinja2", "7777777"), ("twig", "49")),
        "constant string multiplication",
        "Distinguishes Jinja2 repetition from Twig numeric coercion.",
    ),
    _ProbeSpec(
        "freemarker_upper_builtin",
        ("freemarker",),
        '${"r5d"?upper_case}',
        (("freemarker", "R5D"),),
        "constant ?upper_case built-in",
        "FreeMarker-specific built-in syntax; no object access.",
    ),
    _ProbeSpec(
        "velocity_constant_assignment",
        ("velocity",),
        "#set($r5d_probe = 7 * 7)${r5d_probe}",
        (("velocity", "49"),),
        "constant #set arithmetic",
        "Stores and prints a constant local template value.",
    ),
    _ProbeSpec(
        "erb_constant_expression",
        ("erb",),
        "<%= 7 * 7 %>",
        (("erb", "49"),),
        "constant ERB expression",
        "Evaluates arithmetic only.",
    ),
    _ProbeSpec(
        "smarty_constant_expression",
        ("smarty",),
        "{7 * 7}",
        (("smarty", "49"),),
        "constant Smarty expression",
        "Uses Smarty 3+ expression syntax and no variables.",
    ),
    _ProbeSpec(
        "handlebars_constant_block",
        ("handlebars",),
        "{{#if true}}R5D_OK{{/if}}",
        (("handlebars", "R5D_OK"),),
        "constant built-in if block",
        "Uses only the built-in truth test and a constant body.",
    ),
    _ProbeSpec(
        "pug_constant_interpolation",
        ("pug",),
        "#{7 * 7}",
        (("pug", "49"),),
        "constant Pug interpolation",
        "Interpolates arithmetic only.",
        line_prefix="| ",
    ),
    _ProbeSpec(
        "mako_constant_method",
        ("mako",),
        '${"r5d".upper()}',
        (("mako", "R5D"),),
        "constant Python string method",
        "Mako/Python string operation with no external object access.",
    ),
)


_ERROR_HINTS: dict[str, tuple[re.Pattern[str], ...]] = {
    "jinja2": (
        re.compile(r"\bjinja2\.exceptions\.[A-Za-z]+Error\b", re.I),
        re.compile(r"\b(?:TemplateAssertionError|UndefinedError)\b.*\bJinja", re.I),
    ),
    "twig": (
        re.compile(r"\bTwig\\Error\\(?:SyntaxError|RuntimeError|LoaderError)\b", re.I),
        re.compile(r"\bTwig_(?:Error|Exception)(?:_[A-Za-z]+)?\b", re.I),
    ),
    "freemarker": (
        re.compile(r"\bfreemarker\.(?:core|template)\.[A-Za-z_$][\w$]*Exception\b", re.I),
        re.compile(r"\bFreeMarker template error\b", re.I),
    ),
    "velocity": (
        re.compile(r"\borg\.apache\.velocity\.exception\.[A-Za-z]+Exception\b", re.I),
        re.compile(r"\borg\.apache\.velocity\.runtime\.parser\.[A-Za-z]+Exception\b", re.I),
        re.compile(r"\b(?:VelocityException|MethodInvocationException)\b", re.I),
    ),
    "erb": (
        re.compile(r"\bActionView::Template(?::Error)?\b"),
        re.compile(r"(?:^|[\s(])\(erb\):\d+", re.M),
        re.compile(r"\bERB::Util\b"),
    ),
    "smarty": (
        re.compile(r"\bSmarty(?:Compiler)?Exception\b", re.I),
        re.compile(r"\bSmarty_Internal_(?:Template|TemplateCompilerBase)\b", re.I),
        re.compile(r"\bSmarty:\s+(?:Unable to load|Syntax error|Undefined variable)\b", re.I),
    ),
    "handlebars": (
        re.compile(r"\bHandlebars\.(?:Exception|parse)\b", re.I),
        re.compile(r"\bMissing helper:\s*[\"'][^\"']+[\"']", re.I),
    ),
    "pug": (
        re.compile(r"\bpug-(?:runtime|lexer|parser)\b", re.I),
        re.compile(r"\bPug:.*(?:unexpected|error)\b", re.I),
        re.compile(r"(?:^|[\s(])[^\s():]*\.pug:\d+(?::\d+)?", re.I | re.M),
    ),
    "mako": (
        re.compile(r"\bmako\.exceptions\.(?:CompileException|SyntaxException)\b", re.I),
        re.compile(r"\bMakoException\b", re.I),
    ),
}


_SOURCE_HINTS: dict[str, tuple[re.Pattern[str], ...]] = {
    "jinja2": (
        re.compile(r"\{%-?\s*(?:extends|block|macro)\b[^%]*-?%\}.*\|\s*(?:safe|tojson)\b", re.I | re.S),
        re.compile(r"\b(?:from\s+jinja2\s+import|jinja2\.Environment\s*\()", re.I),
    ),
    "twig": (
        re.compile(r"\{%-?\s*(?:extends|embed|use)\b[^%]*%\}.*\|\s*raw\b", re.I | re.S),
        re.compile(r"\{\{\s*(?:path|asset)\s*\(", re.I),
        re.compile(r"\bnew\s+\\?Twig\\Environment\s*\(", re.I),
    ),
    "freemarker": (
        re.compile(r"<(?:#|@)(?:assign|list|macro|include)\b", re.I),
        re.compile(r"\?\s*(?:html|upper_case|lower_case|has_content)\b", re.I),
        re.compile(r"\bimport\s+freemarker\.(?:template|cache)\.", re.I),
    ),
    "velocity": (
        re.compile(r"#(?:set|foreach|macro)\s*\(\s*\$", re.I),
        re.compile(r"\$!\{[A-Za-z_]", re.I),
        re.compile(r"\b(?:new\s+)?VelocityEngine\s*\(", re.I),
    ),
    "erb": (
        re.compile(r"<%(?:=|-|#).*?%>", re.S),
        re.compile(r"\bERB\.new\s*\(", re.I),
    ),
    "smarty": (
        re.compile(r"\{(?:foreach|include|assign)\b[^}]*\}", re.I),
        re.compile(r"\{\$smarty\.[A-Za-z_]", re.I),
        re.compile(r"\bnew\s+Smarty\s*\(", re.I),
    ),
    "handlebars": (
        re.compile(r"\{\{#(?:each|if|with|unless)\b.*?\}\}.*?\{\{/", re.I | re.S),
        re.compile(r"\{\{>\s*[A-Za-z_]", re.I),
        re.compile(r"\bHandlebars\.compile\s*\(", re.I),
    ),
    "pug": (
        re.compile(r"(?m)^\s*(?:doctype\s+html|extends\s+\S+|block\s+\S+|mixin\s+\S+)\s*$", re.I),
        re.compile(r"(?m)^\s*[A-Za-z][\w-]*(?:\.[\w-]+|#[\w-]+)?\([^\n]*\)\s*$"),
        re.compile(r"\bpug\.(?:compile|render|renderFile)\s*\(", re.I),
    ),
    "mako": (
        re.compile(r"<%(?:def|block|namespace|inherit)\b", re.I),
        re.compile(r"(?m)^\s*%\s*(?:for|if|while)\b.*:\s*$", re.I),
        re.compile(r"\bfrom\s+mako\.template\s+import\s+Template\b", re.I),
    ),
}


def normalize_engine(engine: str) -> str:
    """Return a canonical engine name or raise a descriptive ``ValueError``."""

    name = str(engine).strip().lower()
    name = _ALIASES.get(name, name)
    if name not in ENGINES:
        raise ValueError(f"unknown engine {engine!r}; choose one of: {', '.join(ENGINES)}")
    return name


def _validated_marker(marker: str) -> str:
    marker = str(marker)
    if not _MARKER_RE.fullmatch(marker):
        raise ValueError("marker must be 4-40 ASCII letters, digits, underscores, or hyphens")
    return marker


def probe_catalog(engine: str | None = None, *, marker: str = DEFAULT_MARKER) -> tuple[Probe, ...]:
    """Return a stable tuple of inert probes, optionally filtered by engine.

    The caller must retain the marker and pass it to :func:`detect`; changing a
    marker prevents unrelated page text from satisfying an exact result.
    """

    marker = _validated_marker(marker)
    selected = normalize_engine(engine) if engine is not None else None
    rows: list[Probe] = []
    for index, spec in enumerate(_PROBE_SPECS, 1):
        if selected is not None and selected not in spec.engines:
            continue
        prefix = f"{marker}_{index:02d}_A"
        suffix = f"{marker}_{index:02d}_Z"
        expected = tuple(
            ExpectedRender(result_engine, prefix + body + suffix)
            for result_engine, body in spec.results
        )
        probe = Probe(
            probe_id=spec.probe_id,
            engines=spec.engines,
            payload=spec.line_prefix + prefix + spec.expression + suffix,
            expected=expected,
            primitive=spec.primitive,
            note=spec.note,
        )
        # This invariant is the core reflection guard.
        if any(item.rendered in probe.payload for item in probe.expected):
            raise AssertionError(f"probe {probe.probe_id} contains its rendered proof")
        rows.append(probe)
    return tuple(rows)


def encode_for_context(payload: str, context: str) -> str:
    """Encode a probe for one transport/template context without evaluating it."""

    if not isinstance(payload, str):
        raise TypeError("payload must be text")
    value = payload
    if len(value) > MAX_CONTEXT_PAYLOAD_CHARS:
        raise ValueError(f"payload exceeds {MAX_CONTEXT_PAYLOAD_CHARS} characters")
    if "\x00" in value:
        raise ValueError("payload must not contain NUL")
    name = str(context).strip().lower()
    if name not in CONTEXTS:
        raise ValueError(f"unknown context {context!r}; choose one of: {', '.join(CONTEXTS)}")
    if name == "raw":
        return value
    if name == "html_text":
        return html.escape(value, quote=False)
    if name == "html_attr_double":
        return html.escape(value, quote=False).replace('"', "&quot;")
    if name == "html_attr_single":
        return html.escape(value, quote=False).replace("'", "&#x27;")
    if name == "json_string":
        return json.dumps(value, ensure_ascii=True)[1:-1]
    if name == "url_component":
        return quote(value, safe="")
    escaped = value.replace("\\", "\\\\").replace("\r", "\\r").replace("\n", "\\n")
    if name == "template_single_quote":
        return escaped.replace("'", "\\'")
    return escaped.replace('"', '\\"')


def _canonical_contexts(contexts: Iterable[str] | None) -> tuple[str, ...]:
    if contexts is None:
        return CONTEXTS
    if isinstance(contexts, str):
        contexts = (contexts,)
    requested = {str(item).strip().lower() for item in contexts}
    unknown = sorted(requested.difference(CONTEXTS))
    if unknown:
        raise ValueError(f"unknown context(s): {', '.join(unknown)}")
    if not requested:
        raise ValueError("at least one context is required")
    return tuple(name for name in CONTEXTS if name in requested)


def build_payloads(
    engine: str,
    *,
    contexts: Iterable[str] | None = None,
    marker: str = DEFAULT_MARKER,
) -> tuple[PayloadVariant, ...]:
    """Build a deterministic context matrix of benign payload strings."""

    canonical = normalize_engine(engine)
    chosen_contexts = _canonical_contexts(contexts)
    variants: list[PayloadVariant] = []
    for probe in probe_catalog(canonical, marker=marker):
        expected = next(item.rendered for item in probe.expected if item.engine == canonical)
        for context in chosen_contexts:
            variants.append(
                PayloadVariant(
                    engine=canonical,
                    probe_id=probe.probe_id,
                    context=context,
                    payload=encode_for_context(probe.payload, context),
                    raw_payload=probe.payload,
                    expected_render=expected,
                    primitive=probe.primitive,
                    note=probe.note,
                )
            )
    return tuple(variants)


def _as_text(value: object, *, label: str) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        raw = value
        if len(raw) > MAX_SAVED_BYTES:
            raise ValueError(f"{label} exceeds {MAX_SAVED_BYTES} bytes")
        return raw.decode("utf-8", "replace")
    if isinstance(value, bytearray):
        return _as_text(bytes(value), label=label)
    if not isinstance(value, str):
        raise TypeError(f"{label} must be str, bytes, bytearray, or None")
    if len(value.encode("utf-8", "replace")) > MAX_SAVED_BYTES:
        raise ValueError(f"{label} exceeds {MAX_SAVED_BYTES} bytes")
    return value


def _text_views(value: object) -> tuple[tuple[str, str], ...]:
    """Expose one-pass encodings commonly present in saved HTTP material."""

    raw = _as_text(value, label="saved_response")
    candidates = (
        ("raw", raw),
        ("html-unescaped", html.unescape(raw)),
        ("url-decoded", unquote(raw)),
    )
    seen: set[str] = set()
    rows: list[tuple[str, str]] = []
    for label, text in candidates:
        if text not in seen:
            seen.add(text)
            rows.append((label, text))
    return tuple(rows)


def detect(
    saved_response: object,
    *,
    saved_source: object = "",
    marker: str = DEFAULT_MARKER,
) -> tuple[Detection, ...]:
    """Rank SSTI engines from supplied saved response/source evidence.

    No parser, renderer, or deserializer is invoked.  A wrapped evaluated
    marker scores 100, an explicit engine-named error scores 50, and a passive
    source signature scores 20.  Results are stable by score then ``ENGINES``.
    """

    response_views = _text_views(saved_response)
    response_text = response_views[0][1]
    source_text = _as_text(saved_source, label="saved_source")
    records: dict[str, dict[str, object]] = {}

    def add(engine: str, points: int, evidence: str, probe_id: str | None = None) -> None:
        row = records.setdefault(engine, {"score": 0, "evidence": [], "probes": []})
        row["score"] = int(row["score"]) + points
        evidence_rows = row["evidence"]
        probe_rows = row["probes"]
        assert isinstance(evidence_rows, list) and isinstance(probe_rows, list)
        if evidence not in evidence_rows:
            evidence_rows.append(evidence)
        if probe_id is not None and probe_id not in probe_rows:
            probe_rows.append(probe_id)

    for probe in probe_catalog(marker=marker):
        for expected in probe.expected:
            matched_view = next(
                (label for label, text in response_views if expected.rendered in text),
                None,
            )
            if matched_view is not None:
                add(
                    expected.engine,
                    100,
                    f"{probe.probe_id} produced its exact wrapped result ({matched_view})",
                    probe.probe_id,
                )

    for engine in ENGINES:
        for pattern in _ERROR_HINTS[engine]:
            match = pattern.search(response_text)
            if match:
                excerpt = " ".join(match.group(0).split())[:120]
                add(engine, 50, f"engine-named error signature: {excerpt!r}")
                break
        if source_text:
            for pattern in _SOURCE_HINTS[engine]:
                match = pattern.search(source_text)
                if match:
                    excerpt = " ".join(match.group(0).split())[:120]
                    add(engine, 20, f"passive source signature: {excerpt!r}")
                    break

    ranked: list[Detection] = []
    for engine, row in records.items():
        score = int(row["score"])
        confidence = "high" if row["probes"] else ("medium" if score >= 50 else "low")
        ranked.append(
            Detection(
                engine=engine,
                score=score,
                confidence=confidence,
                evidence=tuple(row["evidence"]),  # type: ignore[arg-type]
                probe_ids=tuple(row["probes"]),  # type: ignore[arg-type]
            )
        )
    ranked.sort(key=lambda item: (-item.score, ENGINES.index(item.engine)))
    return tuple(ranked)


def analyze(
    saved_response: object,
    *,
    saved_source: object = "",
    marker: str = DEFAULT_MARKER,
) -> dict[str, object]:
    """Return a JSON-safe offline report for routing and human review."""

    detections = detect(saved_response, saved_source=saved_source, marker=marker)
    confirmed_engines = [row.engine for row in detections if row.confidence == "high"]
    if detections:
        best_score = detections[0].score
        top_score_engines = [row.engine for row in detections if row.score == best_score]
    else:
        top_score_engines = []
    return {
        "offline": True,
        "executed": False,
        "deserialized": False,
        "marker": _validated_marker(marker),
        "detections": [row.as_dict() for row in detections],
        "confirmed_engines": confirmed_engines,
        "top_score_engines": top_score_engines,
        "ambiguous": len(confirmed_engines) > 1 or (
            not confirmed_engines and len(top_score_engines) > 1
        ),
        "covered_engines": list(ENGINES),
        "safety": "inert constant probes only; no network, rendering, file read, or command primitive",
    }


def _read_saved(path: str | None) -> bytes:
    if path is None:
        return b""
    saved_path = Path(path)
    if not saved_path.is_file():
        raise ValueError(f"saved input is not a regular file: {saved_path}")
    size = saved_path.stat().st_size
    if size > MAX_SAVED_BYTES:
        raise ValueError(f"saved input exceeds {MAX_SAVED_BYTES} bytes: {saved_path}")
    return saved_path.read_bytes()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    catalog = sub.add_parser("catalog", help="print inert payload strings")
    catalog.add_argument("--engine", choices=ENGINES)
    catalog.add_argument("--context", action="append", choices=CONTEXTS)
    catalog.add_argument("--marker", default=DEFAULT_MARKER)
    catalog.add_argument("--json", action="store_true")

    detector = sub.add_parser("detect", help="inspect already-saved text")
    detector.add_argument("--response", default="")
    detector.add_argument("--response-file")
    detector.add_argument("--source-file")
    detector.add_argument("--marker", default=DEFAULT_MARKER)
    detector.add_argument("--json", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "catalog":
        contexts = args.context or ["raw"]
        engines = (args.engine,) if args.engine else ENGINES
        rows = [
            row.as_dict()
            for engine in engines
            for row in build_payloads(engine, contexts=contexts, marker=args.marker)
        ]
        if args.json:
            print(json.dumps({"offline": True, "payloads": rows}, indent=2, sort_keys=True))
        else:
            for row in rows:
                print(f"{row['engine']:10} {row['context']:22} {row['payload']}")
        return 0

    if args.response and args.response_file:
        raise SystemExit("choose --response or --response-file, not both")
    response: object = _read_saved(args.response_file) if args.response_file else args.response
    report = analyze(response, saved_source=_read_saved(args.source_file), marker=args.marker)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        for row in report["detections"]:
            print(f"{row['engine']:10} score={row['score']:3} confidence={row['confidence']}")
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through main()
    raise SystemExit(main())
