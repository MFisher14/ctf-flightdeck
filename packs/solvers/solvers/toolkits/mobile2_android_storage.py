#!/usr/bin/env python3
"""Bounded Android SharedPreferences and Preferences DataStore forensics.

This engine fills two storage-specific gaps without duplicating the repository's
generic wire decoder:

* strict AOSP SharedPreferences XML with ordered duplicate evidence and Android's
  effective last-value-wins state, plus ``.bak`` recovery precedence;
* the exact published AndroidX Preferences DataStore protobuf schema, including
  all current value alternatives, duplicate map entries, oneof conflicts, and
  unknown fields.

Unknown/custom Proto DataStore payloads are deliberately not guessed.  Their
artifact role report directs the caller to the existing ``wire_decode.py`` engine
for schema-less facts.  No app code, serializer, XML entity, or network service is
loaded or executed.
"""
from __future__ import annotations

import argparse
import json
import math
import re
import struct
import sys
import xml.etree.ElementTree as ET
from pathlib import Path, PurePosixPath
from typing import Any

import wire_decode


class Mobile2AndroidStorageError(ValueError):
    """Supplied Android storage is malformed, unsupported, or over a bound."""


MAX_INPUT = 16 << 20
MAX_ENTRIES = 100_000
MAX_TEXT = 1 << 20
MAX_PATH = 16_384
MAX_NUMERIC_TEXT = 256

_FORBIDDEN_XML = re.compile(r"<!\s*(?:DOCTYPE|ENTITY)\b", re.IGNORECASE)
_INTEGER = re.compile(r"[+-]?[0-9]+\Z")
_DECIMAL_FLOAT = re.compile(
    r"[+-]?(?:(?:[0-9]+(?:\.[0-9]*)?)|(?:\.[0-9]+))(?:[eE][+-]?[0-9]+)?[fFdD]?\Z"
)


def _as_bytes(data: bytes | bytearray, label: str) -> bytes:
    if not isinstance(data, (bytes, bytearray)):
        raise Mobile2AndroidStorageError(f"{label} must be bytes")
    raw = bytes(data)
    if len(raw) > MAX_INPUT:
        raise Mobile2AndroidStorageError(f"{label} exceeds the {MAX_INPUT}-byte cap")
    return raw


def _text_only(node: ET.Element, *, allow_text: bool) -> str:
    if list(node):
        raise Mobile2AndroidStorageError(f"<{node.tag}> contains an unexpected child element")
    text = node.text or ""
    if len(text.encode("utf-8")) > MAX_TEXT:
        raise Mobile2AndroidStorageError(f"<{node.tag}> text exceeds the cap")
    if not allow_text and text.strip():
        raise Mobile2AndroidStorageError(f"<{node.tag}> contains unexpected text")
    return text


def _attributes(node: ET.Element, expected: set[str]) -> None:
    names = set(node.attrib)
    if names != expected:
        missing = sorted(expected - names)
        extra = sorted(names - expected)
        detail = []
        if missing:
            detail.append("missing " + ", ".join(missing))
        if extra:
            detail.append("unexpected " + ", ".join(extra))
        raise Mobile2AndroidStorageError(f"<{node.tag}> attributes are invalid ({'; '.join(detail)})")


def _number(raw: str, bits: int, kind: str) -> int:
    if len(raw) > MAX_NUMERIC_TEXT:
        raise Mobile2AndroidStorageError(f"{kind} value text exceeds the cap")
    if not _INTEGER.fullmatch(raw):
        raise Mobile2AndroidStorageError(f"invalid {kind} value")
    value = int(raw, 10)
    minimum, maximum = -(1 << (bits - 1)), (1 << (bits - 1)) - 1
    if value < minimum or value > maximum:
        raise Mobile2AndroidStorageError(f"{kind} value is outside signed {bits}-bit range")
    return value


def _float(raw: str) -> float | dict[str, str]:
    if len(raw) > MAX_NUMERIC_TEXT:
        raise Mobile2AndroidStorageError("float value text exceeds the cap")
    if raw in {"NaN", "Infinity", "-Infinity"}:
        # Preserve the exact spelling without emitting non-standard JSON numbers.
        return {"non_finite": raw}
    candidate = raw[:-1] if raw[-1:] in "fFdD" else raw
    if not _DECIMAL_FLOAT.fullmatch(raw):
        raise Mobile2AndroidStorageError("invalid float value")
    value = float(candidate)
    if not math.isfinite(value):
        return {"non_finite": "Infinity" if value > 0 else "-Infinity"}
    try:
        # SharedPreferences stores a Java Float, not a double.  Preserve the
        # actual value Android materializes instead of Python's decimal double.
        value = struct.unpack("<f", struct.pack("<f", value))[0]
    except (OverflowError, struct.error) as exc:
        return {"non_finite": "Infinity" if value > 0 else "-Infinity"}
    return value


def _json_float(value: float) -> float | dict[str, str]:
    """Keep CLI output strict JSON while preserving protobuf IEEE specials."""
    if math.isnan(value):
        return {"non_finite": "NaN"}
    if math.isinf(value):
        return {"non_finite": "Infinity" if value > 0 else "-Infinity"}
    return value


def _preference_entry(node: ET.Element, index: int, source: str) -> tuple[dict[str, Any], Any]:
    if not isinstance(node.tag, str):
        raise Mobile2AndroidStorageError("shared-preference XML contains a non-element node")
    tag = node.tag
    if tag == "string":
        _attributes(node, {"name"})
        value: Any = _text_only(node, allow_text=True)
        effective = value
    elif tag in {"int", "long"}:
        _attributes(node, {"name", "value"})
        _text_only(node, allow_text=False)
        value = _number(node.attrib["value"], 32 if tag == "int" else 64, tag)
        effective = value
    elif tag == "float":
        _attributes(node, {"name", "value"})
        _text_only(node, allow_text=False)
        value = _float(node.attrib["value"])
        effective = value
    elif tag == "boolean":
        _attributes(node, {"name", "value"})
        _text_only(node, allow_text=False)
        raw = node.attrib["value"].lower()
        if raw not in {"true", "false"}:
            raise Mobile2AndroidStorageError("invalid boolean value")
        value = raw == "true"
        effective = value
    elif tag == "set":
        _attributes(node, {"name"})
        if (node.text or "").strip():
            raise Mobile2AndroidStorageError("<set> contains unexpected text")
        strings = []
        for child in list(node):
            if not isinstance(child.tag, str) or child.tag != "string":
                raise Mobile2AndroidStorageError("<set> contains a non-string member")
            _attributes(child, set())
            strings.append(_text_only(child, allow_text=True))
            if child.tail and child.tail.strip():
                raise Mobile2AndroidStorageError("<set> contains unexpected tail text")
        value = strings
        # Android materializes a Set<String>; retain raw duplicates above while
        # exposing its effective de-duplicated value here.
        effective = list(dict.fromkeys(strings))
    else:
        raise Mobile2AndroidStorageError(f"unsupported SharedPreferences tag <{tag}>")
    name = node.attrib.get("name")
    if name is None:
        raise Mobile2AndroidStorageError(f"<{tag}> is missing its name")
    if len(name.encode("utf-8")) > MAX_TEXT:
        raise Mobile2AndroidStorageError("shared-preference key exceeds the cap")
    if node.tail and node.tail.strip():
        raise Mobile2AndroidStorageError(f"<{tag}> contains unexpected tail text")
    return ({"index": index, "source": source, "name": name, "type": tag, "value": value}, effective)


def _parse_shared_preferences(data: bytes | bytearray, source: str) -> dict[str, Any]:
    raw = _as_bytes(data, "shared-preference XML")
    if not isinstance(source, str) or not source or len(source) > 128:
        raise Mobile2AndroidStorageError("source label is invalid")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise Mobile2AndroidStorageError("shared-preference XML is not UTF-8") from exc
    if _FORBIDDEN_XML.search(text):
        raise Mobile2AndroidStorageError("DTD/ENTITY declarations are forbidden")
    try:
        root = ET.fromstring(text)
    except (ET.ParseError, LookupError, UnicodeError, RecursionError) as exc:
        raise Mobile2AndroidStorageError("invalid shared-preference XML") from exc
    if root.tag != "map" or root.attrib:
        raise Mobile2AndroidStorageError("shared-preference root must be an attribute-free <map>")
    if (root.text or "").strip():
        raise Mobile2AndroidStorageError("<map> contains unexpected text")
    children = list(root)
    if len(children) > MAX_ENTRIES:
        raise Mobile2AndroidStorageError("shared-preference entry count exceeds the cap")
    entries, effective, positions = [], {}, {}
    for index, node in enumerate(children):
        entry, effective_value = _preference_entry(node, index, source)
        entries.append(entry)
        positions.setdefault(entry["name"], []).append(index)
        effective[entry["name"]] = effective_value
    duplicates = [
        {"name": name, "entry_indices": indices, "effective_entry_index": indices[-1]}
        for name, indices in positions.items() if len(indices) > 1
    ]
    return {
        "format": "android-shared-preferences",
        "source": source,
        "entry_count": len(entries),
        "entries": entries,
        "duplicates": duplicates,
        "effective": effective,
        "effective_rule": "last duplicate key wins",
    }


def parse_shared_preferences(data: bytes | bytearray, *, source: str = "main") -> dict[str, Any]:
    """Parse one strict AOSP SharedPreferences XML document.

    Every public malformed-input failure is normalized to
    :class:`Mobile2AndroidStorageError`.
    """
    try:
        return _parse_shared_preferences(data, source)
    except Mobile2AndroidStorageError:
        raise
    except Exception as exc:
        raise Mobile2AndroidStorageError("could not parse shared-preference XML") from exc


def analyze_shared_preferences(
    main: bytes | bytearray | None,
    backup: bytes | bytearray | None = None,
) -> dict[str, Any]:
    """Report main/``.bak`` candidates and AOSP's next-load precedence."""
    try:
        if main is None and backup is None:
            raise Mobile2AndroidStorageError("main or backup SharedPreferences bytes are required")
        main_report = parse_shared_preferences(main, source="main") if main is not None else None
        backup_report = parse_shared_preferences(backup, source="backup") if backup is not None else None
        authoritative = backup_report if backup_report is not None else main_report
        return {
            "format": "android-shared-preferences-pair",
            "main": main_report,
            "backup": backup_report,
            "authoritative_source": "backup" if backup_report is not None else "main",
            "effective": authoritative["effective"] if authoritative is not None else {},
            "aosp_recovery_rule": (
                "when .bak exists, Android deletes the main file and renames .bak to main before parsing"
            ),
            "main_discarded_on_next_load": backup_report is not None and main_report is not None,
        }
    except Mobile2AndroidStorageError:
        raise
    except Exception as exc:
        raise Mobile2AndroidStorageError("could not analyze SharedPreferences candidates") from exc


def _wire(raw: bytes, context: str) -> list[dict[str, Any]]:
    try:
        value = wire_decode.decode_protobuf(raw)
    except Exception as exc:
        raise Mobile2AndroidStorageError(f"malformed protobuf in {context}") from exc
    if not isinstance(value, list) or len(value) > MAX_ENTRIES:
        raise Mobile2AndroidStorageError(f"protobuf field count exceeds the cap in {context}")
    return value


def _length_bytes(field: dict[str, Any], context: str) -> bytes:
    value = field.get("value")
    if field.get("wire_type") != 2 or not isinstance(value, dict) or not isinstance(value.get("hex"), str):
        raise Mobile2AndroidStorageError(f"{context} is not length-delimited")
    try:
        raw = bytes.fromhex(value["hex"])
    except (ValueError, TypeError) as exc:
        raise Mobile2AndroidStorageError(f"{context} has an invalid raw payload") from exc
    if len(raw) > MAX_INPUT:
        raise Mobile2AndroidStorageError(f"{context} exceeds the payload cap")
    return raw


def _utf8_field(field: dict[str, Any], context: str) -> str:
    try:
        return _length_bytes(field, context).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise Mobile2AndroidStorageError(f"{context} is not valid UTF-8") from exc


def _signed(value: int, bits: int) -> int:
    value &= (1 << bits) - 1
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def _string_set(raw: bytes) -> dict[str, Any]:
    fields = _wire(raw, "StringSet")
    strings, unknown = [], []
    for position, field in enumerate(fields):
        if field.get("field") == 1 and field.get("wire_type") == 2:
            strings.append(_utf8_field(field, "StringSet.strings"))
        else:
            unknown.append({"position": position, **field})
    return {
        "strings": strings,
        "effective_strings": list(dict.fromkeys(strings)),
        "unknown_fields": unknown,
    }


def _value_message(raw: bytes) -> dict[str, Any]:
    fields = _wire(raw, "Preferences Value")
    members, unknown = [], []
    names = {
        1: ("boolean", 0), 2: ("float", 5), 3: ("integer", 0), 4: ("long", 0),
        5: ("string", 2), 6: ("string_set", 2), 7: ("double", 1), 8: ("bytes", 2),
    }
    for position, field in enumerate(fields):
        descriptor = names.get(field.get("field"))
        if descriptor is None or field.get("wire_type") != descriptor[1]:
            unknown.append({"position": position, **field})
            continue
        name = descriptor[0]
        wire_value = field.get("value")
        if name == "boolean":
            value: Any = bool(wire_value)
        elif name == "float":
            value = _json_float(struct.unpack("<f", struct.pack("<I", int(wire_value)))[0])
        elif name == "integer":
            value = _signed(int(wire_value), 32)
        elif name == "long":
            value = _signed(int(wire_value), 64)
        elif name == "string":
            value = _utf8_field(field, "Value.string")
        elif name == "string_set":
            value = _string_set(_length_bytes(field, "Value.string_set"))
        elif name == "double":
            value = _json_float(struct.unpack("<d", struct.pack("<Q", int(wire_value)))[0])
        else:
            payload = _length_bytes(field, "Value.bytes")
            value = {"length": len(payload), "hex": payload.hex()}
        members.append({"position": position, "field": field["field"], "type": name, "value": value})
    effective = members[-1] if members else None
    return {
        "members": members,
        "oneof_conflict": len(members) > 1,
        "effective": effective,
        "unknown_fields": unknown,
        "valid_for_androidx_serializer": effective is not None,
    }


def _map_entry(raw: bytes, index: int) -> dict[str, Any]:
    fields = _wire(raw, f"PreferenceMap entry {index}")
    keys, values, value_payloads, unknown = [], [], [], []
    for position, field in enumerate(fields):
        if field.get("field") == 1 and field.get("wire_type") == 2:
            keys.append({"position": position, "value": _utf8_field(field, "map key")})
        elif field.get("field") == 2 and field.get("wire_type") == 2:
            payload = _length_bytes(field, "map value")
            value_payloads.append(payload)
            values.append({"position": position, "value": _value_message(payload)})
        else:
            unknown.append({"position": position, **field})
    key = keys[-1]["value"] if keys else ""  # protobuf map-entry default
    # MapEntry.value is a singular *message* field.  Protobuf merges repeated
    # occurrences rather than replacing the whole submessage; parsing their
    # payloads concatenated in wire order exactly models that merge.
    value = _value_message(b"".join(value_payloads)) if values else _value_message(b"")
    return {
        "index": index,
        "key_occurrences": keys,
        "value_occurrences": values,
        "key": key,
        "value": value,
        "duplicate_key_fields": len(keys) > 1,
        "duplicate_value_fields": len(values) > 1,
        "unknown_fields": unknown,
    }


def _decode_preferences_datastore(data: bytes | bytearray) -> dict[str, Any]:
    raw = _as_bytes(data, "Preferences DataStore")
    fields = _wire(raw, "PreferenceMap")
    entries, unknown = [], []
    for position, field in enumerate(fields):
        if field.get("field") == 1 and field.get("wire_type") == 2:
            if len(entries) >= MAX_ENTRIES:
                raise Mobile2AndroidStorageError("Preferences DataStore entry count exceeds the cap")
            entries.append(_map_entry(_length_bytes(field, "PreferenceMap.preferences"), len(entries)))
        else:
            unknown.append({"position": position, **field})
    positions: dict[str, list[int]] = {}
    effective_entries: dict[str, dict[str, Any]] = {}
    for entry in entries:
        positions.setdefault(entry["key"], []).append(entry["index"])
        effective_entries[entry["key"]] = entry
    effective = {}
    for key, entry in effective_entries.items():
        member = entry["value"]["effective"]
        if member is not None:
            effective[key] = {"type": member["type"], "value": member["value"]}
    duplicates = [
        {"key": key, "entry_indices": indices, "effective_entry_index": indices[-1]}
        for key, indices in positions.items() if len(indices) > 1
    ]
    serializer_valid = all(entry["value"]["valid_for_androidx_serializer"]
                           for entry in effective_entries.values())
    return {
        "format": "androidx-preferences-datastore",
        "schema": "androidx.datastore.preferences.PreferenceMap proto2",
        "entry_count": len(entries),
        "entries": entries,
        "duplicate_map_keys": duplicates,
        "unknown_outer_fields": unknown,
        "effective": effective,
        "effective_rule": "protobuf map and Value oneof use the last encoded occurrence",
        "valid_for_androidx_serializer": serializer_valid,
    }


def decode_preferences_datastore(data: bytes | bytearray) -> dict[str, Any]:
    """Decode the exact published AndroidX Preferences DataStore schema."""
    try:
        return _decode_preferences_datastore(data)
    except Mobile2AndroidStorageError:
        raise
    except Exception as exc:
        raise Mobile2AndroidStorageError("could not decode Preferences DataStore") from exc


def classify_datastore_path(path: str | Path) -> dict[str, Any]:
    """Classify a DataStore payload or coordination sidecar without reading it."""
    try:
        if not isinstance(path, (str, Path)):
            raise Mobile2AndroidStorageError("DataStore path must be a string or Path")
        text = str(path).replace("\\", "/")
        if not text or len(text) > MAX_PATH or "\x00" in text:
            raise Mobile2AndroidStorageError("DataStore path is invalid")
        name = PurePosixPath(text).name
        if not name:
            raise Mobile2AndroidStorageError("DataStore path has no file name")
        lower = name.lower()
        role, payload, schema = "candidate", True, "caller-supplied"
        base = name
        if lower.endswith(".lock"):
            role, payload, schema, base = "multiprocess-lock", False, "coordination", name[:-5]
        elif lower.endswith(".version"):
            role, payload, schema, base = "multiprocess-version", False, "coordination", name[:-8]
        elif lower.endswith(".tmp"):
            role, payload, base = "atomic-write-temporary", True, name[:-4]
            schema = "androidx-preferences" if base.lower().endswith(".preferences_pb") else "caller-supplied"
        elif lower.endswith(".preferences_pb"):
            role, schema = "preferences-datastore", "androidx-preferences"
        elif "/datastore/" in "/" + text.lower().lstrip("/"):
            role = "custom-datastore-candidate"
        return {
            "path": text,
            "name": name,
            "base_payload_name": base,
            "role": role,
            "payload": payload,
            "schema": schema,
            "schema_required": payload and schema == "caller-supplied",
            "unknown_schema_plan": ({
                "engine": "wire_decode.py",
                "cli": "./.venv/bin/python solvers/toolkits/wire_decode.py <file> --json",
                "warning": "schema-less output gives field/wire facts only; do not invent semantic names",
            } if payload and schema == "caller-supplied" else None),
        }
    except Mobile2AndroidStorageError:
        raise
    except Exception as exc:
        raise Mobile2AndroidStorageError("could not classify DataStore path") from exc


def _read(path: str | Path) -> bytes:
    try:
        with Path(path).open("rb") as handle:
            data = handle.read(MAX_INPUT + 1)
    except OSError as exc:
        raise Mobile2AndroidStorageError(f"could not read {path}") from exc
    if len(data) > MAX_INPUT:
        raise Mobile2AndroidStorageError(f"{path} exceeds the input cap")
    return data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    prefs = sub.add_parser("shared-prefs", help="parse main XML and optional .bak with AOSP precedence")
    prefs.add_argument("main", nargs="?", help="main SharedPreferences XML")
    prefs.add_argument("--backup", help="captured .xml.bak candidate")
    store = sub.add_parser("preferences-datastore", help="decode AndroidX *.preferences_pb")
    store.add_argument("input")
    role = sub.add_parser("classify", help="classify DataStore payload/tmp/lock/version paths")
    role.add_argument("paths", nargs="+")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        if args.operation == "shared-prefs":
            if args.main is None and args.backup is None:
                raise Mobile2AndroidStorageError("supply a main XML or --backup")
            report = analyze_shared_preferences(
                _read(args.main) if args.main is not None else None,
                _read(args.backup) if args.backup is not None else None,
            )
        elif args.operation == "preferences-datastore":
            report = decode_preferences_datastore(_read(args.input))
        else:
            report = {"artifacts": [classify_datastore_path(path) for path in args.paths]}
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    except Mobile2AndroidStorageError as exc:
        print(f"{parser.prog}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
