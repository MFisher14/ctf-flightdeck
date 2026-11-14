#!/usr/bin/env python3
"""Offline Cursor-on-Target, TAK Protocol v1, and TAK Data Package reader.

The module accepts only caller-supplied bytes.  It never opens a socket, follows
``fileshare`` URLs, extracts a ZIP member, or executes package content.  Its
layouts follow the public TAK Product Center ``atak-civ`` CoT XSD, TAK v1
``.proto`` files, and MissionPackageManifest v2 implementation.

Public byte parsers raise :class:`SecTdlCotError` for every malformed,
unsupported, ambiguous, or excessive input; implementation exceptions are not
part of the API.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from functools import wraps
import hashlib
from io import BytesIO
import json
import math
from pathlib import Path
import re
import stat
import struct
import sys
from typing import Any, Callable, TypeVar
import xml.etree.ElementTree as ET
import zipfile


# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

class SecTdlCotError(ValueError):
    """Malformed, unsupported, ambiguous, or excessive supplied TAK data."""


MAX_INPUT = 32 * 1024 * 1024
MAX_XML_BYTES = 2 * 1024 * 1024
MAX_PROTO_BYTES = 4 * 1024 * 1024
MAX_STREAM_FRAMES = 4096
MAX_PROTO_FIELDS = 20_000
MAX_XML_NODES = 20_000
MAX_XML_DEPTH = 64
MAX_XML_ATTRIBUTES = 40_000
MAX_XML_TEXT = 4 * 1024 * 1024
MAX_ZIP_ENTRIES = 4096
MAX_ZIP_ENTRY = 16 * 1024 * 1024
MAX_ZIP_TOTAL = 128 * 1024 * 1024
MAX_ZIP_RATIO = 250.0
MAX_PACKAGE_COT = 512
MAX_PACKAGE_COT_BYTES = 8 * 1024 * 1024
MAX_OPAQUE_CAPTURE = 4096
MAX_PROTO_FIELD_NUMBER = (1 << 29) - 1

TAK_MAGIC = 0xBF
SUPPORTED_TAK_VERSION = 1

_TYPE_PATTERN = re.compile(r"\w+(?:-\w+)*(?:;[^;]*)?\Z", re.UNICODE)
_HOW_PATTERN = re.compile(r"\w(?:-\w+)*\Z", re.UNICODE)
_TIME_PATTERN = re.compile(
    r"(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})"
    r"T(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})"
    r"(?:\.(?P<fraction>\d+))?(?P<zone>Z|[+-]\d{2}:\d{2})?\Z"
)
_DECIMAL_PATTERN = re.compile(r"[+-]?(?:\d+(?:\.\d*)?|\.\d+)\Z")
_QOS_PATTERN = re.compile(r"\d-\w-\w\Z", re.UNICODE)
_FLAG_PATTERN = flagfmt.TEXT
_FORBIDDEN_XML = re.compile(br"<!\s*(?:DOCTYPE|ENTITY)", re.IGNORECASE)

_TYPE_ROOTS = {
    "a": "atoms",
    "b": "bits",
    "t": "tasking",
    "r": "reservation_restriction_or_references",
    "c": "capability",
}
_AFFILIATIONS = {
    "p": "pending",
    "u": "unknown",
    "a": "assumed_friend",
    "f": "friend",
    "n": "neutral",
    "s": "suspect",
    "h": "hostile",
    "j": "joker",
    "k": "faker",
    "o": "none_specified",
    "x": "other_legacy",
}
_BATTLE_DIMENSIONS = {
    "P": "space",
    "A": "air",
    "G": "ground",
    "S": "sea_surface",
    "U": "sea_subsurface",
    "F": "special_operations",
    "X": "other",
    "Z": "unknown",
}
_HOW_SECOND = {
    "h": {
        "e": "estimated",
        "c": "calculated",
        "t": "transcribed",
        "p": "cut_and_paste",
    },
    "m": {
        "i": "imagery_mensurated",
        "g": "gps",
        "m": "magnetic",
        "s": "simulated",
        "f": "fused",
        "c": "configured",
        "p": "predicted",
        "r": "relayed",
    },
}

_F = TypeVar("_F", bound=Callable[..., Any])


def _guard(function: _F) -> _F:
    @wraps(function)
    def wrapped(*args: Any, **kwargs: Any) -> Any:
        try:
            return function(*args, **kwargs)
        except SecTdlCotError:
            raise
        except Exception:
            raise SecTdlCotError("malformed or unsupported CoT/TAK evidence") from None

    return wrapped  # type: ignore[return-value]


def _bytes(data: object, limit: int, label: str, *, allow_empty: bool = False) -> bytes:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise SecTdlCotError(f"{label} must be bytes-like")
    try:
        size = data.nbytes if isinstance(data, memoryview) else len(data)
        if size == 0 and not allow_empty:
            raise SecTdlCotError(f"{label} is empty")
        if size > limit:
            raise SecTdlCotError(f"{label} exceeds size limit")
        return bytes(data)
    except SecTdlCotError:
        raise
    except Exception:
        raise SecTdlCotError(f"invalid {label} byte buffer") from None


def _local_name(tag: object) -> str:
    if not isinstance(tag, str):
        raise SecTdlCotError("XML contains an unsupported non-text tag")
    return tag.rsplit("}", 1)[-1]


def _xml_root(data: bytes, limit: int = MAX_XML_BYTES) -> ET.Element:
    if len(data) > limit:
        raise SecTdlCotError("XML exceeds size limit")
    # Removing NULs only for the declaration scan also catches UTF-16 encoded
    # DTD/entity tokens.  ElementTree receives the original bytes.
    declaration_view = data.replace(b"\x00", b"")
    if _FORBIDDEN_XML.search(declaration_view):
        raise SecTdlCotError("DTD/entity declarations are not accepted")
    try:
        root = ET.fromstring(data)
    except (ET.ParseError, UnicodeError, ValueError) as exc:
        raise SecTdlCotError("malformed XML") from exc
    nodes = attributes = text_size = 0
    stack: list[tuple[ET.Element, int]] = [(root, 1)]
    while stack:
        element, depth = stack.pop()
        nodes += 1
        if nodes > MAX_XML_NODES or depth > MAX_XML_DEPTH:
            raise SecTdlCotError("XML structure exceeds analysis limits")
        _local_name(element.tag)
        attributes += len(element.attrib)
        if attributes > MAX_XML_ATTRIBUTES:
            raise SecTdlCotError("XML attribute count exceeds limit")
        for key, value in element.attrib.items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise SecTdlCotError("XML attribute is not text")
            text_size += len(key) + len(value)
        if element.text:
            text_size += len(element.text)
        if element.tail:
            text_size += len(element.tail)
        if text_size > MAX_XML_TEXT:
            raise SecTdlCotError("XML expanded text exceeds limit")
        children = list(element)
        stack.extend((child, depth + 1) for child in reversed(children))
    return root


def _element_record(element: ET.Element) -> dict[str, Any]:
    record: dict[str, Any] = {
        "name": _local_name(element.tag),
        "attributes": dict(sorted(element.attrib.items())),
    }
    if element.tag.startswith("{"):
        record["namespace"] = element.tag[1:].split("}", 1)[0]
    if element.text and element.text.strip():
        record["text"] = element.text.strip()
    children = [_element_record(child) for child in list(element)]
    if children:
        record["children"] = children
    return record


def _tree_strings(root: ET.Element) -> list[str]:
    values: list[str] = []
    for element in root.iter():
        values.extend(element.attrib.values())
        if element.text:
            values.append(element.text)
        if element.tail:
            values.append(element.tail)
    return values


def _flags(values: list[str]) -> list[str]:
    found: set[str] = set()
    for value in values:
        found.update(_FLAG_PATTERN.findall(value))
    return sorted(found)


def _parse_time(value: str, name: str) -> tuple[str, datetime, Decimal, bool]:
    match = _TIME_PATTERN.fullmatch(value)
    if match is None:
        raise SecTdlCotError(f"event {name} is not an ISO-8601 CoT timestamp")
    # datetime offers useful calendar validation for the ordinary CoT range.
    fraction = match.group("fraction") or ""
    zone = match.group("zone")
    if zone and zone != "Z":
        zone_hour = int(zone[1:3])
        zone_minute = int(zone[4:6])
        if zone_hour > 14 or zone_minute > 59 or (zone_hour == 14 and zone_minute):
            raise SecTdlCotError(f"event {name} has an invalid ISO-8601 offset")
    normalized_fraction = (fraction[:6]).ljust(6, "0") if fraction else ""
    normalized = value
    if fraction:
        start = value.index(".")
        zone_start = start + 1 + len(fraction)
        normalized = value[:start] + "." + normalized_fraction + value[zone_start:]
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise SecTdlCotError(f"event {name} is not a valid calendar timestamp") from exc
    offset = parsed.utcoffset()
    offset_seconds = int(offset.total_seconds()) if offset is not None else 0
    day_seconds = (
        parsed.date().toordinal() * 86_400
        + parsed.hour * 3_600
        + parsed.minute * 60
        + parsed.second
        - offset_seconds
    )
    exact = Decimal(day_seconds)
    if fraction:
        exact += Decimal("0." + fraction)
    return value, parsed, exact, zone is not None


def _decimal(value: str, name: str) -> float:
    if len(value) > 256:
        raise SecTdlCotError(f"point {name} is excessive")
    if _DECIMAL_PATTERN.fullmatch(value) is None:
        raise SecTdlCotError(f"point {name} is not an XSD decimal")
    try:
        number = Decimal(value)
        result = float(number)
    except (InvalidOperation, OverflowError, ValueError) as exc:
        raise SecTdlCotError(f"point {name} is not decimal") from exc
    if not number.is_finite() or not math.isfinite(result):
        raise SecTdlCotError(f"point {name} must be finite")
    return result


def _decode_type(value: str) -> dict[str, Any]:
    if not _TYPE_PATTERN.fullmatch(value):
        raise SecTdlCotError("event type violates the CoT hierarchy grammar")
    hierarchy, separator, suffix = value.partition(";")
    tokens = hierarchy.split("-")
    decoded: dict[str, Any] = {
        "raw": value,
        "tokens": tokens,
        "root": _TYPE_ROOTS.get(tokens[0], "unregistered"),
    }
    if separator:
        decoded["trailing_filter_field"] = suffix
    if tokens[0] == "a":
        if len(tokens) > 1:
            decoded["affiliation"] = _AFFILIATIONS.get(tokens[1], "unregistered")
        if len(tokens) > 2:
            decoded["battle_dimension"] = _BATTLE_DIMENSIONS.get(
                tokens[2], "non_legacy_or_extension"
            )
        if len(tokens) > 3:
            decoded["function_or_extension"] = tokens[3:]
            decoded["legacy_2525_uppercase_prefix"] = [
                token for token in tokens[2:] if token.upper() == token
            ]
    return decoded


def _decode_how(value: str) -> dict[str, Any]:
    if not _HOW_PATTERN.fullmatch(value):
        raise SecTdlCotError("event how violates the CoT grammar")
    tokens = value.split("-")
    result: dict[str, Any] = {
        "raw": value,
        "tokens": tokens,
        "origin": {"h": "human", "m": "machine"}.get(tokens[0], "extension"),
    }
    if len(tokens) > 1:
        result["method"] = _HOW_SECOND.get(tokens[0], {}).get(
            tokens[1], "noncanonical_or_extension"
        )
    if len(tokens) > 2:
        result["extensions"] = tokens[2:]
    return result


def _parse_cot_root(root: ET.Element) -> dict[str, Any]:
    if root.tag != "event":
        raise SecTdlCotError("CoT XML root must be unnamespaced event")
    required = ("version", "type", "uid", "time", "start", "stale", "how")
    missing = [name for name in required if not root.attrib.get(name)]
    if missing:
        raise SecTdlCotError("event is missing required attributes: " + ", ".join(missing))
    if _DECIMAL_PATTERN.fullmatch(root.attrib["version"]) is None:
        raise SecTdlCotError("event version is not an XSD decimal")
    try:
        version = Decimal(root.attrib["version"])
    except InvalidOperation as exc:
        raise SecTdlCotError("event version is not decimal") from exc
    if not version.is_finite() or version < 2:
        raise SecTdlCotError("event version must be at least 2")

    time_raw, generated, _generated_exact, _time_zoned = _parse_time(
        root.attrib["time"], "time"
    )
    start_raw, start, start_exact, start_zoned = _parse_time(
        root.attrib["start"], "start"
    )
    stale_raw, stale, stale_exact, stale_zoned = _parse_time(
        root.attrib["stale"], "stale"
    )
    drop_track = None if start_zoned != stale_zoned else stale_exact < start_exact
    if root.attrib.get("qos") and _QOS_PATTERN.fullmatch(root.attrib["qos"]) is None:
        raise SecTdlCotError("event qos violates the published CoT grammar")
    event_children = list(root)
    # The published Event.xsd uses xs:all: point is required and detail is
    # optional, but their relative order is deliberately immaterial.
    children: dict[str, list[ET.Element]] = {}
    for child in event_children:
        name = _local_name(child.tag)
        if child.tag != name or name not in {"point", "detail"}:
            raise SecTdlCotError(f"unsupported event child {name}")
        children.setdefault(name, []).append(child)
    if len(children.get("point", [])) != 1 or len(children.get("detail", [])) > 1:
        raise SecTdlCotError("event requires one point and at most one detail")
    if root.text and root.text.strip():
        raise SecTdlCotError("event contains non-whitespace element text")
    if any(child.tail and child.tail.strip() for child in event_children):
        raise SecTdlCotError("event contains non-whitespace child tail text")

    point_element = children["point"][0]
    point_required = ("lat", "lon", "hae", "ce", "le")
    point_missing = [name for name in point_required if name not in point_element.attrib]
    if point_missing or list(point_element):
        raise SecTdlCotError("point is missing fields or contains child elements")
    if point_element.text and point_element.text.strip():
        raise SecTdlCotError("point contains forbidden text")
    point = {name: _decimal(point_element.attrib[name], name) for name in point_required}
    if not -90 <= point["lat"] <= 90 or not -180 <= point["lon"] <= 180:
        raise SecTdlCotError("point latitude/longitude is out of WGS-84 range")

    findings: list[dict[str, Any]] = []
    access = root.attrib.get("access")
    if not access:
        findings.append({
            "code": "legacy_missing_access",
            "severity": "warning",
            "detail": "MIL-STD-6090-era CoT requires access; legacy ATAK samples omit it",
        })
    if drop_track is None:
        findings.append({
            "code": "indeterminate_mixed_timezone_order",
            "severity": "warning",
            "detail": "start/stale mix timezone-qualified and timezone-absent values",
        })
    elif drop_track:
        findings.append({
            "code": "drop_track_time_reversal",
            "severity": "info",
            "detail": "stale precedes start, the documented CoT drop-track convention",
        })
    unknown_point = sorted(set(point_element.attrib) - set(point_required))
    if unknown_point:
        findings.append({"code": "point_extension_attributes", "names": unknown_point})
    defined_event = {
        "version", "type", "access", "caveat", "releasableTo", "releasableto",
        "qos", "opex", "uid", "time", "start", "stale", "how",
    }
    unknown_event = sorted(set(root.attrib) - defined_event)
    if unknown_event:
        findings.append({"code": "event_extension_attributes", "names": unknown_event})
    if "releasableto" in root.attrib and "releasableTo" not in root.attrib:
        findings.append({
            "code": "xsd_releasableto_spelling",
            "severity": "info",
            "detail": "public XSD spelling differs from CommonCommo camel-case releasableTo",
        })

    detail_elements: list[dict[str, Any]] = []
    typed: dict[str, list[dict[str, Any]]] = {}
    detail_attributes: dict[str, str] = {}
    detail = children.get("detail", [])
    if detail:
        detail_attributes = dict(sorted(detail[0].attrib.items()))
        if detail[0].text and detail[0].text.strip():
            raise SecTdlCotError("detail contains non-whitespace direct text")
        if any(child.tail and child.tail.strip() for child in list(detail[0])):
            raise SecTdlCotError("detail contains non-whitespace child tail text")
        for child in list(detail[0]):
            record = _element_record(child)
            detail_elements.append(record)
            name = record["name"]
            if "namespace" not in record and name in {
                "contact", "__group", "precisionlocation", "status", "takv",
                "track", "__milsym", "fileshare", "ackrequest", "ackresponse",
                "usericon",
            }:
                typed.setdefault(name, []).append(record)

    event_attributes = dict(sorted(root.attrib.items()))
    if "releasableTo" not in event_attributes and "releasableto" in event_attributes:
        event_attributes["releasableTo_normalized"] = event_attributes["releasableto"]
    strings = _tree_strings(root)
    return {
        "kind": "cursor-on-target-xml",
        "protocol": "cot",
        "version": str(version),
        "offline": True,
        "network_requests": 0,
        "event": {
            "attributes": event_attributes,
            "uid": root.attrib["uid"],
            "type": _decode_type(root.attrib["type"]),
            "how": _decode_how(root.attrib["how"]),
            "time": time_raw,
            "start": start_raw,
            "stale": stale_raw,
            "drop_track": drop_track,
            "generated_iso": generated.isoformat(),
        },
        "point": point,
        "detail": {
            "attributes": detail_attributes,
            "elements": detail_elements,
            "typed": typed,
        },
        "findings": findings,
        "flag_candidates": _flags(strings),
    }


@_guard
def parse_cot_xml(data: object) -> dict[str, Any]:
    """Parse one bounded CoT 2.x XML event from supplied bytes."""
    raw = _bytes(data, MAX_XML_BYTES, "CoT XML")
    return _parse_cot_root(_xml_root(raw))


def _read_varint(raw: bytes, offset: int, *, frame: bool = False) -> tuple[int, int]:
    start = offset
    value = 0
    for index in range(10):
        if offset >= len(raw):
            raise SecTdlCotError("truncated unsigned varint")
        byte = raw[offset]
        offset += 1
        if index == 9 and byte > 1:
            raise SecTdlCotError("unsigned varint exceeds 64 bits")
        value |= (byte & 0x7F) << (7 * index)
        if not byte & 0x80:
            if offset - start > 1 and value < (1 << (7 * (offset - start - 1))):
                raise SecTdlCotError("non-canonical unsigned varint")
            if frame and value > (1 << 63) - 1:
                raise SecTdlCotError("TAK framing varint exceeds protocol range")
            return value, offset
    raise SecTdlCotError("unterminated unsigned varint")


class _WireReader:
    def __init__(self, raw: bytes):
        self.raw = raw
        self.offset = 0
        self.count = 0

    def fields(self) -> list[dict[str, Any]]:
        output: list[dict[str, Any]] = []
        while self.offset < len(self.raw):
            self.count += 1
            if self.count > MAX_PROTO_FIELDS:
                raise SecTdlCotError("protobuf field count exceeds limit")
            start = self.offset
            key, self.offset = _read_varint(self.raw, self.offset)
            number, wire = key >> 3, key & 7
            if number == 0 or number > MAX_PROTO_FIELD_NUMBER or wire not in {0, 1, 2, 5}:
                raise SecTdlCotError("invalid protobuf field tag or wire type")
            if wire == 0:
                value, self.offset = _read_varint(self.raw, self.offset)
            elif wire == 1:
                value = self._take(8)
            elif wire == 2:
                length, self.offset = _read_varint(self.raw, self.offset)
                if length > MAX_PROTO_BYTES:
                    raise SecTdlCotError("protobuf field exceeds size limit")
                value = self._take(length)
            else:
                value = self._take(4)
            output.append({
                "number": number,
                "wire": wire,
                "value": value,
                "offset": start,
                "end": self.offset,
            })
        return output

    def _take(self, size: int) -> bytes:
        if size < 0 or size > len(self.raw) - self.offset:
            raise SecTdlCotError("truncated protobuf field")
        start = self.offset
        self.offset += size
        return self.raw[start:self.offset]


def _wire_fields(raw: bytes) -> list[dict[str, Any]]:
    return _WireReader(raw).fields()


def _by_number(fields: list[dict[str, Any]]) -> dict[int, list[dict[str, Any]]]:
    grouped: dict[int, list[dict[str, Any]]] = {}
    for field in fields:
        grouped.setdefault(field["number"], []).append(field)
    return grouped


def _wire_value(
    grouped: dict[int, list[dict[str, Any]]], number: int, wire: int, name: str
) -> Any | None:
    matches = grouped.get(number, [])
    if not matches:
        return None
    if any(field["wire"] != wire for field in matches):
        raise SecTdlCotError(f"protobuf {name} has the wrong wire type")
    return matches[-1]["value"]


def _wire_message_value(
    grouped: dict[int, list[dict[str, Any]]], number: int, name: str
) -> bytes | None:
    """Apply protobuf's merge rule for repeated occurrences of singular messages."""
    matches = grouped.get(number, [])
    if not matches:
        return None
    if any(field["wire"] != 2 or not isinstance(field["value"], bytes) for field in matches):
        raise SecTdlCotError(f"protobuf {name} has the wrong wire type")
    return b"".join(field["value"] for field in matches)


def _text(value: Any | None, name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, bytes):
        raise SecTdlCotError(f"protobuf {name} is not length-delimited")
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SecTdlCotError(f"protobuf {name} is not UTF-8") from exc


def _double(value: Any | None, name: str) -> float | None:
    if value is None:
        return None
    if not isinstance(value, bytes) or len(value) != 8:
        raise SecTdlCotError(f"protobuf {name} is not fixed64")
    result = struct.unpack("<d", value)[0]
    if not math.isfinite(result):
        raise SecTdlCotError(f"protobuf {name} is non-finite")
    return result


def _uint32(value: Any | None, name: str) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int) or value > 0xFFFFFFFF:
        raise SecTdlCotError(f"protobuf {name} exceeds uint32")
    return value


def _opaque_value(field: dict[str, Any]) -> dict[str, Any]:
    value = field["value"]
    output: dict[str, Any] = {
        "field": field["number"],
        "wire_type": field["wire"],
        "offset": field["offset"],
    }
    if isinstance(value, int):
        output["value"] = value
    else:
        capture = value[:MAX_OPAQUE_CAPTURE]
        output.update({
            "length": len(value),
            "hex": capture.hex(),
            "capture_truncated": len(value) > len(capture),
            "sha256": hashlib.sha256(value).hexdigest(),
        })
        if field["wire"] == 2:
            try:
                decoded = value.decode("utf-8")
                if decoded.isprintable() and len(decoded) <= MAX_OPAQUE_CAPTURE:
                    output["utf8"] = decoded
            except UnicodeDecodeError:
                pass
    return output


def _unknown(fields: list[dict[str, Any]], known: set[int]) -> list[dict[str, Any]]:
    return [_opaque_value(field) for field in fields if field["number"] not in known]


def _string_message(raw: bytes, names: dict[int, str], label: str) -> dict[str, Any]:
    fields = _wire_fields(raw)
    grouped = _by_number(fields)
    output: dict[str, Any] = {}
    for number, name in names.items():
        value = _text(_wire_value(grouped, number, 2, f"{label}.{name}"), f"{label}.{name}")
        if value is not None:
            output[name] = value
    output["unknown_fields"] = _unknown(fields, set(names))
    return output


def _parse_contact(raw: bytes) -> dict[str, Any]:
    return _string_message(raw, {1: "endpoint", 2: "callsign", 3: "altendpoints"}, "contact")


def _parse_status(raw: bytes) -> dict[str, Any]:
    fields = _wire_fields(raw)
    grouped = _by_number(fields)
    battery = _uint32(_wire_value(grouped, 1, 0, "status.battery"), "status.battery")
    result: dict[str, Any] = {"unknown_fields": _unknown(fields, {1})}
    if battery is not None:
        result["battery"] = battery
    return result


def _parse_track(raw: bytes) -> dict[str, Any]:
    fields = _wire_fields(raw)
    grouped = _by_number(fields)
    result: dict[str, Any] = {"unknown_fields": _unknown(fields, {1, 2})}
    for number, name in ((1, "speed"), (2, "course")):
        value = _double(_wire_value(grouped, number, 1, f"track.{name}"), f"track.{name}")
        if value is not None:
            result[name] = value
    return result


def _parse_extension(raw: bytes) -> dict[str, Any]:
    fields = _wire_fields(raw)
    grouped = _by_number(fields)
    identifier = _uint32(
        _wire_value(grouped, 1, 0, "extension.extensionId"), "extension.extensionId"
    )
    data = _wire_value(grouped, 2, 2, "extension.data")
    result: dict[str, Any] = {
        "extension_id": identifier,
        "unknown_fields": _unknown(fields, {1, 2}),
    }
    if data is not None:
        if not isinstance(data, bytes):
            raise SecTdlCotError("extension data is not bytes")
        capture = data[:MAX_OPAQUE_CAPTURE]
        result.update({
            "data_length": len(data),
            "data_hex": capture.hex(),
            "capture_truncated": len(data) > len(capture),
            "data_sha256": hashlib.sha256(data).hexdigest(),
        })
    return result


def _parse_xml_detail(value: str) -> dict[str, Any]:
    encoded = ("<detail>" + value + "</detail>").encode("utf-8")
    root = _xml_root(encoded)
    return {
        "raw": value,
        "elements": [_element_record(child) for child in list(root)],
        "flag_candidates": _flags(_tree_strings(root)),
    }


def _parse_detail(raw: bytes) -> dict[str, Any]:
    fields = _wire_fields(raw)
    grouped = _by_number(fields)
    result: dict[str, Any] = {"unknown_fields": _unknown(fields, set(range(1, 9)))}
    xml_detail = _text(_wire_value(grouped, 1, 2, "detail.xmlDetail"), "detail.xmlDetail")
    if xml_detail is not None:
        result["xml_detail"] = _parse_xml_detail(xml_detail)
    parsers: dict[int, tuple[str, Callable[[bytes], dict[str, Any]]]] = {
        2: ("contact", _parse_contact),
        3: ("group", lambda value: _string_message(value, {1: "name", 2: "role"}, "group")),
        4: ("precision_location", lambda value: _string_message(
            value, {1: "geopointsrc", 2: "altsrc"}, "precisionLocation"
        )),
        5: ("status", _parse_status),
        6: ("takv", lambda value: _string_message(
            value, {1: "device", 2: "platform", 3: "os", 4: "version"}, "takv"
        )),
        7: ("track", _parse_track),
    }
    for number, (name, parser) in parsers.items():
        value = _wire_message_value(grouped, number, f"detail.{name}")
        if value is not None:
            result[name] = parser(value)
    if "xml_detail" in result:
        xml_names = {
            item["name"] for item in result["xml_detail"]["elements"]
            if "namespace" not in item
        }
        xml_to_typed = {
            "contact": "contact",
            "__group": "group",
            "precisionlocation": "precision_location",
            "status": "status",
            "takv": "takv",
            "track": "track",
        }
        conflicts = sorted(
            xml_name for xml_name, typed_name in xml_to_typed.items()
            if xml_name in xml_names and typed_name in result
        )
        if conflicts:
            result["typed_xml_conflicts"] = conflicts
            result["precedence"] = (
                "official TAK semantics make xmlDetail authoritative over duplicate typed fields"
            )
    extensions: list[dict[str, Any]] = []
    for field in grouped.get(8, []):
        if field["wire"] != 2:
            raise SecTdlCotError("detail extension has the wrong wire type")
        extensions.append(_parse_extension(field["value"]))
    if extensions:
        result["extension_details"] = extensions
        result["extension_limitation"] = (
            "extension IDs are TPC-registered but their body schemas are not public here"
        )
    return result


def _parse_control(raw: bytes) -> dict[str, Any]:
    fields = _wire_fields(raw)
    grouped = _by_number(fields)
    result: dict[str, Any] = {"unknown_fields": _unknown(fields, {1, 2, 3, 4})}
    for number, name in ((1, "min_proto_version"), (2, "max_proto_version")):
        value = _uint32(_wire_value(grouped, number, 0, f"control.{name}"), f"control.{name}")
        result[name] = 1 if value in (None, 0) else value
        if value is not None:
            result[name + "_wire"] = value
    if result["min_proto_version"] > result["max_proto_version"]:
        raise SecTdlCotError("control protocol version range is reversed")
    contact_uid = _text(_wire_value(grouped, 3, 2, "control.contactUid"), "control.contactUid")
    if contact_uid is not None:
        result["contact_uid"] = contact_uid
    extension_ids: list[int] = []
    for field in grouped.get(4, []):
        if field["wire"] == 0:
            if len(extension_ids) >= MAX_PROTO_FIELDS:
                raise SecTdlCotError("control.extensionIds count exceeds limit")
            extension_ids.append(_uint32(field["value"], "control.extensionIds") or 0)
        elif field["wire"] == 2:
            packed = field["value"]
            offset = 0
            while offset < len(packed):
                if len(extension_ids) >= MAX_PROTO_FIELDS:
                    raise SecTdlCotError("control.extensionIds count exceeds limit")
                item, offset = _read_varint(packed, offset)
                extension_ids.append(_uint32(item, "control.extensionIds") or 0)
        else:
            raise SecTdlCotError("control.extensionIds has the wrong wire type")
    if extension_ids:
        result["extension_ids"] = extension_ids
    return result


def _time_ms(value: int | None) -> dict[str, Any] | None:
    if value is None:
        return None
    output: dict[str, Any] = {"epoch_ms": value}
    try:
        output["iso_utc"] = (
            datetime.fromtimestamp(value / 1000, tz=timezone.utc)
            .isoformat()
            .replace("+00:00", "Z")
        )
    except (OverflowError, OSError, ValueError):
        output["iso_utc"] = None
    return output


def _parse_event(raw: bytes) -> dict[str, Any]:
    fields = _wire_fields(raw)
    grouped = _by_number(fields)
    known = set(range(1, 18))
    result: dict[str, Any] = {"unknown_fields": _unknown(fields, known), "findings": []}
    strings = {
        1: "type", 2: "access", 3: "qos", 4: "opex", 5: "uid", 9: "how",
        16: "caveat", 17: "releasable_to",
    }
    presence: set[str] = set()
    for number, name in strings.items():
        value = _text(_wire_value(grouped, number, 2, f"event.{name}"), f"event.{name}")
        if value is not None:
            result[name] = value
            if value:
                presence.add(name)
    for number, name in ((6, "send_time"), (7, "start_time"), (8, "stale_time")):
        value = _wire_value(grouped, number, 0, f"event.{name}")
        if value is not None:
            result[name] = _time_ms(value)
            presence.add(name)
    for number, name in ((10, "lat"), (11, "lon"), (12, "hae"), (13, "ce"), (14, "le")):
        value = _double(_wire_value(grouped, number, 1, f"event.{name}"), f"event.{name}")
        if value is not None:
            result[name] = value
            presence.add(name)
    detail = _wire_message_value(grouped, 15, "event.detail")
    if detail is not None:
        result["detail"] = _parse_detail(detail)
    required = {
        "type", "uid", "send_time", "start_time", "stale_time", "how",
        "lat", "lon", "hae", "ce", "le",
    }
    missing = sorted(required - presence)
    if missing:
        result["findings"].append({
            "code": "semantic_required_fields_absent",
            "fields": missing,
        })
    if "access" not in presence:
        result["findings"].append({
            "code": "access_undefined_or_legacy_absent",
            "severity": "warning",
        })
    if result.get("type"):
        result["type_hierarchy"] = _decode_type(result["type"])
    if result.get("how"):
        result["how_hierarchy"] = _decode_how(result["how"])
    if "lat" in result and not -90 <= result["lat"] <= 90:
        raise SecTdlCotError("protobuf event latitude is out of range")
    if "lon" in result and not -180 <= result["lon"] <= 180:
        raise SecTdlCotError("protobuf event longitude is out of range")
    if all(name in result and result[name] is not None for name in ("start_time", "stale_time")):
        start_ms = result["start_time"]["epoch_ms"]
        stale_ms = result["stale_time"]["epoch_ms"]
        result["drop_track"] = stale_ms < start_ms
        if stale_ms < start_ms:
            result["findings"].append({
                "code": "drop_track_time_reversal",
                "severity": "info",
            })
    return result


def _parse_tak_payload_impl(raw: bytes) -> dict[str, Any]:
    fields = _wire_fields(raw)
    grouped = _by_number(fields)
    control = _wire_message_value(grouped, 1, "TakMessage.takControl")
    event = _wire_message_value(grouped, 2, "TakMessage.cotEvent")
    result: dict[str, Any] = {
        "kind": "tak-protocol-v1-payload",
        "protocol": "tak",
        "version": 1,
        "payload_length": len(raw),
        "offline": True,
        "network_requests": 0,
        "unknown_fields": _unknown(fields, {1, 2}),
    }
    if control is not None:
        result["tak_control"] = _parse_control(control)
    if event is not None:
        result["cot_event"] = _parse_event(event)
    if control is None and event is None:
        result["finding"] = "empty TakMessage (wire-valid, no control or event data)"
    strings: list[str] = []
    for field in fields:
        if field["wire"] == 2 and isinstance(field["value"], bytes):
            try:
                strings.append(field["value"].decode("utf-8"))
            except UnicodeDecodeError:
                pass
    # Nested detail flag candidates are already available, but scanning the
    # bounded payload as Latin-1 also catches ordinary protobuf string bytes.
    strings.append(raw.decode("latin-1"))
    result["flag_candidates"] = _flags(strings)
    return result


@_guard
def parse_tak_payload(data: object) -> dict[str, Any]:
    """Decode one raw current TAK Protocol v1 ``TakMessage`` payload."""
    # Both top-level protobuf fields are optional.  The zero-byte encoding is
    # therefore wire-valid, even though it carries no operational data.
    return _parse_tak_payload_impl(
        _bytes(data, MAX_PROTO_BYTES, "TAK payload", allow_empty=True)
    )


@_guard
def parse_tak_mesh(data: object) -> dict[str, Any]:
    """Decode one mesh/directed frame: ``BF || version-varint || BF || payload``."""
    raw = _bytes(data, MAX_PROTO_BYTES + 16, "TAK mesh frame")
    if raw[0] != TAK_MAGIC:
        raise SecTdlCotError("TAK mesh frame magic is not 0xbf")
    version, offset = _read_varint(raw, 1, frame=True)
    if version != SUPPORTED_TAK_VERSION:
        raise SecTdlCotError(f"unsupported TAK Protocol version {version}")
    if offset >= len(raw) or raw[offset] != TAK_MAGIC:
        raise SecTdlCotError("TAK mesh frame lacks the second 0xbf magic")
    payload = raw[offset + 1:]
    return {
        "kind": "tak-protocol-mesh",
        "protocol": "tak",
        "framing": "mesh_or_directed",
        "version": version,
        "header_length": offset + 1,
        "payload_length": len(payload),
        "offline": True,
        "network_requests": 0,
        "message": _parse_tak_payload_impl(payload),
    }


@_guard
def parse_tak_stream(data: object) -> dict[str, Any]:
    """Decode concatenated stream frames: ``BF || length-varint || payload``."""
    raw = _bytes(data, MAX_INPUT, "TAK stream")
    frames: list[dict[str, Any]] = []
    offset = 0
    while offset < len(raw):
        if len(frames) >= MAX_STREAM_FRAMES:
            raise SecTdlCotError("TAK stream frame count exceeds limit")
        start = offset
        if raw[offset] != TAK_MAGIC:
            raise SecTdlCotError(f"TAK stream magic missing at offset {offset}")
        length, payload_offset = _read_varint(raw, offset + 1, frame=True)
        if length > MAX_PROTO_BYTES:
            raise SecTdlCotError("TAK stream payload length is excessive")
        end = payload_offset + length
        if end > len(raw):
            raise SecTdlCotError("truncated TAK stream payload")
        payload = raw[payload_offset:end]
        frames.append({
            "offset": start,
            "header_length": payload_offset - start,
            "payload_length": length,
            "message": _parse_tak_payload_impl(payload),
        })
        offset = end
    return {
        "kind": "tak-protocol-stream",
        "protocol": "tak",
        "framing": "stream",
        "negotiated_version_required": True,
        "frame_count": len(frames),
        "frames": frames,
        "offline": True,
        "network_requests": 0,
    }


def _zip_path(name: str) -> tuple[str, list[str]]:
    reasons: list[str] = []
    if not name or "\x00" in name:
        reasons.append("empty_or_nul")
    if "\\" in name:
        reasons.append("backslash_ambiguity")
    normalized = name.replace("\\", "/")
    if normalized.startswith(("/", "//")):
        reasons.append("absolute_or_unc")
    if re.match(r"^[A-Za-z]:", normalized):
        reasons.append("windows_drive")
    pieces: list[str] = []
    escaped = False
    for piece in normalized.split("/"):
        if piece in {"", "."}:
            continue
        if piece == "..":
            reasons.append("parent_segment")
            if not pieces:
                escaped = True
            else:
                pieces.pop()
        else:
            pieces.append(piece)
    if escaped:
        reasons.append("parent_traversal")
    return "/".join(pieces), sorted(set(reasons))


def _zip_preflight(raw: bytes) -> dict[str, Any]:
    """Validate the classic single-disk EOCD before ``zipfile`` sees it."""
    eocd_size = 22
    search_start = max(0, len(raw) - (0xFFFF + eocd_size))
    offset = raw.rfind(b"PK\x05\x06", search_start)
    if offset < 0 or len(raw) - offset < eocd_size:
        raise SecTdlCotError("ZIP end-of-central-directory record is missing")
    (
        signature,
        disk_number,
        central_disk,
        entries_on_disk,
        total_entries,
        central_size,
        central_offset,
        comment_length,
    ) = struct.unpack_from("<4s4H2LH", raw, offset)
    if signature != b"PK\x05\x06":
        raise SecTdlCotError("ZIP EOCD signature is invalid")
    if offset + eocd_size + comment_length != len(raw):
        raise SecTdlCotError("ZIP EOCD comment length or trailing data is invalid")
    if disk_number or central_disk or entries_on_disk != total_entries:
        raise SecTdlCotError("multi-disk ZIP archives are unsupported")
    if (
        entries_on_disk == 0xFFFF
        or total_entries == 0xFFFF
        or central_size == 0xFFFFFFFF
        or central_offset == 0xFFFFFFFF
        or raw[max(0, offset - 20):offset].startswith(b"PK\x06\x07")
    ):
        raise SecTdlCotError("ZIP64 archives are unsupported for bounded Mission Packages")
    if total_entries > MAX_ZIP_ENTRIES:
        raise SecTdlCotError("ZIP entry count exceeds limit")
    central_end = central_offset + central_size
    if central_end != offset:
        raise SecTdlCotError("ZIP central-directory bounds are invalid")

    # Bound the real central-directory record count before ZipFile.infolist()
    # can allocate ZipInfo objects.  EOCD counts are attacker-controlled and
    # cannot be used as the sole resource limit.
    cursor = central_offset
    actual_entries = 0
    while cursor < central_end:
        if actual_entries >= MAX_ZIP_ENTRIES:
            raise SecTdlCotError("ZIP actual entry count exceeds limit")
        if cursor + 46 > central_end or raw[cursor:cursor + 4] != b"PK\x01\x02":
            raise SecTdlCotError("ZIP central-directory record is malformed")
        name_length, extra_length, record_comment_length = struct.unpack_from(
            "<HHH", raw, cursor + 28
        )
        starting_disk = struct.unpack_from("<H", raw, cursor + 34)[0]
        if starting_disk:
            raise SecTdlCotError("multi-disk ZIP entries are unsupported")
        record_end = cursor + 46 + name_length + extra_length + record_comment_length
        if record_end > central_end:
            raise SecTdlCotError("ZIP central-directory record is truncated")
        name_start = cursor + 46
        if b"\x00" in raw[name_start:name_start + name_length]:
            raise SecTdlCotError("ZIP central-directory filename contains NUL")
        cursor = record_end
        actual_entries += 1
    if cursor != central_end or actual_entries != total_entries:
        raise SecTdlCotError("ZIP EOCD entry count disagrees with central directory")
    return {
        "format": "zip32",
        "single_disk": True,
        "entry_count": actual_entries,
        "central_directory_offset": central_offset,
        "central_directory_size": central_size,
        "comment_length": comment_length,
    }


def _zip_entry_record(info: zipfile.ZipInfo) -> dict[str, Any]:
    normalized, unsafe = _zip_path(info.filename)
    mode = (info.external_attr >> 16) & 0xFFFF
    # Keep reports strict-JSON serializable.  A non-empty entry with a declared
    # compressed size of zero is represented separately rather than as Infinity.
    ratio = None if not info.file_size or not info.compress_size else info.file_size / info.compress_size
    return {
        "name": info.filename,
        "normalized_name": normalized,
        "compressed_size": info.compress_size,
        "uncompressed_size": info.file_size,
        "crc32": f"{info.CRC:08x}",
        "compression_method": info.compress_type,
        "supported_compression": info.compress_type in {
            zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED, zipfile.ZIP_BZIP2
        },
        "compression_ratio": ratio,
        "zero_compressed_nonempty": bool(info.file_size and not info.compress_size),
        "directory": info.is_dir(),
        "encrypted": bool(info.flag_bits & 1),
        "symlink": stat.S_IFMT(mode) == stat.S_IFLNK,
        "unsafe_path_reasons": unsafe,
    }


def _safe_member(archive: zipfile.ZipFile, info: zipfile.ZipInfo, limit: int) -> bytes:
    record = _zip_entry_record(info)
    if record["directory"] or record["encrypted"] or record["symlink"]:
        raise SecTdlCotError("required ZIP member is not a regular readable file")
    if not record["supported_compression"]:
        raise SecTdlCotError("required ZIP member uses unsupported compression")
    if record["unsafe_path_reasons"]:
        raise SecTdlCotError("required ZIP member has an unsafe path")
    if info.file_size > limit or info.file_size > MAX_ZIP_ENTRY:
        raise SecTdlCotError("required ZIP member exceeds size limit")
    if record["zero_compressed_nonempty"]:
        raise SecTdlCotError("required ZIP member has an impossible compression ratio")
    ratio = record["compression_ratio"]
    if ratio is not None and ratio > MAX_ZIP_RATIO:
        raise SecTdlCotError("required ZIP member has an excessive compression ratio")
    try:
        with archive.open(info, "r") as stream:
            data = stream.read(limit + 1)
    except (OSError, RuntimeError, zipfile.BadZipFile, NotImplementedError) as exc:
        raise SecTdlCotError("cannot read required ZIP member") from exc
    if len(data) > limit:
        raise SecTdlCotError("required ZIP member expands beyond limit")
    return data


def _parameters(element: ET.Element, label: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for child in list(element):
        if child.tag != "Parameter" or list(child):
            raise SecTdlCotError(f"{label} contains a non-Parameter child")
        if set(child.attrib) != {"name", "value"}:
            raise SecTdlCotError(f"{label} Parameter requires only name/value")
        name, value = child.attrib["name"], child.attrib["value"]
        if not name or not value or name in values:
            raise SecTdlCotError(f"{label} has an empty or duplicate Parameter")
        values[name] = value
    return values


def _manifest(raw: bytes) -> dict[str, Any]:
    root = _xml_root(raw)
    if root.tag != "MissionPackageManifest" or set(root.attrib) != {"version"}:
        raise SecTdlCotError("Mission Package manifest root/version is invalid")
    if root.attrib["version"] != "2":
        raise SecTdlCotError("only MissionPackageManifest version 2 is supported")
    configuration = [child for child in list(root) if child.tag == "Configuration"]
    contents = [child for child in list(root) if child.tag == "Contents"]
    if len(configuration) != 1 or len(contents) != 1 or len(root) != 2:
        raise SecTdlCotError("manifest requires exactly Configuration and Contents")
    if configuration[0].attrib or contents[0].attrib:
        raise SecTdlCotError("Configuration/Contents attributes are unsupported")
    config = _parameters(configuration[0], "Configuration")
    if not config.get("uid") or not config.get("name"):
        raise SecTdlCotError("manifest Configuration requires uid and name")
    items: list[dict[str, Any]] = []
    for child in list(contents[0]):
        if child.tag != "Content":
            raise SecTdlCotError("Contents contains a non-Content child")
        if not set(child.attrib) <= {"zipEntry", "ignore"} or not child.attrib.get("zipEntry"):
            raise SecTdlCotError("Content requires zipEntry and optional ignore")
        ignore_text = child.attrib.get("ignore", "false").lower()
        if ignore_text not in {"true", "false"}:
            raise SecTdlCotError("Content ignore must be true or false")
        items.append({
            "zip_entry": child.attrib["zipEntry"],
            "ignore": ignore_text == "true",
            "parameters": _parameters(child, "Content"),
        })
        if len(items) > MAX_ZIP_ENTRIES:
            raise SecTdlCotError("manifest content count exceeds limit")
    return {
        "version": 2,
        "configuration": config,
        "contents": items,
        "flag_candidates": _flags(_tree_strings(root)),
    }


@_guard
def parse_mission_package(data: object) -> dict[str, Any]:
    """Inspect a MissionPackageManifest v2 ZIP without extracting any member."""
    raw = _bytes(data, MAX_INPUT, "Mission Package")
    zip_metadata = _zip_preflight(raw)
    try:
        archive = zipfile.ZipFile(BytesIO(raw), "r")
    except (zipfile.BadZipFile, zipfile.LargeZipFile, OSError) as exc:
        raise SecTdlCotError("input is not a readable ZIP") from exc
    with archive:
        infos = archive.infolist()
        if not infos or len(infos) > MAX_ZIP_ENTRIES:
            raise SecTdlCotError("ZIP entry count is zero or excessive")
        total = sum(info.file_size for info in infos)
        if total > MAX_ZIP_TOTAL:
            raise SecTdlCotError("ZIP declared uncompressed total exceeds limit")
        entries = [_zip_entry_record(info) for info in infos]
        findings: list[dict[str, Any]] = []
        by_name: dict[str, list[zipfile.ZipInfo]] = {}
        normalized: dict[str, list[str]] = {}
        casefolded: dict[str, list[str]] = {}
        for info, record in zip(infos, entries):
            by_name.setdefault(info.filename, []).append(info)
            normalized.setdefault(record["normalized_name"], []).append(info.filename)
            casefolded.setdefault(record["normalized_name"].casefold(), []).append(info.filename)
            if record["unsafe_path_reasons"]:
                findings.append({
                    "code": "unsafe_zip_path",
                    "entry": info.filename,
                    "reasons": record["unsafe_path_reasons"],
                })
            if record["encrypted"]:
                findings.append({"code": "encrypted_entry", "entry": info.filename})
            if record["symlink"]:
                findings.append({"code": "symlink_entry", "entry": info.filename})
            if not record["supported_compression"]:
                findings.append({"code": "unsupported_compression", "entry": info.filename})
            if record["zero_compressed_nonempty"]:
                findings.append({"code": "impossible_compression_ratio", "entry": info.filename})
            if record["compression_ratio"] is not None and record["compression_ratio"] > MAX_ZIP_RATIO:
                findings.append({"code": "excessive_compression_ratio", "entry": info.filename})
        for name, members in sorted(by_name.items()):
            if len(members) > 1:
                findings.append({"code": "duplicate_zip_name", "entry": name, "count": len(members)})
        for name, members in sorted(normalized.items()):
            if len(set(members)) > 1:
                findings.append({"code": "normalized_path_collision", "normalized": name,
                                 "entries": sorted(members)})
        for name, members in sorted(casefolded.items()):
            if len(set(members)) > 1:
                findings.append({"code": "casefold_path_collision", "normalized": name,
                                 "entries": sorted(members)})

        suffix = "MANIFEST/manifest.xml"
        manifests = [info for info, record in zip(infos, entries)
                     if not record["directory"] and (
                         info.filename == suffix or info.filename.endswith("/" + suffix)
                     )]
        if len(manifests) != 1:
            raise SecTdlCotError("ZIP must contain exactly one MANIFEST/manifest.xml")
        manifest_info = manifests[0]
        manifest_record = _zip_entry_record(manifest_info)
        if manifest_record["unsafe_path_reasons"]:
            raise SecTdlCotError("manifest path is unsafe")
        manifest = _manifest(_safe_member(archive, manifest_info, MAX_XML_BYTES))
        base_directory = manifest_info.filename[:-len(suffix)]
        if base_directory:
            findings.append({
                "code": "nested_manifest_base_directory",
                "base_directory": base_directory,
                "severity": "info",
            })

        listed_actual: set[str] = {manifest_info.filename}
        cot_events: list[dict[str, Any]] = []
        cot_bytes = 0
        content_seen: set[str] = set()
        for item in manifest["contents"]:
            requested = item["zip_entry"]
            normalized_request, unsafe = _zip_path(requested)
            item["normalized_zip_entry"] = normalized_request
            if requested in content_seen:
                findings.append({"code": "duplicate_manifest_content", "zip_entry": requested})
            content_seen.add(requested)
            if unsafe:
                findings.append({
                    "code": "unsafe_manifest_content_path",
                    "zip_entry": requested,
                    "reasons": unsafe,
                })
                item["present"] = False
                continue
            actual = base_directory + requested
            item["resolved_entry"] = actual
            matches = by_name.get(actual, [])
            item["present"] = len(matches) == 1
            if len(matches) != 1:
                findings.append({
                    "code": "missing_or_ambiguous_manifest_content",
                    "zip_entry": requested,
                    "match_count": len(matches),
                })
                continue
            listed_actual.add(actual)
            info = matches[0]
            record = _zip_entry_record(info)
            item["entry_metadata"] = record
            if item["ignore"] or not requested.lower().endswith(".cot"):
                continue
            if len(cot_events) >= MAX_PACKAGE_COT or cot_bytes + info.file_size > MAX_PACKAGE_COT_BYTES:
                findings.append({"code": "cot_content_analysis_limit", "zip_entry": requested})
                continue
            try:
                member = _safe_member(archive, info, MAX_XML_BYTES)
                cot = _parse_cot_root(_xml_root(member))
                cot_bytes += len(member)
                cot_events.append({"zip_entry": requested, "event": cot})
            except SecTdlCotError as exc:
                findings.append({
                    "code": "invalid_cot_content",
                    "zip_entry": requested,
                    "reason": str(exc),
                })
        for info in infos:
            if not info.is_dir() and info.filename not in listed_actual:
                findings.append({"code": "unlisted_zip_entry", "entry": info.filename})
        flags = set(manifest["flag_candidates"])
        for record in cot_events:
            flags.update(record["event"]["flag_candidates"])
        return {
            "kind": "tak-mission-package-v2",
            "protocol": "tak-data-package",
            "offline": True,
            "network_requests": 0,
            "zip_metadata": zip_metadata,
            "base_directory": base_directory,
            "manifest_entry": manifest_info.filename,
            "manifest": manifest,
            "entries": entries,
            "cot_events": cot_events,
            "findings": findings,
            "flag_candidates": sorted(flags),
            "limitations": [
                "members are inventoried and selectively read in memory; none are extracted",
                "fileshare URLs are evidence only and are never fetched",
                "MissionPackageManifest v2 has no mandatory per-entry cryptographic hash",
            ],
        }


@_guard
def analyze(data: object, *, kind: str = "auto") -> dict[str, Any]:
    """Dispatch explicitly, or safely identify XML/ZIP while refusing BF ambiguity."""
    if kind not in {"auto", "xml", "raw", "mesh", "stream", "package"}:
        raise SecTdlCotError("unsupported analysis kind")
    raw = _bytes(data, MAX_INPUT, "input", allow_empty=kind == "raw")
    if kind == "xml":
        return parse_cot_xml(raw)
    if kind == "raw":
        return parse_tak_payload(raw)
    if kind == "mesh":
        return parse_tak_mesh(raw)
    if kind == "stream":
        return parse_tak_stream(raw)
    if kind == "package":
        return parse_mission_package(raw)
    if raw.startswith(b"PK\x03\x04") or raw.startswith(b"PK\x05\x06"):
        return parse_mission_package(raw)
    probe = raw.lstrip(b"\xef\xbb\xbf\x00\t\r\n ")
    if probe.startswith(b"<") or raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return parse_cot_xml(raw)
    if raw[0] == TAK_MAGIC:
        raise SecTdlCotError(
            "0xbf data is framing-ambiguous offline; select mesh or stream explicitly"
        )
    raise SecTdlCotError("cannot identify input; select raw protobuf explicitly if appropriate")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", help="supplied CoT XML, TAK frame/payload, or Data Package ZIP")
    parser.add_argument(
        "--format", dest="kind",
        choices=("auto", "xml", "raw", "mesh", "stream", "package"),
        default="auto",
        help="explicit input framing/format (0xbf evidence should use mesh or stream)",
    )
    parser.add_argument("--pretty", action="store_true", help="pretty-print deterministic JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        path = Path(args.file)
        with path.open("rb") as stream:
            raw = stream.read(MAX_INPUT + 1)
        if len(raw) > MAX_INPUT:
            raise SecTdlCotError("input file exceeds size limit")
        report = analyze(raw, kind=args.kind)
        print(json.dumps(
            report,
            indent=2 if args.pretty else None,
            sort_keys=True,
            allow_nan=False,
        ))
        return 0
    except (SecTdlCotError, OSError, ValueError) as exc:
        print(f"sec_tdl_cot: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
