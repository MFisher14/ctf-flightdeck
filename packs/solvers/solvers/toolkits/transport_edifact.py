#!/usr/bin/env python3
"""Bounded offline EDIFACT syntax 1–3 reader and IFTMIN evidence extraction.

Parses saved text only. Escaping is resolved in one pass, preserving component
boundaries and empty elements. Validates message/interchange counts and references;
not a complete directory-specific business-rules validator. UNG functional groups,
syntax 4 repetition and binary UNO/UNP objects are explicitly unsupported.
Supports UNOA/UNOB/UNOC envelopes. Bytes are interpreted as Latin-1 (UNOC).
CLI: transport_edifact.py FILE [--segments-only]
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

MAX_INPUT = 8 * 1024 * 1024
MAX_SEGMENTS = 100_000
MAX_SEGMENT = 65_536
MAX_COMPONENTS = 4096


class TransportEdifactError(ValueError):
    """Malformed, unsupported or over-limit EDIFACT artifact."""


def _text(data: bytes | str) -> str:
    if isinstance(data, bytes):
        if len(data) > MAX_INPUT:
            raise TransportEdifactError("input exceeds size cap")
        return data.decode("latin-1")
    if not isinstance(data, str) or len(data) > MAX_INPUT:
        raise TransportEdifactError("expected bounded bytes or text")
    if any(0xD800 <= ord(c) <= 0xDFFF for c in data):
        raise TransportEdifactError("text contains invalid Unicode surrogates")
    return data


def parse_segments(data: bytes | str) -> list[dict]:
    """Return tag + elements (each a list of components); fail on incomplete input."""
    text = _text(data).lstrip("\r\n\t ")
    component, element, decimal, release, reserved, terminator = ":+.? '"
    if text.startswith("UNA"):
        if len(text) < 9:
            raise TransportEdifactError("truncated UNA service string")
        component, element, decimal, release, reserved, terminator = text[3:9]
        if (reserved != " " or decimal not in ".," or
                len({component, element, decimal, release, terminator}) != 5 or
                any(ord(c) < 33 or ord(c) > 126 or c.isalnum()
                    for c in (component, element, release, terminator))):
            raise TransportEdifactError("invalid UNA or unsupported syntax-4 repetition")
        text = text[9:]
    segments = []
    fields, parts, chars = [], [], []
    escaped = False
    size, count = 0, 0
    for char in text:
        if not fields and not parts and not chars and char in "\r\n\t ":
            continue
        size += 1
        if size > MAX_SEGMENT:
            raise TransportEdifactError("segment exceeds size cap")
        if escaped:
            if char not in (component, element, decimal, release, terminator):
                raise TransportEdifactError("release character precedes non-service character")
            chars.append(char)
            escaped = False
        elif char == release:
            escaped = True
        elif char in (component, element, terminator):
            parts.append("".join(chars))
            chars = []
            count += 1
            if count > MAX_COMPONENTS:
                raise TransportEdifactError("segment component count exceeds cap")
            if char != component:
                fields.append(parts)
                parts = []
            if char == terminator:
                if len(fields[0]) != 1 or not re.fullmatch(r"[A-Z][A-Z0-9]{2}", fields[0][0]):
                    raise TransportEdifactError("invalid segment tag")
                if fields[0][0] in ("UNA", "UNO", "UNP", "UNG", "UNE"):
                    raise TransportEdifactError("unsupported service segment")
                segments.append({"tag": fields[0][0], "elements": fields[1:]})
                if len(segments) > MAX_SEGMENTS:
                    raise TransportEdifactError("segment count exceeds cap")
                fields, parts, chars = [], [], []
                size, count = 0, 0
        elif ord(char) < 32 or ord(char) == 127:
            raise TransportEdifactError("control character inside segment")
        else:
            chars.append(char)
    if escaped or fields or parts or chars:
        raise TransportEdifactError("unterminated segment or dangling release character")
    if not segments:
        raise TransportEdifactError("no segments")
    return segments


def _at(segment: dict, index: int, sub: int = 0) -> str:
    elements = segment["elements"]
    return elements[index][sub] if index < len(elements) and sub < len(elements[index]) else ""


def _required(segment: dict, index: int, sub: int = 0) -> str:
    value = _at(segment, index, sub)
    if not value:
        raise TransportEdifactError(f"{segment['tag']} lacks required field {index + 1}.{sub + 1}")
    return value


def _count(segment: dict) -> int:
    value = _required(segment, 0)
    if not re.fullmatch(r"[0-9]{1,10}", value):
        raise TransportEdifactError(f"{segment['tag']} has invalid control count")
    return int(value)


def _summary(segments: list[dict]) -> dict:
    out = {key: [] for key in ("documents", "dates", "references", "parties", "transport",
                               "locations", "goods", "measurements", "equipment", "free_text")}
    for seg in segments:
        tag, elements = seg["tag"], seg["elements"]
        if tag == "BGM":
            out["documents"].append({"code": _at(seg, 0), "number": _at(seg, 1), "function": _at(seg, 2)})
        elif tag == "DTM":
            out["dates"].append({"qualifier": _at(seg, 0), "value": _at(seg, 0, 1), "format": _at(seg, 0, 2)})
        elif tag == "RFF":
            out["references"].append({"qualifier": _at(seg, 0), "value": _at(seg, 0, 1)})
        elif tag == "NAD":
            out["parties"].append({"qualifier": _at(seg, 0), "id": _at(seg, 1),
                                   "name": elements[3] if len(elements) > 3 else [],
                                   "city": _at(seg, 5), "postcode": _at(seg, 7), "country": _at(seg, 8)})
        elif tag == "TDT":
            out["transport"].append({"stage": _at(seg, 0), "journey": _at(seg, 1),
                                      "mode": _at(seg, 2), "carrier": _at(seg, 4), "vehicle": _at(seg, 7)})
        elif tag == "LOC":
            out["locations"].append({"qualifier": _at(seg, 0), "id": _at(seg, 1), "name": _at(seg, 1, 3)})
        elif tag == "GID":
            out["goods"].append({"item": _at(seg, 0), "packages": elements[1:]})
        elif tag == "MEA":
            out["measurements"].append({"purpose": _at(seg, 0), "dimension": _at(seg, 1),
                                         "unit": _at(seg, 2), "value": _at(seg, 2, 1)})
        elif tag == "EQD":
            out["equipment"].append({"type": _at(seg, 0), "id": _at(seg, 1)})
        elif tag == "FTX":
            out["free_text"].append({"subject": _at(seg, 0), "language": _at(seg, 4),
                                      "components": elements[3] if len(elements) > 3 else []})
    return out


def analyze(data: bytes | str) -> dict:
    """Validate complete UNH/UNT messages, optionally inside one UNB/UNZ envelope."""
    segments = parse_segments(data)
    interchange = None
    start = None
    messages = []
    seen = set()
    closed = False
    for i, segment in enumerate(segments):
        tag = segment["tag"]
        if closed:
            raise TransportEdifactError("content after UNZ")
        if tag == "UNB":
            if i != 0 or start is not None:
                raise TransportEdifactError("UNB must be first and unique")
            if _required(segment, 0) not in ("UNOA", "UNOB", "UNOC"):
                raise TransportEdifactError("unsupported UNB character set (expected UNOA/B/C)")
            syntax = _required(segment, 0, 1)
            if syntax not in ("1", "2", "3"):
                raise TransportEdifactError("only EDIFACT syntax versions 1–3 are supported")
            interchange = {"syntax": segment["elements"][0], "sender": _required(segment, 1),
                           "recipient": _required(segment, 2), "reference": _required(segment, 4)}
        elif tag == "UNH":
            if start is not None:
                raise TransportEdifactError("nested UNH")
            reference = _required(segment, 0)
            if reference in seen:
                raise TransportEdifactError("duplicate message reference")
            for sub in range(4):
                _required(segment, 1, sub)
            seen.add(reference)
            start = i
        elif tag == "UNT":
            if start is None:
                raise TransportEdifactError("orphan UNT")
            if _count(segment) != i - start + 1:
                raise TransportEdifactError("UNT segment count mismatch")
            header = segments[start]
            if _required(segment, 1) != _at(header, 0):
                raise TransportEdifactError("UNT message reference mismatch")
            body = segments[start:i + 1]
            messages.append({"reference": _at(header, 0), "type": _at(header, 1),
                             "version": _at(header, 1, 1), "release": _at(header, 1, 2),
                             "agency": _at(header, 1, 3), "segments": body,
                             "summary": _summary(body)})
            start = None
        elif tag == "UNZ":
            if interchange is None or start is not None or not messages:
                raise TransportEdifactError("orphan or premature UNZ")
            if _count(segment) != len(messages):
                raise TransportEdifactError("UNZ message count mismatch")
            if _required(segment, 1) != interchange["reference"]:
                raise TransportEdifactError("UNZ interchange reference mismatch")
            closed = True
        elif start is None:
            raise TransportEdifactError(f"{tag} outside a message")
    if start is not None or (interchange is not None and not closed) or not messages:
        raise TransportEdifactError("incomplete message/interchange")
    # Only actual decoded components; do not stitch separate fields into a flag.
    flags = sorted({flag for seg in segments for elem in seg["elements"] for val in elem
                    for flag in flagfmt.TEXT.findall(val)})
    return {"interchange": interchange, "messages": messages, "flags": flags}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file")
    parser.add_argument("--segments-only", action="store_true", help="parse syntax without envelope validation")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        with Path(args.file).open("rb") as stream:
            raw = stream.read(MAX_INPUT + 1)
        result = parse_segments(raw) if args.segments_only else analyze(raw)
        print(json.dumps(result, ensure_ascii=True, indent=2))
        return 0
    except (TransportEdifactError, OSError, ValueError) as exc:
        print(f"transport_edifact: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
