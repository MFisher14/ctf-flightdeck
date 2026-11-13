#!/usr/bin/env python3
"""Offline HL7 v2 ER7 hierarchy, dictionary annotations and ED extraction.

All segment IDs (including Z extensions) are preserved; this is a structural
parser, not clinical message-profile validation. hl7apy supplies versioned field
names/types for 2.1--2.8.2. Unknown versions/fields remain explicitly unnamed.
Escapes are decoded only after splitting. Local/formatting/character-set escapes
stay verbatim; X escapes expose their bytes through Latin-1 (a reversible mapping).
Input character encoding is explicit, default UTF-8. No URLs are followed.
"""
from __future__ import annotations

import argparse
import base64
import functools
import json
import re
import sys
from pathlib import Path

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

MAX_BYTES = 16 * 1024 * 1024
MAX_SEGMENTS = 20000
MAX_PARTS = 1000000


class HL7Error(ValueError):
    """Malformed, unsupported, or resource-limited HL7 input."""


def _closed(fn):
    @functools.wraps(fn)
    def wrapped(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except HL7Error:
            raise
        except Exception as exc:
            raise HL7Error(f"{fn.__name__}: {type(exc).__name__}: {exc}") from None
    return wrapped


@functools.lru_cache(maxsize=16)
def _library(version):
    try:
        import hl7apy
    except ImportError:
        raise HL7Error("install hl7apy for the versioned field dictionary") from None
    if version not in hl7apy.SUPPORTED_LIBRARIES:
        return None
    return hl7apy.load_library(version)


@_closed
def field_definition(segment, number, version="2.5"):
    """Return the official dictionary name/type/table, or None if unknown."""
    if not isinstance(segment, str) or not re.fullmatch(r"[A-Z][A-Z0-9]{2}", segment):
        raise HL7Error("invalid segment ID")
    if type(number) is not int or number < 1:
        raise HL7Error("field number must be a positive integer")
    library = _library(version)
    entry = library.FIELDS.get(f"{segment}_{number}") if library else None
    if entry is None:
        return None
    return {"name": entry[3], "datatype": entry[2], "table": entry[4]}


def _delimiters(header):
    if len(header) < 9:
        raise HL7Error("truncated header")
    field = header[3]
    end = header.find(field, 4)
    if end == -1:
        raise HL7Error("missing header encoding terminator")
    enc = header[4:end]
    if len(enc) not in (4, 5) or len(set(field + enc)) != len(field + enc):
        raise HL7Error("header needs four or five distinct encoding characters")
    if any(not 32 <= ord(c) <= 126 for c in field + enc):
        raise HL7Error("delimiters must be printable ASCII")
    return {"field": field, "component": enc[0], "repetition": enc[1],
            "escape": enc[2], "subcomponent": enc[3],
            "truncation": enc[4] if len(enc) == 5 else None}, enc, end


def _split(raw, sep, escape, budget):
    result, begin, pos = [], 0, 0
    while pos < len(raw):
        if raw[pos] == escape:
            close = raw.find(escape, pos + 1)
            if close == -1:
                raise HL7Error("unterminated escape sequence")
            if close == pos + 1:
                raise HL7Error("empty escape sequence")
            pos = close + 1
            continue
        if raw[pos] == sep:
            result.append(raw[begin:pos])
            begin = pos + 1
        pos += 1
    result.append(raw[begin:])
    budget[0] -= len(result)
    if budget[0] < 0:
        raise HL7Error("too many hierarchy elements")
    return result


def _unescape(raw, delimiters):
    esc = delimiters["escape"]
    mapping = dict(zip("FSRTE", (delimiters[x] for x in
                               ("field", "component", "repetition", "subcomponent", "escape"))))
    output, pos = [], 0
    while pos < len(raw):
        if raw[pos] != esc:
            output.append(raw[pos])
            pos += 1
            continue
        close = raw.find(esc, pos + 1)
        if close == -1:
            raise HL7Error("unterminated escape sequence")
        token = raw[pos + 1:close]
        if token in mapping:
            output.append(mapping[token])
        elif token.startswith("X"):
            digits = token[1:]
            if not digits or len(digits) % 2 or not re.fullmatch("[0-9A-Fa-f]+", digits):
                raise HL7Error("invalid hexadecimal escape")
            output.append(bytes.fromhex(digits).decode("latin-1"))
        elif token == ".br":
            output.append("\n")
        elif token in ("H", "N") or token.startswith(("Z", ".", "C", "M")):
            output.append(raw[pos:close + 1])
        else:
            raise HL7Error(f"unknown escape code {token!r}")
        pos = close + 1
    return "".join(output)


def _field(raw, number, segid, delimiters, version, budget, literal=False):
    reps = [[[raw]]] if literal else [
        [[_unescape(s, delimiters) for s in _split(c, delimiters["subcomponent"], delimiters["escape"], budget)]
         for c in _split(r, delimiters["component"], delimiters["escape"], budget)]
        for r in _split(raw, delimiters["repetition"], delimiters["escape"], budget)]
    return {"number": number, "raw": raw, "is_null": raw == '""',
            "repetitions": reps, "definition": field_definition(segid, number, version)}


def _segment(raw, delimiters, version, budget, header=False):
    segid = raw[:3]
    if not re.fullmatch(r"[A-Z][A-Z0-9]{2}", segid) or len(raw) < 4 or raw[3] != delimiters["field"]:
        raise HL7Error("invalid segment ID or field separator")
    if header:
        _, enc, end = _delimiters(raw)
        values = [delimiters["field"], enc] + _split(raw[end + 1:], delimiters["field"], delimiters["escape"], budget)
    else:
        values = _split(raw[4:], delimiters["field"], delimiters["escape"], budget)
    return {"id": segid, "raw": raw, "fields": [
        _field(value, i, segid, delimiters, version, budget, header and i <= 2)
        for i, value in enumerate(values, 1)]}


def _value(segment, number):
    return segment["fields"][number - 1]["raw"] if len(segment["fields"]) >= number else ""


def _message(lines, budget):
    delimiters, _, end = _delimiters(lines[0])
    parts = _split(lines[0][end + 1:], delimiters["field"], delimiters["escape"], budget)
    if len(parts) < 10 or not parts[6] or not parts[7] or not parts[9]:
        raise HL7Error("MSH must include message type, control ID and version")
    version = parts[9].split(delimiters["component"])[0]
    segments = [_segment(line, delimiters, version, budget, i == 0) for i, line in enumerate(lines)]
    result = {"message_type": _value(segments[0], 9), "control_id": _value(segments[0], 10),
              "version": version, "dictionary_available": _library(version) is not None,
              "delimiters": delimiters, "segments": segments, "attachments": []}
    for i, segment in enumerate(segments):
        if segment["id"] != "OBX" or _value(segment, 2) != "ED":
            continue
        if len(segment["fields"]) < 5:
            raise HL7Error("ED observation lacks OBX-5")
        for j, rep in enumerate(segment["fields"][4]["repetitions"]):
            if len(rep) != 5 or any(len(c) != 1 for c in rep[1:]):
                raise HL7Error("ED requires five components and scalar data/encoding")
            source = delimiters["subcomponent"].join(rep[0])
            kind, subtype, encoding, payload = (c[0] for c in rep[1:])
            if encoding == "Base64":
                binary = base64.b64decode(payload, validate=True)
            elif encoding == "Hex":
                if len(payload) % 2 or not re.fullmatch(r"[0-9A-Fa-f]*", payload):
                    raise HL7Error("invalid ED hexadecimal data")
                binary = bytes.fromhex(payload)
            elif encoding == "A":
                binary = payload.encode("ascii")
            else:
                raise HL7Error(f"unsupported ED encoding {encoding!r}")
            result["attachments"].append({"segment_index": i, "repetition_index": j,
                                          "source_application": source, "type": kind,
                                          "subtype": subtype, "encoding": encoding,
                                          "size": len(binary), "data_base64": base64.b64encode(binary).decode("ascii")})
    decoded = [s for seg in segments for f in seg["fields"] for r in f["repetitions"] for c in r for s in c]
    decoded += [base64.b64decode(a["data_base64"]).decode("latin-1") for a in result["attachments"]]
    result["flags"] = list(dict.fromkeys(flagfmt.TEXT.findall("\n".join(decoded))))
    return result


def _payload(text, budget):
    text = text.replace("\r\n", "\r").replace("\n", "\r")
    if text.endswith("\r"):
        text = text[:-1]
    if not text or any(ord(c) < 32 and c != "\r" for c in text):
        raise HL7Error("empty payload or illegal control character")
    lines = text.split("\r")
    if len(lines) > MAX_SEGMENTS or any(not line for line in lines):
        raise HL7Error("empty segment or too many segments")
    messages, envelopes, current = [], [], []
    file_open = batch_open = False
    file_seen = batch_seen = False
    batch_count = message_count = 0
    envelope_delimiters = None
    def flush():
        nonlocal current, message_count
        if current:
            messages.append(_message(current, budget))
            message_count += 1
            current = []
    for index, line in enumerate(lines):
        segid = line[:3]
        if segid in ("FHS", "BHS", "BTS", "FTS", "MSH"):
            flush()
        if segid == "FHS":
            if index != 0 or file_seen:
                raise HL7Error("misplaced FHS")
            file_open = file_seen = True
            d, _, _ = _delimiters(line)
            envelopes.append(_segment(line, d, "2.5", budget, True))
        elif segid == "BHS":
            if batch_open or (file_seen and not file_open) or (messages and not batch_seen):
                raise HL7Error("misplaced BHS")
            batch_open = batch_seen = True
            batch_count += 1
            message_count = 0
            envelope_delimiters, _, _ = _delimiters(line)
            envelopes.append(_segment(line, envelope_delimiters, "2.5", budget, True))
        elif segid in ("BTS", "FTS"):
            if segid == "BTS":
                if not batch_open:
                    raise HL7Error("BTS without BHS")
                batch_open = False
                d, expected = envelope_delimiters, message_count
            else:
                if not file_open or batch_open or not batch_seen:
                    raise HL7Error("misplaced FTS")
                file_open = False
                d, _, _ = _delimiters(lines[0])
                expected = batch_count
            envelope = _segment(line, d, "2.5", budget)
            count = _value(envelope, 1)
            if count and (not count.isascii() or not count.isdecimal() or int(count) != expected):
                raise HL7Error(f"incorrect {segid} count")
            envelopes.append(envelope)
            if segid == "FTS" and index != len(lines) - 1:
                raise HL7Error("data after FTS")
        elif segid == "MSH":
            if (batch_seen and not batch_open) or (file_seen and not batch_open):
                raise HL7Error("message outside batch")
            current = [line]
        else:
            if not current:
                raise HL7Error("segment outside a message")
            current.append(line)
    flush()
    if file_open or batch_open or not messages:
        raise HL7Error("unclosed or empty batch/file")
    return messages, envelopes


@_closed
def parse_hl7(data, *, encoding="utf-8"):
    """Parse bytes/text, consecutive MLLP blocks, or counted batch envelopes.

    Returns JSON-ready messages, ordered envelope segments and decoded ED bytes
    as Base64. The uniform field hierarchy is repetitions/components/subcomponents.
    Every field also preserves raw source text and explicit-null status.
    """
    if not isinstance(data, (bytes, bytearray, str)):
        raise HL7Error("input must be bytes or text")
    if len(data) > MAX_BYTES:
        raise HL7Error("input exceeds size limit")
    text = bytes(data).decode(encoding) if not isinstance(data, str) else data
    payloads = []
    if text.startswith("\x0b"):
        pos = 0
        while pos < len(text):
            if text[pos] != "\x0b":
                raise HL7Error("bytes between MLLP blocks")
            end = text.find("\x1c\r", pos + 1)
            if end == -1:
                raise HL7Error("truncated MLLP block")
            payloads.append(text[pos + 1:end])
            pos = end + 2
    else:
        payloads = [text]
    budget, messages, envelopes = [MAX_PARTS], [], []
    for payload in payloads:
        msg, env = _payload(payload, budget)
        messages.extend(msg)
        envelopes.extend(env)
    return {"kind": "hl7-v2", "framed": text.startswith("\x0b"), "messages": messages,
            "envelopes": envelopes,
            "flags": list(dict.fromkeys(flag for msg in messages for flag in msg["flags"]))}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path)
    parser.add_argument("--encoding", default="utf-8")
    parser.add_argument("--extract", type=Path, help="save ED payloads with generated filenames")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        with args.file.open("rb") as source:
            data = source.read(MAX_BYTES + 1)
        report = parse_hl7(data, encoding=args.encoding)
        if args.extract:
            args.extract.mkdir(parents=True, exist_ok=True)
            for i, message in enumerate(report["messages"]):
                for j, attachment in enumerate(message["attachments"]):
                    path = args.extract / f"message-{i:04d}-ed-{j:04d}.bin"
                    with path.open("xb") as destination:
                        destination.write(base64.b64decode(attachment["data_base64"]))
        print(json.dumps(report, indent=2, ensure_ascii=True))
        return 0
    except Exception as exc:
        print(f"health2_hl7: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
