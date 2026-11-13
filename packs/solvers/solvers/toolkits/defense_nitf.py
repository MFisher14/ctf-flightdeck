#!/usr/bin/env python3
"""Bounded offline NITF 2.1 headers, segment offsets, text, and file-header TREs.

Sources: MIL-STD-2500C (NITF 2.1); NGA's independent implementation at
https://github.com/ngageoint/sarpy/tree/master/sarpy/io/general/nitf_elements
and https://gdal.org/en/stable/drivers/raster/nitf.html .

This is a structural reader, not an imagery decoder or a security-label policy
validator. It rejects other versions, streaming FL=999999999999, unsupported
reserved header values, incomplete files and trailing bytes. Header-only mode
is explicit and requires exactly HL bytes; payloads are then unverified.
TRE overflow pointers are reported, not followed. Image/graphics/DES/RES
subheaders remain opaque (their offsets and lengths are available).

API malformed inputs raise DefenseNITFError only. No network or execution.
CLI: ./.venv/bin/python solvers/toolkits/defense_nitf.py FILE [--header-only]
"""

from __future__ import annotations

import argparse
import json
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

MAX_BYTES = 64 * 1024 * 1024
MAX_HEADER = 999999
MAX_ITEMS = 4096
_FLAG = flagfmt.BYTES


class DefenseNITFError(ValueError):
    """Malformed, oversized, or unsupported NITF input."""


def _bytes(data: object, cap: int) -> bytes:
    if type(data) not in (bytes, bytearray) or len(data) > cap:
        raise DefenseNITFError("expected bounded bytes or bytearray")
    return bytes(data)


class _Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def take(self, size: int) -> bytes:
        end = self.pos + size
        if size < 0 or end > len(self.data):
            raise DefenseNITFError(f"truncated field at byte {self.pos}")
        result = self.data[self.pos:end]
        self.pos = end
        return result

    def text(self, size: int) -> str:
        raw = self.take(size)
        if any(c < 32 or c > 126 for c in raw):
            raise DefenseNITFError(f"non-BCS-A header field at byte {self.pos-size}")
        return raw.decode("ascii").rstrip(" ")

    def number(self, size: int) -> int:
        raw = self.take(size)
        if not raw or not raw.isdigit():
            raise DefenseNITFError(f"non-decimal field at byte {self.pos-size}")
        return int(raw)


_SECURITY = (
    ("CLAS", 1), ("CLSY", 2), ("CODE", 11), ("CTLH", 2), ("REL", 20),
    ("DCTP", 2), ("DCDT", 8), ("DCXM", 4), ("DG", 1), ("DGDT", 8),
    ("CLTX", 43), ("CATP", 1), ("CAUT", 40), ("CRSN", 1),
    ("SRDT", 8), ("CTLN", 15),
)


def _security(reader: _Reader, prefix: str) -> dict:
    fields = {prefix + name: reader.text(size) for name, size in _SECURITY}
    if fields[prefix + "CLAS"] not in {"U", "R", "C", "S", "T"}:
        raise DefenseNITFError("invalid security classification")
    return fields


def parse_tres(data: bytes) -> list[dict]:
    """Read TRE framing, preserving unknown tags and opaque values as hex.

    Offsets are relative to this supplied TRE area. Semantic TRE dictionaries
    (RPC coefficients, BLOCKA, etc.) are deliberately outside this reader.
    """
    raw = _bytes(data, MAX_HEADER)
    reader = _Reader(raw)
    result = []
    while reader.pos < len(raw):
        if len(result) >= MAX_ITEMS:
            raise DefenseNITFError("too many TREs")
        offset = reader.pos
        tag = reader.text(6)
        if not tag or not tag.isalnum():
            raise DefenseNITFError("invalid TRE tag")
        length = reader.number(5)
        if not 1 <= length <= 99985:
            raise DefenseNITFError("invalid TRE value length")
        value = reader.take(length)
        result.append({"tag": tag, "offset": offset, "length": length,
                       "data_hex": value.hex(),
                       "data_text": value.decode("latin-1")})
    return result


def _extension(reader: _Reader) -> dict:
    length = reader.number(5)
    if length == 0:
        return {"length": 0, "overflow": 0, "tres": []}
    if length < 3:
        raise DefenseNITFError("TRE area length excludes its overflow pointer")
    overflow = reader.number(3)
    start = reader.pos
    tres = parse_tres(reader.take(length - 3))
    for tre in tres:
        tre["offset"] += start
    return {"length": length, "overflow": overflow, "tres": tres}


def _text_segment(raw: bytes, payload: bytes) -> dict:
    reader = _Reader(raw)
    if reader.take(2) != b"TE":
        raise DefenseNITFError("invalid text segment marker")
    fields = {"TEXTID": reader.text(7), "TXTALVL": reader.number(3),
              "TXTDT": reader.text(14), "TXTITL": reader.text(80)}
    fields.update(_security(reader, "TS"))
    if reader.take(1) != b"0":
        raise DefenseNITFError("unsupported encrypted text segment")
    fields["TXTFMT"] = reader.text(3)
    extension = _extension(reader)
    if reader.pos != len(raw):
        raise DefenseNITFError("text subheader length mismatch")
    encoding = {"STA": "ascii", "MTF": "ascii", "UT1": "latin-1", "U8S": "utf-8"}
    if fields["TXTFMT"] not in encoding:
        raise DefenseNITFError("unsupported text encoding")
    try:
        text = payload.decode(encoding[fields["TXTFMT"]])
    except UnicodeError as exc:
        raise DefenseNITFError("invalid text encoding bytes") from exc
    return {"fields": fields, "extension": extension, "text": text}


def parse_nitf(data: bytes, *, header_only: bool = False) -> dict:
    """Return JSON-safe fields, segment offsets, text and literal flag hits.

    Full mode verifies FL, HL, every segment boundary and text subheaders.
    Header-only mode verifies the length table against FL but cannot verify
    segment content. This function never renders or executes image payloads.
    """
    raw = _bytes(data, MAX_BYTES)
    if type(header_only) is not bool:
        raise DefenseNITFError("header_only must be boolean")
    if len(raw) < 360 or raw[:9] != b"NITF02.10":
        raise DefenseNITFError("expected NITF 2.1 header")
    size_reader = _Reader(raw[342:360])
    file_length = size_reader.number(12)
    header_length = size_reader.number(6)
    if file_length == 999999999999:
        raise DefenseNITFError("streaming NITF is unsupported")
    if not 388 <= header_length <= min(MAX_HEADER, len(raw), file_length):
        raise DefenseNITFError("invalid header length")
    if len(raw) != (header_length if header_only else file_length):
        raise DefenseNITFError("file length does not match selected parse mode")
    reader = _Reader(raw[:header_length])
    fields = {"FHDR": reader.text(4), "FVER": reader.text(5),
              "CLEVEL": reader.number(2), "STYPE": reader.text(4),
              "OSTAID": reader.text(10), "FDT": reader.text(14),
              "FTITLE": reader.text(80)}
    if fields["STYPE"] != "BF01":
        raise DefenseNITFError("unsupported standard type")
    fields.update(_security(reader, "FS"))
    fields.update({"FSCOP": reader.number(5), "FSCPYS": reader.number(5),
                   "ENCRYP": reader.text(1), "FBKGC": list(reader.take(3)),
                   "ONAME": reader.text(24), "OPHONE": reader.text(18),
                   "FL": reader.number(12), "HL": reader.number(6)})
    if fields["ENCRYP"] != "0":
        raise DefenseNITFError("unsupported encrypted NITF")
    segments = []
    groups = (("image", "NUMI", 6, 10), ("graphic", "NUMS", 4, 6),
              ("text", "NUMT", 4, 5), ("des", "NUMDES", 4, 9),
              ("res", "NUMRES", 4, 7))
    offset = header_length
    for kind, count_name, sub_digits, data_digits in groups:
        if kind == "text":
            fields["NUMX"] = reader.number(3)
            if fields["NUMX"] != 0:
                raise DefenseNITFError("reserved NUMX must be zero")
        count = reader.number(3)
        fields[count_name] = count
        if count + len(segments) > MAX_ITEMS:
            raise DefenseNITFError("too many segments")
        for index in range(1, count + 1):
            sub_size, data_size = reader.number(sub_digits), reader.number(data_digits)
            if sub_size < 2 or data_size < 1:
                raise DefenseNITFError("invalid segment lengths")
            segment = {"kind": kind, "index": index, "subheader_offset": offset,
                       "subheader_length": sub_size, "data_offset": offset + sub_size,
                       "data_length": data_size}
            offset += sub_size + data_size
            if offset > file_length:
                raise DefenseNITFError("segment extends beyond declared file length")
            segments.append(segment)
    user_header, extended_header = _extension(reader), _extension(reader)
    if reader.pos != header_length or offset != file_length:
        raise DefenseNITFError("header or segment table length mismatch")
    if any(ext["overflow"] > fields["NUMDES"] for ext in (user_header, extended_header)):
        raise DefenseNITFError("TRE overflow pointer exceeds DES count")
    warnings = ["Payloads unverified: header-only mode"] if header_only else []
    if user_header["overflow"] or extended_header["overflow"]:
        warnings.append("TRE overflow pointer reported; overflow DES not decoded")
    if not header_only:
        markers = {"image": b"IM", "graphic": b"SY", "text": b"TE",
                   "des": b"DE", "res": b"RE"}
        for segment in segments:
            start, payload_start = segment["subheader_offset"], segment["data_offset"]
            end = payload_start + segment["data_length"]
            if raw[start:start + 2] != markers[segment["kind"]]:
                raise DefenseNITFError("segment marker does not match length table")
            if segment["kind"] == "text":
                segment["decoded"] = _text_segment(raw[start:payload_start], raw[payload_start:end])
                extension = segment["decoded"]["extension"]
                if extension["overflow"] > fields["NUMDES"]:
                    raise DefenseNITFError("text TRE overflow pointer exceeds DES count")
                for tre in extension["tres"]:
                    tre["offset"] += start
    flags = list(dict.fromkeys(m.decode("latin-1") for m in _FLAG.findall(raw)))
    return {"fields": fields, "segments": segments, "user_header": user_header,
            "extended_header": extended_header, "warnings": warnings, "flags": flags,
            "payloads_present": not header_only}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path)
    parser.add_argument("--header-only", action="store_true",
                        help="input contains exactly HL header bytes; payloads unavailable")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        with args.file.open("rb") as stream:
            raw = stream.read(MAX_BYTES + 1)
        result = parse_nitf(raw, header_only=args.header_only)
        print(json.dumps(result, indent=2))
    except (OSError, ValueError) as exc:
        print(f"defense_nitf: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
