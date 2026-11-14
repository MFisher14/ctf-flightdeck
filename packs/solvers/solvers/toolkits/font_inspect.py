#!/usr/bin/env python3
"""Inspect a TTF/OTF font for hidden data — name-table strings and table anomalies, offline.

Flags are frequently tucked into a font's `name` table (family/copyright/version/custom name records)
or an unexpected table, where opening the font in a viewer never shows them.  This parses the SFNT
table directory and the `name` table in pure Python (no fontTools), extracts every name string, and
flag-scans them plus the whole file.  Read-only, offline, ranked findings — never submits.
"""
from __future__ import annotations

import argparse
import struct
import sys
from typing import Iterable

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

MAX_INPUT = 1 << 24
MAX_TABLES = 4096
MAX_NAMES = 8192
_FLAG = flagfmt.BYTES

# nameID -> meaning (the common ones; others are reported by number).
_NAME_IDS = {0: "copyright", 1: "family", 2: "subfamily", 3: "unique_id", 4: "full_name",
             5: "version", 6: "postscript_name", 7: "trademark", 8: "manufacturer", 9: "designer",
             10: "description", 11: "vendor_url", 12: "designer_url", 13: "license", 14: "license_url"}


class FontError(Exception):
    """Malformed font — fail closed."""


def _decode_name(raw: bytes, platform_id: int, encoding_id: int) -> str:
    # platform 3 (Windows) and platform 0 (Unicode) store UTF-16BE; platform 1 (Mac) is usually Mac-Roman.
    if platform_id in (0, 3):
        try:
            return raw.decode("utf-16-be", "replace")
        except Exception:
            return raw.decode("latin-1", "replace")
    try:
        return raw.decode("mac-roman") if platform_id == 1 else raw.decode("latin-1", "replace")
    except Exception:
        return raw.decode("latin-1", "replace")


def _parse_name_table(data: bytes, off: int, length: int) -> list[dict]:
    if off + 6 > len(data):
        return []
    fmt, count, string_off = struct.unpack_from(">HHH", data, off)
    if count > MAX_NAMES:
        return []
    storage = off + string_off
    names = []
    rec = off + 6
    for _ in range(count):
        if rec + 12 > len(data):
            break
        pid, eid, lid, nid, nlen, noff = struct.unpack_from(">HHHHHH", data, rec)
        rec += 12
        start = storage + noff
        if start < 0 or start + nlen > len(data) or nlen == 0:
            continue
        text = _decode_name(data[start:start + nlen], pid, eid)
        names.append({"platform": pid, "encoding": eid, "language": lid,
                      "name_id": nid, "name": _NAME_IDS.get(nid, f"id_{nid}"), "text": text})
    return names


def inspect(data: object) -> dict:
    """Parse an SFNT (TTF/OTF) font. Returns {sfnt, tables, names, flags, anomalies} or fails closed."""
    if not isinstance(data, (bytes, bytearray)):
        raise FontError("font data must be bytes")
    data = bytes(data)
    if len(data) < 12 or len(data) > MAX_INPUT:
        raise FontError("input too short/large for a font")
    magic = data[:4]
    base = 0
    if magic == b"ttcf":            # font collection: inspect the first font
        if len(data) < 16:
            raise FontError("truncated TTC header")
        base = struct.unpack_from(">I", data, 12)[0]
        if base + 12 > len(data):
            raise FontError("TTC first-font offset out of range")
    elif magic == b"wOFF":
        raise FontError("WOFF is compressed — decompress to SFNT first (not handled here)")
    elif magic not in (b"\x00\x01\x00\x00", b"OTTO", b"true", b"typ1"):
        raise FontError("not an SFNT/TTF/OTF font (bad magic)")
    num_tables = struct.unpack_from(">H", data, base + 4)[0]
    if num_tables > MAX_TABLES or base + 12 + num_tables * 16 > len(data):
        raise FontError("implausible table count")
    tables = []
    names = []
    for i in range(num_tables):
        rec = base + 12 + i * 16
        tag, _checksum, off, length = struct.unpack_from(">4sIII", data, rec)
        tables.append({"tag": tag.decode("latin-1", "replace"), "offset": off, "length": length})
        if tag == b"name" and 0 <= off < len(data):
            names = _parse_name_table(data, off, length)
    anomalies = []
    for t in tables:
        if t["offset"] + t["length"] > len(data):
            anomalies.append(f"table {t['tag']!r} extends past EOF (off={t['offset']}, len={t['length']})")
    # trailing data after the last table is a classic hiding spot
    end = max((t["offset"] + t["length"] for t in tables), default=0)
    if 0 < end < len(data) - 4:
        anomalies.append(f"{len(data) - end} bytes of trailing data after the last table")
    flags = sorted({m.group(0).decode("latin-1") for m in _FLAG.finditer(data)}
                   | {n["text"] for n in names if _FLAG.search(n["text"].encode("latin-1", "replace"))})
    return {"sfnt": magic.decode("latin-1", "replace"), "tables": tables, "names": names,
            "flags": flags, "anomalies": anomalies}


def main(argv: Iterable[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Inspect a TTF/OTF font for hidden data (name table + "
                                            "anomalies; offline, read-only).")
    p.add_argument("file")
    p.add_argument("--json", action="store_true")
    try:
        a = p.parse_args(list(argv) if argv is not None else None)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        with open(a.file, "rb") as fh:
            data = fh.read(MAX_INPUT + 1)
        report = inspect(data)
    except (OSError, FontError) as exc:
        print(f"font_inspect: {exc}", file=sys.stderr)
        return 1
    if a.json:
        import json
        print(json.dumps(report, indent=1))
    else:
        print(f"sfnt={report['sfnt']!r}  tables={len(report['tables'])}  names={len(report['names'])}")
        for n in report["names"]:
            print(f"  [{n['name']:14}] {n['text'][:120]}")
        for anom in report["anomalies"]:
            print(f"  ! {anom}")
        for f in report["flags"]:
            print(f"  FLAG: {f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
