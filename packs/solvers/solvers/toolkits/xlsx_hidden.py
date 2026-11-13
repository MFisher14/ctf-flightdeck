#!/usr/bin/env python3
"""Surface hidden/very-hidden sheets, defined-name values and their cell text from an .xlsx, offline.

A classic spreadsheet trick: a worksheet is marked `state="hidden"` or `state="veryHidden"` in
xl/workbook.xml (very-hidden sheets can't even be unhidden from Excel's UI), or the flag is parked in
a workbook-scoped defined name.  The BIFF8 (.xls 97-2003) path lives in `maldoc.py`; this handles the
modern OOXML (.xlsx/.xlsm, a ZIP of XML) container, extracting the hidden sheets' actual cell values
(shared + inline strings), not just their names.  Pure stdlib (zipfile + ElementTree), read-only,
ranked findings — never submits.
"""
from __future__ import annotations

import argparse
import io
import sys
import zipfile
from typing import Iterable
from xml.etree import ElementTree as ET

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

MAX_INPUT = 1 << 26
MAX_UNCOMPRESSED = 1 << 28
_FLAG = flagfmt.TEXT


class XlsxError(Exception):
    """Not a readable .xlsx / zip-bomb guard tripped — fail closed."""


def _local(tag: str) -> str:
    return tag.rpartition("}")[2]  # strip the {namespace}


def _attr(el: ET.Element, name: str) -> str | None:
    # match an attribute by local name regardless of namespace prefix (r:id etc.)
    for k, v in el.attrib.items():
        if _local(k) == name:
            return v
    return None


def _xml(zf: zipfile.ZipFile, path: str) -> ET.Element | None:
    try:
        info = zf.getinfo(path)
    except KeyError:
        return None
    if info.file_size > MAX_UNCOMPRESSED:
        raise XlsxError(f"{path} is implausibly large ({info.file_size} bytes)")
    try:
        with zf.open(info) as fh:
            return ET.parse(fh).getroot()
    except (ET.ParseError, OSError, zipfile.BadZipFile) as exc:
        raise XlsxError(f"{path}: {exc}") from exc


def _shared_strings(zf: zipfile.ZipFile) -> list[str]:
    root = _xml(zf, "xl/sharedStrings.xml")
    if root is None:
        return []
    out = []
    for si in root:
        if _local(si.tag) != "si":
            continue
        # a shared string is either a single <t> or several <r><t> runs
        parts = [t.text or "" for t in si.iter() if _local(t.tag) == "t"]
        out.append("".join(parts))
    return out


def _sheet_text(zf: zipfile.ZipFile, part: str, shared: list[str]) -> list[str]:
    root = _xml(zf, part)
    if root is None:
        return []
    values = []
    for c in root.iter():
        if _local(c.tag) != "c":
            continue
        ctype = _attr(c, "t")
        if ctype == "inlineStr":
            txt = "".join(t.text or "" for t in c.iter() if _local(t.tag) == "t")
            if txt:
                values.append(txt)
            continue
        v = next((e for e in c if _local(e.tag) == "v"), None)
        if v is None or v.text is None:
            continue
        if ctype == "s":                       # shared-string index
            try:
                values.append(shared[int(v.text)])
            except (ValueError, IndexError):
                pass
        else:                                  # number / bool / formula-cached
            values.append(v.text)
    return values


def inspect(data: object) -> dict:
    """Parse an .xlsx. Returns {sheets, defined_names, flags} or fails closed. Each sheet carries its
    name, visibility state, and (for hidden/very-hidden sheets) the extracted cell text."""
    if not isinstance(data, (bytes, bytearray)):
        raise XlsxError("xlsx data must be bytes")
    data = bytes(data)
    if len(data) < 22 or len(data) > MAX_INPUT:      # 22 = minimum empty-zip EOCD
        raise XlsxError("input too short/large for an .xlsx")
    if data[:2] != b"PK":
        raise XlsxError("not a ZIP/OOXML container (bad magic)")
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise XlsxError(f"bad zip: {exc}") from exc
    with zf:
        total = sum(i.file_size for i in zf.infolist())
        if total > MAX_UNCOMPRESSED:
            raise XlsxError("decompressed size exceeds the zip-bomb cap")
        wb = _xml(zf, "xl/workbook.xml")
        if wb is None:
            raise XlsxError("no xl/workbook.xml — not a spreadsheet package")
        rels = _xml(zf, "xl/_rels/workbook.xml.rels")
        rid_to_target = {}
        if rels is not None:
            for r in rels:
                rid, tgt = _attr(r, "Id"), _attr(r, "Target")
                if rid and tgt:
                    tgt = tgt.lstrip("/")
                    rid_to_target[rid] = tgt if tgt.startswith("xl/") else "xl/" + tgt
        shared = _shared_strings(zf)
        sheets, defined = [], []
        for el in wb.iter():
            lt = _local(el.tag)
            if lt == "sheet":
                rid = _attr(el, "id")
                part = rid_to_target.get(rid or "")
                state = _attr(el, "state") or "visible"
                entry = {"name": _attr(el, "name"), "sheet_id": _attr(el, "sheetId"),
                         "state": state, "part": part}
                if state in ("hidden", "veryHidden") and part:
                    entry["cells"] = _sheet_text(zf, part, shared)
                sheets.append(entry)
            elif lt == "definedName":
                defined.append({"name": _attr(el, "name"), "value": (el.text or "").strip()})
        # flag-scan: sheet names, hidden-sheet cell text, defined-name values
        blob = []
        for s in sheets:
            if s.get("name"):
                blob.append(s["name"])
            blob.extend(s.get("cells", []))
        for d in defined:
            blob.append(d["value"])
            if d["name"]:
                blob.append(d["name"])
        flags = sorted({m.group(0) for s in blob for m in _FLAG.finditer(s)})
        return {"sheets": sheets, "defined_names": defined, "flags": flags}


def main(argv: Iterable[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Surface hidden/very-hidden sheets, defined names and their "
                                            "cell text from an .xlsx (offline, read-only).")
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
    except (OSError, XlsxError) as exc:
        print(f"xlsx_hidden: {exc}", file=sys.stderr)
        return 1
    if a.json:
        import json
        print(json.dumps(report, indent=1))
    else:
        for s in report["sheets"]:
            mark = "" if s["state"] == "visible" else f"  <<{s['state'].upper()}>>"
            print(f"sheet {s['name']!r} (id={s['sheet_id']}){mark}")
            for cell in s.get("cells", []):
                print(f"    {cell[:120]}")
        for d in report["defined_names"]:
            print(f"defined name {d['name']!r} = {d['value'][:120]}")
        for f in report["flags"]:
            print(f"  FLAG: {f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
