#!/usr/bin/env python3
"""Static device-description inventory: GSD/GSDML, CIP/CANopen EDS, IEC 61850 SCL.

No network, schema fetching, expression evaluation or device operations. This is
an evidence extractor, not a conformance validator. Unknown fields are retained.
Sources: PI GSD/GSDML, CiA 306, ODVA CIP EDS, IEC 61850-6; see lane result.md.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

MAX_INPUT = 16 * 1024 * 1024
MAX_NODES = 100_000
MAX_DEPTH = 64
MAX_RECORDS = 100_000
MAX_NAME = 512
MAX_PATH = 8192
MAX_OUTPUT_CHARS = 16 * 1024 * 1024
_FLAG = flagfmt.TEXT
_SECRET = re.compile(r"(?i)(?:password|passwd|secret|token|api[_-]?key|credential)")


class ParseError(ValueError):
    """Input is malformed, unsupported, ambiguous or exceeds resource limits."""


def _text(data: bytes | str) -> str:
    if not isinstance(data, (bytes, str)):
        raise ParseError("input must be bytes or text")
    if len(data) > MAX_INPUT:
        raise ParseError("input exceeds byte/character limit")
    if isinstance(data, str):
        if len(data.encode("utf-8")) > MAX_INPUT:
            raise ParseError("input exceeds byte limit")
        return data.lstrip("\ufeff")
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16").lstrip("\ufeff")
    if data[:4] in (b"\x00\x00\x00<", b"<\x00\x00\x00"):
        return data.decode("utf-32-be" if data[0] == 0 else "utf-32-le")
    if data[:2] in (b"\x00<", b"<\x00"):
        return data.decode("utf-16-be" if data[0] == 0 else "utf-16-le")
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        # Legacy GSD and EDS commonly use Windows-1252; XML honors its declaration.
        return data.decode("cp1252")


class _Tree(ET.TreeBuilder):
    def __init__(self) -> None:
        super().__init__(insert_comments=True)
        self.depth = 0
        self.count = 0
        self.outer_comments: list[str] = []

    def start(self, tag: str, attrs: dict[str, str]) -> ET.Element:
        self.depth += 1
        self.count += 1
        if self.depth > MAX_DEPTH or self.count > MAX_NODES:
            raise ParseError("XML depth/node limit exceeded")
        if len(tag) > MAX_NAME or any(len(k) > MAX_NAME for k in attrs):
            raise ParseError("XML name limit exceeded")
        for key in ("name", "ID", "id", "inst"):
            if len(attrs.get(key, "")) > MAX_NAME:
                raise ParseError("XML identifier limit exceeded")
        return super().start(tag, attrs)

    def end(self, tag: str) -> ET.Element:
        self.depth -= 1
        return super().end(tag)

    def doctype(self, name: str, pubid: str, system: str) -> None:
        raise ParseError("DTD and entity declarations are forbidden")

    def comment(self, text: str) -> ET.Element:
        self.count += 1
        if self.count > MAX_NODES:
            raise ParseError("XML node limit exceeded")
        if self.depth == 0:
            self.outer_comments.append(text)
        return super().comment(text)


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _base(kind: str) -> dict[str, Any]:
    return {"format": kind, "metadata": {}, "records": [], "comments": [],
            "strings": [], "flags": [], "secret_candidates": []}


def _finish(out: dict[str, Any]) -> dict[str, Any]:
    strings = list(dict.fromkeys(s for s in out["strings"] if s))
    out["strings"] = strings
    out["flags"] = sorted({m.group() for text in strings for m in _FLAG.finditer(text)})
    for rec in out["records"]:
        key = rec.get("key", rec.get("tag", ""))
        value = rec.get("value", rec.get("text", ""))
        if _SECRET.search(key) or _SECRET.search(value):
            out["secret_candidates"].append(rec.copy())
        elif any(_SECRET.search(k) or _SECRET.search(v) for k, v in rec.get("attributes", {}).items()):
            out["secret_candidates"].append(rec.copy())
    for comment in out["comments"]:
        if _SECRET.search(comment["text"]):
            out["secret_candidates"].append({"kind": "comment", **comment})
    return out


def _xml(data: bytes | str, kind: str) -> dict[str, Any]:
    builder = _Tree()
    root = ET.fromstring(data, parser=ET.XMLParser(target=builder))
    rootname = _local(root.tag)
    detected = {"ISO15745Profile": "gsdml", "SCL": "scl"}.get(rootname)
    if detected is None or kind not in ("auto", detected):
        raise ParseError("XML root does not match a supported device format")
    out = _base(detected)
    out.update({"devices": [], "modules": [], "parameters": [], "networks": [],
                "addresses": [], "logical_nodes": [], "datasets": [],
                "controls": [], "values": [], "texts": []})
    for comment in builder.outer_comments:
        out["comments"].append({"path": "/", "text": comment})
        out["strings"].append(comment)
    output_chars = sum(len(s) for s in builder.outer_comments)
    stack = [(root, "", {}, "")]
    while stack:
        el, parent_path, inherited, suffix = stack.pop()
        if el.tag is ET.Comment:
            out["comments"].append({"path": parent_path, "text": el.text or ""})
            out["strings"].append(el.text or "")
            continue
        tag = _local(el.tag)
        attrs = dict(el.attrib)
        ident = attrs.get("name", attrs.get("ID", attrs.get("id", attrs.get("inst", ""))))
        path = parent_path + "/" + tag + ("[" + ident + "]" if ident else "") + suffix
        if len(path) > MAX_PATH:
            raise ParseError("XML path limit exceeded")
        context = dict(inherited)
        for context_tag, attr, name in (("IED", "name", "ied"), ("AccessPoint", "name", "ap"),
                                      ("LDevice", "inst", "ld"), ("SubNetwork", "name", "network")):
            if tag == context_tag:
                context[name] = attrs.get(attr, "")
        if tag == "ConnectedAP":
            context.update(ied=attrs.get("iedName", ""), ap=attrs.get("apName", ""))
        if tag in ("LN", "LN0"):
            context["ln"] = attrs.get("prefix", "") + attrs.get("lnClass", "") + attrs.get("inst", "")
        if tag in ("GSE", "SMV"):
            context.update(ld=attrs.get("ldInst", ""), control=attrs.get("cbName", ""))
        if tag == "DataSet":
            context["dataset"] = attrs.get("name", "")
        text = (el.text or "").strip()
        output_chars += len(path) + len(text) + sum(len(k) + len(v) for k, v in attrs.items())
        if output_chars > MAX_OUTPUT_CHARS:
            raise ParseError("XML output budget exceeded")
        rec = {"path": path, "tag": tag, "attributes": attrs, "text": text, **context}
        out["records"].append(rec)
        out["strings"].extend([text, (el.tail or "").strip(), *attrs.values()])
        if tag in ("DeviceIdentity", "IED"):
            out["devices"].append(rec.copy())
        if tag == "DeviceIdentity":
            out["metadata"].update(attrs)
        if tag == "Header":
            out["metadata"].update(attrs)
        if tag in ("DeviceAccessPointItem", "ModuleItem", "SubmoduleItem", "VirtualSubmoduleItem"):
            module = rec.copy()
            module["text_refs"] = [n.get("TextId") for n in el.iter() if n.tag is not ET.Comment and n.get("TextId")]
            output_chars += sum(len(s) for s in module["text_refs"])
            if output_chars > MAX_OUTPUT_CHARS:
                raise ParseError("XML output budget exceeded")
            out["modules"].append(module)
        if tag in ("ParameterRecordDataItem", "Ref", "Const", "DataItem"):
            out["parameters"].append(rec.copy())
        if tag == "Text" and "TextId" in attrs:
            out["texts"].append(rec.copy())
        if tag == "SubNetwork":
            out["networks"].append(rec.copy())
        if tag == "P":
            out["addresses"].append({**rec, "type": attrs.get("type", ""), "value": text})
        if tag in ("LN", "LN0"):
            out["logical_nodes"].append(rec.copy())
        if tag == "DataSet":
            out["datasets"].append({**rec, "members": [dict(n.attrib) for n in el if n.tag is not ET.Comment and _local(n.tag) == "FCDA"]})
        if tag in ("GSEControl", "SampledValueControl", "ReportControl"):
            out["controls"].append(rec.copy())
        if tag == "Val":
            out["values"].append(rec.copy())
        children = list(el)
        signatures = []
        for child in children:
            ident = next((child.get(k) for k in ("name", "ID", "id", "inst") if child.get(k)), "")
            signatures.append((child.tag, ident))
        totals: dict[tuple, int] = {}
        for signature in signatures:
            totals[signature] = totals.get(signature, 0) + 1
        seen: dict[tuple, int] = {}
        entries = []
        for child, signature in zip(children, signatures):
            seen[signature] = seen.get(signature, 0) + 1
            ordinal = f"[{seen[signature]}]" if totals[signature] > 1 else ""
            entries.append((child, path, context, ordinal))
        stack.extend(reversed(entries))
    return _finish(out)


def _strip_comment(line: str, marker: str) -> tuple[str, str]:
    quoted = False
    escaped = False
    for i, ch in enumerate(line):
        if escaped:
            escaped = False
        elif ch == "\\" and quoted:
            escaped = True
        elif ch == '"':
            quoted = not quoted
        elif ch == marker and not quoted:
            return line[:i], line[i + 1:]
    return line, ""


def _check_quotes(value: str) -> None:
    quoted = False
    escaped = False
    for ch in value:
        if escaped:
            escaped = False
        elif ch == "\\" and quoted:
            escaped = True
        elif ch == '"':
            quoted = not quoted
    if quoted:
        raise ParseError("unterminated quoted string")


def _add(out: dict[str, Any], section: str, key: str, value: str, line: int) -> None:
    if len(out["records"]) >= MAX_RECORDS:
        raise ParseError("record limit exceeded")
    _check_quotes(value)
    out["records"].append({"section": section, "key": key, "value": value, "line": line})
    out["strings"].append(value)


def _gsd(text: str) -> dict[str, Any]:
    out = _base("gsd")
    pending = ""
    found_header = False
    for lineno, raw in enumerate(text.splitlines(), 1):
        line, comment = _strip_comment(raw, ";")
        if comment:
            out["comments"].append({"line": lineno, "text": comment})
            out["strings"].append(comment)
        line = line.strip()
        if not line:
            continue
        if line.endswith("\\"):
            pending += line[:-1]
            continue
        line, pending = pending + line, ""
        if not found_header:
            if line.lower() not in ("#profibus_dp", "#profibus-dp"):
                raise ParseError("GSD must begin with #Profibus_DP")
            found_header = True
            continue
        if "=" in line:
            key, value = (x.strip() for x in line.split("=", 1))
            if not re.fullmatch(r"[\w.]+(?:\([^()\r\n]*\))?", key) or not value:
                raise ParseError("malformed GSD assignment")
            _add(out, "", key, value, lineno)
        elif re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", line):
            _add(out, "", line, "", lineno)
        else:
            raise ParseError("malformed GSD statement")
    if pending or not found_header or not out["records"]:
        raise ParseError("incomplete GSD")
    return _finish(out)


def _canopen(text: str) -> dict[str, Any]:
    out = _base("canopen-eds")
    section = ""
    sections: set[str] = set()
    keys: set[tuple[str, str]] = set()
    for lineno, raw in enumerate(text.splitlines(), 1):
        line, comment = _strip_comment(raw, ";")
        line = line.strip()
        if comment:
            out["comments"].append({"line": lineno, "text": comment})
            out["strings"].append(comment)
        if not line:
            continue
        if line.startswith("["):
            if not re.fullmatch(r"\[[^\[\]\r\n]+\]", line):
                raise ParseError("malformed EDS section")
            section = line[1:-1]
            if section.casefold() in sections:
                raise ParseError("duplicate CANopen section")
            sections.add(section.casefold())
            continue
        if not section or "=" not in line:
            raise ParseError("EDS field outside section or missing assignment")
        key, value = (x.strip() for x in line.split("=", 1))
        pair = (section.casefold(), key.casefold())
        if not key or pair in keys:
            raise ParseError("empty/duplicate CANopen field")
        keys.add(pair)
        _add(out, section, key, value, lineno)
    if not sections.intersection({"deviceinfo", "fileinfo"}) or not out["records"]:
        raise ParseError("not a CANopen EDS/DCF")
    out["objects"] = []
    grouped: dict[str, dict[str, str]] = {}
    for rec in out["records"]:
        grouped.setdefault(rec["section"], {})[rec["key"]] = rec["value"]
    for section, fields in grouped.items():
        match = re.fullmatch(r"([0-9a-fA-F]{4})(?:sub([0-9a-fA-F]{1,2}))?", section, re.I)
        if match:
            out["objects"].append({"index": int(match[1], 16), "subindex": int(match[2], 16) if match[2] else None,
                                   "fields": fields})
        elif section.casefold() in ("deviceinfo", "fileinfo", "devicecommissioning", "devicecomissioning"):
            out["metadata"][section] = fields
    if sections.intersection({"devicecommissioning", "devicecomissioning"}):
        out["format"] = "canopen-dcf"
    return _finish(out)


def _cip(text: str) -> dict[str, Any]:
    out = _base("cip-eds")
    clean = []
    for lineno, line in enumerate(text.splitlines(), 1):
        body, comment = _strip_comment(line, "$")
        clean.append(body)
        if comment:
            out["comments"].append({"line": lineno, "text": comment})
            out["strings"].append(comment)
    text = "\n".join(clean)
    section = ""
    sections: set[str] = set()
    i = 0
    lineno = 1
    while i < len(text):
        if text[i].isspace():
            lineno += text[i] == "\n"
            i += 1
            continue
        if text[i] == "[":
            end = text.find("]", i + 1)
            if end < 0 or "\n" in text[i:end]:
                raise ParseError("malformed CIP EDS section")
            section = text[i + 1:end].strip()
            if not section:
                raise ParseError("empty CIP EDS section")
            sections.add(section.casefold())
            i = end + 1
            continue
        if not section:
            raise ParseError("CIP EDS field outside section")
        start, startline = i, lineno
        quoted = escaped = False
        while i < len(text):
            ch = text[i]
            if ch == "\n":
                lineno += 1
            if escaped:
                escaped = False
            elif ch == "\\" and quoted:
                escaped = True
            elif ch == '"':
                quoted = not quoted
            elif ch == ";" and not quoted:
                break
            i += 1
        if i == len(text) or quoted:
            raise ParseError("unterminated CIP EDS statement")
        statement = text[start:i].strip()
        i += 1
        if "=" not in statement:
            raise ParseError("missing CIP EDS assignment")
        key, value = (x.strip() for x in statement.split("=", 1))
        if not re.fullmatch(r"[A-Za-z0-9_]+", key):
            raise ParseError("malformed CIP EDS key")
        _add(out, section, key, value, startline)
        if section.casefold() in ("file", "device", "device classification"):
            out["metadata"].setdefault(section, {})[key] = value
    if not {"file", "device"}.issubset(sections) or not out["records"]:
        raise ParseError("CIP EDS requires File and Device sections")
    return _finish(out)


def parse(data: bytes | str, *, kind: str = "auto") -> dict[str, Any]:
    """Extract device descriptions; all malformed input raises only ParseError.

    kind: auto, gsd, gsdml, scl (CID/ICD/SCD/IID), canopen, cip.
    Raw values remain raw: no numeric coercion, $NODEID substitution or execution.
    """
    try:
        if kind not in ("auto", "gsd", "gsdml", "scl", "canopen", "cip"):
            raise ParseError("unsupported device format")
        text = _text(data)
        if not text.strip() or "\x00" in text:
            raise ParseError("empty or binary device description")
        if kind in ("gsdml", "scl") or (kind == "auto" and text.lstrip().startswith("<")):
            return _xml(data, kind)
        if kind == "auto":
            if re.search(r"(?im)^\s*#profibus[_-]dp\s*(?:;[^\r\n]*)?$", text):
                kind = "gsd"
            elif re.search(r"(?im)^\s*\[(?:FileInfo|DeviceInfo)\]\s*(?:;[^\r\n]*)?$", text):
                kind = "canopen"
            elif re.search(r"(?im)^\s*\[File\]\s*(?:\$[^\r\n]*)?$", text):
                kind = "cip"
            else:
                raise ParseError("unrecognized device description")
        return {"gsd": _gsd, "canopen": _canopen, "cip": _cip}[kind](text)
    except ParseError:
        raise
    except (ValueError, TypeError, UnicodeError, LookupError, ET.ParseError, RecursionError, OverflowError) as exc:
        raise ParseError("malformed device description") from exc


def parse_file(path: str | Path, *, kind: str = "auto") -> dict[str, Any]:
    """Read a bounded local file only; no linked references are followed."""
    try:
        if not isinstance(path, (str, Path)):
            raise ParseError("path must be text or a pathlib.Path")
        with open(path, "rb") as handle:
            data = handle.read(MAX_INPUT + 1)
        return parse(data, kind=kind)
    except ParseError:
        raise
    except (OSError, ValueError, TypeError) as exc:
        raise ParseError("cannot read device description") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file")
    parser.add_argument("--kind", choices=("auto", "gsd", "gsdml", "scl", "canopen", "cip"), default="auto")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        print(json.dumps(parse_file(args.file, kind=args.kind), indent=2, ensure_ascii=True))
        return 0
    except ParseError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
