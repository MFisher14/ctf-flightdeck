#!/usr/bin/env python3
"""Bounded offline vendor XML export evidence extraction (never execute/import code).

TwinCAT objects/project references, PLCopen project/interface data, Schneider
XEF source/data blocks, and readable CODESYS .export TextLines are supported.
This is an evidence extractor, not schema validation, decompilation, or the
PLC language/dataflow analysis already provided by plc_logic_depth.py. Native
.project, STU, ACD, and compiled/protected content are deliberately unsupported.
Every public parsing failure is ExportError; XML DTDs are always rejected.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

MAX_INPUT = 16 * 1024 * 1024
MAX_NODES = 50_000
MAX_DEPTH = 64
MAX_ATTRIBUTES = 200_000
MAX_EVIDENCE = 64 * 1024 * 1024
MAX_PATH_TOTAL = 16 * 1024 * 1024


class ExportError(ValueError):
    """Invalid, unsupported, or over-limit vendor XML export."""


class _BoundedTree(ET.TreeBuilder):
    def __init__(self):
        super().__init__(insert_comments=True)
        self.depth = 0
        self.nodes = 0
        self.attributes = 0
        self.document_comments = []

    def start(self, tag, attrs):
        if len(tag) > 512 or any(len(key) > 512 for key in attrs):
            raise ExportError("XML name length cap exceeded")
        self.depth += 1
        self.nodes += 1
        self.attributes += len(attrs)
        if self.depth > MAX_DEPTH or self.nodes > MAX_NODES or self.attributes > MAX_ATTRIBUTES:
            raise ExportError("XML depth/node/attribute cap exceeded")
        return super().start(tag, attrs)

    def end(self, tag):
        result = super().end(tag)
        self.depth -= 1
        return result

    def comment(self, text):
        self.nodes += 1
        if self.nodes > MAX_NODES:
            raise ExportError("XML node cap exceeded")
        if self.depth == 0:
            self.document_comments.append(text)
            return None
        return super().comment(text)

    def doctype(self, name, pubid, system):
        # Parser callback operates on decoded markup, including UTF-16 input.
        raise ExportError("DTD/entity declarations are forbidden")


def _local(tag):
    return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else "#comment"


def _text(element):
    # XML comments are distinct evidence, never PLC source. Their tails remain
    # source text and must survive: <ST>a<!-- note -->b</ST> becomes "ab".
    if not isinstance(element.tag, str):
        return element.text or ""
    pieces = [element.text or ""]
    for child in element:
        if isinstance(child.tag, str):
            pieces.append(_text(child))
        pieces.append(child.tail or "")
    return "".join(pieces)


def _children(element, name):
    return [child for child in element if _local(child.tag) == name]


def _first(element, name):
    return next((child for child in element if _local(child.tag) == name), None)


def _kind(root, name):
    tag = _local(root.tag)
    if tag in {"TcPlcObject", "TcSmProject", "TwinCATProject"}:
        return "twincat-xml"
    if tag == "Project" and (name.lower().endswith((".plcproj", ".tsproj"))
                             or any(_local(e.tag) == "PlcProjectOptions" for e in root.iter())):
        return "twincat-xml"
    if tag == "project" and ("plcopen.org/xml/tc6" in root.tag
                              or (_first(root, "fileHeader") is not None
                                  and _first(root, "types") is not None)):
        return "plcopen-xml"
    if tag in {"FEFExchangeFile", "XEFExchangeFile"}:
        return "schneider-xef"
    if tag == "ExportFile" and _first(root, "StructuredView") is not None:
        return "codesys-export-xml"
    raise ExportError("unsupported XML root; supply a readable vendor export")


def _index(root):
    """Paths are evidence labels, not XPath expressions and never opened as files."""
    records = []
    path_total = 0
    stack = [(root, "/" + _local(root.tag) + "[1]", ())]
    while stack:
        element, path, ancestors = stack.pop()
        path_total += len(path)
        if len(path) > 8192 or path_total > MAX_PATH_TOTAL:
            raise ExportError("XML path evidence cap exceeded")
        records.append((element, path, ancestors))
        counts = {}
        children = []
        for child in element:
            tag = _local(child.tag)
            counts[tag] = counts.get(tag, 0) + 1
            children.append((child, f"{path}/{tag}[{counts[tag]}]", ancestors + (element,)))
        stack.extend(reversed(children))
    return records


def _scope(ancestors):
    parts = []
    for element in ancestors:
        tag = _local(element.tag)
        if tag in {"pou", "POU", "Method", "Action", "Property", "GVL", "DUT", "configuration", "resource", "dataType"}:
            value = element.get("name", element.get("Name", ""))
            parts.append(f"{tag}:{value}")
        elif tag == "program":
            ident = _first(element, "identProgram")
            value = ident.get("name", "") if ident is not None else element.get("name", "")
            parts.append(f"program:{value}")
    return "/".join(parts) or "project"


def _shape(element):
    # Bounded by the XML tree cap. Preserve array dimensions and compound values
    # without pretending to evaluate IEC expressions or flattening field names.
    return {"kind": _local(element.tag), "attributes": dict(element.attrib),
            "text": element.text or "", "children": [_shape(e) for e in element if isinstance(e.tag, str)]}


def _type_name(element):
    if element is None:
        return None
    children = [e for e in element if isinstance(e.tag, str)]
    if not children:
        return None
    item = children[0]
    kind = _local(item.tag)
    return item.get("name") if kind == "derived" else kind


class _EvidenceList(list):
    """Share a conservative serialized output budget across evidence collections."""
    def __init__(self, budget):
        super().__init__()
        self.budget = budget

    def append(self, value):
        size = len(json.dumps(value, ensure_ascii=True))
        self.budget[0] += size
        if self.budget[0] > MAX_EVIDENCE:
            raise ExportError("XML evidence output cap exceeded")
        super().append(value)


def _extract(root, name, document_comments):
    kind = _kind(root, name)
    out = {"format": kind, "source": name, "metadata": dict(root.attrib),
           "objects": [], "declarations": [], "logic": [], "variables": [],
           "references": [], "comments": [], "strings": [], "findings": [],
           "limitations": ["Static evidence only; no schema validation or PLC execution."]}
    budget = [0]
    for key in ("objects", "declarations", "logic", "variables", "references", "comments", "strings", "findings"):
        out[key] = _EvidenceList(budget)
    if kind == "codesys-export-xml":
        out["limitations"].append("Readable XML TextLines only; typed object payloads are not deserialized.")
    elif kind == "twincat-xml":
        out["limitations"].append("Project references are reported but never followed; provide each referenced object separately.")
    records = [(ET.Comment(text), f"/document-comment[{index}]", ())
               for index, text in enumerate(document_comments, 1)] + _index(root)
    for element, path, ancestors in records:
        tag = _local(element.tag)
        scope = _scope(ancestors)
        # Preserve every readable leaf/attribute, including unknown extensions.
        if element.text and element.text.strip():
            out["strings"].append({"path": path, "value": element.text})
        if element.tail and element.tail.strip():
            out["strings"].append({"path": path + "/tail()", "value": element.tail})
        for key, value in element.attrib.items():
            out["strings"].append({"path": path + "/@" + key, "value": value})
        if tag in {"#comment", "comment", "Comment", "documentation", "Description"}:
            out["comments"].append({"path": path, "scope": scope, "text": _text(element)})
        field_name = element.get("name", element.get("Name", ""))
        if re.search(r"(?i)(?:password|passwd|secret|token|api[_-]?key)", field_name):
            for child in element.iter():
                for attribute in ("value", "Value"):
                    if child.get(attribute):
                        out["findings"].append({"kind": "secret-field", "path": path,
                                                "key": field_name, "value": child.get(attribute)})
            if element.text and element.text.strip():
                out["findings"].append({"kind": "secret-field", "path": path,
                                        "key": field_name, "value": element.text})
        if tag in {"fileHeader", "contentHeader"}:
            out["metadata"][tag] = dict(element.attrib)
        if tag in {"pou", "POU", "Method", "Action", "Property", "GVL", "DUT", "dataType", "identProgram"}:
            out["objects"].append({"path": path, "scope": scope, "kind": tag,
                                   "name": element.get("name", element.get("Name", "")),
                                   "attributes": dict(element.attrib)})
        if kind == "twincat-xml":
            if tag == "Declaration":
                out["declarations"].append({"path": path, "scope": scope, "text": _text(element)})
            if tag in {"ST", "IL"} and ancestors and _local(ancestors[-1].tag) == "Implementation":
                out["logic"].append({"path": path, "scope": scope, "language": tag, "text": _text(element)})
            if tag in {"Compile", "ProjectReference", "Content", "None", "Project", "PlcProject"}:
                for key in ("Include", "PrjFilePath", "File", "FileName"):
                    if element.get(key):
                        out["references"].append({"path": path + "/@" + key, "target": element.get(key)})
            if tag in {"ProjectPath", "FileName"} and element.text:
                out["references"].append({"path": path, "target": element.text})
        elif kind == "plcopen-xml":
            if tag == "variable" and element.get("name") and ancestors and _local(ancestors[-1].tag).endswith("Vars"):
                typ = _first(element, "type")
                init = _first(element, "initialValue")
                out["variables"].append({"path": path, "scope": scope, "name": element.get("name"),
                    "section": _local(ancestors[-1].tag), "address": element.get("address"),
                    "type": _type_name(typ), "type_tree": _shape(typ) if typ is not None else None,
                    "initial_value": _shape(init) if init is not None else None})
            if tag in {"ST", "IL"} and ancestors and _local(ancestors[-1].tag) == "body":
                out["logic"].append({"path": path, "scope": scope, "language": tag, "text": _text(element)})
            if tag in {"LD", "FBD", "SFC"} and ancestors and _local(ancestors[-1].tag) == "body":
                out["logic"].append({"path": path, "scope": scope, "language": tag, "tree": _shape(element)})
        elif kind == "schneider-xef":
            if tag in {"STSource", "ILSource"}:
                out["logic"].append({"path": path, "scope": scope, "language": tag[:-6], "text": _text(element)})
            if tag in {"LDSource", "FBDSource", "SFCSource", "SFCProgram"}:
                out["logic"].append({"path": path, "scope": scope, "language": tag, "tree": _shape(element)})
            if tag in {"variables", "variable"} and element.get("name"):
                out["variables"].append({"path": path, "scope": scope, "name": element.get("name"),
                    "type": element.get("typeName"), "address": element.get("topologicalAddress"),
                    "attributes": dict(element.attrib), "tree": _shape(element)})
        elif kind == "codesys-export-xml":
            if tag == "Array" and element.get("Name") == "TextLines":
                lines = []
                for item in element:
                    texts = [e.text or "" for e in item if _local(e.tag) == "Single" and e.get("Name") == "Text"]
                    lines.extend(texts)
                section = next((e.get("Name") for e in reversed(ancestors) if e.get("Name") in {"Implementation", "Interface"}), "TextDocument")
                destination = "declarations" if section == "Interface" else "logic"
                out[destination].append({"path": path, "scope": path, "language": "unclassified-text", "text": "\n".join(lines)})
    seen = set()
    for item in out["strings"]:
        value = item["value"]
        for match in flagfmt.TEXT.finditer(value):
            key = (item["path"], match.group())
            if key not in seen:
                seen.add(key)
                out["findings"].append({"kind": "flag", "path": item["path"], "value": match.group()})
        if re.search(r"(?i)(?:password|passwd|secret|token|api[_-]?key)", item["path"]):
            out["findings"].append({"kind": "secret-field", "path": item["path"], "value": value})
        for match in re.finditer(r"(?i)\b(password|passwd|secret|token|api[_-]?key)\b\s*(?::\s*[A-Za-z_]\w*(?:\([^\r\n)]{1,32}\))?\s*)?(?::=|=|:)\s*(['\"])([^\r\n]{1,256}?)\2", value):
            out["findings"].append({"kind": "literal-secret", "path": item["path"], "key": match[1], "value": match[3]})
    return out


def parse_export(data: bytes | str, *, name: str = "<bytes>") -> dict:
    """Extract XML evidence, or raise only ExportError on malformed input."""
    try:
        if not isinstance(data, (bytes, str)) or not isinstance(name, str):
            raise ExportError("data must be bytes or text; name must be text")
        raw = data.encode("utf-8") if isinstance(data, str) else data
        if not raw or len(raw) > MAX_INPUT:
            raise ExportError("XML input empty or exceeds size cap")
        builder = _BoundedTree()
        parser = ET.XMLParser(target=builder)
        parser.feed(raw)
        return _extract(parser.close(), name, builder.document_comments)
    except ExportError:
        raise
    except Exception as exc:
        raise ExportError("malformed vendor XML export") from exc


def analyze_file(path: str | Path) -> dict:
    """Read at most MAX_INPUT+1 bytes; never open any project references."""
    try:
        with open(path, "rb") as handle:
            data = handle.read(MAX_INPUT + 1)
        return parse_export(data, name=str(path))
    except ExportError:
        raise
    except Exception as exc:
        raise ExportError("cannot read vendor XML export") from exc


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", help="readable vendor XML project/export")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        print(json.dumps(analyze_file(args.artifact), indent=2, ensure_ascii=True))
        return 0
    except ExportError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
