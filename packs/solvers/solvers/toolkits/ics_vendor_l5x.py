#!/usr/bin/env python3
"""Static Rockwell L5X evidence extraction (1756-RM014 import/export format).

Keeps controller/program/AOI scopes, XML provenance, edit variants, and all data
representations. Does not execute logic or decrypt source protection. This is a
bounded extractor, not a complete Logix schema validator or ACD/L5K parser.
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
MAX_NODES = 150_000
MAX_DEPTH = 64
MAX_EVIDENCE = 64 * 1024 * 1024
MAX_PATH_TOTAL = 16 * 1024 * 1024
FLAG = flagfmt.TEXT
SECRET = re.compile(r"password|passwd|secret|token|api[_-]?key|credential", re.I)


class ParseError(ValueError):
    """Malformed, unsupported, or excessive L5X evidence."""


def _local(tag):
    return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else "#comment"


class _Tree(ET.TreeBuilder):
    def __init__(self):
        super().__init__(insert_comments=True)
        self.depth = self.nodes = 0
        self.outside_comments = []

    def start(self, tag, attrs):
        if len(tag) > 512 or any(len(key) > 512 for key in attrs):
            raise ParseError("XML name length limit exceeded")
        self.depth += 1
        self.nodes += 1
        if self.depth > MAX_DEPTH or self.nodes > MAX_NODES:
            raise ParseError("XML depth/node limit exceeded")
        return super().start(tag, attrs)

    def end(self, tag):
        self.depth -= 1
        return super().end(tag)

    def comment(self, text):
        self.nodes += 1
        if self.nodes > MAX_NODES:
            raise ParseError("XML node limit exceeded")
        if self.depth == 0:
            self.outside_comments.append(text)
        return super().comment(text)

    def doctype(self, name, pubid, system):
        raise ParseError("DTD/entity declarations are forbidden")


def decode_logix_string(value: str) -> str:
    """Decode quoted Logix 8-bit string literals; dollar hex is exactly two digits.

    Supports $$, $', $\", $L (LF), $N (CRLF), $P (FF), $R (CR), $T (TAB).
    Unknown escapes fail rather than silently alter recovered evidence.
    """
    if not isinstance(value, str) or len(value) > MAX_INPUT:
        raise ParseError("invalid Logix literal")
    text = value.strip()
    if len(text) < 2 or text[0] != "'" or text[-1] != "'":
        raise ParseError("expected a single-quoted Logix string")
    text = text[1:-1]
    out, pos = [], 0
    escapes = {"$": "$", "'": "'", '"': '"', "L": "\n", "N": "\r\n",
               "P": "\f", "R": "\r", "T": "\t"}
    while pos < len(text):
        char = text[pos]
        if char == "'":
            raise ParseError("unescaped quote in Logix literal")
        if char != "$":
            if ord(char) > 255:
                raise ParseError("non-byte character in Logix string")
            out.append(char)
            pos += 1
            continue
        if pos + 1 >= len(text):
            raise ParseError("truncated Logix escape")
        pair = text[pos + 1:pos + 3]
        if len(pair) == 2 and re.fullmatch(r"[0-9A-Fa-f]{2}", pair):
            out.append(chr(int(pair, 16)))
            pos += 3
        elif text[pos + 1].upper() in escapes:
            out.append(escapes[text[pos + 1].upper()])
            pos += 2
        else:
            raise ParseError("unknown Logix escape")
    return "".join(out)


def _integer(value):
    if not isinstance(value, str) or len(value) > 100:
        raise ParseError("invalid integer")
    text = value.strip().replace("_", "")
    match = re.fullmatch(r"(2|8|16)#([0-9A-Fa-f]+)", text)
    try:
        if match:
            return int(match[2], int(match[1]))
        if re.fullmatch(r"[+-]?[0-9]+", text):
            return int(text, 10)
    except ValueError as exc:
        raise ParseError("invalid radix digit") from exc
    raise ParseError("invalid integer")


def _limited_string(value, length):
    if length is None:
        return value
    count = _integer(length)
    if count < 0 or count > len(value):
        raise ParseError("STRING length exceeds supplied data")
    return value[:count]


def _sized_literal(value, length):
    # Real exports may use empty CDATA (without quotes) for zero-length DATA.
    if not value.strip() and length is not None and _integer(length) == 0:
        return ""
    return _limited_string(decode_logix_string(value), length)


def _text(node):
    # XML comments are separate evidence, never part of a string or instruction.
    result = [node.text or ""]
    for child in node:
        if isinstance(child.tag, str):
            result.append(_text(child))
        result.append(child.tail or "")
    return "".join(result)


def _string_values(data, datatype, string_types, is_array):
    """Yield (relative evidence location, decoded value) from known STRING layouts."""
    fmt = data.get("Format", "Raw")
    if fmt == "String":
        yield "String", _sized_literal(_text(data), data.get("Length"))
    elif fmt == "L5K" and datatype == "STRING" and not is_array:
        match = re.fullmatch(r"\s*\[\s*([0-9]+)\s*,\s*('.*')\s*\]\s*", _text(data), re.S)
        if not match:
            raise ParseError("unsupported L5K STRING initializer")
        yield "L5K", _limited_string(decode_logix_string(match[2]), match[1])
    elif fmt == "Raw" and datatype == "STRING" and not is_array:
        raw_text = _text(data)
        if not re.fullmatch(r"(?:\s*[0-9A-Fa-f]{2})+\s*", raw_text):
            raise ParseError("malformed raw STRING hex")
        raw = bytes.fromhex(raw_text)
        if len(raw) < 4:
            raise ParseError("truncated raw STRING length")
        count = int.from_bytes(raw[:4], "little", signed=True)
        yield "Raw", _limited_string(raw[4:].decode("latin-1"), str(count))
    elif fmt == "Decorated":
        # Structures can be nested in UDTs/arrays. LEN+DATA is the Logix string
        # shape; names or arbitrary byte arrays alone are not assumed strings.
        for ordinal, structure in enumerate(data.iter()):
            if _local(structure.tag) not in {"Structure", "StructureMember"}:
                continue
            lengths = [c for c in structure if c.get("Name") == "LEN"]
            payloads = [c for c in structure if c.get("Name") == "DATA"]
            if not lengths or not payloads:
                continue
            if (structure.get("DataType") not in string_types
                    and not any(p.get("DataType") == "STRING" for p in payloads)):
                continue
            if len(lengths) != 1 or len(payloads) != 1:
                raise ParseError("ambiguous STRING members")
            length = lengths[0].get("Value")
            if length is None:
                raise ParseError("STRING LEN lacks Value")
            payload = payloads[0]
            if _local(payload.tag) == "DataValueMember":
                literal = payload.get("Value")
                literal = _text(payload) if literal is None else literal
                value = _sized_literal(literal, length)
            elif _local(payload.tag) == "ArrayMember":
                entries = {}
                for element in payload:
                    if _local(element.tag) != "Element":
                        continue
                    idx = element.get("Index", "")
                    if not re.fullmatch(r"\[[0-9]+\]", idx):
                        raise ParseError("invalid STRING array index")
                    index = _integer(idx[1:-1])
                    if index in entries:
                        raise ParseError("duplicate STRING array index")
                    number = _integer(element.get("Value"))
                    if not -128 <= number <= 255:
                        raise ParseError("STRING byte out of range")
                    entries[index] = chr(number & 255)
                if sorted(entries) != list(range(len(entries))):
                    raise ParseError("sparse STRING array")
                value = "".join(entries[i] for i in range(len(entries)))
            else:
                continue
            yield f"Decorated/Structure[{ordinal}]/{structure.get('Name', '')}", _limited_string(value, length)


class _EvidenceList(list):
    def __init__(self, budget):
        super().__init__()
        self.budget = budget

    def append(self, value):
        self.budget[0] += len(json.dumps(value, ensure_ascii=True))
        if self.budget[0] > MAX_EVIDENCE:
            raise ParseError("evidence output limit exceeded")
        super().append(value)


def parse_l5x(data: bytes | str) -> dict:
    """Return JSON-safe evidence or raise only ParseError for invalid input.

    `flags` are literal format matches, never validated answers. `secret_candidates`
    are named-tag/text review leads, not evidence of usable authentication.
    """
    try:
        if not isinstance(data, (str, bytes, bytearray)):
            raise ParseError("L5X input must be bytes or text")
        if len(data) > MAX_INPUT:
            raise ParseError("L5X input limit exceeded")
        raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)
        if len(raw) > MAX_INPUT:
            raise ParseError("L5X input limit exceeded")
        tree = _Tree()
        root = ET.fromstring(raw, parser=ET.XMLParser(target=tree))
        if _local(root.tag) != "RSLogix5000Content":
            raise ParseError("not an L5X RSLogix5000Content document")
        string_types = {"STRING"} | {node.get("Name") for node in root.iter()
                                     if _local(node.tag) == "DataType" and node.get("Family") == "StringFamily"}
        result = {"format": "rockwell-l5x", "metadata": dict(root.attrib), "tags": [],
                  "logic": [], "comments": [], "strings": [], "protected": [],
                  "modules": [], "secret_candidates": [], "flags": []}
        budget = [0]
        for key in result:
            if isinstance(result[key], list):
                result[key] = _EvidenceList(budget)
        flags = set()

        def evidence(path, field, value):
            if not value or not value.strip():
                return
            item = {"path": path, "field": field, "value": value}
            result["strings"].append(item)
            flags.update(FLAG.findall(value))
            if SECRET.search(value):
                result["secret_candidates"].append(item)

        for index, comment in enumerate(tree.outside_comments, 1):
            path = f"/#document-comment[{index}]"
            result["comments"].append({"path": path, "text": comment})
            evidence(path, "text", comment)
        stack = [(root, "/RSLogix5000Content", "")]
        path_total = 0
        while stack:
            node, path, scope = stack.pop()
            path_total += len(path)
            if len(path) > 8192 or path_total > MAX_PATH_TOTAL:
                raise ParseError("XML path evidence limit exceeded")
            kind = _local(node.tag)
            if kind in {"Controller", "Program", "AddOnInstructionDefinition"}:
                scope = (scope + "/" if scope else "") + kind + ":" + node.get("Name", "")
            for key, value in node.attrib.items():
                evidence(path, "@" + key, value)
            if node.text:
                evidence(path, "text", node.text)
            if node.tail:
                evidence(path, "tail", node.tail)
            if kind in {"#comment", "Comment", "Description", "LocalizedDescription", "LocalizedComment"}:
                result["comments"].append({"path": path, "text": _text(node)})
            if kind == "Module":
                result["modules"].append({"path": path, "attributes": dict(node.attrib)})
            if kind in {"EncodedData", "EncryptedContent", "EncryptedSegments", "EncryptionInfo"}:
                result["protected"].append({"path": path, "kind": kind, "attributes": dict(node.attrib),
                                             "note": "source protection evidence; content not decrypted"})
            if kind in {"Tag", "LocalTag", "Parameter"}:
                tag = {"path": path, "scope": scope, "name": node.get("Name"),
                       "attributes": dict(node.attrib), "data": [], "decoded_strings": []}
                data_counts = {}
                for child in node:
                    data_kind = _local(child.tag)
                    if data_kind not in {"Data", "DefaultData", "ForceData"}:
                        continue
                    data_counts[data_kind] = data_counts.get(data_kind, 0) + 1
                    data_path = path + "/" + data_kind + f"[{data_counts[data_kind]}]"
                    tag["data"].append({"kind": _local(child.tag), "format": child.get("Format", "Raw"),
                                        "xml": ET.tostring(child, encoding="unicode")})
                    if _local(child.tag) == "ForceData":
                        continue
                    is_array = node.get("Dimensions", "0").strip() not in {"", "0"}
                    for relative, value in _string_values(child, node.get("DataType", ""), string_types, is_array):
                        item = {"path": data_path + "/" + relative, "value": value}
                        tag["decoded_strings"].append(item)
                        evidence(item["path"], "decoded-string", value)
                result["tags"].append(tag)
                if SECRET.search(node.get("Name", "")):
                    result["secret_candidates"].append({"path": path, "field": "named-tag", "tag": tag})
            if kind == "Rung":
                text = "\n".join(_text(c) for c in node if _local(c.tag) == "Text")
                result["logic"].append({"path": path, "scope": scope, "language": "RLL", "text": text,
                                         "attributes": dict(node.attrib)})
            elif kind == "STContent":
                result["logic"].append({"path": path, "scope": scope, "language": "ST",
                                         "text": "\n".join(_text(c) for c in node if _local(c.tag) == "Line"),
                                         "attributes": dict(node.attrib)})
            elif kind in {"FBDContent", "SFCContent"}:
                result["logic"].append({"path": path, "scope": scope, "language": kind[:-7],
                                         "xml": ET.tostring(node, encoding="unicode"),
                                         "attributes": dict(node.attrib)})
            counts, children = {}, []
            for child in node:
                name = _local(child.tag)
                counts[name] = counts.get(name, 0) + 1
                children.append((child, f"{path}/{name}[{counts[name]}]", scope))
            stack.extend(reversed(children))
        result["flags"] = sorted(flags)
        return result
    except ParseError:
        raise
    except (ET.ParseError, ValueError, TypeError, LookupError, OverflowError, RecursionError) as exc:
        raise ParseError(f"invalid L5X: {exc}") from exc


def analyze_file(path: str | Path) -> dict:
    try:
        with open(path, "rb") as handle:
            data = handle.read(MAX_INPUT + 1)
        return parse_l5x(data)
    except ParseError:
        raise
    except (OSError, ValueError, TypeError) as exc:
        raise ParseError(f"cannot read L5X: {exc}") from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", help="Rockwell .L5X export (offline)")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        print(json.dumps(analyze_file(args.file), indent=2, ensure_ascii=True))
        return 0
    except ParseError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
