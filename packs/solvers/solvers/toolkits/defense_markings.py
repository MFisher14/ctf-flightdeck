#!/usr/bin/env python3
"""Offline extraction of common US CAPCO markings and ISM XML attributes.

This is a structural inspector, not a security-policy or classification oracle.
Unknown controls are retained. XML attributes are never inherited implicitly.
Sources: DoDM 5200.01 Vol2 Fig33; NSA/CSS PM1-52 Table1; DoDAF VolIII p3-6.
Only the US U/C/S/TS scale is normalized; NATO/foreign markings need a separate
policy. No DTDs, entities, schema fetching, network access or untrusted execution.
All malformed/unsupported public input raises MarkingsError.
"""
from __future__ import annotations

import argparse
import io
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

MAX_BYTES = 1 << 20
MAX_NODES = 4096
MAX_DEPTH = 32
ISM_NAMESPACES = {"urn:us:gov:ic:ism", "urn:us:gov:ic:ism:v2"}
LEVELS = {"U": (0, "UNCLASSIFIED"), "C": (1, "CONFIDENTIAL"),
          "S": (2, "SECRET"), "TS": (3, "TOP SECRET")}
ALIASES = {name: short for short, (_, name) in LEVELS.items()}
ALIASES.update({short: short for short in LEVELS})
CONTROL_ALIASES = {"NF": "NOFORN", "OC": "ORCON", "RS": "RSEN",
                   "TALENT KEYHOLE": "TK", "FOR OFFICIAL USE ONLY": "FOUO",
                   "ORIGINATOR CONTROLLED": "ORCON", "RISK SENSITIVE": "RSEN",
                   "NOT RELEASABLE TO FOREIGN NATIONALS": "NOFORN"}
DISSEMINATION = {"NOFORN", "ORCON", "RELIDO", "PROPIN", "RSEN", "FOUO", "FISA"}
LIST_ATTRIBUTES = {"ownerProducer", "SCIcontrols", "SARIdentifier",
                   "disseminationControls", "releasableTo", "nonICmarkings",
                   "FGIsourceOpen", "FGIsourceProtected"}


class MarkingsError(ValueError):
    """Malformed, unsupported or oversized marking artifact."""


def _text(value):
    if type(value) is bytes:
        if len(value) > MAX_BYTES:
            raise MarkingsError("input exceeds size limit")
        try:
            value = value.decode("utf-8-sig")
        except UnicodeError as exc:
            raise MarkingsError("input must be UTF-8") from exc
    if type(value) is not str or len(value) > MAX_BYTES:
        raise MarkingsError("expected bounded text or UTF-8 bytes")
    try:
        if len(value.encode("utf-8")) > MAX_BYTES:
            raise MarkingsError("input exceeds size limit")
    except UnicodeError as exc:
        raise MarkingsError("invalid Unicode") from exc
    if any(ord(c) < 32 and c not in "\t\r\n" for c in value):
        raise MarkingsError("control character in input")
    return value


def parse_marking(value) -> dict:
    """Parse a single banner or parenthesized portion mark, preserving controls."""
    raw = _text(value).strip()
    if not raw or len(raw) > 8192 or "\n" in raw or "\r" in raw:
        raise MarkingsError("expected one bounded marking")
    portion = raw.startswith("(")
    text = raw
    if portion:
        if not raw.endswith(")"):
            raise MarkingsError("unterminated portion marking")
        text = raw[1:-1]
    if "(" in text or ")" in text:
        raise MarkingsError("unexpected parentheses")
    groups = text.split("//")
    code = ALIASES.get(groups[0].strip())
    if code is None:
        raise MarkingsError("unsupported or unknown classification")
    result = {"raw": raw, "portion": portion, "classification": code,
              "classification_name": LEVELS[code][1], "level": LEVELS[code][0],
              "groups": [], "sci_controls": [], "dissemination_controls": [],
              "releasable_to": [], "unknown_controls": [], "warnings": []}
    for group in groups[1:]:
        tokens = [token.strip() for token in group.split("/")]
        if any(not token or not re.fullmatch(r"[A-Z0-9 ,.-]+", token) for token in tokens):
            raise MarkingsError("empty or malformed control token")
        result["groups"].append(tokens)
        for original in tokens:
            token = CONTROL_ALIASES.get(original, original)
            if token.startswith("REL TO "):
                countries = [c.strip() for c in token[7:].split(",")]
                if any(not re.fullmatch(r"[A-Z]{3,4}", country) for country in countries):
                    raise MarkingsError("malformed REL TO list")
                result["releasable_to"].extend(countries)
            elif token == "REL":
                result["warnings"].append("REL requires the enclosing banner's release list")
            elif token in DISSEMINATION:
                result["dissemination_controls"].append(token)
            elif re.match(r"^(SI|TK|HCS)(?:-|$)", token):
                result["sci_controls"].append(token)
            else:
                result["unknown_controls"].append(original)
    if result["unknown_controls"]:
        result["warnings"].append("unknown controls retained; no release decision inferred")
    if "NOFORN" in result["dissemination_controls"] and result["releasable_to"]:
        result["warnings"].append("NOFORN and REL TO coexist; review source markings")
    if code == "U" and result["sci_controls"]:
        result["warnings"].append("unclassified level with SCI controls; review source markings")
    return result


def parse_text(value) -> dict:
    """Extract banner lines and line-leading portion marks, with exact line numbers."""
    text = _text(value)
    records = []
    unmarked = 0
    for line_no, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        if re.match(r"^\((?:UNCLASSIFIED|CONFIDENTIAL|SECRET|TOP SECRET|TS|U|C|S)(?://|\)|$)", line):
            end = line.find(")")
            if end < 0:
                raise MarkingsError(f"unterminated portion at line {line_no}")
            mark = parse_marking(line[:end + 1])
            body = line[end + 1:].lstrip()
        elif re.match(r"^(?:UNCLASSIFIED|CONFIDENTIAL|SECRET|TOP SECRET|TS|U|C|S)(?://|$)", line):
            mark, body = parse_marking(line), ""
        else:
            unmarked += 1
            continue
        records.append({"line": line_no, "marking": mark, "text": body})
        if len(records) > MAX_NODES:
            raise MarkingsError("too many markings")
    if not records:
        raise MarkingsError("no supported markings found")
    return {"records": records, "unmarked_nonempty_lines": unmarked,
            "policy_evaluated": False}


def parse_ism(value) -> dict:
    """Extract explicit ISM attributes; report missing/unknown levels without guessing.

    ISM namespaces are matched by URI, not prefix. The output text belongs to the
    explicitly marked element and includes descendants. Paths use child indexes.
    """
    text = _text(value)
    declaration = re.match(r"\A\ufeff?<\?xml\s+(.*?)\?>", text, re.S)
    if declaration:
        encoding = re.search(r"\bencoding\s*=\s*(['\"])(.*?)\1", declaration.group(1), re.S)
        if encoding:
            name = encoding.group(2).lower()
            if name not in {"utf-8", "utf8", "ascii", "us-ascii"}:
                raise MarkingsError("XML encoding declaration conflicts with UTF-8 input contract")
            if name in {"ascii", "us-ascii"} and not text.isascii():
                raise MarkingsError("non-ASCII input with ASCII encoding declaration")
    if re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", text, re.I):
        raise MarkingsError("DTD/entity declarations are forbidden")
    records = []
    warnings = []
    stack = []
    count = unmarked = 0
    try:
        for event, node in ET.iterparse(io.StringIO(text), events=("start", "end")):
            if event == "start":
                count += 1
                if count > MAX_NODES or len(stack) >= MAX_DEPTH:
                    raise MarkingsError("XML node/depth limit exceeded")
                if len(node.tag) > 256 or any(len(k) > 256 or len(v) > 8192 for k, v in node.attrib.items()):
                    raise MarkingsError("XML name/attribute limit exceeded")
                if stack:
                    stack[-1][2] += 1
                    path = stack[-1][1] + f"/{node.tag}[{stack[-1][2]}]"
                else:
                    path = f"/{node.tag}[1]"
                if len(path) > 4096:
                    raise MarkingsError("XML path limit exceeded")
                attributes = {}
                for name, val in node.attrib.items():
                    if name.startswith("{"):
                        namespace, local = name[1:].split("}", 1)
                        if namespace in ISM_NAMESPACES:
                            if local in attributes:
                                raise MarkingsError("ambiguous duplicate ISM attribute")
                            attributes[local] = val
                        elif local == "classification":
                            warnings.append(f"classification in unrecognized namespace at {path}")
                    elif name == "classification":
                        warnings.append(f"unnamespaced classification at {path}")
                record = None
                if attributes:
                    raw_level = attributes.get("classification")
                    known = raw_level in LEVELS
                    record = {"path": path, "attributes": attributes,
                              "classification": raw_level, "recognized_level": known,
                              "level": LEVELS[raw_level][0] if known else None,
                              "lists": {k: v.split() for k, v in attributes.items() if k in LIST_ATTRIBUTES}}
                    records.append(record)
                    if not known:
                        warnings.append(f"missing/unknown explicit classification at {path}")
                    if not attributes.get("ownerProducer"):
                        warnings.append(f"missing explicit ownerProducer at {path}")
                else:
                    unmarked += 1
                stack.append([record, path, 0])
            else:
                record, _, _ = stack.pop()
                if record is not None:
                    record["text"] = "".join(node.itertext())
    except (ET.ParseError, UnicodeError, ValueError) as exc:
        if isinstance(exc, MarkingsError):
            raise
        raise MarkingsError("malformed XML") from exc
    if not records:
        raise MarkingsError("no recognized ISM namespace attributes")
    return {"records": records, "unmarked_elements": unmarked, "warnings": warnings,
            "attributes_inherited": False, "policy_evaluated": False}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path)
    parser.add_argument("--format", choices=("text", "marking", "xml"), default="text")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        with args.file.open("rb") as source:
            data = source.read(MAX_BYTES + 1)
        result = {"text": parse_text, "marking": parse_marking, "xml": parse_ism}[args.format](data)
        print(json.dumps(result, indent=2))
        return 0
    except (MarkingsError, OSError, ValueError) as exc:
        print(f"defense_markings: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
