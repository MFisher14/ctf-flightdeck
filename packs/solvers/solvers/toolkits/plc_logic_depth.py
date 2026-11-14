#!/usr/bin/env python3
"""Offline PLC logic parser and safety-oriented dataflow triage.

Supported supplied artifacts:

* Siemens/IEC statement-list text (AWL/STL/IL), including networks, jumps,
  timers, counters, calls, symbolic operands and direct process-image addresses.
* Allen-Bradley-style textual ladder mnemonics (XIC/XIO/OTE/OTL/OTU,
  timers, counters, moves, comparisons and arithmetic).
* PLCopen XML ladder/function-block bodies without resolving external entities.
* A bounded Structured Text subset for assignments, conditions and FB calls.

The module is a parser only: it never compiles, simulates, uploads, connects to a
controller, opens an interface, or executes project code. Findings are static
review leads, not claims that a physical process is exploitable or unsafe.
"""
from __future__ import annotations

import argparse
import json
import re
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

MAX_INPUT = 16 * 1024 * 1024
MAX_INSTRUCTIONS = 250_000
MAX_XML_NODES = 300_000
MAX_ARGS = 10_000


class ParseError(ValueError):
    """A bounded PLC artifact cannot be parsed unambiguously."""


def _finding(kind: str, severity: str, detail: str, **evidence: Any) -> dict[str, Any]:
    out: dict[str, Any] = {"kind": kind, "severity": severity, "detail": detail}
    out.update({key: value for key, value in evidence.items() if value is not None})
    return out


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _line_comment_mask(text: str) -> str:
    """Mask //, (* *), and /* */ comments while retaining line/column offsets."""
    out = list(text)
    state, quote, index = "code", "", 0
    while index < len(text):
        char = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""
        if state == "code":
            if char == "/" and following == "/":
                out[index] = out[index + 1] = " "
                index += 1
                state = "line"
            elif (char, following) in {( "(", "*"), ("/", "*")}:
                out[index] = out[index + 1] = " "
                index += 1
                state = "paren-block" if char == "(" else "slash-block"
            elif char in "'\"":
                quote, state = char, "string"
        elif state == "line":
            if char == "\n":
                state = "code"
            else:
                out[index] = " "
        elif state in {"paren-block", "slash-block"}:
            closing = (")" if state == "paren-block" else "/")
            if char == "*" and following == closing:
                out[index] = out[index + 1] = " "
                index += 1
                state = "code"
            elif char != "\n":
                out[index] = " "
        else:
            if char == "\\" and index + 1 < len(text):
                index += 1
            elif char == quote:
                state = "code"
        index += 1
    return "".join(out)


def split_arguments(text: str) -> list[str]:
    out, start, depth, quote, index = [], 0, 0, "", 0
    while index < len(text):
        char = text[index]
        if quote:
            if char == "\\":
                index += 1
            elif char == quote:
                quote = ""
        elif char in "'\"":
            quote = char
        elif char in "([{" :
            depth += 1
        elif char in ")]}":
            depth -= 1
            if depth < 0:
                raise ParseError("unbalanced instruction arguments")
        elif char == "," and depth == 0:
            out.append(text[start:index].strip())
            start = index + 1
            if len(out) >= MAX_ARGS:
                raise ParseError("instruction argument cap exceeded")
        index += 1
    if quote or depth:
        raise ParseError("unterminated quoted or nested instruction argument")
    tail = text[start:].strip()
    if tail or out:
        out.append(tail)
    return out


_ADDRESS = re.compile(
    r"(?ix)(?:%?[IQM](?:B|W|D|X)?\s*\d+(?:\.\d+)?|"
    r"DB\s*\d+\s*\.\s*DB[XBWD]\s*\d+(?:\.\d+)?|"
    r"(?:T|C|Z)\s*\d+|PI[WBD]?\s*\d+|PQ[WBD]?\s*\d+)"
)
_SYMBOL = re.compile(r"(?:\"[^\"]+\"|#[A-Za-z_]\w*|[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)")
_KEYWORDS = {
    "TRUE", "FALSE", "AND", "OR", "NOT", "XOR", "MOD", "THEN", "ELSE", "ELSIF", "END_IF",
    "IF", "CASE", "END_CASE", "FOR", "TO", "BY", "DO", "END_FOR", "WHILE", "END_WHILE",
    "IN", "PT", "PV", "CU", "CD", "R", "S", "Q", "ET", "CV", "ENO", "EN",
}


def normalize_tag(value: str) -> str:
    value = value.strip().strip(",;")
    value = re.sub(r"\s+", "", value)
    if len(value) >= 2 and value[0] == value[-1] == '"':
        value = value[1:-1]
    if value.startswith("#"):
        value = value[1:]
    return value


def extract_tags(expression: str) -> list[str]:
    """Extract address/symbol operands, excluding constants, durations, and keywords."""
    tags: list[str] = []
    covered: list[tuple[int, int]] = []
    for match in _ADDRESS.finditer(expression):
        tag = normalize_tag(match.group(0)).upper()
        tags.append(tag)
        covered.append(match.span())
    for match in _SYMBOL.finditer(expression):
        if any(start <= match.start() < end for start, end in covered):
            continue
        raw = match.group(0)
        if expression[match.end():match.end() + 1] == "#":
            continue
        tag = normalize_tag(raw)
        upper = tag.upper()
        if (not tag or upper in _KEYWORDS or re.fullmatch(r"(?:S5)?T#.*", upper)
                or re.fullmatch(r"(?:B#16#|W#16#|DW#16#)?[0-9A-F._+-]+", upper)
                or upper.startswith(("P#", "L#", "2#", "16#"))):
            continue
        tags.append(tag)
    return list(dict.fromkeys(tags))


def tag_role(tag: str) -> str:
    compact = normalize_tag(tag).upper()
    if re.fullmatch(r"%?I(?:[XBWD])?\d+(?:\.\d+)?", compact) or compact.startswith("PI"):
        return "physical-input"
    if re.fullmatch(r"%?Q(?:[XBWD])?\d+(?:\.\d+)?", compact) or compact.startswith("PQ"):
        return "physical-output"
    if re.fullmatch(r"M(?:[XBWD])?\d+(?:\.\d+)?", compact):
        return "marker"
    if compact.startswith("DB"):
        return "data-block"
    if re.fullmatch(r"T\d+", compact):
        return "timer"
    if re.fullmatch(r"(?:C|Z)\d+", compact):
        return "counter"
    return "symbolic"


def parse_duration_ms(value: str | int | float | None) -> int | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return int(value)
    text = str(value).strip().upper().replace("_", "")
    if re.fullmatch(r"[+-]?\d+", text):
        return int(text)
    match = re.fullmatch(r"(?:S5)?T#(.+)", text)
    if not match:
        return None
    body = match.group(1)
    total = 0.0
    position = 0
    scales = {"D": 86_400_000, "H": 3_600_000, "M": 60_000, "S": 1000, "MS": 1}
    for part in re.finditer(r"(\d+(?:\.\d+)?)(MS|D|H|M|S)", body):
        if part.start() != position:
            return None
        total += float(part.group(1)) * scales[part.group(2)]
        position = part.end()
    return int(total) if position == len(body) and position else None


def _instruction(index: int, line: int, network: int, opcode: str, operands: list[str], raw: str,
                 *, reads: Iterable[str] = (), writes: Iterable[str] = (), condition_reads: Iterable[str] = (),
                 label: str | None = None, attributes: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "index": index, "line": line, "network": network, "opcode": opcode.upper(),
        "operands": operands, "raw": raw.rstrip(), "reads": list(dict.fromkeys(reads)),
        "writes": list(dict.fromkeys(writes)), "condition_reads": list(dict.fromkeys(condition_reads)),
        "label": label, "attributes": attributes or {},
    }


_AWL_READ = {"A", "AN", "O", "ON", "X", "XN", "U", "UN", "LD", "LDN", "AND", "ANDN", "OR", "ORN",
             "XOR", "XORN", "L", "LAR1", "LAR2", "FP", "FN", "EU", "ED"}
_AWL_WRITE = {"=", "ST", "STN", "S", "SET", "R", "RESET", "T", "TAK"}
_AWL_TIMER = {"TON", "TOF", "TP", "SD", "SE", "SF", "SS", "SP"}
_AWL_COUNTER = {"CTU", "CTD", "CTUD", "CU", "CD"}
_AWL_JUMPS = {"JU", "JMP", "SPA", "JC", "JCN", "JMPC", "JMPCN", "LOOP"}


def parse_awl(text: str) -> dict[str, Any]:
    if len(text.encode("utf-8", "replace")) > MAX_INPUT:
        raise ParseError("PLC text exceeds input cap")
    masked = _line_comment_mask(text)
    instructions: list[dict[str, Any]] = []
    network, condition, accumulator_sources = 0, [], []
    for line_no, line in enumerate(masked.splitlines(), 1):
        stripped = line.strip().rstrip(";").strip()
        if not stripped:
            continue
        if re.match(r"(?i)^(?:NETWORK|NETZWERK)\b", stripped):
            network += 1
            condition = []
            accumulator_sources = []
            continue
        if re.match(r"(?i)^TITLE\b", stripped):
            continue
        label = None
        label_match = re.match(r"^([A-Za-z_]\w*):\s*(.*)$", stripped)
        if label_match:
            label, stripped = label_match.groups()
            if not stripped:
                instructions.append(_instruction(len(instructions), line_no, network, "LABEL", [], line,
                                                 label=label))
                continue
        parts = stripped.split(None, 1)
        opcode = parts[0].upper()
        operand_text = parts[1].strip() if len(parts) > 1 else ""
        operands = split_arguments(operand_text) if "," in operand_text else ([operand_text] if operand_text else [])
        reads: list[str] = []
        writes: list[str] = []
        attrs: dict[str, Any] = {}
        tags = extract_tags(operand_text)
        if opcode in _AWL_READ:
            reads = tags
            if opcode in {"L", "LAR1", "LAR2"}:
                accumulator_sources = list(dict.fromkeys(accumulator_sources + reads))
            else:
                condition = list(dict.fromkeys(condition + reads))
        elif opcode in _AWL_WRITE:
            writes = tags[:1]
            reads = list(accumulator_sources)
        elif opcode in _AWL_TIMER:
            instance = tags[0] if tags else (normalize_tag(operands[0]) if operands else "")
            if instance:
                writes = [instance]
            reads = list(dict.fromkeys(condition + tags[1:]))
            duration_candidates = [part.strip() for part in operands[1:]]
            duration_candidates.extend(re.findall(r"(?i)(?:S5)?T#[0-9._A-Z]+", operand_text))
            duration = next((parsed for part in duration_candidates
                             if (parsed := parse_duration_ms(part)) is not None), None)
            attrs.update(kind="timer", instance=instance or None, preset_ms=duration)
        elif opcode in _AWL_COUNTER:
            instance = tags[0] if tags else (normalize_tag(operands[0]) if operands else "")
            if instance:
                writes = [instance]
            reads = list(dict.fromkeys(condition + tags[1:]))
            preset_match = re.search(r"(?i)(?:PV\s*:?=\s*)?([+-]?\d+)\s*$", operand_text)
            attrs.update(kind="counter", instance=instance or None,
                         preset=int(preset_match.group(1)) if preset_match else None)
        elif opcode == "CALL":
            named = {}
            for assignment in re.findall(r"([A-Za-z_]\w*)\s*(?::=|=>)\s*([^,]+)", operand_text):
                named[assignment[0].upper()] = assignment[1].strip()
            reads = list(dict.fromkeys(tag for name, value in named.items() if name not in {"Q", "ENO", "CV", "ET"}
                                       for tag in extract_tags(value)))
            writes = list(dict.fromkeys(tag for name, value in named.items() if name in {"Q", "ENO", "CV", "ET", "OUT"}
                                        for tag in extract_tags(value)))
            attrs["call"] = operands[0] if operands else operand_text.split(None, 1)[0] if operand_text else None
        elif opcode in _AWL_JUMPS:
            attrs.update(kind="jump", target=normalize_tag(operands[0]) if operands else None,
                         unconditional=opcode in {"JU", "JMP", "SPA"})
            reads = list(condition) if not attrs["unconditional"] else []
        elif opcode in {"+I", "+D", "+R", "-I", "-D", "-R", "*I", "*D", "*R", "/I", "/D", "/R",
                        "==I", "==D", "==R", "<>I", "<I", ">I", "<=I", ">=I"}:
            reads = list(accumulator_sources)
            condition = list(dict.fromkeys(condition + reads)) if opcode.startswith(("=", "<", ">")) else condition
        else:
            reads = tags
        if len(instructions) >= MAX_INSTRUCTIONS:
            raise ParseError("PLC instruction cap exceeded")
        instructions.append(_instruction(len(instructions), line_no, network, opcode, operands, line,
                                         reads=reads, writes=writes,
                                         condition_reads=condition if writes else (), label=label, attributes=attrs))
        if writes and opcode not in {"S", "SET", "R", "RESET"}:
            accumulator_sources = []
    if not instructions:
        raise ParseError("no AWL/STL instructions found")
    return _program("awl", instructions, source_lines=len(text.splitlines()))


_CONTACTS = {"XIC", "XIO", "ONS", "OSR", "OSF", "EQU", "NEQ", "GRT", "GEQ", "LES", "LEQ", "LIM", "CMP"}
_COILS = {"OTE", "OTL", "OTU", "SET", "RESET", "RST", "COIL"}
_MOVES = {"MOV", "COP", "CPS", "MOVE", "BLKMOV"}
_MATH = {"ADD", "SUB", "MUL", "DIV", "MOD", "SQR", "NEG", "ABS", "CPT"}
_TIMERS = {"TON", "TOF", "RTO", "TP"}
_COUNTERS = {"CTU", "CTD", "CTUD", "RES"}


def _calls(text: str) -> list[tuple[str, str, int]]:
    out, index = [], 0
    while index < len(text):
        match = re.search(r"\b([A-Za-z_][\w.]*)\s*\(", text[index:])
        if not match:
            break
        name = match.group(1)
        opening = index + match.end() - 1
        depth, quote, cursor = 1, "", opening + 1
        while cursor < len(text) and depth:
            char = text[cursor]
            if quote:
                if char == "\\": cursor += 1
                elif char == quote: quote = ""
            elif char in "'\"": quote = char
            elif char == "(": depth += 1
            elif char == ")": depth -= 1
            cursor += 1
        if depth:
            raise ParseError(f"unterminated ladder instruction {name}")
        out.append((name, text[opening + 1:cursor - 1], index + match.start()))
        if len(out) >= MAX_INSTRUCTIONS:
            raise ParseError("ladder instruction cap exceeded")
        index = cursor
    return out


def parse_ladder_text(text: str) -> dict[str, Any]:
    if len(text.encode("utf-8", "replace")) > MAX_INPUT:
        raise ParseError("ladder text exceeds input cap")
    masked = _line_comment_mask(text)
    instructions: list[dict[str, Any]] = []
    rungs = [piece for piece in re.split(r";|^\s*(?:RUNG\b\s*:?|N\s*:)\s*", masked,
                                         flags=re.IGNORECASE | re.MULTILINE) if piece.strip()]
    for rung_no, rung in enumerate(rungs, 1):
        conditions: list[str] = []
        for name, argument_text, position in _calls(rung):
            opcode = name.upper().rsplit(".", 1)[-1]
            operands = split_arguments(argument_text)
            reads: list[str] = []
            writes: list[str] = []
            attrs: dict[str, Any] = {}
            if opcode in _CONTACTS:
                reads = list(dict.fromkeys(tag for value in operands for tag in extract_tags(value)))
                conditions = list(dict.fromkeys(conditions + reads))
                attrs["negated"] = opcode in {"XIO", "OSF", "NEQ", "LES", "LEQ"}
            elif opcode in _COILS:
                writes = extract_tags(operands[0])[:1] if operands else []
            elif opcode in _MOVES:
                reads = extract_tags(operands[0]) if operands else []
                writes = extract_tags(operands[-1])[:1] if len(operands) > 1 else []
            elif opcode in _MATH:
                reads = list(dict.fromkeys(tag for value in operands[:-1] for tag in extract_tags(value)))
                writes = extract_tags(operands[-1])[:1] if operands else []
            elif opcode in _TIMERS:
                instance = normalize_tag(operands[0]) if operands else ""
                writes = [instance] if instance else []
                reads = list(conditions)
                preset = parse_duration_ms(operands[1]) if len(operands) > 1 else None
                if preset is None and len(operands) > 1 and re.fullmatch(r"[+-]?\d+", operands[1].strip()):
                    preset = int(operands[1])
                attrs.update(kind="timer", instance=instance or None, preset_ms=preset,
                             retentive=opcode == "RTO")
            elif opcode in _COUNTERS:
                instance = normalize_tag(operands[0]) if operands else ""
                writes = [instance] if instance else []
                reads = list(conditions)
                preset = int(operands[1]) if len(operands) > 1 and re.fullmatch(r"[+-]?\d+", operands[1].strip()) else None
                attrs.update(kind="counter", instance=instance or None, preset=preset)
            else:
                reads = list(dict.fromkeys(tag for value in operands for tag in extract_tags(value)))
            line_no = masked.count("\n", 0, masked.find(rung) + position) + 1
            instructions.append(_instruction(len(instructions), line_no, rung_no, opcode, operands,
                                             f"{name}({argument_text})", reads=reads, writes=writes,
                                             condition_reads=conditions if writes else (), attributes=attrs))
    if not instructions:
        raise ParseError("no textual ladder instructions found")
    return _program("ladder-text", instructions, rung_count=len(rungs))


def _xml_variable(element: ET.Element) -> str | None:
    for key in ("variable", "name", "operand", "symbol"):
        if element.get(key):
            return normalize_tag(str(element.get(key)))
    for child in element.iter():
        if _local(child.tag).lower() in {"variable", "expression", "symbol"} and child.text and child.text.strip():
            return normalize_tag(child.text)
    return None


def parse_plcopen_xml(data: bytes | str) -> dict[str, Any]:
    raw = data.encode() if isinstance(data, str) else bytes(data)
    if len(raw) > MAX_INPUT:
        raise ParseError("PLC XML exceeds input cap")
    if re.search(br"(?i)<!DOCTYPE|<!ENTITY", raw):
        raise ParseError("DTD/entity declarations are not accepted")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise ParseError("malformed PLC XML") from exc
    elements = list(root.iter())
    if len(elements) > MAX_XML_NODES:
        raise ParseError("PLC XML node cap exceeded")
    nodes: dict[str, dict[str, Any]] = {}
    node_networks: dict[str, int] = {}
    containers = [element for element in elements if _local(element.tag).lower() == "network"]
    if not containers:
        containers = [element for element in elements if _local(element.tag).lower() in {"ld", "fbd"}]
    for network_index, container in enumerate(containers, 1):
        for descendant in container.iter():
            descendant_id = descendant.get("localId") or descendant.get("id")
            if descendant_id is not None:
                node_networks[str(descendant_id)] = network_index
    for element in elements:
        local_id = element.get("localId") or element.get("id")
        if local_id is None:
            continue
        kind = _local(element.tag).lower()
        refs = []
        for descendant in element.iter():
            if _local(descendant.tag).lower() == "connection" and descendant.get("refLocalId"):
                refs.append(str(descendant.get("refLocalId")))
        nodes[str(local_id)] = {"id": str(local_id), "kind": kind, "variable": _xml_variable(element),
                                "type": element.get("typeName") or element.get("name"),
                                "incoming": list(dict.fromkeys(refs)), "element": element}
    upstream_cache: dict[str, list[str]] = {}

    def upstream_contacts(node_id: str, seen: set[str] | None = None) -> list[str]:
        if node_id in upstream_cache:
            return upstream_cache[node_id]
        seen = set() if seen is None else set(seen)
        if node_id in seen:
            return []
        seen.add(node_id)
        node = nodes.get(node_id)
        if not node:
            return []
        found = [node["variable"]] if node["kind"] in {"contact", "invariable"} and node["variable"] else []
        for ref in node["incoming"]:
            found.extend(upstream_contacts(ref, seen))
        upstream_cache[node_id] = list(dict.fromkeys(found))
        return upstream_cache[node_id]

    instructions: list[dict[str, Any]] = []
    network = 1
    for node_id, node in nodes.items():
        kind, variable = node["kind"], node["variable"]
        current_network = node_networks.get(node_id, 1)
        conditions = list(dict.fromkeys(tag for ref in node["incoming"] for tag in upstream_contacts(ref)))
        if kind in {"contact", "invariable"} and variable:
            instructions.append(_instruction(len(instructions), 0, current_network, "CONTACT", [variable], f"XML:{node_id}",
                                             reads=[variable], attributes={"negated": node["element"].get("negated") == "true"}))
        elif kind in {"coil", "outvariable"} and variable:
            storage = str(node["element"].get("storage", "none")).lower()
            opcode = "SET" if storage in {"set", "setdominant"} else "RESET" if storage in {"reset", "resetdominant"} else "COIL"
            instructions.append(_instruction(len(instructions), 0, current_network, opcode, [variable], f"XML:{node_id}",
                                             writes=[variable], condition_reads=conditions,
                                             attributes={"negated": node["element"].get("negated") == "true"}))
        elif kind in {"block", "functionblock"}:
            block_type = str(node["type"] or "BLOCK").upper()
            reads = list(conditions)
            outputs = []
            for child in node["element"].iter():
                child_kind = _local(child.tag).lower()
                value = _xml_variable(child)
                if value and child_kind in {"outputvariable", "outvariable"}:
                    outputs.append(value)
                elif value and child_kind in {"inputvariable", "invariable"}:
                    reads.append(value)
            attrs: dict[str, Any] = {"block_type": block_type}
            if block_type in _TIMERS:
                attrs.update(kind="timer", instance=variable or f"XML_BLOCK_{node_id}")
            elif block_type in _COUNTERS:
                attrs.update(kind="counter", instance=variable or f"XML_BLOCK_{node_id}")
            instructions.append(_instruction(len(instructions), 0, current_network, block_type, [], f"XML:{node_id}",
                                             reads=reads, writes=outputs, condition_reads=conditions, attributes=attrs))
    # PLCopen may embed ST rather than LD; include it as a separate normalized stream.
    for element in elements:
        if _local(element.tag).upper() == "ST" and "".join(element.itertext()).strip():
            st = parse_structured_text("".join(element.itertext()))
            for instruction in st["instructions"]:
                instruction = dict(instruction)
                instruction["index"] = len(instructions)
                instruction["network"] += network
                instructions.append(instruction)
    if not instructions:
        raise ParseError("PLC XML contains no supported logic elements")
    return _program("plcopen-xml", instructions, xml_nodes=len(elements))


def parse_structured_text(text: str) -> dict[str, Any]:
    if len(text.encode("utf-8", "replace")) > MAX_INPUT:
        raise ParseError("Structured Text exceeds input cap")
    masked = _line_comment_mask(text)
    instructions: list[dict[str, Any]] = []
    conditions: list[str] = []
    network = 1
    statements = re.split(r";|\n", masked)
    for statement in statements:
        raw = statement.strip()
        if not raw:
            continue
        upper = raw.upper()
        if upper.startswith(("IF ", "ELSIF ", "WHILE ")):
            expression = re.split(r"(?i)\b(?:THEN|DO)\b", raw, maxsplit=1)[0]
            expression = re.sub(r"(?i)^(?:IF|ELSIF|WHILE)\s+", "", expression)
            conditions = extract_tags(expression)
            instructions.append(_instruction(len(instructions), 0, network, "CONDITION", [expression], raw,
                                             reads=conditions))
            continue
        if upper in {"ELSE", "END_IF", "END_WHILE", "END_FOR"}:
            if upper.startswith("END_"):
                conditions = []
                network += 1
            continue
        assignment = re.match(r"([#%A-Za-z_][\w.#%\[\],]*)\s*:=\s*(.+)$", raw)
        if assignment:
            destination = extract_tags(assignment.group(1))
            reads = extract_tags(assignment.group(2))
            instructions.append(_instruction(len(instructions), 0, network, "ASSIGN", [assignment.group(1), assignment.group(2)], raw,
                                             reads=reads, writes=destination[:1], condition_reads=conditions))
            continue
        calls = _calls(raw)
        if calls:
            for name, args_text, _ in calls:
                args = split_arguments(args_text)
                named = {}
                for arg in args:
                    match = re.match(r"([A-Za-z_]\w*)\s*(?::=|=>)\s*(.*)", arg)
                    if match:
                        named[match.group(1).upper()] = match.group(2)
                reads = list(dict.fromkeys(tag for key, value in named.items() if key not in {"Q", "ET", "CV", "OUT", "ENO"}
                                           for tag in extract_tags(value)))
                writes = list(dict.fromkeys(tag for key, value in named.items() if key in {"Q", "ET", "CV", "OUT", "ENO"}
                                            for tag in extract_tags(value)))
                attrs: dict[str, Any] = {"call": name}
                opcode = name.upper()
                if opcode in _TIMERS or any(key in named for key in {"PT", "ET"}):
                    attrs.update(kind="timer", instance=name,
                                 preset_ms=parse_duration_ms(named.get("PT")))
                elif opcode in _COUNTERS or any(key in named for key in {"PV", "CV", "CU", "CD"}):
                    preset = named.get("PV")
                    attrs.update(kind="counter", instance=name,
                                 preset=int(preset) if preset and re.fullmatch(r"[+-]?\d+", preset.strip()) else None)
                instructions.append(_instruction(len(instructions), 0, network, opcode, args, raw,
                                                 reads=reads, writes=writes, condition_reads=conditions, attributes=attrs))
    if not instructions:
        raise ParseError("no supported Structured Text statements found")
    return _program("structured-text", instructions, source_lines=len(text.splitlines()))


def _cycles(edges: list[dict[str, Any]]) -> list[list[str]]:
    adjacency: dict[str, set[str]] = defaultdict(set)
    for edge in edges:
        adjacency[edge["source"]].add(edge["target"])
    visiting: set[str] = set()
    visited: set[str] = set()
    cycles: set[tuple[str, ...]] = set()

    def walk(node: str, path: list[str]) -> None:
        if node in visiting:
            start = path.index(node)
            cycle = path[start:]
            if cycle:
                rotations = [tuple(cycle[index:] + cycle[:index]) for index in range(len(cycle))]
                cycles.add(min(rotations))
            return
        if node in visited or len(path) > 256:
            return
        visiting.add(node)
        for target in adjacency.get(node, ()):
            walk(target, path + [target])
        visiting.remove(node)
        visited.add(node)

    for source in sorted(adjacency):
        walk(source, [source])
    return [list(cycle) for cycle in sorted(cycles)][:1000]


def analyze_instructions(instructions: list[dict[str, Any]]) -> dict[str, Any]:
    reads: dict[str, list[int]] = defaultdict(list)
    writes: dict[str, list[int]] = defaultdict(list)
    edges: list[dict[str, Any]] = []
    timers, counters, findings = [], [], []
    sets: dict[str, list[int]] = defaultdict(list)
    resets: dict[str, list[int]] = defaultdict(list)
    labels = {instruction.get("label"): instruction["index"] for instruction in instructions if instruction.get("label")}
    for instruction in instructions:
        for tag in instruction["reads"]:
            reads[tag].append(instruction["index"])
        for tag in instruction["writes"]:
            writes[tag].append(instruction["index"])
            sources = instruction["condition_reads"] or instruction["reads"]
            for source in sources:
                edges.append({"source": source, "target": tag, "instruction": instruction["index"],
                              "network": instruction["network"]})
            if tag_role(tag) == "physical-input":
                findings.append(_finding("write-to-input", "critical", "logic writes a physical/process input address",
                                         tag=tag, instruction=instruction["index"], line=instruction["line"]))
            if tag_role(tag) == "physical-output" and not instruction["condition_reads"] and instruction["opcode"] in _COILS | {"=", "ST", "ASSIGN"}:
                findings.append(_finding("unconditional-output", "high", "physical output write has no parsed enabling condition",
                                         tag=tag, instruction=instruction["index"], line=instruction["line"]))
            dangerous = re.search(r"(?i)(?:motor|pump|valve|heater|burner|drive|conveyor|fan|compressor|boiler)", tag)
            interlocked = any(re.search(r"(?i)(?:e[_-]?stop|safety|permit|permissive|interlock|guard|trip)", value)
                              for value in instruction["condition_reads"])
            if dangerous and not interlocked:
                findings.append(_finding("hazard-output-no-visible-interlock", "medium",
                                         "hazard-named output has no visible safety/permissive dependency in the parsed rung",
                                         tag=tag, instruction=instruction["index"], conditions=instruction["condition_reads"]))
        opcode = instruction["opcode"]
        if opcode in {"S", "SET", "OTL"}:
            for tag in instruction["writes"]:
                sets[tag].append(instruction["index"])
        if opcode in {"R", "RESET", "RST", "OTU"}:
            for tag in instruction["writes"]:
                resets[tag].append(instruction["index"])
        attrs = instruction.get("attributes", {})
        if attrs.get("kind") == "timer":
            timer = {"instruction": instruction["index"], "network": instruction["network"], **attrs}
            timers.append(timer)
            preset = attrs.get("preset_ms")
            if preset is not None and preset <= 0:
                findings.append(_finding("timer-nonpositive-preset", "high", "timer preset is zero or negative",
                                         instance=attrs.get("instance"), preset_ms=preset, instruction=instruction["index"]))
            elif preset is not None and preset > 7 * 86_400_000:
                findings.append(_finding("timer-extreme-preset", "medium", "timer preset exceeds seven days",
                                         instance=attrs.get("instance"), preset_ms=preset, instruction=instruction["index"]))
        if attrs.get("kind") == "counter":
            counter = {"instruction": instruction["index"], "network": instruction["network"], **attrs}
            counters.append(counter)
            preset = attrs.get("preset")
            if preset is not None and preset <= 0:
                findings.append(_finding("counter-nonpositive-preset", "high", "counter preset is zero or negative",
                                         instance=attrs.get("instance"), preset=preset, instruction=instruction["index"]))
        raw = instruction["raw"]
        if re.search(r"(?i)(?:FORCE|BYPASS|OVERRIDE|SIMULATE|JUMPER)", raw):
            findings.append(_finding("force-bypass-indicator", "critical", "logic contains a force/bypass/override indicator",
                                     instruction=instruction["index"], line=instruction["line"], raw=raw.strip()))
        if re.search(r"(?i)(?:\bAR[12]\b|\bANY\b|\bP#|\[[^]]+\])", raw):
            findings.append(_finding("indirect-addressing", "medium", "logic uses indirect/pointer addressing that needs manual bounds review",
                                     instruction=instruction["index"], line=instruction["line"]))
        if re.search(r"(?i)(?:\bDIV\s*\([^,]+,\s*0(?:\.0+)?\b|/\s*0(?:\.0+)?\b|/I\s+0\b|/D\s+0\b)", raw):
            findings.append(_finding("constant-divide-by-zero", "high", "logic contains a constant divide-by-zero expression",
                                     instruction=instruction["index"], line=instruction["line"]))
        if attrs.get("kind") == "jump" and attrs.get("unconditional"):
            target = attrs.get("target")
            if target in labels and labels[target] <= instruction["index"]:
                findings.append(_finding("backward-unconditional-jump", "high", "unconditional jump targets an earlier label",
                                         instruction=instruction["index"], target=target, target_instruction=labels[target]))
    for tag, locations in sets.items():
        if tag not in resets:
            findings.append(_finding("latch-without-reset", "high", "latched/set value has no parsed reset/unlatch",
                                     tag=tag, set_instructions=locations))
    for tag, locations in resets.items():
        if tag not in sets:
            findings.append(_finding("reset-without-set", "low", "reset/unlatch has no parsed set in this artifact",
                                     tag=tag, reset_instructions=locations))
    for tag, locations in writes.items():
        networks = sorted({instructions[index]["network"] for index in locations})
        if tag_role(tag) == "physical-output" and len(networks) > 1:
            findings.append(_finding("physical-output-multiple-writers", "high",
                                     "physical output is written from multiple networks/rungs",
                                     tag=tag, networks=networks, instructions=locations))
    for collection, kind in ((timers, "timer"), (counters, "counter")):
        instances: dict[str, set[int]] = defaultdict(set)
        for item in collection:
            if item.get("instance"):
                instances[str(item["instance"])].add(int(item["network"]))
        for instance, networks in instances.items():
            if len(networks) > 1:
                findings.append(_finding(f"{kind}-instance-reused", "medium",
                                         f"{kind} instance is driven from multiple networks/rungs",
                                         instance=instance, networks=sorted(networks)))
    xref = {tag: {"role": tag_role(tag), "reads": reads.get(tag, []), "writes": writes.get(tag, [])}
            for tag in sorted(set(reads) | set(writes))}
    unique_edges = list({(edge["source"], edge["target"], edge["instruction"]): edge for edge in edges}.values())
    rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    findings = sorted({(item["kind"], item.get("tag"), item.get("instruction"), item.get("instance")): item
                       for item in findings}.values(),
                      key=lambda item: (-rank.get(item["severity"], 0), item["kind"], str(item.get("tag", ""))))
    return {"cross_reference": xref, "dataflow": sorted(unique_edges, key=lambda edge: (edge["source"], edge["target"], edge["instruction"])),
            "cycles": _cycles(unique_edges), "timers": timers, "counters": counters, "findings": findings}


def _program(dialect: str, instructions: list[dict[str, Any]], **metadata: Any) -> dict[str, Any]:
    analysis = analyze_instructions(instructions)
    return {"format": "plc-logic", "dialect": dialect, "instruction_count": len(instructions),
            "instructions": instructions, **metadata, **analysis}


def detect_dialect(data: bytes | str, name: str = "") -> str:
    raw = data.encode() if isinstance(data, str) else bytes(data)
    if raw.lstrip().startswith(b"<") or name.lower().endswith(('.xml', '.plcopen')):
        return "plcopen-xml"
    text = raw.decode("utf-8", "replace")
    if re.search(r"(?i)\b(?:XIC|XIO|OTE|OTL|OTU|RTO)\s*\(", text) or name.lower().endswith((".l5k", ".lad")):
        return "ladder-text"
    if (":=" in text or re.search(r"(?i)\b(?:IF\b.+\bTHEN|END_IF|VAR_GLOBAL)\b", text)
            or name.lower().endswith((".st", ".scl"))):
        return "structured-text"
    return "awl"


def parse_plc_logic(data: bytes | str, *, dialect: str = "auto", name: str = "") -> dict[str, Any]:
    raw = data.encode() if isinstance(data, str) else bytes(data)
    if len(raw) > MAX_INPUT:
        raise ParseError("PLC artifact exceeds input cap")
    chosen = detect_dialect(raw, name) if dialect == "auto" else dialect.lower()
    if chosen in {"plcopen", "plcopen-xml", "xml"}:
        return parse_plcopen_xml(raw)
    text = raw.decode("utf-8", "strict")
    if chosen in {"ladder", "ladder-text", "l5k"}:
        return parse_ladder_text(text)
    if chosen in {"st", "scl", "structured-text"}:
        return parse_structured_text(text)
    if chosen in {"awl", "stl", "il", "statement-list"}:
        return parse_awl(text)
    raise ParseError(f"unsupported PLC dialect: {dialect}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline PLC ladder/AWL/STL dataflow and safety triage")
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--dialect", default="auto",
                        choices=("auto", "awl", "stl", "il", "ladder", "ladder-text", "l5k", "st", "scl", "structured-text", "plcopen-xml"))
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args(argv)
    report = parse_plc_logic(args.artifact.read_bytes(), dialect=args.dialect, name=args.artifact.name)
    print(json.dumps(report, indent=2 if args.pretty else None, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
