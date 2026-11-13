#!/usr/bin/env python3
"""Offline reversing-depth planner and static structure helpers.

This module does not execute a delivered binary.  It generates a bounded angr harness for the
player to run inside the repository's networkless Docker image, analyzes supplied disassembly text
for opaque predicates/control-flow flattening, maps VM handler blocks by mnemonic semantics, and
recovers Go/Rust symbol/type leads from binary string/symbol data.

Challenge bytes are never imported, eval'd, or exec'd.  The angr operation emits source text only;
the engine itself does not import angr or launch the harness.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
MAX_INPUT = 128 << 20
MAX_TEXT = 8 << 20
MAX_SPEC = 1 << 20
MAX_SYMBOLS = 20000
MAX_BLOCKS = 10000
MAX_BLOCK_LINES = 4096


def _load(name: str, path: Path):
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path.name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


facts_reader = _load("csctf_reverse_facts", REPO / "solvers" / "binary" / "facts.py")


def _address(value, field: str) -> int:
    if isinstance(value, str):
        try:
            value = int(value, 0)
        except ValueError as exc:
            raise ValueError(f"{field} is not an integer address") from exc
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < 1 << 64:
        raise ValueError(f"{field} is outside the 64-bit address range")
    return value


def _byte_sequence(spec: dict, name: str) -> bytes:
    text, hexa = spec.get(name), spec.get(name + "_hex")
    if text is not None and hexa is not None:
        raise ValueError(f"choose either {name} or {name}_hex")
    if text is not None:
        if not isinstance(text, str):
            raise ValueError(f"{name} must be text")
        value = text.encode("utf-8")
    elif hexa is not None:
        if not isinstance(hexa, str) or len(hexa) % 2:
            raise ValueError(f"{name}_hex must be even-length hex")
        try:
            value = bytes.fromhex(hexa)
        except ValueError as exc:
            raise ValueError(f"{name}_hex is not hex") from exc
    else:
        value = b""
    if len(value) > 4096:
        raise ValueError(f"{name} exceeds the input cap")
    return value


def validate_angr_spec(spec: dict) -> dict:
    """Normalize the safe declarative subset accepted by the harness generator."""
    if not isinstance(spec, dict):
        raise ValueError("angr specification must be an object")
    binary = spec.get("binary", "/chal/challenge")
    mode = spec.get("mode", "stdin")
    length = spec.get("length")
    if not isinstance(binary, str) or not binary or len(binary) > 4096 or "\x00" in binary:
        raise ValueError("binary path is invalid")
    if mode not in ("stdin", "argv"):
        raise ValueError("mode must be stdin or argv")
    if not isinstance(length, int) or isinstance(length, bool) or not 1 <= length <= 4096:
        raise ValueError("length must be in 1..4096")
    find = spec.get("find")
    avoid = spec.get("avoid", [])
    if not isinstance(find, list) or not 1 <= len(find) <= 64:
        raise ValueError("find must contain 1..64 addresses")
    if not isinstance(avoid, list) or len(avoid) > 256:
        raise ValueError("avoid may contain at most 256 addresses")
    find = [_address(value, "find") for value in find]
    avoid = [_address(value, "avoid") for value in avoid]
    prefix, suffix = _byte_sequence(spec, "prefix"), _byte_sequence(spec, "suffix")
    if bool(spec.get("null_terminate", False)) and not suffix.endswith(b"\x00"):
        suffix += b"\x00"
    if len(prefix) + len(suffix) > length:
        raise ValueError("prefix and suffix exceed symbolic input length")
    alphabet = spec.get("alphabet", "printable")
    if alphabet == "printable":
        alphabet_values = list(range(0x20, 0x7F))
    elif alphabet == "alnum":
        alphabet_values = list(b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
    elif isinstance(alphabet, list) and 1 <= len(alphabet) <= 256 and all(
            isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 255 for value in alphabet):
        alphabet_values = sorted(set(alphabet))
    else:
        raise ValueError("alphabet must be printable, alnum, or a byte list")
    base = spec.get("base_addr")
    base = _address(base, "base_addr") if base is not None else None
    return {"binary": binary, "mode": mode, "length": length, "find": find, "avoid": avoid,
            "prefix": prefix, "suffix": suffix, "alphabet": alphabet_values, "base_addr": base,
            "null_terminate": bool(spec.get("null_terminate", False))}


def build_angr_harness(spec: dict) -> str:
    """Return a reviewable Python harness; it is not imported or run by this engine."""
    value = validate_angr_spec(spec)
    project_opts = "{}" if value["base_addr"] is None else repr({"main_opts": {"base_addr": value["base_addr"]}})
    # Embed normalized primitives through repr; no challenge-derived source expression is accepted.
    lines = [
        "#!/usr/bin/env python3",
        '"""Generated offline; run only in the CSCTF networkless Docker sandbox."""',
        "import json",
        "import angr",
        "import claripy",
        f"BINARY = {value['binary']!r}",
        f"LENGTH = {value['length']!r}",
        f"FIND = {value['find']!r}",
        f"AVOID = {value['avoid']!r}",
        f"ALPHABET = {value['alphabet']!r}",
        "symbolic = claripy.BVS('candidate', LENGTH * 8)",
        f"project = angr.Project(BINARY, auto_load_libs=False, **{project_opts})",
    ]
    if value["mode"] == "stdin":
        lines += [
            "stream = angr.SimFileStream(name='stdin', content=symbolic, has_end=True)",
            "state = project.full_init_state(stdin=stream)",
        ]
    else:
        lines.append("state = project.full_init_state(args=[BINARY, symbolic])")
    for index, byte in enumerate(value["prefix"]):
        lines.append(f"state.solver.add(symbolic.get_byte({index}) == {byte})")
    suffix_start = value["length"] - len(value["suffix"])
    for offset, byte in enumerate(value["suffix"]):
        lines.append(f"state.solver.add(symbolic.get_byte({suffix_start + offset}) == {byte})")
    unconstrained = range(len(value["prefix"]), suffix_start)
    if len(value["alphabet"]) >= 95 and value["alphabet"] == list(range(0x20, 0x7F)):
        for index in unconstrained:
            lines.append(f"state.solver.add(symbolic.get_byte({index}) >= 0x20, symbolic.get_byte({index}) <= 0x7e)")
    else:
        for index in unconstrained:
            lines.append(f"state.solver.add(claripy.Or(*[symbolic.get_byte({index}) == b for b in ALPHABET]))")
    lines += [
        "manager = project.factory.simgr(state)",
        "manager.explore(find=lambda s: s.addr in FIND, avoid=lambda s: s.addr in AVOID)",
        "candidates = []",
        "for found in manager.found[:64]:",
        "    for model in found.solver.eval_upto(symbolic, 2, cast_to=bytes):",
        "        if model not in candidates:",
        "            candidates.append(model)",
        "result = {'candidates_hex': [item.hex() for item in candidates[:128]],",
        "          'unique_in_found_states': len(candidates) == 1,",
        "          'found_states': len(manager.found), 'active_states': len(manager.active)}",
        "print(json.dumps(result, sort_keys=True))",
    ]
    script = "\n".join(lines) + "\n"
    if len(script) > MAX_TEXT:
        raise ValueError("generated harness exceeds cap")
    return script


_INSN = re.compile(r"^\s*(?:0x)?([0-9A-Fa-f]{3,16})\s*:?\s+(?:[0-9A-Fa-f]{2}\s+)*([A-Za-z.]+)\s*(.*?)\s*$")


def parse_disassembly(text: str) -> list[dict]:
    if not isinstance(text, str) or len(text) > MAX_TEXT:
        raise ValueError("disassembly exceeds 8 MiB cap")
    out = []
    for line in text.splitlines():
        match = _INSN.match(line)
        if not match:
            continue
        out.append({"address": int(match.group(1), 16), "mnemonic": match.group(2).lower(),
                    "operands": match.group(3).strip(), "text": line.strip()})
        if len(out) >= 500000:
            break
    return out


def analyze_control_flow(text: str) -> dict:
    """Find high-confidence invariant branches and flattening indicators in disassembly text."""
    instructions = parse_disassembly(text)
    opaque, notes = [], []
    for index, instruction in enumerate(instructions):
        mnemonic = instruction["mnemonic"]
        if not (mnemonic.startswith("j") and mnemonic not in ("jmp", "jmpq")):
            continue
        window = instructions[max(0, index - 3):index]
        reason = None
        if window:
            last = window[-1]
            operands = [part.strip().lstrip("%") for part in last["operands"].split(",")]
            if last["mnemonic"] in ("cmp", "cmpq", "cmpl", "cmpw", "cmpb") and len(operands) == 2 and operands[0] == operands[1]:
                reason = "comparison of a value with itself has a constant result"
            elif last["mnemonic"] in ("test", "testq", "testl") and len(operands) == 2 and operands[0] == operands[1]:
                prev = window[-2] if len(window) >= 2 else None
                if prev and prev["mnemonic"].startswith("xor"):
                    xor_ops = [part.strip().lstrip("%") for part in prev["operands"].split(",")]
                    if len(xor_ops) == 2 and xor_ops[0] == xor_ops[1] == operands[0]:
                        reason = "xor-self zeroes the tested register"
            elif last["mnemonic"].startswith("cmp") and re.match(r"(?:\$?0x?0+|0)$", last["operands"].split(",")[0].strip()):
                prev = window[-2] if len(window) >= 2 else None
                if prev and prev["mnemonic"].startswith("xor"):
                    reason = "zeroed register is compared with zero"
        if reason:
            opaque.append({"score": 100, "branch": instruction["address"], "mnemonic": mnemonic,
                           "target": instruction["operands"], "reason": reason,
                           "suggestion": "prove flags in the decompiler, then replace with the determined edge"})
    indirect = [item for item in instructions if item["mnemonic"] in ("jmp", "jmpq")
                and ("*" in item["operands"] or "[" in item["operands"])]
    compares = [item for item in instructions if item["mnemonic"].startswith("cmp")]
    conditional = [item for item in instructions if item["mnemonic"].startswith("j")
                   and item["mnemonic"] not in ("jmp", "jmpq")]
    if indirect:
        notes.append({"score": 85, "kind": "indirect-dispatch",
                      "note": f"{len(indirect)} indirect jump(s): recover the table/index expression and name each target handler"})
    if len(compares) >= 4 and len(conditional) >= 4:
        notes.append({"score": 75, "kind": "state-dispatch",
                      "note": "repeated compare/conditional branches may be a flattened state dispatcher; track the state variable in SSA"})
    if len({item["operands"] for item in compares}) < max(2, len(compares) // 3) and len(compares) >= 6:
        notes.append({"score": 82, "kind": "reused-state",
                      "note": "many comparisons reuse a small operand set; slice writes to that operand to recover original CFG edges"})
    return {"instruction_count": len(instructions), "opaque_predicates": opaque[:1024],
            "flattening_notes": sorted(notes, key=lambda item: -item["score"])}


_LABEL = re.compile(r"(?m)^\s*(?:0x)?([0-9A-Fa-f]{3,16})\s+<([^>]+)>:\s*$")


def _handler_semantics(body: str) -> list[str]:
    mnemonics = [match.group(2).lower() for line in body.splitlines() if (match := _INSN.match(line))]
    joined = " " + " ".join(mnemonics) + " "
    semantics = []
    for label, names in (
        ("arithmetic-add", ("add", "adc", "inc")), ("arithmetic-sub", ("sub", "sbb", "dec")),
        ("bitwise-xor", ("xor",)), ("bitwise", ("and", "or", "not")),
        ("compare", ("cmp", "test")), ("branch", ("jmp", "je", "jne", "jz", "jnz")),
        ("call", ("call", "callq")), ("stack", ("push", "pop")),
        ("shift-rotate", ("shl", "shr", "sar", "rol", "ror")),
        ("return-halt", ("ret", "retq", "hlt")),
    ):
        if any(f" {name} " in joined or any(mnemonic.startswith(name) for mnemonic in mnemonics) for name in names):
            semantics.append(label)
    return semantics or ["data-move/unknown"]


def map_vm_handlers(text: str) -> dict:
    """Split labeled handler blocks and classify their operations without executing bytecode."""
    if not isinstance(text, str) or len(text) > MAX_TEXT:
        raise ValueError("VM disassembly exceeds cap")
    labels = list(_LABEL.finditer(text))
    handlers = []
    for index, match in enumerate(labels[:MAX_BLOCKS]):
        name = match.group(2)
        if not re.search(r"(?i)(?:handler|opcode|op[_-]?[0-9a-f]|vm[_.$])", name):
            continue
        end = labels[index + 1].start() if index + 1 < len(labels) else len(text)
        body = "\n".join(text[match.end():end].splitlines()[:MAX_BLOCK_LINES])
        opcode_match = re.search(r"(?i)(?:opcode|op)[_-]?(?:0x)?([0-9a-f]{1,4})", name)
        handlers.append({"address": int(match.group(1), 16), "name": name,
                         "opcode": int(opcode_match.group(1), 16) if opcode_match else None,
                         "semantics": _handler_semantics(body),
                         "instruction_count": len(parse_disassembly(body))})
    dispatch = analyze_control_flow(text)["flattening_notes"]
    return {"handlers": handlers, "handler_count": len(handlers), "dispatcher_notes": dispatch}


_PRINTABLE = re.compile(rb"[\x20-\x7e]{4,512}")
_RUST_LEGACY = re.compile(r"^_?ZN(?:\d+[A-Za-z0-9_$]+)+E$")


def demangle_rust_legacy(symbol: str) -> str | None:
    raw = symbol[1:] if symbol.startswith("_") else symbol
    if not raw.startswith("ZN") or not raw.endswith("E"):
        return None
    at, end, parts = 2, len(raw) - 1, []
    while at < end:
        match = re.match(r"\d+", raw[at:end])
        if not match:
            return None
        length = int(match.group(0))
        at += len(match.group(0))
        if length <= 0 or at + length > end:
            return None
        parts.append(raw[at:at + length])
        at += length
        if len(parts) > 128:
            return None
    if parts and re.fullmatch(r"h[0-9a-f]{16}", parts[-1]):
        parts.pop()
    return "::".join(parts) if parts else None


def recover_go_rust_symbols(data: bytes) -> dict:
    if not isinstance(data, bytes) or len(data) > MAX_INPUT:
        raise ValueError("binary exceeds 128 MiB cap")
    strings = []
    for match in _PRINTABLE.finditer(data):
        strings.append(match.group().decode("ascii", "replace"))
        if len(strings) >= 500000:
            break
    go, rust, types = [], [], []
    for text in strings:
        for token in re.findall(r"[A-Za-z0-9_./-]{1,180}(?:\.\(\*?[A-Za-z0-9_]+\))?\.[A-Za-z0-9_$<>-]{1,100}", text):
            if ("/" in token or token.startswith(("main.", "runtime.", "type:."))) and token not in go:
                go.append(token)
                if len(go) >= MAX_SYMBOLS:
                    break
        for token in re.findall(r"_?ZN(?:\d+[A-Za-z0-9_$]+)+E|_R[A-Za-z0-9_$.]+", text):
            demangled = demangle_rust_legacy(token)
            item = {"raw": token, "demangled": demangled, "scheme": "legacy" if demangled else "v0"}
            if item not in rust:
                rust.append(item)
                if len(rust) >= MAX_SYMBOLS:
                    break
        if text.startswith(("type:", "go:itab.", "runtime.gcbits.", "*runtime._type")) or "drop_in_place" in text:
            types.append(text[:512])
    facts = facts_reader.facts(data)
    return {"runtime_facts": {key: value for key, value in facts.items()
                               if key.startswith(("go_", "rustc_"))},
            "go_symbols": go[:MAX_SYMBOLS], "rust_symbols": rust[:MAX_SYMBOLS],
            "type_leads": list(dict.fromkeys(types))[:MAX_SYMBOLS]}


def _read(path: str, cap: int) -> bytes:
    with Path(path).open("rb") as handle:
        data = handle.read(cap + 1)
    if len(data) > cap:
        raise ValueError("input exceeds size cap")
    return data


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # pragma: no cover
        raise ValueError(message)


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(prog="reverse_depth.py")
    parser.add_argument("operation", choices=("angr", "cfg", "vm", "symbols"))
    parser.add_argument("input")
    parser.add_argument("--json", action="store_true")
    try:
        args = parser.parse_args(argv)
        raw = _read(args.input, MAX_INPUT if args.operation == "symbols" else MAX_TEXT)
        if args.operation == "angr":
            spec = json.loads(raw.decode("utf-8"))
            script = build_angr_harness(spec)
            result = {"harness": script, "run_in": "tools/sandbox.py / networkless Docker"}
        elif args.operation == "cfg":
            result = analyze_control_flow(raw.decode("utf-8", "replace"))
        elif args.operation == "vm":
            result = map_vm_handlers(raw.decode("utf-8", "replace"))
        else:
            result = recover_go_rust_symbols(raw)
        if args.json:
            print(json.dumps(result, sort_keys=True))
        elif args.operation == "angr":
            print(result["harness"], end="")
        else:
            print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, TypeError, ValueError, OverflowError, UnicodeError, json.JSONDecodeError,
            RecursionError, MemoryError) as exc:
        print(f"reverse_depth: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
