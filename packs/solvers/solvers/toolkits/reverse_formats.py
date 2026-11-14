#!/usr/bin/env python3
"""Strict static analyzers for managed/VM formats and packer evidence.

Nothing in this module executes, imports, unpacks, or emulates challenge bytes.  Packer results are
multi-evidence classifications plus review plans; symbolic output is source text for later review and
networkless Docker use; VM lifting only applies a caller-supplied declarative opcode table.  Ambiguous,
truncated, or inconsistent input is declined rather than promoted to a recovered value.
"""
from __future__ import annotations

import argparse
import dataclasses
import hashlib
import importlib.util
import json
import re
import struct
import sys
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
MAX_INPUT = 128 << 20
MAX_SECTIONS = 4096
MAX_ITEMS = 65536
MAX_TEXTS = 20000
MAX_VM_BYTES = 1 << 20


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


facts_reader = _load("csctf_r5_reverse_facts", REPO / "solvers" / "binary" / "facts.py")
reverse_depth = _load("csctf_r5_reverse_depth", HERE / "reverse_depth.py")


def _read(path: str, cap: int = MAX_INPUT) -> bytes:
    with Path(path).open("rb") as handle:
        data = handle.read(cap + 1)
    if len(data) > cap:
        raise ValueError(f"input exceeds {cap} bytes")
    return data


def _texts(data: bytes) -> list[str]:
    result = []
    for match in re.finditer(rb"[\x20-\x7e]{4,512}", data):
        result.append(match.group().decode("ascii", "replace"))
        if len(result) >= MAX_TEXTS:
            break
    return result


def _container(data: bytes) -> str | None:
    if _pe_layout(data) is not None:
        return "pe"
    if (data.startswith(b"\x7fELF") and len(data) >= 20 and data[4] in (1, 2)
            and data[5] in (1, 2) and data[6] == 1):
        return "elf"
    if (data[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce")
            and len(data) >= 28):
        return "macho"
    if data.startswith(b"\0asm"):
        return "wasm"
    if (data.startswith(b"\xca\xfe\xba\xbe") and len(data) >= 10
            and struct.unpack_from(">H", data, 6)[0] >= 45):
        return "jvm-class"
    return None


def _pe_layout(data: bytes) -> dict[str, Any] | None:
    """Validated PE header/section layout sufficient for RVA mapping."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if pe > len(data) - 24 or data[pe:pe + 4] != b"PE\0\0":
        return None
    _machine, sections, _stamp, _sym, _nsym, optional_size, _chars = struct.unpack_from("<HHIIIHH", data, pe + 4)
    optional = pe + 24
    section_at = optional + optional_size
    if not 0 < sections <= 96 or optional_size < 96 or section_at > len(data) - sections * 40:
        return None
    magic = struct.unpack_from("<H", data, optional)[0]
    if magic == 0x10B:
        count_at, directories = optional + 92, optional + 96
    elif magic == 0x20B:
        count_at, directories = optional + 108, optional + 112
    else:
        return None
    if count_at + 4 > section_at:
        return None
    number_directories = struct.unpack_from("<I", data, count_at)[0]
    rows = []
    for index in range(sections):
        at = section_at + index * 40
        virtual_size, virtual_address, raw_size, raw_at = struct.unpack_from("<IIII", data, at + 8)
        if raw_size and (raw_at > len(data) or raw_size > len(data) - raw_at):
            return None
        rows.append((virtual_address, max(virtual_size, raw_size), raw_at, raw_size))
    return {"directories": directories, "directory_count": number_directories,
            "directory_end": section_at, "sections": rows}


def _map_pe_rva(layout: dict[str, Any], rva: int, size: int, data_size: int) -> int | None:
    for virtual, span, raw, raw_size in layout["sections"]:
        if virtual <= rva and size <= raw_size and rva - virtual <= raw_size - size:
            offset = raw + rva - virtual
            if offset <= data_size - size:
                return offset
    return None


def _pe_cli_metadata(data: bytes) -> tuple[int, int] | None:
    layout = _pe_layout(data)
    if layout is None or layout["directory_count"] <= 14:
        return None
    entry = layout["directories"] + 14 * 8
    if entry + 8 > layout["directory_end"]:
        return None
    cli_rva, cli_size = struct.unpack_from("<II", data, entry)
    if not cli_rva or cli_size < 0x48:
        return None
    cli = _map_pe_rva(layout, cli_rva, 0x48, len(data))
    if cli is None or struct.unpack_from("<I", data, cli)[0] < 0x48:
        return None
    metadata_rva, metadata_size = struct.unpack_from("<II", data, cli + 8)
    metadata = _map_pe_rva(layout, metadata_rva, metadata_size, len(data))
    if metadata is None or metadata_size < 16 or data[metadata:metadata + 4] != b"BSJB":
        return None
    return metadata, metadata_size


@dataclasses.dataclass(frozen=True)
class Finding:
    kind: str
    confidence: str
    evidence: tuple[str, ...]
    verified: bool
    note: str
    review_plan: tuple[str, ...] = ()


def packer_evidence(data: bytes) -> list[dict[str, Any]]:
    """Return packer candidates only when container and independent markers agree."""
    if not isinstance(data, bytes) or len(data) > MAX_INPUT:
        raise ValueError("binary input is invalid or too large")
    container = _container(data)
    if container not in {"pe", "elf", "macho"}:
        return []
    low = data.lower()
    rows: list[Finding] = []
    upx = []
    if b"UPX!" in data:
        upx.append("UPX! signature")
    if b"UPX0" in data and b"UPX1" in data:
        upx.append("paired UPX0/UPX1 section markers")
    if b"$Id: UPX " in data:
        upx.append("UPX version identifier")
    if len(upx) >= 2:
        rows.append(Finding(
            "UPX", "high", tuple(upx), False,
            "packer evidence only; accept unpacked bytes only if their container validates independently",
            ("review the exact input hash", "run `upx -t` then `upx -d` only in tools/sandbox.py",
             "re-run static triage on the unpacked copy and compare architecture/entrypoint"),
        ))
    elif upx:
        rows.append(Finding("UPX-like", "low", tuple(upx), False,
                            "one embedded marker can be bait or ordinary data; no unpack plan emitted"))

    products = (
        ("VMProtect", ((b".vmp0", ".vmp0 section marker"), (b".vmp1", ".vmp1 section marker"),
                       (b"vmprotect", "VMProtect product string"))),
        ("Themida/WinLicense", ((b".themida", ".themida section marker"),
                                (b"themida", "Themida product string"),
                                (b"winlicense", "WinLicense product string"),
                                (b".winlice", ".winlice section marker"))),
    )
    if container == "pe":
        for name, markers in products:
            evidence = tuple(label for marker, label in markers if marker in low)
            # Product strings alone are easy to plant.  Require two distinct marker classes.
            if len(evidence) >= 2:
                rows.append(Finding(
                    name, "medium", evidence, False,
                    "commercial-protector evidence; version and unpacked code are not inferred",
                    ("map executable/high-entropy sections statically", "identify dispatcher/VM entry stubs",
                     "trace only in the networkless sacrificial debugger container"),
                ))
            elif evidence:
                rows.append(Finding(name + "-like", "low", evidence, False,
                                    "single marker is insufficient; decline product attribution"))
    return [dataclasses.asdict(row) for row in rows]


def _u32(data: bytes, at: int, end: int) -> tuple[int, int]:
    value = 0
    for shift in range(0, 35, 7):
        if at >= end:
            raise ValueError("truncated unsigned LEB128")
        byte = data[at]
        at += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            if value > 0xFFFFFFFF:
                raise ValueError("u32 LEB128 overflow")
            # The WebAssembly spec permits non-minimal (zero-padded) uN encodings up
            # to ceil(N/7) bytes, which the range(0,35,7) bound already enforces, and
            # wasmtime accepts them -- so a padded non-zero section size must parse.
            # The one form still refused is a value that pads down to zero, whose
            # degenerate zero-length framing has no second legitimate interpretation.
            if shift and byte == 0 and value == 0:
                raise ValueError("non-canonical unsigned LEB128")
            return value, at
    raise ValueError("unterminated unsigned LEB128")


def _name(data: bytes, at: int, end: int) -> tuple[str, int]:
    size, at = _u32(data, at, end)
    if size > end - at:
        raise ValueError("WASM name exceeds section")
    try:
        value = data[at:at + size].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("WASM name is not UTF-8") from exc
    return value, at + size


def _limits(data: bytes, at: int, end: int) -> int:
    flags, at = _u32(data, at, end)
    if flags & ~0x07:
        raise ValueError("unsupported WASM limits flags")
    _minimum, at = _u32(data, at, end)
    if flags & 1:
        _maximum, at = _u32(data, at, end)
    return at


def _import_desc(data: bytes, at: int, end: int, kind: int) -> int:
    if kind in (0, 4):  # function / tag
        if kind == 4:
            if at >= end or data[at] != 0:
                raise ValueError("unsupported WASM tag attribute")
            at += 1
        _typeidx, at = _u32(data, at, end)
        return at
    if kind == 1:  # table
        if at >= end or data[at] not in (0x70, 0x6F):
            raise ValueError("unsupported WASM table reference type")
        return _limits(data, at + 1, end)
    if kind == 2:
        return _limits(data, at, end)
    if kind == 3:
        if at + 2 > end or data[at] not in (0x7F, 0x7E, 0x7D, 0x7C, 0x7B, 0x70, 0x6F) or data[at + 1] not in (0, 1):
            raise ValueError("invalid WASM global type")
        return at + 2
    raise ValueError("unknown WASM import kind")


def parse_wasm(data: bytes) -> dict[str, Any]:
    """Parse bounded module sections, import/export names and code body framing."""
    if not isinstance(data, bytes) or len(data) > MAX_INPUT:
        raise ValueError("WASM input is invalid or too large")
    if len(data) < 8 or data[:4] != b"\0asm":
        raise ValueError("not a WebAssembly binary")
    version = int.from_bytes(data[4:8], "little")
    if version != 1:
        raise ValueError(f"unsupported WebAssembly version {version}")
    # Section ids are not their semantic order: data-count (12) precedes code (10),
    # and the exception-handling tag section (13) sits before globals.
    order = {1: 1, 2: 2, 3: 3, 4: 4, 5: 5, 13: 6, 6: 7, 7: 8,
             8: 9, 9: 10, 12: 11, 10: 12, 11: 13}
    at, last_rank, sections = 8, 0, []
    imports: list[dict[str, Any]] = []
    exports: list[dict[str, Any]] = []
    custom_names: list[str] = []
    code_bodies: list[dict[str, int]] = []
    while at < len(data):
        if len(sections) >= MAX_SECTIONS:
            raise ValueError("too many WASM sections")
        section_id = data[at]
        at += 1
        size, at = _u32(data, at, len(data))
        end = at + size
        if end > len(data):
            raise ValueError("WASM section exceeds file")
        if section_id != 0:
            rank = order.get(section_id)
            if rank is None or rank <= last_rank:
                raise ValueError("unknown or out-of-order WASM section")
            last_rank = rank
        item: dict[str, Any] = {"id": section_id, "offset": at, "size": size}
        cursor = at
        if section_id == 0:
            # A custom section's required name field must be present; a zero-size section
            # leaves no room for it and is rejected by the reference validator.
            value, cursor = _name(data, cursor, end)
            custom_names.append(value)
            item["name"] = value
        elif section_id == 2:
            count, cursor = _u32(data, cursor, end)
            if count > MAX_ITEMS:
                raise ValueError("too many WASM imports")
            for _ in range(count):
                module, cursor = _name(data, cursor, end)
                name, cursor = _name(data, cursor, end)
                if cursor >= end:
                    raise ValueError("truncated WASM import")
                kind = data[cursor]
                cursor = _import_desc(data, cursor + 1, end, kind)
                imports.append({"module": module, "name": name, "kind": kind})
        elif section_id == 7:
            count, cursor = _u32(data, cursor, end)
            if count > MAX_ITEMS:
                raise ValueError("too many WASM exports")
            for _ in range(count):
                name, cursor = _name(data, cursor, end)
                if cursor >= end:
                    raise ValueError("truncated WASM export")
                kind = data[cursor]
                if kind > 4:
                    raise ValueError("unknown WASM export kind")
                index, cursor = _u32(data, cursor + 1, end)
                exports.append({"name": name, "kind": kind, "index": index})
        elif section_id == 10:
            count, cursor = _u32(data, cursor, end)
            if count > MAX_ITEMS:
                raise ValueError("too many WASM code bodies")
            for index in range(count):
                body_size, body_at = _u32(data, cursor, end)
                body_end = body_at + body_size
                if body_end > end:
                    raise ValueError("WASM code body exceeds section")
                local_groups, local_at = _u32(data, body_at, body_end)
                if local_groups > MAX_ITEMS:
                    raise ValueError("too many WASM local groups")
                for _ in range(local_groups):
                    _n, local_at = _u32(data, local_at, body_end)
                    if local_at >= body_end:
                        raise ValueError("truncated WASM local type")
                    local_at += 1
                if body_size == 0 or data[body_end - 1] != 0x0B:
                    raise ValueError("WASM function body lacks end opcode")
                code_bodies.append({"index": index, "offset": local_at, "size": body_end - local_at})
                cursor = body_end
        if section_id in (2, 7, 10) and cursor != end:
            raise ValueError("trailing bytes in parsed WASM section")
        sections.append(item)
        at = end
    return {"format": "wasm-module", "version": version, "sections": sections,
            "imports": imports, "exports": exports, "custom_sections": custom_names,
            "code_bodies": code_bodies, "verified_structure": True,
            "note": "names and framing are byte-verified; behavior is not inferred"}


def _parse_dotnet_root(data: bytes, root: int) -> dict[str, Any]:
    if root + 16 > len(data):
        raise ValueError("truncated CLR metadata root")
    major, minor, _reserved, version_size = struct.unpack_from("<HHII", data, root + 4)
    if not 1 <= version_size <= 1024 or root + 16 + version_size > len(data):
        raise ValueError("invalid CLR metadata version length")
    raw_version = data[root + 16:root + 16 + version_size].split(b"\0", 1)[0]
    try:
        version = raw_version.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("CLR metadata version is not ASCII") from exc
    at = (root + 16 + version_size + 3) & ~3
    if at + 4 > len(data):
        raise ValueError("truncated CLR stream header")
    flags, count = struct.unpack_from("<HH", data, at)
    at += 4
    if count > 64:
        raise ValueError("too many CLR metadata streams")
    streams = []
    seen = set()
    for _ in range(count):
        if at + 8 > len(data):
            raise ValueError("truncated CLR stream record")
        offset, size = struct.unpack_from("<II", data, at)
        name_end = data.find(b"\0", at + 8, min(len(data), at + 8 + 32))
        if name_end < 0:
            raise ValueError("unterminated CLR stream name")
        try:
            name = data[at + 8:name_end].decode("ascii")
        except UnicodeDecodeError as exc:
            raise ValueError("CLR stream name is not ASCII") from exc
        if name not in {"#~", "#-", "#Strings", "#US", "#GUID", "#Blob", "#Pdb", "#JTD"}:
            raise ValueError(f"unknown CLR stream name {name!r}")
        if name in seen or offset > len(data) - root or size > len(data) - root - offset:
            raise ValueError("duplicate or out-of-range CLR metadata stream")
        seen.add(name)
        streams.append({"name": name, "offset": root + offset, "size": size})
        at = (name_end + 4) & ~3
    if not ({"#~", "#-"} & seen) or "#Strings" not in seen:
        raise ValueError("CLR metadata lacks tables or string heap")
    ranges = sorted((row["offset"], row["offset"] + row["size"], row["name"]) for row in streams)
    for index, (start, end, _name_value) in enumerate(ranges):
        if start < at or (index and start < ranges[index - 1][1]):
            raise ValueError("CLR stream overlaps headers or another stream")
    return {"format": "dotnet-metadata", "root_offset": root, "major": major, "minor": minor,
            "runtime_version": version, "flags": flags, "streams": streams,
            "verified_structure": True,
            "note": "metadata root/streams are bounds-checked; assembly semantics are not inferred"}


def parse_dotnet_metadata(data: bytes) -> dict[str, Any]:
    """Parse one unambiguous CLR BSJB metadata root, without loading an assembly."""
    if not isinstance(data, bytes) or len(data) > MAX_INPUT:
        raise ValueError(".NET input is invalid or too large")
    roots, at = [], 0
    while len(roots) < 64:
        root = data.find(b"BSJB", at)
        if root < 0:
            break
        at = root + 4
        try:
            roots.append(_parse_dotnet_root(data, root))
        except (struct.error, UnicodeError, ValueError):
            continue
    if not roots:
        raise ValueError("no valid CLR BSJB metadata root")
    if len(roots) != 1:
        raise ValueError("multiple valid CLR metadata roots are ambiguous")
    return roots[0]


HELPERS = {1: "map_lookup_elem", 2: "map_update_elem", 3: "map_delete_elem", 4: "probe_read",
           5: "ktime_get_ns", 6: "trace_printk", 14: "get_current_pid_tgid",
           25: "perf_event_output", 113: "probe_read_kernel"}


def _valid_ebpf_opcode(opcode: int) -> bool:
    cls, operation = opcode & 0x07, opcode & 0xF0
    if opcode == 0x18:  # LD_DW_IMM
        return True
    if cls in (4, 7):  # ALU / ALU64
        allowed = {0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70,
                   0x80, 0x90, 0xA0, 0xB0, 0xC0}
        if cls == 4:
            allowed.add(0xD0)  # endian conversion exists only in ALU32
        return operation in allowed
    if cls in (5, 6):  # JMP / JMP32; CALL and EXIT only exist in JMP64
        if operation in {0x80, 0x90}:
            return cls == 5
        return operation in {0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70,
                             0xA0, 0xB0, 0xC0, 0xD0}
    mode = opcode & 0xE0
    if cls == 0:  # legacy packet ABS/IND loads retained by eBPF
        return mode in {0x20, 0x40}
    if cls == 1:
        return mode in {0x60, 0x80}  # MEM / MEMSX
    if cls == 2:
        return mode == 0x60
    if cls == 3:
        return mode in {0x60, 0xC0}  # MEM / atomic
    return False


def parse_ebpf(data: bytes) -> dict[str, Any]:
    """Validate and summarize a raw little-endian eBPF instruction stream."""
    if not isinstance(data, bytes) or not data or len(data) > MAX_VM_BYTES or len(data) % 8:
        raise ValueError("raw eBPF must be 1..1MiB and a multiple of 8 bytes")
    count = len(data) // 8
    instructions, continuation = [], set()
    index = 0
    while index < count:
        opcode, regs, off, imm = struct.unpack_from("<BBhi", data, index * 8)
        dst, src = regs & 0x0F, regs >> 4
        if dst > 10 or src > 10:
            raise ValueError("eBPF register exceeds r10")
        if not _valid_ebpf_opcode(opcode):
            raise ValueError(f"reserved or unsupported eBPF opcode 0x{opcode:02x}")
        cls, operation = opcode & 0x07, opcode & 0xF0
        # CALL/EXIT opcodes have reserved fields whose values are part of the instruction
        # grammar.  Accepting arbitrary registers/offsets made malformed streams look verified.
        if cls == 5 and operation == 0x90:
            if opcode != 0x95 or regs or off or imm:
                raise ValueError("invalid eBPF EXIT reserved fields")
        if cls == 5 and operation == 0x80:
            if opcode != 0x85 or dst or off or src not in (0, 1, 2):
                raise ValueError("invalid eBPF CALL encoding")
        row = {"index": index, "opcode": opcode, "dst": dst, "src": src, "offset": off, "immediate": imm}
        if opcode == 0x18:  # LD_DW_IMM consumes the next slot
            if index + 1 >= count:
                raise ValueError("truncated eBPF LD_DW_IMM")
            op2, regs2, off2, imm2 = struct.unpack_from("<BBhi", data, (index + 1) * 8)
            if op2 or regs2 or off2:
                raise ValueError("invalid eBPF LD_DW_IMM continuation")
            row["immediate64"] = (imm & 0xFFFFFFFF) | ((imm2 & 0xFFFFFFFF) << 32)
            continuation.add(index + 1)
            index += 2
        else:
            index += 1
        instructions.append(row)
    helpers, exits, targets = [], [], []
    valid_starts = {row["index"] for row in instructions}
    for row in instructions:
        cls, operation = row["opcode"] & 0x07, row["opcode"] & 0xF0
        if cls in (5, 6):
            if operation == 0x80:  # CALL
                if row["src"] == 0:
                    helpers.append({"index": row["index"], "id": row["immediate"],
                                    "name": HELPERS.get(row["immediate"], "unknown")})
                elif row["src"] == 1:  # BPF_PSEUDO_CALL uses a relative instruction offset.
                    target = row["index"] + 1 + row["immediate"]
                    if target not in valid_starts or target in continuation:
                        raise ValueError("eBPF pseudo-call target is outside/mid-instruction")
                    targets.append({"from": row["index"], "to": target, "kind": "pseudo_call"})
            elif operation == 0x90:  # EXIT
                exits.append(row["index"])
            else:
                target = row["index"] + 1 + row["offset"]
                if target not in valid_starts or target in continuation:
                    raise ValueError("eBPF jump target is outside/mid-instruction")
                targets.append({"from": row["index"], "to": target})
    if not exits:
        raise ValueError("eBPF program has no EXIT")
    return {"format": "raw-ebpf", "instruction_count": count, "instructions": instructions,
            "helper_calls": helpers, "jump_targets": targets, "exit_indices": exits,
            "verified_structure": True,
            "note": "instruction framing/targets are verified; kernel verifier acceptance is not claimed"}


def analyze_languages(data: bytes) -> dict[str, Any]:
    """Combine structural readers with conservative toolchain evidence."""
    if not isinstance(data, bytes) or len(data) > MAX_INPUT:
        raise ValueError("binary input is invalid or too large")
    container = _container(data)
    languages: list[dict[str, Any]] = []
    structured: dict[str, Any] = {}
    if container == "wasm":
        structured["wasm"] = parse_wasm(data)
        languages.append({"language": "WebAssembly", "confidence": "structural", "verified": True,
                          "evidence": ["valid WASM module framing"]})
    if container == "jvm-class":
        try:
            cls = facts_reader.parse_class(data)
            meta = facts_reader.kotlin_metadata(cls)
            structured["jvm"] = {"major": cls["major"], "minor": cls["minor"], "class": cls["this"],
                                 "string_constants": [value for _idx, value in cls["strings"][:1024]],
                                 "code_attributes": len(cls["codes"]), "kotlin_metadata": meta}
            languages.append({"language": "Kotlin" if meta is not None else "Java/JVM",
                              "confidence": "structural", "verified": True,
                              "evidence": ["validated class constant pool/attributes"]})
        except (IndexError, KeyError, struct.error, TypeError, ValueError, UnicodeError) as exc:
            raise ValueError(f"malformed JVM class: {exc}") from exc
    if b"BSJB" in data:
        cli = _pe_cli_metadata(data) if container == "pe" else None
        if cli is not None:
            metadata = parse_dotnet_metadata(data)
            if metadata["root_offset"] != cli[0] or cli[1] < 16:
                raise ValueError("CLR directory and metadata root disagree")
            structured["dotnet"] = metadata
            languages.append({"language": ".NET IL", "confidence": "structural", "verified": True,
                              "evidence": ["PE CLR directory points to validated BSJB metadata streams"]})
        elif container is None:
            # A standalone metadata blob is useful evidence but is not proof of a PE assembly.
            structured["dotnet_metadata_candidate"] = parse_dotnet_metadata(data)
            languages.append({"language": ".NET metadata", "confidence": "structural", "verified": True,
                              "evidence": ["validated standalone BSJB metadata streams"],
                              "note": "no PE CLR directory: do not call this a managed executable"})
    markers = (
        ("Go", ((b"\xff Go buildinf:", "Go buildinfo header"),
                (b"runtime.main", "runtime.main"), (b"go1.", "Go version string"))),
        ("Rust", ((b"rustc version ", "rustc version string"),
                  (b"/rustc/", "rust source prefix"), (b"core::panicking", "Rust core panic path"))),
        ("Swift", ((b"swift_retain", "swift_retain"),
                   (b"__swift5_", "Swift metadata section string"), (b"libswiftCore", "libswiftCore"))),
    )
    for name, choices in markers:
        evidence = [label for marker, label in choices if marker in data]
        if evidence:
            languages.append({"language": name, "confidence": "medium" if len(evidence) >= 2 else "low",
                              "verified": False, "evidence": evidence,
                              "note": "toolchain strings are leads, not proof of source language"})
    if container == "elf" and len(data) >= 20:
        end = "<" if data[5:6] == b"\x01" else ">" if data[5:6] == b"\x02" else None
        if end:
            machine = struct.unpack_from(end + "H", data, 18)[0]
            if machine == 247:
                languages.append({"language": "eBPF ELF", "confidence": "structural", "verified": True,
                                  "evidence": ["ELF e_machine=EM_BPF (247)"],
                                  "note": "extract executable section bytes before raw eBPF parsing"})
    return {"container": container, "languages": languages, "structured": structured,
            "packers": packer_evidence(data), "candidate_only": True}


ALLOWED_VM_SEMANTICS = {"push", "pop", "add", "sub", "xor", "and", "or", "load", "store",
                        "compare", "jump", "jump_if", "call", "return", "halt", "move", "unknown"}


def lift_vm(spec: dict[str, Any]) -> dict[str, Any]:
    """Decode bytecode with a declarative opcode table and validate every boundary/branch."""
    if not isinstance(spec, dict):
        raise ValueError("VM lift specification must be an object")
    raw = spec.get("bytecode_hex")
    table = spec.get("opcode_table")
    if not isinstance(raw, str) or len(raw) % 2 or len(raw) > MAX_VM_BYTES * 2:
        raise ValueError("bytecode_hex must be bounded even-length hex")
    try:
        code = bytes.fromhex(raw)
    except ValueError as exc:
        raise ValueError("bytecode_hex is not hex") from exc
    if not isinstance(table, dict) or not 1 <= len(table) <= 256:
        raise ValueError("opcode_table must contain 1..256 entries")
    normalized = {}
    branch_mode = spec.get("branch_mode")
    for key, item in table.items():
        try:
            opcode = int(str(key), 0)
        except ValueError as exc:
            raise ValueError("opcode key is not an integer") from exc
        if not 0 <= opcode <= 255 or not isinstance(item, dict):
            raise ValueError("invalid opcode table entry")
        name = item.get("name", f"op_{opcode:02x}")
        semantic = item.get("semantic", "unknown")
        width = item.get("immediate_bytes", 0)
        signed = item.get("signed", False)
        endian = item.get("endian", "little")
        pop, push = item.get("pop", 0), item.get("push", 0)
        if (not isinstance(name, str) or len(name) > 80 or not isinstance(semantic, str)
                or semantic not in ALLOWED_VM_SEMANTICS
                or not isinstance(width, int) or not 0 <= width <= 8 or not isinstance(signed, bool)
                or endian not in ("little", "big") or not all(isinstance(x, int) and 0 <= x <= 32 for x in (pop, push))):
            raise ValueError("invalid opcode metadata")
        normalized[opcode] = {"name": name, "semantic": semantic, "width": width, "signed": signed,
                              "endian": endian, "pop": pop, "push": push}
    at, ir, boundaries, unknown = 0, [], set(), []
    while at < len(code):
        boundaries.add(at)
        opcode = code[at]
        item = normalized.get(opcode)
        if item is None:
            unknown.append({"offset": at, "opcode": opcode})
            break
        end = at + 1 + item["width"]
        if end > len(code):
            raise ValueError("VM immediate runs past bytecode")
        immediate = None if not item["width"] else int.from_bytes(code[at + 1:end], item["endian"], signed=item["signed"])
        ir.append({"offset": at, "opcode": opcode, "name": item["name"], "semantic": item["semantic"],
                   "immediate": immediate, "stack_pop": item["pop"], "stack_push": item["push"],
                   "size": end - at})
        at = end
        if len(ir) > MAX_ITEMS:
            raise ValueError("too many VM instructions")
    complete = at == len(code) and not unknown
    targets = []
    if complete:
        has_branches = any(row["semantic"] in ("jump", "jump_if") for row in ir)
        if has_branches and branch_mode not in ("relative", "absolute"):
            raise ValueError("branch_mode must explicitly be relative or absolute")
        for row in ir:
            if row["semantic"] in ("jump", "jump_if"):
                if row["immediate"] is None:
                    raise ValueError("VM branch has no immediate target")
                target = (row["offset"] + row["size"] + row["immediate"]
                          if branch_mode == "relative" else row["immediate"])
                if target not in boundaries:
                    raise ValueError("VM branch target is not an instruction boundary")
                targets.append({"from": row["offset"], "to": target})
    return {"ir": ir, "unknown": unknown, "complete": complete, "branch_mode": branch_mode,
            "branch_targets": targets,
            "verified": False,
            "note": ("IR is a mechanical application of the supplied opcode table; verify handler semantics "
                     "against disassembly before treating it as recovered behavior")}


def symbolic_review_plan(spec: dict[str, Any]) -> dict[str, Any]:
    try:
        harness = reverse_depth.build_angr_harness(spec)
    except UnicodeError as exc:
        # Surrogate/invalid text in a declarative field is a bad spec, not an engine crash.
        raise ValueError(f"symbolic review spec is not encodable text: {exc}") from exc
    return {"harness": harness, "sha256": hashlib.sha256(harness.encode()).hexdigest(),
            "run_in": "networkless read-only sacrificial Docker container only",
            "candidate_only": True,
            "verification": "replay a unique candidate through the original checker in that same container"}


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ValueError(message)


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(description="static managed/VM format and packer analysis")
    parser.add_argument("operation", choices=("scan", "wasm", "dotnet", "ebpf", "vmlift", "symbolic-plan"))
    parser.add_argument("input")
    try:
        try:
            args = parser.parse_args(argv)
        except SystemExit as exc:
            # --help/--version exit through argparse; surface their code, not a leaked SystemExit.
            return exc.code if isinstance(exc.code, int) else 0
        raw = _read(args.input, MAX_INPUT)
        if args.operation == "scan":
            result = analyze_languages(raw)
        elif args.operation == "wasm":
            result = parse_wasm(raw)
        elif args.operation == "dotnet":
            result = parse_dotnet_metadata(raw)
        elif args.operation == "ebpf":
            result = parse_ebpf(raw)
        else:
            try:
                spec = json.loads(raw.decode("utf-8"))
            except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
                raise ValueError("input is not bounded JSON") from exc
            result = lift_vm(spec) if args.operation == "vmlift" else symbolic_review_plan(spec)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (OSError, TypeError, ValueError, OverflowError, UnicodeError, struct.error,
            RecursionError, MemoryError) as exc:
        print(f"reverse_formats: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
