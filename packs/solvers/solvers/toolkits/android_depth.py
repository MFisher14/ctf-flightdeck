#!/usr/bin/env python3
"""Deep, deterministic Android package triage and patch *planning*.

Only caller-supplied bytes are read.  The module does not invoke adb, install or run an
APK, load a native library, apply a patch, or access a network.  It provides structural
DEX inventories, evidence-backed DEX/smali bypass plans, ELF hardening/JNI triage, and
bounded extraction for Xamarin, Unity IL2CPP, and Flutter AOT packages.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import struct
import zipfile
import zlib
from pathlib import Path
from typing import Any

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    _sys.path.append(str(Path(__file__).resolve().parents[2]))
    from ctf import flagfmt


MAX_FILE = 512 << 20
MAX_ARCHIVE_MEMBERS = 16_384
MAX_MEMBER = 256 << 20
MAX_ARCHIVE_TOTAL = 768 << 20
MAX_DEX_ITEMS = 1_000_000
MAX_METHOD_CODE_UNITS = 4_000_000
MAX_STRINGS = 8192
MAX_STRING_LENGTH = 16_384
MAX_ELF_SECTIONS = 65_536
MAX_ELF_SYMBOLS = 1_000_000
MAX_CODEC_NODES = 100_000


class AndroidError(ValueError):
    """Malformed or unsupported Android package data."""


_DEX_MAGIC = re.compile(rb"dex\n0(?:35|37|38|39|40|41)\x00")
_PRINTABLE = re.compile(rb"[\x20-\x7e]{5,1024}")
_UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){5,512}")
_LEAD = re.compile(
    r"(?i)(?:CTF\{|flag\{|https?://|wss?://|api[_-]?key|secret|token|password|"
    r"certificate|pinning|firebase|client[_-]?id|oauth|debug|root|frida)"
)


def _is_lead(text: str) -> bool:
    """An interesting string: a generic lead word, or the active event's flag lead (PINK{, spooky{;
    R-16: this was a hard-coded CSCTF{)."""
    return bool(_LEAD.search(text) or flagfmt.LEAD_TEXT.search(text))
_SUSPICIOUS = (
    ("root-detection", re.compile(r"(?i)(?:isrooted|rootbeer|magisk|superuser|su\b|test-keys|busybox)")),
    ("debugger-detection", re.compile(r"(?i)(?:isdebuggerconnected|waitingfordebugger|debuggable|ptrace)")),
    ("tls-pinning", re.compile(r"(?i)(?:checkservertrusted|hostnameverifier|certificatepinner|sslpeer|pinning|x509trust)")),
    ("signature-integrity", re.compile(r"(?i)(?:getsigningcertificates|getsignatures|signature|certificate|tamper|integrity|playintegrity|safetynet)")),
    ("emulator-detection", re.compile(r"(?i)(?:isemulator|goldfish|ranchu|genymotion|qemu|sdk_gphone)")),
)

_MACHINES = {3: "x86", 8: "mips", 40: "arm", 62: "x86_64", 183: "aarch64", 243: "riscv"}
_ACCESS = {
    0x1: "public", 0x2: "private", 0x4: "protected", 0x8: "static", 0x10: "final",
    0x20: "synchronized", 0x40: "bridge", 0x80: "varargs", 0x100: "native",
    0x400: "abstract", 0x800: "strict", 0x1000: "synthetic", 0x10000: "constructor",
}


def _bounded_file(path: str | Path) -> bytes:
    with Path(path).open("rb") as handle:
        data = handle.read(MAX_FILE + 1)
    if len(data) > MAX_FILE:
        raise ValueError("input exceeds 512 MiB cap")
    return data


def _u16(data: bytes, offset: int, endian: str = "<") -> int | None:
    if offset < 0 or offset + 2 > len(data):
        return None
    return struct.unpack_from(endian + "H", data, offset)[0]


def _u32(data: bytes, offset: int, endian: str = "<") -> int | None:
    if offset < 0 or offset + 4 > len(data):
        return None
    return struct.unpack_from(endian + "I", data, offset)[0]


def _uleb(data: bytes, offset: int) -> tuple[int, int] | None:
    value = 0
    for index in range(5):
        if offset + index >= len(data):
            return None
        byte = data[offset + index]
        value |= (byte & 0x7F) << (7 * index)
        if byte < 0x80:
            return value, offset + index + 1
    return None


def _mutf8(data: bytes, offset: int) -> str | None:
    length = _uleb(data, offset)
    if length is None:
        return None
    _, cursor = length
    end = data.find(b"\x00", cursor, min(len(data), cursor + MAX_STRING_LENGTH + 1))
    if end < 0:
        return None
    raw = data[cursor:end].replace(b"\xc0\x80", b"\x00")
    try:
        return raw.decode("utf-8", "surrogatepass")
    except UnicodeDecodeError:
        return raw.decode("utf-8", "replace")


def _table(header: dict[str, int], name: str, stride: int, length: int) -> tuple[int, int] | None:
    count, offset = header.get(name + "_size", 0), header.get(name + "_off", 0)
    if count > MAX_DEX_ITEMS or offset > length or count * stride > length - offset:
        return None
    return offset, count


def parse_dex(data: bytes) -> dict[str, Any] | None:
    """Parse DEX identifiers and defined method code ranges, failing closed per table."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("DEX input must be bytes")
    raw = bytes(data)
    if len(raw) < 0x70 or len(raw) > MAX_FILE or not _DEX_MAGIC.fullmatch(raw[:8]):
        return None
    file_size, header_size, endian_tag = struct.unpack_from("<III", raw, 0x20)
    if endian_tag == 0x12345678:
        endian = "<"
    elif endian_tag == 0x78563412:
        endian = ">"
    else:
        return {"version": raw[4:7].decode(), "error": "invalid endian tag"}
    if file_size > len(raw) or header_size < 0x70 or header_size > len(raw):
        return {"version": raw[4:7].decode(), "error": "invalid file/header size"}
    link_size, link_off, map_off = struct.unpack_from(endian + "III", raw, 0x2C)
    header = {"link_size": link_size, "link_off": link_off, "map_off": map_off}
    for index, name in enumerate(("string_ids", "type_ids", "proto_ids", "field_ids",
                                  "method_ids", "class_defs", "data")):
        size, offset = struct.unpack_from(endian + "II", raw, 0x38 + index * 8)
        header[name + "_size"], header[name + "_off"] = size, offset
    notes = []
    strings: list[str | None] = []
    table = _table(header, "string_ids", 4, len(raw))
    if table:
        offset, count = table
        for index in range(count):
            at = _u32(raw, offset + index * 4, endian)
            strings.append(_mutf8(raw, at) if at is not None else None)
    else:
        notes.append("invalid string_ids table")
    types: list[str | None] = []
    table = _table(header, "type_ids", 4, len(raw))
    if table:
        offset, count = table
        for index in range(count):
            string_index = _u32(raw, offset + index * 4, endian)
            types.append(strings[string_index] if string_index is not None and string_index < len(strings) else None)
    else:
        notes.append("invalid type_ids table")
    protos: list[dict[str, Any]] = []
    table = _table(header, "proto_ids", 12, len(raw))
    if table:
        offset, count = table
        for index in range(count):
            shorty, return_type, parameters_off = struct.unpack_from(endian + "III", raw, offset + index * 12)
            params = []
            if parameters_off:
                pcount = _u32(raw, parameters_off, endian)
                if pcount is not None and pcount <= 65_535 and parameters_off + 4 + pcount * 2 <= len(raw):
                    for pindex in range(pcount):
                        type_index = _u16(raw, parameters_off + 4 + pindex * 2, endian)
                        params.append(types[type_index] if type_index is not None and type_index < len(types) else None)
            protos.append({"shorty": strings[shorty] if shorty < len(strings) else None,
                           "return": types[return_type] if return_type < len(types) else None,
                           "parameters": params})
    methods: list[dict[str, Any]] = []
    table = _table(header, "method_ids", 8, len(raw))
    if table:
        offset, count = table
        for index in range(count):
            class_index, proto_index, name_index = struct.unpack_from(endian + "HHI", raw, offset + index * 8)
            methods.append({"index": index, "class": types[class_index] if class_index < len(types) else None,
                            "name": strings[name_index] if name_index < len(strings) else None,
                            "proto": protos[proto_index] if proto_index < len(protos) else None})
    else:
        notes.append("invalid method_ids table")
    defined: list[dict[str, Any]] = []
    class_table = _table(header, "class_defs", 32, len(raw))
    if class_table:
        offset, count = class_table
        for class_number in range(count):
            values = struct.unpack_from(endian + "8I", raw, offset + class_number * 32)
            class_index, access, super_index, interfaces_off, source_index, annotations_off, class_data_off, static_off = values
            if not class_data_off:
                continue
            sizes = []
            cursor = class_data_off
            for _ in range(4):
                got = _uleb(raw, cursor)
                if got is None:
                    sizes = []
                    break
                value, cursor = got
                sizes.append(value)
            if len(sizes) != 4 or sum(sizes) > MAX_DEX_ITEMS:
                notes.append(f"class {class_number} has invalid class_data")
                continue
            # Skip encoded fields (field_idx_diff, access_flags).
            valid = True
            for _ in range(sizes[0] + sizes[1]):
                for _field in range(2):
                    got = _uleb(raw, cursor)
                    if got is None:
                        valid = False
                        break
                    _, cursor = got
                if not valid:
                    break
            # The method_idx_diff accumulator restarts for each encoded_method list.
            for method_kind, method_count in (("direct", sizes[2]), ("virtual", sizes[3])) if valid else ():
                method_index = 0
                for _ in range(method_count):
                    triplet = []
                    for _field in range(3):
                        got = _uleb(raw, cursor)
                        if got is None:
                            valid = False
                            break
                        value, cursor = got
                        triplet.append(value)
                    if not valid:
                        break
                    method_index += triplet[0]
                    method = methods[method_index] if method_index < len(methods) else None
                    item = {"method_index": method_index, "method_kind": method_kind,
                            "access_flags": triplet[1], "code_offset": triplet[2],
                            "access": [name for bit, name in _ACCESS.items() if triplet[1] & bit]}
                    if method:
                        item.update({"class": method["class"], "name": method["name"], "proto": method["proto"]})
                    if triplet[2] and triplet[2] + 16 <= len(raw):
                        registers, ins, outs, tries = struct.unpack_from(endian + "HHHH", raw, triplet[2])
                        debug_info, insns_size = struct.unpack_from(endian + "II", raw, triplet[2] + 8)
                        code_start = triplet[2] + 16
                        if insns_size <= MAX_METHOD_CODE_UNITS and code_start + insns_size * 2 <= len(raw):
                            item["code"] = {"registers": registers, "ins": ins, "outs": outs, "tries": tries,
                                            "debug_info_offset": debug_info, "instructions_offset": code_start,
                                            "code_units": insns_size}
                            item["invokes"] = _dex_invokes(raw, code_start, insns_size, methods, endian)
                        else:
                            item["code_error"] = "code_item instructions exceed file or cap"
                    defined.append(item)
    else:
        notes.append("invalid class_defs table")
    return {"version": raw[4:7].decode(), "file_size": file_size, "sha1": raw[12:32].hex(),
            "checksum": struct.unpack_from(endian + "I", raw, 8)[0], "header": header,
            "strings": strings, "types": types, "protos": protos, "methods": methods,
            "defined_methods": defined, "notes": notes}


def _dex_invokes(raw: bytes, start: int, count: int, methods: list[dict[str, Any]], endian: str) -> list[dict[str, Any]]:
    """Conservatively locate invoke-* formats in a validated code-item range.

    DEX payloads can make a full disassembler version-sensitive.  Every hit here is
    therefore reported as a patch lead, not asserted control flow.  The method index is
    nevertheless an exact field of the 35c/3rc encoding at the stated byte offset.
    """
    out = []
    end = start + count * 2
    for at in range(start, end - 3, 2):
        opcode = raw[at]
        if opcode not in range(0x6E, 0x73) and opcode not in range(0x74, 0x79):
            continue
        method_index = _u16(raw, at + 2, endian)
        if method_index is None or method_index >= len(methods):
            continue
        target = methods[method_index]
        text = f"{target.get('class') or '?'}->{target.get('name') or '?'}"
        categories = [name for name, pattern in _SUSPICIOUS if pattern.search(text)]
        if categories:
            out.append({"offset": at, "opcode": opcode, "method_index": method_index,
                        "target": target, "categories": categories})
    return out[:4096]


def _boolean_choice(method_name: str, categories: list[str]) -> bool | None:
    lowered = method_name.lower()
    if re.search(r"(?:rooted|debugger|emulator|tamper|compromised|hooked|instrumented)", lowered):
        return False
    if re.search(r"(?:valid|trusted|verified|integrityok|safe)", lowered):
        return True
    # A category learned only from a callee does not prove whether its caller negates it.
    return None


def _return_plan(return_type: str | None, boolean_value: bool | None = None) -> dict[str, Any]:
    if return_type == "V":
        return {"value": "void", "smali": ["return-void"]}
    if return_type == "Z":
        if boolean_value is None:
            return {"value": None, "smali": [], "note": "boolean gate polarity requires control-flow review",
                    "alternatives": [
                        {"value": False, "smali": ["const/4 v0, 0x0", "return v0"]},
                        {"value": True, "smali": ["const/4 v0, 0x1", "return v0"]},
                    ]}
        return {"value": boolean_value,
                "smali": [f"const/4 v0, 0x{1 if boolean_value else 0:x}", "return v0"]}
    if return_type in ("B", "S", "C", "I"):
        return {"value": 0, "smali": ["const/4 v0, 0x0", "return v0"]}
    if return_type == "J":
        return {"value": 0, "smali": ["const-wide/16 v0, 0x0", "return-wide v0"]}
    if return_type in ("F", "D"):
        return {"value": 0.0, "smali": ["const-wide/16 v0, 0x0" if return_type == "D" else "const/4 v0, 0x0",
                                         "return-wide v0" if return_type == "D" else "return v0"]}
    if return_type and (return_type.startswith("L") or return_type.startswith("[")):
        return {"value": None, "smali": ["const/4 v0, 0x0", "return-object v0"]}
    return {"value": None, "smali": [], "note": "return type is unavailable"}


def plan_dex_patches(data: bytes) -> list[dict[str, Any]]:
    """Produce non-mutating bypass plans for evidence-backed DEX gates."""
    dex = parse_dex(data)
    if dex is None:
        return []
    plans = []
    for method in dex.get("defined_methods", []):
        text = f"{method.get('class') or ''}->{method.get('name') or ''}"
        categories = [name for name, pattern in _SUSPICIOUS if pattern.search(text)]
        for invoke in method.get("invokes", []):
            categories.extend(invoke["categories"])
        categories = sorted(set(categories))
        if not categories:
            continue
        proto = method.get("proto") or {}
        plan = {"class": method.get("class"), "method": method.get("name"), "prototype": proto,
                "categories": categories, "access": method.get("access"), "code_offset": method.get("code_offset"),
                "instructions_offset": (method.get("code") or {}).get("instructions_offset"),
                "strategy": "replace method body or invert the documented branch after human control-flow review",
                "replacement": _return_plan(proto.get("return"), _boolean_choice(method.get("name") or "", categories)),
                "apply": False,
                "evidence_invokes": method.get("invokes", [])}
        plans.append(plan)
    return plans


_METHOD = re.compile(r"^\s*\.method\s+(?P<flags>.*?)\s+(?P<name>[^\s(]+)\((?P<args>[^)]*)\)(?P<ret>\S+)\s*$")


def plan_smali_patches(text: str) -> list[dict[str, Any]]:
    """Locate security gates in smali source and propose, but never apply, replacements."""
    if not isinstance(text, str) or len(text) > (32 << 20):
        raise ValueError("smali source exceeds 32 MiB cap")
    lines = text.splitlines()
    plans = []
    index = 0
    while index < len(lines):
        match = _METHOD.match(lines[index])
        if not match:
            index += 1
            continue
        end = index + 1
        while end < len(lines) and not re.match(r"^\s*\.end\s+method\b", lines[end]):
            end += 1
        body = "\n".join(lines[index:end + 1])
        categories = [name for name, pattern in _SUSPICIOUS if pattern.search(match.group("name") + "\n" + body)]
        if categories:
            register_line = next((line.strip() for line in lines[index + 1:end]
                                  if re.match(r"\s*\.(?:locals|registers)\s+\d+", line)), None)
            evidence = []
            for lineno in range(index, min(end + 1, len(lines))):
                if any(pattern.search(lines[lineno]) for _, pattern in _SUSPICIOUS):
                    evidence.append({"line": lineno + 1, "text": lines[lineno].strip()[:300]})
            plans.append({"method": match.group("name"), "arguments": match.group("args"),
                          "return_type": match.group("ret"), "flags": match.group("flags").split(),
                          "start_line": index + 1, "end_line": min(end + 1, len(lines)),
                          "register_directive": register_line, "categories": sorted(set(categories)),
                          "evidence": evidence[:64],
                          "replacement": _return_plan(match.group("ret"),
                                                      _boolean_choice(match.group("name"), categories)),
                          "register_note": "ensure v0 exists; increase .locals when needed",
                          "apply": False})
        index = end + 1
    return plans


def _elf_cstr(table: bytes, offset: int) -> str | None:
    if offset < 0 or offset >= len(table):
        return None
    end = table.find(b"\x00", offset)
    if end < 0:
        return None
    return table[offset:end].decode("utf-8", "replace")


def parse_elf(data: bytes) -> dict[str, Any] | None:
    """Parse ELF metadata, dynamic dependencies, exports, JNI symbols, and hardening."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("ELF input must be bytes")
    raw = bytes(data)
    if len(raw) < 52 or len(raw) > MAX_FILE or raw[:4] != b"\x7fELF" or raw[4] not in (1, 2) or raw[5] not in (1, 2):
        return None
    bits, endian = (32 if raw[4] == 1 else 64), ("<" if raw[5] == 1 else ">")
    if len(raw) < (64 if bits == 64 else 52):
        return None
    if bits == 64:
        etype, machine, version, entry, phoff, shoff, flags, ehsize, phentsize, phnum, shentsize, shnum, shstrndx = struct.unpack_from(
            endian + "HHIQQQIHHHHHH", raw, 16)
        ph_expected, sh_expected = 56, 64
    else:
        etype, machine, version, entry, phoff, shoff, flags, ehsize, phentsize, phnum, shentsize, shnum, shstrndx = struct.unpack_from(
            endian + "HHIIIIIHHHHHH", raw, 16)
        ph_expected, sh_expected = 32, 40
    out: dict[str, Any] = {"bits": bits, "endian": "little" if endian == "<" else "big",
                           "type": etype, "machine": _MACHINES.get(machine, machine), "entry": entry,
                           "program_headers": [], "sections": [], "needed": [], "exports": [], "imports": [],
                           "jni_exports": [], "hardening": {}, "notes": []}
    program_types = set()
    stack_flags = None
    if phnum <= MAX_ELF_SECTIONS and phentsize >= ph_expected and phoff <= len(raw) and phnum * phentsize <= len(raw) - phoff:
        for index in range(phnum):
            at = phoff + index * phentsize
            if bits == 64:
                ptype, pflags, poff, vaddr, paddr, filesz, memsz, align = struct.unpack_from(endian + "IIQQQQQQ", raw, at)
            else:
                ptype, poff, vaddr, paddr, filesz, memsz, pflags, align = struct.unpack_from(endian + "IIIIIIII", raw, at)
            item = {"index": index, "type": ptype, "flags": pflags, "offset": poff, "virtual_address": vaddr,
                    "file_size": filesz, "memory_size": memsz, "alignment": align,
                    "range_valid": poff <= len(raw) and filesz <= len(raw) - poff}
            out["program_headers"].append(item)
            program_types.add(ptype)
            if ptype == 0x6474E551:
                stack_flags = pflags
    sections = []
    if shnum <= MAX_ELF_SECTIONS and shentsize >= sh_expected and shoff <= len(raw) and shnum * shentsize <= len(raw) - shoff:
        for index in range(shnum):
            at = shoff + index * shentsize
            if bits == 64:
                values = struct.unpack_from(endian + "IIQQQQIIQQ", raw, at)
            else:
                values = struct.unpack_from(endian + "IIIIIIIIII", raw, at)
            sections.append({"index": index, "name_offset": values[0], "type": values[1], "flags": values[2],
                             "address": values[3], "offset": values[4], "size": values[5], "link": values[6],
                             "info": values[7], "alignment": values[8], "entry_size": values[9]})
    if shstrndx < len(sections):
        sec = sections[shstrndx]
        table = raw[sec["offset"]:sec["offset"] + sec["size"]] if sec["offset"] + sec["size"] <= len(raw) else b""
        for sec in sections:
            sec["name"] = _elf_cstr(table, sec["name_offset"])
    out["sections"] = sections
    exports, imports = [], []
    for sec in sections:
        if sec["type"] not in (2, 11) or not sec["entry_size"] or sec["link"] >= len(sections):
            continue
        symbol_size = 24 if bits == 64 else 16
        if sec["entry_size"] < symbol_size:
            out["notes"].append(f"symbol table {sec.get('name')} has an undersized entry stride")
            continue
        linked = sections[sec["link"]]
        if sec["offset"] + sec["size"] > len(raw) or linked["offset"] + linked["size"] > len(raw):
            continue
        strtab = raw[linked["offset"]:linked["offset"] + linked["size"]]
        count = sec["size"] // sec["entry_size"]
        if count > MAX_ELF_SYMBOLS:
            out["notes"].append(f"symbol table {sec.get('name')} exceeds cap")
            continue
        for index in range(count):
            at = sec["offset"] + index * sec["entry_size"]
            if bits == 64 and at + 24 <= len(raw):
                nameoff, info, other, shindex, value, size = struct.unpack_from(endian + "IBBHQQ", raw, at)
            elif bits == 32 and at + 16 <= len(raw):
                nameoff, value, size, info, other, shindex = struct.unpack_from(endian + "IIIBBH", raw, at)
            else:
                continue
            name = _elf_cstr(strtab, nameoff)
            if name and (info >> 4) in (1, 2):
                (imports if shindex == 0 else exports).append(name)
    out["exports"] = sorted(set(exports))[:MAX_STRINGS]
    out["imports"] = sorted(set(imports))[:MAX_STRINGS]
    out["jni_exports"] = [name for name in out["exports"] if name.startswith("Java_") or name == "JNI_OnLoad"]
    dynamic = next((sec for sec in sections if sec.get("name") == ".dynamic" or sec["type"] == 6), None)
    bind_now = False
    if dynamic and dynamic["link"] < len(sections) and dynamic["offset"] + dynamic["size"] <= len(raw):
        strsec = sections[dynamic["link"]]
        strtab = raw[strsec["offset"]:strsec["offset"] + strsec["size"]] if strsec["offset"] + strsec["size"] <= len(raw) else b""
        expected = 16 if bits == 64 else 8
        entsize = dynamic["entry_size"] or expected
        if entsize < expected:
            out["notes"].append("dynamic table has an undersized entry stride")
        else:
            for at in range(dynamic["offset"], dynamic["offset"] + dynamic["size"] - entsize + 1, entsize):
                tag, value = struct.unpack_from(endian + ("qQ" if bits == 64 else "iI"), raw, at)
                if tag == 1:
                    name = _elf_cstr(strtab, value)
                    if name:
                        out["needed"].append(name)
                elif tag == 24 or (tag == 30 and value & 8) or (tag == 0x6FFFFFFB and value & 1):
                    bind_now = True
                elif tag == 0:
                    break
    names = set(out["exports"]) | set(out["imports"])
    relro = 0x6474E552 in program_types
    out["hardening"] = {"pie": etype == 3, "nx_stack": stack_flags is None or not bool(stack_flags & 1),
                         "relro": "full" if relro and bind_now else "partial" if relro else "none",
                         "stack_canary": "__stack_chk_fail" in names,
                         "fortify": any(name.endswith("_chk") for name in names)}
    out["frida"] = _marker_report(raw, (b"frida-gadget", b"frida_agent_main", b"gum-js-loop", b"libfrida"))
    out["interesting_strings"] = _interesting_strings(raw)
    return out


def _interesting_strings(data: bytes, limit: int = 512) -> list[dict[str, Any]]:
    out, seen = [], set()
    for encoding, pattern in (("ascii", _PRINTABLE), ("utf-16le", _UTF16)):
        for match in pattern.finditer(data):
            text = match.group(0).decode(encoding, "replace")
            if text in seen or not _is_lead(text):
                continue
            seen.add(text)
            out.append({"offset": match.start(), "encoding": encoding, "value": text[:1024]})
            if len(out) >= limit:
                return out
    return out


def _all_strings(data: bytes, limit: int = 2048) -> list[dict[str, Any]]:
    out, seen = [], set()
    for encoding, pattern in (("ascii", _PRINTABLE), ("utf-16le", _UTF16)):
        for match in pattern.finditer(data):
            value = match.group(0).decode(encoding, "replace")
            if value in seen:
                continue
            seen.add(value)
            out.append({"offset": match.start(), "encoding": encoding, "value": value[:1024]})
            if len(out) >= limit:
                return out
    return out


def _marker_report(data: bytes, markers: tuple[bytes, ...]) -> list[dict[str, Any]]:
    lowered = data.lower()
    out = []
    for marker in markers:
        positions, cursor = [], 0
        while len(positions) < 16:
            hit = lowered.find(marker.lower(), cursor)
            if hit < 0:
                break
            positions.append(hit)
            cursor = hit + 1
        if positions:
            out.append({"marker": marker.decode("ascii", "replace"), "offsets": positions})
    return out


def _cli_compressed_uint(data: bytes, offset: int) -> tuple[int, int] | None:
    if offset >= len(data):
        return None
    first = data[offset]
    if first & 0x80 == 0:
        return first, offset + 1
    if first & 0xC0 == 0x80 and offset + 2 <= len(data):
        return ((first & 0x3F) << 8) | data[offset + 1], offset + 2
    if first & 0xE0 == 0xC0 and offset + 4 <= len(data):
        return ((first & 0x1F) << 24) | (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3], offset + 4
    return None


def parse_dotnet_metadata(data: bytes) -> dict[str, Any] | None:
    """Read PE/CLI metadata stream headers plus #Strings and #US heaps.

    This deliberately does not load the assembly.  Heap values are byte-derived and
    useful for Xamarin app triage even when method bodies are AOT compiled.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError(".NET input must be bytes")
    raw = bytes(data)
    if len(raw) < 0x100 or len(raw) > MAX_MEMBER or raw[:2] != b"MZ":
        return None
    peoff = _u32(raw, 0x3C)
    if peoff is None or peoff + 24 > len(raw) or raw[peoff:peoff + 4] != b"PE\x00\x00":
        return None
    section_count = _u16(raw, peoff + 6)
    optional_size = _u16(raw, peoff + 20)
    if section_count is None or optional_size is None or section_count > MAX_ELF_SECTIONS:
        return None
    optional = peoff + 24
    sections_at = optional + optional_size
    if optional + optional_size > len(raw) or sections_at + section_count * 40 > len(raw):
        return None
    magic = _u16(raw, optional)
    if magic == 0x10B:
        directory_count_at, directories_at = optional + 92, optional + 96
    elif magic == 0x20B:
        directory_count_at, directories_at = optional + 108, optional + 112
    else:
        return None
    directory_count = _u32(raw, directory_count_at)
    if directory_count is None or directory_count <= 14 or directories_at + 15 * 8 > optional + optional_size:
        return {"managed": False, "reason": "CLI data directory is absent"}
    cli_rva, cli_size = struct.unpack_from("<II", raw, directories_at + 14 * 8)
    sections = []
    for index in range(section_count):
        at = sections_at + index * 40
        name = raw[at:at + 8].split(b"\x00", 1)[0].decode("ascii", "replace")
        virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from("<IIII", raw, at + 8)
        sections.append({"name": name, "virtual_size": virtual_size, "virtual_address": virtual_address,
                         "raw_size": raw_size, "raw_offset": raw_offset})

    def rva_offset(rva: int, size: int = 1) -> int | None:
        for section in sections:
            delta = rva - section["virtual_address"]
            # Only file-backed bytes may be parsed.  A PE section's virtual tail is
            # zero-filled by the loader but has no corresponding artifact bytes.
            if 0 <= delta <= section["raw_size"] and size <= section["raw_size"] - delta:
                offset = section["raw_offset"] + delta
                if offset <= len(raw) and size <= len(raw) - offset:
                    return offset
        return None

    if cli_size < 16:
        return {"managed": True, "error": "CLI header is too small", "sections": sections}
    cli = rva_offset(cli_rva, 16)
    if cli is None or cli + 16 > len(raw):
        return {"managed": True, "error": "CLI header range is invalid", "sections": sections}
    metadata_rva, metadata_size = struct.unpack_from("<II", raw, cli + 8)
    metadata = rva_offset(metadata_rva, metadata_size)
    if metadata is None or metadata_size < 20:
        return {"managed": True, "error": "metadata root range is invalid", "sections": sections}
    root = raw[metadata:metadata + metadata_size]
    if root[:4] != b"BSJB":
        return {"managed": True, "error": "metadata signature is invalid", "sections": sections}
    major, minor, reserved, version_length = struct.unpack_from("<HHII", root, 4)
    if version_length > len(root) - 16:
        return {"managed": True, "error": "metadata version is truncated", "sections": sections}
    version_raw = root[16:16 + version_length]
    cursor = (16 + version_length + 3) & ~3
    if cursor + 4 > len(root):
        return {"managed": True, "error": "metadata stream header is truncated", "sections": sections}
    flags, stream_count = struct.unpack_from("<HH", root, cursor)
    cursor += 4
    if stream_count > 64:
        return {"managed": True, "error": "metadata stream count exceeds cap", "sections": sections}
    streams = []
    for _ in range(stream_count):
        if cursor + 9 > len(root):
            return {"managed": True, "error": "metadata stream directory is truncated", "sections": sections}
        offset, size = struct.unpack_from("<II", root, cursor)
        name_end = root.find(b"\x00", cursor + 8, min(len(root), cursor + 40))
        if name_end < 0:
            return {"managed": True, "error": "metadata stream name is unterminated", "sections": sections}
        name = root[cursor + 8:name_end].decode("ascii", "replace")
        cursor = (name_end + 1 + 3) & ~3
        streams.append({"name": name, "offset": offset, "size": size,
                        "range_valid": offset <= len(root) and size <= len(root) - offset})
    result: dict[str, Any] = {"managed": True, "runtime_version": version_raw.rstrip(b"\x00").decode("utf-8", "replace"),
                              "metadata_version": [major, minor], "flags": flags, "sections": sections,
                              "streams": streams, "strings": [], "user_strings": [], "interesting_strings": [],
                              "notes": []}
    by_name = {stream["name"]: stream for stream in streams if stream["range_valid"]}
    strings_stream = by_name.get("#Strings")
    if strings_stream:
        heap = root[strings_stream["offset"]:strings_stream["offset"] + strings_stream["size"]]
        position = 1 if heap[:1] == b"\x00" else 0
        while position < len(heap) and len(result["strings"]) < MAX_STRINGS:
            end = heap.find(b"\x00", position)
            if end < 0:
                break
            if end > position:
                value = heap[position:end].decode("utf-8", "replace")
                result["strings"].append({"offset": position, "value": value})
                if _is_lead(value):
                    result["interesting_strings"].append({"heap": "#Strings", "offset": position, "value": value})
            position = end + 1
    user_stream = by_name.get("#US")
    if user_stream:
        heap = root[user_stream["offset"]:user_stream["offset"] + user_stream["size"]]
        position = 1 if heap[:1] == b"\x00" else 0
        while position < len(heap) and len(result["user_strings"]) < MAX_STRINGS:
            start = position
            got = _cli_compressed_uint(heap, position)
            if got is None:
                break
            length, position = got
            if length == 0:
                continue
            if length > MAX_STRING_LENGTH or position + length > len(heap):
                result["notes"].append("#US entry exceeds its heap or size cap")
                break
            payload = heap[position:position + length]
            if length < 1 or (length - 1) % 2:
                result["notes"].append("#US entry has an invalid UTF-16 payload length")
                break
            text_bytes = payload[:-1]
            value = text_bytes.decode("utf-16le", "replace")
            result["user_strings"].append({"offset": start, "value": value, "terminal": payload[-1]})
            if _is_lead(value):
                result["interesting_strings"].append({"heap": "#US", "offset": start, "value": value})
            position += length
    return result


def parse_il2cpp_metadata(data: bytes) -> dict[str, Any] | None:
    """Extract byte-exact IL2CPP string literals and identifier-heap leads."""
    if len(data) < 32 or len(data) > MAX_MEMBER or data[:4] != b"\xaf\x1b\xb1\xfa":
        return None
    version = _u32(data, 4)
    if version is None:
        return None
    literal_off, literal_size, literal_data_off, literal_data_size, string_off, string_size = struct.unpack_from("<6I", data, 8)
    result: dict[str, Any] = {"version": version, "literals": [], "identifier_leads": [], "notes": []}
    if literal_size % 8 or literal_size // 8 > MAX_DEX_ITEMS or literal_off + literal_size > len(data) or literal_data_off + literal_data_size > len(data):
        result["notes"].append("literal table/blob is inconsistent")
    else:
        for index in range(literal_size // 8):
            length, relative = struct.unpack_from("<II", data, literal_off + index * 8)
            if length <= MAX_STRING_LENGTH and relative <= literal_data_size and length <= literal_data_size - relative:
                raw = data[literal_data_off + relative:literal_data_off + relative + length]
                result["literals"].append({"index": index, "offset": literal_data_off + relative,
                                           "bytes_hex": raw.hex(), "text": raw.decode("utf-8", "replace")})
                if len(result["literals"]) >= MAX_STRINGS:
                    result["notes"].append("literal report cap reached")
                    break
    if string_off <= len(data) and string_size <= len(data) - string_off:
        heap = data[string_off:string_off + string_size]
        for match in _PRINTABLE.finditer(heap):
            value = match.group().decode("ascii", "replace")
            if _is_lead(value):
                result["identifier_leads"].append({"offset": string_off + match.start(), "value": value})
                if len(result["identifier_leads"]) >= MAX_STRINGS:
                    break
    else:
        result["notes"].append("identifier string heap is inconsistent")
    return result


class _FlutterCodec:
    """Bounded reader for Flutter's StandardMessageCodec value grammar."""

    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0
        self.nodes = 0

    def _take(self, size: int) -> bytes:
        if size < 0 or self.offset > len(self.data) or size > len(self.data) - self.offset:
            raise ValueError("Flutter message is truncated")
        value = self.data[self.offset:self.offset + size]
        self.offset += size
        return value

    def _align(self, width: int):
        aligned = (self.offset + width - 1) & ~(width - 1)
        self._take(aligned - self.offset)

    def _size(self) -> int:
        first = self._take(1)[0]
        if first < 254:
            return first
        if first == 254:
            return struct.unpack("<H", self._take(2))[0]
        return struct.unpack("<I", self._take(4))[0]

    def value(self, depth: int = 0):
        if depth > 64:
            raise ValueError("Flutter message nesting exceeds cap")
        self.nodes += 1
        if self.nodes > MAX_CODEC_NODES:
            raise ValueError("Flutter message node count exceeds cap")
        tag = self._take(1)[0]
        if tag == 0:
            return None
        if tag == 1:
            return True
        if tag == 2:
            return False
        if tag == 3:
            return struct.unpack("<i", self._take(4))[0]
        if tag == 4:
            return struct.unpack("<q", self._take(8))[0]
        if tag == 5:  # arbitrary integer encoded as an ASCII hexadecimal string
            size = self._size()
            if size > MAX_STRING_LENGTH:
                raise ValueError("Flutter large integer exceeds cap")
            text = self._take(size).decode("ascii")
            if not re.fullmatch(r"-?[0-9a-fA-F]+", text):
                raise ValueError("Flutter large integer is malformed")
            return int(text, 16) if not text.startswith("-") else -int(text[1:], 16)
        if tag == 6:
            self._align(8)
            return struct.unpack("<d", self._take(8))[0]
        if tag == 7:
            size = self._size()
            if size > MAX_STRING_LENGTH:
                raise ValueError("Flutter string exceeds cap")
            return self._take(size).decode("utf-8")
        if tag == 8:
            size = self._size()
            if size > MAX_MEMBER:
                raise ValueError("Flutter byte list exceeds cap")
            return self._take(size)
        if tag in (9, 10, 11, 14):
            size = self._size()
            width, code = {9: (4, "i"), 10: (8, "q"), 11: (8, "d"), 14: (4, "f")}[tag]
            if size > MAX_CODEC_NODES:
                raise ValueError("Flutter typed list exceeds cap")
            self._align(width)
            raw = self._take(size * width)
            return list(struct.unpack("<" + code * size, raw))
        if tag == 12:
            size = self._size()
            if size > MAX_CODEC_NODES:
                raise ValueError("Flutter list exceeds cap")
            return [self.value(depth + 1) for _ in range(size)]
        if tag == 13:
            size = self._size()
            if size > MAX_CODEC_NODES:
                raise ValueError("Flutter map exceeds cap")
            pairs = [(self.value(depth + 1), self.value(depth + 1)) for _ in range(size)]
            # JSON-facing reports can safely preserve string-keyed maps.  Other legal
            # codec keys stay as ordered pairs so mixed key types remain serializable
            # even with deterministic key sorting enabled by the CLI.
            if all(isinstance(key, str) for key, _ in pairs):
                result = {}
                for key, value in pairs:
                    if key in result:
                        raise ValueError("Flutter map has duplicate keys")
                    result[key] = value
                return result
            return {"pairs": pairs}
        raise ValueError(f"unsupported Flutter StandardMessageCodec tag {tag}")


def parse_flutter_message(data: bytes) -> dict[str, Any] | None:
    """Decode one bounded StandardMessageCodec value (for AssetManifest.bin)."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("Flutter message input must be bytes")
    raw = bytes(data)
    if not raw or len(raw) > MAX_MEMBER:
        return None
    reader = _FlutterCodec(raw)
    try:
        value = reader.value()
    except (ValueError, UnicodeDecodeError, struct.error):
        return None
    return {"value": value, "consumed": reader.offset, "trailing_bytes": len(raw) - reader.offset,
            "nodes": reader.nodes}


def _archive(data: bytes) -> dict[str, bytes]:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_ARCHIVE_MEMBERS:
                raise AndroidError("APK member count exceeds cap")
            members, total = {}, 0
            for info in infos:
                if info.is_dir() or info.file_size < 0 or info.file_size > MAX_MEMBER:
                    continue
                total += info.file_size
                if total > MAX_ARCHIVE_TOTAL:
                    raise AndroidError("APK expanded-size cap exceeded")
                with archive.open(info) as handle:
                    body = handle.read(info.file_size + 1)
                if len(body) != info.file_size:
                    raise AndroidError("APK member size mismatch")
                members[info.filename] = body
    except AndroidError:
        raise
    except (zipfile.BadZipFile, OSError, ValueError, RuntimeError, EOFError, zlib.error) as exc:
        raise AndroidError("APK is not a readable ZIP") from exc
    return members


def inspect_apk(data: bytes) -> dict[str, Any]:
    """Aggregate DEX, native, Xamarin, Unity, and Flutter evidence from an APK."""
    if not isinstance(data, (bytes, bytearray)):
        raise AndroidError("APK input must be bytes")
    raw = bytes(data)
    if len(raw) > MAX_FILE:
        raise AndroidError("APK exceeds 512 MiB cap")
    members = _archive(raw)
    dex_reports = []
    for name in sorted(name for name in members if re.search(r"(?:^|/)classes(?:\d*)\.dex$", name)):
        parsed = parse_dex(members[name])
        dex_reports.append({"path": name, "dex": parsed, "patch_plans": plan_dex_patches(members[name])})
    native = []
    for name in sorted(name for name in members if re.search(r"(?:^|/)lib/[^/]+/[^/]+\.so$", name)):
        native.append({"path": name, "abi": name.split("/")[-2], "elf": parse_elf(members[name])})

    xamarin_paths = sorted(name for name in members if re.search(
        r"(?i)(?:assemblies/(?:[^/]+/)?[^/]+\.dll$|assemblies\.blob$|typemap|libmonodroid|libxamarin)", name))
    xamarin = {"detected": bool(xamarin_paths), "artifacts": []}
    for name in xamarin_paths:
        body = members[name]
        xamarin["artifacts"].append({"path": name, "size": len(body),
                                      "sha256": hashlib.sha256(body).hexdigest(),
                                      "interesting_strings": _interesting_strings(body),
                                      "dotnet_metadata": parse_dotnet_metadata(body) if name.lower().endswith(".dll") else None})

    metadata_names = sorted(name for name in members if name.endswith("global-metadata.dat"))
    il2cpp_libs = sorted(name for name in members if name.endswith("libil2cpp.so") or name.endswith("GameAssembly.dll"))
    unity_paths = sorted(name for name in members if any(token in name for token in (
        "global-metadata.dat", "libil2cpp.so", "UnityPlayer", "/Data/Managed/", "resources.assets", "sharedassets")))
    unity = {"detected": bool(metadata_names or il2cpp_libs), "artifacts": unity_paths,
             "native_libraries": il2cpp_libs,
             "metadata": [{"path": name, "report": parse_il2cpp_metadata(members[name])} for name in metadata_names]}

    flutter_paths = sorted(name for name in members if any(token in name for token in (
        "libflutter.so", "libapp.so", "flutter_assets/", "isolate_snapshot_data", "vm_snapshot_data", "kernel_blob.bin")))
    flutter_reports = []
    for name in flutter_paths:
        body = members[name]
        if name.endswith(("libapp.so", "isolate_snapshot_data", "vm_snapshot_data", "kernel_blob.bin")):
            flutter_reports.append({"path": name, "size": len(body), "sha256": hashlib.sha256(body).hexdigest(),
                                    "header_hex": body[:16].hex(), "strings": _all_strings(body),
                                    "interesting_strings": _interesting_strings(body),
                                    "elf": parse_elf(body) if body.startswith(b"\x7fELF") else None,
                                    "dart_markers": _marker_report(body, (b"_kDartVmSnapshot", b"Dart_CObject", b"dart:core",
                                                                                 b"package:", b"_PrecompiledRuntime"))})
        elif name.endswith(("AssetManifest.json", "FontManifest.json")):
            try:
                value = json.loads(body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                value = None
            flutter_reports.append({"path": name, "manifest": value})
        elif name.endswith("AssetManifest.bin"):
            flutter_reports.append({"path": name, "standard_message": parse_flutter_message(body)})
    flutter = {"detected": bool(flutter_paths), "artifacts": flutter_paths, "reports": flutter_reports}
    framework_hits = [name for name, report in (("xamarin", xamarin), ("unity-il2cpp", unity), ("flutter", flutter))
                      if report["detected"]]
    return {"sha256": hashlib.sha256(raw).hexdigest(), "member_count": len(members), "frameworks": framework_hits,
            "dex": dex_reports, "native_libraries": native, "xamarin": xamarin, "unity": unity, "flutter": flutter}


def _json_default(value: Any):
    if isinstance(value, bytes):
        return {"hex": value.hex(), "length": len(value)}
    raise TypeError(f"cannot encode {type(value).__name__}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact")
    parser.add_argument("--kind", choices=("auto", "apk", "dex", "elf", "smali", "il2cpp"), default="auto")
    args = parser.parse_args(argv)
    data = _bounded_file(args.artifact)
    kind = args.kind
    if kind == "auto":
        if data.startswith(b"PK"):
            kind = "apk"
        elif _DEX_MAGIC.fullmatch(data[:8]):
            kind = "dex"
        elif data.startswith(b"\x7fELF"):
            kind = "elf"
        elif data.startswith(b"\xaf\x1b\xb1\xfa"):
            kind = "il2cpp"
        else:
            kind = "smali"
    if kind == "apk":
        report = inspect_apk(data)
    elif kind == "dex":
        report = {"dex": parse_dex(data), "patch_plans": plan_dex_patches(data)}
    elif kind == "elf":
        report = parse_elf(data)
    elif kind == "il2cpp":
        report = parse_il2cpp_metadata(data)
    else:
        report = plan_smali_patches(data.decode("utf-8", "replace"))
    print(json.dumps(report, indent=2, sort_keys=True, default=_json_default))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
