#!/usr/bin/env python3
"""Bounded, offline structural analysis for iOS challenge artifacts.

The module reads bytes supplied by the caller.  It never invokes an app, talks to a
device, attaches a debugger, or loads a Mach-O.  Its three entry points are:

``parse_macho``
    Decode thin/universal Mach-O headers, load commands, segments, sections,
    linked dylibs, encryption state, build targets, UUIDs, and embedded code-signature
    entitlements.
``parse_dyld_shared_cache``
    Decode the stable header, mapping, and image tables of a supplied dyld cache.
``inspect_ipa``
    Inspect a ZIP/IPA in memory, parse Info.plist and provisioning entitlements,
    analyze the app executable, and report static Frida-gadget evidence.

All offsets and counts are range checked and capped.  Malformed optional structures
produce notes rather than speculative values.  Archive members are never extracted.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import plistlib
import re
import struct
import sys
import zipfile
import zlib
from pathlib import Path
from typing import Any
from xml.parsers.expat import ExpatError


class ArtifactError(ValueError):
    """An iOS artifact is malformed, unsupported, or outside parser limits."""


MAX_FILE = 512 << 20
MAX_SLICES = 32
MAX_COMMANDS = 16_384
MAX_SECTIONS = 65_536
MAX_CACHE_MAPPINGS = 4096
MAX_CACHE_IMAGES = 500_000
MAX_SYMBOLS = 250_000
MAX_ARCHIVE_MEMBERS = 16_384
MAX_MEMBER = 256 << 20
MAX_ARCHIVE_TOTAL = 768 << 20
MAX_STRINGS = 4096

_MACH_MAGICS = {
    b"\xce\xfa\xed\xfe": ("<", False),
    b"\xcf\xfa\xed\xfe": ("<", True),
    b"\xfe\xed\xfa\xce": (">", False),
    b"\xfe\xed\xfa\xcf": (">", True),
}
_FAT_MAGICS = {
    b"\xca\xfe\xba\xbe": (">", False),
    b"\xca\xfe\xba\xbf": (">", True),
    b"\xbe\xba\xfe\xca": ("<", False),
    b"\xbf\xba\xfe\xca": ("<", True),
}
_CPU = {
    7: "i386",
    12: "arm",
    18: "ppc",
    0x01000007: "x86_64",
    0x0100000C: "arm64",
    0x0200000C: "arm64_32",
}
_FILETYPE = {
    1: "object", 2: "execute", 3: "fvmlib", 4: "core", 5: "preload",
    6: "dylib", 7: "dylinker", 8: "bundle", 9: "dylib-stub", 10: "dsym",
    11: "kext-bundle", 12: "fileset",
}
_LOAD_NAMES = {
    1: "segment", 2: "symtab", 0x0B: "dysymtab", 0x0C: "load-dylib",
    0x0D: "id-dylib", 0x0E: "load-dylinker", 0x0F: "id-dylinker",
    0x18: "load-weak-dylib", 0x19: "segment-64", 0x1B: "uuid",
    0x1C: "rpath", 0x1D: "code-signature", 0x1F: "reexport-dylib", 0x20: "lazy-load-dylib",
    0x21: "encryption-info", 0x22: "dyld-info", 0x23: "load-upward-dylib",
    0x24: "version-min-macos", 0x25: "version-min-iphoneos",
    0x28: "main", 0x2A: "source-version", 0x2C: "encryption-info-64",
    0x2F: "version-min-tvos", 0x30: "version-min-watchos", 0x32: "build-version",
    0x33: "dyld-exports-trie", 0x34: "dyld-chained-fixups", 0x35: "fileset-entry",
}
_PLATFORMS = {
    1: "macos", 2: "ios", 3: "tvos", 4: "watchos", 5: "bridgeos",
    6: "maccatalyst", 7: "ios-simulator", 8: "tvos-simulator",
    9: "watchos-simulator", 10: "driverkit", 11: "visionos",
    12: "visionos-simulator",
}
_FRIDA_MARKERS = (
    b"frida-gadget", b"frida_agent_main", b"frida-gum", b"gum-js-loop",
    b"gum_script_backend", b"frida_agent_thread", b"libfrida", b"re.frida.server",
)
_PRINTABLE = re.compile(rb"[\x20-\x7e]{5,512}")


def _bounded_file(path: str | Path) -> bytes:
    with Path(path).open("rb") as handle:
        data = handle.read(MAX_FILE + 1)
    if len(data) > MAX_FILE:
        raise ArtifactError("input exceeds 512 MiB cap")
    return data


def _cstr(data: bytes, start: int, end: int, cap: int = 4096) -> str | None:
    if start < 0 or start >= end or end > len(data):
        return None
    stop = data.find(b"\x00", start, min(end, start + cap))
    if stop < 0:
        stop = min(end, start + cap)
    try:
        value = data[start:stop].decode("utf-8")
    except UnicodeDecodeError:
        return None
    return value if value else None


def _version(value: int) -> str:
    return f"{value >> 16}.{(value >> 8) & 0xff}.{value & 0xff}"


def _arch(cpu: int, subtype: int) -> str:
    if cpu == 0x0100000C and (subtype & 0x00FFFFFF) == 2:
        return "arm64e"
    if cpu == 0x01000007 and (subtype & 0x00FFFFFF) == 8:
        return "x86_64h"
    return _CPU.get(cpu, f"cpu-{cpu:#x}")


def _plist_at(data: bytes, start: int = 0) -> dict[str, Any] | None:
    """Read one XML plist beginning at/after start; CMS padding may surround it."""
    xml = data.find(b"<?xml", start)
    if xml < 0:
        xml = data.find(b"<plist", start)
    if xml < 0:
        binary = data.find(b"bplist00", start)
        if binary < 0:
            return None
        try:
            value = plistlib.loads(data[binary:])
        except (plistlib.InvalidFileException, ValueError, TypeError, OverflowError, LookupError, ExpatError):
            return None
        return value if isinstance(value, dict) else None
    end = data.find(b"</plist>", xml)
    if end < 0 or end + 8 - xml > (16 << 20):
        return None
    try:
        value = plistlib.loads(data[xml:end + 8])
    except (plistlib.InvalidFileException, ValueError, TypeError, OverflowError, LookupError, ExpatError):
        return None
    return value if isinstance(value, dict) else None


def _code_signature(data: bytes, offset: int, size: int) -> dict[str, Any]:
    out: dict[str, Any] = {"offset": offset, "size": size, "slots": [], "entitlements": None}
    if offset < 0 or size < 12 or size > len(data) or offset + size > len(data):
        out["error"] = "code-signature range is invalid"
        return out
    blob = data[offset:offset + size]
    try:
        magic, length, count = struct.unpack_from(">III", blob, 0)
    except struct.error:
        out["error"] = "truncated code-signature header"
        return out
    out["magic"] = f"0x{magic:08x}"
    if magic != 0xFADE0CC0 or length < 12 or length > len(blob) or count > 4096:
        # Some fixtures provide a bare entitlement blob rather than a SuperBlob.
        if magic in (0xFADE7171, 0xFADE7172) and 8 <= length <= len(blob):
            out["entitlements"] = _plist_at(blob[8:length])
        else:
            out["error"] = "unsupported or inconsistent code-signature blob"
        return out
    if 12 + count * 8 > length:
        out["error"] = "code-signature index exceeds blob"
        return out
    for index in range(count):
        slot_type, slot_offset = struct.unpack_from(">II", blob, 12 + index * 8)
        slot = {"type": slot_type, "offset": slot_offset}
        if slot_offset + 8 <= length:
            smagic, slength = struct.unpack_from(">II", blob, slot_offset)
            slot.update({"magic": f"0x{smagic:08x}", "size": slength})
            if 8 <= slength <= length - slot_offset and smagic in (0xFADE7171, 0xFADE7172):
                parsed = _plist_at(blob[slot_offset + 8:slot_offset + slength])
                if parsed is not None:
                    out["entitlements"] = parsed
        out["slots"].append(slot)
    return out


def _parse_thin(data: bytes, *, file_offset: int = 0) -> dict[str, Any] | None:
    info = _MACH_MAGICS.get(data[:4])
    if info is None:
        return None
    endian, is64 = info
    header_size = 32 if is64 else 28
    if len(data) < header_size:
        return {"kind": "thin", "error": "truncated Mach-O header", "file_offset": file_offset}
    cpu, subtype, filetype, ncmds, sizeofcmds, flags = struct.unpack_from(endian + "IIIIII", data, 4)
    out: dict[str, Any] = {
        "kind": "thin", "bits": 64 if is64 else 32,
        "endian": "little" if endian == "<" else "big", "cpu_type": cpu,
        "cpu_subtype": subtype, "architecture": _arch(cpu, subtype),
        "file_type": _FILETYPE.get(filetype, f"type-{filetype}"), "commands_count": ncmds,
        "commands_size": sizeofcmds, "flags": flags, "file_offset": file_offset,
        "uuid": None, "dylibs": [], "rpaths": [], "segments": [], "commands": [],
        "symbols": [], "imports": [], "exports": [],
        "encryption": [], "build_versions": [], "code_signature": None, "notes": [],
    }
    if ncmds > MAX_COMMANDS or sizeofcmds > len(data) - header_size:
        out["notes"].append("load-command table exceeds file or cap")
        return out
    cursor, table_end, section_count = header_size, header_size + sizeofcmds, 0
    for index in range(ncmds):
        if cursor + 8 > table_end:
            out["notes"].append(f"load command {index} header is truncated")
            break
        raw_cmd, cmdsize = struct.unpack_from(endian + "II", data, cursor)
        base_cmd = raw_cmd & 0x7FFFFFFF
        if cmdsize < 8 or cursor + cmdsize > table_end:
            out["notes"].append(f"load command {index} has invalid size")
            break
        command: dict[str, Any] = {
            "index": index, "command": raw_cmd,
            "name": _LOAD_NAMES.get(base_cmd, f"load-{base_cmd:#x}"),
            "size": cmdsize, "required": bool(raw_cmd & 0x80000000),
        }
        if base_cmd in (1, 0x19):
            wide = base_cmd == 0x19
            fixed = 72 if wide else 56
            sec_size = 80 if wide else 68
            if cmdsize >= fixed:
                segname = data[cursor + 8:cursor + 24].split(b"\x00", 1)[0].decode("ascii", "replace")
                if wide:
                    vmaddr, vmsize, foff, fsize = struct.unpack_from(endian + "QQQQ", data, cursor + 24)
                    maxprot, initprot, nsects, segflags = struct.unpack_from(endian + "IIII", data, cursor + 56)
                else:
                    vmaddr, vmsize, foff, fsize, maxprot, initprot, nsects, segflags = struct.unpack_from(
                        endian + "IIIIIIII", data, cursor + 24)
                seg = {"name": segname, "vm_address": vmaddr, "vm_size": vmsize,
                       "file_offset": foff, "file_size": fsize, "max_protection": maxprot,
                       "initial_protection": initprot, "flags": segflags, "sections": []}
                if nsects > MAX_SECTIONS - section_count or fixed + nsects * sec_size > cmdsize:
                    out["notes"].append(f"segment {segname!r} has invalid section table")
                else:
                    for sec_index in range(nsects):
                        at = cursor + fixed + sec_index * sec_size
                        sectname = data[at:at + 16].split(b"\x00", 1)[0].decode("ascii", "replace")
                        secseg = data[at + 16:at + 32].split(b"\x00", 1)[0].decode("ascii", "replace")
                        if wide:
                            address, ssize = struct.unpack_from(endian + "QQ", data, at + 32)
                            soff, align, reloff, nreloc, sflags = struct.unpack_from(endian + "IIIII", data, at + 48)
                        else:
                            address, ssize, soff, align, reloff, nreloc, sflags = struct.unpack_from(
                                endian + "IIIIIII", data, at + 32)
                        seg["sections"].append({"name": sectname, "segment": secseg,
                                                "address": address, "size": ssize, "offset": soff,
                                                "alignment_power": align, "relocations_offset": reloff,
                                                "relocations_count": nreloc, "flags": sflags})
                    section_count += nsects
                out["segments"].append(seg)
        elif base_cmd == 2 and cmdsize >= 24:
            symoff, nsyms, stroff, strsize = struct.unpack_from(endian + "IIII", data, cursor + 8)
            entry_size = 16 if is64 else 12
            if (nsyms > MAX_SYMBOLS or symoff > len(data) or nsyms * entry_size > len(data) - symoff
                    or stroff > len(data) or strsize > len(data) - stroff):
                out["notes"].append("symbol/string table exceeds file or cap")
            else:
                strings = data[stroff:stroff + strsize]
                for symbol_index in range(nsyms):
                    at = symoff + symbol_index * entry_size
                    if is64:
                        nameoff, ntype, section, description, value = struct.unpack_from(endian + "IBBHQ", data, at)
                    else:
                        nameoff, ntype, section, description, value = struct.unpack_from(endian + "IBBHI", data, at)
                    name = _cstr(strings, nameoff, len(strings))
                    item = {"index": symbol_index, "name": name, "type": ntype, "section": section,
                            "description": description, "value": value, "external": bool(ntype & 1),
                            "debug": bool(ntype & 0xE0)}
                    out["symbols"].append(item)
                    if name and item["external"] and not item["debug"]:
                        if (ntype & 0x0E) == 0 and value == 0:
                            out["imports"].append(name)
                        else:
                            out["exports"].append(name)
        elif base_cmd in (0x0C, 0x0D, 0x18, 0x1F, 0x20, 0x23) and cmdsize >= 24:
            nameoff, timestamp, current, compat = struct.unpack_from(endian + "IIII", data, cursor + 8)
            name = _cstr(data, cursor + nameoff, cursor + cmdsize)
            item = {"kind": command["name"], "path": name, "timestamp": timestamp,
                    "current_version": _version(current), "compatibility_version": _version(compat)}
            out["dylibs"].append(item)
        elif base_cmd == 0x1C and cmdsize >= 12:
            nameoff = struct.unpack_from(endian + "I", data, cursor + 8)[0]
            value = _cstr(data, cursor + nameoff, cursor + cmdsize)
            if value is not None:
                out["rpaths"].append(value)
        elif base_cmd == 0x1B and cmdsize >= 24:
            raw = data[cursor + 8:cursor + 24]
            out["uuid"] = f"{raw[:4].hex()}-{raw[4:6].hex()}-{raw[6:8].hex()}-{raw[8:10].hex()}-{raw[10:].hex()}"
        elif base_cmd in (0x21, 0x2C) and cmdsize >= (24 if base_cmd == 0x2C else 20):
            cryptoff, cryptsize, cryptid = struct.unpack_from(endian + "III", data, cursor + 8)
            out["encryption"].append({"offset": cryptoff, "size": cryptsize, "crypt_id": cryptid,
                                      "encrypted": cryptid != 0})
        elif base_cmd in (0x24, 0x25, 0x2F, 0x30) and cmdsize >= 16:
            minimum, sdk = struct.unpack_from(endian + "II", data, cursor + 8)
            out["build_versions"].append({"platform": command["name"].removeprefix("version-min-"),
                                          "minimum": _version(minimum), "sdk": _version(sdk)})
        elif base_cmd == 0x32 and cmdsize >= 24:
            platform, minimum, sdk, tool_count = struct.unpack_from(endian + "IIII", data, cursor + 8)
            tools = []
            if tool_count <= 1024 and 24 + tool_count * 8 <= cmdsize:
                for tool_index in range(tool_count):
                    tool, version = struct.unpack_from(endian + "II", data, cursor + 24 + tool_index * 8)
                    tools.append({"tool": tool, "version": _version(version)})
            out["build_versions"].append({"platform": _PLATFORMS.get(platform, platform),
                                          "minimum": _version(minimum), "sdk": _version(sdk), "tools": tools})
        elif base_cmd == 0x1D and cmdsize >= 16:
            dataoff, datasize = struct.unpack_from(endian + "II", data, cursor + 8)
            out["code_signature"] = _code_signature(data, dataoff, datasize)
        out["commands"].append(command)
        cursor += cmdsize
    out["pie"] = bool(flags & 0x00200000)
    out["allow_stack_execution"] = bool(flags & 0x00020000)
    out["no_heap_execution"] = bool(flags & 0x01000000)
    out["imports"] = sorted(set(out["imports"]))
    out["exports"] = sorted(set(out["exports"]))
    out["frida"] = detect_frida(data, paths=[item.get("path") or "" for item in out["dylibs"]])
    return out


def parse_macho(data: bytes) -> dict[str, Any] | None:
    """Parse a bounded thin or universal Mach-O without executing it."""
    if not isinstance(data, (bytes, bytearray)):
        raise ArtifactError("Mach-O input must be bytes")
    raw = bytes(data)
    if len(raw) > MAX_FILE:
        raise ArtifactError("Mach-O exceeds 512 MiB cap")
    thin = _parse_thin(raw)
    if thin is not None:
        return thin
    fat = _FAT_MAGICS.get(raw[:4])
    if fat is None or len(raw) < 8:
        return None
    endian, wide = fat
    count = struct.unpack_from(endian + "I", raw, 4)[0]
    entry_size = 32 if wide else 20
    out: dict[str, Any] = {"kind": "universal", "slice_count": count, "slices": [], "notes": []}
    if count > MAX_SLICES or 8 + count * entry_size > len(raw):
        out["notes"].append("fat architecture table exceeds file or cap")
        return out
    ranges: list[tuple[int, int]] = []
    for index in range(count):
        at = 8 + index * entry_size
        if wide:
            cpu, subtype, offset, size, align, reserved = struct.unpack_from(endian + "IIQQII", raw, at)
        else:
            cpu, subtype, offset, size, align = struct.unpack_from(endian + "IIIII", raw, at)
            reserved = None
        item: dict[str, Any] = {"index": index, "cpu_type": cpu, "cpu_subtype": subtype,
                                "architecture": _arch(cpu, subtype), "offset": offset, "size": size,
                                "alignment_power": align}
        if reserved is not None:
            item["reserved"] = reserved
        if offset > len(raw) or size > len(raw) or offset + size > len(raw):
            item["error"] = "slice exceeds file"
        elif size == 0:
            item["error"] = "empty slice"
        else:
            if any(offset < end and start < offset + size for start, end in ranges):
                item["overlaps_prior_slice"] = True
            ranges.append((offset, offset + size))
            item["macho"] = _parse_thin(raw[offset:offset + size], file_offset=offset)
        out["slices"].append(item)
    return out


def detect_frida(data: bytes, *, paths: list[str] | None = None) -> dict[str, Any]:
    """Return static, reproducible Frida Gadget/instrumentation indicators."""
    lowered = bytes(data).lower()
    evidence = []
    for marker in _FRIDA_MARKERS:
        positions = []
        cursor = 0
        while len(positions) < 8:
            hit = lowered.find(marker, cursor)
            if hit < 0:
                break
            positions.append(hit)
            cursor = hit + 1
        if positions:
            evidence.append({"kind": "byte-marker", "value": marker.decode(), "offsets": positions})
    for path in sorted(set(paths or [])):
        # "Gadget" alone is a common product/library name.  Treat a path as
        # instrumentation evidence only when it actually names Frida; renamed Gadget
        # builds are still found by their byte/symbol markers above.
        if "frida" in path.lower():
            evidence.append({"kind": "path", "value": path})
    score = min(100, sum(45 if item["kind"] == "path" else 30 for item in evidence))
    return {"detected": bool(evidence), "score": score, "evidence": evidence}


def parse_dyld_shared_cache(data: bytes) -> dict[str, Any] | None:
    """Decode stable dyld cache mapping/image tables from supplied bytes."""
    if not isinstance(data, (bytes, bytearray)):
        raise ArtifactError("dyld cache input must be bytes")
    raw = bytes(data)
    if len(raw) > MAX_FILE:
        raise ArtifactError("dyld cache exceeds 512 MiB cap")
    if len(raw) < 32 or not raw[:16].rstrip(b"\x00").startswith(b"dyld_v1"):
        return None
    magic = raw[:16].rstrip(b"\x00").decode("ascii", "replace")
    mapping_offset, mapping_count, images_offset, images_count = struct.unpack_from("<IIII", raw, 16)
    out: dict[str, Any] = {"magic": magic, "mapping_offset": mapping_offset,
                           "mapping_count": mapping_count, "images_offset": images_offset,
                           "images_count": images_count, "mappings": [], "images": [], "notes": []}
    if len(raw) >= 0x68:
        out["uuid"] = raw[0x58:0x68].hex()
    if mapping_count > MAX_CACHE_MAPPINGS or mapping_offset + mapping_count * 32 > len(raw):
        out["notes"].append("mapping table exceeds file or cap")
    else:
        for index in range(mapping_count):
            at = mapping_offset + index * 32
            address, size, fileoff, maxprot, initprot = struct.unpack_from("<QQQII", raw, at)
            out["mappings"].append({"index": index, "address": address, "size": size,
                                    "file_offset": fileoff, "max_protection": maxprot,
                                    "initial_protection": initprot,
                                    "range_valid": fileoff <= len(raw) and size <= len(raw) - fileoff})
    if images_count > MAX_CACHE_IMAGES or images_offset + images_count * 32 > len(raw):
        out["notes"].append("image table exceeds file or cap")
    else:
        for index in range(images_count):
            at = images_offset + index * 32
            address, modtime, inode, pathoff, pad = struct.unpack_from("<QQQII", raw, at)
            path = _cstr(raw, pathoff, len(raw), cap=16_384)
            out["images"].append({"index": index, "address": address, "modification_time": modtime,
                                  "inode": inode, "path_offset": pathoff, "path": path, "padding": pad})
    out["architecture"] = next((name for token, name in (("arm64e", "arm64e"), ("arm64", "arm64"),
                                                               ("x86_64", "x86_64")) if token in magic), None)
    return out


def _archive(data: bytes) -> dict[str, bytes]:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_ARCHIVE_MEMBERS:
                raise ArtifactError("IPA member count exceeds cap")
            members: dict[str, bytes] = {}
            total = 0
            for info in infos:
                if info.is_dir():
                    continue
                if info.file_size < 0 or info.file_size > MAX_MEMBER:
                    continue
                total += info.file_size
                if total > MAX_ARCHIVE_TOTAL:
                    raise ArtifactError("IPA expanded-size cap exceeded")
                with archive.open(info) as handle:
                    body = handle.read(info.file_size + 1)
                if len(body) != info.file_size:
                    raise ArtifactError("IPA member size mismatch")
                members[info.filename] = body
            return members
    except ArtifactError:
        raise
    except (zipfile.BadZipFile, OSError, EOFError, RuntimeError, ValueError, struct.error, zlib.error) as exc:
        raise ArtifactError("IPA is not a readable ZIP") from exc


def _entitlement_summary(value: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    keys = (
        "application-identifier", "com.apple.application-identifier", "com.apple.developer.team-identifier",
        "keychain-access-groups", "get-task-allow", "aps-environment", "com.apple.developer.associated-domains",
        "com.apple.developer.icloud-container-identifiers", "com.apple.security.application-groups",
        "com.apple.developer.networking.wifi-info", "com.apple.developer.healthkit",
    )
    return {key: value[key] for key in keys if key in value}


def inspect_ipa(data: bytes) -> dict[str, Any]:
    """Inspect an IPA/ZIP entirely in memory and return deterministic static facts."""
    if not isinstance(data, (bytes, bytearray)):
        raise ArtifactError("IPA input must be bytes")
    raw = bytes(data)
    if len(raw) > MAX_FILE:
        raise ArtifactError("IPA exceeds 512 MiB cap")
    members = _archive(raw)
    plist_names = sorted(name for name in members if re.fullmatch(
        r"Payload/(?:[^/]+/)*[^/]+\.(?:app|appex)/Info\.plist", name))
    apps = []
    for plist_name in plist_names:
        prefix = plist_name[:-len("Info.plist")]
        try:
            info = plistlib.loads(members[plist_name])
        except (plistlib.InvalidFileException, ValueError, TypeError, OverflowError, LookupError, ExpatError):
            info = None
        if not isinstance(info, dict):
            apps.append({"path": prefix, "error": "Info.plist is invalid"})
            continue
        executable_name = info.get("CFBundleExecutable")
        executable_path = prefix + executable_name if isinstance(executable_name, str) else None
        macho = parse_macho(members[executable_path]) if executable_path in members else None
        provision_path = prefix + "embedded.mobileprovision"
        provision = _plist_at(members[provision_path]) if provision_path in members else None
        provision_entitlements = provision.get("Entitlements") if isinstance(provision, dict) else None
        signature_entitlements = None
        thin_reports = []
        if isinstance(macho, dict):
            thin_reports = [macho] if macho.get("kind") == "thin" else [
                item.get("macho") for item in macho.get("slices", []) if isinstance(item.get("macho"), dict)]
            signature_entitlements = next((report.get("code_signature", {}).get("entitlements")
                                           for report in thin_reports
                                           if isinstance(report.get("code_signature"), dict)
                                           and isinstance(report["code_signature"].get("entitlements"), dict)), None)
        schemes = []
        for url_type in info.get("CFBundleURLTypes", []) if isinstance(info.get("CFBundleURLTypes"), list) else []:
            if isinstance(url_type, dict) and isinstance(url_type.get("CFBundleURLSchemes"), list):
                schemes.extend(value for value in url_type.get("CFBundleURLSchemes", [])
                               if isinstance(value, str))
        query_schemes = [value for value in info.get("LSApplicationQueriesSchemes", [])
                         if isinstance(value, str)] if isinstance(info.get("LSApplicationQueriesSchemes"), list) else []
        privacy = {key: value for key, value in info.items()
                   if isinstance(key, str) and key.startswith("NS") and key.endswith("UsageDescription")}
        app_paths = sorted(name for name in members if name.startswith(prefix))
        frida = detect_frida(b"\n".join(members[name][:8 << 20] for name in app_paths), paths=app_paths)
        apps.append({
            "path": prefix, "bundle_kind": "extension" if prefix.rstrip("/").endswith(".appex") else "application",
            "bundle_id": info.get("CFBundleIdentifier"),
            "display_name": info.get("CFBundleDisplayName") or info.get("CFBundleName"),
            "version": info.get("CFBundleShortVersionString"), "build": info.get("CFBundleVersion"),
            "minimum_os": info.get("MinimumOSVersion"), "executable": executable_path,
            "url_schemes": sorted(set(schemes)), "query_schemes": sorted(set(query_schemes)),
            "associated_domains": _entitlement_summary(signature_entitlements or provision_entitlements).get(
                "com.apple.developer.associated-domains", []),
            "ats": info.get("NSAppTransportSecurity"), "privacy_usage": privacy,
            "provisioning": {
                "name": provision.get("Name") if isinstance(provision, dict) else None,
                "team_names": provision.get("TeamName") if isinstance(provision, dict) else None,
                "uuid": provision.get("UUID") if isinstance(provision, dict) else None,
                "entitlements": _entitlement_summary(provision_entitlements),
            },
            "signature_entitlements": _entitlement_summary(signature_entitlements),
            "macho": macho, "frida": frida,
            "frameworks": sorted(name for name in app_paths if ".framework/" in name and not name.endswith("/")),
        })
    return {"sha256": hashlib.sha256(raw).hexdigest(), "member_count": len(members), "apps": apps,
            "orphan_plists": sorted(name for name in members if name.endswith(".plist") and name not in plist_names)}


def _json_default(value: Any):
    if isinstance(value, bytes):
        return {"hex": value.hex(), "length": len(value)}
    raise TypeError(f"cannot encode {type(value).__name__}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact")
    parser.add_argument("--kind", choices=("auto", "macho", "dyld", "ipa"), default="auto")
    try:
        args = parser.parse_args(argv)
        data = _bounded_file(args.artifact)
        kind = args.kind
        if kind == "auto":
            if data[:4] in _MACH_MAGICS or data[:4] in _FAT_MAGICS:
                kind = "macho"
            elif data.startswith(b"dyld_v1"):
                kind = "dyld"
            elif data.startswith(b"PK"):
                kind = "ipa"
            else:
                parser.error("artifact is not a recognized Mach-O, dyld cache, or IPA")
        report = parse_macho(data) if kind == "macho" else parse_dyld_shared_cache(data) if kind == "dyld" else inspect_ipa(data)
        print(json.dumps(report, indent=2, sort_keys=True, default=_json_default))
        return 0
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    except (OSError, ValueError, TypeError) as exc:
        print(f"ios_depth: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
