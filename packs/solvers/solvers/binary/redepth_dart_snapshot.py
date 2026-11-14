#!/usr/bin/env python3
"""Bounded static inspection of Dart and Flutter AOT snapshot artifacts.

The raw header follows ``runtime/vm/snapshot.h``: a native-endian
``0xdcdcf5f5`` magic, a signed 64-bit length which excludes the four-byte
magic, and a signed 64-bit ``Snapshot::Kind``.  The 32-byte snapshot hash and
NUL-terminated feature string follow the header, as written by
``Serializer::WriteVersionAndFeatures`` in ``runtime/vm/app_snapshot.cc``.

ELF and thin Mach-O symbol tables are inspected for both the current
``_kDartSnapshot*`` names and the legacy VM/isolate split names.  Target bytes
are never loaded or executed.  Clustered objects are intentionally left
opaque because their encoding is tied to the exact Dart snapshot hash.
"""
from __future__ import annotations

import argparse
import json
import re
import struct
import sys
from pathlib import Path
from typing import Any


MAGIC = 0xDCDCF5F5
HEADER_SIZE = 20
VERSION_SIZE = 32

MAX_INPUT = 512 << 20
MAX_FEATURES = 16 << 10
MAX_STRING_SCAN = 64 << 20
MAX_REPORTED_STRINGS = 4096
MAX_NAME = 4096
MAX_SECTIONS = 16384
MAX_SEGMENTS = 4096
MAX_SYMBOLS = 1_000_000
MAX_LOAD_COMMANDS = 4096
MAX_LOAD_COMMAND_BYTES = 32 << 20
MAX_BUILD_ID_BYTES = 256

LC_SEGMENT = 0x1
LC_SYMTAB = 0x2
LC_SEGMENT_64 = 0x19
LC_UUID = 0x1B

_MACHO_MAGICS = {
    b"\xce\xfa\xed\xfe": (32, "<"),
    b"\xcf\xfa\xed\xfe": (64, "<"),
    b"\xfe\xed\xfa\xce": (32, ">"),
    b"\xfe\xed\xfa\xcf": (64, ">"),
}
_FAT_MAGICS = {
    b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
    b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca",
}

_KIND_NAMES = {
    0: "full",
    1: "full-jit",
    2: "full-aot",
    3: "module",
}

_SYMBOL_ROLES = {
    "_kDartSnapshotBuildId": "snapshot_build_id",
    "_kDartSnapshotData": "snapshot_data",
    "_kDartSnapshotText": "snapshot_text",
    "_kDartSnapshotBss": "snapshot_bss",
    "_kDartVmSnapshotData": "vm_snapshot_data",
    "_kDartVmSnapshotInstructions": "vm_snapshot_instructions",
    "_kDartVmSnapshotBss": "vm_snapshot_bss",
    "_kDartIsolateSnapshotData": "isolate_snapshot_data",
    "_kDartIsolateSnapshotInstructions": "isolate_snapshot_instructions",
    "_kDartIsolateSnapshotBss": "isolate_snapshot_bss",
}
_DATA_SYMBOLS = {
    "_kDartSnapshotData",
    "_kDartVmSnapshotData",
    "_kDartIsolateSnapshotData",
}
_CONSOLIDATED_SYMBOLS = {
    "_kDartSnapshotData", "_kDartSnapshotText", "_kDartSnapshotBss",
}
_LEGACY_SYMBOLS = {
    "_kDartVmSnapshotData", "_kDartVmSnapshotInstructions",
    "_kDartVmSnapshotBss", "_kDartIsolateSnapshotData",
    "_kDartIsolateSnapshotInstructions", "_kDartIsolateSnapshotBss",
}

_VERSION_RE = re.compile(rb"[0-9a-fA-F]{32}\Z")


class DartSnapshotError(ValueError):
    """Recognized Dart/native data is malformed or exceeds a safety cap."""


def _checked_end(start: int, size: int, limit: int, what: str) -> int:
    if not isinstance(start, int) or not isinstance(size, int):
        raise DartSnapshotError(f"invalid {what} range")
    if start < 0 or size < 0 or start > limit or size > limit - start:
        raise DartSnapshotError(f"{what} runs outside the input")
    return start + size


def _unpack(fmt: str, data: bytes, offset: int, what: str) -> tuple[Any, ...]:
    size = struct.calcsize(fmt)
    _checked_end(offset, size, len(data), what)
    try:
        return struct.unpack_from(fmt, data, offset)
    except struct.error as exc:
        raise DartSnapshotError(f"cannot decode {what}") from exc


def _normalize_input(data: bytes | bytearray | memoryview) -> bytes:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise DartSnapshotError("input must be bytes-like")
    try:
        size = data.nbytes if isinstance(data, memoryview) else len(data)
    except (TypeError, ValueError, OverflowError) as exc:
        raise DartSnapshotError("invalid bytes-like input") from exc
    if size > MAX_INPUT:
        raise DartSnapshotError("input exceeds the size cap")
    try:
        value = bytes(data)
    except (TypeError, ValueError, BufferError, OverflowError) as exc:
        raise DartSnapshotError("cannot copy bytes-like input") from exc
    if len(value) > MAX_INPUT:
        raise DartSnapshotError("input exceeds the size cap")
    return value


def _validate_inventory_options(min_string_length: int, max_strings: int) -> None:
    if (not isinstance(min_string_length, int) or isinstance(min_string_length, bool)
            or not 3 <= min_string_length <= 1024):
        raise DartSnapshotError("min_string_length must be an integer from 3 to 1024")
    if (not isinstance(max_strings, int) or isinstance(max_strings, bool)
            or not 0 <= max_strings <= MAX_REPORTED_STRINGS):
        raise DartSnapshotError(
            f"max_strings must be an integer from 0 to {MAX_REPORTED_STRINGS}"
        )


def _ascii_strings(data: bytes, start: int, end: int, *,
                   base: int, min_length: int,
                   max_strings: int) -> tuple[list[dict[str, Any]], bool]:
    """Inventory printable ASCII without scanning unbounded snapshot bytes."""
    _checked_end(start, end - start, len(data), "string scan")
    scan_end = min(end, start + MAX_STRING_SCAN)
    rows: list[dict[str, Any]] = []
    found_more = False
    run_start: int | None = None
    for offset in range(start, scan_end + 1):
        byte = data[offset] if offset < scan_end else 0
        if 0x20 <= byte <= 0x7E:
            if run_start is None:
                run_start = offset
            continue
        if run_start is not None and offset - run_start >= min_length:
            if len(rows) < max_strings:
                raw = data[run_start:offset]
                rows.append({
                    "offset": run_start - base,
                    "file_offset": run_start,
                    "value": raw.decode("ascii"),
                })
            else:
                found_more = True
        run_start = None
    return rows, found_more or scan_end < end


def _parse_snapshot_at(data: bytes, offset: int, available_end: int,
                       *, min_string_length: int,
                       max_strings: int) -> dict[str, Any] | None:
    if offset < 0 or available_end < offset or available_end > len(data):
        raise DartSnapshotError("invalid snapshot bounds")
    if available_end - offset < 4:
        return None
    marker = data[offset:offset + 4]
    if marker == b"\xf5\xf5\xdc\xdc":
        endian = "<"
        byte_order = "little"
    elif marker == b"\xdc\xdc\xf5\xf5":
        endian = ">"
        byte_order = "big"
    else:
        return None
    if available_end - offset < HEADER_SIZE:
        raise DartSnapshotError("truncated Dart snapshot header")

    stored_length = _unpack(endian + "q", data, offset + 4,
                            "snapshot length")[0]
    kind = _unpack(endian + "q", data, offset + 12,
                   "snapshot kind")[0]
    if stored_length < 0:
        raise DartSnapshotError("snapshot has a negative stored length")
    total_length = stored_length + 4
    minimum = HEADER_SIZE + VERSION_SIZE + 1
    if total_length < minimum:
        raise DartSnapshotError("snapshot length is too small for version and features")
    if total_length > available_end - offset:
        raise DartSnapshotError("declared snapshot length exceeds available bytes")
    if kind not in _KIND_NAMES:
        raise DartSnapshotError(f"invalid Dart Snapshot::Kind value {kind}")

    version_start = offset + HEADER_SIZE
    version_raw = data[version_start:version_start + VERSION_SIZE]
    if not _VERSION_RE.fullmatch(version_raw):
        raise DartSnapshotError("snapshot version is not a 32-byte hexadecimal hash")
    version = version_raw.decode("ascii")

    feature_start = version_start + VERSION_SIZE
    snapshot_end = offset + total_length
    feature_limit = min(snapshot_end, feature_start + MAX_FEATURES + 1)
    feature_end = data.find(b"\0", feature_start, feature_limit)
    if feature_end < 0:
        if feature_limit < snapshot_end:
            raise DartSnapshotError("snapshot feature string exceeds its size cap")
        raise DartSnapshotError("snapshot feature string is unterminated")
    feature_raw = data[feature_start:feature_end]
    if any(byte < 0x20 or byte > 0x7E for byte in feature_raw):
        raise DartSnapshotError("snapshot feature string is not printable ASCII")
    features = feature_raw.decode("ascii")

    strings, strings_truncated = _ascii_strings(
        data, offset, snapshot_end, base=offset,
        min_length=min_string_length, max_strings=max_strings,
    )
    return {
        "offset": offset,
        "byte_order": byte_order,
        "magic": f"0x{MAGIC:08x}",
        "stored_length": stored_length,
        "total_length": total_length,
        "kind": kind,
        "kind_name": _KIND_NAMES[kind],
        "includes_code": kind in {1, 2, 3},
        "is_aot": kind == 2,
        "version": version,
        "features": features,
        "feature_tokens": features.split(),
        "payload_offset": feature_end + 1,
        "payload_size": snapshot_end - (feature_end + 1),
        "available_trailing_bytes": available_end - snapshot_end,
        "strings": strings,
        "strings_truncated": strings_truncated,
        "clustered_objects_parsed": False,
    }


def parse_snapshot(data: bytes | bytearray | memoryview, offset: int = 0,
                   available_size: int | None = None, *,
                   min_string_length: int = 4,
                   max_strings: int = 512) -> dict[str, Any] | None:
    """Parse one raw Dart snapshot at *offset*.

    ``None`` means the magic is absent.  Once the magic is present, malformed
    data raises only :class:`DartSnapshotError`.  ``available_size`` can bound
    a snapshot embedded in a symbol or section.
    """
    try:
        value = _normalize_input(data)
        _validate_inventory_options(min_string_length, max_strings)
        if not isinstance(offset, int) or isinstance(offset, bool):
            raise DartSnapshotError("snapshot offset must be an integer")
        if available_size is None:
            available_end = len(value)
        else:
            if not isinstance(available_size, int) or isinstance(available_size, bool):
                raise DartSnapshotError("available_size must be an integer")
            available_end = _checked_end(offset, available_size, len(value),
                                         "snapshot availability")
        return _parse_snapshot_at(
            value, offset, available_end,
            min_string_length=min_string_length, max_strings=max_strings,
        )
    except DartSnapshotError:
        raise
    except Exception as exc:
        raise DartSnapshotError("unexpected failure while parsing a snapshot") from exc


def _cstring(data: bytes, table_start: int, table_size: int,
             index: int, what: str) -> str:
    if index < 0 or index >= table_size:
        raise DartSnapshotError(f"{what} string index is outside its table")
    start = table_start + index
    table_end = table_start + table_size
    end = data.find(b"\0", start, min(table_end, start + MAX_NAME + 1))
    if end < 0:
        raise DartSnapshotError(f"{what} name is unterminated or too long")
    try:
        return data[start:end].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DartSnapshotError(f"{what} name is not UTF-8") from exc


def _canonical_symbol(name: str) -> str | None:
    core = name
    while core.startswith("_"):
        core = core[1:]
    candidate = "_" + core
    return candidate if candidate in _SYMBOL_ROLES else None


def _layout(symbols: list[dict[str, Any]]) -> str | None:
    names = {row["name"] for row in symbols}
    current = bool(names & _CONSOLIDATED_SYMBOLS)
    legacy = bool(names & _LEGACY_SYMBOLS)
    if current and legacy:
        return "mixed"
    if current:
        return "consolidated"
    if legacy:
        return "legacy"
    return None


def _symbol_report(raw_name: str, canonical: str, value: int, size: int | None,
                   file_offset: int | None, section: str | None,
                   source: str) -> dict[str, Any]:
    return {
        "raw_name": raw_name,
        "name": canonical,
        "role": _SYMBOL_ROLES[canonical],
        "value": value,
        "size": size,
        "file_offset": file_offset,
        "section": section,
        "source": source,
    }


def _elf_notes(data: bytes, offset: int, size: int,
               endian: str) -> list[dict[str, Any]]:
    end = _checked_end(offset, size, len(data), "ELF note section")
    cursor = offset
    rows: list[dict[str, Any]] = []
    while cursor < end:
        if end - cursor < 12:
            if any(data[cursor:end]):
                raise DartSnapshotError("truncated ELF note header")
            break
        namesz, descsz, note_type = _unpack(endian + "III", data, cursor,
                                            "ELF note header")
        cursor += 12
        name_end = _checked_end(cursor, namesz, end, "ELF note name")
        name = data[cursor:name_end].rstrip(b"\0")
        cursor = (name_end + 3) & ~3
        if cursor > end:
            raise DartSnapshotError("ELF note name padding is truncated")
        desc_end = _checked_end(cursor, descsz, end, "ELF note descriptor")
        desc = data[cursor:desc_end]
        cursor = (desc_end + 3) & ~3
        if cursor > end:
            raise DartSnapshotError("ELF note descriptor padding is truncated")
        if name == b"GNU" and note_type == 3:
            rows.append({
                "source": "gnu-build-id",
                "file_offset": desc_end - descsz,
                "size": len(desc),
                "hex": desc.hex(),
            })
    return rows


def _inspect_elf(data: bytes, *, min_string_length: int,
                 max_strings: int) -> dict[str, Any] | None:
    if len(data) < 16:
        raise DartSnapshotError("truncated ELF identification")
    elf_class, data_encoding, ident_version = data[4], data[5], data[6]
    if elf_class not in {1, 2} or data_encoding not in {1, 2} or ident_version != 1:
        raise DartSnapshotError("unsupported or malformed ELF identification")
    bits = 32 if elf_class == 1 else 64
    endian = "<" if data_encoding == 1 else ">"
    byte_order = "little" if endian == "<" else "big"
    if bits == 32:
        header = _unpack(endian + "HHIIIIIHHHHHH", data, 16, "ELF32 header")
        minimum_header, minimum_ph, minimum_sh = 52, 32, 40
    else:
        header = _unpack(endian + "HHIQQQIHHHHHH", data, 16, "ELF64 header")
        minimum_header, minimum_ph, minimum_sh = 64, 56, 64
    (elf_type, machine, version, _entry, phoff, shoff, flags, ehsize,
     phentsize, phnum, shentsize, shnum, shstrndx) = header
    if version != 1 or ehsize < minimum_header or ehsize > len(data):
        raise DartSnapshotError("invalid ELF header size or version")
    if phnum > MAX_SEGMENTS:
        raise DartSnapshotError("ELF program-header count exceeds the cap")
    if phnum and phentsize < minimum_ph:
        raise DartSnapshotError("ELF program-header entry is too small")
    if phnum:
        _checked_end(phoff, phentsize * phnum, len(data),
                     "ELF program-header table")

    segments: list[dict[str, Any]] = []
    for index in range(phnum):
        at = phoff + index * phentsize
        if bits == 32:
            p_type, p_offset, p_vaddr, _paddr, p_filesz, p_memsz, p_flags, p_align = \
                _unpack(endian + "IIIIIIII", data, at, "ELF32 program header")
        else:
            p_type, p_flags, p_offset, p_vaddr, _paddr, p_filesz, p_memsz, p_align = \
                _unpack(endian + "IIQQQQQQ", data, at, "ELF64 program header")
        _checked_end(p_offset, p_filesz, len(data), "ELF segment")
        segments.append({
            "type": p_type, "flags": p_flags, "file_offset": p_offset,
            "file_size": p_filesz, "address": p_vaddr,
            "memory_size": p_memsz, "alignment": p_align,
        })

    if shoff == 0:
        if shnum != 0:
            raise DartSnapshotError("ELF section count exists without a section table")
        return None
    if shentsize < minimum_sh:
        raise DartSnapshotError("ELF section-header entry is too small")

    def raw_section(index: int) -> tuple[int, ...]:
        at = shoff + index * shentsize
        if bits == 32:
            return _unpack(endian + "IIIIIIIIII", data, at,
                           "ELF32 section header")
        return _unpack(endian + "IIQQQQIIQQ", data, at,
                       "ELF64 section header")

    # ELF reserves zero counts and SHN_XINDEX for extended numbering.
    provisional_count = 1 if shnum == 0 else shnum
    _checked_end(shoff, shentsize * provisional_count, len(data),
                 "ELF section-header table")
    first = raw_section(0)
    if shnum == 0:
        shnum = first[5]
    if shstrndx == 0xFFFF:
        shstrndx = first[6]
    if shnum > MAX_SECTIONS:
        raise DartSnapshotError("ELF section count exceeds the cap")
    if shnum == 0:
        return None
    _checked_end(shoff, shentsize * shnum, len(data), "ELF section-header table")

    sections: list[dict[str, Any]] = []
    for index in range(shnum):
        row = raw_section(index)
        (name_index, section_type, section_flags, address, file_offset,
         size, link, info, alignment, entry_size) = row
        if section_type != 8:  # SHT_NOBITS
            _checked_end(file_offset, size, len(data), "ELF section")
        sections.append({
            "index": index, "name_index": name_index, "type": section_type,
            "flags": section_flags, "address": address,
            "file_offset": file_offset, "size": size, "link": link,
            "info": info, "alignment": alignment, "entry_size": entry_size,
            "name": "",
        })
    if shstrndx >= shnum:
        raise DartSnapshotError("ELF section-name table index is invalid")
    if shstrndx:
        names = sections[shstrndx]
        if names["type"] != 3:
            raise DartSnapshotError("ELF section-name table is not a string table")
        for section in sections:
            section["name"] = _cstring(
                data, names["file_offset"], names["size"],
                section["name_index"], "ELF section",
            )

    build_ids: list[dict[str, Any]] = []
    for section in sections:
        if section["type"] == 7 and section["size"]:
            notes = _elf_notes(data, section["file_offset"], section["size"], endian)
            for note in notes:
                if note not in build_ids:
                    build_ids.append(note)

    total_symbols = 0
    recognized: list[dict[str, Any]] = []
    seen: set[tuple[str, int, int | None]] = set()
    for table in sections:
        if table["type"] not in {2, 11}:  # SHT_SYMTAB / SHT_DYNSYM
            continue
        if table["link"] >= len(sections):
            raise DartSnapshotError("ELF symbol table has an invalid string-table link")
        strings = sections[table["link"]]
        if strings["type"] != 3:
            raise DartSnapshotError("ELF symbol table link is not a string table")
        base_size = 16 if bits == 32 else 24
        entry_size = table["entry_size"] or base_size
        if entry_size < base_size or table["size"] % entry_size:
            raise DartSnapshotError("ELF symbol table has an invalid entry size")
        count = table["size"] // entry_size
        total_symbols += count
        if total_symbols > MAX_SYMBOLS:
            raise DartSnapshotError("ELF symbol count exceeds the cap")
        for index in range(count):
            at = table["file_offset"] + index * entry_size
            if bits == 32:
                name_index, value, size, info, _other, section_index = _unpack(
                    endian + "IIIBBH", data, at, "ELF32 symbol"
                )
            else:
                name_index, info, _other, section_index, value, size = _unpack(
                    endian + "IBBHQQ", data, at, "ELF64 symbol"
                )
            if name_index == 0:
                continue
            raw_name = _cstring(data, strings["file_offset"], strings["size"],
                                name_index, "ELF symbol")
            canonical = _canonical_symbol(raw_name)
            if canonical is None or section_index == 0:
                continue
            section_name: str | None = None
            file_offset: int | None = None
            if section_index < len(sections):
                target = sections[section_index]
                section_name = target["name"] or f"section[{section_index}]"
                if target["type"] != 8:
                    relative = value if elf_type == 1 else value - target["address"]
                    if relative < 0 or relative > target["size"]:
                        raise DartSnapshotError(
                            f"Dart symbol {raw_name} lies outside its ELF section"
                        )
                    if size > target["size"] - relative:
                        raise DartSnapshotError(
                            f"Dart symbol {raw_name} exceeds its ELF section"
                        )
                    file_offset = target["file_offset"] + relative
            else:
                # Reserved section indexes can still be mapped through PT_LOAD.
                for segment in segments:
                    relative = value - segment["address"]
                    if (segment["type"] == 1 and relative >= 0
                            and relative <= segment["file_size"]
                            and size <= segment["file_size"] - relative):
                        file_offset = segment["file_offset"] + relative
                        break
            key = (canonical, value, size)
            if key in seen:
                continue
            seen.add(key)
            recognized.append(_symbol_report(
                raw_name, canonical, value, size, file_offset, section_name,
                "dynsym" if table["type"] == 11 else "symtab",
            ))

    if not recognized:
        return None
    return _finish_native_report(
        data, container="elf", bits=bits, byte_order=byte_order,
        symbols=recognized, build_ids=build_ids,
        metadata={"elf_type": elf_type, "machine": machine, "flags": flags},
        min_string_length=min_string_length, max_strings=max_strings,
    )


def _fixed_macho_name(raw: bytes, what: str) -> str:
    end = raw.find(b"\0")
    if end >= 0:
        raw = raw[:end]
    try:
        return raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise DartSnapshotError(f"{what} is not ASCII") from exc


def _inspect_macho(data: bytes, *, min_string_length: int,
                   max_strings: int) -> dict[str, Any] | None:
    bits, endian = _MACHO_MAGICS[data[:4]]
    byte_order = "little" if endian == "<" else "big"
    header_size = 28 if bits == 32 else 32
    if len(data) < header_size:
        raise DartSnapshotError("truncated Mach-O header")
    cpu_type, cpu_subtype, file_type, ncmds, sizeofcmds, flags = _unpack(
        endian + "iiIIII", data, 4, "Mach-O header"
    )
    if ncmds > MAX_LOAD_COMMANDS or sizeofcmds > MAX_LOAD_COMMAND_BYTES:
        raise DartSnapshotError("Mach-O load-command count or size exceeds its cap")
    command_end = _checked_end(header_size, sizeofcmds, len(data),
                               "Mach-O load commands")
    cursor = header_size
    sections: list[dict[str, Any]] = []
    symtab: tuple[int, int, int, int] | None = None
    uuids: list[dict[str, Any]] = []
    for _ in range(ncmds):
        if cursor + 8 > command_end:
            raise DartSnapshotError("truncated Mach-O load command")
        command, command_size = _unpack(endian + "II", data, cursor,
                                        "Mach-O load command")
        if command_size < 8 or cursor + command_size > command_end:
            raise DartSnapshotError("invalid Mach-O load-command size")
        if command == LC_SYMTAB:
            if command_size < 24 or symtab is not None:
                raise DartSnapshotError("invalid or duplicate LC_SYMTAB")
            symtab = _unpack(endian + "IIII", data, cursor + 8, "LC_SYMTAB")
        elif command == LC_UUID:
            if command_size < 24:
                raise DartSnapshotError("truncated LC_UUID")
            raw_uuid = data[cursor + 8:cursor + 24]
            text_uuid = "-".join((
                raw_uuid[0:4].hex(), raw_uuid[4:6].hex(), raw_uuid[6:8].hex(),
                raw_uuid[8:10].hex(), raw_uuid[10:16].hex(),
            ))
            uuids.append({"source": "mach-o-uuid", "hex": raw_uuid.hex(),
                          "uuid": text_uuid})
        elif command in {LC_SEGMENT, LC_SEGMENT_64}:
            expected = LC_SEGMENT_64 if bits == 64 else LC_SEGMENT
            if command != expected:
                raise DartSnapshotError("Mach-O segment command disagrees with word size")
            if bits == 32:
                fixed_size, section_size = 56, 68
                if command_size < fixed_size:
                    raise DartSnapshotError("truncated LC_SEGMENT")
                segment_name = _fixed_macho_name(data[cursor + 8:cursor + 24],
                                                 "Mach-O segment name")
                (vm_address, vm_size, file_offset, file_size, _maxprot,
                 _initprot, section_count, _segment_flags) = _unpack(
                    endian + "IIIIiiII", data, cursor + 24, "LC_SEGMENT"
                )
            else:
                fixed_size, section_size = 72, 80
                if command_size < fixed_size:
                    raise DartSnapshotError("truncated LC_SEGMENT_64")
                segment_name = _fixed_macho_name(data[cursor + 8:cursor + 24],
                                                 "Mach-O segment name")
                (vm_address, vm_size, file_offset, file_size, _maxprot,
                 _initprot, section_count, _segment_flags) = _unpack(
                    endian + "QQQQiiII", data, cursor + 24, "LC_SEGMENT_64"
                )
            if section_count > MAX_SECTIONS - len(sections):
                raise DartSnapshotError("Mach-O section count exceeds the cap")
            if fixed_size + section_count * section_size > command_size:
                raise DartSnapshotError("Mach-O sections exceed their segment command")
            _checked_end(file_offset, file_size, len(data), "Mach-O segment")
            section_cursor = cursor + fixed_size
            for _section_index in range(section_count):
                section_name = _fixed_macho_name(
                    data[section_cursor:section_cursor + 16], "Mach-O section name"
                )
                declared_segment = _fixed_macho_name(
                    data[section_cursor + 16:section_cursor + 32],
                    "Mach-O section segment name",
                )
                if bits == 32:
                    (address, size, section_offset, _align, _reloff, _nreloc,
                     section_flags, _r1, _r2) = _unpack(
                        endian + "IIIIIIIII", data, section_cursor + 32,
                        "Mach-O section",
                    )
                else:
                    (address, size, section_offset, _align, _reloff, _nreloc,
                     section_flags, _r1, _r2, _r3) = _unpack(
                        endian + "QQIIIIIIII", data, section_cursor + 32,
                        "Mach-O 64-bit section",
                    )
                zerofill = (section_flags & 0xFF) in {1, 0x0C, 0x12}
                if not zerofill:
                    _checked_end(section_offset, size, len(data), "Mach-O section")
                sections.append({
                    "name": section_name,
                    "segment": declared_segment or segment_name,
                    "address": address, "size": size,
                    "file_offset": section_offset,
                    "zerofill": zerofill,
                })
                section_cursor += section_size
        cursor += command_size
    if cursor != command_end:
        raise DartSnapshotError("Mach-O load-command byte count is inconsistent")
    if symtab is None:
        return None
    symbol_offset, symbol_count, string_offset, string_size = symtab
    if symbol_count > MAX_SYMBOLS:
        raise DartSnapshotError("Mach-O symbol count exceeds the cap")
    entry_size = 12 if bits == 32 else 16
    _checked_end(symbol_offset, symbol_count * entry_size, len(data),
                 "Mach-O symbol table")
    _checked_end(string_offset, string_size, len(data), "Mach-O string table")

    recognized: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    for index in range(symbol_count):
        at = symbol_offset + index * entry_size
        if bits == 32:
            name_index, symbol_type, section_index, _desc, value = _unpack(
                endian + "IBBHI", data, at, "Mach-O symbol"
            )
        else:
            name_index, symbol_type, section_index, _desc, value = _unpack(
                endian + "IBBHQ", data, at, "Mach-O 64-bit symbol"
            )
        if name_index == 0:
            continue
        raw_name = _cstring(data, string_offset, string_size, name_index,
                            "Mach-O symbol")
        canonical = _canonical_symbol(raw_name)
        if canonical is None or (symbol_type & 0x0E) == 0:
            continue
        if section_index == 0 or section_index > len(sections):
            raise DartSnapshotError(
                f"Dart symbol {raw_name} has an invalid Mach-O section"
            )
        target = sections[section_index - 1]
        relative = value - target["address"]
        if relative < 0 or relative > target["size"]:
            raise DartSnapshotError(
                f"Dart symbol {raw_name} lies outside its Mach-O section"
            )
        file_offset = None if target["zerofill"] else target["file_offset"] + relative
        key = (canonical, value)
        if key in seen:
            continue
        seen.add(key)
        report = _symbol_report(
            raw_name, canonical, value, None, file_offset,
            f"{target['segment']},{target['name']}", "LC_SYMTAB",
        )
        report["_section_index"] = section_index - 1
        report["_section_remaining"] = target["size"] - relative
        recognized.append(report)
    if not recognized:
        return None

    # nlist has no symbol size.  The next symbol in the same section provides
    # a conservative upper bound; otherwise use the remaining section bytes.
    by_section: dict[int, list[dict[str, Any]]] = {}
    for row in recognized:
        by_section.setdefault(row["_section_index"], []).append(row)
    for rows in by_section.values():
        rows.sort(key=lambda item: item["value"])
        for index, row in enumerate(rows):
            extent = row["_section_remaining"]
            if index + 1 < len(rows):
                extent = min(extent, rows[index + 1]["value"] - row["value"])
            row["_extent"] = max(0, extent)

    return _finish_native_report(
        data, container="mach-o", bits=bits, byte_order=byte_order,
        symbols=recognized, build_ids=uuids,
        metadata={
            "cpu_type": cpu_type, "cpu_subtype": cpu_subtype,
            "file_type": file_type, "flags": flags,
        },
        min_string_length=min_string_length, max_strings=max_strings,
    )


def _finish_native_report(data: bytes, *, container: str, bits: int,
                          byte_order: str,
                          symbols: list[dict[str, Any]],
                          build_ids: list[dict[str, Any]],
                          metadata: dict[str, Any],
                          min_string_length: int,
                          max_strings: int) -> dict[str, Any]:
    snapshots: list[dict[str, Any]] = []
    for row in symbols:
        if row["name"] not in _DATA_SYMBOLS or row["file_offset"] is None:
            continue
        offset = row["file_offset"]
        declared_size = row["size"]
        extent = row.get("_extent")
        if declared_size is not None and declared_size > 0:
            available_end = _checked_end(offset, declared_size, len(data),
                                         "Dart data symbol")
        elif extent is not None:
            available_end = _checked_end(offset, extent, len(data),
                                         "Dart data symbol extent")
        else:
            available_end = len(data)
        snapshot = _parse_snapshot_at(
            data, offset, available_end,
            min_string_length=min_string_length, max_strings=max_strings,
        )
        if snapshot is not None:
            snapshot["symbol"] = row["name"]
            snapshot["raw_symbol"] = row["raw_name"]
            snapshots.append(snapshot)

    for row in symbols:
        if row["name"] != "_kDartSnapshotBuildId" or row["file_offset"] is None:
            continue
        available = row["size"] if row["size"] else row.get("_extent", 0)
        if available <= 0:
            continue
        length = min(available, MAX_BUILD_ID_BYTES)
        start = row["file_offset"]
        raw = data[start:start + length]
        build_id: dict[str, Any] = {
            "source": "_kDartSnapshotBuildId",
            "file_offset": start,
            "size": available,
            "hex": raw.hex(),
            "truncated": available > length,
        }
        text = raw.rstrip(b"\0")
        if text and all(0x20 <= byte <= 0x7E for byte in text):
            build_id["ascii"] = text.decode("ascii")
        build_ids.append(build_id)

    public_symbols: list[dict[str, Any]] = []
    for row in sorted(symbols, key=lambda item: (item["name"], item["value"])):
        public_symbols.append({key: value for key, value in row.items()
                               if not key.startswith("_")})
    return {
        "format": "dart-aot-native",
        "container": container,
        "bits": bits,
        "byte_order": byte_order,
        "layout": _layout(public_symbols),
        "metadata": metadata,
        "symbols": public_symbols,
        "build_ids": build_ids,
        "snapshots": snapshots,
        "clustered_objects_parsed": False,
    }


def _inspect(data: bytes, *, min_string_length: int,
             max_strings: int) -> dict[str, Any] | None:
    raw = _parse_snapshot_at(
        data, 0, len(data), min_string_length=min_string_length,
        max_strings=max_strings,
    )
    if raw is not None:
        return {
            "format": "dart-snapshot",
            "container": "raw",
            "layout": "raw",
            "symbols": [],
            "build_ids": [],
            "snapshots": [raw],
            "clustered_objects_parsed": False,
        }
    if data.startswith(b"\x7fELF"):
        return _inspect_elf(
            data, min_string_length=min_string_length, max_strings=max_strings
        )
    if data[:4] in _MACHO_MAGICS:
        return _inspect_macho(
            data, min_string_length=min_string_length, max_strings=max_strings
        )
    if data[:4] in _FAT_MAGICS:
        raise DartSnapshotError("fat Mach-O containers are not supported; inspect one slice")
    return None


def inspect_dart_snapshot(data: bytes | bytearray | memoryview, *,
                          min_string_length: int = 4,
                          max_strings: int = 512) -> dict[str, Any] | None:
    """Inspect raw, ELF, or thin Mach-O Dart snapshot data without loading it.

    Unrecognized bytes return ``None``.  Recognized malformed inputs raise
    only :class:`DartSnapshotError`.
    """
    try:
        value = _normalize_input(data)
        _validate_inventory_options(min_string_length, max_strings)
        return _inspect(
            value, min_string_length=min_string_length, max_strings=max_strings
        )
    except DartSnapshotError:
        raise
    except Exception as exc:
        raise DartSnapshotError("unexpected failure while inspecting Dart data") from exc


analyze = inspect_dart_snapshot


def analyze_file(path: str | Path, *, min_string_length: int = 4,
                 max_strings: int = 512) -> dict[str, Any] | None:
    try:
        with Path(path).open("rb") as handle:
            data = handle.read(MAX_INPUT + 1)
    except (OSError, ValueError, TypeError) as exc:
        raise DartSnapshotError(f"cannot read input: {exc}") from exc
    if len(data) > MAX_INPUT:
        raise DartSnapshotError("input exceeds the size cap")
    return inspect_dart_snapshot(
        data, min_string_length=min_string_length, max_strings=max_strings
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="redepth_dart_snapshot.py",
        description="statically inspect raw, ELF, or thin Mach-O Dart AOT snapshots",
    )
    parser.add_argument("input", help="snapshot or native artifact (never loaded/executed)")
    parser.add_argument("--min-string", type=int, default=4,
                        help="minimum printable ASCII run (3..1024; default: 4)")
    parser.add_argument("--max-strings", type=int, default=512,
                        help=f"maximum strings reported (0..{MAX_REPORTED_STRINGS})")
    parser.add_argument("--indent", type=int, choices=range(0, 9), default=None)
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        result = analyze_file(
            args.input, min_string_length=args.min_string,
            max_strings=args.max_strings,
        )
        if result is None:
            raise DartSnapshotError("input has no supported Dart snapshot evidence")
        print(json.dumps(result, sort_keys=True, indent=args.indent))
        return 0
    except DartSnapshotError as exc:
        print(f"redepth_dart_snapshot: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
