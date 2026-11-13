#!/usr/bin/env python3
"""Offline structural inventory for .NET IL, ReadyToRun, and NativeAOT images.

The ``RTR\0`` signature is shared by two different formats.  CoreCLR ReadyToRun
uses ``(type, RVA, size)`` directory entries and is normally reached through a
PE CLI header.  NativeAOT uses a pointer-sized directory embedded in an ordinary
PE/ELF/Mach-O executable.  This module validates those layouts independently,
maps every reported address back to file bytes, and never loads the artifact.
"""
from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import re
import struct
import sys
from pathlib import Path
from typing import Iterable


# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

RTR_SIGNATURE = b"RTR\0"
MAX_INPUT = 256 << 20
MAX_REGIONS = 4096
MAX_SECTIONS = 4096
MAX_SYMBOLS = 100_000
MAX_REPORTED_SYMBOLS = 4096
MAX_RTR_CANDIDATES = 256
MAX_RTR_SECTIONS = 4096
MAX_STRING_MATCHES = 50_000
MAX_REPORTED_STRINGS = 512
MAX_STRING_SCAN = 64 << 20


class NativeAotError(ValueError):
    """The supplied binary is malformed or outside the engine's safety caps."""


CORE_RTR_SECTIONS = {
    100: "CompilerIdentifier",
    101: "ImportSections",
    102: "RuntimeFunctions",
    103: "MethodDefEntryPoints",
    104: "ExceptionInfo",
    105: "DebugInfo",
    106: "DelayLoadMethodCallThunks",
    108: "AvailableTypes",
    109: "InstanceMethodEntryPoints",
    110: "InliningInfo",
    111: "ProfileDataInfo",
    112: "ManifestMetadata",
    113: "AttributePresence",
    114: "InliningInfo2",
    115: "ComponentAssemblies",
    116: "OwnerCompositeExecutable",
    117: "PgoInstrumentationData",
    118: "ManifestAssemblyMvids",
    119: "CrossModuleInlineInfo",
    120: "HotColdMap",
    121: "MethodIsGenericMap",
    122: "EnclosingTypeMap",
    123: "TypeGenericInfoMap",
    124: "ExternalTypeMaps",
    125: "ProxyTypeMaps",
    126: "TypeMapAssemblyTargets",
    127: "WasmAsyncResumeInfo",
}

NATIVE_RTR_SECTIONS = {
    200: "StringTable",
    201: "GCStaticRegion",
    202: "ThreadStaticRegion",
    204: "TypeManagerIndirection",
    205: "EagerCctor",
    206: "FrozenObjectRegion",
    207: "DehydratedData",
    208: "ThreadStaticOffsetRegion",
    209: "InterfaceDispatchCellInfoRegion",
    210: "InterfaceDispatchCellRegion",
    212: "ImportAddressTables",
    213: "ModuleInitializerList",
    214: "GvmDispatchCellInfoRegion",
    215: "GvmDispatchCellRegion",
}

_REFLECTION_BLOBS = {
    1: "TypeMap",
    2: "ArrayMap",
    3: "PointerTypeMap",
    4: "FunctionPointerTypeMap",
    6: "InvokeMap",
    7: "VirtualInvokeMap",
    8: "CommonFixupsTable",
    9: "FieldAccessMap",
    10: "CCtorContextMap",
    11: "ByRefTypeMap",
    13: "EmbeddedMetadata",
    16: "StructMarshallingStubMap",
    17: "DelegateMarshallingStubMap",
    18: "GenericVirtualMethodTable",
    19: "InterfaceGenericVirtualMethodTable",
    21: "TypeTemplateMap",
    22: "GenericMethodsTemplateMap",
    24: "ResourceIndex",
    25: "ResourceData",
    26: "StackTraceEmbeddedMetadata",
    27: "StackTraceMethodRvaToTokenMapping",
    28: "StackTraceLineNumbers",
    29: "StackTraceDocuments",
    30: "NativeLayoutInfo",
    31: "NativeReferences",
    32: "GenericsHashtable",
    33: "NativeStatics",
    34: "StaticsInfoHashtable",
    35: "GenericMethodsHashtable",
    36: "ExactMethodInstantiationsHashtable",
    37: "UnboxingStubMap",
}
for _blob_id, _blob_name in _REFLECTION_BLOBS.items():
    NATIVE_RTR_SECTIONS[300 + _blob_id] = f"ReflectionMap.{_blob_name}"

CORE_RTR_FLAGS = {
    0x0001: "PlatformNeutralSource",
    0x0002: "SkipTypeValidation",
    0x0004: "Partial",
    0x0008: "NonSharedPInvokeStubs",
    0x0010: "EmbeddedMSIL",
    0x0020: "Component",
    0x0040: "MultimoduleVersionBubble",
    0x0080: "UnrelatedR2RCode",
    0x0100: "PlatformNativeImage",
    0x0200: "StrippedILBodies",
    0x0400: "StrippedInliningInfo",
    0x0800: "StrippedDebugInfo",
    0x1000: "VerifyGCModeTransitions",
    0x2000: "SingleThreaded",
}

_MACHINE_PE = {
    0x014C: "x86",
    0x8664: "x86_64",
    0x01C0: "arm",
    0x01C4: "armv7",
    0xAA64: "aarch64",
    0x5032: "riscv32",
    0x5064: "riscv64",
    0x5128: "riscv128",
    0x6264: "loongarch64",
}
_MACHINE_ELF = {
    3: "x86",
    8: "mips",
    20: "powerpc",
    21: "powerpc64",
    40: "arm",
    62: "x86_64",
    183: "aarch64",
    243: "riscv",
    258: "loongarch",
}
_CPU_MACHO = {
    7: "x86",
    0x01000007: "x86_64",
    12: "arm",
    0x0100000C: "aarch64",
}


@dataclasses.dataclass(frozen=True)
class _Region:
    name: str
    file_offset: int
    file_size: int
    address: int
    memory_size: int


@dataclasses.dataclass
class _Image:
    data: bytes
    kind: str
    bits: int
    endian: str
    architecture: str
    image_base: int
    regions: list[_Region]
    section_names: list[str]
    symbols: list[str]
    metadata: dict
    chain_formats: list[tuple[int, int, int]] = dataclasses.field(default_factory=list)
    chain_slots: dict[int, int] = dataclasses.field(default_factory=dict)

    @property
    def pointer_size(self) -> int:
        return self.bits // 8

    def address_to_offset(self, address: int, size: int = 1) -> int | None:
        if address < 0 or size < 0:
            return None
        found: set[int] = set()
        for region in self.regions:
            delta = address - region.address
            if delta < 0:
                continue
            if size == 0:
                if region.file_size == 0 or delta > region.file_size:
                    continue
            elif delta >= region.file_size or size > region.file_size - delta:
                continue
            found.add(region.file_offset + delta)
        if len(found) == 1:
            return next(iter(found))
        return None

    def address_in_memory(self, address: int, size: int = 0) -> bool:
        if address < 0 or size < 0:
            return False
        for region in self.regions:
            delta = address - region.address
            if delta < 0:
                continue
            if size == 0 and delta <= region.memory_size:
                return True
            if size and delta < region.memory_size and size <= region.memory_size - delta:
                return True
        return False

    def file_backed_prefix(self, address: int, size: int) -> int:
        """Number of initial bytes at ``address`` represented in the file."""
        if size <= 0:
            return 0
        best = 0
        for region in self.regions:
            delta = address - region.address
            if 0 <= delta < region.file_size:
                best = max(best, min(size, region.file_size - delta))
        return best

    def rva_to_offset(self, rva: int, size: int = 1) -> int | None:
        if self.kind == "PE":
            return self.address_to_offset(rva, size)
        return self.address_to_offset(self.image_base + rva, size)

    def offset_to_address(self, offset: int) -> int | None:
        if offset < 0:
            return None
        found: set[int] = set()
        for region in self.regions:
            delta = offset - region.file_offset
            if 0 <= delta <= region.file_size:
                found.add(region.address + delta)
        if len(found) == 1:
            return next(iter(found))
        return None

    def chain_format_at(self, file_offset: int) -> int | None:
        return self.chain_slots.get(file_offset)

    def resolve_pointer(self, raw: int, field_offset: int, size: int = 0) -> tuple[int, int | None, str] | None:
        if raw <= 0:
            return None
        if self.kind == "PE":
            if raw >= self.image_base:
                rva = raw - self.image_base
                mapped = self.rva_to_offset(rva, size)
                if mapped is not None or self.address_in_memory(rva, size):
                    return raw, mapped, "virtual_address"
            mapped = self.rva_to_offset(raw, size)
            if mapped is not None or self.address_in_memory(raw, size):
                return self.image_base + raw, mapped, "rva"
        else:
            mapped = self.address_to_offset(raw, size)
            if mapped is not None or self.address_in_memory(raw, size):
                return raw, mapped, "virtual_address"

        # Modern Mach-O linkers encode rebases in-place.  NativeAOT header
        # pointers use DYLD_CHAINED_PTR_64(_OFFSET); accept them only in a
        # segment whose chained-fixup descriptor declared that format.
        if self.kind == "Mach-O" and self.bits == 64:
            pointer_format = self.chain_format_at(field_offset)
            if pointer_format in (2, 6) and not (raw >> 63):
                target = raw & ((1 << 36) - 1)
                high8 = (raw >> 36) & 0xFF
                address = (self.image_base + target if pointer_format == 6
                           else target | (high8 << 56))
                mapped = self.address_to_offset(address, size)
                if mapped is not None or self.address_in_memory(address, size):
                    return address, mapped, "mach_o_chained_rebase"
        return None

    def region_report(self) -> list[dict]:
        rows = []
        for region in self.regions:
            virtual_address = (self.image_base + region.address
                               if self.kind == "PE" else region.address)
            row = {
                "name": region.name,
                "file_offset": region.file_offset,
                "file_size": region.file_size,
                "virtual_address": virtual_address,
                "memory_size": region.memory_size,
            }
            rva = region.address if self.kind == "PE" else region.address - self.image_base
            if rva >= 0:
                row["rva"] = rva
            rows.append(row)
        return rows


def _span(data: bytes, offset: int, size: int, label: str) -> None:
    if not isinstance(offset, int) or not isinstance(size, int) or offset < 0 or size < 0:
        raise NativeAotError(f"invalid {label} span")
    if offset > len(data) or size > len(data) - offset:
        raise NativeAotError(f"truncated {label}")


def _unpack(data: bytes, endian: str, fmt: str, offset: int, label: str) -> tuple:
    size = struct.calcsize(endian + fmt)
    _span(data, offset, size, label)
    try:
        return struct.unpack_from(endian + fmt, data, offset)
    except (struct.error, OverflowError) as exc:  # defensive: _span normally prevents this
        raise NativeAotError(f"malformed {label}") from exc


def _cstring(data: bytes, offset: int, limit: int, *, strict: bool = False) -> str | None:
    if offset < 0 or limit < 0 or offset > len(data):
        if strict:
            raise NativeAotError("string points outside input")
        return None
    end = min(len(data), offset + limit)
    zero = data.find(b"\0", offset, end)
    if zero < 0:
        if strict:
            raise NativeAotError("unterminated bounded string")
        zero = end
    raw = data[offset:zero]
    if not raw:
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        if strict:
            raise NativeAotError("non-UTF-8 structural string")
        return None
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in text):
        return None
    return text


def _append_symbol(symbols: list[str], seen: set[str], name: str | None) -> None:
    if not name or name in seen or len(name) > 1024:
        return
    interesting = re.search(
        r"(?:Rhp|Rh[A-Z]|ReadyToRun|managedcode|modules|DotNetRuntime|CoreLib|ILCompiler)", name,
    )
    if len(symbols) < 512 or interesting:
        if len(symbols) < MAX_REPORTED_SYMBOLS:
            symbols.append(name)
            seen.add(name)


def _parse_pe(data: bytes) -> _Image:
    _span(data, 0, 0x40, "DOS header")
    pe_offset = _unpack(data, "<", "I", 0x3C, "DOS e_lfanew")[0]
    _span(data, pe_offset, 24, "PE/COFF header")
    if data[pe_offset:pe_offset + 4] != b"PE\0\0":
        raise NativeAotError("invalid PE signature")
    coff = pe_offset + 4
    machine, section_count, _timestamp, symbol_ptr, symbol_count, optional_size, _chars = _unpack(
        data, "<", "HHIIIHH", coff, "COFF header",
    )
    if section_count == 0 or section_count > 96:
        raise NativeAotError("PE section count exceeds cap")
    optional = coff + 20
    _span(data, optional, optional_size, "PE optional header")
    magic = _unpack(data, "<", "H", optional, "PE optional magic")[0]
    if magic == 0x20B:
        bits, minimum, image_base_off, count_off, dirs_off = 64, 112, 24, 108, 112
        image_base = _unpack(data, "<", "Q", optional + image_base_off, "PE image base")[0]
    elif magic == 0x10B:
        bits, minimum, image_base_off, count_off, dirs_off = 32, 96, 28, 92, 96
        image_base = _unpack(data, "<", "I", optional + image_base_off, "PE image base")[0]
    else:
        raise NativeAotError("unsupported PE optional-header magic")
    if optional_size < minimum:
        raise NativeAotError("truncated PE optional header")
    size_of_headers = _unpack(data, "<", "I", optional + 60, "PE SizeOfHeaders")[0]
    if size_of_headers == 0 or size_of_headers > len(data):
        raise NativeAotError("invalid PE SizeOfHeaders")
    directory_count = _unpack(data, "<", "I", optional + count_off, "PE directory count")[0]
    available_dirs = max(0, (optional_size - dirs_off) // 8)
    if directory_count > available_dirs:
        raise NativeAotError("PE data-directory table is truncated")
    directories: dict[int, tuple[int, int]] = {}
    for index in range(min(directory_count, 32)):
        directories[index] = _unpack(
            data, "<", "II", optional + dirs_off + index * 8, f"PE directory {index}",
        )

    table = optional + optional_size
    _span(data, table, section_count * 40, "PE section table")
    regions = [_Region("headers", 0, size_of_headers, 0, size_of_headers)]
    section_names: list[str] = []
    for index in range(section_count):
        offset = table + index * 40
        raw_name = data[offset:offset + 8].split(b"\0", 1)[0]
        name = raw_name.decode("ascii", "replace") or f"section_{index}"
        virtual_size, rva, raw_size, raw_offset = _unpack(
            data, "<", "IIII", offset + 8, f"PE section {index}",
        )
        section_names.append(name)
        if raw_size:
            _span(data, raw_offset, raw_size, f"PE section {name}")
        if virtual_size or raw_size:
            regions.append(_Region(name, raw_offset, raw_size, rva, max(virtual_size, raw_size)))
    if len(regions) > MAX_REGIONS:
        raise NativeAotError("PE region count exceeds cap")

    image = _Image(data, "PE", bits, "<", _MACHINE_PE.get(machine, f"machine_{machine:#x}"),
                   image_base, regions, section_names, [],
                   {"directories": directories, "size_of_headers": size_of_headers,
                    "coff_symbol_pointer": symbol_ptr, "coff_symbol_count": symbol_count})
    _parse_pe_symbols(image)
    _parse_pe_exports(image)
    return image


def _parse_pe_symbols(image: _Image) -> None:
    data = image.data
    pointer = image.metadata["coff_symbol_pointer"]
    count = image.metadata["coff_symbol_count"]
    if not pointer and not count:
        return
    if not pointer or count > MAX_SYMBOLS:
        raise NativeAotError("invalid COFF symbol table")
    _span(data, pointer, count * 18, "COFF symbol table")
    string_offset = pointer + count * 18
    _span(data, string_offset, 4, "COFF string table")
    string_size = _unpack(data, "<", "I", string_offset, "COFF string-table size")[0]
    if string_size < 4:
        raise NativeAotError("invalid COFF string-table size")
    _span(data, string_offset, string_size, "COFF string table")
    seen: set[str] = set(image.symbols)
    index = 0
    while index < count:
        offset = pointer + index * 18
        raw = data[offset:offset + 8]
        if raw[:4] == b"\0\0\0\0":
            string_index = _unpack(data, "<", "I", offset + 4, "COFF symbol name")[0]
            name = (_cstring(data, string_offset + string_index, string_size - string_index)
                    if 4 <= string_index < string_size else None)
        else:
            name = raw.split(b"\0", 1)[0].decode("ascii", "replace")
        _append_symbol(image.symbols, seen, name)
        auxiliary = data[offset + 17]
        if auxiliary > count - index - 1:
            raise NativeAotError("COFF auxiliary symbols exceed table")
        index += 1 + auxiliary


def _parse_pe_exports(image: _Image) -> None:
    rva, size = image.metadata["directories"].get(0, (0, 0))
    if not rva and not size:
        return
    if not rva or size < 40:
        raise NativeAotError("invalid PE export directory")
    offset = image.rva_to_offset(rva, 40)
    if offset is None:
        raise NativeAotError("PE export directory is not file-backed")
    name_count = _unpack(image.data, "<", "I", offset + 24, "PE export name count")[0]
    names_rva = _unpack(image.data, "<", "I", offset + 32, "PE export name table")[0]
    if name_count > MAX_SYMBOLS:
        raise NativeAotError("PE export-name count exceeds cap")
    table = image.rva_to_offset(names_rva, name_count * 4)
    if table is None and name_count:
        raise NativeAotError("PE export-name table is not file-backed")
    seen = set(image.symbols)
    for index in range(name_count):
        name_rva = _unpack(image.data, "<", "I", table + index * 4, "PE export name RVA")[0]
        name_offset = image.rva_to_offset(name_rva, 1)
        if name_offset is None:
            raise NativeAotError("PE export name is not file-backed")
        _append_symbol(image.symbols, seen, _cstring(image.data, name_offset, 1024, strict=True))


def _parse_elf(data: bytes) -> _Image:
    _span(data, 0, 16, "ELF identification")
    elf_class, encoding = data[4], data[5]
    if elf_class not in (1, 2) or encoding not in (1, 2):
        raise NativeAotError("unsupported ELF class or byte order")
    bits, endian = (32 if elf_class == 1 else 64), ("<" if encoding == 1 else ">")
    header_size = 52 if bits == 32 else 64
    _span(data, 0, header_size, "ELF header")
    machine = _unpack(data, endian, "H", 18, "ELF machine")[0]
    if bits == 64:
        program_offset = _unpack(data, endian, "Q", 32, "ELF program offset")[0]
        section_offset = _unpack(data, endian, "Q", 40, "ELF section offset")[0]
        program_entry_size = _unpack(data, endian, "H", 54, "ELF program-entry size")[0]
        program_count = _unpack(data, endian, "H", 56, "ELF program count")[0]
        section_entry_size = _unpack(data, endian, "H", 58, "ELF section-entry size")[0]
        section_count = _unpack(data, endian, "H", 60, "ELF section count")[0]
        string_index = _unpack(data, endian, "H", 62, "ELF shstr index")[0]
        expected_program, expected_section = 56, 64
    else:
        program_offset = _unpack(data, endian, "I", 28, "ELF program offset")[0]
        section_offset = _unpack(data, endian, "I", 32, "ELF section offset")[0]
        program_entry_size = _unpack(data, endian, "H", 42, "ELF program-entry size")[0]
        program_count = _unpack(data, endian, "H", 44, "ELF program count")[0]
        section_entry_size = _unpack(data, endian, "H", 46, "ELF section-entry size")[0]
        section_count = _unpack(data, endian, "H", 48, "ELF section count")[0]
        string_index = _unpack(data, endian, "H", 50, "ELF shstr index")[0]
        expected_program, expected_section = 32, 40
    if program_count == 0 or program_count > MAX_REGIONS or program_entry_size < expected_program:
        raise NativeAotError("invalid ELF program-header table")
    _span(data, program_offset, program_count * program_entry_size, "ELF program-header table")
    regions: list[_Region] = []
    segment_rows: list[tuple[int, int, int, int]] = []
    for index in range(program_count):
        offset = program_offset + index * program_entry_size
        p_type = _unpack(data, endian, "I", offset, f"ELF program header {index}")[0]
        if bits == 64:
            file_offset, address, _physical, file_size, memory_size = _unpack(
                data, endian, "QQQQQ", offset + 8, f"ELF program header {index} fields",
            )
        else:
            file_offset, address, _physical, file_size, memory_size = _unpack(
                data, endian, "IIIII", offset + 4, f"ELF program header {index} fields",
            )
        segment_rows.append((p_type, file_offset, address, file_size))
        if p_type == 1:
            if file_size > memory_size:
                raise NativeAotError("ELF PT_LOAD file size exceeds memory size")
            if file_size:
                _span(data, file_offset, file_size, f"ELF PT_LOAD {index}")
            if file_size or memory_size:
                regions.append(_Region(f"PT_LOAD[{index}]", file_offset, file_size, address, memory_size))
    if not regions:
        raise NativeAotError("ELF has no file-backed PT_LOAD segment")
    image_base = min(region.address - region.file_offset for region in regions)

    section_names: list[str] = []
    section_rows: list[dict] = []
    if section_count:
        if section_count > MAX_SECTIONS or section_entry_size < expected_section or string_index >= section_count:
            raise NativeAotError("invalid ELF section-header table")
        _span(data, section_offset, section_count * section_entry_size, "ELF section-header table")
        for index in range(section_count):
            offset = section_offset + index * section_entry_size
            if bits == 64:
                name_index, section_type = _unpack(data, endian, "II", offset, "ELF section header")
                address, file_offset, size = _unpack(data, endian, "QQQ", offset + 16, "ELF section fields")
                link = _unpack(data, endian, "I", offset + 40, "ELF section link")[0]
                entry_size = _unpack(data, endian, "Q", offset + 56, "ELF section entsize")[0]
            else:
                name_index, section_type = _unpack(data, endian, "II", offset, "ELF section header")
                address, file_offset, size = _unpack(data, endian, "III", offset + 12, "ELF section fields")
                link = _unpack(data, endian, "I", offset + 24, "ELF section link")[0]
                entry_size = _unpack(data, endian, "I", offset + 36, "ELF section entsize")[0]
            if section_type != 8 and size:
                _span(data, file_offset, size, f"ELF section {index}")
            section_rows.append({"name_index": name_index, "type": section_type, "address": address,
                                 "offset": file_offset, "size": size, "link": link,
                                 "entry_size": entry_size})
        names_row = section_rows[string_index]
        if names_row["type"] != 3:
            raise NativeAotError("ELF section-name table is not STRTAB")
        for row in section_rows:
            index = row["name_index"]
            name = (_cstring(data, names_row["offset"] + index, names_row["size"] - index)
                    if index < names_row["size"] else None)
            section_names.append(name or "")

    image = _Image(data, "ELF", bits, endian, _MACHINE_ELF.get(machine, f"machine_{machine}"),
                   image_base, regions, section_names, [], {"segments": segment_rows})
    _parse_elf_symbols(image, section_rows)
    return image


def _parse_elf_symbols(image: _Image, rows: list[dict]) -> None:
    if not rows:
        return
    seen: set[str] = set()
    total = 0
    expected = 24 if image.bits == 64 else 16
    for row in rows:
        if row["type"] not in (2, 11):
            continue
        entry_size = row["entry_size"] or expected
        if entry_size < expected or row["size"] % entry_size or row["link"] >= len(rows):
            raise NativeAotError("invalid ELF symbol table")
        strings = rows[row["link"]]
        if strings["type"] != 3:
            raise NativeAotError("ELF symbol table does not link to STRTAB")
        count = row["size"] // entry_size
        total += count
        if total > MAX_SYMBOLS:
            raise NativeAotError("ELF symbol count exceeds cap")
        for index in range(count):
            offset = row["offset"] + index * entry_size
            name_index = _unpack(image.data, image.endian, "I", offset, "ELF symbol name")[0]
            name = (_cstring(image.data, strings["offset"] + name_index, strings["size"] - name_index)
                    if name_index < strings["size"] else None)
            _append_symbol(image.symbols, seen, name)


def _parse_macho(data: bytes) -> _Image:
    magics = {
        b"\xcf\xfa\xed\xfe": (64, "<"),
        b"\xfe\xed\xfa\xcf": (64, ">"),
        b"\xce\xfa\xed\xfe": (32, "<"),
        b"\xfe\xed\xfa\xce": (32, ">"),
    }
    bits, endian = magics[data[:4]]
    header_size = 32 if bits == 64 else 28
    _span(data, 0, header_size, "Mach-O header")
    cpu_type = _unpack(data, endian, "I", 4, "Mach-O CPU type")[0]
    command_count, command_size = _unpack(data, endian, "II", 16, "Mach-O load-command sizes")
    if command_count > MAX_SECTIONS or command_size > len(data) - header_size:
        raise NativeAotError("Mach-O load-command table exceeds bounds")
    command_end = header_size + command_size
    regions: list[_Region] = []
    all_segments: list[tuple[int, int, int, int, str]] = []
    section_names: list[str] = []
    symtab: tuple[int, int, int, int] | None = None
    chained: tuple[int, int] | None = None
    cursor = header_size
    for index in range(command_count):
        _span(data, cursor, 8, f"Mach-O load command {index}")
        command, size = _unpack(data, endian, "II", cursor, f"Mach-O load command {index}")
        if size < 8 or size > command_end - cursor:
            raise NativeAotError("invalid Mach-O load-command size")
        if command == 0x19 and bits == 64:
            if size < 72:
                raise NativeAotError("truncated LC_SEGMENT_64")
            segment_name = data[cursor + 8:cursor + 24].split(b"\0", 1)[0].decode("ascii", "replace")
            address, memory_size, file_offset, file_size = _unpack(
                data, endian, "QQQQ", cursor + 24, "Mach-O 64-bit segment",
            )
            section_count = _unpack(data, endian, "I", cursor + 64, "Mach-O section count")[0]
            if section_count > MAX_SECTIONS or 72 + section_count * 80 > size:
                raise NativeAotError("Mach-O section table exceeds load command")
            all_segments.append((file_offset, file_size, address, memory_size, segment_name))
            if file_size:
                _span(data, file_offset, file_size, f"Mach-O segment {segment_name}")
                regions.append(_Region(segment_name or f"segment_{index}", file_offset, file_size,
                                       address, memory_size))
            for section_index in range(section_count):
                section = cursor + 72 + section_index * 80
                section_name = data[section:section + 16].split(b"\0", 1)[0].decode("ascii", "replace")
                section_segment = data[section + 16:section + 32].split(b"\0", 1)[0].decode("ascii", "replace")
                section_names.extend(filter(None, (section_name, f"{section_segment},{section_name}")))
        elif command == 0x1 and bits == 32:
            if size < 56:
                raise NativeAotError("truncated LC_SEGMENT")
            segment_name = data[cursor + 8:cursor + 24].split(b"\0", 1)[0].decode("ascii", "replace")
            address, memory_size, file_offset, file_size = _unpack(
                data, endian, "IIII", cursor + 24, "Mach-O 32-bit segment",
            )
            section_count = _unpack(data, endian, "I", cursor + 48, "Mach-O section count")[0]
            if section_count > MAX_SECTIONS or 56 + section_count * 68 > size:
                raise NativeAotError("Mach-O section table exceeds load command")
            all_segments.append((file_offset, file_size, address, memory_size, segment_name))
            if file_size:
                _span(data, file_offset, file_size, f"Mach-O segment {segment_name}")
                regions.append(_Region(segment_name or f"segment_{index}", file_offset, file_size,
                                       address, memory_size))
            for section_index in range(section_count):
                section = cursor + 56 + section_index * 68
                section_name = data[section:section + 16].split(b"\0", 1)[0].decode("ascii", "replace")
                section_segment = data[section + 16:section + 32].split(b"\0", 1)[0].decode("ascii", "replace")
                section_names.extend(filter(None, (section_name, f"{section_segment},{section_name}")))
        elif command == 0x2:
            if size < 24:
                raise NativeAotError("truncated LC_SYMTAB")
            symtab = _unpack(data, endian, "IIII", cursor + 8, "Mach-O symbol table")
        elif command == 0x80000034:
            if size < 16:
                raise NativeAotError("truncated LC_DYLD_CHAINED_FIXUPS")
            chained = _unpack(data, endian, "II", cursor + 8, "Mach-O chained-fixup command")
        cursor += size
    if cursor != command_end or not regions:
        raise NativeAotError("invalid Mach-O command extent or no file-backed segment")
    image_base = min(region.address - region.file_offset for region in regions)
    image = _Image(data, "Mach-O", bits, endian, _CPU_MACHO.get(cpu_type, f"cpu_{cpu_type:#x}"),
                   image_base, regions, section_names, [], {"segments": all_segments})
    if chained is not None:
        _parse_macho_chains(image, chained)
    if symtab is not None:
        _parse_macho_symbols(image, symtab)
    return image


def _parse_macho_chains(image: _Image, command: tuple[int, int]) -> None:
    data_offset, data_size = command
    if data_size < 28:
        raise NativeAotError("Mach-O chained-fixup data is truncated")
    _span(image.data, data_offset, data_size, "Mach-O chained-fixup data")
    _version, starts_offset, _imports, _symbols, _count, _import_fmt, _symbol_fmt = _unpack(
        image.data, image.endian, "IIIIIII", data_offset, "Mach-O chained-fixup header",
    )
    starts = data_offset + starts_offset
    if starts < data_offset or starts > data_offset + data_size - 4:
        raise NativeAotError("Mach-O chained starts point outside fixup data")
    segment_count = _unpack(image.data, image.endian, "I", starts, "Mach-O chained segment count")[0]
    segments = image.metadata["segments"]
    if segment_count > len(segments) or segment_count > MAX_REGIONS:
        raise NativeAotError("Mach-O chained segment count is invalid")
    _span(image.data, starts + 4, segment_count * 4, "Mach-O chained segment offsets")
    for index in range(segment_count):
        relative = _unpack(image.data, image.endian, "I", starts + 4 + index * 4,
                           "Mach-O chained segment offset")[0]
        if not relative:
            continue
        info = starts + relative
        _span(image.data, info, 22, "Mach-O chained segment info")
        size, page_size, pointer_format = _unpack(
            image.data, image.endian, "IHH", info, "Mach-O chained segment info",
        )
        segment_offset = _unpack(image.data, image.endian, "Q", info + 8,
                                 "Mach-O chained segment file offset")[0]
        page_count = _unpack(image.data, image.endian, "H", info + 20,
                             "Mach-O chained page count")[0]
        starts_table = info + 22
        if not page_size or size < 22 + page_count * 2 or info + size > data_offset + data_size:
            raise NativeAotError("Mach-O chained page table is truncated")
        file_offset, file_size, _address, _memory_size, _name = segments[index]
        if file_size:
            image.chain_formats.append((file_offset, file_size, pointer_format))
        if pointer_format not in (2, 6):
            continue

        def starts_for_page(value: int) -> list[int]:
            if value == 0xFFFF:
                return []
            if not value & 0x8000:
                return [value]
            result: list[int] = []
            overflow_index = value & 0x7FFF
            for _ in range(4096):
                overflow_offset = starts_table + overflow_index * 2
                if overflow_offset + 2 > info + size:
                    raise NativeAotError("Mach-O chained multi-start table is truncated")
                item = _unpack(image.data, image.endian, "H", overflow_offset,
                               "Mach-O chained multi-start")[0]
                result.append(item & 0x7FFF)
                overflow_index += 1
                if item & 0x8000:
                    return result
            raise NativeAotError("Mach-O chained multi-start count exceeds cap")

        for page_index in range(page_count):
            page_start = _unpack(image.data, image.endian, "H", starts_table + page_index * 2,
                                  "Mach-O chained page start")[0]
            for within_page in starts_for_page(page_start):
                slot = segment_offset + page_index * page_size + within_page
                page_end = segment_offset + (page_index + 1) * page_size
                for _ in range(page_size // 4 + 1):
                    if slot < file_offset or slot + 8 > file_offset + file_size or slot + 8 > page_end:
                        raise NativeAotError("Mach-O chained pointer leaves its segment page")
                    raw = _unpack(image.data, image.endian, "Q", slot,
                                  "Mach-O chained pointer")[0]
                    image.chain_slots[slot] = pointer_format
                    next_delta = (raw >> 51) & 0xFFF
                    if not next_delta:
                        break
                    slot += next_delta * 4
                else:
                    raise NativeAotError("Mach-O chained pointer count exceeds page cap")


def _parse_macho_symbols(image: _Image, symtab: tuple[int, int, int, int]) -> None:
    symbol_offset, symbol_count, string_offset, string_size = symtab
    if symbol_count > MAX_SYMBOLS:
        raise NativeAotError("Mach-O symbol count exceeds cap")
    entry_size = 16 if image.bits == 64 else 12
    _span(image.data, symbol_offset, symbol_count * entry_size, "Mach-O symbol table")
    _span(image.data, string_offset, string_size, "Mach-O string table")
    seen: set[str] = set()
    for index in range(symbol_count):
        offset = symbol_offset + index * entry_size
        name_index = _unpack(image.data, image.endian, "I", offset, "Mach-O symbol name")[0]
        name = (_cstring(image.data, string_offset + name_index, string_size - name_index)
                if name_index < string_size else None)
        _append_symbol(image.symbols, seen, name)


def _parse_container(data: bytes) -> _Image | None:
    if data.startswith(b"MZ"):
        return _parse_pe(data)
    if data.startswith(b"\x7fELF"):
        return _parse_elf(data)
    if data[:4] in {b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf",
                    b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xce"}:
        return _parse_macho(data)
    return None


def _parse_cli_header(image: _Image) -> dict | None:
    if image.kind != "PE":
        return None
    rva, size = image.metadata["directories"].get(14, (0, 0))
    if not rva and not size:
        return None
    if not rva or size < 72:
        raise NativeAotError("invalid PE CLI data directory")
    offset = image.rva_to_offset(rva, 72)
    if offset is None:
        raise NativeAotError("PE CLI header is not file-backed")
    cb, major, minor = _unpack(image.data, "<", "IHH", offset, "CLI header")
    if cb < 72 or cb > size or major == 0:
        raise NativeAotError("invalid CLI header size or version")
    metadata_rva, metadata_size = _unpack(image.data, "<", "II", offset + 8, "CLI metadata directory")
    flags, entrypoint = _unpack(image.data, "<", "II", offset + 16, "CLI flags")
    if metadata_size < 16:
        raise NativeAotError("CLI metadata directory is too small")
    metadata_offset = image.rva_to_offset(metadata_rva, metadata_size)
    if metadata_offset is None or image.data[metadata_offset:metadata_offset + 4] != b"BSJB":
        raise NativeAotError("CLI metadata root is missing or malformed")
    native_rva, native_size = _unpack(image.data, "<", "II", offset + 64,
                                     "CLI managed-native directory")
    if bool(native_rva) != bool(native_size):
        raise NativeAotError("incomplete CLI managed-native directory")
    native_offset = None
    if native_rva:
        native_offset = image.rva_to_offset(native_rva, native_size)
        if native_offset is None:
            raise NativeAotError("CLI managed-native directory is not file-backed")
    return {
        "file_offset": offset,
        "rva": rva,
        "size": cb,
        "runtime_version": f"{major}.{minor}",
        "flags": flags,
        "entrypoint": entrypoint,
        "metadata": {"rva": metadata_rva, "size": metadata_size,
                     "file_offset": metadata_offset, "signature": "BSJB"},
        "managed_native_header": ({"rva": native_rva, "size": native_size,
                                   "file_offset": native_offset} if native_rva else None),
    }


def _flag_names(flags: int) -> list[str]:
    return [name for bit, name in CORE_RTR_FLAGS.items() if flags & bit]


def _header_location(image: _Image, offset: int) -> dict:
    row = {"file_offset": offset}
    address = image.offset_to_address(offset)
    if address is not None:
        row["virtual_address"] = image.image_base + address if image.kind == "PE" else address
        rva = address if image.kind == "PE" else address - image.image_base
        if rva >= 0:
            row["rva"] = rva
    return row


def _parse_core_rtr(image: _Image, offset: int, source: str,
                    directory_size: int | None = None) -> dict:
    data = image.data
    _span(data, offset, 16, "ReadyToRun header")
    signature, major, minor, flags, count = _unpack(data, "<", "IHHII", offset,
                                                   "ReadyToRun header")
    if signature != 0x00525452:
        raise NativeAotError("ReadyToRun signature mismatch")
    if not 1 <= major <= 64 or flags & ~0x00003FFF or not 1 <= count <= MAX_RTR_SECTIONS:
        raise NativeAotError("implausible ReadyToRun header fields")
    total = 16 + count * 12
    if directory_size is not None and total > directory_size:
        raise NativeAotError("ReadyToRun directory exceeds CLI declaration")
    _span(data, offset, total, "ReadyToRun section directory")
    sections: list[dict] = []
    previous = -1
    recognized = 0
    nonempty = 0
    for index in range(count):
        section_type, rva, size = _unpack(data, "<", "III", offset + 16 + index * 12,
                                         "ReadyToRun section entry")
        if not 100 <= section_type < 200 or section_type <= previous or rva == 0:
            raise NativeAotError("invalid or unsorted ReadyToRun section directory")
        previous = section_type
        recognized += section_type in CORE_RTR_SECTIONS
        nonempty += size > 0
        file_offset = image.rva_to_offset(rva, size)
        if file_offset is None:
            raise NativeAotError("ReadyToRun section is not fully file-backed")
        row = {"type": section_type,
               "name": CORE_RTR_SECTIONS.get(section_type, f"Unknown_{section_type}"),
               "rva": rva, "size": size, "file_offset": file_offset}
        if section_type == 100:
            if not size:
                raise NativeAotError("ReadyToRun compiler identifier is empty")
            raw_compiler = data[file_offset:file_offset + min(size, 4096)].rstrip(b"\0")
            try:
                compiler = raw_compiler.decode("ascii")
            except UnicodeDecodeError as exc:
                raise NativeAotError("ReadyToRun compiler identifier is not ASCII") from exc
            if not compiler or any(ord(char) < 0x20 or ord(char) > 0x7E for char in compiler):
                raise NativeAotError("ReadyToRun compiler identifier is malformed")
            row["compiler_identifier"] = compiler
        sections.append(row)
    if not recognized or not nonempty:
        raise NativeAotError("ReadyToRun directory has no recognized non-empty sections")
    report = {"kind": "coreclr_readytorun", "source": source, "major_version": major,
              "minor_version": minor, "flags": flags, "flag_names": _flag_names(flags),
              "directory_size": total, "section_count": count, "sections": sections}
    report.update(_header_location(image, offset))
    return report


def _native_section_name(section_type: int) -> str:
    if section_type in NATIVE_RTR_SECTIONS:
        return NATIVE_RTR_SECTIONS[section_type]
    if 300 <= section_type < 400:
        return f"ReflectionMap.Unknown_{section_type - 300}"
    return f"Unknown_{section_type}"


def _parse_native_rtr(image: _Image, offset: int, source: str) -> dict:
    data = image.data
    _span(data, offset, 16, "NativeAOT ReadyToRun header")
    signature, major, minor, flags, count, entry_size, entry_type = _unpack(
        data, "<", "IHHIHBB", offset, "NativeAOT ReadyToRun header",
    )
    legacy_entry_size = 8 + 2 * image.pointer_size  # type, flags, start, optional end
    compact_entry_size = 8 + image.pointer_size    # type, byte size, start
    allowed_sizes = {legacy_entry_size, compact_entry_size}
    if signature != 0x00525452 or not 1 <= major <= 64 or flags & ~0x00003FFF:
        raise NativeAotError("implausible NativeAOT ReadyToRun header")
    if not 1 <= count <= MAX_RTR_SECTIONS or entry_type != 1 or entry_size not in allowed_sizes:
        raise NativeAotError("unsupported NativeAOT ReadyToRun directory layout")
    total = 16 + count * entry_size
    _span(data, offset, total, "NativeAOT ReadyToRun directory")
    sections: list[dict] = []
    previous = -1
    recognized = 0
    for index in range(count):
        entry = offset + 16 + index * entry_size
        section_type = _unpack(data, image.endian, "I", entry, "NativeAOT section type")[0]
        if not (200 <= section_type < 400) or section_type <= previous:
            raise NativeAotError("invalid or unsorted NativeAOT section directory")
        previous = section_type
        recognized += section_type in NATIVE_RTR_SECTIONS
        legacy_layout = entry_size == legacy_entry_size
        if legacy_layout:
            entry_flags = _unpack(data, image.endian, "I", entry + 4,
                                  "NativeAOT section flags")[0]
            if entry_flags & ~1:
                raise NativeAotError("unsupported NativeAOT section-entry flags")
            pointer_code = "Q" if image.pointer_size == 8 else "I"
            start_raw, end_raw = _unpack(data, image.endian, pointer_code * 2, entry + 8,
                                         "NativeAOT section pointers")
            start = image.resolve_pointer(start_raw, entry + 8, 0)
            if start is None:
                raise NativeAotError("NativeAOT section start pointer is unmapped")
            if entry_flags & 1:
                if not end_raw:
                    raise NativeAotError("NativeAOT sized section has no end pointer")
                end = image.resolve_pointer(end_raw, entry + 8 + image.pointer_size, 0)
                if end is None or end[0] < start[0]:
                    raise NativeAotError("NativeAOT section end pointer is invalid")
                size = end[0] - start[0]
                if not image.address_in_memory(start[0] - image.image_base if image.kind == "PE"
                                               else start[0], size):
                    raise NativeAotError("NativeAOT section crosses an image mapping")
            else:
                if end_raw:
                    raise NativeAotError("NativeAOT unsized section has an end pointer")
                size = 0
        elif image.pointer_size == 8:
            size, start_raw = _unpack(data, image.endian, "IQ", entry + 4,
                                      "NativeAOT section entry")
            start = image.resolve_pointer(start_raw, entry + 8, size)
            if start is None:
                raise NativeAotError("NativeAOT section pointer is unmapped")
        else:
            size, start_raw = _unpack(data, image.endian, "II", entry + 4,
                                      "NativeAOT section entry")
            start = image.resolve_pointer(start_raw, entry + 8, size)
            if start is None:
                raise NativeAotError("NativeAOT section pointer is unmapped")
        address, file_offset, encoding = start
        row = {"type": section_type, "name": _native_section_name(section_type),
               "size": size, "virtual_address": address, "file_offset": file_offset,
               "file_backed_size": image.file_backed_prefix(
                   address - image.image_base if image.kind == "PE" else address, size,
               ), "pointer_encoding": encoding}
        if legacy_layout:
            row["entry_flags"] = entry_flags
            row["flag_names"] = ["HasEndPointer"] if entry_flags & 1 else []
        row["fully_file_backed"] = row["file_backed_size"] == size
        if address >= image.image_base:
            row["rva"] = address - image.image_base
        sections.append(row)
    if not recognized:
        raise NativeAotError("NativeAOT directory has no recognized section types")
    report = {"kind": "nativeaot", "source": source, "major_version": major,
              "minor_version": minor, "flags": flags, "entry_size": entry_size,
              "entry_type": entry_type, "directory_size": total,
              "section_count": count, "sections": sections}
    report.update(_header_location(image, offset))
    return report


_RUNTIME_MARKERS = {
    b"RhpNewFast": ("RhpNewFast", "strong"),
    b"RhpNewArray": ("RhpNewArray", "strong"),
    b"RhpAssignRef": ("RhpAssignRef", "strong"),
    b"RhpCidResolve": ("RhpCidResolve", "medium"),
    b"RhpReversePInvoke": ("RhpReversePInvoke", "strong"),
    b"DotNetRuntimeDebugHeader": ("DotNetRuntimeDebugHeader", "strong"),
    b"__ReadyToRunHeader": ("__ReadyToRunHeader", "strong"),
    b"__managedcode": ("__managedcode", "strong"),
    b"__modules_a": ("__modules_a", "strong"),
    b"S_P_CoreLib_": ("S_P_CoreLib_", "strong"),
    b"System.Private.CoreLib": ("System.Private.CoreLib", "medium"),
    b"System.Private.Reflection.Execution": ("System.Private.Reflection.Execution", "medium"),
    b"ReadyToRunSectionType": ("ReadyToRunSectionType", "medium"),
}
_SECTION_MARKERS = {"__managedcode", ".managedcode", "__modules", ".modules",
                    ".dotnet_eh_table", "hydrated"}
_SYMBOL_RE = re.compile(r"(?:Rhp|Rh[A-Z]|ReadyToRun|managedcode|modules|DotNetRuntime|S_P_CoreLib|CoreLib)")


def _marker_inventory(image: _Image) -> dict:
    hits: list[dict] = []
    seen: set[tuple[str, str, int | str]] = set()
    for marker, (name, strength) in _RUNTIME_MARKERS.items():
        cursor = 0
        for _ in range(4):
            offset = image.data.find(marker, cursor)
            if offset < 0:
                break
            key = ("string", name, offset)
            if key not in seen:
                hits.append({"kind": "string", "name": name, "strength": strength,
                             "file_offset": offset})
                seen.add(key)
            cursor = offset + 1
    for section in image.section_names:
        leaf = section.rsplit(",", 1)[-1]
        if leaf in _SECTION_MARKERS:
            key = ("section", leaf, section)
            if key not in seen:
                hits.append({"kind": "section", "name": section, "strength": "strong"})
                seen.add(key)
    relevant_symbols = []
    for symbol in image.symbols:
        if _SYMBOL_RE.search(symbol):
            relevant_symbols.append(symbol)
            strength = "strong" if re.search(r"Rhp|ReadyToRun|DotNetRuntime|managedcode|modules", symbol) else "medium"
            key = ("symbol", symbol, symbol)
            if key not in seen:
                hits.append({"kind": "symbol", "name": symbol, "strength": strength})
                seen.add(key)
    strong = sum(row["strength"] == "strong" for row in hits)
    medium = sum(row["strength"] == "medium" for row in hits)
    return {"score": strong * 3 + medium, "strong_count": strong, "medium_count": medium,
            "markers": hits[:256], "symbols": relevant_symbols[:256]}


_ASCII_RE = re.compile(rb"[\x20-\x7e]{5,256}")
_UTF16LE_RE = re.compile(rb"(?:[\x20-\x7e]\x00){5,128}")
_UTF16BE_RE = re.compile(rb"(?:\x00[\x20-\x7e]){5,128}")


def _string_score(value: str) -> int:
    score = min(len(value), 80)
    if flagfmt.PACKED_TEXT.search(value):     # a string carved from the binary (R-16)
        score += 1000
    if _SYMBOL_RE.search(value) or "System.Private" in value:
        score += 250
    if re.search(r"[A-Z][A-Z0-9_]{7,}", value):
        score += 180
    if ".dll" in value or ".exe" in value:
        score += 80
    return score


def _extract_strings(data: bytes) -> tuple[list[dict], bool]:
    scan = data[:MAX_STRING_SCAN]
    truncated = len(data) > len(scan)
    candidates: dict[tuple[str, str], dict] = {}
    match_count = 0
    for encoding, regex in (("ascii", _ASCII_RE), ("utf-16le", _UTF16LE_RE),
                            ("utf-16be", _UTF16BE_RE)):
        for match in regex.finditer(scan):
            match_count += 1
            if match_count > MAX_STRING_MATCHES:
                truncated = True
                break
            raw = match.group()
            try:
                value = raw.decode(encoding)
            except UnicodeError:
                continue
            key = (encoding, value)
            candidates.setdefault(key, {"file_offset": match.start(), "encoding": encoding,
                                        "value": value})
        if match_count > MAX_STRING_MATCHES:
            break
    ranked = sorted(candidates.values(), key=lambda row: (-_string_score(row["value"]),
                                                           row["file_offset"], row["encoding"]))
    if len(ranked) > MAX_REPORTED_STRINGS:
        truncated = True
    selected = ranked[:MAX_REPORTED_STRINGS]
    selected.sort(key=lambda row: (row["file_offset"], row["encoding"]))
    return selected, truncated


def _signature_offsets(data: bytes) -> tuple[list[int], bool]:
    offsets: list[int] = []
    cursor = 0
    while len(offsets) < MAX_RTR_CANDIDATES:
        offset = data.find(RTR_SIGNATURE, cursor)
        if offset < 0:
            return offsets, False
        offsets.append(offset)
        cursor = offset + 1
    return offsets, data.find(RTR_SIGNATURE, cursor) >= 0


def _try_header(parser, image: _Image, offset: int, source: str) -> dict | None:
    try:
        return parser(image, offset, source)
    except NativeAotError:
        return None


def _analyze(data: bytes, source_name: str | None) -> dict | None:
    if not isinstance(data, bytes):
        raise NativeAotError("input must be bytes")
    if not data:
        return None
    if len(data) > MAX_INPUT:
        raise NativeAotError("input exceeds size cap")
    image = _parse_container(data)
    if image is None:
        return None
    cli = _parse_cli_header(image)
    headers: list[dict] = []
    validated_offsets: set[int] = set()
    if cli and cli["managed_native_header"]:
        native = cli["managed_native_header"]
        offset = native["file_offset"]
        if data[offset:offset + 4] == RTR_SIGNATURE:
            header = _parse_core_rtr(image, offset, "cli_managed_native_header", native["size"])
            headers.append(header)
            validated_offsets.add(offset)
            native["validated_kind"] = "coreclr_readytorun"
        else:
            native["validated_kind"] = None

    signatures, signature_scan_truncated = _signature_offsets(data)
    for offset in signatures:
        if offset in validated_offsets:
            continue
        native_header = _try_header(_parse_native_rtr, image, offset, "signature_scan")
        if native_header is not None:
            headers.append(native_header)
            validated_offsets.add(offset)
            continue
        core_header = _try_header(_parse_core_rtr, image, offset, "signature_scan")
        if core_header is not None:
            headers.append(core_header)
            validated_offsets.add(offset)

    evidence = _marker_inventory(image)
    native_headers = [row for row in headers if row["kind"] == "nativeaot"]
    core_headers = [row for row in headers if row["kind"] == "coreclr_readytorun"]
    if native_headers and evidence["strong_count"] and evidence["score"] >= 3:
        classification, confidence = "nativeaot", "high"
        reason = "validated NativeAOT directory plus NativeAOT runtime/section evidence"
    elif core_headers:
        classification, confidence = "readytorun", "high"
        reason = "validated CoreCLR ReadyToRun section directory"
    elif cli:
        classification, confidence = "managed_il", "high"
        reason = "validated CLI header and BSJB metadata without a validated ReadyToRun directory"
    else:
        classification, confidence = "native", "high"
        reason = "valid native container without sufficient validated .NET native structure"
    strings, strings_truncated = _extract_strings(data)
    report = {
        "source": Path(source_name).name if source_name else None,
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "classification": classification,
        "confidence": confidence,
        "classification_reason": reason,
        "image": {"format": image.kind, "bits": image.bits, "endianness":
                  "little" if image.endian == "<" else "big",
                  "architecture": image.architecture, "image_base": image.image_base,
                  "regions": image.region_report(), "section_names": image.section_names[:MAX_SECTIONS]},
        "cli_header": cli,
        "readytorun_headers": headers,
        "rtr_signature_offsets": signatures,
        "unvalidated_rtr_signature_offsets": [row for row in signatures
                                               if row not in validated_offsets],
        "rtr_signature_scan_truncated": signature_scan_truncated,
        "nativeaot_evidence": evidence,
        "strings": strings,
        "strings_truncated": strings_truncated,
    }
    return report


def analyze(data: bytes, *, source_name: str | None = None) -> dict | None:
    """Return a bounded JSON-ready inventory, ``None``, or raise only ``NativeAotError``."""
    try:
        return _analyze(data, source_name)
    except NativeAotError:
        raise
    except (Exception, MemoryError) as exc:
        raise NativeAotError(f"analysis failed closed: {type(exc).__name__}") from exc


def analyze_file(path: str | Path) -> dict | None:
    """Read and analyze one artifact without loading or executing it."""
    try:
        file_path = Path(path)
        with file_path.open("rb") as handle:
            data = handle.read(MAX_INPUT + 1)
        if len(data) > MAX_INPUT:
            raise NativeAotError("input exceeds size cap")
        return analyze(data, source_name=str(file_path))
    except NativeAotError:
        raise
    except (OSError, TypeError, ValueError, MemoryError) as exc:
        raise NativeAotError(f"could not read input: {exc}") from exc


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Classify and inventory .NET IL, ReadyToRun, and NativeAOT binaries offline.",
    )
    parser.add_argument("input", help="PE, ELF, or thin Mach-O artifact")
    parser.add_argument("--pretty", action="store_true", help="indent JSON output")
    try:
        args = parser.parse_args(list(argv) if argv is not None else None)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        report = analyze_file(args.input)
        if report is None:
            raise NativeAotError("unsupported or unrecognized input container")
        print(json.dumps(report, sort_keys=True, indent=2 if args.pretty else None))
        return 0
    except NativeAotError as exc:
        print(f"redepth_nativeaot: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
