#!/usr/bin/env python3
"""Bounded, static Swift metadata recovery for thin Mach-O images.

The extractor reads Mach-O load commands, maps virtual addresses to file
offsets, inventories Swift symbols from ``LC_SYMTAB``, and follows the signed
32-bit relative pointers in ``__swift5_types`` and the referenced reflection
field descriptors.  It never imports, loads, or executes the target image.

The primary API is :func:`extract_swift_metadata`.  :func:`parse_macho`
exposes the validated container and its :meth:`MachOImage.va_to_file_offset`
mapping for callers that need to inspect another Swift metadata record.
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import struct
import sys
from pathlib import Path
from typing import Any


MAX_INPUT = 512 << 20
MAX_LOAD_COMMANDS = 4096
MAX_LOAD_COMMAND_BYTES = 32 << 20
MAX_SECTIONS = 16384
MAX_SYMBOLS = 1_000_000
MAX_TYPES = 200_000
MAX_FIELDS = 1_000_000
MAX_FIELDS_PER_TYPE = 100_000
MAX_NAME = 4096
MAX_MANGLED_NAME = 65536

LC_SEGMENT = 0x1
LC_SYMTAB = 0x2
LC_SEGMENT_64 = 0x19

_MACHO_MAGICS = {
    b"\xce\xfa\xed\xfe": (32, "<"),
    b"\xcf\xfa\xed\xfe": (64, "<"),
    b"\xfe\xed\xfa\xce": (32, ">"),
    b"\xfe\xed\xfa\xcf": (64, ">"),
}

_CONTEXT_KINDS = {
    0: "module",
    1: "extension",
    2: "anonymous",
    3: "protocol",
    4: "opaque_type",
    16: "class",
    17: "struct",
    18: "enum",
}

_FIELD_DESCRIPTOR_KINDS = {
    0: "struct",
    1: "class",
    2: "enum",
    3: "multi_payload_enum",
    4: "protocol",
    5: "class_protocol",
    6: "objc_protocol",
    7: "objc_class",
}

_ZEROFILL_SECTION_TYPES = {0x1, 0x0C, 0x12}


class SwiftMetadataError(ValueError):
    """The input claims to be relevant Mach-O/Swift data but is malformed."""


def _checked_end(start: int, size: int, limit: int, what: str) -> int:
    if not isinstance(start, int) or not isinstance(size, int):
        raise SwiftMetadataError(f"invalid {what} range")
    if start < 0 or size < 0 or start > limit or size > limit - start:
        raise SwiftMetadataError(f"{what} runs outside the input")
    return start + size


class _Reader:
    def __init__(self, data: bytes, endian: str):
        self.data = data
        self.endian = endian

    def raw(self, offset: int, size: int, what: str) -> bytes:
        end = _checked_end(offset, size, len(self.data), what)
        return self.data[offset:end]

    def unpack(self, fmt: str, offset: int, what: str) -> tuple[Any, ...]:
        size = struct.calcsize(self.endian + fmt)
        _checked_end(offset, size, len(self.data), what)
        return struct.unpack_from(self.endian + fmt, self.data, offset)

    def u16(self, offset: int, what: str) -> int:
        return self.unpack("H", offset, what)[0]

    def u32(self, offset: int, what: str) -> int:
        return self.unpack("I", offset, what)[0]

    def i32(self, offset: int, what: str) -> int:
        return self.unpack("i", offset, what)[0]

    def u64(self, offset: int, what: str) -> int:
        return self.unpack("Q", offset, what)[0]

    def fixed_name(self, offset: int, what: str) -> str:
        raw = self.raw(offset, 16, what)
        nul = raw.find(b"\0")
        if nul >= 0:
            if any(raw[nul + 1:]):
                raise SwiftMetadataError(f"{what} has nonzero bytes after its terminator")
            raw = raw[:nul]
        try:
            return raw.decode("ascii")
        except UnicodeDecodeError as exc:
            raise SwiftMetadataError(f"{what} is not ASCII") from exc

    def file_cstring(self, offset: int, limit: int, what: str) -> str:
        if offset < 0 or offset >= len(self.data):
            raise SwiftMetadataError(f"{what} starts outside the input")
        stop = min(len(self.data), offset + limit + 1)
        end = self.data.find(b"\0", offset, stop)
        if end < 0:
            raise SwiftMetadataError(f"{what} is unterminated or exceeds its size cap")
        try:
            return self.data[offset:end].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SwiftMetadataError(f"{what} is not UTF-8") from exc


@dataclasses.dataclass(frozen=True)
class Section:
    segment: str
    name: str
    address: int
    size: int
    file_offset: int
    align: int
    flags: int

    @property
    def file_backed(self) -> bool:
        return (self.flags & 0xFF) not in _ZEROFILL_SECTION_TYPES

    def report(self) -> dict[str, Any]:
        return {
            "segment": self.segment,
            "name": self.name,
            "address": self.address,
            "size": self.size,
            "file_offset": self.file_offset,
            "align": self.align,
            "flags": self.flags,
        }


@dataclasses.dataclass(frozen=True)
class Segment:
    name: str
    vm_address: int
    vm_size: int
    file_offset: int
    file_size: int
    max_protection: int
    initial_protection: int
    flags: int
    section_count: int

    def report(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "vm_address": self.vm_address,
            "vm_size": self.vm_size,
            "file_offset": self.file_offset,
            "file_size": self.file_size,
            "max_protection": self.max_protection,
            "initial_protection": self.initial_protection,
            "flags": self.flags,
            "section_count": self.section_count,
        }


@dataclasses.dataclass(frozen=True)
class LoadCommand:
    command: int
    size: int
    file_offset: int

    def report(self) -> dict[str, int]:
        return {"command": self.command, "size": self.size,
                "file_offset": self.file_offset}


@dataclasses.dataclass(frozen=True)
class Symtab:
    symbol_offset: int
    symbol_count: int
    string_offset: int
    string_size: int


@dataclasses.dataclass
class MachOImage:
    """A validated thin Mach-O image and its file-backed VA mappings."""

    data: bytes
    bits: int
    endian: str
    cpu_type: int
    cpu_subtype: int
    file_type: int
    flags: int
    load_commands: list[LoadCommand]
    segments: list[Segment]
    sections: list[Section]
    symtab: Symtab | None

    @property
    def byte_order(self) -> str:
        return "little" if self.endian == "<" else "big"

    @property
    def pointer_size(self) -> int:
        return self.bits // 8

    def va_to_file_offset(self, virtual_address: int, size: int = 1) -> int:
        """Map one wholly file-backed virtual range, failing on ambiguity."""
        if (not isinstance(virtual_address, int) or isinstance(virtual_address, bool)
                or not isinstance(size, int) or isinstance(size, bool) or size < 0
                or virtual_address < 0):
            raise SwiftMetadataError("virtual address and size must be nonnegative integers")
        max_address = 1 << self.bits
        if virtual_address >= max_address or size > max_address - virtual_address:
            raise SwiftMetadataError("virtual address range exceeds the Mach-O address width")

        section_matches: list[int] = []
        for section in self.sections:
            if not section.file_backed:
                continue
            if (virtual_address >= section.address
                    and size <= section.size
                    and virtual_address - section.address <= section.size - size):
                offset = section.file_offset + virtual_address - section.address
                _checked_end(offset, size, len(self.data), "mapped section range")
                section_matches.append(offset)
        if section_matches:
            if any(value != section_matches[0] for value in section_matches[1:]):
                raise SwiftMetadataError("virtual address has ambiguous section mappings")
            return section_matches[0]

        segment_matches: list[int] = []
        for segment in self.segments:
            if (virtual_address >= segment.vm_address
                    and size <= segment.file_size
                    and virtual_address - segment.vm_address <= segment.file_size - size):
                offset = segment.file_offset + virtual_address - segment.vm_address
                _checked_end(offset, size, len(self.data), "mapped segment range")
                segment_matches.append(offset)
        if not segment_matches:
            raise SwiftMetadataError(
                f"virtual address 0x{virtual_address:x} is not wholly file-backed")
        if any(value != segment_matches[0] for value in segment_matches[1:]):
            raise SwiftMetadataError("virtual address has ambiguous segment mappings")
        return segment_matches[0]


def _parse_segment(reader: _Reader, bits: int, command_offset: int,
                   command_size: int, section_total: int) -> tuple[Segment, list[Section]]:
    wide = bits == 64
    expected_command = LC_SEGMENT_64 if wide else LC_SEGMENT
    command = reader.u32(command_offset, "segment command")
    if command != expected_command:
        raise SwiftMetadataError("segment command width disagrees with the Mach-O header")
    fixed_size, section_size = (72, 80) if wide else (56, 68)
    if command_size < fixed_size:
        raise SwiftMetadataError("segment load command is truncated")
    segment_name = reader.fixed_name(command_offset + 8, "segment name")
    if wide:
        vm_address = reader.u64(command_offset + 24, "segment VM address")
        vm_size = reader.u64(command_offset + 32, "segment VM size")
        file_offset = reader.u64(command_offset + 40, "segment file offset")
        file_size = reader.u64(command_offset + 48, "segment file size")
        max_protection = reader.u32(command_offset + 56, "segment maximum protection")
        initial_protection = reader.u32(command_offset + 60, "segment initial protection")
        section_count = reader.u32(command_offset + 64, "segment section count")
        flags = reader.u32(command_offset + 68, "segment flags")
    else:
        vm_address = reader.u32(command_offset + 24, "segment VM address")
        vm_size = reader.u32(command_offset + 28, "segment VM size")
        file_offset = reader.u32(command_offset + 32, "segment file offset")
        file_size = reader.u32(command_offset + 36, "segment file size")
        max_protection = reader.u32(command_offset + 40, "segment maximum protection")
        initial_protection = reader.u32(command_offset + 44, "segment initial protection")
        section_count = reader.u32(command_offset + 48, "segment section count")
        flags = reader.u32(command_offset + 52, "segment flags")

    if section_count > MAX_SECTIONS or section_total > MAX_SECTIONS - section_count:
        raise SwiftMetadataError("Mach-O exceeds the section count cap")
    required = fixed_size + section_count * section_size
    if command_size != required:
        raise SwiftMetadataError("segment command size does not match its section table")
    _checked_end(file_offset, file_size, len(reader.data), "segment file range")
    address_limit = 1 << bits
    if vm_address >= address_limit or vm_size > address_limit - vm_address:
        raise SwiftMetadataError("segment virtual range exceeds the address width")

    sections: list[Section] = []
    for index in range(section_count):
        offset = command_offset + fixed_size + index * section_size
        name = reader.fixed_name(offset, "section name")
        owner = reader.fixed_name(offset + 16, "section segment name")
        if wide:
            address = reader.u64(offset + 32, "section address")
            size = reader.u64(offset + 40, "section size")
            file_at = reader.u32(offset + 48, "section file offset")
            align = reader.u32(offset + 52, "section alignment")
            section_flags = reader.u32(offset + 64, "section flags")
        else:
            address = reader.u32(offset + 32, "section address")
            size = reader.u32(offset + 36, "section size")
            file_at = reader.u32(offset + 40, "section file offset")
            align = reader.u32(offset + 44, "section alignment")
            section_flags = reader.u32(offset + 56, "section flags")
        if address >= address_limit or size > address_limit - address:
            raise SwiftMetadataError("section virtual range exceeds the address width")
        if align > 63:
            raise SwiftMetadataError("section alignment exponent exceeds its bound")
        section = Section(owner, name, address, size, file_at, align, section_flags)
        if section.file_backed:
            _checked_end(file_at, size, len(reader.data), "section file range")
        sections.append(section)
    return (Segment(segment_name, vm_address, vm_size, file_offset, file_size,
                    max_protection, initial_protection, flags, section_count), sections)


def _parse_macho(data: bytes) -> MachOImage | None:
    if len(data) < 4 or data[:4] not in _MACHO_MAGICS:
        return None
    bits, endian = _MACHO_MAGICS[data[:4]]
    header_size = 32 if bits == 64 else 28
    if len(data) < header_size:
        raise SwiftMetadataError("thin Mach-O header is truncated")
    reader = _Reader(data, endian)
    cpu_type = reader.u32(4, "CPU type")
    cpu_subtype = reader.u32(8, "CPU subtype")
    file_type = reader.u32(12, "Mach-O file type")
    command_count = reader.u32(16, "load command count")
    command_bytes = reader.u32(20, "load command byte count")
    flags = reader.u32(24, "Mach-O flags")
    if command_count > MAX_LOAD_COMMANDS:
        raise SwiftMetadataError("Mach-O exceeds the load command count cap")
    if command_bytes > MAX_LOAD_COMMAND_BYTES:
        raise SwiftMetadataError("Mach-O exceeds the load command byte cap")
    command_end = _checked_end(header_size, command_bytes, len(data), "load command table")

    commands: list[LoadCommand] = []
    segments: list[Segment] = []
    sections: list[Section] = []
    symtab: Symtab | None = None
    cursor = header_size
    alignment = 8 if bits == 64 else 4
    for _ in range(command_count):
        if cursor + 8 > command_end:
            raise SwiftMetadataError("load command header is truncated")
        command, command_size = reader.unpack("II", cursor, "load command header")
        if command_size < 8 or command_size % alignment:
            raise SwiftMetadataError("load command has an invalid size/alignment")
        if command_size > command_end - cursor:
            raise SwiftMetadataError("load command runs past the declared table")
        commands.append(LoadCommand(command, command_size, cursor))
        if command in (LC_SEGMENT, LC_SEGMENT_64):
            segment, new_sections = _parse_segment(
                reader, bits, cursor, command_size, len(sections))
            segments.append(segment)
            sections.extend(new_sections)
        elif command == LC_SYMTAB:
            if symtab is not None:
                raise SwiftMetadataError("Mach-O contains more than one LC_SYMTAB")
            if command_size != 24:
                raise SwiftMetadataError("LC_SYMTAB has an invalid size")
            symbol_offset, symbol_count, string_offset, string_size = reader.unpack(
                "IIII", cursor + 8, "LC_SYMTAB body")
            if symbol_count > MAX_SYMBOLS:
                raise SwiftMetadataError("Mach-O exceeds the symbol count cap")
            entry_size = 16 if bits == 64 else 12
            _checked_end(symbol_offset, symbol_count * entry_size, len(data), "symbol table")
            _checked_end(string_offset, string_size, len(data), "symbol string table")
            symtab = Symtab(symbol_offset, symbol_count, string_offset, string_size)
        cursor += command_size
    if cursor != command_end:
        raise SwiftMetadataError("load commands do not consume sizeofcmds exactly")
    return MachOImage(data, bits, endian, cpu_type, cpu_subtype, file_type, flags,
                      commands, segments, sections, symtab)


def _normalize_input(data: bytes | bytearray | memoryview) -> bytes:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise SwiftMetadataError("input must be bytes-like")
    value = data if isinstance(data, bytes) else bytes(data)
    if len(value) > MAX_INPUT:
        raise SwiftMetadataError("input exceeds the size cap")
    return value


def parse_macho(data: bytes | bytearray | memoryview) -> MachOImage | None:
    """Parse one thin Mach-O, returning ``None`` for another file format."""
    try:
        return _parse_macho(_normalize_input(data))
    except SwiftMetadataError:
        raise
    except Exception as exc:  # Public malformed-input boundary.
        raise SwiftMetadataError("unexpected failure while parsing Mach-O") from exc


def _swift_symbols(image: MachOImage) -> list[dict[str, Any]]:
    table = image.symtab
    if table is None:
        return []
    reader = _Reader(image.data, image.endian)
    entry_size = 16 if image.bits == 64 else 12
    output: list[dict[str, Any]] = []
    string_end = table.string_offset + table.string_size
    for index in range(table.symbol_count):
        at = table.symbol_offset + index * entry_size
        string_index = reader.u32(at, "symbol string index")
        symbol_type = image.data[at + 4]
        section_index = image.data[at + 5]
        description = reader.u16(at + 6, "symbol description")
        value = (reader.u64(at + 8, "symbol value") if image.bits == 64
                 else reader.u32(at + 8, "symbol value"))
        if string_index == 0:
            continue
        if string_index >= table.string_size:
            raise SwiftMetadataError("symbol name index runs outside the string table")
        name_at = table.string_offset + string_index
        end = image.data.find(b"\0", name_at, string_end)
        if end < 0:
            raise SwiftMetadataError("symbol name is unterminated")
        if end - name_at > MAX_NAME:
            raise SwiftMetadataError("symbol name exceeds the size cap")
        try:
            raw_name = image.data[name_at:end].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SwiftMetadataError("symbol name is not UTF-8") from exc

        normalized = raw_name
        if raw_name.startswith("_$s") or raw_name.startswith("_$S"):
            normalized = raw_name[1:]
        elif raw_name.startswith("__T"):
            normalized = raw_name[1:]
        if normalized.startswith("$s"):
            scheme = "swift5"
        elif normalized.startswith("$S") or normalized.startswith("_T0"):
            scheme = "swift4"
        elif normalized.startswith("_T"):
            scheme = "legacy"
        else:
            continue
        output.append({
            "index": index,
            "raw": raw_name,
            "normalized": normalized,
            "scheme": scheme,
            "type": symbol_type,
            "section": section_index,
            "description": description,
            "value": value,
        })
    return output


class _SwiftReader:
    def __init__(self, image: MachOImage):
        self.image = image
        self.reader = _Reader(image.data, image.endian)
        self.field_total = 0

    def offset(self, virtual_address: int, size: int, what: str) -> int:
        try:
            return self.image.va_to_file_offset(virtual_address, size)
        except SwiftMetadataError as exc:
            raise SwiftMetadataError(f"{what}: {exc}") from exc

    def u16(self, virtual_address: int, what: str) -> int:
        return self.reader.u16(self.offset(virtual_address, 2, what), what)

    def u32(self, virtual_address: int, what: str) -> int:
        return self.reader.u32(self.offset(virtual_address, 4, what), what)

    def i32(self, virtual_address: int, what: str) -> int:
        return self.reader.i32(self.offset(virtual_address, 4, what), what)

    def pointer(self, virtual_address: int, what: str) -> int:
        offset = self.offset(virtual_address, self.image.pointer_size, what)
        if self.image.pointer_size == 8:
            return self.reader.u64(offset, what)
        return self.reader.u32(offset, what)

    def relative(self, field_address: int, what: str, *, nullable: bool,
                 indirectable: bool = False) -> int | None:
        relative = self.i32(field_address, what)
        if relative == 0:
            if nullable:
                return None
            raise SwiftMetadataError(f"{what} is unexpectedly null")
        indirect = indirectable and bool(relative & 1)
        displacement = relative & ~1 if indirectable else relative
        target = field_address + displacement
        maximum = 1 << self.image.bits
        if target < 0 or target >= maximum:
            raise SwiftMetadataError(f"{what} overflows the Mach-O address width")
        if indirect:
            target = self.pointer(target, f"{what} indirect slot")
            if target == 0:
                if nullable:
                    return None
                raise SwiftMetadataError(f"{what} indirect slot is null")
            if target >= maximum:
                raise SwiftMetadataError(f"{what} indirect target exceeds the address width")
        return target

    def cstring(self, virtual_address: int, what: str) -> str:
        value = bytearray()
        for index in range(MAX_NAME + 1):
            at = self.offset(virtual_address + index, 1, what)
            byte = self.image.data[at]
            if byte == 0:
                try:
                    return bytes(value).decode("utf-8")
                except UnicodeDecodeError as exc:
                    raise SwiftMetadataError(f"{what} is not UTF-8") from exc
            value.append(byte)
        raise SwiftMetadataError(f"{what} is unterminated or exceeds the size cap")

    def symbolic_name(self, virtual_address: int, what: str) -> bytes:
        """Read a Swift symbolic mangling without mistaking pointer bytes for NUL."""
        output = bytearray()
        cursor = virtual_address
        while len(output) <= MAX_MANGLED_NAME:
            byte_at = self.offset(cursor, 1, what)
            byte = self.image.data[byte_at]
            cursor += 1
            if byte == 0:
                return bytes(output)
            output.append(byte)
            operand_size = 4 if 0x01 <= byte <= 0x17 else (
                self.image.pointer_size if 0x18 <= byte <= 0x1F else 0)
            if operand_size:
                operand_at = self.offset(cursor, operand_size, what)
                output.extend(self.image.data[operand_at:operand_at + operand_size])
                cursor += operand_size
            if len(output) > MAX_MANGLED_NAME:
                break
        raise SwiftMetadataError(f"{what} is unterminated or exceeds the size cap")

    @staticmethod
    def raw_fields(raw: bytes | None, prefix: str = "mangled_type") -> dict[str, Any]:
        if raw is None:
            return {f"{prefix}_raw": None, f"{prefix}_hex": None}
        return {f"{prefix}_raw": raw.decode("latin-1"), f"{prefix}_hex": raw.hex()}

    def _context(self, descriptor: int) -> dict[str, Any]:
        flags = self.u32(descriptor, "context descriptor flags")
        kind_value = flags & 0x1F
        if kind_value not in _CONTEXT_KINDS and not 16 <= kind_value <= 31:
            raise SwiftMetadataError(f"unknown context descriptor kind {kind_value}")
        kind = _CONTEXT_KINDS.get(kind_value, f"type_{kind_value}")
        parent = self.relative(descriptor + 4, "context parent", nullable=True,
                               indirectable=True)
        name: str | None = None
        if kind_value in (0, 3) or 16 <= kind_value <= 31:
            name_address = self.relative(descriptor + 8, "context name", nullable=False)
            assert name_address is not None
            name = self.cstring(name_address, "context name")
            if not name:
                raise SwiftMetadataError("context descriptor has an empty name")
        return {
            "descriptor_va": descriptor,
            "kind": kind,
            "kind_value": kind_value,
            "name": name,
            "parent_va": parent,
            "flags": flags,
        }

    def parent_chain(self, parent: int | None) -> list[dict[str, Any]]:
        immediate: list[dict[str, Any]] = []
        seen: set[int] = set()
        for _ in range(64):
            if parent is None:
                break
            if parent in seen:
                raise SwiftMetadataError("context parent chain contains a cycle")
            seen.add(parent)
            context = self._context(parent)
            immediate.append({key: context[key] for key in
                              ("descriptor_va", "kind", "kind_value", "name", "flags")})
            parent = context["parent_va"]
        else:
            raise SwiftMetadataError("context parent chain exceeds the depth cap")
        if not immediate or immediate[-1]["kind_value"] != 0:
            raise SwiftMetadataError("nominal type parent chain does not end in a module")
        return list(reversed(immediate))

    def _nullable_symbolic(self, field_address: int, what: str) -> bytes | None:
        target = self.relative(field_address, what, nullable=True)
        return None if target is None else self.symbolic_name(target, what)

    def field_descriptor(self, address: int, context_kind: int,
                         declared_count: int) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        file_offset = self.offset(address, 16, "field descriptor")
        type_name = self._nullable_symbolic(address, "field descriptor type name")
        superclass = self._nullable_symbolic(address + 4, "field descriptor superclass")
        kind_value = self.u16(address + 8, "field descriptor kind")
        record_size = self.u16(address + 10, "field record size")
        record_count = self.u32(address + 12, "field record count")
        if kind_value not in _FIELD_DESCRIPTOR_KINDS:
            raise SwiftMetadataError(f"unknown field descriptor kind {kind_value}")
        allowed = {16: {1}, 17: {0}, 18: {2, 3}}.get(context_kind)
        if allowed is not None and kind_value not in allowed:
            raise SwiftMetadataError("field descriptor kind disagrees with its nominal type")
        if record_count > MAX_FIELDS_PER_TYPE:
            raise SwiftMetadataError("field descriptor exceeds the per-type field cap")
        if self.field_total > MAX_FIELDS - record_count:
            raise SwiftMetadataError("Swift metadata exceeds the total field cap")
        self.field_total += record_count
        if record_count and (record_size < 12 or record_size > 1024):
            raise SwiftMetadataError("field record size is outside its ABI bounds")
        if record_count != declared_count:
            raise SwiftMetadataError("field descriptor count disagrees with the nominal descriptor")
        total_size = 16 + record_size * record_count
        self.offset(address, total_size, "field descriptor records")

        records: list[dict[str, Any]] = []
        for index in range(record_count):
            record = address + 16 + index * record_size
            flags = self.u32(record, "field record flags")
            mangled = self._nullable_symbolic(record + 4, "field mangled type")
            name_address = self.relative(record + 8, "field name", nullable=True)
            name = None if name_address is None else self.cstring(name_address, "field name")
            if name == "":
                raise SwiftMetadataError("field record has an empty name")
            row = {
                "index": index,
                "name": name,
                "flags": flags,
                "is_indirect_case": bool(flags & 0x1),
                "is_var": bool(flags & 0x2),
                "is_artificial": bool(flags & 0x4),
            }
            row.update(self.raw_fields(mangled))
            records.append(row)

        descriptor = {
            "virtual_address": address,
            "file_offset": file_offset,
            "kind": _FIELD_DESCRIPTOR_KINDS[kind_value],
            "kind_value": kind_value,
            "record_size": record_size,
            "record_count": record_count,
        }
        descriptor.update(self.raw_fields(type_name))
        descriptor.update(self.raw_fields(superclass, "superclass_mangled_type"))
        return descriptor, records

    def nominal_type(self, descriptor: int, entry_address: int,
                     entry_offset: int) -> dict[str, Any]:
        if descriptor & 3:
            raise SwiftMetadataError("nominal context descriptor is not 4-byte aligned")
        descriptor_offset = self.offset(descriptor, 20, "nominal context descriptor")
        context = self._context(descriptor)
        kind_value = context["kind_value"]
        if not 16 <= kind_value <= 31:
            raise SwiftMetadataError("__swift5_types points to a non-type context descriptor")
        name = context["name"]
        assert isinstance(name, str)
        chain = self.parent_chain(context["parent_va"])
        module = next((item["name"] for item in chain if item["kind_value"] == 0), None)
        if not isinstance(module, str):
            raise SwiftMetadataError("type parent module has no name")
        qualified_parts = [item["name"] for item in chain if item["name"]]
        qualified_parts.append(name)

        if kind_value == 16:
            self.offset(descriptor, 44, "class descriptor")
            declared_count = self.u32(descriptor + 36, "class field count")
        elif kind_value == 17:
            self.offset(descriptor, 28, "struct descriptor")
            declared_count = self.u32(descriptor + 20, "struct field count")
        elif kind_value == 18:
            self.offset(descriptor, 28, "enum descriptor")
            payload_word = self.u32(descriptor + 20, "enum payload case count")
            empty_count = self.u32(descriptor + 24, "enum empty case count")
            declared_count = (payload_word & 0x00FFFFFF) + empty_count
        else:
            declared_count = 0

        field_address = self.relative(descriptor + 16, "type field descriptor", nullable=True)
        field_info: dict[str, Any] | None = None
        fields: list[dict[str, Any]] = []
        if field_address is not None:
            field_info, fields = self.field_descriptor(
                field_address, kind_value, declared_count)

        return {
            "record_va": entry_address,
            "record_file_offset": entry_offset,
            "descriptor_va": descriptor,
            "descriptor_file_offset": descriptor_offset,
            "flags": context["flags"],
            "generic": bool(context["flags"] & 0x80),
            "unique": bool(context["flags"] & 0x40),
            "kind_specific_flags": context["flags"] >> 16,
            "kind": context["kind"],
            "kind_value": kind_value,
            "name": name,
            "qualified_name": ".".join(qualified_parts),
            "module": module,
            "parent_chain": chain,
            "declared_field_count": declared_count,
            "field_descriptor": field_info,
            "fields": fields,
        }


def _swift_types(image: MachOImage) -> list[dict[str, Any]]:
    type_sections = [section for section in image.sections
                     if section.name in ("__swift5_types", "__swift5_types2")]
    count = 0
    for section in type_sections:
        if section.size % 4:
            raise SwiftMetadataError("Swift type record section size is not a multiple of four")
        count += section.size // 4
        if count > MAX_TYPES:
            raise SwiftMetadataError("Swift metadata exceeds the type record cap")
    parser = _SwiftReader(image)
    output: list[dict[str, Any]] = []
    for section in type_sections:
        for index in range(section.size // 4):
            entry_address = section.address + index * 4
            entry_offset = section.file_offset + index * 4
            relative = _Reader(image.data, image.endian).i32(
                entry_offset, "Swift type record")
            if relative == 0:
                raise SwiftMetadataError("Swift type record contains a null relative pointer")
            descriptor = entry_address + relative
            if descriptor < 0 or descriptor >= 1 << image.bits:
                raise SwiftMetadataError("Swift type record overflows the address width")
            output.append(parser.nominal_type(descriptor, entry_address, entry_offset))
    return output


def _extract_swift_metadata(data: bytes) -> dict[str, Any] | None:
    image = _parse_macho(data)
    if image is None:
        return None
    symbols = _swift_symbols(image)
    swift_sections = [section for section in image.sections
                      if section.name.startswith("__swift5_")]
    if not symbols and not swift_sections:
        return None
    types = _swift_types(image)
    return {
        "format": "mach-o-swift",
        "bits": image.bits,
        "byte_order": image.byte_order,
        "cpu_type": image.cpu_type,
        "cpu_subtype": image.cpu_subtype,
        "file_type": image.file_type,
        "flags": image.flags,
        "load_commands": [command.report() for command in image.load_commands],
        "segments": [segment.report() for segment in image.segments],
        "sections": [section.report() for section in image.sections],
        "swift_sections": [section.report() for section in swift_sections],
        "swift_symbols": symbols,
        "types": types,
    }


def extract_swift_metadata(data: bytes | bytearray | memoryview) -> dict[str, Any] | None:
    """Recover Swift symbols, nominal descriptors, parents, fields, and cases.

    ``None`` means the input is not a thin Mach-O or has no Swift evidence.
    Recognized malformed structures raise only :class:`SwiftMetadataError`.
    """
    try:
        return _extract_swift_metadata(_normalize_input(data))
    except SwiftMetadataError:
        raise
    except Exception as exc:  # Public malformed-input boundary.
        raise SwiftMetadataError("unexpected failure while extracting Swift metadata") from exc


analyze = extract_swift_metadata


def analyze_file(path: str | Path) -> dict[str, Any] | None:
    try:
        with Path(path).open("rb") as handle:
            data = handle.read(MAX_INPUT + 1)
    except (OSError, ValueError, TypeError) as exc:
        raise SwiftMetadataError(f"cannot read input: {exc}") from exc
    if len(data) > MAX_INPUT:
        raise SwiftMetadataError("input exceeds the size cap")
    return extract_swift_metadata(data)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="redepth_swift.py",
        description="statically recover Swift symbols and reflection metadata from a thin Mach-O",
    )
    parser.add_argument("input", help="thin Mach-O file (never executed)")
    parser.add_argument("--indent", type=int, choices=range(0, 9), default=None)
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        result = analyze_file(args.input)
        if result is None:
            raise SwiftMetadataError("input is not a Swift thin Mach-O image")
        print(json.dumps(result, sort_keys=True, indent=args.indent))
        return 0
    except SwiftMetadataError as exc:
        print(f"redepth_swift: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
