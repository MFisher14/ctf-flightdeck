#!/usr/bin/env python3
"""Bounded, offline PE mapping and fail-closed x86-64 and x86 Unicorn primitives.

This is an analyst hand tool, not a matcher or answer solver: it deliberately has no
``signals`` or ``solve_set`` entry point.  It accepts bytes, never a pathname, and never
executes, imports, or loads code from a delivery on the host.  The optional execution
path maps those bytes only inside Unicorn (PE32+ in 64-bit mode, PE32 in 32-bit mode).
Every imported API is replaced by a denying stub unless a Windows environment models it;
software interrupts, syscalls, invalid instructions, protection faults and unmapped
accesses stop the run, except the exceptions the PE32 sandbox delivers to the image's own
handlers (see :class:`SafeUnicorn`).  A run is useful only when it reaches an analyst-chosen
stop site or returns to the synthetic sentinel inside both its instruction and wall
budgets.

The mapper is intentionally smaller and stricter than the Windows loader.  Ambiguous or
unsupported structures raise :class:`PEError` instead of being repaired heuristically.
That makes it suitable for deriving evidence, never for turning a malformed specimen
into a plain answer.
"""
from __future__ import annotations

import binascii
import hashlib
import struct
import time
from dataclasses import dataclass, field
from typing import Callable, Iterable, Mapping, Protocol


PAGE = 0x1000
MAX_FILE = 64 << 20
MAX_IMAGE = 128 << 20
MAX_SECTIONS = 96
MAX_IMPORTS = 16_384
MAX_IMPORT_DESCRIPTORS = 2_048
MAX_IMPORT_NAME = 512
MAX_RELOCATIONS = 1_000_000
MAX_DIRECTORY = 16 << 20
MAX_DISASSEMBLY = 32 << 20
MAX_COMPARE_SITES = 16_384
MAX_SNAPSHOT = 32 << 20

IMAGE_FILE_MACHINE_I386 = 0x014C
IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000

IMAGE_DIRECTORY_ENTRY_IMPORT = 1
IMAGE_DIRECTORY_ENTRY_SECURITY = 4
IMAGE_DIRECTORY_ENTRY_BASERELOC = 5
IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT = 13
IMAGE_REL_BASED_ABSOLUTE = 0
IMAGE_REL_BASED_HIGHLOW = 3
IMAGE_REL_BASED_DIR64 = 10


class PEError(ValueError):
    """The bytes are not one unambiguous PE image this mapper supports."""


class EmulationDenied(RuntimeError):
    """The emulated path crossed a denied or undefined boundary, or hit a cap."""


def _align(value: int, alignment: int = PAGE) -> int:
    if value < 0 or alignment <= 0 or alignment & (alignment - 1):
        raise PEError("invalid alignment")
    return (value + alignment - 1) & ~(alignment - 1)


def _u16(data: bytes | bytearray, offset: int) -> int:
    if offset < 0 or offset + 2 > len(data):
        raise PEError("truncated 16-bit field")
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes | bytearray, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise PEError("truncated 32-bit field")
    return struct.unpack_from("<I", data, offset)[0]


def _u64(data: bytes | bytearray, offset: int) -> int:
    if offset < 0 or offset + 8 > len(data):
        raise PEError("truncated 64-bit field")
    return struct.unpack_from("<Q", data, offset)[0]


def _bounded_range(start: int, size: int, limit: int, what: str) -> tuple[int, int]:
    if start < 0 or size < 0 or start > limit or size > limit - start:
        raise PEError(f"{what} is outside its bounded container")
    return start, start + size


def _cstring(image: bytes | bytearray, rva: int, cap: int, what: str) -> bytes:
    _bounded_range(rva, 1, len(image), what)
    end = min(len(image), rva + cap + 1)
    zero = image.find(0, rva, end)
    if zero < 0:
        raise PEError(f"{what} has no NUL within {cap} bytes")
    return bytes(image[rva:zero])


@dataclass(frozen=True)
class DataDirectory:
    rva: int
    size: int


@dataclass(frozen=True)
class Section:
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    characteristics: int

    @property
    def mapped_size(self) -> int:
        return max(self.virtual_size, self.raw_size)

    @property
    def executable(self) -> bool:
        return bool(self.characteristics & IMAGE_SCN_MEM_EXECUTE)

    @property
    def writable(self) -> bool:
        return bool(self.characteristics & IMAGE_SCN_MEM_WRITE)


@dataclass(frozen=True)
class ImportSymbol:
    dll: str
    name: str | None
    ordinal: int | None
    iat_rva: int

    @property
    def display(self) -> str:
        target = self.name if self.name is not None else f"#{self.ordinal}"
        return f"{self.dll}!{target}"


@dataclass(frozen=True)
class Relocation:
    rva: int
    kind: int
    original: int
    relocated: int


@dataclass(frozen=True)
class MappedPE:
    image: bytes
    file_sha256: str
    machine: int
    is_64: bool
    preferred_base: int
    load_base: int
    entry_rva: int
    size_of_headers: int
    sections: tuple[Section, ...]
    directories: tuple[DataDirectory, ...]
    imports: tuple[ImportSymbol, ...]
    relocations: tuple[Relocation, ...]
    # Delay-load imports (B-241): parsed, never resolved by the mapper.  Each row's ``iat_rva`` is its
    # delay IAT slot, which the image still fills with its own load thunk.
    delay_imports: tuple[ImportSymbol, ...] = ()

    @property
    def entry(self) -> int:
        return self.load_base + self.entry_rva

    @property
    def image_sha256(self) -> str:
        return hashlib.sha256(self.image).hexdigest()

    def directory(self, index: int) -> DataDirectory:
        return self.directories[index] if 0 <= index < len(self.directories) else DataDirectory(0, 0)

    def rva_bytes(self, rva: int, size: int) -> bytes:
        if (not isinstance(rva, int) or isinstance(rva, bool)
                or not isinstance(size, int) or isinstance(size, bool)):
            raise PEError("RVA read bounds must be integers")
        start, end = _bounded_range(rva, size, len(self.image), "RVA read")
        return self.image[start:end]


def _parse_imports(image: bytearray, directory: DataDirectory, is_64: bool) -> tuple[ImportSymbol, ...]:
    if not directory.rva and not directory.size:
        return ()
    if not directory.rva or not directory.size or directory.size > MAX_DIRECTORY:
        raise PEError("invalid import directory")
    start, end = _bounded_range(directory.rva, directory.size, len(image), "import directory")
    width = 8 if is_64 else 4
    ordinal_mask = 1 << (63 if is_64 else 31)
    value_mask = ordinal_mask - 1
    rows: list[ImportSymbol] = []
    terminated = False
    cursor = start
    descriptors = 0
    while cursor + 20 <= end:
        original_thunk, stamp, chain, name_rva, first_thunk = struct.unpack_from("<IIIII", image, cursor)
        cursor += 20
        if not any((original_thunk, stamp, chain, name_rva, first_thunk)):
            terminated = True
            break
        descriptors += 1
        if descriptors > MAX_IMPORT_DESCRIPTORS:
            raise PEError("too many import descriptors")
        if not name_rva or not first_thunk:
            raise PEError("import descriptor has no DLL name or IAT")
        raw_dll = _cstring(image, name_rva, 260, "import DLL name")
        try:
            dll = raw_dll.decode("ascii").lower()
        except UnicodeDecodeError as exc:
            raise PEError("import DLL name is not ASCII") from exc
        if not dll or any(c < " " or c > "~" for c in dll):
            raise PEError("invalid import DLL name")
        thunk = original_thunk or first_thunk
        index = 0
        while True:
            if len(rows) >= MAX_IMPORTS:
                raise PEError("too many imported symbols")
            thunk_rva = thunk + index * width
            iat_rva = first_thunk + index * width
            _bounded_range(thunk_rva, width, len(image), "import name thunk")
            _bounded_range(iat_rva, width, len(image), "import address thunk")
            value = _u64(image, thunk_rva) if is_64 else _u32(image, thunk_rva)
            if value == 0:
                break
            if value & ordinal_mask:
                ordinal = value & 0xFFFF
                if value & value_mask != ordinal:
                    raise PEError("import ordinal thunk has non-ordinal payload bits")
                rows.append(ImportSymbol(dll, None, ordinal, iat_rva))
            else:
                name_ptr = value & value_mask
                _bounded_range(name_ptr, 3, len(image), "import hint/name")
                raw_name = _cstring(image, name_ptr + 2, MAX_IMPORT_NAME, "import symbol name")
                try:
                    name = raw_name.decode("ascii")
                except UnicodeDecodeError as exc:
                    raise PEError("import symbol name is not ASCII") from exc
                if not name or any(c < " " or c > "~" for c in name):
                    raise PEError("invalid import symbol name")
                rows.append(ImportSymbol(dll, name, None, iat_rva))
            index += 1
    if not terminated:
        raise PEError("import descriptor table has no terminator inside its directory")
    return tuple(rows)


DELAY_ATTR_RVA = 1                  # ImgDelayDescr.grAttrs dlattrRva: every field is an RVA


def _parse_delay_imports(image: bytearray, directory: DataDirectory, is_64: bool,
                         preferred_base: int, taken: int) -> tuple[ImportSymbol, ...]:
    """Parse the delay-load import descriptors (ImgDelayDescr, delayimp.h) into named IAT slots.

    The delay-load helper walks descriptors from the directory's RVA until one has no DLL name; it
    does not read the directory's size, so neither does this.  ``grAttrs`` 1 means every field is an
    RVA; 0 is the pre-VC7 form whose fields are VAs at the preferred base, which exists for PE32
    only.  A descriptor without a name table cannot be named and is refused, as is any other
    attribute bit.  Nothing is resolved here: the slots keep the image's own load thunks.
    """
    if not directory.rva and not directory.size:
        return ()
    if not directory.rva or not directory.size or directory.size > MAX_DIRECTORY:
        raise PEError("invalid delay-import directory")
    width = 8 if is_64 else 4
    ordinal_mask = 1 << (63 if is_64 else 31)
    value_mask = ordinal_mask - 1
    rows: list[ImportSymbol] = []
    cursor = directory.rva
    descriptors = 0
    while True:
        _bounded_range(cursor, 32, len(image), "delay-import descriptor")
        attrs, name_field, _hmod, iat_field, int_field, _bound, _unload, _stamp = \
            struct.unpack_from("<IIIIIIII", image, cursor)
        cursor += 32
        if not name_field:
            break
        descriptors += 1
        if descriptors > MAX_IMPORT_DESCRIPTORS:
            raise PEError("too many delay-import descriptors")
        if attrs == DELAY_ATTR_RVA:
            def to_rva(value: int, what: str) -> int:
                return value
        elif attrs == 0 and not is_64:
            def to_rva(value: int, what: str) -> int:
                if value < preferred_base:
                    raise PEError(f"delay-import {what} VA lies below the preferred base")
                return value - preferred_base
        else:
            raise PEError(f"unsupported delay-import attributes {attrs:#x}")
        if not iat_field or not int_field:
            raise PEError("delay-import descriptor has no IAT or no name table")
        raw_dll = _cstring(image, to_rva(name_field, "DLL name"), 260, "delay-import DLL name")
        try:
            dll = raw_dll.decode("ascii").lower()
        except UnicodeDecodeError as exc:
            raise PEError("delay-import DLL name is not ASCII") from exc
        if not dll or any(c < " " or c > "~" for c in dll):
            raise PEError("invalid delay-import DLL name")
        iat, names = to_rva(iat_field, "IAT"), to_rva(int_field, "name table")
        index = 0
        while True:
            if len(rows) + taken >= MAX_IMPORTS:
                raise PEError("too many imported symbols")
            thunk_rva, iat_rva = names + index * width, iat + index * width
            _bounded_range(thunk_rva, width, len(image), "delay-import name thunk")
            _bounded_range(iat_rva, width, len(image), "delay-import address thunk")
            value = _u64(image, thunk_rva) if is_64 else _u32(image, thunk_rva)
            if value == 0:
                break
            if value & ordinal_mask:
                ordinal = value & 0xFFFF
                if value & value_mask != ordinal:
                    raise PEError("delay-import ordinal thunk has non-ordinal payload bits")
                rows.append(ImportSymbol(dll, None, ordinal, iat_rva))
            else:
                name_ptr = to_rva(value & value_mask, "hint/name")
                _bounded_range(name_ptr, 3, len(image), "delay-import hint/name")
                raw_name = _cstring(image, name_ptr + 2, MAX_IMPORT_NAME, "delay-import symbol name")
                try:
                    name = raw_name.decode("ascii")
                except UnicodeDecodeError as exc:
                    raise PEError("delay-import symbol name is not ASCII") from exc
                if not name or any(c < " " or c > "~" for c in name):
                    raise PEError("invalid delay-import symbol name")
                rows.append(ImportSymbol(dll, name, None, iat_rva))
            index += 1
    return tuple(rows)


def _apply_relocations(image: bytearray, directory: DataDirectory, is_64: bool,
                       preferred_base: int, load_base: int) -> tuple[Relocation, ...]:
    if not directory.rva and not directory.size:
        if load_base != preferred_base:
            raise PEError("image has no relocation directory for the requested base")
        return ()
    if not directory.rva or not directory.size or directory.size > MAX_DIRECTORY:
        raise PEError("invalid base-relocation directory")
    start, end = _bounded_range(directory.rva, directory.size, len(image), "base-relocation directory")
    cursor = start
    seen: set[int] = set()
    rows: list[Relocation] = []
    delta = load_base - preferred_base
    while cursor < end:
        if end - cursor < 8:
            raise PEError("truncated base-relocation block")
        page_rva, block_size = struct.unpack_from("<II", image, cursor)
        if block_size < 8 or block_size & 1 or block_size > end - cursor:
            raise PEError("invalid base-relocation block size")
        entries = (block_size - 8) // 2
        for index in range(entries):
            raw = _u16(image, cursor + 8 + index * 2)
            kind, offset = raw >> 12, raw & 0xFFF
            if kind == IMAGE_REL_BASED_ABSOLUTE:
                continue
            rva = page_rva + offset
            if rva in seen:
                raise PEError("duplicate base-relocation target")
            seen.add(rva)
            if is_64 and kind == IMAGE_REL_BASED_DIR64:
                _bounded_range(rva, 8, len(image), "DIR64 relocation")
                original = _u64(image, rva)
                relocated = (original + delta) & 0xFFFFFFFFFFFFFFFF
                struct.pack_into("<Q", image, rva, relocated)
            elif not is_64 and kind == IMAGE_REL_BASED_HIGHLOW:
                _bounded_range(rva, 4, len(image), "HIGHLOW relocation")
                original = _u32(image, rva)
                relocated = (original + delta) & 0xFFFFFFFF
                struct.pack_into("<I", image, rva, relocated)
            else:
                raise PEError(f"unsupported relocation type {kind} for this PE class")
            rows.append(Relocation(rva, kind, original, relocated))
            if len(rows) > MAX_RELOCATIONS:
                raise PEError("too many base relocations")
        cursor += block_size
    if cursor != end:
        raise PEError("base-relocation directory did not end on a block boundary")
    return tuple(rows)


def map_pe(data: bytes | bytearray | memoryview, *, load_base: int | None = None,
           max_file: int = MAX_FILE, max_image: int = MAX_IMAGE) -> MappedPE:
    """Map one PE32/PE32+ image from inert bytes and apply bounded relocations.

    The returned image is immutable.  Overlapping sections, truncated raw data, unsupported
    relocation kinds and ambiguous directory ranges are refused rather than interpreted
    differently from Windows.  Delay-load imports are parsed into ``delay_imports`` (their IAT
    slots are left as the image wrote them; the harness decides whether to bind them).
    """
    try:
        raw = bytes(data)
    except Exception as exc:
        raise PEError("PE input is not bytes-like") from exc
    for cap_name, cap in (("max_file", max_file), ("max_image", max_image)):
        if not isinstance(cap, int) or isinstance(cap, bool) or cap <= 0:
            raise PEError(f"{cap_name} must be a positive integer")
    if len(raw) < 0x40 or len(raw) > max_file:
        raise PEError("PE file is empty, truncated, or over the file cap")
    if raw[:2] != b"MZ":
        raise PEError("missing DOS MZ signature")
    pe_offset = _u32(raw, 0x3C)
    _bounded_range(pe_offset, 24, len(raw), "PE/COFF header")
    if raw[pe_offset:pe_offset + 4] != b"PE\0\0":
        raise PEError("missing PE signature")
    coff = pe_offset + 4
    machine, section_count, _, _, _, optional_size, _ = struct.unpack_from("<HHIIIHH", raw, coff)
    if machine not in (IMAGE_FILE_MACHINE_I386, IMAGE_FILE_MACHINE_AMD64):
        raise PEError(f"unsupported PE machine {machine:#x}")
    if not 1 <= section_count <= MAX_SECTIONS:
        raise PEError("invalid or excessive PE section count")
    optional = coff + 20
    _bounded_range(optional, optional_size, len(raw), "optional header")
    magic = _u16(raw, optional)
    is_64 = magic == 0x20B
    if magic not in (0x10B, 0x20B) or is_64 != (machine == IMAGE_FILE_MACHINE_AMD64):
        raise PEError("optional-header class does not match the supported machine")
    minimum_optional = 112 if is_64 else 96
    if optional_size < minimum_optional:
        raise PEError("optional header is too small")
    entry_rva = _u32(raw, optional + 16)
    preferred_base = _u64(raw, optional + 24) if is_64 else _u32(raw, optional + 28)
    section_alignment = _u32(raw, optional + 32)
    file_alignment = _u32(raw, optional + 36)
    image_size = _u32(raw, optional + 56)
    headers_size = _u32(raw, optional + 60)
    if not preferred_base or preferred_base & (PAGE - 1):
        raise PEError("preferred image base is not page-aligned")
    if not section_alignment or section_alignment & (section_alignment - 1):
        raise PEError("section alignment is not a power of two")
    if not file_alignment or file_alignment & (file_alignment - 1) or file_alignment > 0x10000:
        raise PEError("file alignment is invalid")
    if image_size < PAGE or image_size > max_image or image_size & (section_alignment - 1):
        raise PEError("image size is invalid or over the image cap")
    if not headers_size or headers_size > len(raw) or headers_size > image_size:
        raise PEError("size of headers is invalid")
    if entry_rva >= image_size:
        raise PEError("entry RVA lies outside the image")
    try:
        chosen_base = preferred_base if load_base is None else int(load_base)
    except (TypeError, ValueError, OverflowError) as exc:
        raise PEError("requested load base is not an integer address") from exc
    if chosen_base < 0 or chosen_base & (PAGE - 1) or (is_64 and chosen_base >= 1 << 64):
        raise PEError("requested load base is invalid")
    if not is_64 and chosen_base >= 1 << 32:
        raise PEError("PE32 load base does not fit 32 bits")
    address_limit = 1 << (64 if is_64 else 32)
    if preferred_base > address_limit - image_size or chosen_base > address_limit - image_size:
        raise PEError("mapped PE image would overflow its address width")

    number_offset = optional + (108 if is_64 else 92)
    directory_offset = optional + (112 if is_64 else 96)
    directory_count = min(_u32(raw, number_offset), 16)
    if directory_offset + directory_count * 8 > optional + optional_size:
        raise PEError("data-directory array exceeds the optional header")
    directories = [DataDirectory(0, 0) for _ in range(16)]
    for index in range(directory_count):
        rva, size = struct.unpack_from("<II", raw, directory_offset + index * 8)
        if bool(rva) != bool(size):
            raise PEError(f"data directory {index} has only an RVA or a size")
        if rva and index == IMAGE_DIRECTORY_ENTRY_SECURITY:
            # The certificate table is the one PE directory whose first field is a
            # file offset rather than an RVA.  It is never mapped or interpreted here.
            _bounded_range(rva, size, len(raw), "certificate table")
        elif rva:
            _bounded_range(rva, size, image_size, f"data directory {index}")
        directories[index] = DataDirectory(rva, size)
    section_table = optional + optional_size
    _bounded_range(section_table, section_count * 40, len(raw), "section table")
    if section_table + section_count * 40 > headers_size:
        raise PEError("section table extends past SizeOfHeaders")
    sections: list[Section] = []
    virtual_ranges: list[tuple[int, int]] = []
    raw_ranges: list[tuple[int, int]] = []
    for index in range(section_count):
        at = section_table + index * 40
        name_raw = raw[at:at + 8].split(b"\0", 1)[0]
        try:
            name = name_raw.decode("ascii")
        except UnicodeDecodeError as exc:
            raise PEError("section name is not ASCII") from exc
        virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from("<IIII", raw, at + 8)
        characteristics = _u32(raw, at + 36)
        if virtual_address & (section_alignment - 1):
            raise PEError(f"section {name or index} has a misaligned RVA")
        mapped_size = max(virtual_size, raw_size)
        if mapped_size:
            start, end = _bounded_range(virtual_address, mapped_size, image_size, f"section {name or index}")
            for old_start, old_end in virtual_ranges:
                if start < old_end and old_start < end:
                    raise PEError("overlapping section virtual ranges")
            virtual_ranges.append((start, end))
        if raw_size:
            start, end = _bounded_range(raw_offset, raw_size, len(raw), f"section {name or index} raw bytes")
            if start < headers_size:
                raise PEError("section raw data overlaps the PE headers")
            for old_start, old_end in raw_ranges:
                if start < old_end and old_start < end:
                    raise PEError("overlapping section raw ranges")
            raw_ranges.append((start, end))
        sections.append(Section(name, virtual_address, virtual_size, raw_offset, raw_size, characteristics))

    image = bytearray(image_size)
    image[:headers_size] = raw[:headers_size]
    for section in sections:
        if section.raw_size:
            image[section.virtual_address:section.virtual_address + section.raw_size] = \
                raw[section.raw_offset:section.raw_offset + section.raw_size]
    imports = _parse_imports(image, directories[IMAGE_DIRECTORY_ENTRY_IMPORT], is_64)
    delay_imports = _parse_delay_imports(image, directories[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT],
                                         is_64, preferred_base, len(imports))
    delay_slots = [row.iat_rva for row in delay_imports]
    if len(set(delay_slots)) != len(delay_slots) or {row.iat_rva for row in imports} & set(delay_slots):
        raise PEError("a delay-import IAT slot is shared with another import")
    relocations = _apply_relocations(image, directories[IMAGE_DIRECTORY_ENTRY_BASERELOC], is_64,
                                     preferred_base, chosen_base)
    return MappedPE(bytes(image), hashlib.sha256(raw).hexdigest(), machine, is_64,
                    preferred_base, chosen_base, entry_rva, headers_size, tuple(sections),
                    tuple(directories), imports, relocations, delay_imports)


# --------------------------------------------------------------------------- API-hash catalog
def _ror32(value: int, count: int) -> int:
    count &= 31
    value &= 0xFFFFFFFF
    return ((value >> count) | (value << (32 - count))) & 0xFFFFFFFF


def _api_name_bytes(name: str, uppercase: bool) -> bytes:
    if not isinstance(name, str):
        raise PEError("API names must be ASCII strings")
    text = name.upper() if uppercase else name
    try:
        return text.encode("ascii")
    except UnicodeEncodeError as exc:
        raise PEError("API names must be ASCII") from exc


def hash_ror13(name: str, *, uppercase: bool = False) -> int:
    """Classic shellcode ROR13+ADD hash over one ASCII export name."""
    raw = _api_name_bytes(name, uppercase)
    value = 0
    for byte in raw:
        value = (_ror32(value, 13) + byte) & 0xFFFFFFFF
    return value


def hash_djb2(name: str, *, uppercase: bool = False) -> int:
    raw = _api_name_bytes(name, uppercase)
    value = 5381
    for byte in raw:
        value = ((value * 33) + byte) & 0xFFFFFFFF
    return value


def hash_fnv1a(name: str, *, uppercase: bool = False) -> int:
    raw = _api_name_bytes(name, uppercase)
    value = 0x811C9DC5
    for byte in raw:
        value = ((value ^ byte) * 0x01000193) & 0xFFFFFFFF
    return value


def hash_crc32(name: str, *, uppercase: bool = False) -> int:
    raw = _api_name_bytes(name, uppercase)
    return binascii.crc32(raw) & 0xFFFFFFFF


HASHERS: Mapping[str, Callable[[str], int]] = {
    "ror13": hash_ror13,
    "ror13_upper": lambda name: hash_ror13(name, uppercase=True),
    "djb2": hash_djb2,
    "djb2_upper": lambda name: hash_djb2(name, uppercase=True),
    "fnv1a": hash_fnv1a,
    "fnv1a_upper": lambda name: hash_fnv1a(name, uppercase=True),
    "crc32": hash_crc32,
    "crc32_upper": lambda name: hash_crc32(name, uppercase=True),
}

COMMON_WINDOWS_APIS: tuple[tuple[str, str], ...] = tuple(
    (dll, name) for dll, names in (
        ("kernel32.dll", (
            "LoadLibraryA", "LoadLibraryW", "GetProcAddress", "VirtualAlloc", "VirtualFree",
            "VirtualProtect", "CreateFileA", "CreateFileW", "ReadFile", "WriteFile", "CloseHandle",
            "GetModuleHandleA", "GetModuleHandleW", "GetModuleFileNameA", "GetModuleFileNameW",
            "GetProcessHeap", "HeapAlloc", "HeapReAlloc", "HeapFree", "HeapSize",
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "QueryPerformanceCounter",
            "GetSystemTimeAsFileTime", "GetSystemMetrics", "Sleep",
        )),
        ("ntdll.dll", (
            "NtQueryInformationProcess", "NtQuerySystemInformation", "NtQueryVirtualMemory",
            "NtReadFile", "NtProtectVirtualMemory", "RtlDecompressBuffer", "RtlGetVersion",
            "RtlAddVectoredExceptionHandler", "RtlRemoveVectoredExceptionHandler",
        )),
        ("advapi32.dll", ("RegOpenKeyExA", "RegOpenKeyExW", "RegQueryValueExA", "RegQueryValueExW")),
        ("bcrypt.dll", ("BCryptOpenAlgorithmProvider", "BCryptHashData", "BCryptFinishHash")),
    ) for name in names
)


@dataclass(frozen=True)
class HashMatch:
    algorithm: str
    dll: str
    name: str
    value: int

    @property
    def display(self) -> str:
        return f"{self.dll}!{self.name}" if self.dll else self.name


def build_api_hash_index(symbols: Iterable[str | tuple[str, str]] = COMMON_WINDOWS_APIS,
                         algorithms: Mapping[str, Callable[[str], int]] = HASHERS
                         ) -> dict[int, tuple[HashMatch, ...]]:
    """Index common export hashes without collapsing collisions or algorithm ambiguity."""
    rows: dict[int, list[HashMatch]] = {}
    seen: set[tuple[str, str]] = set()
    count = 0
    for symbol in symbols:
        if isinstance(symbol, str):
            dll, name = "", symbol
        else:
            try:
                dll, name = symbol
            except (ValueError, TypeError) as exc:
                raise PEError("API symbol must be a name or a (dll, name) pair") from exc
        dll, name = str(dll).lower(), str(name)
        if not name or (dll, name) in seen:
            continue
        seen.add((dll, name))
        count += 1
        if count > MAX_IMPORTS:
            raise PEError("API-hash catalog exceeds its symbol cap")
        for algorithm, function in algorithms.items():
            value = int(function(name)) & 0xFFFFFFFF
            rows.setdefault(value, []).append(HashMatch(str(algorithm), dll, name, value))
    return {value: tuple(sorted(matches, key=lambda row: (row.algorithm, row.dll, row.name)))
            for value, matches in rows.items()}


def resolve_api_hash(value: int, symbols: Iterable[str | tuple[str, str]] = COMMON_WINDOWS_APIS,
                     algorithms: Mapping[str, Callable[[str], int]] = HASHERS) -> tuple[HashMatch, ...]:
    """Return every matching name/algorithm.  Empty and collisions remain explicit."""
    try:
        key = int(value) & 0xFFFFFFFF
    except (TypeError, ValueError) as exc:
        raise PEError("API hash value must be an integer") from exc
    return build_api_hash_index(symbols, algorithms).get(key, ())


# --------------------------------------------------------------------------- compare sites
@dataclass(frozen=True)
class CompareSite:
    address: int
    rva: int
    section: str
    mnemonic: str
    operands: str
    size: int
    encoding: bytes


def _capstone_x86(is_64: bool):
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
    except Exception as exc:
        raise EmulationDenied("Capstone is required for instruction vetting") from exc
    engine = Cs(CS_ARCH_X86, CS_MODE_64 if is_64 else CS_MODE_32)
    engine.detail = True
    return engine


def find_compare_sites(pe: MappedPE, *, max_bytes: int = MAX_DISASSEMBLY,
                       max_sites: int = MAX_COMPARE_SITES) -> tuple[CompareSite, ...]:
    """Disassemble executable sections and return bounded CMP/TEST sites."""
    if not isinstance(pe, MappedPE):
        raise PEError("find_compare_sites requires a MappedPE")
    if max_bytes <= 0 or max_sites <= 0:
        return ()
    engine = _capstone_x86(pe.is_64)
    consumed = 0
    sites: list[CompareSite] = []
    for section in pe.sections:
        if not section.executable or not section.mapped_size:
            continue
        size = min(section.mapped_size, len(pe.image) - section.virtual_address)
        if size < 0 or consumed + size > max_bytes:
            raise EmulationDenied("executable-section disassembly exceeds its byte cap")
        blob = pe.image[section.virtual_address:section.virtual_address + size]
        consumed += size
        base = pe.load_base + section.virtual_address
        for instruction in engine.disasm(blob, base):
            if instruction.mnemonic.lower() not in ("cmp", "test", "cmpsb", "cmpsw", "cmpsd", "cmpsq"):
                continue
            sites.append(CompareSite(instruction.address, instruction.address - pe.load_base,
                                     section.name, instruction.mnemonic.lower(), instruction.op_str,
                                     instruction.size, bytes(instruction.bytes)))
            if len(sites) > max_sites:
                raise EmulationDenied("compare-site count exceeds its cap")
    return tuple(sites)


@dataclass(frozen=True)
class OperandValue:
    kind: str
    size: int
    value: int
    address: int | None = None
    register: str | None = None


# --------------------------------------------------------------------------- safe Unicorn harness
@dataclass(frozen=True)
class _MemoryRegion:
    name: str
    start: int
    size: int
    permissions: int
    defined_mask: bool

    @property
    def end(self) -> int:
        return self.start + self.size


@dataclass(frozen=True)
class MemorySnapshot:
    name: str
    start: int
    data: bytes
    defined: bytes | None


@dataclass(frozen=True)
class Snapshot:
    """Everything a run can observe or that decides where it stops, so a restore or fork replays.

    Beyond registers and the writable regions: every image page that has been writable at any
    time since mapping, whatever its protection now (an unpacker makes ``.text`` writable with
    VirtualProtect, writes it and protects it again; the pages never writable still hold the
    mapped bytes, which a restore writes back from the harness's own pristine copy), the image
    page protections, the heap cursor, the vectored-handler chain, the per-process
    Windows-model state (the stdin read position, the command-line buffers, LastError, the
    tick, performance and file-time counters, the live heap allocations) and, when the
    harness tracks them, the image bytes the run has written.  The environment's output
    streams and traces are logs shared by every fork, not process state.
    """
    image_sha256: str
    registers: tuple[tuple[str, int], ...]
    memory: tuple[MemorySnapshot, ...]
    page_perms: tuple[int, ...] = ()
    heap_ptr: int | None = None
    model_state: tuple = ()
    image_written: bytes | None = None
    veh: tuple[tuple[int, int], ...] = ()
    veh_next_cookie: int = 1
    mapped_sha256: str | None = None


@dataclass(frozen=True)
class RunResult:
    reason: str
    address: int
    instructions: int
    memory_accesses: int
    seconds: float


@dataclass(frozen=True)
class _Backend:
    uc: object
    x86: object


def _default_backend() -> _Backend:
    # native_emulate owns the Darwin/arm64 cache-line prerequisite check.  Importing
    # Unicorn directly here could let its fallback issue an uncatchable privileged MRS.
    try:
        from solvers.common import native_emulate
    except Exception as exc:
        raise EmulationDenied("the guarded Unicorn capability check is unavailable") from exc
    if not native_emulate.UNICORN_AVAILABLE:
        raise EmulationDenied("Unicorn is unavailable or unsafe in this workshop")
    return _Backend(native_emulate._uc, native_emulate._x86c)


def _new_veh_chain() -> "VehChain":
    """A fresh vectored-exception-handler chain (the Windows model section owns the semantics)."""
    return VehChain()


_SYSTEM_MNEMONICS = frozenset({
    "syscall", "sysenter", "int", "int1", "int3", "into", "iret", "iretd", "iretq", "hlt",
    "in", "insb", "insw", "insd", "out", "outsb", "outsw", "outsd", "cpuid", "rdtsc",
    "rdtscp", "rdrand", "rdseed", "rdpid", "rdpmc", "xgetbv", "xsetbv", "sgdt", "sidt",
    "sldt", "str", "smsw", "lsl", "lar", "verr", "verw", "rdfsbase", "rdgsbase",
    "wrfsbase", "wrgsbase", "xsave", "xrstor", "fxsave", "fxrstor", "ud0", "ud1", "ud2",
})


# Instructions a user-mode Windows thread may not execute: #GP, reported as a privileged-instruction
# exception.  The PE32 harness raises that exception; the x86-64 harness keeps its denial.
_PRIVILEGED_MNEMONICS = frozenset({
    "hlt", "in", "insb", "insw", "insd", "out", "outsb", "outsw", "outsd", "cli", "sti",
    "lgdt", "lidt", "lldt", "ltr", "lmsw", "clts", "invd", "wbinvd", "invlpg", "rdmsr", "wrmsr",
})

# Far transfers load CS from the instruction or the stack (a WoW64 "heaven's gate" jumps to 0x33 this
# way); the PE32 harness denies them by name, as it does any read of CS or SS.
_FAR_MNEMONICS = frozenset({"ljmp", "lcall", "retf"})
_X86_PREFIXES = frozenset({0x66, 0x67, 0xF0, 0xF2, 0xF3, 0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65})

EXCEPTION_BREAKPOINT = 0x80000003
EXCEPTION_SINGLE_STEP = 0x80000004
EXCEPTION_ACCESS_VIOLATION = 0xC0000005
EXCEPTION_ILLEGAL_INSTRUCTION = 0xC000001D
EXCEPTION_INT_DIVIDE_BY_ZERO = 0xC0000094
EXCEPTION_PRIV_INSTRUCTION = 0xC0000096
STATUS_UNWIND = 0xC0000027
EXCEPTION_UNWINDING = 0x2
EXCEPTION_CHAIN_END = 0xFFFFFFFF
NULL_PAGE_END = 0x10000            # Windows never maps the first 64 KiB of a process

# Offsets of the integer and control registers inside the x86 CONTEXT record (winnt.h).
_CTX32_REGS = (("edi", 0x9C), ("esi", 0xA0), ("ebx", 0xA4), ("edx", 0xA8), ("ecx", 0xAC),
               ("eax", 0xB0), ("ebp", 0xB4))
_CTX32_DR = 0x04                   # Dr0..Dr3, Dr6, Dr7: six DWORDs
_CTX32_EIP, _CTX32_EFLAGS, _CTX32_ESP = 0xB8, 0xC0, 0xC4

# Windows page protections <-> emulator permission bits (read 1, write 2, execute 4).
_PAGE_PROTECTIONS = {0x01: 0, 0x02: 1, 0x04: 3, 0x08: 3, 0x10: 4, 0x20: 5, 0x40: 7, 0x80: 7}
_PAGE_CONSTANTS = {0: 0x01, 1: 0x02, 2: 0x04, 3: 0x04, 4: 0x10, 5: 0x20, 6: 0x40, 7: 0x40}
PROTECT_FAILED = -1


def _page_runs(pages: list[int]) -> list[tuple[int, int, int]]:
    """(offset, size, permissions) for each run of equally protected image pages."""
    out: list[tuple[int, int, int]] = []
    first = 0
    for index in range(1, len(pages) + 1):
        if index == len(pages) or pages[index] != pages[first]:
            out.append((first * PAGE, (index - first) * PAGE, pages[first]))
            first = index
    return out


class SafeUnicorn:
    """One closed x86-64 (PE32+) or x86 (PE32) sandbox with denying imports and reproducible forks.

    ``backend`` exists only so the safety policy can be tested without loading a native
    engine in a restricted workshop.  Production callers omit it and receive the guarded
    repository Unicorn backend.

    PE32 images (B-241) run in 32-bit mode with the Win32 stdcall convention, a TEB and PEB
    that define only the fields this model answers, and frame-based structured exception
    handling: a breakpoint, a single-step trap, an access violation in the null page or on a
    read-only image page, an integer division by zero, an illegal instruction and a privileged
    instruction are delivered to the vectored handlers and then to the ``FS:[0]`` chain.  An
    exception no handler continues, and everything the model does not carry, still ends the
    run with a named denial.  ``bind_delay_imports`` points each delay-load IAT slot at its
    own stub, the state the delay-load helper leaves after a successful first call.
    ``track_image_writes`` records every byte of the image the run writes, so
    ``run(stop_on_written_exec=True)`` can stop where control first enters written bytes.
    """

    STUB_BASE = 0x50000000
    STACK_BASE = 0x60000000
    STACK_SIZE = 512 << 10
    SCRATCH_BASE = 0x70000000
    SCRATCH_SIZE = 1 << 20
    HEAP_BASE = 0x80000000
    HEAP_SIZE = 8 << 20
    TEB_BASE = 0x7FFDE000            # PE32 only: one page of TEB, then one of PEB
    TEB_SIZE = 2 * PAGE
    GDT_BASE = 0x7FFDC000            # PE32 only: the descriptor table FS is loaded from (not guest-visible)
    FS_SELECTOR = 0x3B               # the x86 Windows TEB selector: GDT entry 7, ring 3
    DIRECTION_FLAG = 1 << 10
    THREAD_EFLAGS = 0x202            # PE32: the EFLAGS a Windows thread starts with (IF, reserved bit 1)
    MAX_GUEST_CALLS = 64
    MAX_SEH_FRAMES = 256

    # The single-step trap flag in RFLAGS, and the VEH dispatch verdicts (see tools pe_win.VehChain).
    TRAP_FLAG = 1 << 8
    EXCEPTION_SINGLE_STEP = 0x80000004
    EXCEPTION_CONTINUE_SEARCH = 0x00000000
    EXCEPTION_CONTINUE_EXECUTION = 0xFFFFFFFF
    # Byte offsets of EFlags and Rip inside the x64 CONTEXT record (winnt.h).  The handler sees the
    # real layout, so a VEH that rewrites ContextRecord->Rip to skip junk is read back faithfully.
    CONTEXT_EFLAGS_OFFSET = 0x44
    CONTEXT_RIP_OFFSET = 0xF8

    def __init__(self, pe: MappedPE, *, instruction_cap: int = 500_000,
                 memory_cap: int = 1_000_000, wall_seconds: float = 2.0,
                 snapshot_cap: int = MAX_SNAPSHOT, backend: object | None = None,
                 clock: Callable[[], float] = time.monotonic,
                 environment: object | None = None, bind_delay_imports: bool = True,
                 track_image_writes: bool = False):
        if (not isinstance(pe, MappedPE)
                or pe.machine not in (IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_I386)
                or pe.is_64 != (pe.machine == IMAGE_FILE_MACHINE_AMD64)):
            raise EmulationDenied("SafeUnicorn accepts mapped x86-64 (PE32+) and x86 (PE32) images only")
        for budget_name, budget in (("instruction_cap", instruction_cap),
                                    ("memory_cap", memory_cap), ("snapshot_cap", snapshot_cap)):
            if not isinstance(budget, int) or isinstance(budget, bool):
                raise EmulationDenied(f"{budget_name} must be an integer")
        if not isinstance(wall_seconds, (int, float)) or isinstance(wall_seconds, bool):
            raise EmulationDenied("wall_seconds must be a number")
        if instruction_cap <= 0 or memory_cap <= 0 or not (0 < wall_seconds <= 60):
            raise EmulationDenied("invalid emulation budget")
        if snapshot_cap <= 0 or snapshot_cap > MAX_IMAGE:
            raise EmulationDenied("invalid snapshot cap")
        self.pe = pe
        self.instruction_cap = int(instruction_cap)
        self.memory_cap = int(memory_cap)
        self.wall_seconds = float(wall_seconds)
        self.snapshot_cap = int(snapshot_cap)
        self._backend = backend if backend is not None else _default_backend()
        self._u = self._backend.uc
        self._x = self._backend.x86
        self._clock = clock
        self.bits = 64 if pe.is_64 else 32
        self.pointer_bits = self.bits                   # read by the Windows model to pick the ABI
        self._ptr = self.bits // 8
        self._mask = (1 << self.bits) - 1
        self._ip, self._sp, self._fl = (("rip", "rsp", "rflags") if pe.is_64
                                        else ("eip", "esp", "eflags"))
        self.bind_delay_imports = bool(bind_delay_imports)
        self.uc = self._u.Uc(self._u.UC_ARCH_X86,
                             self._u.UC_MODE_64 if pe.is_64 else self._u.UC_MODE_32)
        self._regions: list[_MemoryRegion] = []
        self._defined: dict[str, bytearray] = {}
        self._state: dict[str, object] = {}
        self._compare_engine = _capstone_x86(pe.is_64)
        self._vetted: dict[bytes, tuple[str, int, frozenset]] = {}
        self.import_stubs: dict[ImportSymbol, int] = {}
        self._imports = pe.imports + (pe.delay_imports if self.bind_delay_imports else ())
        self._stub_size = _align(max(PAGE, (len(self._imports) + 4) * 16))
        if self._stub_size > 1 << 20:
            raise EmulationDenied("import stub table exceeds its cap")
        self.return_sentinel = self.STUB_BASE + self._stub_size - 16
        self.veh_trampoline = self.STUB_BASE + self._stub_size - 8
        self.nested_handler = self.STUB_BASE + self._stub_size - 32
        self.image_written = bytearray(len(pe.image)) if track_image_writes else None
        self.exception_trace: list[tuple[int, int]] = []
        self.exit_code: int | None = None
        self._guest_calls: list[tuple[int, Callable[[int], None]]] = []
        self._page_perms: list[int] = []
        self._ever_writable: list[bool] = []     # image pages writable at any time since mapping
        self._pristine = b""                     # the image as mapped (relocated, IAT slots on stubs)
        self._mapped_sha256 = ""
        self.stack_base, self.stack_size = self.STACK_BASE, self.STACK_SIZE
        self.scratch_base, self.scratch_size = self.SCRATCH_BASE, self.SCRATCH_SIZE
        self.heap_base, self.heap_size = self.HEAP_BASE, self.HEAP_SIZE
        self._heap_ptr = self.HEAP_BASE
        # Per-process state the Windows model keeps on the machine (not on the shared environment),
        # so a snapshot carries it and a fork replays it: the stdin cursor, the command-line buffers.
        self.model_state: dict = {}
        self.environment = environment
        self._stub_owner: dict[int, ImportSymbol] = {}
        self.anti_debug_trace: list = []
        self.single_step_trace: list[int] = []
        self._veh = _new_veh_chain()
        self._map()
        self._install_hooks()
        self._initialize_registers()

    def _add_region(self, name: str, start: int, size: int, permissions: int,
                    defined_mask: bool = False) -> None:
        if size <= 0:
            return
        end = start + size
        for region in self._regions:
            if start < region.end and region.start < end:
                raise EmulationDenied(f"emulated regions overlap: {name} and {region.name}")
        self._regions.append(_MemoryRegion(name, start, size, permissions, defined_mask))
        if defined_mask:
            self._defined[name] = bytearray(size)

    def _initial_page_perms(self) -> list[int]:
        read, write, execute = self._u.UC_PROT_READ, self._u.UC_PROT_WRITE, self._u.UC_PROT_EXEC
        pages = [0] * (_align(len(self.pe.image)) // PAGE)
        for index in range((_align(self.pe.size_of_headers) // PAGE)):
            pages[index] |= read
        for section in self.pe.sections:
            if not section.mapped_size:
                continue
            permissions = ((read if section.characteristics & IMAGE_SCN_MEM_READ else 0)
                           | (write if section.characteristics & IMAGE_SCN_MEM_WRITE else 0)
                           | (execute if section.characteristics & IMAGE_SCN_MEM_EXECUTE else 0))
            first = section.virtual_address // PAGE
            last = _align(section.virtual_address + section.mapped_size) // PAGE
            for index in range(first, min(last, len(pages))):
                pages[index] |= permissions
        return pages

    def _image_pages(self) -> list[tuple[int, int, int]]:
        return _page_runs(self._page_perms)

    def _map(self) -> None:
        image_size = _align(len(self.pe.image))
        all_permissions = self._u.UC_PROT_READ | self._u.UC_PROT_WRITE | self._u.UC_PROT_EXEC
        image_end = self.pe.load_base + image_size
        fixed = ((self.STUB_BASE, self._stub_size), (self.STACK_BASE, self.STACK_SIZE),
                 (self.SCRATCH_BASE, self.SCRATCH_SIZE), (self.HEAP_BASE, self.HEAP_SIZE))
        if self.bits == 32:
            fixed += ((self.TEB_BASE, self.TEB_SIZE), (self.GDT_BASE, PAGE))
        if any(self.pe.load_base < start + size and start < image_end for start, size in fixed):
            raise EmulationDenied("PE image overlaps the fixed closed-sandbox regions")
        self._page_perms = self._initial_page_perms()
        self.uc.mem_map(self.pe.load_base, image_size, all_permissions)
        image = bytearray(self.pe.image)
        for index, imported in enumerate(self._imports):
            stub = self.STUB_BASE + index * 16
            struct.pack_into("<Q" if self.bits == 64 else "<I", image, imported.iat_rva, stub)
            self.import_stubs[imported] = stub
            self._stub_owner[stub] = imported
        self._pristine = bytes(image)
        self._mapped_sha256 = hashlib.sha256(self._pristine).hexdigest()
        self._ever_writable = [bool(value & self._u.UC_PROT_WRITE) for value in self._page_perms]
        self.uc.mem_write(self.pe.load_base, self._pristine)
        self.uc.mem_map(self.STUB_BASE, self._stub_size, all_permissions)
        self.uc.mem_write(self.STUB_BASE, b"\xCC" * self._stub_size)
        self.uc.mem_map(self.STACK_BASE, self.STACK_SIZE,
                        self._u.UC_PROT_READ | self._u.UC_PROT_WRITE)
        self.uc.mem_map(self.SCRATCH_BASE, self.SCRATCH_SIZE,
                        self._u.UC_PROT_READ | self._u.UC_PROT_WRITE)
        self.uc.mem_map(self.HEAP_BASE, self.HEAP_SIZE,
                        self._u.UC_PROT_READ | self._u.UC_PROT_WRITE)

        for offset, size, permissions in self._image_pages():
            self.uc.mem_protect(self.pe.load_base + offset, size, permissions)
            if permissions:
                self._add_region(f"image:{offset:08x}", self.pe.load_base + offset, size, permissions)
        self.uc.mem_protect(self.STUB_BASE, self._stub_size,
                            self._u.UC_PROT_READ | self._u.UC_PROT_EXEC)
        self._add_region("api-stubs", self.STUB_BASE, self._stub_size,
                         self._u.UC_PROT_READ | self._u.UC_PROT_EXEC)
        self._add_region("stack", self.STACK_BASE, self.STACK_SIZE,
                         self._u.UC_PROT_READ | self._u.UC_PROT_WRITE, True)
        self._add_region("scratch", self.SCRATCH_BASE, self.SCRATCH_SIZE,
                         self._u.UC_PROT_READ | self._u.UC_PROT_WRITE, True)
        self._add_region("heap", self.HEAP_BASE, self.HEAP_SIZE,
                         self._u.UC_PROT_READ | self._u.UC_PROT_WRITE, True)
        if self.bits == 32:
            self.uc.mem_map(self.TEB_BASE, self.TEB_SIZE,
                            self._u.UC_PROT_READ | self._u.UC_PROT_WRITE)
            self._add_region("teb", self.TEB_BASE, self.TEB_SIZE,
                             self._u.UC_PROT_READ | self._u.UC_PROT_WRITE, True)
            # Mapped for the engine only: it is in no region, so the image can neither read nor write it.
            self.uc.mem_map(self.GDT_BASE, PAGE, self._u.UC_PROT_READ | self._u.UC_PROT_WRITE)

    def _load_fs32(self) -> None:
        """Point FS at the TEB the way x86 Windows does: a 4 KiB data segment behind a selector.

        Unicorn takes no FS base in 32-bit mode, so the base comes from a descriptor: GDT entry 7
        (selector 0x3B), base the TEB, byte-granular limit 0xFFF, ring 3 read/write data.  Loading
        any segment makes the engine recompute its stack width from SS, so SS is loaded too (a flat
        32-bit ring 0 data segment: the engine runs at ring 0), and DS and ES get the flat ring 3
        data selector 0x23 a Windows thread holds, so code that reads them sees Windows' value.
        The table is not guest memory, so the image cannot load a segment register itself:
        ``mov es, ax``, ``pop ds`` and ``les`` are denied by name (see ``_segment_load``).
        """
        def descriptor(base: int, limit: int, access: int, flags: int) -> bytes:
            return struct.pack("<HHBBBB", limit & 0xFFFF, base & 0xFFFF, (base >> 16) & 0xFF, access,
                               (flags << 4) | ((limit >> 16) & 0xF), (base >> 24) & 0xFF)

        table = bytearray(8 * 8)
        table[8:16] = descriptor(0, 0xFFFFF, 0x9B, 0xC)                 # 0x08: ring 0 code
        table[16:24] = descriptor(0, 0xFFFFF, 0x93, 0xC)                # 0x10: ring 0 data (SS)
        table[24:32] = descriptor(0, 0xFFFFF, 0xFB, 0xC)                # 0x1B: ring 3 code
        table[32:40] = descriptor(0, 0xFFFFF, 0xF3, 0xC)                # 0x23: ring 3 data (DS, ES)
        table[56:64] = descriptor(self.TEB_BASE, PAGE - 1, 0xF3, 0x4)   # 0x3B: the TEB (FS)
        self.uc.mem_write(self.GDT_BASE, bytes(table))
        self.uc.reg_write(self._x.UC_X86_REG_GDTR, (0, self.GDT_BASE, len(table) - 1, 0))
        self.uc.reg_write(self._x.UC_X86_REG_SS, 0x10)
        self.uc.reg_write(self._x.UC_X86_REG_DS, 0x23)
        self.uc.reg_write(self._x.UC_X86_REG_ES, 0x23)
        self.uc.reg_write(self._x.UC_X86_REG_FS, self.FS_SELECTOR)

    @property
    def peb(self) -> int:
        """Address of the PE32 process environment block (the page after the TEB)."""
        return self.TEB_BASE + PAGE

    def _initialize_teb(self) -> None:
        """The TEB and PEB fields this model answers; every other byte stays undefined, so a read
        of one (the loader data, the heap flags, the TLS array) ends the run instead of reading 0."""
        teb, peb = self.TEB_BASE, self.peb
        for offset, value in ((0x00, EXCEPTION_CHAIN_END),            # NT_TIB.ExceptionList
                              (0x04, self.STACK_BASE + self.STACK_SIZE),   # StackBase
                              (0x08, self.STACK_BASE),                # StackLimit
                              (0x18, teb),                            # NT_TIB.Self
                              (0x30, peb)):                           # ProcessEnvironmentBlock
            self.write_memory(teb + offset, struct.pack("<I", value))
        self.write_memory(peb, b"\x00\x00\x00")            # ..., ..., BeingDebugged = 0
        self.write_memory(peb + 0x08, struct.pack("<I", self.pe.load_base))   # ImageBaseAddress
        self.write_memory(peb + 0x68, struct.pack("<I", 0))                   # NtGlobalFlag

    def _registers(self) -> dict[str, int]:
        if self.bits == 64:
            names = ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip", "rflags",
                     "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "fs_base", "gs_base",
                     "mxcsr") + tuple(f"xmm{i}" for i in range(16))
        else:
            names = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip", "eflags",
                     "mxcsr") + tuple(f"xmm{i}" for i in range(8))
        out = {}
        for name in names:
            attr = "UC_X86_REG_" + name.upper()
            if hasattr(self._x, attr):
                out[name] = getattr(self._x, attr)
        return out

    def _initialize_registers(self) -> None:
        registers = self._registers()
        for name, value in registers.items():
            if name not in (self._sp, self._ip, self._fl, "mxcsr"):
                self.uc.reg_write(value, (0xA5A5A5A5A5A5A5A5 & self._mask)
                                  if not name.startswith("xmm") else 0)
        if self.bits == 32:
            self._load_fs32()
            self._initialize_teb()
            self.write_register("eflags", self.THREAD_EFLAGS)   # IF and the reserved bit, as a thread starts
        rsp = self.STACK_BASE + self.STACK_SIZE - 0x100
        rsp &= ~0xF
        self.write_memory(rsp, self.return_sentinel.to_bytes(self._ptr, "little"))
        self.write_register(self._sp, rsp)
        self.write_register(self._ip, self.pe.entry)

    def _region(self, address: int, size: int, permission: int = 0) -> _MemoryRegion | None:
        if size < 0:
            return None
        for region in self._regions:
            if region.start <= address and size <= region.end - address:
                return region if not permission or region.permissions & permission == permission else None
        return None

    def _is_defined(self, address: int, size: int) -> bool:
        region = self._region(address, size, self._u.UC_PROT_READ)
        if region is None:
            return False
        if not region.defined_mask:
            return True
        mask = self._defined[region.name]
        offset = address - region.start
        return all(mask[offset:offset + size])

    def _mark_defined(self, address: int, size: int) -> None:
        region = self._region(address, size, self._u.UC_PROT_WRITE)
        if region is None:
            return
        if region.defined_mask:
            offset = address - region.start
            self._defined[region.name][offset:offset + size] = b"\x01" * size

    def _deny(self, reason: str) -> None:
        if not self._state.get("violation"):
            self._state["violation"] = reason
        self.uc.emu_stop()

    def _hook_code(self, _uc, address: int, size: int, _user) -> None:
        if self.STUB_BASE <= address < self.STUB_BASE + self._stub_size:
            if address == self.return_sentinel:
                self._state["stop"] = ("return", address)
                self.uc.emu_stop()
                return
            if address == self.veh_trampoline:
                if self.bits == 64:
                    self._veh_return()
                else:
                    self._guest_return32()
                return
            imported = self._stub_owner.get(address)
            if (imported is not None and self.environment is not None
                    and self.environment.handles(imported)):
                self._dispatch_api(imported)
                return
            match = imported.display if imported is not None else "unknown"
            self._deny(f"import/API call denied: {match}")
            return
        if address in self._state.get("stop_addresses", ()):
            self._state["stop"] = ("site", address)
            self.uc.emu_stop()
            return
        if self._state.get("stop_written") and self._is_written(address):
            self._state["stop"] = ("written-exec", address)
            self.uc.emu_stop()
            return
        instructions = int(self._state.get("instructions", 0)) + 1
        self._state["instructions"] = instructions
        if instructions > int(self._state["instruction_cap"]):
            self._deny("instruction budget exceeded")
            return
        if self._clock() > float(self._state["deadline"]):
            self._deny("wall-time budget exceeded")
            return
        if not 0 < size <= 15:
            size = 0                     # the engine could not size it (an undefined opcode)
        if self._region(address, max(1, size), self._u.UC_PROT_EXEC) is None:
            self._deny(f"instruction fetch outside an executable mapped region at {address:#x}")
            return
        mnemonic, size, registers = self._vet(address, size)
        if not mnemonic:
            self._deny(f"instruction cannot be vetted at {address:#x}")
            return
        self._state["last_instruction"] = address
        if self.bits == 32 and self._raise_for_instruction32(address, size, mnemonic, registers):
            return
        if mnemonic in _SYSTEM_MNEMONICS:
            self._deny(f"system/environment instruction denied: {mnemonic}")
            return
        if self.bits == 64:
            self._maybe_single_step(address)

    def _vet(self, address: int, size: int) -> tuple[str, int, frozenset]:
        """The lower-case mnemonic, length and register operands (for ``mov``/``push``/``pop``,
        the only forms that name a segment, control or debug register) of the instruction at
        ``address``; ('', 0, {}) when it cannot be decoded.  ``size`` 0 means the engine did not
        size it: the bytes up to the end of its executable region (16 at most) are decoded instead.

        The decode is cached by the bytes it read (a mnemonic depends on nothing else), so a loop
        is disassembled once and self-modified code is decoded afresh.
        """
        length = size
        if not length:
            region = self._region(address, 1, self._u.UC_PROT_EXEC)
            length = min(16, region.end - address) if region is not None else 0
        try:
            encoded = bytes(self.uc.mem_read(address, min(16, max(1, length))))
        except Exception:
            return "", 0, frozenset()
        hit = self._vetted.get(encoded)
        if hit is None:
            try:
                instruction = next(iter(self._compare_engine.disasm(encoded, address, 1)), None)
            except Exception:
                instruction = None
            if instruction is None:
                hit = ("", 0, frozenset())
            else:
                mnemonic = instruction.mnemonic.lower()
                registers: frozenset = frozenset()
                if mnemonic in ("mov", "push", "pop"):
                    try:
                        from capstone.x86 import X86_OP_REG
                        registers = frozenset(instruction.reg_name(operand.reg).lower()
                                              for operand in instruction.operands
                                              if operand.type == X86_OP_REG)
                    except Exception:
                        hit = ("", 0, frozenset())   # operands unreadable: cannot be vetted
                if hit is None:
                    hit = (mnemonic, int(instruction.size), registers)
            if len(self._vetted) >= 65_536:
                self._vetted.clear()
            self._vetted[encoded] = hit
        return hit

    def _is_written(self, address: int) -> bool:
        offset = address - self.pe.load_base
        return (self.image_written is not None and 0 <= offset < len(self.image_written)
                and bool(self.image_written[offset]))

    def _mark_written(self, address: int, size: int) -> None:
        if self.image_written is None or size <= 0:
            return
        start = max(0, address - self.pe.load_base)
        end = min(len(self.image_written), address - self.pe.load_base + size)
        if start < end:
            self.image_written[start:end] = b"\x01" * (end - start)

    # ------------------------------------------------------------- modeled Windows API dispatch
    def _dispatch_api(self, imported: ImportSymbol) -> None:
        try:
            self.environment.dispatch(imported, self)
        except EmulationDenied:
            raise
        except Exception as exc:
            self._deny(f"modeled API {imported.display} failed: {type(exc).__name__}: {exc}")
            return
        trace = getattr(self.environment, "anti_debug", None)
        if trace is not None:
            self.anti_debug_trace = list(trace)
        self._state["api_calls"] = int(self._state.get("api_calls", 0)) + 1
        if self._state.pop("api_no_return", False):
            return                       # ExitProcess stopped the run, or RtlUnwind resumes it later
        popped = 0
        if self.bits == 32:
            count = getattr(self.environment, "stdcall_args", lambda _imported: None)(imported)
            if count is None:
                self._deny(f"modeled API {imported.display} has no stdcall argument count")
                return
            popped = 4 * int(count)
        self._simulate_ret(popped)

    def _simulate_ret(self, popped: int = 0) -> None:
        rsp = self.read_register(self._sp)
        if self._region(rsp, self._ptr, self._u.UC_PROT_READ) is None:
            self._deny("modeled API return address is not on the mapped stack")
            return
        retaddr = int.from_bytes(bytes(self.uc.mem_read(rsp, self._ptr)), "little")
        self.write_register(self._sp, (rsp + self._ptr + popped) & self._mask)
        self.write_register(self._ip, retaddr)

    # ------------------------------------------------------------- pe_win.Machine interface
    @property
    def load_base(self) -> int:
        return self.pe.load_base

    def read(self, address: int, size: int) -> bytes:
        if size < 0 or self._region(address, size, self._u.UC_PROT_READ) is None:
            raise EmulationDenied(f"modeled API read outside readable memory at {address:#x}")
        return bytes(self.uc.mem_read(address, size))

    def write(self, address: int, data: bytes) -> None:
        raw = bytes(data)
        if self._region(address, len(raw), self._u.UC_PROT_WRITE) is None:
            raise EmulationDenied(f"modeled API write outside writable memory at {address:#x}")
        self.uc.mem_write(address, raw)
        self._invalidate_code(address, len(raw))
        self._mark_defined(address, len(raw))
        self._mark_written(address, len(raw))

    def reg(self, name: str) -> int:
        return self.read_register(name)

    def setreg(self, name: str, value: int) -> None:
        self.write_register(name, value)

    def alloc(self, size: int) -> int:
        if size <= 0:
            return 0
        rounded = _align(size)
        if self._heap_ptr + rounded > self.HEAP_BASE + self.HEAP_SIZE:
            return 0
        base = self._heap_ptr
        self._heap_ptr += rounded
        self._mark_defined(base, rounded)
        return base

    def add_veh(self, first: bool, handler: int) -> int:
        if self._region(handler, 1, self._u.UC_PROT_EXEC) is None:
            raise EmulationDenied("a VEH handler must point at executable mapped code")
        return self._veh.add(bool(first), int(handler))

    def remove_veh(self, cookie: int) -> bool:
        return self._veh.remove(int(cookie))

    def exit_process(self, code: int) -> None:
        """ExitProcess: the run ends here with reason ``exit``; the code is kept on ``exit_code``."""
        self.exit_code = int(code) & 0xFFFFFFFF
        self._state["stop"] = ("exit", self.read_register(self._ip))
        self._state["api_no_return"] = True
        self.uc.emu_stop()

    def protect(self, address: int, size: int, protection: int) -> int | None:
        """VirtualProtect on image pages: apply the protection and return the old constant.

        None means the range is not image memory (the caller keeps its own answer for heap
        blocks); ``PROTECT_FAILED`` means a protection constant this model does not carry.
        """
        base, count = self.pe.load_base, len(self._page_perms)
        if size <= 0 or address < base or address + size > base + count * PAGE:
            return None
        permissions = _PAGE_PROTECTIONS.get(int(protection) & 0xFF)
        if permissions is None or int(protection) & ~0xFF:
            return PROTECT_FAILED
        first, last = (address - base) // PAGE, (address + size - 1 - base) // PAGE
        old = self._page_perms[first]
        pages = list(self._page_perms)
        for index in range(first, last + 1):
            pages[index] = permissions
        self._apply_page_perms(pages)
        return _PAGE_CONSTANTS[old]

    def _apply_page_perms(self, pages: list[int]) -> None:
        """Set every image page's protection and rebuild the image regions from them."""
        base = self.pe.load_base
        for offset, run, run_permissions in _page_runs(pages):
            self.uc.mem_protect(base + offset, run, run_permissions)
        self._page_perms = list(pages)
        for index, value in enumerate(pages):
            if value & self._u.UC_PROT_WRITE:
                self._ever_writable[index] = True
        self._regions = [region for region in self._regions if not region.name.startswith("image:")]
        for offset, run, run_permissions in self._image_pages():
            if run_permissions:
                self._add_region(f"image:{offset:08x}", base + offset, run, run_permissions)

    def image_memory(self) -> bytes:
        """The image as it stands in the sandbox now (what a dump of the process would hold)."""
        return bytes(self.uc.mem_read(self.pe.load_base, len(self.pe.image)))

    # ------------------------------------------------------------- x86 (PE32) exception dispatch
    def _read_u32(self, address: int) -> int:
        return int.from_bytes(self.read_memory(address, 4), "little")

    def _raise32(self, code: int, address: int, resume: int, info: tuple[int, ...] = ()) -> None:
        """Stop the engine and deliver exception ``code`` once it has stopped (see ``run``)."""
        if self._state.get("pending") is None and not self._state.get("violation"):
            self._state["pending"] = lambda: self._dispatch_exception32(code, address, resume, info)
        self.uc.emu_stop()

    def _raise_for_instruction32(self, address: int, size: int, mnemonic: str,
                                 registers: frozenset = frozenset()) -> bool:
        """Raise the exception Windows reports for the instruction about to run, if it has one.

        The engine runs the thread at ring 0 with its own CS and SS, so an instruction that reads
        or loads either selector would see a value no Windows thread holds (0x1B / 0x23 there):
        it is denied by name.  A control or debug register access is #GP in user mode, raised as
        a privileged-instruction exception."""
        sregs = sorted(registers & {"cs", "ss"})
        if mnemonic == "lss":
            sregs = ["ss"]
        elif mnemonic in _FAR_MNEMONICS or (mnemonic in ("jmp", "call") and self._far_indirect(address)):
            sregs = ["cs"]
        if sregs:
            self._deny(f"{mnemonic} touches the {'/'.join(sregs).upper()} selector at {address:#x}: "
                       "the sandbox does not hold the selectors a Windows thread holds")
            return True
        loaded = self._segment_load(address, mnemonic, registers)
        if loaded:
            # The engine would fetch the descriptor from a table that is not guest memory, and
            # the access checks it makes are ring 0's: reading DS/ES/FS/GS is modelled, loading
            # one is not.
            self._deny(f"{mnemonic} loads the {loaded.upper()} segment register at {address:#x}: "
                       "segment register loads are not modelled")
            return True
        if mnemonic in ("popf", "popfd"):
            changed = self._popf_ring_change(4 if mnemonic == "popfd" else 2)
            if changed:
                self._deny(f"{mnemonic} at {address:#x} would change {changed}: a ring-3 thread "
                           "keeps it, and the sandbox runs the thread at ring 0")
                return True
        if any(name.startswith(("cr", "dr")) and name[2:].isdigit() for name in registers):
            self._raise32(EXCEPTION_PRIV_INSTRUCTION, address, address)
            return True
        if mnemonic == "int3":
            self._raise32(EXCEPTION_BREAKPOINT, address, address)
            return True
        if mnemonic == "int" and bytes(self.uc.mem_read(address, 2)) == b"\xcd\x03":
            # capstone reads CD 03 as ``int 3``; Windows reports it as a breakpoint at the byte
            # after it (not the int3 address), which the dispatch here does not carry.
            self._deny("the two-byte int 3 form is not modelled")
            return True
        if mnemonic == "ud2":
            self._raise32(EXCEPTION_ILLEGAL_INSTRUCTION, address, address)
            return True
        if mnemonic in _PRIVILEGED_MNEMONICS:
            self._raise32(EXCEPTION_PRIV_INSTRUCTION, address, address)
            return True
        if mnemonic in ("div", "idiv") and self._divisor32(address, size) == 0:
            self._raise32(EXCEPTION_INT_DIVIDE_BY_ZERO, address, address)
            return True
        return False

    _SEGMENT_POPS = {b"\x1f": "ds", b"\x07": "es", b"\x0f\xa1": "fs", b"\x0f\xa9": "gs"}

    def _segment_load(self, address: int, mnemonic: str, registers: frozenset) -> str:
        """The data segment register (ds, es, fs, gs) the instruction at ``address`` loads, or ''.

        Read from the encoding: ``mov Sreg, r/m`` is 8E /r (8C, the store, only reads one), and
        ``pop ds|es|fs|gs`` has its own opcodes.  ``lds``/``les``/``lfs``/``lgs`` load a far pointer."""
        if mnemonic in ("lds", "les", "lfs", "lgs"):
            return mnemonic[1:]
        if mnemonic not in ("mov", "pop") or not registers & {"ds", "es", "fs", "gs"}:
            return ""
        region = self._region(address, 1, self._u.UC_PROT_EXEC)
        if region is None:
            return ""
        raw = bytes(self.uc.mem_read(address, min(16, region.end - address)))
        index = 0
        while index < len(raw) - 1 and raw[index] in _X86_PREFIXES:
            index += 1
        body = raw[index:]
        if mnemonic == "pop":
            for opcode, name in self._SEGMENT_POPS.items():
                if body.startswith(opcode):
                    return name
            return ""
        if body[:1] == b"\x8e" and len(body) > 1:
            return ("es", "cs", "ss", "ds", "fs", "gs", "", "")[(body[1] >> 3) & 7]
        return ""

    _IF_FLAG, _IOPL_MASK, _VM_FLAG = 1 << 9, 3 << 12, 1 << 17

    def _popf_ring_change(self, width: int) -> str:
        """What a POPF/POPFD of ``width`` bytes would change that a ring-3 thread cannot ('' if
        nothing): at CPL 3 with IOPL 0 the processor leaves IF and IOPL as they are, at ring 0
        (where the engine runs) it loads them.  An unreadable stack is left to fault."""
        esp = self.read_register("esp")
        if self._region(esp, width, self._u.UC_PROT_READ) is None:
            return ""
        value = int.from_bytes(bytes(self.uc.mem_read(esp, width)), "little")
        current = self.read_register("eflags")
        changes = []
        if (value ^ current) & self._IF_FLAG:
            changes.append("IF")
        if (value ^ current) & self._IOPL_MASK:
            changes.append("IOPL")
        return " and ".join(changes)

    def _far_indirect(self, address: int) -> bool:
        """Whether the JMP/CALL at ``address`` is the far indirect form (FF /3, FF /5), which loads CS
        from memory; capstone does not name it consistently, so the encoding is read."""
        region = self._region(address, 1, self._u.UC_PROT_EXEC)
        if region is None:
            return True                                  # cannot be read: treat as the denied form
        raw = bytes(self.uc.mem_read(address, min(16, region.end - address)))
        if len(raw) < 2:
            return False                                 # one byte left: no ModRM, not the far form
        index = 0
        while index < len(raw) - 1 and raw[index] in _X86_PREFIXES:
            index += 1
        return raw[index] == 0xFF and ((raw[index + 1] >> 3) & 7) in (3, 5)

    def _divisor32(self, address: int, size: int) -> int | None:
        """The divisor of the DIV/IDIV at ``address``, or None when it cannot be read here."""
        try:
            from capstone.x86 import X86_OP_MEM, X86_OP_REG
            encoded = bytes(self.uc.mem_read(address, min(16, max(1, size))))
            instruction = next(iter(self._compare_engine.disasm(encoded, address, 1)), None)
            operand = instruction.operands[0]
            width = int(operand.size)
            if operand.type == X86_OP_REG:
                name = instruction.reg_name(operand.reg).upper()
                return int(self.uc.reg_read(getattr(self._x, "UC_X86_REG_" + name))) & ((1 << (8 * width)) - 1)
            if operand.type != X86_OP_MEM:
                return None
            where = int(operand.mem.disp)
            for register, scale in ((operand.mem.base, 1), (operand.mem.index, int(operand.mem.scale))):
                if register:
                    name = instruction.reg_name(register).upper()
                    where += int(self.uc.reg_read(getattr(self._x, "UC_X86_REG_" + name))) * scale
            if operand.mem.segment and instruction.reg_name(operand.mem.segment).lower() == "fs":
                where += self.TEB_BASE
            where &= 0xFFFFFFFF
            if not self._is_defined(where, width):
                return None
            return int.from_bytes(bytes(self.uc.mem_read(where, width)), "little")
        except Exception:
            return None

    def _dispatch_exception32(self, code: int, address: int, resume: int,
                              info: tuple[int, ...]) -> None:
        """Build EXCEPTION_RECORD and CONTEXT below the stack pointer and start the handler walk:
        the vectored handlers in order, then the frame-based chain at ``FS:[0]``."""
        self.exception_trace.append((code & 0xFFFFFFFF, address & 0xFFFFFFFF))
        esp = self.read_register("esp")
        record = (esp - 0x400) & ~0xF
        context = record + 0x60
        dispatcher = record - 0x10
        pointers = record - 0x20
        flags = self.read_register("eflags")
        if code == EXCEPTION_SINGLE_STEP:
            flags &= ~self.TRAP_FLAG     # the kernel clears TF in the frame a single-step reports
        try:
            self.write(record, struct.pack("<IIIII", code & 0xFFFFFFFF, 0, 0, address & 0xFFFFFFFF,
                                           len(info))
                       + b"".join(struct.pack("<I", value & 0xFFFFFFFF) for value in info))
            self.write(context + _CTX32_DR, bytes(24))      # no hardware breakpoints are set
            for name, offset in _CTX32_REGS:
                self.write(context + offset, struct.pack("<I", self.read_register(name)))
            self.write(context + _CTX32_EIP, struct.pack("<I", resume & 0xFFFFFFFF))
            self.write(context + _CTX32_EFLAGS, struct.pack("<I", flags & 0xFFFFFFFF))
            self.write(context + _CTX32_ESP, struct.pack("<I", esp))
            self.write(pointers, struct.pack("<II", record, context))
        except EmulationDenied:
            self._deny(f"no room on the stack to deliver exception {code:#x}")
            return
        self._exception_step32({"code": code, "address": address, "record": record,
                                "context": context, "dispatcher": dispatcher, "pointers": pointers,
                                "stack": pointers - 0x20, "stage": "veh", "index": 0, "frame": 0,
                                "frames": 0})

    def _frame_problem32(self, frame: int) -> str | None:
        low, high = self.STACK_BASE, self.STACK_BASE + self.STACK_SIZE
        if frame & 3 or not (low <= frame and frame + 8 <= high):
            return f"SEH registration record {frame:#x} is not an aligned record on the stack"
        if not self._is_defined(frame, 8):
            return f"SEH registration record {frame:#x} holds undefined bytes"
        return None

    def _exception_step32(self, exc: dict) -> None:
        what = f"exception {exc['code']:#x} at {exc['address']:#x}"
        if exc["stage"] == "veh":
            handlers = self._veh.handlers()
            if exc["index"] < len(handlers):
                self._guest_call32(handlers[exc["index"]], (exc["pointers"],), exc["stack"], 4,
                                   lambda value: self._veh_verdict32(exc, value))
                return
            exc["stage"] = "seh"
            exc["frame"] = self._read_u32(self.TEB_BASE)
        frame = exc["frame"]
        if frame == EXCEPTION_CHAIN_END:
            self._deny(f"unhandled {what} (no VEH or SEH handler continued execution)")
            return
        exc["frames"] += 1
        problem = self._frame_problem32(frame)
        if problem or exc["frames"] > self.MAX_SEH_FRAMES:
            self._deny(f"{what}: {problem or 'the SEH chain exceeds its cap'}")
            return
        handler = self._read_u32(frame + 4)
        if handler == self.nested_handler:
            self._deny(f"{what} was raised inside an exception handler (nested dispatch is not modelled)")
            return
        if self._region(handler, 1, self._u.UC_PROT_EXEC) is None:
            self._deny(f"{what}: SEH handler {handler:#x} is not executable mapped code")
            return
        # RtlpExecuteHandlerForException links its own registration record around the handler call.
        guard = exc["stack"] - 8
        try:
            self.write(guard, struct.pack("<II", self._read_u32(self.TEB_BASE), self.nested_handler))
            self.write(self.TEB_BASE, struct.pack("<I", guard))
        except EmulationDenied:
            self._deny(f"no room on the stack to deliver {what}")
            return
        self._guest_call32(handler, (exc["record"], frame, exc["context"], exc["dispatcher"]),
                           guard - 0x10, 0, lambda value: self._seh_verdict32(exc, value))

    def _veh_verdict32(self, exc: dict, value: int) -> None:
        if value == self.EXCEPTION_CONTINUE_EXECUTION:
            self._continue32(exc)
        elif value == self.EXCEPTION_CONTINUE_SEARCH:
            exc["index"] += 1
            self._exception_step32(exc)
        else:
            self._deny(f"a vectored handler returned {value:#x}, which is not a disposition")

    def _seh_verdict32(self, exc: dict, value: int) -> None:
        # The dispatcher's epilogue: mov esp, fs:[0]; pop fs:[0] (it unlinks its own record).
        head = self._read_u32(self.TEB_BASE)
        problem = None if head == EXCEPTION_CHAIN_END else self._frame_problem32(head)
        if head == EXCEPTION_CHAIN_END or problem:
            self._deny(problem or "an SEH handler returned with an empty handler chain")
            return
        self.write(self.TEB_BASE, struct.pack("<I", self._read_u32(head)))
        if value == 0:                               # ExceptionContinueExecution
            self._continue32(exc)
        elif value == 1:                             # ExceptionContinueSearch
            problem = self._frame_problem32(exc["frame"])
            if problem:
                self._deny(problem)
                return
            exc["frame"] = self._read_u32(exc["frame"])
            self._exception_step32(exc)
        else:
            self._deny(f"an SEH handler returned disposition {value}, which is not modelled")

    def _continue32(self, exc: dict) -> None:
        """Resume from the CONTEXT the handler left: NtContinue."""
        context = exc["context"]
        if any(self.read_memory(context + _CTX32_DR, 24)):
            self._deny("a handler set debug registers through CONTEXT (hardware breakpoints are "
                       "not modelled)")
            return
        for name, offset in _CTX32_REGS:
            self.write_register(name, self._read_u32(context + offset))
        self.write_register("esp", self._read_u32(context + _CTX32_ESP))
        # NtContinue sanitizes a user-mode CONTEXT: IF set, IOPL 0, never virtual-8086 mode.
        eflags = self._read_u32(context + _CTX32_EFLAGS)
        self.write_register("eflags", (eflags & ~(self._IOPL_MASK | self._VM_FLAG)) | self._IF_FLAG | 0x2)
        self.write_register("eip", self._read_u32(context + _CTX32_EIP))
        self._state["exceptions_handled"] = int(self._state.get("exceptions_handled", 0)) + 1

    def _guest_call32(self, target: int, args: tuple[int, ...], stack: int, popped: int,
                      resume: Callable[[int], None]) -> None:
        """Enter guest code at ``target`` with ``args`` on the stack; ``resume(eax)`` runs when it
        returns to the trampoline with the stack it was given (less ``popped`` callee-cleaned bytes)."""
        if len(self._guest_calls) >= self.MAX_GUEST_CALLS:
            self._deny("exception-dispatch depth exceeds its cap")
            return
        sp = (stack - 4 * len(args) - 4) & ~3
        try:
            self.write(sp, struct.pack("<I", self.veh_trampoline)
                       + b"".join(struct.pack("<I", value & 0xFFFFFFFF) for value in args))
        except EmulationDenied:
            self._deny("no room on the stack to call an exception handler")
            return
        self._guest_calls.append((sp + 4 + popped, resume))
        for name in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp"):
            self.write_register(name, 0xA5A5A5A5)    # what the dispatcher leaves is not the image's
        self.write_register("eflags", self.read_register("eflags")
                            & ~(self.TRAP_FLAG | self.DIRECTION_FLAG))
        self.write_register("esp", sp)
        self.write_register("eip", target)

    def _guest_return32(self) -> None:
        esp, value = self.read_register("esp"), self.read_register("eax")
        while self._guest_calls:
            expected, resume = self._guest_calls.pop()
            if expected == esp:
                self._state["pending"] = lambda: resume(value)
                self.uc.emu_stop()
                return
        self._deny("return to the exception dispatcher with a stack it did not hand out")

    def unwind(self) -> None:
        """RtlUnwind for frame-based x86 SEH: call every handler below the target frame with
        EXCEPTION_UNWINDING, unlink each, then return to the caller with ReturnValue in EAX."""
        if self.bits != 32:
            raise EmulationDenied("RtlUnwind is modelled for x86 frame-based SEH only")
        esp = self.read_register("esp")
        ret, target, _target_ip, record, value = struct.unpack("<IIIII", self.read(esp, 20))
        if not target:
            raise EmulationDenied("RtlUnwind with a NULL target frame (an exit unwind) is not modelled")
        work = (esp - 0x400) & ~0xF
        if record:
            self.write(record + 4, struct.pack("<I", self._read_u32(record + 4) | EXCEPTION_UNWINDING))
        else:
            record = work
            self.write(record, struct.pack("<IIIII", STATUS_UNWIND, EXCEPTION_UNWINDING, 0, ret, 0))
        state = {"target": target, "record": record, "value": value, "ret": ret,
                 "resume_sp": (esp + 20) & 0xFFFFFFFF, "context": work + 0x60,
                 "dispatcher": work - 0x10, "stack": work - 0x40, "frames": 0,
                 "saved": {name: self.read_register(name) for name in ("ebx", "esi", "edi", "ebp")}}
        self._state["api_no_return"] = True
        self._state["pending"] = lambda: self._unwind_step32(state)
        self.uc.emu_stop()

    def _unwind_step32(self, state: dict) -> None:
        while True:
            frame = self._read_u32(self.TEB_BASE)
            if frame == state["target"]:
                for name, value in state["saved"].items():
                    self.write_register(name, value)
                self.write_register("eax", state["value"])
                self.write_register("esp", state["resume_sp"])
                self.write_register("eip", state["ret"])
                return
            state["frames"] += 1
            problem = None
            if frame == EXCEPTION_CHAIN_END or frame > state["target"]:
                problem = "RtlUnwind target frame is not on the handler chain"
            elif state["frames"] > self.MAX_SEH_FRAMES:
                problem = "the SEH chain exceeds its cap"
            problem = problem or self._frame_problem32(frame)
            if problem:
                self._deny(problem)
                return
            handler = self._read_u32(frame + 4)
            if handler != self.nested_handler:
                break
            # The dispatcher's own record answers ExceptionContinueSearch to an unwind.
            self.write(self.TEB_BASE, struct.pack("<I", self._read_u32(frame)))
        if self._region(handler, 1, self._u.UC_PROT_EXEC) is None:
            self._deny(f"RtlUnwind: SEH handler {handler:#x} is not executable mapped code")
            return
        self._guest_call32(handler, (state["record"], frame, state["context"], state["dispatcher"]),
                           state["stack"], 0, lambda value: self._unwind_verdict32(state, frame, value))

    def _unwind_verdict32(self, state: dict, frame: int, value: int) -> None:
        if value != 1:
            self._deny(f"an SEH handler answered an unwind with disposition {value}, which is not modelled")
            return
        problem = self._frame_problem32(frame)
        if problem:
            self._deny(problem)
            return
        self.write(self.TEB_BASE, struct.pack("<I", self._read_u32(frame)))
        self._unwind_step32(state)

    def _note_peb_read(self, address: int, size: int) -> None:
        """Log a read of a debugger-detection field of the PEB (answered as on a clean host)."""
        for offset, width, field_name, answered in ((0x02, 1, "BeingDebugged", "0 (not present)"),
                                                    (0x68, 4, "NtGlobalFlag", "0 (no heap debug flags)")):
            start = self.peb + offset
            if address < start + width and start < address + size:
                event = AntiDebugEvent("PEB", field_name, answered)
                trace = getattr(self.environment, "anti_debug", None)
                if trace is not None:
                    trace.append(event)
                    self.anti_debug_trace = list(trace)
                else:
                    self.anti_debug_trace.append(event)

    # ------------------------------------------------------------- VEH single-step delivery
    def _maybe_single_step(self, address: int) -> None:
        if not len(self._veh) or self._state.get("in_veh"):
            return
        if not (self.read_register("rflags") & self.TRAP_FLAG):
            return
        self.single_step_trace.append(address)
        self._state["veh_ctx"] = {"resume": address, "index": 0}
        self._enter_veh_handler(address)

    def _enter_veh_handler(self, address: int) -> None:
        context = self._state["veh_ctx"]
        handlers = self._veh.handlers()
        index = int(context["index"])
        if index >= len(handlers):
            self._deny("unhandled single-step exception (no VEH continued execution)")
            return
        handler = handlers[index]
        mask = 0xFFFFFFFFFFFFFFFF
        record_at = self.SCRATCH_BASE
        context_at = self.SCRATCH_BASE + 0x80
        pointers_at = self.SCRATCH_BASE + 0x200
        self._state["veh_context_at"] = context_at
        if index == 0:
            # Build the exception frame once; a CONTINUE_SEARCH handler's edits to CONTEXT persist to
            # the next handler in the chain (the CPU does not re-materialise it between handlers).
            # EXCEPTION_RECORD: code, flags, PEXCEPTION_RECORD, ExceptionAddress, NumberParameters.
            self.write(record_at, struct.pack("<IIQQI", self.EXCEPTION_SINGLE_STEP, 0, 0,
                                              address & mask, 0))
            # A single-step is a trap: the CPU clears TF on entry, so the saved CONTEXT (the state the
            # handler resumes into) already has TF cleared and the handler body does not re-trap.
            entry_flags = self.read_register("rflags") & ~self.TRAP_FLAG
            self.write(context_at + self.CONTEXT_EFLAGS_OFFSET,
                       struct.pack("<I", entry_flags & 0xFFFFFFFF))
            self.write(context_at + self.CONTEXT_RIP_OFFSET, struct.pack("<Q", address & mask))
            self.write(pointers_at, struct.pack("<QQ", record_at, context_at))
        rsp = (self.read_register("rsp") - 8) & mask
        if self._region(rsp, 8, self._u.UC_PROT_WRITE) is None:
            self._deny("no room on the stack to deliver the single-step exception")
            return
        self.write(rsp, struct.pack("<Q", self.veh_trampoline))
        self.write_register("rsp", rsp)
        self.write_register("rcx", pointers_at)
        self.write_register("rflags", self.read_register("rflags") & ~self.TRAP_FLAG)
        self._state["in_veh"] = True
        self.write_register("rip", handler)

    def _veh_return(self) -> None:
        verdict = self.read_register("rax") & 0xFFFFFFFF
        context = self._state.get("veh_ctx") or {}
        if verdict == self.EXCEPTION_CONTINUE_EXECUTION:
            self._state["in_veh"] = False
            self._state["veh_handled"] = int(self._state.get("veh_handled", 0)) + 1
            # Resume from the CONTEXT the handler leaves behind, not the original fault: an anti-debug
            # VEH that advances Rip past junk or clears flags through CONTEXT is honoured here.
            context_at = int(self._state.get("veh_context_at", 0))
            resume_rip = int.from_bytes(self.read(context_at + self.CONTEXT_RIP_OFFSET, 8), "little")
            resume_flags = int.from_bytes(self.read(context_at + self.CONTEXT_EFLAGS_OFFSET, 4),
                                          "little")
            self.write_register("rip", resume_rip)
            self.write_register("rflags",
                                (self.read_register("rflags") & ~0xFFFFFFFF) | resume_flags)
            return
        context["index"] = int(context.get("index", 0)) + 1
        self._state["veh_ctx"] = context
        self._enter_veh_handler(int(context.get("resume", 0)))

    def _hook_memory(self, _uc, access: int, address: int, size: int, value: int, _user) -> None:
        accesses = int(self._state.get("memory_accesses", 0)) + 1
        self._state["memory_accesses"] = accesses
        if accesses > int(self._state["memory_cap"]):
            self._deny("memory-access budget exceeded")
            return
        write_access = access in self._state.get("write_accesses", ())
        if write_access:
            if self._region(address, size, self._u.UC_PROT_WRITE) is None:
                if not self._access_violation32(1, address):
                    self._deny(f"write to a non-writable region at {address:#x}")
            else:
                self._mark_defined(address, size)
                self._mark_written(address, size)
        elif not self._is_defined(address, size):
            if self._region(address, size) is not None or not self._access_violation32(0, address):
                self._deny(f"read of unmapped or undefined memory at {address:#x}")
        elif self.bits == 32 and self.peb <= address < self.peb + 0x6C:
            self._note_peb_read(address, size)

    def _access_violation32(self, kind: int, address: int) -> bool:
        """Raise the access violation Windows reports for this fault, if it is one Windows must
        raise: any access to the null page, or a write to an image page mapped without write.
        False when it is not (another unmapped address may be mapped in a real process)."""
        if self.bits != 32:
            return False
        offset = address - self.pe.load_base
        if not (0 <= address < NULL_PAGE_END
                or (kind == 1 and 0 <= offset < len(self._page_perms) * PAGE)):
            return False
        at = address if kind == 8 else int(self._state.get("last_instruction", 0))
        self._raise32(EXCEPTION_ACCESS_VIOLATION, at, at, (kind, address & 0xFFFFFFFF))
        return True

    def _hook_invalid_memory(self, _uc, access: int, address: int, size: int, value: int, _user) -> bool:
        if self.bits == 32:
            unit = self._u
            writes = (getattr(unit, "UC_MEM_WRITE_UNMAPPED", 20), getattr(unit, "UC_MEM_WRITE_PROT", 22))
            fetches = (getattr(unit, "UC_MEM_FETCH_UNMAPPED", 21), getattr(unit, "UC_MEM_FETCH_PROT", 24))
            kind = 1 if access in writes else (8 if access in fetches else 0)
            if self._access_violation32(kind, address):
                return False
        self._deny(f"unmapped/protection memory access denied at {address:#x} ({size} byte(s))")
        return False

    def _hook_interrupt(self, _uc, interrupt: int, _user) -> None:
        if self.bits == 32 and interrupt == 1:
            # The single-step trap: the instruction that ran with TF set has completed.
            at = self.read_register("eip")
            self._raise32(EXCEPTION_SINGLE_STEP, at, at)
            return
        self._deny(f"software interrupt denied: {interrupt}")

    def _hook_syscall(self, _uc, _user) -> None:
        self._deny("syscall/sysenter denied")

    def _hook_invalid_instruction(self, _uc, _user) -> bool:
        self._deny("invalid instruction denied")
        return False

    def _install_hooks(self) -> None:
        self.uc.hook_add(self._u.UC_HOOK_CODE, self._hook_code)
        self.uc.hook_add(self._u.UC_HOOK_MEM_READ | self._u.UC_HOOK_MEM_WRITE, self._hook_memory)
        self.uc.hook_add(self._u.UC_HOOK_MEM_INVALID, self._hook_invalid_memory)
        self.uc.hook_add(self._u.UC_HOOK_INTR, self._hook_interrupt)
        self.uc.hook_add(self._u.UC_HOOK_INSN_INVALID, self._hook_invalid_instruction)
        for name in ("UC_X86_INS_SYSCALL", "UC_X86_INS_SYSENTER"):
            if not hasattr(self._x, name):
                continue
            try:
                self.uc.hook_add(self._u.UC_HOOK_INSN, self._hook_syscall,
                                 begin=1, end=0, aux1=getattr(self._x, name))
            except Exception:
                # The code hook disassembles and denies both before execution even on a
                # Unicorn build that lacks the specialized instruction hook.
                pass

    def write_register(self, name: str, value: int) -> None:
        registers = self._registers()
        key = name.lower()
        if key not in registers:
            raise EmulationDenied(f"unknown x86-64 register {name!r}" if self.bits == 64
                                  else f"unknown x86 register {name!r}")
        width = 128 if key.startswith("xmm") else self.bits
        self.uc.reg_write(registers[key], int(value) & ((1 << width) - 1))

    def read_register(self, name: str) -> int:
        registers = self._registers()
        key = name.lower()
        if key not in registers:
            raise EmulationDenied(f"unknown x86-64 register {name!r}" if self.bits == 64
                                  else f"unknown x86 register {name!r}")
        return int(self.uc.reg_read(registers[key]))

    def write_memory(self, address: int, data: bytes | bytearray | memoryview) -> None:
        raw = bytes(data)
        if len(raw) > self.SCRATCH_SIZE:
            raise EmulationDenied("one analyst memory write exceeds its cap")
        if self._region(address, len(raw), self._u.UC_PROT_WRITE) is None:
            raise EmulationDenied(f"analyst write outside writable emulated memory at {address:#x}")
        self.uc.mem_write(address, raw)
        self._invalidate_code(address, len(raw))
        self._mark_defined(address, len(raw))

    def read_memory(self, address: int, size: int) -> bytes:
        if size < 0 or size > self.SCRATCH_SIZE or not self._is_defined(address, size):
            raise EmulationDenied(f"analyst read outside defined emulated memory at {address:#x}")
        return bytes(self.uc.mem_read(address, size))

    def run(self, start: int | None = None, *, stop_addresses: Iterable[int] = (),
            registers: Mapping[str, int] | None = None, instruction_cap: int | None = None,
            memory_cap: int | None = None, wall_seconds: float | None = None,
            stop_on_written_exec: bool = False) -> RunResult:
        """Run from ``start`` to an approved stop: the return sentinel (``return``), a requested
        site (``site``), ExitProcess (``exit``) or, with ``stop_on_written_exec``, the first
        instruction fetched from image bytes this harness saw written (``written-exec``)."""
        if stop_on_written_exec and self.image_written is None:
            raise EmulationDenied("write tracking is off: build the harness with track_image_writes=True")
        if registers:
            for name, value in registers.items():
                self.write_register(name, value)
        start = self.pe.entry if start is None else int(start)
        stops = frozenset(int(value) for value in stop_addresses)
        if any(self._region(value, 1, self._u.UC_PROT_EXEC) is None for value in stops):
            raise EmulationDenied("a requested stop address is not executable mapped PE code")
        icap = self.instruction_cap if instruction_cap is None else int(instruction_cap)
        mcap = self.memory_cap if memory_cap is None else int(memory_cap)
        wcap = self.wall_seconds if wall_seconds is None else float(wall_seconds)
        if icap <= 0 or mcap <= 0 or not (0 < wcap <= self.wall_seconds):
            raise EmulationDenied("a per-run budget is invalid or widens the harness cap")
        begun = self._clock()
        read_access = getattr(self._u, "UC_MEM_READ", 16)
        write_accesses = tuple(value for value in (
            getattr(self._u, "UC_MEM_WRITE", None), getattr(self._u, "UC_MEM_WRITE_UNMAPPED", None),
            getattr(self._u, "UC_MEM_WRITE_PROT", None)) if value is not None)
        self._state = {
            "instructions": 0, "memory_accesses": 0, "violation": None, "stop": None,
            "stop_addresses": stops, "instruction_cap": icap, "memory_cap": mcap,
            "deadline": begun + wcap, "read_access": read_access, "write_accesses": write_accesses,
            "stop_written": bool(stop_on_written_exec), "pending": None,
        }
        self.write_register(self._ip, start)
        while True:
            aborted = None
            try:
                self.uc.emu_start(start, self.pe.load_base + len(self.pe.image),
                                  timeout=max(1, int(wcap * 1_000_000)), count=icap + 1)
            except Exception as exc:
                aborted = exc
            pending = self._state.get("pending")
            self._state["pending"] = None
            if self._state.get("violation") or self._state.get("stop") or pending is None:
                if aborted is not None and not self._state.get("violation"):
                    self._state["violation"] = f"Unicorn aborted: {type(aborted).__name__}: {aborted}"
                break
            # An x86 exception or a return into the exception dispatcher: carry it out with the
            # engine stopped, then resume wherever it left the instruction pointer.
            try:
                pending()
            except EmulationDenied as exc:
                self._deny(str(exc))
            if self._state.get("violation") or self._state.get("stop"):
                break
            start = self.read_register(self._ip)
        elapsed = max(0.0, self._clock() - begun)
        if self._state.get("violation"):
            raise EmulationDenied(str(self._state["violation"]))
        stop = self._state.get("stop")
        if not stop:
            reason = "wall-time cap" if elapsed >= wcap else "instruction cap or unmodelled stop"
            raise EmulationDenied(f"emulation ended without an approved stop ({reason})")
        return RunResult(str(stop[0]), int(stop[1]), int(self._state["instructions"]),
                         int(self._state["memory_accesses"]), elapsed)

    def call(self, target: int, args: Iterable[int] = (), *, stop_addresses: Iterable[int] = (),
             instruction_cap: int | None = None, memory_cap: int | None = None,
             wall_seconds: float | None = None) -> RunResult:
        """Run ``target`` as a Windows x64 function and return when it returns to the sentinel.

        ``args`` are placed in RCX/RDX/R8/R9 and (beyond four) above the 32-byte shadow space; a
        fresh frame is set up with the return sentinel as the caller.  This is how TLS callbacks
        and VEH handlers are driven.  The usual deny hooks and caps apply unchanged.
        """
        if self.bits == 32:
            # Win32: every argument on the stack, first argument lowest; the callee may clean up.
            words = tuple(int(a) & 0xFFFFFFFF for a in args)
            if len(words) > 32:
                raise EmulationDenied("more than 32 stack arguments")
            esp = ((self.STACK_BASE + self.STACK_SIZE - 0x200) & ~0xF) - 4 * len(words) - 4
            self.write(esp, struct.pack("<I", self.return_sentinel)
                       + b"".join(struct.pack("<I", word) for word in words))
            self.write_register("esp", esp)
            return self.run(int(target), stop_addresses=stop_addresses,
                            instruction_cap=instruction_cap, memory_cap=memory_cap,
                            wall_seconds=wall_seconds)
        mask = 0xFFFFFFFFFFFFFFFF
        values = tuple(int(a) & mask for a in args)
        order = ("rcx", "rdx", "r8", "r9")
        rsp = (self.STACK_BASE + self.STACK_SIZE - 0x200) & ~0xF
        for offset, value in enumerate(values[4:]):
            self.write(rsp + 0x28 + offset * 8, struct.pack("<Q", value))
        self.write(rsp, struct.pack("<Q", self.return_sentinel))
        self.write_register("rsp", rsp)
        reg_args = {order[index]: values[index] for index in range(min(4, len(values)))}
        return self.run(int(target), stop_addresses=stop_addresses, registers=reg_args,
                        instruction_cap=instruction_cap, memory_cap=memory_cap,
                        wall_seconds=wall_seconds)

    def run_tls_callbacks(self, *, reason: int = 1, instruction_cap: int | None = None,
                          memory_cap: int | None = None,
                          wall_seconds: float | None = None) -> tuple[RunResult, ...]:
        """Call every TLS callback in order with (DllHandle=load_base, reason, Reserved=0).

        Windows runs these before the entry point (the ``.CRT$XC`` initializers and TLS
        callbacks are a classic anti-analysis hiding spot).  Returns one RunResult per callback;
        an image with no TLS directory returns an empty tuple.
        """
        tls = parse_tls(self.pe)
        results: list[RunResult] = []
        for callback in tls.callbacks:
            results.append(self.call(callback, args=(self.pe.load_base, reason, 0),
                                     instruction_cap=instruction_cap, memory_cap=memory_cap,
                                     wall_seconds=wall_seconds))
        return tuple(results)

    _IMAGE_ROW = "image+"

    def _image_page_rows(self) -> list[tuple[int, int]]:
        """(offset, size) of each run of image pages writable at some time since mapping."""
        rows: list[tuple[int, int]] = []
        for offset, size, ever in _page_runs([int(flag) for flag in self._ever_writable]):
            if ever:
                rows.append((offset, size))
        return rows

    def snapshot(self) -> Snapshot:
        memory: list[MemorySnapshot] = []
        total = 0
        for region in self._regions:
            if region.name.startswith("image:") or not region.permissions & self._u.UC_PROT_WRITE:
                continue
            total += region.size
            if total > self.snapshot_cap:
                raise EmulationDenied("mutable emulated state exceeds the snapshot cap")
            defined = bytes(self._defined[region.name]) if region.defined_mask else None
            memory.append(MemorySnapshot(region.name, region.start,
                                         bytes(self.uc.mem_read(region.start, region.size)), defined))
        # Every image page that has ever been writable, whatever its protection now: one made
        # writable, written and protected again after mapping holds bytes the mapped copy lacks.
        for offset, size in self._image_page_rows():
            total += size
            if total > self.snapshot_cap:
                raise EmulationDenied("mutable emulated state exceeds the snapshot cap")
            start = self.pe.load_base + offset
            memory.append(MemorySnapshot(f"{self._IMAGE_ROW}{offset:08x}", start,
                                         bytes(self.uc.mem_read(start, size)), None))
        registers = tuple((name, self.read_register(name)) for name in sorted(self._registers()))
        veh, next_cookie = self._veh.state()
        return Snapshot(self.pe.image_sha256, registers, tuple(memory), tuple(self._page_perms),
                        self._heap_ptr, tuple(sorted(self.model_state.items(), key=repr)),
                        bytes(self.image_written) if self.image_written is not None else None,
                        veh, next_cookie, self._mapped_sha256)

    def restore(self, snapshot: Snapshot) -> None:
        if snapshot.image_sha256 != self.pe.image_sha256:
            raise EmulationDenied("snapshot belongs to a different mapped PE")
        if snapshot.mapped_sha256 != self._mapped_sha256:
            raise EmulationDenied("snapshot was taken from an image mapped differently (import "
                                  "slots or delay binding differ)")
        if len(snapshot.page_perms) != len(self._page_perms):
            raise EmulationDenied("snapshot image page protections do not match the harness")
        if snapshot.heap_ptr is None or not (
                self.HEAP_BASE <= snapshot.heap_ptr <= self.HEAP_BASE + self.HEAP_SIZE):
            raise EmulationDenied("snapshot heap cursor is missing or outside the heap")
        if (self.image_written is None) != (snapshot.image_written is None) or (
                snapshot.image_written is not None
                and len(snapshot.image_written) != len(self.image_written)):
            raise EmulationDenied("snapshot write tracking does not match the harness")
        valid = {self._u.UC_PROT_READ, self._u.UC_PROT_WRITE, self._u.UC_PROT_EXEC}
        if any(value & ~(sum(valid)) for value in snapshot.page_perms):
            raise EmulationDenied("snapshot image page protection is not a permission set")
        # Image rows: page-aligned runs inside the image, each named by its own offset.
        pages = len(self._page_perms)
        ever = [False] * pages
        image_rows: list[MemorySnapshot] = []
        other_rows: list[MemorySnapshot] = []
        for row in snapshot.memory:
            if not row.name.startswith(self._IMAGE_ROW):
                other_rows.append(row)
                continue
            try:
                offset = int(row.name[len(self._IMAGE_ROW):], 16)
            except ValueError:
                raise EmulationDenied("snapshot image row is not named by its offset") from None
            if (offset % PAGE or len(row.data) % PAGE or not row.data
                    or row.start != self.pe.load_base + offset
                    or offset + len(row.data) > pages * PAGE or row.defined is not None):
                raise EmulationDenied("snapshot image row does not fit the mapped image")
            for index in range(offset // PAGE, (offset + len(row.data)) // PAGE):
                if ever[index]:
                    raise EmulationDenied("snapshot image rows overlap")
                ever[index] = True
            image_rows.append(row)
        if any(value & self._u.UC_PROT_WRITE and not ever[index]
               for index, value in enumerate(snapshot.page_perms)):
            raise EmulationDenied("snapshot omits the bytes of a writable image page")
        writable = {region.name: region for region in self._regions
                    if region.permissions & self._u.UC_PROT_WRITE
                    and not region.name.startswith("image:")}
        if set(writable) != {row.name for row in other_rows} or len(other_rows) != len(writable):
            raise EmulationDenied("snapshot memory layout does not match the harness")
        for row in other_rows:
            region = writable[row.name]
            if row.start != region.start or len(row.data) != region.size:
                raise EmulationDenied("snapshot memory range does not match the harness")
            if region.defined_mask:
                if row.defined is None or len(row.defined) != region.size:
                    raise EmulationDenied("snapshot definedness mask is missing or malformed")
            elif row.defined is not None:
                raise EmulationDenied("snapshot unexpectedly masks image memory")
        veh = self._veh_from_snapshot(snapshot)
        # Validated: apply.  Image pages the snapshot does not carry were never writable in the
        # harness it came from, so they hold the mapped bytes; this harness may have written them
        # since (a page made writable after the snapshot), so the whole image is reset first.
        if list(snapshot.page_perms) != self._page_perms:
            self._apply_page_perms(list(snapshot.page_perms))
        self.uc.mem_write(self.pe.load_base, self._pristine)
        for row in image_rows:
            self.uc.mem_write(row.start, row.data)
        self._ever_writable = ever
        for row in other_rows:
            self.uc.mem_write(row.start, row.data)
            if row.defined is not None:
                self._defined[row.name][:] = row.defined
        for name, value in snapshot.registers:
            self.write_register(name, value)
        self._heap_ptr = int(snapshot.heap_ptr)
        self.model_state = dict(snapshot.model_state)
        if snapshot.image_written is not None:
            self.image_written[:] = snapshot.image_written
        self._veh = veh
        # The engine keeps translated blocks of code it ran; the memory written back is not
        # guest-written, so nothing invalidates them.  Without this a replay runs stale code.
        self._flush_translations()

    def _veh_from_snapshot(self, snapshot: Snapshot) -> "VehChain":
        try:
            chain = VehChain.from_state(snapshot.veh, snapshot.veh_next_cookie)
        except (WindowsModelError, TypeError, ValueError) as exc:
            raise EmulationDenied(f"snapshot vectored-handler chain is malformed: {exc}") from None
        return chain

    def _flush_translations(self) -> None:
        flush = getattr(self.uc, "ctl_flush_tb", None)
        if flush is None:
            raise EmulationDenied("the engine cannot drop its translated code (no ctl_flush_tb): "
                                  "a restore could run stale instructions")
        flush()

    def _invalidate_code(self, address: int, size: int) -> None:
        """Drop translated code over a host write into the image (guest writes the engine sees)."""
        start, end = self.pe.load_base, self.pe.load_base + _align(len(self._pristine))
        low, high = max(address, start), min(address + size, end)
        if low >= high:
            return
        remove = getattr(self.uc, "ctl_remove_cache", None)
        if remove is None:
            raise EmulationDenied("the engine cannot drop translated code (no ctl_remove_cache): "
                                  "a write into the image could leave stale instructions")
        remove(low, high)

    def fork(self, snapshot: Snapshot | None = None) -> "SafeUnicorn":
        child = type(self)(self.pe, instruction_cap=self.instruction_cap, memory_cap=self.memory_cap,
                           wall_seconds=self.wall_seconds, snapshot_cap=self.snapshot_cap,
                           backend=self._backend, clock=self._clock, environment=self.environment,
                           bind_delay_imports=self.bind_delay_imports,
                           track_image_writes=self.image_written is not None)
        child.restore(self.snapshot() if snapshot is None else snapshot)
        return child

    def observe_compare(self, site: CompareSite) -> tuple[OperandValue, ...]:
        """Read the explicit operands at a stopped CMP/TEST site without executing it."""
        if self.read_register(self._ip) != site.address:
            raise EmulationDenied("the harness is not stopped at the requested compare site")
        instructions = tuple(self._compare_engine.disasm(site.encoding, site.address, 1))
        if len(instructions) != 1 or instructions[0].mnemonic.lower() not in ("cmp", "test"):
            raise EmulationDenied("site is not one explicit two-operand CMP/TEST instruction")
        instruction = instructions[0]
        try:
            from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
        except Exception as exc:
            raise EmulationDenied("Capstone x86 operand constants are unavailable") from exc
        out: list[OperandValue] = []
        for operand in instruction.operands:
            size = int(operand.size)
            if not 0 < size <= 16:
                raise EmulationDenied("compare operand width is unsupported")
            mask = (1 << (size * 8)) - 1
            if operand.type == X86_OP_IMM:
                out.append(OperandValue("immediate", size, int(operand.imm) & mask))
            elif operand.type == X86_OP_REG:
                name = instruction.reg_name(operand.reg).lower()
                attr = "UC_X86_REG_" + name.upper()
                if not hasattr(self._x, attr):
                    raise EmulationDenied(f"compare register {name!r} is not exposed by Unicorn")
                value = int(self.uc.reg_read(getattr(self._x, attr))) & mask
                out.append(OperandValue("register", size, value, register=name))
            elif operand.type == X86_OP_MEM:
                mem = operand.mem
                address = int(mem.disp)
                if mem.base:
                    base_name = instruction.reg_name(mem.base).lower()
                    if base_name == "rip":
                        address += site.address + site.size
                    else:
                        attr = "UC_X86_REG_" + base_name.upper()
                        if not hasattr(self._x, attr):
                            raise EmulationDenied(f"compare base register {base_name!r} is unsupported")
                        address += int(self.uc.reg_read(getattr(self._x, attr)))
                if mem.index:
                    index_name = instruction.reg_name(mem.index).lower()
                    attr = "UC_X86_REG_" + index_name.upper()
                    if not hasattr(self._x, attr):
                        raise EmulationDenied(f"compare index register {index_name!r} is unsupported")
                    address += int(self.uc.reg_read(getattr(self._x, attr))) * int(mem.scale)
                if mem.segment:
                    segment = instruction.reg_name(mem.segment).lower()
                    if segment == "fs" and self.bits == 32:
                        address += self.TEB_BASE
                    elif segment in ("fs", "gs") and self.bits == 64:
                        address += self.read_register(segment + "_base")
                    elif segment not in ("", "ds", "es", "ss", "cs"):
                        raise EmulationDenied(f"compare segment {segment!r} is unsupported")
                address &= self._mask
                value = int.from_bytes(self.read_memory(address, size), "little")
                out.append(OperandValue("memory", size, value, address=address))
            else:
                raise EmulationDenied("compare operand kind is unsupported")
        return tuple(out)


# =========================================================================== Windows process model
# The deep-RE layer (B-148): the Windows behaviours SHA1-Hulud needed modelled -- TLS init, a VEH
# single-step trap, VirtualAlloc/HeapSize/LastError, an exact LZNT1 blob, dynamic API resolution and
# native NtQuery* results -- plus an anti-debug trace log and answer selection through B-165's pinned
# acceptance gate.  It drives SafeUnicorn (and a test's dict fake) through the abstract Machine
# interface, so the semantics are tested with no native engine.  An unmodelled API is never faked:
# WindowsEnvironment.handles returns False and the harness denies the call by name.


class Lznt1Error(ValueError):
    """The bytes are not one well-formed LZNT1 stream this decompressor supports."""


class WindowsModelError(RuntimeError):
    """A modelled Windows behaviour could not be carried out inside its bounds."""


MASK64 = (1 << 64) - 1
MASK32 = (1 << 32) - 1
MAX_TLS_CALLBACKS = 256
MAX_DECOMPRESSED = 64 << 20           # RtlDecompressBuffer output ceiling (fail closed over it)
MAX_COMPRESSED = 64 << 20

COMPRESSION_FORMAT_NONE = 0
COMPRESSION_FORMAT_LZNT1 = 2


def _lznt1_decompress_chunk(chunk: bytes) -> bytes:
    """Decode one *compressed* LZNT1 chunk (flag groups of eight tokens).

    Each flag byte is read LSB-first: a 0 bit copies one literal, a 1 bit is a two-byte
    little-endian phrase token whose (length, displacement) split widens as the chunk's
    decompressed output grows -- the exact NT rule used by RtlDecompressBuffer.
    """
    out = bytearray()
    index = 0
    size = len(chunk)
    while index < size:
        flags = chunk[index]
        index += 1
        for _ in range(8):
            if index >= size:
                return bytes(out)
            if not (flags & 1):
                out.append(chunk[index])
                index += 1
            else:
                if index + 2 > size:
                    raise Lznt1Error("truncated LZNT1 phrase token")
                phrase = chunk[index] | (chunk[index + 1] << 8)
                index += 2
                pos = len(out) - 1
                length_mask = 0x0FFF
                offset_shift = 12
                while pos >= 0x10:
                    pos >>= 1
                    length_mask >>= 1
                    offset_shift -= 1
                length = (phrase & length_mask) + 3
                displacement = (phrase >> offset_shift) + 1
                start = len(out) - displacement
                if start < 0:
                    raise Lznt1Error("LZNT1 back-reference points before the chunk start")
                for step in range(length):
                    out.append(out[start + step])
                    if len(out) > MAX_DECOMPRESSED:
                        raise Lznt1Error("LZNT1 output exceeds its ceiling")
            flags >>= 1
            if len(out) > MAX_DECOMPRESSED:
                raise Lznt1Error("LZNT1 output exceeds its ceiling")
    return bytes(out)


def lznt1_decompress(data: bytes | bytearray | memoryview) -> bytes:
    """Decompress an NT LZNT1 buffer (a series of 4 KiB chunks) to its original bytes.

    A chunk header is two little-endian bytes: the low 12 bits are ``size - 1`` of the chunk
    data, the three signature bits are ``0b011`` and the top bit flags a compressed chunk.
    A zero header (or running out of input mid-header) ends the stream.  Malformed headers,
    truncated chunks and out-of-range back-references raise :class:`Lznt1Error` rather than
    guessing -- this is evidence tooling, never a repair tool.
    """
    raw = bytes(data)
    if len(raw) > MAX_COMPRESSED:
        raise Lznt1Error("LZNT1 input exceeds its ceiling")
    out = bytearray()
    index = 0
    total = len(raw)
    while index + 1 < total:
        header = raw[index] | (raw[index + 1] << 8)
        index += 2
        if header == 0:
            break
        if (header & 0x7000) != 0x3000:
            raise Lznt1Error(f"LZNT1 chunk signature bits are not 0b011: {header:#06x}")
        chunk_size = (header & 0x0FFF) + 1
        compressed = bool(header & 0x8000)
        if index + chunk_size > total:
            raise Lznt1Error("LZNT1 chunk extends past the input")
        chunk = raw[index:index + chunk_size]
        index += chunk_size
        if compressed:
            out += _lznt1_decompress_chunk(chunk)
        else:
            out += chunk
        if len(out) > MAX_DECOMPRESSED:
            raise Lznt1Error("LZNT1 output exceeds its ceiling")
    return bytes(out)


def lznt1_compress_stored(data: bytes) -> bytes:
    """Emit ``data`` as LZNT1 *stored* (uncompressed) chunks.

    Not an optimizing compressor -- it only produces well-formed, verifiable LZNT1 that
    :func:`lznt1_decompress` round-trips, so tests can build inputs without hand-encoding tokens.
    """
    out = bytearray()
    for start in range(0, len(data), 0x1000):
        block = data[start:start + 0x1000]
        header = 0x3000 | (len(block) - 1)
        out += struct.pack("<H", header)
        out += block
    return bytes(out)


class Machine(Protocol):
    """The sandbox surface the Windows model drives; ``SafeUnicorn`` and a test fake supply it."""

    def read(self, address: int, size: int) -> bytes: ...
    def write(self, address: int, data: bytes) -> None: ...
    def reg(self, name: str) -> int: ...
    def setreg(self, name: str, value: int) -> None: ...
    def alloc(self, size: int) -> int: ...
    def add_veh(self, first: bool, handler: int) -> int: ...
    def remove_veh(self, cookie: int) -> bool: ...


_ARG_REGS = ("rcx", "rdx", "r8", "r9")


def win64_arg(machine: "Machine", index: int) -> int:
    """The ``index``-th integer argument under the Windows x64 calling convention.

    Args 0..3 are RCX/RDX/R8/R9; args 4+ are on the stack above the 32-byte shadow space
    (``[rsp + 8 + 8*index]`` at function entry, the return address at ``[rsp]``).
    """
    if index < 0:
        raise WindowsModelError("argument index must be non-negative")
    if index < 4:
        return machine.reg(_ARG_REGS[index]) & MASK64
    rsp = machine.reg("rsp")
    return int.from_bytes(machine.read(rsp + 8 + 8 * index, 8), "little")


def machine_bits(machine: "Machine") -> int:
    """32 for a machine that declares ``pointer_bits == 32`` (a PE32 sandbox), else 64."""
    return 32 if getattr(machine, "pointer_bits", 64) == 32 else 64


def machine_mask(machine: "Machine") -> int:
    """The all-ones value of the machine's pointer width."""
    return MASK32 if machine_bits(machine) == 32 else MASK64


def api_arg(machine: "Machine", index: int) -> int:
    """The ``index``-th integer argument of a Windows API call on the machine's own ABI.

    x86-64: :func:`win64_arg`.  x86 (stdcall and cdecl alike): every argument is a 32-bit stack
    slot, ``[esp + 4 + 4*index]`` at function entry with the return address at ``[esp]``.
    """
    if machine_bits(machine) == 64:
        return win64_arg(machine, index)
    if index < 0:
        raise WindowsModelError("argument index must be non-negative")
    esp = machine.reg("esp")
    return int.from_bytes(machine.read((esp + 4 + 4 * index) & MASK32, 4), "little")


@dataclass(frozen=True)
class AntiDebugEvent:
    """One debugger-detection probe the model answered benignly."""

    api: str
    query: str
    answered: str


@dataclass
class _VehEntry:
    cookie: int
    handler: int


class VehChain:
    """The vectored-exception-handler chain: registration order and dispatch semantics.

    ``add(first, handler)`` inserts at the front when ``first`` else at the back and returns a
    non-zero cookie (the handle ``RtlAddVectoredExceptionHandler`` hands back).  ``remove`` takes a
    cookie.  ``dispatch`` walks the chain in order, asking ``verdict(handler)`` for each until one
    returns ``EXCEPTION_CONTINUE_EXECUTION``; it returns that handler, or None when every handler
    returned ``EXCEPTION_CONTINUE_SEARCH`` (an unhandled exception).
    """

    EXCEPTION_CONTINUE_SEARCH = 0x00000000
    EXCEPTION_CONTINUE_EXECUTION = 0xFFFFFFFF

    def __init__(self) -> None:
        self._entries: list[_VehEntry] = []
        self._next_cookie = 1

    def __len__(self) -> int:
        return len(self._entries)

    def handlers(self) -> tuple[int, ...]:
        return tuple(entry.handler for entry in self._entries)

    def add(self, first: bool, handler: int) -> int:
        if not isinstance(handler, int) or handler <= 0:
            raise WindowsModelError("a VEH handler must be a non-null address")
        cookie = self._next_cookie
        self._next_cookie += 1
        entry = _VehEntry(cookie, int(handler) & MASK64)
        if first:
            self._entries.insert(0, entry)
        else:
            self._entries.append(entry)
        return cookie

    def remove(self, cookie: int) -> bool:
        for index, entry in enumerate(self._entries):
            if entry.cookie == cookie:
                del self._entries[index]
                return True
        return False

    def state(self) -> tuple[tuple[tuple[int, int], ...], int]:
        """The chain as plain values: ((cookie, handler), ...) in dispatch order, and the next cookie."""
        return tuple((entry.cookie, entry.handler) for entry in self._entries), self._next_cookie

    @classmethod
    def from_state(cls, entries, next_cookie: int) -> "VehChain":
        """Rebuild a chain from :meth:`state`; a cookie that is not positive, repeats or is not
        below the next cookie, or a null handler, is refused."""
        chain = cls()
        if not isinstance(next_cookie, int) or isinstance(next_cookie, bool) or next_cookie < 1:
            raise WindowsModelError("the next VEH cookie is not a positive integer")
        seen: set[int] = set()
        for cookie, handler in entries:
            if (not isinstance(cookie, int) or not isinstance(handler, int)
                    or not 0 < cookie < next_cookie or cookie in seen or handler <= 0):
                raise WindowsModelError("a VEH entry has a bad cookie or a null handler")
            seen.add(cookie)
            chain._entries.append(_VehEntry(cookie, handler & MASK64))
        chain._next_cookie = next_cookie
        return chain

    def dispatch(self, verdict: Callable[[int], int]) -> int | None:
        for entry in self._entries:
            if (int(verdict(entry.handler)) & MASK32) == self.EXCEPTION_CONTINUE_EXECUTION:
                return entry.handler
        return None


IMAGE_DIRECTORY_ENTRY_TLS = 9


@dataclass(frozen=True)
class TlsImage:
    """The parsed TLS directory of a mapped PE (absolute addresses, at the image's load base)."""

    index_address: int | None
    callbacks: tuple[int, ...]
    raw_data_start: int
    raw_data_end: int
    size_of_zero_fill: int

    @property
    def has_callbacks(self) -> bool:
        return bool(self.callbacks)


def parse_tls(pe: MappedPE) -> TlsImage:
    """Parse the TLS data directory of a :class:`MappedPE`.

    The directory's pointer fields are VAs; because ``map_pe`` already relocated the image to its
    load base, a stored pointer equals ``load_base + rva``.  The callback array is a null-terminated
    list of such VAs.  Returns absolute addresses so the harness can call each callback directly.
    An out-of-image pointer raises :class:`PEError`.
    """
    directory = pe.directory(IMAGE_DIRECTORY_ENTRY_TLS)
    if not directory.rva and not directory.size:
        return TlsImage(None, (), 0, 0, 0)
    width = 8 if pe.is_64 else 4
    header_size = 4 * width + 8          # four pointers of the PE's width, then two DWORDs
    raw = pe.rva_bytes(directory.rva, header_size)
    if pe.is_64:
        start, end, index_va, callbacks_va = struct.unpack_from("<QQQQ", raw, 0)
        zero_fill = struct.unpack_from("<I", raw, 32)[0]
    else:
        start, end, index_va, callbacks_va = struct.unpack_from("<IIII", raw, 0)
        zero_fill = struct.unpack_from("<I", raw, 16)[0]

    base = pe.load_base
    image_len = len(pe.image)

    def _to_rva(va: int, what: str) -> int:
        rva = va - base
        if rva < 0 or rva >= image_len:
            raise PEError(f"TLS {what} VA {va:#x} is outside the mapped image")
        return rva

    callbacks: list[int] = []
    if callbacks_va:
        cursor = _to_rva(callbacks_va, "callback array")
        while True:
            if len(callbacks) >= MAX_TLS_CALLBACKS:
                raise PEError("TLS callback array exceeds its cap")
            entry = int.from_bytes(pe.rva_bytes(cursor, width), "little")
            if entry == 0:
                break
            _to_rva(entry, "callback")
            callbacks.append(entry)
            cursor += width

    index_address = None
    if index_va:
        _to_rva(index_va, "index")
        index_address = index_va
    return TlsImage(index_address, tuple(callbacks), start, end, zero_fill)


STATUS_SUCCESS = 0x00000000
STATUS_PORT_NOT_SET = 0xC0000353
STATUS_UNSUPPORTED_COMPRESSION = 0xC000025F
STATUS_INFO_LENGTH_MISMATCH = 0xC0000004

HEAP_ZERO_MEMORY = 0x00000008

PROCESS_DEBUG_PORT = 7
PROCESS_DEBUG_OBJECT_HANDLE = 0x1E
PROCESS_DEBUG_FLAGS = 0x1F
SYSTEM_KERNEL_DEBUGGER_INFORMATION = 0x23

_PSEUDO_HEAP_HANDLE = 0x00A70000
_PSEUDO_MODULE_BASE = 0x7FFD00000000
_PSEUDO_PROC_BASE = 0x7FFD40000000
_PSEUDO_MODULE_BASE32 = 0x79000000      # PE32: never mapped by the sandbox, below the TEB
_PSEUDO_PROC_BASE32 = 0x7A000000

STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE = -10, -11, -12
_PSEUDO_STDIN, _PSEUDO_STDOUT, _PSEUDO_STDERR = 0x3, 0x7, 0xB    # the classic console handle values
MAX_STREAM = 1 << 20                    # bytes the modelled stdout / stderr keep
MAX_API_STRING = 1 << 16                # longest string a modelled string API scans
ERROR_INVALID_HANDLE = 6
ERROR_INVALID_PARAMETER = 87

# Number of 4-byte stack arguments of each modelled API under Win32 stdcall (the callee pops them).
_STDCALL_ARGS = {
    "virtualalloc": 4, "virtualfree": 3, "virtualprotect": 4, "getprocessheap": 0, "heapalloc": 3,
    "heaprealloc": 4, "heapfree": 3, "heapsize": 3, "getlasterror": 0, "setlasterror": 1,
    "isdebuggerpresent": 0, "checkremotedebuggerpresent": 2, "ntqueryinformationprocess": 5,
    "ntquerysysteminformation": 4, "rtldecompressbuffer": 6, "loadlibrarya": 1, "loadlibraryw": 1,
    "getmodulehandlea": 1, "getmodulehandlew": 1, "getprocaddress": 2, "rtlgetversion": 1,
    "sleep": 1, "gettickcount": 0, "queryperformancecounter": 1, "getsystemtimeasfiletime": 1,
    "rtladdvectoredexceptionhandler": 2, "rtlremovevectoredexceptionhandler": 1,
    "addvectoredexceptionhandler": 2, "removevectoredexceptionhandler": 1,
    "getcurrentprocess": 0, "getcurrentthread": 0, "getstdhandle": 1, "writefile": 5,
    "writeconsolea": 5, "readfile": 5, "getcommandlinea": 0, "getcommandlinew": 0,
    "exitprocess": 1, "lstrlena": 1, "lstrlenw": 1, "lstrcpya": 2, "lstrcata": 2,
    "rtlmovememory": 3, "rtlzeromemory": 2, "rtlfillmemory": 3, "rtlunwind": 4,
}


@dataclass
class WindowsEnvironment:
    """A modelled Windows user-mode environment for the closed harness.

    Instead of denying every imported call, the harness asks this model to carry a *subset* of APIs
    with their real observable effect: memory from VirtualAlloc/HeapAlloc, the size remembered by
    HeapSize, the LastError cell, the benign answers to debugger probes, an exact LZNT1
    decompression, and dynamic resolution bookkeeping.  Everything it touches goes through the
    :class:`Machine`, so the sandbox stays the single source of memory truth.

    ``anti_debug`` accumulates every debugger-detection probe; ``resolved`` records each
    GetProcAddress/LoadLibrary lookup; ``allocations`` maps each live base to the size HeapSize
    should report.  None of these is a solver answer.

    The model serves both ABIs (B-241): a machine that declares ``pointer_bits == 32`` is read as
    Win32 stdcall (:func:`api_arg`), with pointer-sized answers four bytes wide.  ``stdin`` is the
    input ReadFile hands the program, ``stdout`` / ``stderr`` collect what it writes to its
    standard handles, ``command_line`` is what GetCommandLine returns and ``exit_code`` is set by
    ExitProcess; ``resolved_addresses`` maps each pseudo-address GetProcAddress returned to its
    ``(dll, name)``, so a dump can name the slots a stub rebuilt.
    """

    os_version: tuple[int, int, int] = (10, 0, 19041)
    last_error: int = 0
    anti_debug: list = field(default_factory=list)
    resolved: list = field(default_factory=list)
    allocations: dict = field(default_factory=dict)
    loaded_modules: dict = field(default_factory=dict)
    tick: int = 0x00010000
    _perf: int = 0x0100000000
    _filetime: int = 0x01D0000000000000
    stdin: bytes = b""
    stdout: bytearray = field(default_factory=bytearray)
    stderr: bytearray = field(default_factory=bytearray)
    command_line: str = "sample.exe"
    exit_code: int | None = None
    resolved_addresses: dict = field(default_factory=dict)
    _own_state: dict = field(default_factory=dict)
    _start: dict = field(default_factory=dict, init=False, repr=False)

    # Per-process values (see ``_process``) and the attribute that mirrors the latest one set.
    _MIRRORS = {"last_error": "last_error", "tick": "tick", "perf": "_perf", "filetime": "_filetime"}

    def __post_init__(self) -> None:
        # The values every process starts from.  LastError, the tick, performance and file-time
        # counters and the live allocations are per process (a snapshot carries them, so a restore
        # rewinds them); the public attributes only mirror the value a process set last.
        self._start = {key: int(getattr(self, attr)) for key, attr in self._MIRRORS.items()}

    def _value(self, machine: "Machine", key: str) -> int:
        return int(self._process(machine).get(key, self._start[key]))

    def _set_value(self, machine: "Machine", key: str, value: int) -> None:
        self._process(machine)[key] = int(value)
        setattr(self, self._MIRRORS[key], int(value))

    def _allocs(self, machine: "Machine") -> dict:
        """The live heap blocks of ``machine``'s process, {base: size} (a copy)."""
        return dict(self._process(machine).get("allocations", ()))

    def _set_allocs(self, machine: "Machine", blocks: dict) -> None:
        # Stored as a tuple: a snapshot holds the per-process values as they are, so none may be
        # a mutable container a later run would change underneath it.
        self._process(machine)["allocations"] = tuple(sorted(blocks.items()))
        self.allocations.clear()
        self.allocations.update(blocks)

    def _process(self, machine: "Machine") -> dict:
        """The per-process state of ``machine`` (stdin cursor, command-line buffers, LastError, the
        counters, the live allocations).

        A sandbox keeps it on itself (``model_state``) so its snapshots carry it and each fork
        replays it; a plain machine without one shares this environment's own dict."""
        state = getattr(machine, "model_state", None)
        return state if isinstance(state, dict) else self._own_state

    def stdcall_args(self, imported) -> int | None:
        """How many stack arguments the modelled API pops on x86, None when it is not modelled."""
        name = getattr(imported, "name", None)
        return _STDCALL_ARGS.get(name.lower()) if isinstance(name, str) else None

    def _table(self) -> dict:
        return _WIN_HANDLERS

    def handles(self, imported) -> bool:
        """True when this model carries ``imported`` (an :class:`ImportSymbol`), else the harness
        denies the call.  Ordinal-only imports are never modelled."""
        name = getattr(imported, "name", None)
        return isinstance(name, str) and name.lower() in self._table()

    def dispatch(self, imported, machine: "Machine") -> None:
        """Carry out the modelled API named by ``imported`` against ``machine``."""
        name = getattr(imported, "name", None)
        if not isinstance(name, str):
            raise WindowsModelError("only named imports can be modelled")
        handler = self._table().get(name.lower())
        if handler is None:
            raise WindowsModelError(f"API {name!r} is not modelled by this environment")
        handler(self, machine)

    def _ret(self, machine: "Machine", value: int) -> None:
        if machine_bits(machine) == 32:
            machine.setreg("eax", value & MASK32)
        else:
            machine.setreg("rax", value & MASK64)

    def _set_last_error(self, machine: "Machine", code: int) -> None:
        self._set_value(machine, "last_error", code & MASK32)

    def _log_anti_debug(self, api: str, query: str, answered: str) -> None:
        self.anti_debug.append(AntiDebugEvent(api, query, answered))

    def _alloc_zeroed(self, machine: "Machine", size: int, zero: bool) -> int:
        base = machine.alloc(size)
        if base and zero:
            machine.write(base, b"\x00" * size)
        return base

    def VirtualAlloc(self, machine: "Machine") -> None:
        size = api_arg(machine, 1)
        if size <= 0 or size > MAX_DECOMPRESSED:
            self._set_last_error(machine, 87)
            self._ret(machine, 0)
            return
        rounded = (size + PAGE - 1) & ~(PAGE - 1)
        base = self._alloc_zeroed(machine, rounded, True)
        if not base:
            self._set_last_error(machine, 8)
            self._ret(machine, 0)
            return
        blocks = self._allocs(machine)
        blocks[base] = size
        self._set_allocs(machine, blocks)
        self._set_last_error(machine, 0)
        self._ret(machine, base)

    def VirtualFree(self, machine: "Machine") -> None:
        blocks = self._allocs(machine)
        blocks.pop(api_arg(machine, 0), None)
        self._set_allocs(machine, blocks)
        self._ret(machine, 1)

    def VirtualProtect(self, machine: "Machine") -> None:
        old_ptr = api_arg(machine, 3)
        old = 0x40
        protect = getattr(machine, "protect", None)
        if protect is not None:
            # A sandbox applies the protection to its image pages and reports the old one; a range
            # outside the image (a VirtualAlloc block) keeps the answer below.
            changed = protect(api_arg(machine, 0), api_arg(machine, 1), api_arg(machine, 2) & MASK32)
            if changed == PROTECT_FAILED:
                self._set_last_error(machine, ERROR_INVALID_PARAMETER)
                self._ret(machine, 0)
                return
            if changed is not None:
                old = changed
        if old_ptr:
            machine.write(old_ptr, struct.pack("<I", old))
        self._ret(machine, 1)

    def GetProcessHeap(self, machine: "Machine") -> None:
        self._ret(machine, _PSEUDO_HEAP_HANDLE)

    def HeapAlloc(self, machine: "Machine") -> None:
        flags = api_arg(machine, 1)
        size = api_arg(machine, 2)
        if size <= 0 or size > MAX_DECOMPRESSED:
            self._ret(machine, 0)
            return
        base = self._alloc_zeroed(machine, size, bool(flags & HEAP_ZERO_MEMORY))
        if base:
            blocks = self._allocs(machine)
            blocks[base] = size
            self._set_allocs(machine, blocks)
        self._ret(machine, base)

    def HeapReAlloc(self, machine: "Machine") -> None:
        flags = api_arg(machine, 1)
        old = api_arg(machine, 2)
        size = api_arg(machine, 3)
        if size <= 0 or size > MAX_DECOMPRESSED:
            self._ret(machine, 0)
            return
        base = self._alloc_zeroed(machine, size, bool(flags & HEAP_ZERO_MEMORY))
        if not base:
            self._ret(machine, 0)
            return
        blocks = self._allocs(machine)
        old_size = blocks.get(old)
        if old and old_size:
            machine.write(base, machine.read(old, min(old_size, size)))
            blocks.pop(old, None)
        blocks[base] = size
        self._set_allocs(machine, blocks)
        self._ret(machine, base)

    def HeapFree(self, machine: "Machine") -> None:
        blocks = self._allocs(machine)
        blocks.pop(api_arg(machine, 2), None)
        self._set_allocs(machine, blocks)
        self._ret(machine, 1)

    def HeapSize(self, machine: "Machine") -> None:
        size = self._allocs(machine).get(api_arg(machine, 2))
        self._ret(machine, size if size is not None else MASK64)

    def GetLastError(self, machine: "Machine") -> None:
        self._ret(machine, self._value(machine, "last_error"))

    def SetLastError(self, machine: "Machine") -> None:
        self._set_last_error(machine, api_arg(machine, 0))
        self._ret(machine, 0)

    def IsDebuggerPresent(self, machine: "Machine") -> None:
        self._log_anti_debug("IsDebuggerPresent", "PEB.BeingDebugged", "0 (not present)")
        self._ret(machine, 0)

    def CheckRemoteDebuggerPresent(self, machine: "Machine") -> None:
        out_ptr = api_arg(machine, 1)
        if out_ptr:
            machine.write(out_ptr, struct.pack("<I", 0))
        self._log_anti_debug("CheckRemoteDebuggerPresent", "DebugPort", "0 (not present)")
        self._ret(machine, 1)

    def NtQueryInformationProcess(self, machine: "Machine") -> None:
        info_class = api_arg(machine, 1)
        buffer = api_arg(machine, 2)
        length = api_arg(machine, 3)
        ret_len_ptr = api_arg(machine, 4)
        status = STATUS_SUCCESS
        written = 0
        pointer = machine_bits(machine) // 8          # DWORD_PTR / HANDLE: the machine's pointer
        if info_class == PROCESS_DEBUG_PORT:
            if length >= pointer and buffer:
                machine.write(buffer, bytes(pointer))
            written = pointer
            self._log_anti_debug("NtQueryInformationProcess", "ProcessDebugPort", "0 (no port)")
        elif info_class == PROCESS_DEBUG_OBJECT_HANDLE:
            if length >= pointer and buffer:
                machine.write(buffer, bytes(pointer))
            written = pointer
            status = STATUS_PORT_NOT_SET
            self._log_anti_debug("NtQueryInformationProcess", "ProcessDebugObjectHandle",
                                 "NULL / STATUS_PORT_NOT_SET")
        elif info_class == PROCESS_DEBUG_FLAGS:
            if length >= 4 and buffer:
                machine.write(buffer, struct.pack("<I", 1))
            written = 4
            self._log_anti_debug("NtQueryInformationProcess", "ProcessDebugFlags", "1 (not debugged)")
        else:
            if length and buffer:
                machine.write(buffer, b"\x00" * min(length, 8))
            written = min(length, 8)
        if ret_len_ptr:
            machine.write(ret_len_ptr, struct.pack("<I", written & MASK32))
        self._ret(machine, status)

    def NtQuerySystemInformation(self, machine: "Machine") -> None:
        info_class = api_arg(machine, 0)
        buffer = api_arg(machine, 1)
        length = api_arg(machine, 2)
        ret_len_ptr = api_arg(machine, 3)
        status = STATUS_SUCCESS
        written = 0
        if info_class == SYSTEM_KERNEL_DEBUGGER_INFORMATION:
            if length >= 2 and buffer:
                machine.write(buffer, bytes((0, 1)))
                written = 2
            else:
                status = STATUS_INFO_LENGTH_MISMATCH
            self._log_anti_debug("NtQuerySystemInformation", "SystemKernelDebuggerInformation",
                                 "not present")
        else:
            if length and buffer:
                machine.write(buffer, b"\x00" * min(length, 8))
            written = min(length, 8)
        if ret_len_ptr:
            machine.write(ret_len_ptr, struct.pack("<I", written & MASK32))
        self._ret(machine, status)

    def RtlDecompressBuffer(self, machine: "Machine") -> None:
        fmt = api_arg(machine, 0) & 0xFF
        dst = api_arg(machine, 1)
        dst_size = api_arg(machine, 2)
        src = api_arg(machine, 3)
        src_size = api_arg(machine, 4)
        final_ptr = api_arg(machine, 5)
        if fmt != COMPRESSION_FORMAT_LZNT1:
            self._ret(machine, STATUS_UNSUPPORTED_COMPRESSION)
            return
        if src_size <= 0 or src_size > MAX_COMPRESSED or dst_size <= 0 or dst_size > MAX_DECOMPRESSED:
            self._ret(machine, STATUS_INFO_LENGTH_MISMATCH)
            return
        compressed = machine.read(src, src_size)
        try:
            plain = lznt1_decompress(compressed)
        except Lznt1Error:
            self._ret(machine, STATUS_UNSUPPORTED_COMPRESSION)
            return
        emitted = plain[:dst_size]
        if dst and emitted:
            machine.write(dst, emitted)
        if final_ptr:
            machine.write(final_ptr, struct.pack("<I", len(emitted) & MASK32))
        self._ret(machine, STATUS_SUCCESS)

    def _read_cstring(self, machine: "Machine", address: int, cap: int = 512) -> str:
        if not address:
            return ""
        raw = machine.read(address, cap)
        end = raw.find(b"\x00")
        if end >= 0:
            raw = raw[:end]
        return raw.decode("latin-1")

    def _read_wstring(self, machine: "Machine", address: int, cap: int = 512) -> str:
        """A NUL-terminated UTF-16LE string of at most ``cap`` code units."""
        if not address:
            return ""
        units = []
        for index in range(cap):
            unit = machine.read(address + 2 * index, 2)
            if unit == b"\x00\x00":
                break
            units.append(unit)
        return b"".join(units).decode("utf-16-le", "replace")

    def _load_library(self, machine: "Machine", name: str) -> None:
        name = name.lower()
        handle = self.loaded_modules.get(name)
        if handle is None:
            base = _PSEUDO_MODULE_BASE32 if machine_bits(machine) == 32 else _PSEUDO_MODULE_BASE
            handle = (base + (len(self.loaded_modules) + 1) * PAGE) & MASK64
            self.loaded_modules[name] = handle
        self._ret(machine, handle)

    def LoadLibraryA(self, machine: "Machine") -> None:
        self._load_library(machine, self._read_cstring(machine, api_arg(machine, 0)))

    def LoadLibraryW(self, machine: "Machine") -> None:
        self._load_library(machine, self._read_wstring(machine, api_arg(machine, 0)))

    def _module_handle(self, machine: "Machine", ptr: int, wide: bool) -> None:
        if not ptr:
            self._ret(machine, getattr(machine, "load_base", _PSEUDO_MODULE_BASE))
            return
        name = (self._read_wstring if wide else self._read_cstring)(machine, ptr).lower()
        self._ret(machine, self.loaded_modules.get(name, 0))

    def GetModuleHandleA(self, machine: "Machine") -> None:
        self._module_handle(machine, api_arg(machine, 0), False)

    def GetModuleHandleW(self, machine: "Machine") -> None:
        self._module_handle(machine, api_arg(machine, 0), True)

    def GetProcAddress(self, machine: "Machine") -> None:
        module = api_arg(machine, 0)
        name_ptr = api_arg(machine, 1)
        if name_ptr >> 16:
            name = self._read_cstring(machine, name_ptr)
        else:
            name = f"#{name_ptr & 0xFFFF}"
        dll = next((d for d, h in self.loaded_modules.items() if h == module), f"{module:#x}")
        self.resolved.append((dll, name))
        base = _PSEUDO_PROC_BASE32 if machine_bits(machine) == 32 else _PSEUDO_PROC_BASE
        address = (base + len(self.resolved) * 16) & MASK64
        self.resolved_addresses[address] = (dll, name)
        self._ret(machine, address)

    def RtlGetVersion(self, machine: "Machine") -> None:
        ptr = api_arg(machine, 0)
        if ptr:
            major, minor, build = self.os_version
            machine.write(ptr + 4, struct.pack("<III", major, minor, build))
        self._ret(machine, STATUS_SUCCESS)

    def Sleep(self, machine: "Machine") -> None:
        self._set_value(machine, "tick", (self._value(machine, "tick") + max(1, api_arg(machine, 0))) & MASK32)
        self._ret(machine, 0)

    def GetTickCount(self, machine: "Machine") -> None:
        value = self._value(machine, "tick") & MASK32
        self._set_value(machine, "tick", (value + 16) & MASK32)
        self._log_anti_debug("GetTickCount", "elapsed-time", f"{value}")
        self._ret(machine, value)

    def QueryPerformanceCounter(self, machine: "Machine") -> None:
        ptr = api_arg(machine, 0)
        value = self._value(machine, "perf") & MASK64
        self._set_value(machine, "perf", (value + 1000) & MASK64)
        if ptr:
            machine.write(ptr, struct.pack("<Q", value))
        self._log_anti_debug("QueryPerformanceCounter", "elapsed-time", f"{value}")
        self._ret(machine, 1)

    def GetSystemTimeAsFileTime(self, machine: "Machine") -> None:
        ptr = api_arg(machine, 0)
        value = self._value(machine, "filetime") & MASK64
        self._set_value(machine, "filetime", (value + 0x10000) & MASK64)
        if ptr:
            machine.write(ptr, struct.pack("<Q", value))
        self._ret(machine, 0)

    def RtlAddVectoredExceptionHandler(self, machine: "Machine") -> None:
        first = bool(api_arg(machine, 0))
        handler = api_arg(machine, 1)
        try:
            cookie = machine.add_veh(first, handler)
        except (WindowsModelError, EmulationDenied):
            cookie = 0
        self._ret(machine, cookie)

    def RtlRemoveVectoredExceptionHandler(self, machine: "Machine") -> None:
        self._ret(machine, 1 if machine.remove_veh(api_arg(machine, 0)) else 0)

    AddVectoredExceptionHandler = RtlAddVectoredExceptionHandler
    RemoveVectoredExceptionHandler = RtlRemoveVectoredExceptionHandler

    # ------------------------------------------------------------- B-241: the wider stub layer
    # Each of these has one answer that does not depend on the host: a constant, a bounded copy, or
    # the caller's own injected input.  An API whose answer a real machine chooses stays denied.
    def GetCurrentProcess(self, machine: "Machine") -> None:
        self._ret(machine, MASK64)                       # the pseudo handle (HANDLE)-1

    def GetCurrentThread(self, machine: "Machine") -> None:
        self._ret(machine, MASK64 - 1)                   # the pseudo handle (HANDLE)-2

    def GetStdHandle(self, machine: "Machine") -> None:
        which = api_arg(machine, 0) & MASK32
        which -= (1 << 32) if which & 0x80000000 else 0
        handle = {STD_INPUT_HANDLE: _PSEUDO_STDIN, STD_OUTPUT_HANDLE: _PSEUDO_STDOUT,
                  STD_ERROR_HANDLE: _PSEUDO_STDERR}.get(which)
        if handle is None:
            self._set_last_error(machine, ERROR_INVALID_HANDLE)
            self._ret(machine, MASK64)                   # INVALID_HANDLE_VALUE
            return
        self._ret(machine, handle)

    def _stream(self, handle: int) -> bytearray:
        stream = {_PSEUDO_STDOUT: self.stdout, _PSEUDO_STDERR: self.stderr}.get(handle)
        if stream is None:
            raise WindowsModelError(f"write to handle {handle:#x}: only the standard output and "
                                    "error handles are modelled")
        return stream

    def WriteFile(self, machine: "Machine") -> None:
        stream = self._stream(api_arg(machine, 0) & machine_mask(machine))
        buffer, count, written_ptr = api_arg(machine, 1), api_arg(machine, 2) & MASK32, api_arg(machine, 3)
        if len(stream) + count > MAX_STREAM:
            raise WindowsModelError("the modelled output stream exceeds its cap")
        if count:
            stream += machine.read(buffer, count)
        if written_ptr:
            machine.write(written_ptr, struct.pack("<I", count))
        self._ret(machine, 1)

    WriteConsoleA = WriteFile                            # same five slots; the count is in characters

    def ReadFile(self, machine: "Machine") -> None:
        handle = api_arg(machine, 0) & machine_mask(machine)
        if handle != _PSEUDO_STDIN:
            raise WindowsModelError(f"read from handle {handle:#x}: only the standard input handle "
                                    "is modelled")
        buffer, count, read_ptr = api_arg(machine, 1), api_arg(machine, 2) & MASK32, api_arg(machine, 3)
        process = self._process(machine)
        at = int(process.get("stdin_at", 0))
        chunk = bytes(self.stdin[at:at + count])
        process["stdin_at"] = at + len(chunk)
        if chunk:
            machine.write(buffer, chunk)
        if read_ptr:
            machine.write(read_ptr, struct.pack("<I", len(chunk)))
        self._ret(machine, 1)                            # end of input is success with zero bytes

    def _command_line(self, machine: "Machine", wide: bool) -> None:
        process = self._process(machine)
        key = "command_line_w" if wide else "command_line_a"
        address = process.get(key)
        if address is None:
            raw = (self.command_line.encode("utf-16-le") + b"\x00\x00" if wide
                   else self.command_line.encode("latin-1", "replace") + b"\x00")
            address = machine.alloc(len(raw))
            if not address:
                raise WindowsModelError("no room for the command line")
            machine.write(address, raw)
            process[key] = address
        self._ret(machine, address)

    def GetCommandLineA(self, machine: "Machine") -> None:
        self._command_line(machine, False)

    def GetCommandLineW(self, machine: "Machine") -> None:
        self._command_line(machine, True)

    def ExitProcess(self, machine: "Machine") -> None:
        self.exit_code = api_arg(machine, 0) & MASK32
        leave = getattr(machine, "exit_process", None)
        if leave is None:
            raise WindowsModelError("ExitProcess needs a sandbox that can end the run")
        leave(self.exit_code)

    def _scan(self, machine: "Machine", address: int, unit: int) -> bytes:
        """The bytes of a NUL-terminated string of ``unit``-byte characters, without its NUL."""
        out = bytearray()
        zero = bytes(unit)
        while len(out) <= MAX_API_STRING * unit:
            piece = machine.read(address + len(out), unit)
            if piece == zero:
                return bytes(out)
            out += piece
        raise WindowsModelError("a string argument has no terminator within its cap")

    def lstrlenA(self, machine: "Machine") -> None:
        pointer = api_arg(machine, 0)
        self._ret(machine, len(self._scan(machine, pointer, 1)) if pointer else 0)

    def lstrlenW(self, machine: "Machine") -> None:
        pointer = api_arg(machine, 0)
        self._ret(machine, len(self._scan(machine, pointer, 2)) // 2 if pointer else 0)

    def lstrcpyA(self, machine: "Machine") -> None:
        destination, source = api_arg(machine, 0), api_arg(machine, 1)
        machine.write(destination, self._scan(machine, source, 1) + b"\x00")
        self._ret(machine, destination)

    def lstrcatA(self, machine: "Machine") -> None:
        destination, source = api_arg(machine, 0), api_arg(machine, 1)
        end = destination + len(self._scan(machine, destination, 1))
        machine.write(end, self._scan(machine, source, 1) + b"\x00")
        self._ret(machine, destination)

    def _span(self, length: int) -> int:
        if length > MAX_DECOMPRESSED:
            raise WindowsModelError("a memory block argument exceeds its cap")
        return length

    def RtlMoveMemory(self, machine: "Machine") -> None:
        destination, source = api_arg(machine, 0), api_arg(machine, 1)
        length = self._span(api_arg(machine, 2) & machine_mask(machine))
        if length:
            machine.write(destination, machine.read(source, length))

    def RtlZeroMemory(self, machine: "Machine") -> None:
        length = self._span(api_arg(machine, 1) & machine_mask(machine))
        if length:
            machine.write(api_arg(machine, 0), bytes(length))

    def RtlFillMemory(self, machine: "Machine") -> None:
        length = self._span(api_arg(machine, 1) & machine_mask(machine))
        if length:
            machine.write(api_arg(machine, 0), bytes([api_arg(machine, 2) & 0xFF]) * length)

    def RtlUnwind(self, machine: "Machine") -> None:
        unwind = getattr(machine, "unwind", None)
        if unwind is None or machine_bits(machine) != 32:
            raise WindowsModelError("RtlUnwind is modelled for x86 frame-based SEH inside the sandbox only")
        unwind()


def _build_win_handler_table() -> dict:
    names = (
        "VirtualAlloc", "VirtualFree", "VirtualProtect", "GetProcessHeap", "HeapAlloc",
        "HeapReAlloc", "HeapFree", "HeapSize", "GetLastError", "SetLastError",
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
        "NtQuerySystemInformation", "RtlDecompressBuffer", "LoadLibraryA", "LoadLibraryW",
        "GetModuleHandleA", "GetModuleHandleW", "GetProcAddress", "RtlGetVersion", "Sleep",
        "GetTickCount", "QueryPerformanceCounter", "GetSystemTimeAsFileTime",
        "RtlAddVectoredExceptionHandler", "RtlRemoveVectoredExceptionHandler",
        "AddVectoredExceptionHandler", "RemoveVectoredExceptionHandler",
        # B-241
        "GetCurrentProcess", "GetCurrentThread", "GetStdHandle", "WriteFile", "WriteConsoleA",
        "ReadFile", "GetCommandLineA", "GetCommandLineW", "ExitProcess", "lstrlenA", "lstrlenW",
        "lstrcpyA", "lstrcatA", "RtlMoveMemory", "RtlZeroMemory", "RtlFillMemory", "RtlUnwind",
    )
    missing = sorted(name for name in names if name.lower() not in _STDCALL_ARGS)
    if missing or len(_STDCALL_ARGS) != len(names):
        raise RuntimeError(f"modelled API table and stdcall argument table disagree: {missing}")
    table: dict = {}
    for name in names:
        method = getattr(WindowsEnvironment, name)
        table[name.lower()] = lambda env, machine, _m=method: _m(env, machine)
    return table


_WIN_HANDLERS = _build_win_handler_table()


def modelled_apis() -> tuple[str, ...]:
    """The lowercase export names the Windows environment carries (everything else is denied)."""
    return tuple(sorted(_WIN_HANDLERS))


# ---------------------------------------------------------------- B-241: a dump as a PE file
def dump_pe(pe: MappedPE, memory: bytes, entry_rva: int | None = None) -> bytes:
    """Write ``memory`` (the image as a sandbox holds it, :meth:`SafeUnicorn.image_memory`) as a
    PE file a static tool can load: every section's file offset is its RVA and its raw size its
    mapped size, the image base is the base the memory was relocated to, and the entry point is
    ``entry_rva`` (the recovered original entry point) when given.

    The IAT slots of the image's own import and delay-import tables are put back as the file had
    them, since the sandbox filled them with stub addresses that mean nothing outside it.  Slots a
    stub rebuilt itself keep what it wrote; :func:`rebuilt_imports` names those.
    """
    if not isinstance(pe, MappedPE) or len(memory) != len(pe.image):
        raise PEError("the dump is not the size of the mapped image")
    out = bytearray(memory)
    out[:pe.size_of_headers] = pe.image[:pe.size_of_headers]
    width = 8 if pe.is_64 else 4
    for imported in pe.imports + pe.delay_imports:
        out[imported.iat_rva:imported.iat_rva + width] = \
            pe.image[imported.iat_rva:imported.iat_rva + width]
    optional = _u32(out, 0x3C) + 24
    section_alignment = _u32(out, optional + 32)
    if entry_rva is not None:
        if not 0 <= int(entry_rva) < len(out):
            raise PEError("the recovered entry point lies outside the image")
        struct.pack_into("<I", out, optional + 16, int(entry_rva))
    if pe.is_64:
        struct.pack_into("<Q", out, optional + 24, pe.load_base)
    else:
        struct.pack_into("<I", out, optional + 28, pe.load_base)
    struct.pack_into("<I", out, optional + 36, min(section_alignment, 0x10000))   # FileAlignment
    table = optional + _u16(out, optional - 4)           # SizeOfOptionalHeader sits before it
    for index, section in enumerate(pe.sections):
        at = table + index * 40
        size = min(_align(section.mapped_size, section_alignment),
                   len(out) - section.virtual_address) if section.mapped_size else 0
        struct.pack_into("<I", out, at + 8, size)                        # VirtualSize
        struct.pack_into("<II", out, at + 16, size, section.virtual_address if size else 0)
    return bytes(out)


def rebuilt_imports(pe: MappedPE, memory: bytes,
                    environment: "WindowsEnvironment") -> tuple[tuple[int, str, str], ...]:
    """``(rva, dll, name)`` for every pointer-sized slot of ``memory`` that holds an address the
    environment's GetProcAddress returned: the import table a stub rebuilt at run time."""
    width = 8 if pe.is_64 else 4
    found = []
    for address, (dll, name) in sorted(environment.resolved_addresses.items()):
        needle = int(address).to_bytes(width, "little")
        at = memory.find(needle)
        while at >= 0:
            found.append((at, dll, name))
            at = memory.find(needle, at + 1)
    return tuple(sorted(found))


def verify_candidates(board, candidates: Iterable[str], *, agent: str,
                      key: str = "flag", summary: str = "pe_emu Windows-emulation candidate"
                      ) -> str | None:
    """Return the first candidate the board's *pinned acceptance gate* accepts, else None.

    Emulation can surface a printable string that merely looks like an answer (the SHA1-Hulud decoy
    that overwrote the real flag).  Answer selection runs every candidate through B-165's pinned
    GateSpec: a candidate that passes is accepted on the board (and so goes on to ``ctf submit``); a
    decoy that fails is recorded for the audit trail but never returned.  The gate is the board's,
    not the caller's, so a looser check cannot be slipped in here.
    """
    try:
        from shared_findings import AcceptanceRejected, Finding
    except ModuleNotFoundError:
        import sys as _sys
        from pathlib import Path as _Path
        _sys.path.append(str(_Path(__file__).resolve().parents[2] / "tools"))
        from shared_findings import AcceptanceRejected, Finding

    winner: str | None = None
    for candidate in candidates:
        finding = Finding(key=key, agent=agent, summary=summary, kind="candidate",
                          candidate=candidate)
        try:
            board.accept(finding)
        except AcceptanceRejected:
            board.record(finding)
            continue
        if winner is None:
            winner = candidate
    return winner


# ---------------------------------------------------------------- B-226: the ready setup (running start)
def _unicorn_status() -> tuple[bool, str | None]:
    """Whether the guarded Unicorn backend is usable here, and the reason when it is not.

    `native_emulate` owns the Darwin/arm64 cache-line prerequisite (importing Unicorn directly can take
    an uncatchable SIGILL), so the status is read from it rather than probed here.  A broken check is
    reported as unavailable with a named reason, never assumed usable.
    """
    try:
        from solvers.common import native_emulate as _ne
    except Exception as exc:                                 # pragma: no cover - import-time only
        return False, f"the guarded Unicorn capability check is unavailable: {exc}"
    return bool(_ne.UNICORN_AVAILABLE), _ne.UNICORN_UNAVAILABLE_REASON


@dataclass(frozen=True)
class ReadySetup:
    """A pre-wired Windows-PE / native-emulation setup: the running start for a flag-only static-RE sample.

    :func:`ready_environment` assembles this from PE *bytes* using only the carried harness -- the mapper,
    B-148's :class:`WindowsEnvironment`/:class:`SafeUnicorn` model (VEH, TLS, clocks, the modelled API
    table) and B-165's shared-findings acceptance gate.  It writes no second emulator.  The mapping, the
    hashed-API table, the parsed TLS directory and the CMP/TEST sites are all computed offline, so an
    agent -- or a host where Unicorn is declined (the Darwin/arm64 guard) -- still gets them.
    :meth:`sandbox` is the only member that needs the native backend; where it is unavailable it fails
    loudly with the named reason instead of a silent empty run.  The reversing itself stays the agent's
    (the item's standing blocker): this removes the setup work, not the thinking.
    """

    pe: MappedPE
    environment: WindowsEnvironment
    tls: TlsImage
    api_hash_index: Mapping[int, tuple["HashMatch", ...]]
    compare_sites: tuple["CompareSite", ...]
    clock: Callable[[], float]
    unicorn_available: bool
    unicorn_reason: str | None
    compare_sites_reason: str | None = None

    def resolve_api_hash(self, value: int) -> tuple["HashMatch", ...]:
        """Look a 32-bit API-hash constant up in the pre-built index; collisions are kept, not hidden.

        This *reads* the index already built by :func:`ready_environment`; it does not rebuild it.  The
        value is masked to its low 32 bits, so a 64-bit register value whose low word is the hash still
        resolves.  Not to be confused with the module-level :func:`resolve_api_hash`, which takes the raw
        symbol list and builds an index itself.
        """
        return self.api_hash_index.get(int(value) & 0xFFFFFFFF, ())

    def sandbox(self, **kwargs) -> "SafeUnicorn":
        """Build the wired :class:`SafeUnicorn` on this image and the clean Windows environment.

        The clock defaults to the setup's injected clock and the environment to the setup's clean-env
        model, unless the caller overrides either.  A PE32 image gets the 32-bit sandbox (stdcall,
        TEB/PEB, frame-based SEH); a PE32+ image the x86-64 one.  The native backend is required: when it is declined
        here (and no explicit ``backend`` is supplied for testing) this raises :class:`EmulationDenied`
        naming the reason, rather than returning a harness that cannot run.
        """
        kwargs.setdefault("clock", self.clock)
        kwargs.setdefault("environment", self.environment)
        if kwargs.get("backend") is None and not self.unicorn_available:
            raise EmulationDenied(self.unicorn_reason
                                  or "the guarded Unicorn backend is unavailable on this host")
        return SafeUnicorn(self.pe, **kwargs)

    def verify(self, board, candidates: Iterable[str], *, agent: str, **kwargs) -> str | None:
        """Select an answer through the board's *pinned* acceptance gate (a decoy can never win).

        Thin pass-through to :func:`verify_candidates` so the on-ramp carries the decoy-proof verify road
        (B-165/B-148) without the caller importing it separately.
        """
        return verify_candidates(board, candidates, agent=agent, **kwargs)

    def summary(self) -> dict:
        """A JSON-able description of everything the setup wired, for the swarm brief and the audit trail."""
        return {
            "image_sha256": self.pe.image_sha256,
            "file_sha256": self.pe.file_sha256,
            "machine": self.pe.machine,
            "is_64": self.pe.is_64,
            "entry_rva": self.pe.entry_rva,
            "load_base": self.pe.load_base,
            "sections": [s.name for s in self.pe.sections],
            "imports": [s.display for s in self.pe.imports],
            "delay_imports": [s.display for s in self.pe.delay_imports],
            "tls_callbacks": [hex(c) for c in self.tls.callbacks],
            "tls_index_address": self.tls.index_address,
            "compare_sites": len(self.compare_sites),
            "compare_sites_reason": self.compare_sites_reason,
            "api_hash_values": len(self.api_hash_index),
            "modelled_apis": list(modelled_apis()),
            "unicorn_available": self.unicorn_available,
            "unicorn_reason": self.unicorn_reason,
        }


def ready_environment(data: bytes, *, clock: Callable[[], float] | None = None,
                      api_symbols: Iterable[str | tuple[str, str]] = COMMON_WINDOWS_APIS,
                      algorithms: Mapping[str, Callable[[str], int]] = HASHERS,
                      compare_sites: bool = True) -> ReadySetup:
    """Assemble the ready Windows-PE / native-emulation setup from PE *bytes* (B-226, the hard-tail on-ramp).

    One call turns a handed-out Windows PE into the running start the Day-30 SHA1-Hulud class had to
    hand-build every race: the mapped image, a clean :class:`WindowsEnvironment` (VEH / TLS / clock /
    modelled-API model), the hashed-API table seeded from :data:`COMMON_WINDOWS_APIS`, the parsed TLS
    directory, and the CMP/TEST sites.  It reuses the carried harness only -- it adds no second
    emulator -- and the reversing stays the agent's (the item's standing blocker).

    ``clock`` is handed to :meth:`ReadySetup.sandbox` so anti-timing checks are driven by an injectable
    clock; it defaults to ``time.monotonic``.  ``api_symbols`` / ``algorithms`` seed the hashed-API
    index.  Set ``compare_sites=False`` to skip the capstone disassembly pass.  A malformed PE raises
    :class:`PEError`.  When capstone is absent the compare-site pass is skipped and the named reason is
    recorded on the result (and in :meth:`ReadySetup.summary`), never silently swallowed; Unicorn's
    availability is reported the same way.
    """
    pe = map_pe(data)
    index = build_api_hash_index(api_symbols, algorithms)
    tls = parse_tls(pe)
    sites: tuple[CompareSite, ...] = ()
    compare_reason: str | None = None
    if compare_sites:
        try:
            sites = find_compare_sites(pe)
        except EmulationDenied as exc:
            # Capstone is the only prerequisite find_compare_sites needs; surface, don't swallow.
            compare_reason = str(exc)
    available, unicorn_reason = _unicorn_status()
    return ReadySetup(
        pe=pe,
        environment=WindowsEnvironment(),
        tls=tls,
        api_hash_index=index,
        compare_sites=sites,
        clock=clock if clock is not None else time.monotonic,
        unicorn_available=available,
        unicorn_reason=unicorn_reason,
        compare_sites_reason=compare_reason,
    )


__all__ = [
    "PEError", "EmulationDenied", "DataDirectory", "Section", "ImportSymbol", "Relocation", "MappedPE",
    "map_pe", "hash_ror13", "hash_djb2", "hash_fnv1a", "hash_crc32", "HASHERS",
    "COMMON_WINDOWS_APIS", "HashMatch", "build_api_hash_index", "resolve_api_hash", "CompareSite",
    "find_compare_sites", "OperandValue", "MemorySnapshot", "Snapshot", "RunResult", "SafeUnicorn",
    # Windows process model (B-148)
    "Lznt1Error", "WindowsModelError", "lznt1_decompress", "lznt1_compress_stored",
    "COMPRESSION_FORMAT_LZNT1", "Machine", "win64_arg", "api_arg", "machine_bits",
    "AntiDebugEvent", "VehChain",
    "TlsImage", "parse_tls", "IMAGE_DIRECTORY_ENTRY_TLS", "WindowsEnvironment",
    "modelled_apis", "verify_candidates",
    # Ready setup / running start (B-226)
    "ReadySetup", "ready_environment",
    # PE32 execution, x86 exceptions, delay imports, dumps (B-241)
    "EXCEPTION_BREAKPOINT", "EXCEPTION_SINGLE_STEP", "EXCEPTION_ACCESS_VIOLATION",
    "EXCEPTION_ILLEGAL_INSTRUCTION", "EXCEPTION_INT_DIVIDE_BY_ZERO", "EXCEPTION_PRIV_INSTRUCTION",
    "PROTECT_FAILED", "dump_pe", "rebuilt_imports",
]
