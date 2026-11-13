#!/usr/bin/env python3
"""Fail-closed, offline verification for classic amd64 ret2dlresolve plans.

This module complements the repository's existing payload serializers.  It does
not build a ROP chain.  Instead it parses a stripped ELF through its program
headers/``PT_DYNAMIC`` entries and independently verifies the exact addresses
and records that glibc's ``_dl_fixup`` will consume.

Only ELF64 little-endian x86-64 is accepted.  All runtime addresses, including
the load bias of a PIE, are caller supplied; nothing is executed or contacted.
"""
from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
import struct
import sys
from typing import Iterable, Mapping, Sequence


MAX_ELF = 64 * 1024 * 1024
MAX_BLOB = 16 * 1024 * 1024
MAX_PHDRS = 4096
MAX_DYNAMIC = 4096
UINT64_LIMIT = 1 << 64

ET_EXEC = 2
ET_DYN = 3
EM_X86_64 = 62
PT_LOAD = 1
PT_DYNAMIC = 2
PT_NOTE = 4
PT_GNU_RELRO = 0x6474E552
PT_GNU_PROPERTY = 0x6474E553
PF_X = 1
PF_W = 2
PF_R = 4

DT_NULL = 0
DT_PLTRELSZ = 2
DT_PLTGOT = 3
DT_STRTAB = 5
DT_SYMTAB = 6
DT_RELA = 7
DT_RELAENT = 9
DT_SYMENT = 11
DT_PLTREL = 20
DT_JMPREL = 23
DT_BIND_NOW = 24
DT_FLAGS = 30
DT_VERSYM = 0x6FFFFFF0
DT_FLAGS_1 = 0x6FFFFFFB
DF_BIND_NOW = 0x8
DF_1_NOW = 0x1

R_X86_64_JUMP_SLOT = 7
ELF64_SYM_SIZE = 24
ELF64_RELA_SIZE = 24

NT_GNU_PROPERTY_TYPE_0 = 5
GNU_PROPERTY_X86_FEATURE_1_AND = 0xC0000002
GNU_PROPERTY_X86_FEATURE_1_IBT = 1
GNU_PROPERTY_X86_FEATURE_1_SHSTK = 2
ENDBR64 = b"\xf3\x0f\x1e\xfa"


class PwnDepthRet2DlError(ValueError):
    """The ELF, loader state, or forged records are malformed/unsupported."""


@dataclass(frozen=True)
class AddressRange:
    start: int
    end: int
    flags: int

    def contains(self, address: int, size: int = 1) -> bool:
        try:
            start = _address(self.start, "range start")
            end = _integer(self.end, "range end")
            if end <= start:
                raise PwnDepthRet2DlError("range end must follow its start")
            _address(end - 1, "range final byte")
            at = _address(address, "address")
            if isinstance(size, bool) or not isinstance(size, int) or size < 0:
                raise PwnDepthRet2DlError("range size must be a non-negative integer")
            return start <= at and at + size <= end
        except PwnDepthRet2DlError:
            raise
        except Exception as exc:  # defensive public boundary
            raise PwnDepthRet2DlError("malformed address range") from exc

    def as_dict(self) -> dict[str, object]:
        return {"start": hex(self.start), "end": hex(self.end), "flags": self.flags}


@dataclass(frozen=True)
class Ret2DlProfile:
    elf_type: int
    load_bias: int | None
    plt0: int | None
    dynamic: Mapping[int, int]
    readable_ranges: tuple[AddressRange, ...]
    writable_ranges: tuple[AddressRange, ...]
    executable_ranges: tuple[AddressRange, ...]
    relro: bool
    bind_now: bool
    cet_ibt: bool
    cet_shstk: bool
    blockers: tuple[str, ...]
    warnings: tuple[str, ...]

    @property
    def feasible(self) -> bool:
        return not self.blockers

    @property
    def pie(self) -> bool:
        return self.elf_type == ET_DYN

    def runtime_tag(self, tag: int) -> int | None:
        try:
            checked_tag = _integer(tag, "dynamic tag")
            if not isinstance(self.dynamic, Mapping):
                raise PwnDepthRet2DlError("profile dynamic tags must be a mapping")
            value = self.dynamic.get(checked_tag)
            if value is None or self.load_bias is None:
                return None
            value = _integer(value, "dynamic value")
            bias = _address(self.load_bias, "profile load_bias")
            result = value + bias
            if result >= UINT64_LIMIT:
                raise PwnDepthRet2DlError("runtime dynamic pointer overflows")
            return _address(result, "runtime dynamic pointer")
        except PwnDepthRet2DlError:
            raise
        except Exception as exc:
            raise PwnDepthRet2DlError("malformed dynamic profile") from exc

    def as_dict(self) -> dict[str, object]:
        tags = {hex(tag): hex(value) for tag, value in sorted(self.dynamic.items())}
        return {
            "architecture": "amd64",
            "elf_type": "ET_DYN" if self.pie else "ET_EXEC",
            "load_bias": None if self.load_bias is None else hex(self.load_bias),
            "plt0": None if self.plt0 is None else hex(self.plt0),
            "dynamic": tags,
            "readable_ranges": [item.as_dict() for item in self.readable_ranges],
            "writable_ranges": [item.as_dict() for item in self.writable_ranges],
            "executable_ranges": [item.as_dict() for item in self.executable_ranges],
            "relro": self.relro,
            "bind_now": self.bind_now,
            "cet_ibt": self.cet_ibt,
            "cet_shstk": self.cet_shstk,
            "feasible": self.feasible,
            "blockers": list(self.blockers),
            "warnings": list(self.warnings),
        }


@dataclass(frozen=True)
class Ret2DlVerification:
    relocation_selector: int
    symbol_index: int
    symbol: bytes
    relocation_target: int
    versym_address: int | None
    versym_value: int | None
    steps: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "verified": True,
            "relocation_selector": self.relocation_selector,
            "symbol_index": self.symbol_index,
            "symbol": self.symbol.decode("ascii", "backslashreplace"),
            "relocation_target": hex(self.relocation_target),
            "versym_address": None if self.versym_address is None else hex(self.versym_address),
            "versym_value": self.versym_value,
            "steps": list(self.steps),
        }


@dataclass(frozen=True)
class _ProgramHeader:
    ptype: int
    flags: int
    file_offset: int
    vaddr: int
    filesz: int
    memsz: int
    align: int


def _integer(value: object, name: str, *, allow_zero: bool = True) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < UINT64_LIMIT:
        raise PwnDepthRet2DlError(f"{name} must be an unsigned 64-bit integer")
    if not allow_zero and value == 0:
        raise PwnDepthRet2DlError(f"{name} must be non-zero")
    return value


def _address(value: object, name: str, *, allow_zero: bool = True) -> int:
    """Validate one canonical x86-64 runtime address."""

    result = _integer(value, name, allow_zero=allow_zero)
    if result:
        upper = result >> 48
        sign = (result >> 47) & 1
        if upper != (0xFFFF if sign else 0):
            raise PwnDepthRet2DlError(f"{name} is not a canonical x86-64 address")
    return result


def _checked_end(start: int, size: int, name: str) -> int:
    _integer(start, f"{name} start")
    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        raise PwnDepthRet2DlError(f"{name} size must be a non-negative integer")
    end = start + size
    if end > UINT64_LIMIT:
        raise PwnDepthRet2DlError(f"{name} crosses the 64-bit address space")
    return end


def _unpack(fmt: str, data: bytes, offset: int, name: str) -> tuple[int, ...]:
    size = struct.calcsize(fmt)
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0 or offset + size > len(data):
        raise PwnDepthRet2DlError(f"{name} extends past the available bytes")
    try:
        return struct.unpack_from(fmt, data, offset)
    except (struct.error, OverflowError) as exc:  # defensive: never leak a stdlib parser exception
        raise PwnDepthRet2DlError(f"cannot decode {name}") from exc


def _read_source(source: bytes | bytearray | memoryview | str | Path) -> bytes:
    try:
        if isinstance(source, (bytes, bytearray, memoryview)):
            data = bytes(source)
        elif isinstance(source, (str, Path)):
            with Path(source).open("rb") as handle:
                data = handle.read(MAX_ELF + 1)
        else:
            raise PwnDepthRet2DlError("ELF source must be bytes or a filesystem path")
    except PwnDepthRet2DlError:
        raise
    except (OSError, TypeError, ValueError, OverflowError) as exc:
        raise PwnDepthRet2DlError(f"cannot read ELF source: {exc}") from exc
    if len(data) > MAX_ELF:
        raise PwnDepthRet2DlError(f"ELF exceeds {MAX_ELF} bytes")
    return data


def _program_headers(data: bytes) -> tuple[int, tuple[_ProgramHeader, ...]]:
    if len(data) < 64 or data[:4] != b"\x7fELF":
        raise PwnDepthRet2DlError("source is not a complete ELF64 file")
    if data[4] != 2 or data[5] != 1 or data[6] != 1:
        raise PwnDepthRet2DlError("only ELF64 little-endian version-1 files are supported")
    elf_type, machine = _unpack("<HH", data, 16, "ELF identity")
    if elf_type not in (ET_EXEC, ET_DYN) or machine != EM_X86_64:
        raise PwnDepthRet2DlError("only x86-64 ET_EXEC/ET_DYN files are supported")
    phoff = _unpack("<Q", data, 32, "program-header offset")[0]
    phentsize, phnum = _unpack("<HH", data, 54, "program-header geometry")
    if phentsize < 56 or not 1 <= phnum <= MAX_PHDRS:
        raise PwnDepthRet2DlError("ELF has no bounded standard program-header table")
    if phoff + phentsize * phnum > len(data):
        raise PwnDepthRet2DlError("program-header table extends past end of file")
    headers: list[_ProgramHeader] = []
    for index in range(phnum):
        row = _unpack("<IIQQQQQQ", data, phoff + index * phentsize, f"program header {index}")
        ptype, flags, file_offset, vaddr, _paddr, filesz, memsz, align = row
        if filesz > memsz:
            raise PwnDepthRet2DlError(f"program header {index} has filesz greater than memsz")
        if file_offset + filesz > len(data):
            raise PwnDepthRet2DlError(f"program header {index} extends past end of file")
        _checked_end(vaddr, memsz, f"program header {index} virtual range")
        headers.append(_ProgramHeader(ptype, flags, file_offset, vaddr, filesz, memsz, align))
    return elf_type, tuple(headers)


def _dynamic_entries(data: bytes, headers: Sequence[_ProgramHeader]) -> dict[int, int]:
    dynamic_headers = [header for header in headers if header.ptype == PT_DYNAMIC]
    if len(dynamic_headers) != 1:
        raise PwnDepthRet2DlError("ELF must contain exactly one PT_DYNAMIC segment")
    header = dynamic_headers[0]
    if not header.filesz or header.filesz % 16:
        raise PwnDepthRet2DlError("PT_DYNAMIC must contain whole Elf64_Dyn records")
    count = header.filesz // 16
    if count > MAX_DYNAMIC:
        raise PwnDepthRet2DlError("PT_DYNAMIC record count exceeds cap")
    wanted = {
        DT_PLTRELSZ, DT_PLTGOT, DT_STRTAB, DT_SYMTAB, DT_RELAENT, DT_SYMENT,
        DT_PLTREL, DT_JMPREL, DT_BIND_NOW, DT_FLAGS, DT_VERSYM, DT_FLAGS_1,
    }
    result: dict[int, int] = {}
    terminated = False
    for index in range(count):
        tag, value = _unpack("<qQ", data, header.file_offset + index * 16, f"dynamic record {index}")
        if tag == DT_NULL:
            terminated = True
            break
        if tag in wanted:
            if tag in result and result[tag] != value:
                raise PwnDepthRet2DlError(f"conflicting dynamic tag {tag:#x}")
            result[tag] = value
    if not terminated:
        raise PwnDepthRet2DlError("PT_DYNAMIC lacks a bounded DT_NULL terminator")
    return result


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def _gnu_property_features(data: bytes, headers: Sequence[_ProgramHeader]) -> tuple[bool, bool]:
    features = 0
    for header in headers:
        if header.ptype not in (PT_NOTE, PT_GNU_PROPERTY) or not header.filesz:
            continue
        cursor, end = header.file_offset, header.file_offset + header.filesz
        while cursor + 12 <= end:
            namesz, descsz, note_type = _unpack("<III", data, cursor, "GNU property note header")
            cursor += 12
            name_end = cursor + namesz
            desc_start = _align(name_end, 4)
            desc_end = desc_start + descsz
            if name_end > end or desc_end > end:
                raise PwnDepthRet2DlError("ELF note extends past its program segment")
            name = data[cursor:name_end].rstrip(b"\x00")
            if name == b"GNU" and note_type == NT_GNU_PROPERTY_TYPE_0:
                at = desc_start
                while at + 8 <= desc_end:
                    property_type, property_size = _unpack("<II", data, at, "GNU property entry")
                    value_start = at + 8
                    value_end = value_start + property_size
                    if value_end > desc_end:
                        raise PwnDepthRet2DlError("GNU property data extends past note")
                    if property_type == GNU_PROPERTY_X86_FEATURE_1_AND:
                        if property_size != 4:
                            raise PwnDepthRet2DlError(
                                "GNU_PROPERTY_X86_FEATURE_1_AND must be four bytes"
                            )
                        features |= _unpack("<I", data, value_start, "x86 feature property")[0]
                    at = _align(value_end, 8)
            cursor = _align(desc_end, 4)
    return bool(features & GNU_PROPERTY_X86_FEATURE_1_IBT), bool(features & GNU_PROPERTY_X86_FEATURE_1_SHSTK)


def _runtime_ranges(headers: Sequence[_ProgramHeader], bias: int | None) -> tuple[AddressRange, ...]:
    if bias is None:
        return ()
    ranges: list[AddressRange] = []
    for header in headers:
        if header.ptype != PT_LOAD or not header.memsz:
            continue
        raw_start = header.vaddr + bias
        _address(raw_start, "runtime PT_LOAD start")
        raw_end = _checked_end(raw_start, header.memsz, "runtime PT_LOAD")
        _address(raw_end - 1, "runtime PT_LOAD final byte")
        # Linux maps PT_LOAD segments in page units.  The tail between p_memsz and the next
        # page boundary is still mapped (and zero-filled where it extends beyond p_filesz),
        # which is precisely where many valid ret2dlresolve VERSYM probes land.
        start = raw_start & ~0xFFF
        if raw_end > UINT64_LIMIT - 0xFFF:
            raise PwnDepthRet2DlError("page-rounded PT_LOAD range overflows")
        end = (raw_end + 0xFFF) & ~0xFFF
        _address(end - 1, "page-rounded PT_LOAD final byte")
        ranges.append(AddressRange(start, end, header.flags))
    return tuple(sorted(ranges, key=lambda item: (item.start, item.end, item.flags)))


def _in_ranges(ranges: Sequence[AddressRange], address: int, size: int, required_flag: int) -> bool:
    return any((item.flags & required_flag) and item.contains(address, size) for item in ranges)


def inspect_elf(
    source: bytes | bytearray | memoryview | str | Path,
    *,
    load_bias: int | None = None,
    plt0: int | None = None,
) -> Ret2DlProfile:
    """Parse an ELF and report whether classic PLT0 ret2dlresolve is supportable.

    A PIE/ET_DYN requires an explicit page-aligned ``load_bias``.  ``plt0`` is
    likewise explicit because stripped ELF program headers do not identify the
    semantic boundary of the traditional PLT resolver entry.
    """

    try:
        data = _read_source(source)
        elf_type, headers = _program_headers(data)
        dynamic = _dynamic_entries(data, headers)
        if load_bias is not None:
            load_bias = _address(load_bias, "load_bias")
            if load_bias & 0xFFF:
                raise PwnDepthRet2DlError("load_bias must be page aligned")
        if elf_type == ET_EXEC:
            if load_bias not in (None, 0):
                raise PwnDepthRet2DlError("ET_EXEC load_bias must be zero")
            runtime_bias: int | None = 0
        else:
            runtime_bias = load_bias
        if plt0 is not None:
            plt0 = _address(plt0, "plt0", allow_zero=False)
        ranges = _runtime_ranges(headers, runtime_bias)
        readable = tuple(item for item in ranges if item.flags & PF_R)
        writable = tuple(item for item in ranges if item.flags & PF_W)
        executable = tuple(item for item in ranges if item.flags & PF_X)
        relro = any(header.ptype == PT_GNU_RELRO and header.memsz for header in headers)
        bind_now = (
            DT_BIND_NOW in dynamic
            or bool(dynamic.get(DT_FLAGS, 0) & DF_BIND_NOW)
            or bool(dynamic.get(DT_FLAGS_1, 0) & DF_1_NOW)
        )
        ibt, shstk = _gnu_property_features(data, headers)
        blockers: list[str] = []
        warnings: list[str] = []
        if runtime_bias is None:
            blockers.append("ET_DYN requires an explicit runtime load_bias")
        required = (DT_PLTGOT, DT_STRTAB, DT_SYMTAB, DT_JMPREL, DT_PLTRELSZ, DT_PLTREL, DT_SYMENT)
        missing = [tag for tag in required if tag not in dynamic]
        if missing:
            blockers.append("missing dynamic tags: " + ", ".join(hex(tag) for tag in missing))
        if dynamic.get(DT_PLTREL) != DT_RELA:
            blockers.append("amd64 lazy binding requires DT_PLTREL=DT_RELA")
        if dynamic.get(DT_SYMENT) != ELF64_SYM_SIZE:
            blockers.append("DT_SYMENT is not sizeof(Elf64_Sym)=24")
        if DT_RELAENT in dynamic and dynamic[DT_RELAENT] != ELF64_RELA_SIZE:
            blockers.append("DT_RELAENT is not sizeof(Elf64_Rela)=24")
        if DT_PLTRELSZ in dynamic and dynamic[DT_PLTRELSZ] % ELF64_RELA_SIZE:
            blockers.append("DT_PLTRELSZ is not a whole Elf64_Rela table")
        if not dynamic.get(DT_PLTRELSZ, 0):
            blockers.append("DT_PLTRELSZ is zero; no lazy relocation table is available")
        if bind_now:
            blockers.append("BIND_NOW/-z now disables the ordinary lazy PLT0 route")
        if plt0 is None:
            blockers.append("traditional PLT0 address was not supplied")
        elif runtime_bias is not None and not _in_ranges(executable, plt0, 1, PF_X):
            blockers.append("supplied PLT0 is not inside an executable PT_LOAD range")
        if runtime_bias is not None:
            for tag, size, label in (
                (DT_PLTGOT, 24, "DT_PLTGOT"),
                (DT_STRTAB, 1, "DT_STRTAB"),
                (DT_SYMTAB, ELF64_SYM_SIZE, "DT_SYMTAB"),
                (DT_JMPREL, dynamic.get(DT_PLTRELSZ, 0), "DT_JMPREL"),
            ):
                value = dynamic.get(tag)
                if value is not None:
                    runtime_value = value + runtime_bias
                    if value == 0 or runtime_value >= UINT64_LIMIT:
                        blockers.append(f"{label} has a zero or overflowing runtime pointer")
                    elif not (
                        (runtime_value >> 48)
                        == (0xFFFF if ((runtime_value >> 47) & 1) else 0)
                    ):
                        blockers.append(f"{label} has a noncanonical runtime pointer")
                    elif size and not _in_ranges(readable, runtime_value, size, PF_R):
                        blockers.append(f"{label} is not wholly inside a readable PT_LOAD range")
        if shstk:
            blockers.append("GNU property requests SHSTK; an overwritten-return chain is not proven usable")
        if ibt:
            warnings.append("GNU property requests IBT; confirm every indirect resolver target is ENDBR-compatible")
        if relro and not bind_now:
            warnings.append("PT_GNU_RELRO without NOW is partial RELRO and is compatible with lazy binding")
        elif relro and bind_now:
            warnings.append("PT_GNU_RELRO plus NOW is full RELRO")
        if DT_VERSYM in dynamic:
            warnings.append("DT_VERSYM is present; the forged symbol index needs a readable zero version entry")
        return Ret2DlProfile(
            elf_type, runtime_bias, plt0, dict(dynamic), readable, writable, executable,
            relro, bind_now, ibt, shstk, tuple(blockers), tuple(warnings),
        )
    except PwnDepthRet2DlError:
        raise
    except Exception as exc:  # every malformed public input maps to the declared error
        raise PwnDepthRet2DlError(f"malformed ELF: {exc}") from exc


def _validate_extra_ranges(
    ranges: Iterable[tuple[int, int]], *, name: str = "extra_readable_ranges", flags: int = PF_R,
) -> tuple[AddressRange, ...]:
    try:
        values = tuple(ranges)
    except (TypeError, ValueError) as exc:
        raise PwnDepthRet2DlError(f"{name} must be iterable") from exc
    if len(values) > 4096:
        raise PwnDepthRet2DlError(f"{name} exceeds cap")
    result: list[AddressRange] = []
    for index, pair in enumerate(values):
        if not isinstance(pair, (tuple, list)) or len(pair) != 2:
            raise PwnDepthRet2DlError(f"each {name} item must be (start,end)")
        start = _address(pair[0], f"{name} {index} start")
        end = _integer(pair[1], f"{name} {index} end")
        if end <= start:
            raise PwnDepthRet2DlError(f"{name} ranges must be increasing")
        _address(end - 1, f"{name} {index} final byte")
        result.append(AddressRange(start, end, flags))
    return tuple(result)


def verify_forged_records(
    profile: Ret2DlProfile,
    *,
    blob: bytes | bytearray | memoryview,
    blob_address: int,
    rela_address: int,
    sym_address: int,
    name_address: int,
    requested_symbol: bytes | None = None,
    versym_value: int | None = None,
    versym_memory: bytes | bytearray | memoryview | None = None,
    versym_memory_address: int = 0,
    extra_readable_ranges: Iterable[tuple[int, int]] = (),
    extra_writable_ranges: Iterable[tuple[int, int]] = (),
) -> Ret2DlVerification:
    """Inverse-check forged ``Rela``, ``Sym``, name, and loader dereferences.

    The contiguous staging ``blob`` must already contain the caller's records;
    no bytes are generated here.  If ``DT_VERSYM`` exists, the exact loader
    address must be readable and contain value zero, established either by a
    supplied memory snapshot or by explicit ``versym_value=0``.
    """

    try:
        if not isinstance(profile, Ret2DlProfile):
            raise PwnDepthRet2DlError("profile must come from inspect_elf")
        if not profile.feasible:
            raise PwnDepthRet2DlError("ELF is not feasible: " + "; ".join(profile.blockers))
        if not isinstance(blob, (bytes, bytearray, memoryview)):
            raise PwnDepthRet2DlError("blob must be bytes-like")
        raw = bytes(blob)
        if not raw or len(raw) > MAX_BLOB:
            raise PwnDepthRet2DlError(f"blob must contain 1..{MAX_BLOB} bytes")
        blob_address = _address(blob_address, "blob_address", allow_zero=False)
        blob_end = _checked_end(blob_address, len(raw), "staging blob")
        _address(blob_end - 1, "staging blob final byte")
        rela_address = _address(rela_address, "rela_address", allow_zero=False)
        sym_address = _address(sym_address, "sym_address", allow_zero=False)
        name_address = _address(name_address, "name_address", allow_zero=False)
        extra_writable = _validate_extra_ranges(
            extra_writable_ranges, name="extra_writable_ranges", flags=PF_W,
        )
        writable = profile.writable_ranges + extra_writable
        if not _in_ranges(writable, blob_address, len(raw), PF_W):
            raise PwnDepthRet2DlError(
                "entire staging blob is not inside one supplied writable range"
            )

        jmprel = profile.runtime_tag(DT_JMPREL)
        dynsym = profile.runtime_tag(DT_SYMTAB)
        dynstr = profile.runtime_tag(DT_STRTAB)
        if jmprel is None or dynsym is None or dynstr is None or profile.load_bias is None:
            raise PwnDepthRet2DlError("runtime dynamic-table addresses are unresolved")
        # Check the record grids before interpreting bytes at a shifted address.  This both mirrors
        # the resolver arithmetic and gives a deterministic diagnostic for a one-byte placement bug.
        if rela_address < jmprel or (rela_address - jmprel) % ELF64_RELA_SIZE:
            raise PwnDepthRet2DlError("fake Rela is not congruent with DT_JMPREL")
        if sym_address < dynsym or (sym_address - dynsym) % ELF64_SYM_SIZE:
            raise PwnDepthRet2DlError("fake Sym is not congruent with DT_SYMTAB")

        def take(address: int, size: int, name: str) -> bytes:
            if address < blob_address or address + size > blob_end:
                raise PwnDepthRet2DlError(f"{name} is outside the staging blob")
            offset = address - blob_address
            return raw[offset:offset + size]

        rela = take(rela_address, ELF64_RELA_SIZE, "fake Rela")
        symbol_record = take(sym_address, ELF64_SYM_SIZE, "fake Sym")
        r_offset, r_info, r_addend = _unpack("<QQq", rela, 0, "fake Elf64_Rela")
        st_name, st_info, st_other, st_shndx, st_value, st_size = _unpack(
            "<IBBHQQ", symbol_record, 0, "fake Elf64_Sym"
        )
        if r_addend != 0:
            raise PwnDepthRet2DlError("fake JUMP_SLOT Rela addend must be zero")
        relocation_type = r_info & 0xFFFFFFFF
        symbol_index = r_info >> 32
        if relocation_type != R_X86_64_JUMP_SLOT:
            raise PwnDepthRet2DlError("fake relocation is not R_X86_64_JUMP_SLOT")
        if st_info not in (0, 0x10, 0x12) or st_other != 0 or st_shndx != 0 or st_value != 0 or st_size != 0:
            raise PwnDepthRet2DlError(
                "fake symbol must be undefined default-visibility NOTYPE/FUNC"
            )

        relocation_selector = (rela_address - jmprel) // ELF64_RELA_SIZE
        expected_sym = dynsym + symbol_index * ELF64_SYM_SIZE
        if expected_sym >= UINT64_LIMIT or expected_sym != sym_address:
            raise PwnDepthRet2DlError("r_info symbol index does not select fake Sym from DT_SYMTAB")
        expected_name = dynstr + st_name
        if expected_name >= UINT64_LIMIT or expected_name != name_address:
            raise PwnDepthRet2DlError("st_name does not select supplied name from DT_STRTAB")
        if not blob_address <= name_address < blob_end:
            raise PwnDepthRet2DlError("symbol name begins outside the staging blob")
        name_offset = name_address - blob_address
        terminator = raw.find(b"\x00", name_offset, min(len(raw), name_offset + 256))
        if terminator < 0:
            raise PwnDepthRet2DlError("symbol name is not NUL-terminated within 255 bytes")
        symbol_name = raw[name_offset:terminator]
        if not symbol_name:
            raise PwnDepthRet2DlError("symbol name must be non-empty")
        if requested_symbol is not None:
            if not isinstance(requested_symbol, bytes) or not requested_symbol or b"\x00" in requested_symbol:
                raise PwnDepthRet2DlError("requested_symbol must be non-empty NUL-free bytes")
            if symbol_name != requested_symbol:
                raise PwnDepthRet2DlError("forged symbol name differs from requested_symbol")
        relocation_target = r_offset + (profile.load_bias if profile.pie else 0)
        if relocation_target >= UINT64_LIMIT:
            raise PwnDepthRet2DlError("relocation target overflows after load bias")
        _address(relocation_target, "relocation target", allow_zero=False)
        if not _in_ranges(writable, relocation_target, 8, PF_W):
            raise PwnDepthRet2DlError("Rela r_offset does not resolve to a writable eight-byte target")

        versym_address: int | None = None
        used_versym: int | None = None
        versym = profile.runtime_tag(DT_VERSYM)
        if versym is not None:
            versym_address = versym + 2 * symbol_index
            if versym_address + 2 > UINT64_LIMIT:
                raise PwnDepthRet2DlError("DT_VERSYM dereference overflows")
            _address(versym_address, "DT_VERSYM entry", allow_zero=False)
            _address(versym_address + 1, "DT_VERSYM final byte", allow_zero=False)
            extras = _validate_extra_ranges(extra_readable_ranges)
            memory_raw: bytes | None = None
            memory_start = 0
            if versym_memory is not None:
                if not isinstance(versym_memory, (bytes, bytearray, memoryview)):
                    raise PwnDepthRet2DlError("versym_memory must be bytes-like")
                memory_raw = bytes(versym_memory)
                if not memory_raw or len(memory_raw) > MAX_BLOB:
                    raise PwnDepthRet2DlError("versym_memory must be bounded and non-empty")
                memory_start = _address(versym_memory_address, "versym_memory_address")
                _checked_end(memory_start, len(memory_raw), "versym memory")
                _address(memory_start + len(memory_raw) - 1, "versym memory final byte")
                extras += (AddressRange(memory_start, memory_start + len(memory_raw), PF_R),)
                if memory_start <= versym_address and versym_address + 2 <= memory_start + len(memory_raw):
                    at = versym_address - memory_start
                    used_versym = int.from_bytes(memory_raw[at:at + 2], "little")
            readable = profile.readable_ranges + extras
            if not _in_ranges(readable, versym_address, 2, PF_R):
                raise PwnDepthRet2DlError("computed DT_VERSYM entry is not in supplied readable memory")
            if versym_value is not None:
                if isinstance(versym_value, bool) or not isinstance(versym_value, int) or not 0 <= versym_value <= 0xFFFF:
                    raise PwnDepthRet2DlError("versym_value must be an unsigned 16-bit integer")
                if used_versym is not None and used_versym != versym_value:
                    raise PwnDepthRet2DlError("versym snapshot disagrees with explicit versym_value")
                used_versym = versym_value
            if used_versym is None:
                raise PwnDepthRet2DlError("DT_VERSYM exists; supply its exact value or a memory snapshot")
            if used_versym != 0:
                raise PwnDepthRet2DlError("forged symbol requires an unversioned (zero) VERSYM entry")

        steps = (
            f"stage {len(raw)} verified bytes at {blob_address:#x}",
            f"enter supplied PLT0 {profile.plt0:#x} with relocation selector {relocation_selector}",
            f"_dl_fixup selects symbol index {symbol_index} ({symbol_name!r})",
            f"resolved address is written to {relocation_target:#x}",
        )
        return Ret2DlVerification(
            relocation_selector, symbol_index, symbol_name, relocation_target,
            versym_address, used_versym, steps,
        )
    except PwnDepthRet2DlError:
        raise
    except Exception as exc:  # every malformed public input maps to the declared error
        raise PwnDepthRet2DlError(f"malformed forged records: {exc}") from exc


class _Parser(argparse.ArgumentParser):
    pass


def _number(value: str) -> int:
    try:
        return int(value, 0)
    except (TypeError, ValueError, OverflowError) as exc:
        raise argparse.ArgumentTypeError("expected an integer address") from exc


def _load_config(path: str | Path) -> dict[str, object]:
    try:
        with Path(path).open("rb") as handle:
            raw = handle.read(MAX_BLOB * 2 + 1)
        if len(raw) > MAX_BLOB * 2:
            raise PwnDepthRet2DlError("JSON config exceeds cap")
        value = json.loads(raw.decode("utf-8"))
    except PwnDepthRet2DlError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise PwnDepthRet2DlError(f"invalid JSON config: {exc}") from exc
    if not isinstance(value, dict):
        raise PwnDepthRet2DlError("JSON config root must be an object")
    return value


def _config_int(config: Mapping[str, object], name: str, *, optional: bool = False) -> int | None:
    value = config.get(name)
    if value is None and optional:
        return None
    if isinstance(value, str):
        try:
            value = int(value, 0)
        except (ValueError, OverflowError) as exc:
            raise PwnDepthRet2DlError(f"{name} is not an integer") from exc
    return _integer(value, name)  # type: ignore[arg-type]


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(prog="pwndepth_ret2dlresolve.py")
    sub = parser.add_subparsers(dest="command", required=True)
    inspect_parser = sub.add_parser("inspect")
    inspect_parser.add_argument("elf")
    inspect_parser.add_argument("--load-bias", type=_number)
    inspect_parser.add_argument("--plt0", type=_number)
    inspect_parser.add_argument("--json", action="store_true")
    verify_parser = sub.add_parser("verify")
    verify_parser.add_argument("elf")
    verify_parser.add_argument("config", help="JSON containing forged blob and explicit addresses")
    verify_parser.add_argument("--json", action="store_true")
    try:
        try:
            args = parser.parse_args(argv)
        except SystemExit as exc:
            return exc.code if isinstance(exc.code, int) else 2
        if args.command == "inspect":
            profile = inspect_elf(args.elf, load_bias=args.load_bias, plt0=args.plt0)
            rendered = profile.as_dict()
            if args.json:
                print(json.dumps(rendered, sort_keys=True))
            else:
                print("SUPPORTED" if profile.feasible else "UNSUPPORTED")
                for reason in profile.blockers:
                    print(f"blocker: {reason}")
                for warning in profile.warnings:
                    print(f"warning: {warning}")
            return 0 if profile.feasible else 1
        config = _load_config(args.config)
        profile = inspect_elf(
            args.elf,
            load_bias=_config_int(config, "load_bias", optional=True),
            plt0=_config_int(config, "plt0"),
        )
        try:
            blob = bytes.fromhex(str(config.get("blob_hex", "")))
        except (ValueError, TypeError) as exc:
            raise PwnDepthRet2DlError("blob_hex must be hexadecimal") from exc
        symbol_value = config.get("requested_symbol")
        requested = None if symbol_value is None else str(symbol_value).encode("ascii", "strict")
        def config_ranges(name: str) -> list[tuple[int, int]]:
            values = config.get(name, [])
            if not isinstance(values, list):
                raise PwnDepthRet2DlError(f"{name} must be a JSON list")
            parsed_ranges: list[tuple[int, int]] = []
            for pair in values:
                if not isinstance(pair, list) or len(pair) != 2:
                    raise PwnDepthRet2DlError(f"{name} items must be two-item lists")
                parsed: list[int] = []
                for item in pair:
                    if isinstance(item, str):
                        item = int(item, 0)
                    parsed.append(_integer(item, name))
                parsed_ranges.append((parsed[0], parsed[1]))
            return parsed_ranges

        extra_ranges = config_ranges("extra_readable_ranges")
        extra_writable = config_ranges("extra_writable_ranges")
        result = verify_forged_records(
            profile,
            blob=blob,
            blob_address=_config_int(config, "blob_address"),
            rela_address=_config_int(config, "rela_address"),
            sym_address=_config_int(config, "sym_address"),
            name_address=_config_int(config, "name_address"),
            requested_symbol=requested,
            versym_value=_config_int(config, "versym_value", optional=True),
            extra_readable_ranges=extra_ranges,
            extra_writable_ranges=extra_writable,
        )
        rendered = {"profile": profile.as_dict(), "verification": result.as_dict()}
        print(json.dumps(rendered, sort_keys=True) if args.json else json.dumps(result.as_dict(), indent=2))
        return 0
    except PwnDepthRet2DlError as exc:
        print(f"pwndepth_ret2dlresolve: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # guarded CLI boundary
        # CLI is also fail closed even if a future argparse/config edge bypasses a helper.
        print(f"pwndepth_ret2dlresolve: invalid input: {exc}", file=sys.stderr)
        return 2


__all__ = [
    "AddressRange", "PwnDepthRet2DlError", "Ret2DlProfile", "Ret2DlVerification",
    "inspect_elf", "verify_forged_records", "main",
]


if __name__ == "__main__":
    raise SystemExit(main())
