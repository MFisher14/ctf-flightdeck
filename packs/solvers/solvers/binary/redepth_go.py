#!/usr/bin/env python3
"""Bounded, static Go 1.20+ ``pclntab`` function-name recovery.

This parser implements the layouts published by the Go project for
``runtime.pcHeader``, ``runtime.functab``, and ``runtime._func``.  It does not
load or execute the target.  A table may be supplied directly, or located by
its structurally validated magic inside an ELF, Mach-O, PE, or opaque blob.

The Go 1.20 magic is still the current magic in later Go releases.  File/line
PC-value programs and ``moduledata`` relocation state are deliberately not
decoded here; the report labels the corresponding raw offsets honestly.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import json
from pathlib import Path
import sys
from typing import Any


GO120_MAGIC = 0xFFFFFFF1
_MAGIC_LE = b"\xf1\xff\xff\xff"
_MAGIC_BE = b"\xff\xff\xff\xf1"

MAX_INPUT = 128 << 20
MAX_FUNCTIONS = 500_000
MAX_FILES = 2_000_000
MAX_NAME_BYTES = 4096
MAX_AUX_WORDS = 4096
MAX_MAGIC_CANDIDATES = 64
MAX_SCAN_FUNCTIONS = 750_000
_FUNC_SIZE = 44


class RedepthGoError(ValueError):
    """Malformed, unsupported, ambiguous, or resource-capped Go metadata."""


@dataclass(frozen=True)
class PcHeader:
    """Decoded Go 1.20+ ``runtime.pcHeader`` fields.

    The six table offsets are relative to the beginning of this header, as
    encoded by the linker.  ``pcln_offset`` is also the base used by encoded
    function-record offsets.  ``text_start`` is the raw third word: Go 1.20
    defines it as the entry base, but an on-disk relocation or a compatible
    newer linker can leave/reserve it as zero and rely on ``moduledata.text``.
    """

    magic_hex: str
    version: str
    byte_order: str
    pointer_size: int
    minimum_instruction_size: int
    header_size: int
    function_count: int
    file_count: int
    text_start: int
    text_start_available: bool
    funcname_offset: int
    cu_offset: int
    filetab_offset: int
    pctab_offset: int
    pcln_offset: int


@dataclass(frozen=True)
class GoFunction:
    """One validated function-table entry and its fixed ``runtime._func``."""

    index: int
    name: str
    entry_offset: int
    end_offset: int
    nominal_entry_pc: int | None
    nominal_end_pc: int | None
    functab_entry_offset: int
    functab_entry_file_offset: int
    func_offset: int
    func_record_offset: int
    func_record_file_offset: int
    name_offset: int
    name_record_offset: int
    name_record_file_offset: int
    args_size: int
    defer_return_offset: int
    pcsp_offset: int
    pcfile_offset: int
    pcline_offset: int
    pcdata_count: int
    cu_offset: int
    start_line: int
    func_id: int
    flags: int
    funcdata_count: int
    pcdata_offsets: tuple[int, ...]
    funcdata_offsets: tuple[int, ...]


@dataclass(frozen=True)
class GoPclnReport:
    """A validated Go pclntab plus exact table/file locations."""

    container: str
    table_offset: int
    header: PcHeader
    funcname_file_offset: int
    functab_file_offset: int
    validated_span_end_offset: int
    validated_span_end_file_offset: int
    functions: tuple[GoFunction, ...]
    limitations: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _fail(message: str) -> None:
    raise RedepthGoError(message)


def _require_bytes(data: object) -> bytes:
    if not isinstance(data, bytes):
        _fail("input must be bytes")
    if len(data) > MAX_INPUT:
        _fail(f"input exceeds {MAX_INPUT}-byte cap")
    return data


def _uint(data: bytes, offset: int, size: int, byte_order: str) -> int:
    if offset < 0 or size not in (1, 2, 4, 8) or offset > len(data) - size:
        _fail("truncated integer field")
    return int.from_bytes(data[offset:offset + size], byte_order, signed=False)


def _int32(data: bytes, offset: int, byte_order: str) -> int:
    if offset < 0 or offset > len(data) - 4:
        _fail("truncated signed integer field")
    return int.from_bytes(data[offset:offset + 4], byte_order, signed=True)


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & -alignment


def _parse_header(data: bytes, table_offset: int) -> PcHeader:
    if table_offset < 0 or table_offset > len(data) - 8:
        _fail("truncated pcHeader")

    raw_magic = data[table_offset:table_offset + 4]
    if raw_magic == _MAGIC_LE:
        byte_order = "little"
    elif raw_magic == _MAGIC_BE:
        byte_order = "big"
    else:
        _fail("not a Go 1.20+ pclntab magic")

    if data[table_offset + 4:table_offset + 6] != b"\0\0":
        _fail("pcHeader padding bytes are nonzero")
    quantum = data[table_offset + 6]
    if quantum not in (1, 2, 4):
        _fail("invalid minimum instruction size")
    pointer_size = data[table_offset + 7]
    if pointer_size not in (4, 8):
        _fail("invalid pointer size")

    header_size = 8 + 8 * pointer_size
    available = len(data) - table_offset
    if available < header_size:
        _fail("truncated pcHeader words")

    words = tuple(
        _uint(data, table_offset + 8 + index * pointer_size, pointer_size, byte_order)
        for index in range(8)
    )
    nfunc, nfiles, text_start, funcname, cutab, filetab, pctab, pcln = words

    if nfunc == 0:
        _fail("pcHeader has no functions")
    if nfunc > MAX_FUNCTIONS:
        _fail(f"function count exceeds {MAX_FUNCTIONS} cap")
    if nfiles > MAX_FILES:
        _fail(f"file count exceeds {MAX_FILES} cap")

    # Go's carrier symbol is laid out in this order.  Equal boundaries are
    # permitted for empty CU/file/PC tables, but a nonempty function-name
    # table must exist for every function record.
    if not (header_size <= funcname < cutab <= filetab <= pctab <= pcln < available):
        _fail("pcHeader table offsets are out of range or out of order")
    if cutab % 4 or pcln % 4:
        _fail("uint32 table is not 4-byte aligned")

    functab_size = (2 * nfunc + 1) * 4
    if functab_size > available - pcln:
        _fail("truncated function lookup table")

    return PcHeader(
        magic_hex="0xfffffff1",
        version="Go 1.20+",
        byte_order=byte_order,
        pointer_size=pointer_size,
        minimum_instruction_size=quantum,
        header_size=header_size,
        function_count=nfunc,
        file_count=nfiles,
        text_start=text_start,
        # Go 1.20 defines textStart here.  A pending on-disk relocation or a
        # compatible newer linker may retain a zero word and use moduledata.
        text_start_available=text_start != 0,
        funcname_offset=funcname,
        cu_offset=cutab,
        filetab_offset=filetab,
        pctab_offset=pctab,
        pcln_offset=pcln,
    )


def _decode_name(data: bytes, base: int, header: PcHeader, name_offset: int) -> tuple[str, int]:
    name_table_size = header.cu_offset - header.funcname_offset
    if name_offset < 0 or name_offset >= name_table_size:
        _fail("function name offset is outside funcnametab")
    relative = header.funcname_offset + name_offset
    absolute = base + relative
    if name_offset and data[absolute - 1] != 0:
        _fail("function name offset points into the middle of a name")
    table_end = base + header.cu_offset
    search_end = min(table_end, absolute + MAX_NAME_BYTES + 1)
    terminator = data.find(b"\0", absolute, search_end)
    if terminator < 0:
        _fail("unterminated or overlong function name")
    raw = data[absolute:terminator]
    if not raw:
        _fail("empty function name")
    try:
        name = raw.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise RedepthGoError("function name is not valid UTF-8") from exc
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in name):
        _fail("function name contains a control character")
    return name, relative


def _validate_pctab_offset(value: int, size: int, label: str) -> None:
    if value and value >= size:
        _fail(f"{label} is outside pctab")


def _parse_with_header(
    data: bytes,
    table_offset: int,
    header: PcHeader,
    container: str,
) -> GoPclnReport:
    order = header.byte_order
    nfunc = header.function_count
    functab_relative = header.pcln_offset
    functab_absolute = table_offset + functab_relative
    functab_size = (2 * nfunc + 1) * 4

    entries: list[int] = []
    func_offsets: list[int] = []
    for index in range(nfunc):
        position = functab_absolute + index * 8
        entries.append(_uint(data, position, 4, order))
        func_offsets.append(_uint(data, position + 4, 4, order))
    end_entry = _uint(data, functab_absolute + nfunc * 8, 4, order)

    previous = entries[0]
    for entry in entries[1:]:
        if entry < previous:
            _fail("function entries are not sorted by PC offset")
        previous = entry
    if end_entry < previous:
        _fail("terminal function entry precedes the final function")

    max_pointer = (1 << (8 * header.pointer_size)) - 1
    if header.text_start > max_pointer - end_entry:
        _fail("textStart plus terminal function offset overflows target pointer")

    first_record = _align(functab_size, header.pointer_size)
    if func_offsets[0] != first_record:
        _fail("first function record is not at the canonical aligned offset")
    for left, right in zip(func_offsets, func_offsets[1:]):
        if right <= left:
            _fail("function record offsets are not strictly increasing")
        if right % header.pointer_size:
            _fail("function record is not pointer-aligned")

    pctab_size = header.pcln_offset - header.pctab_offset
    cutab_size = header.filetab_offset - header.cu_offset
    functions: list[GoFunction] = []
    name_cache: dict[int, tuple[str, int]] = {}
    maximum_record_end = first_record

    for index, (entry, func_offset) in enumerate(zip(entries, func_offsets)):
        if func_offset % header.pointer_size:
            _fail("function record is not pointer-aligned")
        record_relative = header.pcln_offset + func_offset
        record_absolute = table_offset + record_relative
        if record_absolute < 0 or record_absolute > len(data) - _FUNC_SIZE:
            _fail("truncated function record")

        record_entry = _uint(data, record_absolute, 4, order)
        if record_entry != entry:
            _fail("function record entry does not match functab entry")
        name_offset = _int32(data, record_absolute + 4, order)
        cached_name = name_cache.get(name_offset)
        if cached_name is None:
            cached_name = _decode_name(data, table_offset, header, name_offset)
            name_cache[name_offset] = cached_name
        name, name_relative = cached_name
        args_size = _int32(data, record_absolute + 8, order)
        defer_return = _uint(data, record_absolute + 12, 4, order)
        pcsp = _uint(data, record_absolute + 16, 4, order)
        pcfile = _uint(data, record_absolute + 20, 4, order)
        pcline = _uint(data, record_absolute + 24, 4, order)
        npcdata = _uint(data, record_absolute + 28, 4, order)
        cu_offset = _uint(data, record_absolute + 32, 4, order)
        start_line = _int32(data, record_absolute + 36, order)
        func_id = data[record_absolute + 40]
        flags = data[record_absolute + 41]
        if data[record_absolute + 42] != 0:
            _fail("function record padding byte is nonzero")
        nfuncdata = data[record_absolute + 43]

        if npcdata > MAX_AUX_WORDS or npcdata + nfuncdata > MAX_AUX_WORDS:
            _fail(f"function auxiliary words exceed {MAX_AUX_WORDS} cap")
        aux_size = 4 * (npcdata + nfuncdata)
        record_end_absolute = record_absolute + _FUNC_SIZE + aux_size
        if record_end_absolute > len(data):
            _fail("truncated function auxiliary arrays")
        record_end = func_offset + _FUNC_SIZE + aux_size

        if index + 1 < nfunc:
            expected = _align(record_end, header.pointer_size)
            if func_offsets[index + 1] != expected:
                _fail("next function record does not follow the published layout")

        function_size = (entries[index + 1] if index + 1 < nfunc else end_entry) - entry
        if defer_return and defer_return > function_size:
            _fail("deferreturn offset exceeds function extent")

        _validate_pctab_offset(pcsp, pctab_size, "pcsp offset")
        _validate_pctab_offset(pcfile, pctab_size, "pcfile offset")
        _validate_pctab_offset(pcline, pctab_size, "pcline offset")
        # Despite its historical ``cuOffset`` name, the runtime uses this as
        # an index into its []uint32 cutab (and debug/gosym multiplies it by
        # four before slicing raw bytes).
        if cu_offset != 0xFFFFFFFF and cu_offset >= cutab_size // 4:
            _fail("compilation-unit index is outside cutab")

        pcdata_base = record_absolute + _FUNC_SIZE
        pcdata_offsets = tuple(
            _uint(data, pcdata_base + item * 4, 4, order)
            for item in range(npcdata)
        )
        for value in pcdata_offsets:
            _validate_pctab_offset(value, pctab_size, "pcdata offset")
        funcdata_base = pcdata_base + 4 * npcdata
        funcdata_offsets = tuple(
            _uint(data, funcdata_base + item * 4, 4, order)
            for item in range(nfuncdata)
        )

        next_entry = entries[index + 1] if index + 1 < nfunc else end_entry
        functab_entry_relative = header.pcln_offset + index * 8
        functions.append(GoFunction(
            index=index,
            name=name,
            entry_offset=entry,
            end_offset=next_entry,
            nominal_entry_pc=header.text_start + entry if header.text_start_available else None,
            nominal_end_pc=header.text_start + next_entry if header.text_start_available else None,
            functab_entry_offset=functab_entry_relative,
            functab_entry_file_offset=table_offset + functab_entry_relative,
            func_offset=func_offset,
            func_record_offset=record_relative,
            func_record_file_offset=record_absolute,
            name_offset=name_offset,
            name_record_offset=name_relative,
            name_record_file_offset=table_offset + name_relative,
            args_size=args_size,
            defer_return_offset=defer_return,
            pcsp_offset=pcsp,
            pcfile_offset=pcfile,
            pcline_offset=pcline,
            pcdata_count=npcdata,
            cu_offset=cu_offset,
            start_line=start_line,
            func_id=func_id,
            flags=flags,
            funcdata_count=nfuncdata,
            pcdata_offsets=pcdata_offsets,
            funcdata_offsets=funcdata_offsets,
        ))
        maximum_record_end = max(maximum_record_end, record_end)

    validated_end = header.pcln_offset + maximum_record_end
    pc_limitation = (
        "nominal PCs use pcHeader.textStart; relocatable or multi-text-section images may need moduledata relocation state"
        if header.text_start_available
        else "pcHeader entry-base word is zero/unavailable; absolute PCs require moduledata or container text mapping"
    )
    return GoPclnReport(
        container=container,
        table_offset=table_offset,
        header=header,
        funcname_file_offset=table_offset + header.funcname_offset,
        functab_file_offset=functab_absolute,
        validated_span_end_offset=validated_end,
        validated_span_end_file_offset=table_offset + validated_end,
        functions=tuple(functions),
        limitations=(
            "file/line PC-value programs are not decoded",
            pc_limitation,
        ),
    )


def _container_kind(data: bytes, table_offset: int) -> str:
    if table_offset == 0:
        return "raw-pclntab"
    if len(data) >= 16 and data.startswith(b"\x7fELF") and data[4] in (1, 2) and data[5] in (1, 2):
        return "ELF"
    macho_magics = {
        b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
        b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca",
    }
    if data[:4] in macho_magics:
        return "Mach-O"
    if len(data) >= 0x40 and data.startswith(b"MZ"):
        pe_offset = int.from_bytes(data[0x3C:0x40], "little")
        if 0 <= pe_offset <= len(data) - 4 and data[pe_offset:pe_offset + 4] == b"PE\0\0":
            return "PE"
    return "binary-blob"


def _magic_offsets(data: bytes) -> tuple[int, ...]:
    offsets: set[int] = set()
    for magic in (_MAGIC_LE, _MAGIC_BE):
        start = 0
        while True:
            found = data.find(magic, start)
            if found < 0:
                break
            # Large native executables naturally contain many occurrences of
            # either four-byte magic pattern in code and data.  Only count a
            # candidate after the invariant padding/quantum/ptr-size suffix
            # from pcHeader also matches.
            if (
                found <= len(data) - 8
                and data[found + 4:found + 6] == b"\0\0"
                and data[found + 6] in (1, 2, 4)
                and data[found + 7] in (4, 8)
            ):
                offsets.add(found)
                if len(offsets) > MAX_MAGIC_CANDIDATES:
                    _fail(f"more than {MAX_MAGIC_CANDIDATES} pclntab header candidates")
            start = found + 1
    return tuple(sorted(offsets))


def parse_pclntab(data: bytes) -> GoPclnReport:
    """Parse a Go 1.20+ pclntab beginning exactly at byte zero.

    Malformed or unsupported input raises only :class:`RedepthGoError`.
    """

    try:
        blob = _require_bytes(data)
        header = _parse_header(blob, 0)
        return _parse_with_header(blob, 0, header, "raw-pclntab")
    except RedepthGoError:
        raise
    except Exception as exc:
        raise RedepthGoError("unexpected malformed pclntab structure") from exc


def analyze_go(data: bytes) -> GoPclnReport:
    """Locate and parse one validated Go 1.20+ pclntab in a binary blob.

    ELF, Mach-O, and PE containers need no execution and no platform-specific
    loader.  Multiple independently valid tables are rejected as ambiguous.
    Malformed or unsupported input raises only :class:`RedepthGoError`.
    """

    try:
        blob = _require_bytes(data)
        candidates = _magic_offsets(blob)
        if not candidates:
            _fail("no Go 1.20+ pclntab magic found")

        reports: list[GoPclnReport] = []
        failures: list[str] = []
        scan_functions = 0
        for offset in candidates:
            try:
                header = _parse_header(blob, offset)
                scan_functions += header.function_count
                if scan_functions > MAX_SCAN_FUNCTIONS:
                    _fail(f"candidate function work exceeds {MAX_SCAN_FUNCTIONS} cap")
                reports.append(_parse_with_header(
                    blob,
                    offset,
                    header,
                    _container_kind(blob, offset),
                ))
            except RedepthGoError as exc:
                failures.append(str(exc))

        if not reports:
            detail = failures[0] if len(candidates) == 1 and failures else "all candidates failed validation"
            _fail(f"no valid Go 1.20+ pclntab: {detail}")
        if len(reports) != 1:
            _fail("multiple valid Go pclntabs found; extract one table and call parse_pclntab")
        return reports[0]
    except RedepthGoError:
        raise
    except Exception as exc:
        raise RedepthGoError("unexpected malformed Go binary structure") from exc


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Statically recover Go 1.20+ pclntab function names",
    )
    parser.add_argument("input", help="ELF, Mach-O, PE, blob, or raw pclntab")
    parser.add_argument("--raw", action="store_true", help="require pclntab at byte zero")
    parser.add_argument("--pretty", action="store_true", help="indent JSON output")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _argument_parser()
    try:
        try:
            args = parser.parse_args(argv)
        except SystemExit as exc:
            return exc.code if isinstance(exc.code, int) else 2

        path = Path(args.input)
        try:
            if path.stat().st_size > MAX_INPUT:
                raise RedepthGoError(f"input exceeds {MAX_INPUT}-byte cap")
            data = path.read_bytes()
        except RedepthGoError:
            raise
        except OSError as exc:
            raise RedepthGoError(f"cannot read input: {exc}") from exc
        report = parse_pclntab(data) if args.raw else analyze_go(data)
        print(json.dumps(report.to_dict(), indent=2 if args.pretty else None, sort_keys=True))
        return 0
    except RedepthGoError as exc:
        print(f"redepth_go: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"redepth_go: unexpected failure: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
