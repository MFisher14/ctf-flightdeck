#!/usr/bin/env python3
"""Symbols from the container's own table, keyed by the container read from the magic (B-216).

  .venv/bin/python solvers/binary/container_symbols.py SAMPLE [...]   what each table states

Huntress Day 17 lost 14 min on COFF symbol names of the PE builds of a sample whose ELF builds were read
from `.symtab` (row 328), and 1 h 43 min on a stripped ELF whose symbol-derived field was the literal
`none` (row 323). Both were fixed for one prefix. This module states, for any ELF, PE or thin Mach-O:

  container   elf | pe | macho, from the magic
  table       the table the names come from: symtab (ELF SHT_SYMTAB), coff (the PE COFF symbol table),
              macho (LC_SYMTAB), or None when the container carries none
  names       every entry's name in raw table order (ELF: every SHT_SYMTAB in section order; COFF: the
              primary records, auxiliary records skipped, long names through the string table)
  functions   the defined functions among them, raw order (ELF STT_FUNC with a section; COFF type 0x20
              with a section number > 0; Mach-O N_SECT entries that are not debug stabs)
  exports     the defined functions the image exports (ELF .dynsym; PE export directory names)
  absent      True only when the container PROVES no table names a function: the section table (ELF),
              the COFF header and export directory (PE) or the load commands (Mach-O) were read whole,
              none holds a symbol table, and nothing is exported. None when that could not be read.

read() returns None for a file that is none of the three, or whose headers are cut. Struct reads only,
no program is run and no library is loaded; tables are bounded (TABLE_MAX entries).
"""
from __future__ import annotations

import struct
import sys
from collections import namedtuple
from pathlib import Path

import binfmt

TABLE_MAX = 1 << 18
Symbols = namedtuple("Symbols", "container table names functions exports absent why")


def container_of(data: bytes):
    """elf | pe | macho | None, from the magic alone."""
    if data[:4] == b"\x7fELF":
        return "elf"
    if data[:2] == b"MZ":
        return "pe"
    if data[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce"):
        return "macho"
    return None


# ---------------------------------------------------------------------------- ELF

def _elf_table(data: bytes, info: dict, sec: dict):
    """[(name, type, shndx)] of one ELF symbol table section, or None when it cannot be read."""
    secs = info["sections"]
    if sec["link"] >= len(secs):
        return None
    end, wide = ("<" if info["ei_data"] == 1 else ">"), info["bits"] == 64
    size = 24 if wide else 16
    count = sec["size"] // size
    if count > TABLE_MAX or sec["offset"] + count * size > len(data):
        return None
    strs = secs[sec["link"]]["offset"]
    out = []
    try:
        for k in range(count):
            at = sec["offset"] + k * size
            name = struct.unpack_from(end + "I", data, at)[0]
            st_info = data[at + (4 if wide else 12)]
            shndx = struct.unpack_from(end + "H", data, at + (6 if wide else 14))[0]
            out.append((binfmt._cstr(data, strs + name, 4096) or "", st_info & 0xF, shndx))
    except (struct.error, IndexError):
        return None
    return out


def _elf(data: bytes):
    info = binfmt.elf(data)
    if not info:
        return None
    if not info.get("sections"):
        return Symbols("elf", None, [], [], [], None, "no section header table is readable")
    tables = [s for s in info["sections"] if s["type"] == 2]
    names, funcs = [], []
    for sec in tables:
        rows = _elf_table(data, info, sec)
        if rows is None:
            return Symbols("elf", "symtab", [], [], [], None, "a .symtab section cannot be read")
        names += [n for n, _, _ in rows]
        funcs += [n for n, t, x in rows if t == 2 and x != 0 and n]
    exports = []
    for sec in (s for s in info["sections"] if s["type"] == 11):
        rows = _elf_table(data, info, sec)
        if rows is None:
            return Symbols("elf", "symtab" if tables else None, names, funcs, [], None, ".dynsym cannot be read")
        exports += [n for n, t, x in rows if t == 2 and x != 0 and n]
    if tables:
        return Symbols("elf", "symtab", names, funcs, exports, False, f"{len(tables)} SHT_SYMTAB section(s)")
    if exports:
        return Symbols("elf", None, [], [], exports, False, "no .symtab, but .dynsym exports a defined function")
    return Symbols("elf", None, [], [], [], True, "section table read: no SHT_SYMTAB, no defined .dynsym function")


# ---------------------------------------------------------------------------- PE

def _pe_exports(data: bytes, info: dict):
    """The export directory's names in its own order, [] when the image has none, None when it is cut."""
    rva, size = info["dirs"].get("export", (0, 0))
    if not rva or not size:
        return []
    at = binfmt.pe_offset(info["sections"], rva)
    if at is None:
        return None
    try:
        count, names_rva = struct.unpack_from("<I", data, at + 24)[0], struct.unpack_from("<I", data, at + 32)[0]
        if count > TABLE_MAX:
            return None
        table = binfmt.pe_offset(info["sections"], names_rva) if count else None
        out = []
        for k in range(count):
            name_at = binfmt.pe_offset(info["sections"], struct.unpack_from("<I", data, table + 4 * k)[0])
            if name_at is None:
                return None
            out.append(binfmt._cstr(data, name_at, 4096) or "")
    except (struct.error, TypeError):
        return None
    return out


def _pe(data: bytes):
    info = binfmt.pe(data)
    if info is None:
        return None
    nt = struct.unpack_from("<I", data, 0x3C)[0]
    ptr, count = struct.unpack_from("<II", data, nt + 12)
    exports = _pe_exports(data, info)
    if exports is None:
        return Symbols("pe", None, [], [], [], None, "the export directory cannot be read")
    if not ptr or not count:
        if exports:
            return Symbols("pe", None, [], [], exports, False, "no COFF symbol table, but the image exports names")
        return Symbols("pe", None, [], [], [], True, "PointerToSymbolTable is 0 and nothing is exported")
    rows = binfmt.pe_coff_symbols(data)
    if rows is None:
        return Symbols("pe", "coff", [], [], exports, None, "the COFF symbol table is cut or malformed")
    funcs = []
    for index, name, section, _ in rows:
        kind = struct.unpack_from("<H", data, ptr + 18 * index + 14)[0]
        if section > 0 and (kind >> 4) & 0x3 == 2 and name:
            funcs.append(name)
    return Symbols("pe", "coff", [n for _, n, _, _ in rows], funcs, exports, False,
                   f"{len(rows)} COFF symbol record(s)")


# ---------------------------------------------------------------------------- Mach-O

MACHO = {b"\xcf\xfa\xed\xfe": (64, "<"), b"\xce\xfa\xed\xfe": (32, "<"), b"\xfe\xed\xfa\xcf": (64, ">"),
         b"\xfe\xed\xfa\xce": (32, ">")}


def _macho(data: bytes):
    if data[:4] not in MACHO or len(data) < 28:
        return None
    bits, end = MACHO[data[:4]]
    try:
        ncmds, sizeofcmds = struct.unpack_from(end + "II", data, 16)
        cur = 32 if bits == 64 else 28
        if ncmds > 4096 or cur + sizeofcmds > len(data):
            return None
        symtab = None
        for _ in range(ncmds):
            cmd, size = struct.unpack_from(end + "II", data, cur)
            if size < 8 or cur + size > len(data):
                return None
            if cmd == 0x2:
                symtab = struct.unpack_from(end + "IIII", data, cur + 8)
            cur += size
        if symtab is None or symtab[1] == 0:
            return Symbols("macho", None, [], [], [], True, "no LC_SYMTAB entries in the load commands")
        symoff, nsyms, stroff, strsize = symtab
        step = 16 if bits == 64 else 12
        if nsyms > TABLE_MAX or symoff + nsyms * step > len(data) or stroff + strsize > len(data):
            return Symbols("macho", "macho", [], [], [], None, "LC_SYMTAB points outside the file")
        names, funcs, exports = [], [], []
        for k in range(nsyms):
            at = symoff + k * step
            strx, ntype, nsect = struct.unpack_from(end + "IBB", data, at)
            name = binfmt._cstr(data, stroff + strx, 4096) if strx < strsize else ""
            name = name or ""
            names.append(name)
            if not ntype & 0xE0 and ntype & 0x0E == 0x0E and nsect and name:
                funcs.append(name)
                if ntype & 0x01:
                    exports.append(name)
    except struct.error:
        return None
    return Symbols("macho", "macho", names, funcs, exports, False, f"LC_SYMTAB with {nsyms} entr(ies)")


def read(data) -> Symbols | None:
    """The Symbols of one sample, or None for a file that is not a readable ELF, PE or thin Mach-O."""
    if not isinstance(data, (bytes, bytearray)):
        return None
    data = bytes(data)
    kind = container_of(data)
    return {"elf": _elf, "pe": _pe, "macho": _macho}.get(kind, lambda _: None)(data)


def absent(data) -> tuple:
    """(True, why) when the container proves no symbol table names a function; (False, why) otherwise."""
    got = read(data)
    if got is None:
        return False, "not a readable ELF, PE or thin Mach-O"
    return got.absent is True, got.why


def _main(argv) -> int:
    if not argv:
        print("usage: container_symbols.py SAMPLE [...]", file=sys.stderr)
        return 2
    for arg in argv:
        got = read(Path(arg).read_bytes())
        if got is None:
            print(f"{arg}: not a readable ELF, PE or thin Mach-O")
            continue
        print(f"{arg}: container={got.container} table={got.table} absent={got.absent} ({got.why})")
        print(f"  functions ({len(got.functions)}): {', '.join(got.functions[:20])}")
        print(f"  exports ({len(got.exports)}): {', '.join(got.exports[:20])}")
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
