#!/usr/bin/env python3
"""Header readers for the Binary lane's field catalog: ELF, PE, Mach-O (thin and fat), WebAssembly, DEX, Neko.

  .venv/bin/python solvers/binary/binfmt.py <sample> [...]      print what each reader states

Plain struct reads, no library and no program: a reader costs microseconds to a few milliseconds
whatever the size of the file (it reads tables, never the whole image), so it is safe inside a timed
window. Each reader returns a dict of the facts the file's own tables state, or None for a file that
is not its format or is cut inside a table it needs; a table that is absent is stated as absent
(`sections: None` for an ELF without a section header table), which is how field_catalog.py tells
"the container proves it is not there" from "not read".

Nothing here names anything: field_catalog.py turns these facts into unsure answers.
"""
import struct
import sys
from pathlib import Path

TABLE_MAX = 4096          # entries of one table read (sections, segments, load commands, wasm sections)
NAME_MAX = 256

# ---------------------------------------------------------------------------- ELF

PT = {0: "PT_NULL", 1: "PT_LOAD", 2: "PT_DYNAMIC", 3: "PT_INTERP", 4: "PT_NOTE", 6: "PT_PHDR", 7: "PT_TLS",
      0x6474E550: "PT_GNU_EH_FRAME", 0x6474E551: "PT_GNU_STACK", 0x6474E552: "PT_GNU_RELRO",
      0x6474E553: "PT_GNU_PROPERTY"}
DT_NEEDED, DT_STRTAB, DT_SONAME, DT_RPATH, DT_BIND_NOW, DT_RUNPATH, DT_FLAGS, DT_FLAGS_1 = 1, 5, 14, 15, 24, 29, 30, \
    0x6FFFFFFB
DF_BIND_NOW, DF_1_NOW, DF_1_PIE = 0x8, 0x1, 0x08000000


def _cstr(data: bytes, at: int, limit: int = NAME_MAX):
    if at < 0 or at >= len(data):
        return None
    end = data.find(b"\0", at, at + limit)
    if end < 0:
        return None
    return data[at:end].decode("utf-8", "replace")


def elf(data: bytes):
    """The ELF header, its program headers and section headers, the dynamic table and the build id.

    None for a file that is not an ELF with a readable header. `sections` is None when the file has
    no section header table (e_shoff 0) or the table lies outside the file; `segments` likewise."""
    if data[:4] != b"\x7fELF" or len(data) < 52 or data[4] not in (1, 2) or data[5] not in (1, 2):
        return None
    wide, end = data[4] == 2, "<" if data[5] == 1 else ">"
    try:
        if wide:
            (e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum,
             e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from(end + "HHIQQQIHHHHHH", data, 16)
        else:
            (e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum,
             e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from(end + "HHIIIIIHHHHHH", data, 16)
    except struct.error:
        return None
    out = {"bits": 64 if wide else 32, "ei_class": data[4], "ei_data": data[5], "ei_version": data[6],
           "ei_osabi": data[7], "ei_abiversion": data[8], "e_type": e_type, "e_machine": e_machine,
           "e_version": e_version, "e_entry": e_entry, "e_phoff": e_phoff, "e_shoff": e_shoff, "e_flags": e_flags,
           "e_ehsize": e_ehsize, "e_phentsize": e_phentsize, "e_phnum": e_phnum, "e_shentsize": e_shentsize,
           "e_shnum": e_shnum, "e_shstrndx": e_shstrndx, "sections": None, "segments": None, "interp": None,
           "dynamic": None, "needed": None, "soname": None, "rpath": None, "runpath": None, "build_id": None,
           "bind_now": None, "flags_1": None}
    # Extended counts/indices live in section zero. Preserve the raw e_* header
    # fields above, using the resolved values only to traverse the tables.
    # When section zero is unreadable (garbage e_shoff), fall through with the
    # raw counts: the section table is then unreadable too, but the program
    # headers do not depend on it and must still be reported.
    phnum, shnum, shstrndx = e_phnum, e_shnum, e_shstrndx
    zero = None
    if (e_shoff and (e_shnum == 0 or e_shstrndx == 0xFFFF or e_phnum == 0xFFFF)
            and e_shentsize >= (64 if wide else 40) and e_shoff + e_shentsize <= len(data)):
        try:
            zero = struct.unpack_from(end + ("IIQQQQIIQQ" if wide else "IIIIIIIIII"), data, e_shoff)
        except struct.error:
            zero = None
    if zero is not None:
        if e_shnum == 0:
            shnum = zero[5]           # sh_size
        if e_shstrndx == 0xFFFF:
            shstrndx = zero[6]        # sh_link
        if e_phnum == 0xFFFF:
            phnum = zero[7]           # sh_info
    # program headers
    segs = []
    try:
        if e_phoff and 0 < phnum <= TABLE_MAX and e_phoff + phnum * e_phentsize <= len(data):
            for i in range(phnum):
                at = e_phoff + i * e_phentsize
                if wide:
                    p_type, p_flags, p_offset, p_vaddr, _, p_filesz, p_memsz, _ = struct.unpack_from(end + "IIQQQQQQ",
                                                                                                    data, at)
                else:
                    p_type, p_offset, p_vaddr, _, p_filesz, p_memsz, p_flags, _ = struct.unpack_from(end + "IIIIIIII",
                                                                                                    data, at)
                segs.append({"type": p_type, "flags": p_flags, "offset": p_offset, "vaddr": p_vaddr,
                             "filesz": p_filesz, "memsz": p_memsz})
            out["segments"] = segs
    except struct.error:
        out["segments"] = None
    # section headers
    try:
        if e_shoff and 0 < shnum <= TABLE_MAX and e_shoff + shnum * e_shentsize <= len(data):
            raw = []
            for i in range(shnum):
                at = e_shoff + i * e_shentsize
                if wide:
                    name, typ, flags, addr, off, size, link, info, _, entsize = struct.unpack_from(end + "IIQQQQIIQQ",
                                                                                                 data, at)
                else:
                    name, typ, flags, addr, off, size, link, info, _, entsize = struct.unpack_from(end + "IIIIIIIIII",
                                                                                                 data, at)
                raw.append({"name_at": name, "type": typ, "flags": flags, "addr": addr, "offset": off, "size": size,
                            "link": link, "info": info, "entsize": entsize})
            names = raw[shstrndx]["offset"] if shstrndx < len(raw) else None
            for sec in raw:
                sec["name"] = _cstr(data, names + sec["name_at"]) if names is not None else None
            out["sections"] = raw
    except struct.error:
        out["sections"] = None

    def offset_of(vaddr):
        for seg in segs:
            if seg["type"] == 1 and seg["vaddr"] <= vaddr < seg["vaddr"] + seg["filesz"]:
                return seg["offset"] + vaddr - seg["vaddr"]
        return None

    for seg in segs:
        if seg["type"] == 3:
            out["interp"] = _cstr(data, seg["offset"], 4096)
        elif seg["type"] == 2 and out["dynamic"] is None:
            entries, size = [], 16 if wide else 8
            try:
                for k in range(min(seg["filesz"] // size, TABLE_MAX)):
                    tag, val = struct.unpack_from(end + ("qQ" if wide else "iI"), data, seg["offset"] + k * size)
                    if tag == 0:
                        break
                    entries.append((tag, val))
            except struct.error:
                entries = None
            out["dynamic"] = entries
        elif seg["type"] == 4 and out["build_id"] is None:
            out["build_id"] = _gnu_build_id(data, seg["offset"], seg["filesz"], end)
    if out["dynamic"]:
        strtab = next((offset_of(v) for t, v in out["dynamic"] if t == DT_STRTAB), None)
        if strtab is not None:
            def text(v):
                return _cstr(data, strtab + v, 4096)
            out["needed"] = [text(v) for t, v in out["dynamic"] if t == DT_NEEDED]
            out["soname"] = next((text(v) for t, v in out["dynamic"] if t == DT_SONAME), None)
            out["rpath"] = next((text(v) for t, v in out["dynamic"] if t == DT_RPATH), None)
            out["runpath"] = next((text(v) for t, v in out["dynamic"] if t == DT_RUNPATH), None)
        flags = next((v for t, v in out["dynamic"] if t == DT_FLAGS), 0)
        flags_1 = next((v for t, v in out["dynamic"] if t == DT_FLAGS_1), 0)
        out["flags_1"] = flags_1
        out["bind_now"] = bool(any(t == DT_BIND_NOW for t, _ in out["dynamic"]) or flags & DF_BIND_NOW
                               or flags_1 & DF_1_NOW)
    if out["build_id"] is None and out["sections"]:
        for sec in out["sections"]:
            if sec["type"] == 7 and sec["name"] == ".note.gnu.build-id":
                out["build_id"] = _gnu_build_id(data, sec["offset"], sec["size"], end)
    return out


def _gnu_build_id(data: bytes, at: int, size: int, end: str):
    """The NT_GNU_BUILD_ID descriptor (hex) among the notes at data[at:at+size], or None."""
    stop = min(len(data), at + size)
    try:
        while at + 12 <= stop:
            namesz, descsz, typ = struct.unpack_from(end + "III", data, at)
            name = data[at + 12:at + 12 + namesz]
            desc_at = at + 12 + (namesz + 3 & ~3)
            if typ == 3 and name.rstrip(b"\0") == b"GNU" and 0 < descsz <= 64 and desc_at + descsz <= stop:
                return data[desc_at:desc_at + descsz].hex()
            at = desc_at + (descsz + 3 & ~3)
    except struct.error:
        pass
    return None


def elf_symbol_names(data: bytes, info: dict, table: str = ".symtab"):
    """The names of one symbol table's entries, table order, the empty ones included; None when the
    file has no such table (or no section header table to find it by). At most 1 << 16 entries."""
    if not info or not info.get("sections"):
        return None
    want = 2 if table == ".symtab" else 11
    sec = next((s for s in info["sections"] if s["type"] == want), None)
    if sec is None or sec["link"] >= len(info["sections"]):
        return None
    strs = info["sections"][sec["link"]]
    end, wide = ("<" if info["ei_data"] == 1 else ">"), info["bits"] == 64
    size = 24 if wide else 16
    out = []
    try:
        for k in range(min(sec["size"] // size, 1 << 16)):
            name = struct.unpack_from(end + "I", data, sec["offset"] + k * size)[0]
            out.append(_cstr(data, strs["offset"] + name, 1024) or "")
    except struct.error:
        return None
    return out


def elf_symtab_entries(data: bytes, info: dict, limit: int = 1 << 18):
    """[(name, st_info type, st_shndx)] of every SHT_SYMTAB section, in section-header order and each
    table's entries in entry order, the empty names included (backlog row 328: the traversal the Day 17
    question states for ELF64). None when the file has no section header table or no SHT_SYMTAB, or a
    table cannot be read; at most `limit` entries in all."""
    if not info or not info.get("sections"):
        return None
    tables = [s for s in info["sections"] if s["type"] == 2]
    if not tables:
        return None
    end, wide = ("<" if info["ei_data"] == 1 else ">"), info["bits"] == 64
    size = 24 if wide else 16
    out = []
    try:
        for sec in tables:
            if sec["link"] >= len(info["sections"]) or not sec["size"]:
                return None
            strs = info["sections"][sec["link"]]["offset"]
            count = sec["size"] // size
            if len(out) + count > limit or sec["offset"] + count * size > len(data):
                return None
            for k in range(count):
                at = sec["offset"] + k * size
                name = struct.unpack_from(end + "I", data, at)[0]
                st_info = data[at + (4 if wide else 12)]
                shndx = struct.unpack_from(end + "H", data, at + (6 if wide else 14))[0]
                out.append((_cstr(data, strs + name, 4096) or "", st_info & 0xF, shndx))
    except (struct.error, IndexError):
        return None
    return out


def elf_symbol_counts(data: bytes, info: dict):
    """(entries, entries with a name) of the ELF's .symtab, or None when it has none. A name is
    counted by its st_name offset, without reading the string; at most 1 << 20 entries."""
    if not info or not info.get("sections"):
        return None
    sec = next((s for s in info["sections"] if s["type"] == 2), None)
    if sec is None:
        return None
    wide = info["bits"] == 64
    size = 24 if wide else 16
    count = sec["size"] // size
    if count > 1 << 20 or sec["offset"] + count * size > len(data):
        return None
    end = "<" if info["ei_data"] == 1 else ">"
    table = data[sec["offset"]:sec["offset"] + count * size]
    named = sum(1 for (name,) in struct.iter_unpack(end + ("I20x" if wide else "I12x"), table) if name)
    return count, named


# ---------------------------------------------------------------------------- PE

PE_DIRS = ("export", "import", "resource", "exception", "security", "basereloc", "debug", "architecture",
           "globalptr", "tls", "load_config", "bound_import", "iat", "delay_import", "com_descriptor", "reserved")
PE_SUBSYSTEM = {1: "NATIVE", 2: "WINDOWS_GUI", 3: "WINDOWS_CUI", 5: "OS2_CUI", 7: "POSIX_CUI", 9: "WINDOWS_CE_GUI",
                10: "EFI_APPLICATION", 11: "EFI_BOOT_SERVICE_DRIVER", 12: "EFI_RUNTIME_DRIVER", 13: "EFI_ROM",
                14: "XBOX", 16: "WINDOWS_BOOT_APPLICATION"}


def pe(data: bytes):
    """The COFF header, the optional header, the data directories and the section table of a PE image.
    None for anything that is not one, or is cut inside those tables."""
    if data[:2] != b"MZ" or len(data) < 0x40:
        return None
    try:
        nt = struct.unpack_from("<I", data, 0x3C)[0]
        if data[nt:nt + 4] != b"PE\0\0":
            return None
        machine, nsec, stamp, _, _, optsize, chars = struct.unpack_from("<HHIIIHH", data, nt + 4)
        opt = nt + 24
        magic, link_major, link_minor = struct.unpack_from("<HBB", data, opt)
        if magic not in (0x10B, 0x20B):
            return None
        plus = magic == 0x20B
        entry = struct.unpack_from("<I", data, opt + 16)[0]
        base = struct.unpack_from("<Q" if plus else "<I", data, opt + (24 if plus else 28))[0]
        sect_align, file_align = struct.unpack_from("<II", data, opt + 32)
        os_major, os_minor, img_major, img_minor, sub_major, sub_minor = struct.unpack_from("<HHHHHH", data, opt + 40)
        size_image, size_headers, checksum, subsystem, dll_chars = struct.unpack_from("<IIIHH", data, opt + 56)
        dirs_at = opt + (112 if plus else 96)
        count = min(struct.unpack_from("<I", data, dirs_at - 4)[0], 16)
        dirs = {PE_DIRS[i]: struct.unpack_from("<II", data, dirs_at + 8 * i) for i in range(count)}
        sections = []
        for i in range(min(nsec, TABLE_MAX)):
            at = opt + optsize + 40 * i
            name = data[at:at + 8].rstrip(b"\0").decode("utf-8", "replace")
            vsize, va, rsize, raw = struct.unpack_from("<IIII", data, at + 8)
            sections.append({"name": name, "vsize": vsize, "va": va, "rsize": rsize, "raw": raw,
                             "flags": struct.unpack_from("<I", data, at + 36)[0]})
    except struct.error:
        return None
    end = max([s["raw"] + s["rsize"] for s in sections if s["rsize"]] + [size_headers])
    cert = dirs.get("security", (0, 0))
    # The certificate table is file data past the sections and is not an overlay of the image.
    overlay = max(0, len(data) - end - (cert[1] if cert[0] and cert[0] >= end else 0))
    return {"machine": machine, "number_of_sections": nsec, "timestamp": stamp, "characteristics": chars,
            "magic": magic, "plus": plus, "linker": (link_major, link_minor), "entry_rva": entry, "image_base": base,
            "section_alignment": sect_align, "file_alignment": file_align, "os_version": (os_major, os_minor),
            "image_version": (img_major, img_minor), "subsystem_version": (sub_major, sub_minor),
            "size_of_image": size_image, "size_of_headers": size_headers, "checksum": checksum,
            "subsystem": subsystem, "dll_characteristics": dll_chars, "dirs": dirs, "sections": sections,
            "overlay": overlay, "pdb": _pdb_path(data, dirs.get("debug"), sections)}


COFF_SYMBOLS_MAX = 1 << 20


def pe_coff_symbols(data: bytes):
    """[(index, name, section number, storage class)] of a PE image's COFF symbol table: the primary
    entries in raw table order, long names resolved through the string table that follows the table,
    auxiliary records skipped, section-definition symbols (`.text$_Z...`, storage class 3) kept as they
    stand (backlog row 328: the traversal the Day 17 question states for PE). None when the image
    has no COFF symbol table (PointerToSymbolTable 0, as most linkers leave it) or the table is cut."""
    if data[:2] != b"MZ" or len(data) < 0x40:
        return None
    try:
        nt = struct.unpack_from("<I", data, 0x3C)[0]
        if data[nt:nt + 4] != b"PE\0\0":
            return None
        ptr, count = struct.unpack_from("<II", data, nt + 12)
        if not ptr or not count or count > COFF_SYMBOLS_MAX or ptr + 18 * count + 4 > len(data):
            return None
        strtab = ptr + 18 * count
        strsize = struct.unpack_from("<I", data, strtab)[0]
        out, i = [], 0
        while i < count:
            rec = data[ptr + 18 * i:ptr + 18 * i + 18]
            if rec[:4] == b"\0\0\0\0":
                off = struct.unpack_from("<I", rec, 4)[0]
                if off < 4 or off >= strsize:
                    return None
                end = data.find(b"\0", strtab + off, strtab + strsize)
                if end < 0:
                    return None
                name = data[strtab + off:end].decode("utf-8", "replace")
            else:
                name = rec[:8].split(b"\0", 1)[0].decode("utf-8", "replace")
            out.append((i, name, struct.unpack_from("<h", rec, 12)[0], rec[16]))
            i += 1 + rec[17]
        return out
    except (struct.error, IndexError):
        return None


def pe_offset(sections: list, rva: int):
    for s in sections:
        if s["va"] <= rva < s["va"] + max(s["vsize"], s["rsize"]):
            return s["raw"] + rva - s["va"]
    return None


def _pdb_path(data: bytes, debug, sections: list):
    """The PDB path of the CodeView (RSDS) entry of the debug directory, or None."""
    if not debug or not debug[0] or not debug[1]:
        return None
    at = pe_offset(sections, debug[0])
    if at is None:
        return None
    try:
        for k in range(min(debug[1] // 28, 16)):
            typ, size, _, raw = struct.unpack_from("<IIII", data, at + 28 * k + 12)
            if typ == 2 and data[raw:raw + 4] == b"RSDS":
                return _cstr(data, raw + 24, 1024)
    except struct.error:
        pass
    return None


def pe_imports(data: bytes, info: dict):
    """The DLL names of the import directory, table order; None when the image has no import
    directory or it cannot be followed."""
    rva, size = (info or {}).get("dirs", {}).get("import", (0, 0))
    if not rva:
        return None
    at = pe_offset(info["sections"], rva)
    if at is None:
        return None
    names = []
    try:
        for k in range(TABLE_MAX):
            ilt, _, _, name, iat = struct.unpack_from("<IIIII", data, at + 20 * k)
            if not (ilt or name or iat):
                break
            where = pe_offset(info["sections"], name)
            text = _cstr(data, where, 260) if where is not None else None
            if text is None:
                return None
            names.append(text)
    except struct.error:
        return None
    return names


# ---------------------------------------------------------------------------- Mach-O

MACHO_MAGIC = {b"\xcf\xfa\xed\xfe": (64, "<"), b"\xce\xfa\xed\xfe": (32, "<"),
               b"\xfe\xed\xfa\xcf": (64, ">"), b"\xfe\xed\xfa\xce": (32, ">")}
MACHO_FILETYPE = {1: "MH_OBJECT", 2: "MH_EXECUTE", 3: "MH_FVMLIB", 4: "MH_CORE", 5: "MH_PRELOAD", 6: "MH_DYLIB",
                  7: "MH_DYLINKER", 8: "MH_BUNDLE", 9: "MH_DYLIB_STUB", 10: "MH_DSYM", 11: "MH_KEXT_BUNDLE",
                  12: "MH_FILESET"}
MACHO_CPU = {7: "i386", 0x01000007: "x86_64", 12: "arm", 0x0100000C: "arm64", 0x0200000C: "arm64_32", 18: "ppc",
             0x01000012: "ppc64"}
MACHO_PLATFORM = {1: "macos", 2: "ios", 3: "tvos", 4: "watchos", 5: "bridgeos", 6: "maccatalyst", 7: "iossimulator",
                  8: "tvossimulator", 9: "watchossimulator", 10: "driverkit", 11: "visionos", 12: "visionossimulator"}
LC_REQ = 0x80000000
LC = {0x1: "segment", 0x19: "segment", 0x2: "symtab", 0xB: "dysymtab", 0xC: "load_dylib", 0xD: "id_dylib",
      0xE: "load_dylinker", 0x1B: "uuid", 0x1C | LC_REQ: "rpath", 0x1D: "code_signature", 0x21: "encryption_info",
      0x2C: "encryption_info", 0x24: "version_min_macosx", 0x25: "version_min_iphoneos", 0x2F: "version_min_tvos",
      0x30: "version_min_watchos", 0x32: "build_version", 0x28 | LC_REQ: "main", 0x2A: "source_version",
      0x18 | LC_REQ: "load_dylib", 0x1F | LC_REQ: "load_dylib", 0x26: "function_starts", 0x29: "data_in_code",
      0x22 | LC_REQ: "dyld_info", 0x22: "dyld_info", 0x33 | LC_REQ: "dyld_exports_trie",
      0x34 | LC_REQ: "dyld_chained_fixups"}
VERSION_MIN_PLATFORM = {"version_min_macosx": 1, "version_min_iphoneos": 2, "version_min_tvos": 3,
                        "version_min_watchos": 4}


def _version(word: int) -> str:
    """X.Y.Z of a Mach-O version word (xxxx.yy.zz nibbles)."""
    return f"{word >> 16}.{word >> 8 & 0xFF}.{word & 0xFF}"


def macho(data: bytes, at: int = 0):
    """One Mach-O image's header and load commands (the image that starts at `at`). None for anything
    else, or a load-command table that runs out of the file."""
    if data[at:at + 4] not in MACHO_MAGIC or len(data) < at + 28:
        return None
    bits, end = MACHO_MAGIC[data[at:at + 4]]
    try:
        magic, cpu, sub, ftype, ncmds, sizeofcmds, flags = struct.unpack_from(end + "IiIIIII", data, at)
    except struct.error:
        return None
    out = {"bits": bits, "endian": "little" if end == "<" else "big", "magic": magic, "cputype": cpu & 0xFFFFFFFF,
           "cpusubtype": sub, "filetype": ftype, "ncmds": ncmds, "sizeofcmds": sizeofcmds, "flags": flags,
           "commands": [], "segments": [], "sections": [], "dylibs": [], "rpaths": [], "uuid": None, "minos": None,
           "sdk": None, "platform": None, "entryoff": None, "id_dylib": None, "dylinker": None,
           "code_signature": False, "cryptid": None, "source_version": None, "offset": at}
    cur = at + (32 if bits == 64 else 28)
    if ncmds > TABLE_MAX or cur + sizeofcmds > len(data):
        return None
    try:
        for _ in range(ncmds):
            cmd, size = struct.unpack_from(end + "II", data, cur)
            if size < 8 or cur + size > len(data):
                return None
            name = LC.get(cmd) or LC.get(cmd & ~LC_REQ)
            out["commands"].append(cmd)
            body = cur + 8
            if name == "segment":
                wide = cmd == 0x19
                seg = data[body:body + 16].rstrip(b"\0").decode("utf-8", "replace")
                out["segments"].append(seg)
                nsects = struct.unpack_from(end + "I", data, body + (56 if wide else 40))[0]
                first = body + (64 if wide else 48)
                step = 80 if wide else 68
                for k in range(min(nsects, TABLE_MAX)):
                    sect = data[first + k * step:first + k * step + 16].rstrip(b"\0").decode("utf-8", "replace")
                    owner = data[first + k * step + 16:first + k * step + 32].rstrip(b"\0").decode("utf-8", "replace")
                    out["sections"].append((owner, sect))
            elif name in ("load_dylib", "id_dylib"):
                text = _cstr(data, cur + struct.unpack_from(end + "I", data, body)[0], 1024)
                if name == "id_dylib":
                    out["id_dylib"] = text
                elif text is not None:
                    out["dylibs"].append(text)
            elif name == "load_dylinker":
                out["dylinker"] = _cstr(data, cur + struct.unpack_from(end + "I", data, body)[0], 1024)
            elif name == "rpath":
                text = _cstr(data, cur + struct.unpack_from(end + "I", data, body)[0], 1024)
                if text is not None:
                    out["rpaths"].append(text)
            elif name == "uuid":
                out["uuid"] = data[body:body + 16].hex()
            elif name == "code_signature":
                out["code_signature"] = True
            elif name == "encryption_info":
                out["cryptid"] = struct.unpack_from(end + "I", data, body + 8)[0]
            elif name == "main":
                out["entryoff"] = struct.unpack_from(end + "Q", data, body)[0]
            elif name == "source_version":
                v = struct.unpack_from(end + "Q", data, body)[0]
                out["source_version"] = f"{v >> 40}.{v >> 30 & 0x3FF}.{v >> 20 & 0x3FF}.{v >> 10 & 0x3FF}.{v & 0x3FF}"
            elif name == "build_version":
                platform, minos, sdk = struct.unpack_from(end + "III", data, body)
                out.update(platform=platform, minos=_version(minos), sdk=_version(sdk))
            elif name in VERSION_MIN_PLATFORM and out["minos"] is None:
                minos, sdk = struct.unpack_from(end + "II", data, body)
                out.update(platform=VERSION_MIN_PLATFORM[name], minos=_version(minos), sdk=_version(sdk))
            cur += size
    except struct.error:
        return None
    return out


def macho_fat(data: bytes):
    """[(cputype, cpusubtype, offset, size)] of a fat Mach-O's architectures, table order; None for
    anything else (a Java class has the same magic and a version word of 45 or more in the count's
    place)."""
    if data[:4] not in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf") or len(data) < 8:
        return None
    n = struct.unpack_from(">I", data, 4)[0]
    if not 0 < n < 45:
        return None
    wide = data[3] == 0xBF
    size = 32 if wide else 20
    out = []
    try:
        for k in range(n):
            cpu, sub = struct.unpack_from(">iI", data, 8 + size * k)
            off, length = struct.unpack_from(">QQ" if wide else ">II", data, 8 + size * k + 8)
            out.append((cpu & 0xFFFFFFFF, sub, off, length))
    except struct.error:
        return None
    return out


# ---------------------------------------------------------------------------- WebAssembly

WASM_SECTION = {0: "custom", 1: "type", 2: "import", 3: "function", 4: "table", 5: "memory", 6: "global",
                7: "export", 8: "start", 9: "element", 10: "code", 11: "data", 12: "data_count", 13: "tag"}
WASM_KIND = {0: "func", 1: "table", 2: "memory", 3: "global", 4: "tag"}


def leb128(data: bytes, at: int, signed: bool = False):
    """(value, next offset) of the LEB128 number at data[at]. At most ten bytes (a u64): a longer run
    of continuation bytes is not a number and raises ValueError, as does the end of the data."""
    if not isinstance(at, int) or at < 0:
        raise ValueError("LEB128 offset must be a nonnegative integer")
    value = 0
    for shift in range(0, 70, 7):
        if at >= len(data):
            raise ValueError("LEB128 runs out of the data")
        byte = data[at]
        at += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            if signed and byte & 0x40:
                value -= 1 << (shift + 7)
            return value, at
    raise ValueError("a LEB128 number longer than ten bytes")


def _wasm_name(data: bytes, at: int):
    size, at = leb128(data, at)
    if size > 4096 or at + size > len(data):
        raise ValueError("a name runs out of the data")
    return data[at:at + size].decode("utf-8", "replace"), at + size


def wasm(data: bytes):
    """A WebAssembly module's sections and what the import, export, start, memory, data and custom
    sections state. None for anything that is not a module or whose section table runs out of the
    file; a section body that does not parse leaves its own facts None."""
    if data[:4] != b"\0asm" or len(data) < 8:
        return None
    out = {"version": struct.unpack_from("<I", data, 4)[0], "sections": [], "custom": [], "imports": None,
           "exports": None, "types": None, "functions": None, "start": None, "memory_min": None,
           "data_segments": None, "data_count": None, "producers": None, "globals": None, "tables": None}
    at = 8
    try:
        while at < len(data) and len(out["sections"]) < TABLE_MAX:
            sid = data[at]
            size, body = leb128(data, at + 1)
            if body + size > len(data):
                return None
            out["sections"].append((sid, body, size))
            at = body + size
    except ValueError:
        return None
    for sid, body, size in out["sections"]:
        try:
            if sid == 0:
                name, rest = _wasm_name(data, body)
                out["custom"].append(name)
                if name == "producers":
                    out["producers"] = _wasm_producers(data, rest)
            elif sid in (1, 3, 4, 6, 11):
                count, _ = leb128(data, body)
                out[{1: "types", 3: "functions", 4: "tables", 6: "globals", 11: "data_segments"}[sid]] = count
            elif sid == 12:
                out["data_count"], _ = leb128(data, body)
            elif sid == 8:
                out["start"], _ = leb128(data, body)
            elif sid == 5:
                count, cur = leb128(data, body)
                if count:
                    out["memory_min"], _ = leb128(data, cur + 1)
            elif sid == 2:
                count, cur = leb128(data, body)
                items = []
                for _ in range(min(count, TABLE_MAX)):
                    module, cur = _wasm_name(data, cur)
                    field, cur = _wasm_name(data, cur)
                    kind = data[cur]
                    cur += 1
                    if kind == 0 or kind == 4:
                        if kind == 4:
                            cur += 1
                        _, cur = leb128(data, cur)
                    elif kind == 1:
                        cur += 1
                        cur = _wasm_limits(data, cur)
                    elif kind == 2:
                        cur = _wasm_limits(data, cur)
                    elif kind == 3:
                        cur += 2
                    else:
                        raise ValueError("an import of an unknown kind")
                    items.append((module, field, WASM_KIND[kind]))
                out["imports"] = items if count <= TABLE_MAX else None
            elif sid == 7:
                count, cur = leb128(data, body)
                items = []
                for _ in range(min(count, TABLE_MAX)):
                    name, cur = _wasm_name(data, cur)
                    kind = data[cur]
                    _, cur = leb128(data, cur + 1)
                    items.append((name, WASM_KIND.get(kind, str(kind))))
                out["exports"] = items if count <= TABLE_MAX else None
        except (ValueError, IndexError, KeyError):
            continue
    return out


def wasm_data_segments(data: bytes, info: dict):
    """[(file offset, size)] of the bytes of each segment of a module's data section, in order: active
    segments (an i32.const, i64.const or global.get offset expression) and passive ones. None when the
    module has no data section or a segment does not parse."""
    section = next(((body, size) for sid, body, size in (info or {}).get("sections") or () if sid == 11), None)
    if section is None:
        return None
    body, size = section
    try:
        count, cur = leb128(data, body)
        out = []
        for _ in range(min(count, TABLE_MAX)):
            mode, cur = leb128(data, cur)
            if mode == 2:
                _, cur = leb128(data, cur)            # memory index
            if mode in (0, 2):
                op = data[cur]
                if op in (0x41, 0x42):
                    _, cur = leb128(data, cur + 1, signed=True)
                elif op == 0x23:
                    _, cur = leb128(data, cur + 1)
                else:
                    return None
                if data[cur] != 0x0B:
                    return None
                cur += 1
            elif mode != 1:
                return None
            n, cur = leb128(data, cur)
            if cur + n > body + size:
                return None
            out.append((cur, n))
            cur += n
        return out if count <= TABLE_MAX else None
    except (ValueError, IndexError):
        return None


def java_class_table(blob: bytes):
    """(access_flags, this class name, [method names in declared order]) of a class file, read from its
    constant pool and method table (backlog row 340: Day 17 judged `access_flags` as the decimal of the
    class's own flags and `methods` as the method table in order, `<init>` and `<clinit>` included).
    None for anything that is not a whole class file."""
    if blob[:4] != b"\xca\xfe\xba\xbe" or len(blob) < 10:
        return None
    try:
        count = struct.unpack_from(">H", blob, 8)[0]
        utf8, classes, at, i = {}, {}, 10, 1
        while i < count:
            tag = blob[at]
            if tag == 1:
                n = struct.unpack_from(">H", blob, at + 1)[0]
                utf8[i] = blob[at + 3:at + 3 + n].replace(b"\xc0\x80", b"\0").decode("utf-8", "replace")
                at += 3 + n
            elif tag in (7, 8, 16, 19, 20):
                if tag == 7:
                    classes[i] = struct.unpack_from(">H", blob, at + 1)[0]
                at += 3
            elif tag == 15:
                at += 4
            elif tag in (3, 4, 9, 10, 11, 12, 17, 18):
                at += 5
            elif tag in (5, 6):
                at += 9
                i += 1
            else:
                return None
            i += 1
        access, this = struct.unpack_from(">HH", blob, at)
        at += 6
        at += 2 + 2 * struct.unpack_from(">H", blob, at)[0]          # interfaces

        def members(at):
            """(names, offset after the table) of a fields or methods table that begins at `at`."""
            count, at, names = struct.unpack_from(">H", blob, at)[0], at + 2, []
            for _ in range(count):
                name, attrs = struct.unpack_from(">H", blob, at + 2)[0], struct.unpack_from(">H", blob, at + 6)[0]
                if name not in utf8:
                    raise ValueError("a member name that is no Utf8 constant")
                names.append(utf8[name])
                at += 8
                for _ in range(attrs):
                    at += 6 + struct.unpack_from(">I", blob, at + 2)[0]
            return names, at

        _, at = members(at)          # fields
        methods, at = members(at)
        # Even a class with no attributes has a mandatory u16 count. Consume
        # each attribute's complete payload before accepting the class file.
        attrs = struct.unpack_from(">H", blob, at)[0]
        at += 2
        for _ in range(attrs):
            at += 6 + struct.unpack_from(">I", blob, at + 2)[0]
            if at > len(blob):
                return None
    except (struct.error, IndexError, ValueError):
        return None
    if at != len(blob) or this not in classes or classes[this] not in utf8:
        return None
    return access, utf8[classes[this]], methods


def wasm_component(data: bytes):
    """{version, layer, sections [(id, offset, size)], core_modules, custom [names]} of a WebAssembly
    component (the component-model layer of the binary format: `\\0asm`, a 16-bit version, a 16-bit layer
    that is 1), or None. Only the section framing is read (an id byte and a LEB128 size, as in a core
    module); a section that does not fit ends the reading, and what was read before it stands."""
    if data[:4] != b"\0asm" or len(data) < 8 or data[6:8] != b"\x01\0":
        return None
    out = {"version": int.from_bytes(data[4:6], "little"), "layer": 1, "sections": [], "core_modules": 0, "custom": []}
    at = 8
    while at < len(data) and len(out["sections"]) < 4096:
        sid = data[at]
        try:
            size, body = leb128(data, at + 1)
        except Exception:
            break
        if size is None or body + size > len(data):
            break
        out["sections"].append((sid, body, size))
        if sid == 1 and data[body:body + 8] == b"\0asm\x01\0\0\0":
            out["core_modules"] += 1
        elif sid == 0:
            try:
                name = _wasm_name(data, body)
            except Exception:
                name = None
            if isinstance(name, tuple):
                name = name[0]
            if isinstance(name, str):
                out["custom"].append(name)
        at = body + size
    return out


def _wasm_limits(data: bytes, at: int) -> int:
    flags = data[at]
    _, at = leb128(data, at + 1)
    if flags & 1:
        _, at = leb128(data, at)
    return at


def _wasm_producers(data: bytes, at: int) -> dict:
    """{field: [(name, version), ...]} of a `producers` custom section (language, processed-by, sdk)."""
    out = {}
    fields, at = leb128(data, at)
    for _ in range(min(fields, 16)):
        field, at = _wasm_name(data, at)
        count, at = leb128(data, at)
        values = []
        for _ in range(min(count, 64)):
            name, at = _wasm_name(data, at)
            version, at = _wasm_name(data, at)
            values.append((name, version))
        out[field] = values
    return out


# ---------------------------------------------------------------------------- DEX

def dex(data: bytes):
    """A DEX file's header: version, checksum, signature and the sizes of its id tables. None for
    anything else."""
    if data[:4] != b"dex\n" or len(data) < 0x70 or data[7:8] != b"\0":
        return None
    checksum = struct.unpack_from("<I", data, 8)[0]
    file_size, header_size, endian = struct.unpack_from("<III", data, 0x20)
    strings, _, types, _, protos, _, fields, _, methods, _, classes = struct.unpack_from("<11I", data, 0x38)
    return {"version": data[4:7].decode("ascii", "replace"), "checksum": checksum, "signature": data[12:32].hex(),
            "file_size": file_size, "header_size": header_size, "endian_tag": endian, "strings": strings,
            "types": types, "protos": protos, "fields": fields, "methods": methods, "classes": classes}


# ---------------------------------------------------------------------------- Neko VM bytecode

NEKO_MAGIC = b"NEKO"
NEKO_NAME_MAX = 0x100       # neko_read_module's read_string buffer: a name is at most 255 bytes and its NUL


def _neko_text_end(data: bytes, at: int):
    """The offset of the NUL that ends the text starting at `at`, within the loader's limit, or None."""
    end = data.find(b"\0", at, at + NEKO_NAME_MAX)
    return end if end >= 0 else None


def _neko_debug(data: bytes, at: int, codesize: int) -> int:
    """The offset after a debug-information global (type 5), read as the loader's read_debug_infos reads it: a file
    count (one byte, or two when the first has its high bit set), that many NUL-ended file names, a u32le position
    count that must equal the module's code size, then a stream of tags until that many positions were given: a tag
    with bit 0 set switches the file (one byte more when the count took two), bit 1 a run of `(tag >> 2) & 15` positions,
    bit 2 a line step of one position, none of them an absolute line (two bytes more). ValueError when it does not read
    as that."""
    c = data[at]
    at += 1
    many = c >= 0x80
    if many:
        nfiles = ((c & 0x7F) << 8) | data[at]
        at += 1
    else:
        nfiles = c
    if nfiles == 0:
        raise ValueError("no file names")
    for _ in range(nfiles):
        end = _neko_text_end(data, at)
        if end is None:
            raise ValueError("a file name with no end")
        at = end + 1
    if struct.unpack_from("<I", data, at)[0] != codesize:
        raise ValueError("a position count that is not the code size")
    at += 4
    done, open_pair = 0, False
    while done < codesize:
        c = data[at]
        at += 1
        if c & 1:
            index = c >> 1
            if many:
                index = (index << 8) | data[at]
                at += 1
            if index >= nfiles:
                raise ValueError("a file index past the file names")
            open_pair = False
        elif c & 2:
            count = (c >> 2) & 15
            if done + count > codesize or (count == 0 and not open_pair):
                raise ValueError("a run past the positions")
            done += count
            open_pair = not (c >> 6)        # a line step in the run's top bits closes the pair
        elif c & 4:
            done += 1
            open_pair = True
        else:
            at += 2
            done += 1
            open_pair = True
    return at


def _neko_tables(data: bytes, nglobals: int, nfields: int, codesize: int):
    """(strings, names, code start) when the globals, the field names and the packed code of a module read exactly as
    the loader reads them and the code ends where the file does; None for anything else. Globals: a type byte, then 1 a
    NUL-ended name, 2 a function (one u32le: its address in the low 24 bits, below the code size, and its number of
    arguments above them), 3 a string (u16le length, bytes), 4 a NUL-ended float text, 5 debug information, 6 a version
    byte; then the field names (NUL-ended). The code is `codesize` slots packed into bytes: a tag byte whose low two bits
    say 0 one slot, 1 two slots, 2 a parameter byte follows (one slot when the tag is 2 itself: an extra opcode; else
    two), 3 a u32le follows (two slots)."""
    strings, names, at, size = [], [], 16, len(data)
    try:
        for _ in range(nglobals):
            kind = data[at]
            at += 1
            if kind == 1:
                end = _neko_text_end(data, at)
                if end is None:
                    return None
                names.append((at, end - at))
                at = end + 1
            elif kind == 4:
                end = _neko_text_end(data, at)
                if end is None:
                    return None
                at = end + 1
            elif kind == 2:
                if (struct.unpack_from("<I", data, at)[0] & 0xFFFFFF) >= codesize:
                    return None
                at += 4
            elif kind == 3:
                n = struct.unpack_from("<H", data, at)[0]
                at += 2
                if at + n > size:
                    return None
                strings.append((at, n))
                at += n
            elif kind == 5:
                at = _neko_debug(data, at, codesize)
            elif kind == 6:
                at += 1
            else:
                return None
        for _ in range(nfields):
            end = _neko_text_end(data, at)
            if end is None:
                return None
            names.append((at, end - at))
            at = end + 1
        code_start, slots = at, 0
        while slots < codesize:
            tag = data[at]
            at += 1
            form = tag & 3
            if form == 0:
                slots += 1
            elif form == 1:
                slots += 2
            elif form == 2:
                at += 1
                slots += 1 if tag == 2 else 2
            else:
                at += 4
                slots += 2
    except (ValueError, IndexError, struct.error):
        return None
    if slots != codesize or at != size:
        return None
    return strings, names, code_start


def neko_header(data: bytes):
    """(nglobals, nfields, codesize) of a NEKO module's 16-byte header when it is one the loader accepts (the magic, room
    for the header, at most 0xFFFF globals and 0xFFFF field names, at most 0xFFFFFF code slots), else None. It reads
    16 bytes and nothing else: `neko` parses the tables too, which costs as much as the module is long."""
    if data[:4] != NEKO_MAGIC or len(data) < 16:
        return None
    nglobals, nfields, codesize = struct.unpack_from("<III", data, 4)
    if nglobals > 0xFFFF or nfields > 0xFFFF or codesize > 0xFFFFFF:
        return None
    return nglobals, nfields, codesize


def neko(data: bytes):
    """A Neko VM module's (.n) header and, when its tables read whole, the strings in them (KB-6, the Day 27 build),
    read the way Neko's own loader (vm/module.c, neko_read_module) reads a module: `NEKO`, then three u32le, the number
    of globals and of field names (at most 0xFFFF each) and the code size in SLOTS (at most 0xFFFFFF; the code is stored
    packed, so the file does not hold four bytes a slot), then the globals, the field names and the packed code
    (`_neko_tables`). The header fields are read from the 16 bytes alone (`neko_header`); `tables` is True only when
    everything parses as the loader reads it and the code ends exactly where the file does, and only then are `strings`
    (file offset, length of each string global), `names` (file offset, length of each variable name and field name),
    `code_start` and `code_bytes` (the packed code's length in the file) given. None for anything that is not a NEKO
    header."""
    header = neko_header(data)
    if header is None:
        return None
    nglobals, nfields, codesize = header
    out = {"nglobals": nglobals, "nfields": nfields, "codesize": codesize, "tables": False,
           "strings": [], "names": [], "code_start": None, "code_bytes": None}
    got = _neko_tables(data, nglobals, nfields, codesize)
    if got is not None:
        out.update(tables=True, strings=got[0], names=got[1], code_start=got[2], code_bytes=len(data) - got[2])
    return out


def _main(argv) -> int:
    if argv and argv[0] in ("-h", "--help"):
        print("usage: binfmt.py <sample> [...]")
        return 0
    if not argv:
        print("binfmt.py: expected at least one sample", file=sys.stderr)
        return 2
    try:
        for path in argv:
            blob = Path(path).read_bytes()
            print(path)
            for reader in (elf, pe, macho, macho_fat, wasm, dex, neko):
                got = reader(blob)
                if got is None:
                    continue
                print(f"  {reader.__name__}:")
                for k, v in (got.items() if isinstance(got, dict) else [("architectures", got)]):
                    text = repr(v)
                    print(f"    {k} = {text if len(text) <= 160 else text[:160] + '...'}")
    except Exception as exc:  # CLI boundary: challenge bytes must never leak a traceback
        print(f"binfmt.py: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
