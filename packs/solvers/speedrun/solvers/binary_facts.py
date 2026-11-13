"""What the Binary speed solver reads from one sample's bytes. Pure parsing, nothing is run.

facts(name, data) -> {
  "sha256", "size", "format" (elf | pe | pe_cli | jar | None), "machine" (x86-64 | i386 | None),
  "elf_class", "elf_type", "endianness", "sections", "symbols", "disassembly" (ELF only),
  "elf_bits" (32 | 64), "elf_type_id" (e_type), "ei_data" (1 | 2), "machine_id" (e_machine, or a PE's
  COFF Machine): the header's own numbers, for a question that asks an integer,
  "entry" (e_entry) and "has_symtab" (a SHT_SYMTAB section in a readable section table), ELF64 only,
  "has_cpp_typeinfo" / "has_cpp_vtable" (bool): C++ RTTI in a native binary, Day 8's d02 (below),
  "compression_methods" (list[int]): distinct zip methods of a jar/zip, first-appearance order, Day 8's
  d06/d07 (below),
  "metadata_version" (.NET metadata root), "hcfg": {"version", "key", "crc", "json"} or None,
}

has_cpp_typeinfo / has_cpp_vtable (backlog row 165): Day 8 asked d02_analysis_has_cpp_typeinfo and
d02_analysis_has_cpp_vtable of the small C++ ELF (answer "true"/"false"). They are read from the bytes,
not from the key store, so a stale key never spends a ranked attempt. Typeinfo and vtables are the C++
Itanium ABI symbols/names (`_ZTI*`, `_ZTV*`, ELF/GCC/Clang) or MSVC RTTI (`.?AV`/`.?AU`, `??_7`,
`vftable`, PE). The scan is whole-file but only on a native binary up to CPP_SCAN_CAP, so the 67 MB d08
sample and the multi-MB Go/Rust samples (never asked about C++) are never scanned; the C++ specimens are
tens of KB. compression_methods (row 165): Day 8 asked d06/d07_analysis_compression_methods of the jars,
the distinct zip methods in first-appearance order as compact JSON ([0,8]); read from the central
directory (directory entries included, as solvers/binary/zip_methods_owner.py does).

HCFG is the lane's config container: "HCFG" | version u8 | xor key u8 | length u16 | crc32 u32 | payload,
payload XOR key = a JSON object whose zlib CRC-32 is crc32. A header whose payload is not JSON under its key
or whose CRC does not check is a decoy (the Rust sample carries two) and is skipped. In a JAR the container
is a base64 String constant inside a class, so the class members are inflated and base64 runs that open
with "SENGR" (the encoding of "HCFG" plus one byte) are decoded. Copied from solvers/binary/hcfg.py and
the day modules as rules, never imported.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import io
import json
import re
import struct
import zipfile
import zlib

ELF_MACHINE = {62: "x86-64", 3: "i386"}
PE_MACHINE = {0x8664: "x86-64", 0x14C: "i386"}
ELF_TYPE = {1: "ET_REL", 2: "ET_EXEC", 3: "ET_DYN", 4: "ET_CORE"}
B64_HCFG = re.compile(rb"SENGR[A-Za-z0-9+/]{11,}={0,2}")


def hcfg_in(data: bytes):
    """The first valid container in `data`, or None."""
    o = data.find(b"HCFG")
    while o >= 0:
        if o + 12 <= len(data):
            version, key = data[o + 4], data[o + 5]
            length, crc = struct.unpack_from("<HI", data, o + 6)
            if length and o + 12 + length <= len(data) and data[o + 12] ^ key == 0x7B:
                plain = bytes(b ^ key for b in data[o + 12:o + 12 + length])
                if zlib.crc32(plain) & 0xFFFFFFFF == crc:
                    try:
                        obj = json.loads(plain.decode("utf-8"))
                    except (ValueError, UnicodeDecodeError):
                        obj = None
                    if isinstance(obj, dict):
                        return {"version": version, "key": key, "crc": crc, "json": obj}
        o = data.find(b"HCFG", o + 1)
    return None


ZLIB_RE = re.compile(rb"\x78[\x01\x5e\x9c\xda]")
DEEP_LIMIT = 256                 # compressed-stream starts tried per sample (the fallback only)
INFLATE_LIMIT = 1 << 22


def _decompressors():
    import bz2
    import lzma
    return (
        (re.compile(rb"\x1f\x8b\x08"), lambda b: zlib.decompressobj(47).decompress(b, INFLATE_LIMIT)),
        (re.compile(rb"\xfd7zXZ\x00"), lambda b: lzma.LZMADecompressor().decompress(b, INFLATE_LIMIT)),
        (re.compile(rb"BZh[1-9]1AY&SY"), lambda b: bz2.BZ2Decompressor().decompress(b, INFLATE_LIMIT)),
        (re.compile(rb"\x5d\x00\x00[\x01-\x80]\x00"), lambda b: lzma.LZMADecompressor(lzma.FORMAT_ALONE).decompress(b, INFLATE_LIMIT)),
        (ZLIB_RE, lambda b: zlib.decompressobj().decompress(b, INFLATE_LIMIT)),
    )


def hcfg_deep(data: bytes):
    """The container in a form the plain search does not see, or None. Only called when that search
    found nothing: as UTF-8 / Java modified UTF-8 text (a str or String constant), as UTF-16LE
    characters, base64 anywhere, or inside a gzip, xz, bzip2, lzma or zlib stream."""
    o = data.find(b"HCFG")
    while o >= 0:          # the container's bytes written as UTF-8 characters
        chunk = data[o:o + 4 * 65536 + 64].replace(b"\xc0\x80", b"\x00")
        try:
            raw = chunk.decode("utf-8", "ignore").encode("latin-1", "ignore")
        except Exception:  # noqa: BLE001
            raw = b""
        h = hcfg_in(raw)
        if h:
            return h
        o = data.find(b"HCFG", o + 1)
    o = data.find(b"H\x00C\x00F\x00G\x00")
    while o >= 0:          # as UTF-16LE characters
        try:
            raw = data[o:o + 2 * 65600].decode("utf-16-le", "ignore").encode("latin-1", "ignore")
        except Exception:  # noqa: BLE001
            raw = b""
        h = hcfg_in(raw)
        if h:
            return h
        o = data.find(b"H\x00C\x00F\x00G\x00", o + 2)
    for m in B64_HCFG.finditer(data):
        try:
            h = hcfg_in(base64.b64decode(m.group(), validate=True))
        except (binascii.Error, ValueError):
            h = None
        if h:
            return h
    tried = 0
    for rx, fn in _decompressors():
        for m in rx.finditer(data):
            tried += 1
            if tried > DEEP_LIMIT:
                return None
            try:
                out = fn(data[m.start():])
            except Exception:  # noqa: BLE001 - not a stream after all
                continue
            if out:
                h = hcfg_in(out) or (hcfg_deep(out) if len(out) < INFLATE_LIMIT and out.find(b"HCFG") < 0 else None)
                if h:
                    return h
    return None


# --- C++ RTTI and zip compression methods (backlog row 165) ---
CPP_SCAN_CAP = 1 << 20          # scan whole-file for C++ RTTI only up to 1 MB (C++ specimens are tiny;
                                # keeps the 67 MB d08 and the Go/Rust samples, never asked, off the scan)
_TYPEINFO = (b"_ZTI", b".?AV", b".?AU")      # Itanium type_info object/name; MSVC RTTI type descriptor
_VTABLE = (b"_ZTV", b"??_7", b"vftable")     # Itanium vtable; MSVC vftable


def _cpp_flags(data: bytes, out: dict) -> None:
    """has_cpp_typeinfo / has_cpp_vtable for a native binary, from its bytes. None (absent) for a
    binary over the cap or a non-native format: those are never the C++ specimen the field asks about."""
    if out.get("format") not in ("elf", "pe", "pe_cli") or len(data) > CPP_SCAN_CAP:
        return
    out["has_cpp_typeinfo"] = any(m in data for m in _TYPEINFO)
    out["has_cpp_vtable"] = any(m in data for m in _VTABLE)


def zip_methods(data: bytes):
    """Distinct zip compression methods in first-appearance order (directory entries included), or None
    when the bytes are not a readable zip. Matches solvers/binary/zip_methods_owner.py."""
    if data[:2] != b"PK":
        return None
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
        seen: list = []
        for i in z.infolist():
            if i.compress_type not in seen:
                seen.append(i.compress_type)
        return seen or None
    except Exception:  # noqa: BLE001 - not a readable zip
        return None


def _zip_members(data: bytes) -> list:
    """[(name, bytes)] of a plain (unencrypted) zip such as a JAR; [] if it cannot be read."""
    try:
        from speedrun.common import open_zip
        z = open_zip(data)
        return [(n, z.read(n)) for n in z.names()]
    except Exception:  # noqa: BLE001 - not a readable zip
        return []


def _elf(d: bytes, out: dict):
    if len(d) < 64:
        return
    cls, enc = d[4], d[5]
    out["elf_class"] = {1: "ELF32", 2: "ELF64"}.get(cls)
    out["endianness"] = {1: "little", 2: "big"}.get(enc)
    # The header's own numbers, for a question whose answer_format kind is integer (Day 8).
    out["elf_bits"] = {1: 32, 2: 64}.get(cls)
    out["ei_data"] = enc if enc in (1, 2) else None
    if enc in (1, 2):
        out["elf_type_id"], out["machine_id"] = struct.unpack_from("<HH" if enc == 1 else ">HH", d, 16)
    if cls != 2 or enc != 1:
        out["machine"] = ELF_MACHINE.get(struct.unpack_from("<H" if enc == 1 else ">H", d, 18)[0])
        return
    (e_type, e_machine, _v, _entry, _phoff, e_shoff, _fl, _eh, _phes, _phn, e_shentsize, e_shnum,
     e_shstrndx) = struct.unpack_from("<HHIQQQIHHHHHH", d, 16)
    out["elf_type"] = ELF_TYPE.get(e_type)
    out["machine"] = ELF_MACHINE.get(e_machine)
    out["entry"] = _entry
    if not e_shoff or e_shentsize != 64 or e_shoff + e_shnum * 64 > len(d) or e_shstrndx >= e_shnum:
        return
    secs = [struct.unpack_from("<IIQQQQIIQQ", d, e_shoff + i * 64) for i in range(e_shnum)]

    def name_at(tab_off, o):
        e = d.find(b"\0", tab_off + o)
        return d[tab_off + o:e].decode("utf-8", "replace") if e >= 0 else ""

    shs = secs[e_shstrndx]
    out["sections"] = [name_at(shs[4], s[0]) for s in secs]
    # The original Day-1/2 timed routes use non-cumulative ids (slot0_marker, c_marker).  Keep the
    # byte-proven section value alongside the cumulative facts so the speed solver can serve both
    # question shapes without importing the release solver.
    try:
        marker_i = out["sections"].index(".huntress")
        marker_sec = secs[marker_i]
        marker = d[marker_sec[4]:marker_sec[4] + marker_sec[5]].split(b"\0", 1)[0]
        out["marker"] = marker.decode("utf-8", "replace")
    except (ValueError, IndexError):
        out["marker"] = "none"
    out["has_symtab"] = any(s[1] == 2 for s in secs)        # a section of type SHT_SYMTAB
    symtab = next((s for s in secs if s[1] == 2), None)
    if symtab is None or symtab[9] != 24 or symtab[6] >= len(secs):
        return
    strtab = secs[symtab[6]]
    syms = []
    for i in range(symtab[5] // 24):
        n, info, _other, shndx, value, size = struct.unpack_from("<IBBHQQ", d, symtab[4] + i * 24)
        syms.append((name_at(strtab[4], n), info, shndx, value, size))
    out["symbols"] = [s[0] for s in syms if s[0]]
    funcs = [s for s in syms if s[0] and s[1] & 0xF == 2 and s[2] != 0]
    crt = {"_start", "_init", "_fini", "_dl_relocate_static_pie", "__libc_csu_init",
           "__libc_csu_fini", "deregister_tm_clones", "register_tm_clones",
           "__do_global_dtors_aux", "frame_dummy"}
    own = [s for s in funcs if s[0] not in crt]
    named = [s for s in own if s[0] == "recover_code"]
    rest = [s for s in own if s[0] != "main"]
    designated = (named or rest or own or [None])[0]
    out["designated_symbol"] = designated[0] if designated is not None else "none"

    rc = next((s for s in syms if s[0] == "recover_code" and s[1] & 0xF == 2), None)
    if rc is None:
        out["disassembly"] = []
    elif 0 < rc[2] < len(secs):
        sec = secs[rc[2]]
        off = rc[3] - sec[3] + sec[4]
        out["disassembly"] = _x86(d[off:off + rc[4]])
    if designated is not None and 0 < designated[2] < len(secs):
        sec = secs[designated[2]]
        off = designated[3] - sec[3] + sec[4]
        ins = _x86(d[off:off + designated[4]])
        if ins:
            first = next((x for x in ins if x.startswith("mov eax, ")), None)
            if first is not None:
                out["designated_constant"] = first[len("mov eax, "):]
            elif "xor eax, eax" in ins:
                out["designated_constant"] = "0"


def _coff_symbols(d: bytes, pe: int) -> list[str]:
    """COFF symbol/section names in table order, including long names from its string table."""
    if pe + 24 > len(d):
        return []
    ptr, count = struct.unpack_from("<II", d, pe + 12)
    end = ptr + count * 18
    if not ptr or count > 1_000_000 or end + 4 > len(d):
        return []
    str_size = struct.unpack_from("<I", d, end)[0]
    str_end = min(len(d), end + str_size) if str_size >= 4 else end + 4

    def name_at(raw: bytes):
        if raw[:4] == b"\0\0\0\0":
            off = struct.unpack_from("<I", raw, 4)[0]
            pos = end + off
            if off < 4 or pos >= str_end:
                return ""
            stop = d.find(b"\0", pos, str_end)
            return d[pos:stop if stop >= 0 else str_end].decode("utf-8", "replace")
        return raw.split(b"\0", 1)[0].decode("utf-8", "replace")

    names, i = [], 0
    while i < count:
        pos = ptr + i * 18
        if pos + 18 > len(d):
            break
        name = name_at(d[pos:pos + 8])
        if name:
            names.append(name)
        i += 1 + d[pos + 17]       # skip auxiliary records belonging to this symbol
    return names


def _x86(code: bytes):
    """The constant-return bodies the lane has shown: mov eax, imm32 / xor eax, eax / ret. Else None."""
    ins, i = [], 0
    while i < len(code):
        b = code[i]
        if b == 0xB8 and i + 5 <= len(code):
            ins.append(f"mov eax, {struct.unpack_from('<i', code, i + 1)[0]}")
            i += 5
        elif code[i:i + 2] == b"\x31\xc0":
            ins.append("xor eax, eax")
            i += 2
        elif b == 0xC3:
            ins.append("ret")
            i += 1
        else:
            return None
    return ins or None


def _pe(d: bytes, out: dict):
    if len(d) < 0x40:
        return
    pe = struct.unpack_from("<I", d, 0x3C)[0]
    if d[pe:pe + 4] != b"PE\0\0":
        return
    out["machine_id"] = struct.unpack_from("<H", d, pe + 4)[0]
    out["machine"] = PE_MACHINE.get(out["machine_id"])
    out["symbols"] = _coff_symbols(d, pe)
    opt = pe + 24
    magic = struct.unpack_from("<H", d, opt)[0]
    dirs = opt + (96 if magic == 0x10B else 112)
    cli = 0
    if dirs + 15 * 8 <= len(d):
        cli = struct.unpack_from("<I", d, dirs + 14 * 8)[0]
    out["format"] = "pe_cli" if cli else "pe"
    o = d.find(b"BSJB")
    if o >= 0 and o + 16 <= len(d):
        ln = struct.unpack_from("<I", d, o + 12)[0]
        out["metadata_version"] = d[o + 16:o + 16 + ln].split(b"\0", 1)[0].decode("ascii", "replace")


def facts(name: str, data: bytes) -> dict:
    out = {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data), "format": None, "machine": None,
           "hcfg": None}
    if data[:4] == b"\x7fELF":
        out["format"] = "elf"
        _elf(data, out)
        _cpp_flags(data, out)
        out["hcfg"] = hcfg_in(data)
    elif data[:2] == b"MZ":
        out["format"] = "pe"
        _pe(data, out)
        _cpp_flags(data, out)
        out["hcfg"] = hcfg_in(data)
    elif data[:4] == b"PK\x03\x04":
        out["compression_methods"] = zip_methods(data)
        members = _zip_members(data)
        if any(b[:4] == b"\xca\xfe\xba\xbe" for _, b in members):
            out["format"] = "jar"
        for _, b in members:
            h = hcfg_in(b)
            if h is None:
                for m in B64_HCFG.finditer(b):
                    try:
                        h = hcfg_in(base64.b64decode(m.group(), validate=True))
                    except (binascii.Error, ValueError):
                        h = None
                    if h:
                        break
            if h:
                out["hcfg"] = h
                break
    elif data[:4] == b"\xca\xfe\xba\xbe":
        out["format"] = "class"
        out["hcfg"] = hcfg_in(data)
    else:
        out["hcfg"] = hcfg_in(data)
    if out["hcfg"] is None:
        if data[:4] == b"PK\x03\x04":
            for _, b in _zip_members(data):
                out["hcfg"] = hcfg_deep(b)
                if out["hcfg"]:
                    break
        else:
            out["hcfg"] = hcfg_deep(data)
    return out
