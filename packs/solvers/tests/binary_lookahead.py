"""Synthetic Binary-lane samples and the packaging steps a later day may take (B-216 look-ahead fixtures).

Nothing here is a challenge file: every image is built from struct calls in this module.

  elf64(...)      a little-endian ELF64 with a section header table, one PT_LOAD, optional .symtab/.dynsym
  pe64(...)       a PE32+ with a section table, optional COFF symbol table, export directory and
                  certificate table
  macho64(...)    a thin little-endian Mach-O with __TEXT, optional LC_SYMTAB in __LINKEDIT
  record(...)     a self-describing record in any framing overlay_records.py reads, under any tag

  PACKAGINGS      {name: fn(day, image, sidecars) -> files dict}: the member names a day has used and the
                  next steps (renamed build word, a folder named for the day, no day word at all)
"""
from __future__ import annotations

import hashlib
import json
import struct
import zlib

# ---------------------------------------------------------------------------- ELF64


def _strtab(names):
    blob, at = b"\0", {}
    for n in names:
        if n not in at:
            at[n] = len(blob)
            blob += n.encode() + b"\0"
    return blob, at


def elf64(sections=(), symtab=None, dynsym=None, overlay=b"", machine=62, nobits=()):
    """sections: [(name, payload, flags, addr)]; symtab/dynsym: [(name, st_type, shndx)] (the null entry is
    added first); nobits: [(name, size, addr)], SHT_NOBITS sections (.bss) that occupy no file bytes, whose
    sh_offset is where the next bytes would go and whose size may run past the end of the file. Returns the
    image followed by `overlay`."""
    secs = [(n, p, f, a, 1) for n, p, f, a in sections]       # SHT_PROGBITS
    names = [n for n, *_ in secs] + [n for n, _, _ in nobits]
    extra = []
    for table, tname, sname, typ in ((symtab, ".symtab", ".strtab", 2), (dynsym, ".dynsym", ".dynstr", 11)):
        if table is None:
            continue
        sblob, sat = _strtab([n for n, _, _ in table])
        rows = b"\0" * 24
        for n, st_type, shndx in table:
            rows += struct.pack("<IBBHQQ", sat[n], (1 << 4) | st_type, 0, shndx, 0x1000, 0)
        extra.append((tname, rows, typ, sname, sblob))
    for tname, _, _, sname, _ in extra:
        names += [tname, sname]
    shstr, shat = _strtab(names + [".shstrtab"])
    body = bytearray(64 + 56)
    headers = [(0, 0, 0, 0, 0, 0, 0, 0, 0)]                    # name, type, flags, addr, off, size, link, info, entsize
    for n, p, f, a, t in secs:
        headers.append((shat[n], t, f, a, len(body), len(p), 0, 0, 0))
        body += p
    for n, size, a in nobits:
        headers.append((shat[n], 8, 3, a, len(body), size, 0, 0, 0))     # SHT_NOBITS, WA: no bytes in the file
    for tname, rows, typ, sname, sblob in extra:
        idx = len(headers)
        headers.append((shat[tname], typ, 2, 0, len(body), len(rows), idx + 1, 1, 24))
        body += rows
        headers.append((shat[sname], 3, 0, 0, len(body), len(sblob), 0, 0, 0))
        body += sblob
    headers.append((shat[".shstrtab"], 3, 0, 0, len(body), len(shstr), 0, 0, 0))
    body += shstr
    while len(body) % 8:
        body += b"\0"
    shoff = len(body)
    for h in headers:
        body += struct.pack("<IIQQQQIIQQ", h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7], 8, h[8])
    struct.pack_into("<4sBBBBB7x", body, 0, b"\x7fELF", 2, 1, 1, 0, 0)
    struct.pack_into("<HHIQQQIHHHHHH", body, 16, 2, machine, 1, 0x401000, 64, shoff, 0, 64, 56, 1, 64,
                     len(headers), len(headers) - 1)
    struct.pack_into("<IIQQQQQQ", body, 64, 1, 5, 0, 0x400000, 0x400000, shoff, shoff, 0x1000)
    return bytes(body) + overlay


# ---------------------------------------------------------------------------- PE32+

def _align(n, a):
    return (n + a - 1) // a * a


def pe64(sections=(), coff_symbols=None, exports=None, overlay=b"", cert=b""):
    """sections: [(name, payload, flags)]; coff_symbols: [(name, section number, type, storage class)],
    each optionally followed by aux records (a 5th element: count of 18-byte aux records); exports:
    [name] (an .edata section is added). The image, then `overlay`, then `cert` as the certificate table."""
    secs = list(sections)
    file_align, sect_align = 0x200, 0x1000
    nsec = len(secs) + (1 if exports else 0)
    head = _align(0x40 + 4 + 20 + 240 + 40 * nsec, file_align)
    table, raw, va = [], head, sect_align
    body_parts = []
    for name, payload, flags in secs:
        rsize = _align(len(payload), file_align) if payload else 0
        table.append((name, len(payload), va, rsize, raw if rsize else 0, flags))
        body_parts.append(payload.ljust(rsize, b"\0"))
        raw += rsize
        va += _align(max(len(payload), 1), sect_align)
    export_dir = (0, 0)
    if exports:
        edata_va = va
        names_at = 40 + 4 * len(exports)
        strings, rvas = b"", []
        for n in exports:
            rvas.append(edata_va + names_at + len(strings))
            strings += n.encode() + b"\0"
        ed = bytearray(40)
        struct.pack_into("<I", ed, 24, len(exports))
        struct.pack_into("<I", ed, 32, edata_va + 40)
        ed += b"".join(struct.pack("<I", r) for r in rvas) + strings
        rsize = _align(len(ed), file_align)
        table.append((".edata", len(ed), edata_va, rsize, raw, 0x40000040))
        body_parts.append(bytes(ed).ljust(rsize, b"\0"))
        export_dir = (edata_va, len(ed))
        raw += rsize
        va += _align(len(ed), sect_align)
    sym_ptr, sym_count, symblob = 0, 0, b""
    if coff_symbols is not None:
        strings, recs = b"", b""
        for entry in coff_symbols:
            name, secno, typ, cls = entry[:4]
            aux = entry[4] if len(entry) > 4 else 0
            enc = name.encode()
            if len(enc) <= 8:
                field = enc.ljust(8, b"\0")
            else:
                field = struct.pack("<II", 0, 4 + len(strings))
                strings += enc + b"\0"
            recs += field + struct.pack("<IhHBB", 0, secno, typ, cls, aux) + b"\0" * 18 * aux
            sym_count += 1 + aux
        sym_ptr = raw
        symblob = recs + struct.pack("<I", 4 + len(strings)) + strings
    image_end = raw + len(symblob)
    cert_dir = (image_end + len(overlay), len(cert)) if cert else (0, 0)
    hdr = bytearray(head)
    hdr[0:2] = b"MZ"
    struct.pack_into("<I", hdr, 0x3C, 0x40)
    hdr[0x40:0x44] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", hdr, 0x44, 0x8664, nsec, 0, sym_ptr, sym_count, 240, 0x22)
    opt = 0x58
    struct.pack_into("<HBB", hdr, opt, 0x20B, 14, 0)
    struct.pack_into("<I", hdr, opt + 16, 0x1000)
    struct.pack_into("<Q", hdr, opt + 24, 0x140000000)
    struct.pack_into("<II", hdr, opt + 32, sect_align, file_align)
    struct.pack_into("<IIIHH", hdr, opt + 56, va, head, 0, 3, 0x8160)
    struct.pack_into("<I", hdr, opt + 108, 16)
    struct.pack_into("<II", hdr, opt + 112, *export_dir)
    struct.pack_into("<II", hdr, opt + 112 + 8 * 4, *cert_dir)
    at = opt + 240
    for name, vsize, sva, rsize, rptr, flags in table:
        struct.pack_into("<8sIIII12xI", hdr, at, name.encode()[:8], vsize, sva, rsize, rptr, flags)
        at += 40
    return bytes(hdr) + b"".join(body_parts) + symblob + overlay + cert


# ---------------------------------------------------------------------------- Mach-O 64

def macho64(symbols=None, overlay=b""):
    """symbols: [(name, n_type, n_sect)] in LC_SYMTAB, or None for no LC_SYMTAB."""
    text = b"\x90" * 64
    ncmds = 1 + (2 if symbols is not None else 0)
    sizeofcmds = 72 + (72 + 24 if symbols is not None else 0)
    head = 32 + sizeofcmds
    text_end = head + len(text)
    cmds = struct.pack("<II16sQQQQIIII", 0x19, 72, b"__TEXT", 0x100000000, 0x1000, 0, text_end, 5, 5, 0, 0)
    tail = b""
    if symbols is not None:
        sblob, sat = _strtab([n for n, _, _ in symbols])
        rows = b"".join(struct.pack("<IBBHQ", sat[n], t, s, 0, 0x100000f00) for n, t, s in symbols)
        symoff, stroff = text_end, text_end + len(rows)
        tail = rows + sblob
        cmds += struct.pack("<II16sQQQQIIII", 0x19, 72, b"__LINKEDIT", 0x100002000, 0x1000, text_end, len(tail),
                            1, 1, 0, 0)
        cmds += struct.pack("<IIIIII", 0x2, 24, symoff, len(symbols), stroff, len(sblob))
    hdr = struct.pack("<IiIIIII4x", 0xFEEDFACF, 0x01000007, 3, 2, ncmds, sizeofcmds, 0)
    return hdr + cmds + text + tail + overlay


# ---------------------------------------------------------------------------- records

def record(framing, tag: bytes, obj, key=0x5A, endian="<", version=1, corrupt=False):
    """One self-describing record carrying `obj` as JSON. framing: hdr16crc, hdr32crc, len32crc, len32sha,
    tlv32, footer (see overlay_records.py). With corrupt=True the stored check value is wrong."""
    plain = json.dumps(obj, separators=(",", ":")).encode()
    crc = zlib.crc32(plain) ^ (1 if corrupt else 0)
    if framing == "hdr16crc":
        payload = bytes(b ^ key for b in plain)
        return tag + struct.pack(endian + "BBHI", version, key, len(payload), crc) + payload
    if framing == "hdr32crc":
        payload = zlib.compress(bytes(b ^ key for b in plain))
        crc = zlib.crc32(bytes(b ^ key for b in plain)) ^ (1 if corrupt else 0)
        return tag + struct.pack(endian + "BBII", version, key, len(payload), crc) + payload
    if framing == "len32crc":
        payload = zlib.compress(plain)
        return tag + struct.pack(endian + "II", len(payload), crc) + payload
    if framing == "len32sha":
        digest = hashlib.sha256(plain).digest()
        if corrupt:
            digest = bytes([digest[0] ^ 1]) + digest[1:]
        return tag + struct.pack(endian + "I", len(plain)) + digest + plain
    if framing == "tlv32":
        return tag + struct.pack(endian + "I", len(plain)) + plain
    if framing == "footer":
        return plain + tag + struct.pack(endian + "I", len(plain))
    raise ValueError(framing)


# ---------------------------------------------------------------------------- packaging steps

def by_name(day, image, sidecars=()):
    return {f"d{day:02d}--variant-000.bin": image, **{f"d{day:02d}--variant-000.{n}": b for n, b in sidecars}}


def renamed(day, image, sidecars=()):
    return {f"d{day:02d}--sample-direct.bin": image, **{f"d{day:02d}--sample-direct.{n}": b for n, b in sidecars}}


def day_folder(day, image, sidecars=()):
    return {f"day{day:02d}/sample.bin": image, **{f"day{day:02d}/sample.{n}": b for n, b in sidecars}}


def no_day_word(day, image, sidecars=()):
    return {"payload.bin": image, **{f"payload.{n}": b for n, b in sidecars}, "readme.txt": b"see the sample"}


PACKAGINGS = {"by_name": by_name, "renamed": renamed, "day_folder": day_folder, "no_day_word": no_day_word}
