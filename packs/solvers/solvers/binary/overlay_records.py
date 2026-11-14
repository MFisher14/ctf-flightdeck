#!/usr/bin/env python3
"""A generic overlay and trailer reader with self-describing records, magic-agnostic (B-216).

  .venv/bin/python solvers/binary/overlay_records.py SAMPLE [...]   the overlay and the records in it

At Huntress the Binary lane's trailing data changed shape almost weekly (Day 19 `PK19`, Day 20 `RS20`, Day 23
`hcfg_storage`) and every reader there was keyed on a magic someone had seen (`generic._overlay_record`,
`packed_tail`, `generic.tagged_trailer` all start from the HCFG magic). This module reads the shape instead:

overlay(data)   where the image ends by its own tables, and the bytes after it.
                ELF: the ELF header, the program and section header tables, every section that occupies
                file bytes (not SHT_NOBITS) and every segment's file range. PE: the headers, every section's
                raw range and the COFF symbol and string tables; a certificate table that starts at or after
                the image end is the signature, not an overlay, and is cut off. Mach-O (thin): every
                segment's file range (LC_SEGMENT/LC_SEGMENT_64). Anything else: None (no image, no overlay).

records(blob)   the self-describing records a blob holds, by FRAMING, never by magic. A tag is any four
                bytes of [A-Za-z0-9_] (the record names itself); the framing says how long it is and how it
                is checked:

  hdr16crc    tag | version u8 | key u8 | length u16 | crc32 u32 | payload    (the HCFG shape, any tag;
              the version byte is at most VERSION_MAX, here and in hdr32crc)
  hdr32crc    tag | version u8 | key u8 | length u32 | crc32 u32 | payload
  len32crc    tag | length u32 | crc32 u32 | payload
  len32sha    tag | length u32 | sha256[32] | payload
  tlv32       tag | length u32 | payload                (a chain of these, or one that fills the blob)
  footer      payload | tag | length u32 at the very end, length == the payload before it (also
              length | tag); the payload must start the blob, so the footer accounts for every byte

  Every framing is tried little-endian, then big-endian. A record counts only when it is VERIFIED:
    crc32     the stored CRC-32 is that of the payload, raw or decoded (decodings below)
    sha256    the stored SHA-256 is that of the payload, raw or decoded
    chain     two or more tlv32 records that cover the blob exactly (trailing zero padding of at most 15
              bytes allowed): the lengths describe every byte, which random data does not do
    exact     one tlv32 or footer record that covers the blob exactly
  Decodings tried on a payload: raw, XOR with the record's key byte, XOR then zlib, zlib, gzip, base64
  (an unpacked reading is capped at DECODED_MAX bytes: a stream that would unpack to more is not decoded, so a
  compression bomb in a challenge overlay costs at most that much before its check value is compared);
  when the check verifies an unpacked reading that is still masked, the record's key byte is applied to it
  (`zlib+xor`). A verified record whose decoded payload is a JSON object carries it in `.json`. One byte
  range can verify under two framings (a big-endian len32crc is also an hdr16crc with version and key 0):
  both are listed, and they carry the same payload.

  Records are searched at the blob's start (after zero padding), as a chain, as a footer, and, for the
  CRC- and SHA-checked framings, at every place a tag could start within SCAN_MAX bytes of either end.

config(blobs)   the one distinct verified JSON object among the records of several blobs, or None (zero, or
                two that differ: never a guess). A blob that is base64, base32 or base32hex text as a whole is
                read decoded as well (text_layers), so a record written whole in one of those text forms is a
                rival of a framed one and the two are never taken for one.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import struct
import sys
import zlib
from collections import namedtuple
from pathlib import Path

import binfmt

SCAN_MAX = 1 << 16          # bytes searched from each end for a checked record that does not start the blob
PAYLOAD_MAX = 64 << 20
DECODED_MAX = 16 << 20      # the most one zlib or gzip reading unpacks to (read at call time)
TEXT_MIN = 16               # the shortest blob text_layers reads as base64 / base32 text
PAD_MAX = 15
VERSION_MAX = 15            # a header's version byte; text bytes (>= 0x20) never pass, so a text blob is cheap
TAG = re.compile(rb"[A-Za-z0-9_]{4}")

Overlay = namedtuple("Overlay", "container start end blob")
Record = namedtuple("Record", "offset end framing endian tag version key length payload plain decoding verified json")

# name: (header struct after the tag, fields of that struct, integrity)
FRAMINGS = {
    "hdr16crc": ("BBHI", ("version", "key", "length", "crc"), "crc32"),
    "hdr32crc": ("BBII", ("version", "key", "length", "crc"), "crc32"),
    "len32crc": ("II", ("length", "crc"), "crc32"),
    "len32sha": ("I32s", ("length", "sha"), "sha256"),
    "tlv32": ("I", ("length",), None),
}


# ---------------------------------------------------------------------------- where the image ends

def _elf_end(data: bytes):
    info = binfmt.elf(data)
    if not info:
        return None
    ends = [64 if info["bits"] == 64 else 52]
    if info["e_phoff"] and info["e_phnum"]:
        ends.append(info["e_phoff"] + info["e_phnum"] * info["e_phentsize"])
    if info["e_shoff"] and info["e_shnum"]:
        ends.append(info["e_shoff"] + info["e_shnum"] * info["e_shentsize"])
    for s in info.get("sections") or []:
        if s["type"] not in (0, 8) and s["size"]:
            ends.append(s["offset"] + s["size"])
    for g in info.get("segments") or []:
        if g["filesz"]:
            ends.append(g["offset"] + g["filesz"])
    return "elf", min(max(ends), len(data))


def _pe_end(data: bytes):
    info = binfmt.pe(data)
    if info is None:
        return None
    end = max([s["raw"] + s["rsize"] for s in info["sections"] if s["rsize"]] + [info["size_of_headers"]])
    nt = struct.unpack_from("<I", data, 0x3C)[0]
    ptr, count = struct.unpack_from("<II", data, nt + 12)
    if ptr and count and ptr + 18 * count + 4 <= len(data):
        strsize = struct.unpack_from("<I", data, ptr + 18 * count)[0]
        end = max(end, ptr + 18 * count + max(strsize, 4))
    cert_at, cert_size = info["dirs"].get("security", (0, 0))
    stop = len(data)
    if cert_at and cert_size and cert_at >= end and cert_at + cert_size <= len(data):
        stop = cert_at
    return "pe", min(end, stop), stop


def _macho_end(data: bytes):
    magic = data[:4]
    if magic not in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce"):
        return None
    wide = magic in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf")
    end_ = "<" if magic[0] in (0xCF, 0xCE) else ">"
    try:
        ncmds, sizeofcmds = struct.unpack_from(end_ + "II", data, 16)
        cur = 32 if wide else 28
        if ncmds > 4096 or cur + sizeofcmds > len(data):
            return None
        ends = [cur + sizeofcmds]
        for _ in range(ncmds):
            cmd, size = struct.unpack_from(end_ + "II", data, cur)
            if size < 8 or cur + size > len(data):
                return None
            if cmd == 0x19:
                fileoff, filesize = struct.unpack_from(end_ + "QQ", data, cur + 40)
                ends.append(fileoff + filesize)
            elif cmd == 0x1:
                fileoff, filesize = struct.unpack_from(end_ + "II", data, cur + 32)
                ends.append(fileoff + filesize)
            cur += size
    except struct.error:
        return None
    return "macho", min(max(ends), len(data))


def overlay(data) -> Overlay | None:
    """The bytes after the image's last described byte, or None for a file that is no readable ELF, PE or
    thin Mach-O. An image with nothing after it has an Overlay with an empty blob."""
    if not isinstance(data, (bytes, bytearray)):
        return None
    data = bytes(data)
    if data[:4] == b"\x7fELF":
        got = _elf_end(data)
    elif data[:2] == b"MZ":
        got = _pe_end(data)
    else:
        got = _macho_end(data)
    if got is None:
        return None
    kind, start = got[0], got[1]
    stop = got[2] if len(got) > 2 else len(data)
    return Overlay(kind, start, stop, data[start:stop])


# ---------------------------------------------------------------------------- self-describing records

_XOR = {}


def _xor_table(key: int) -> bytes:
    if key not in _XOR:
        _XOR[key] = bytes(b ^ key for b in range(256))
    return _XOR[key]


def _inflate(data: bytes, gz: bool = False):
    """zlib.decompress (gz: gzip.decompress, every member) of `data`, or None when the stream is not whole or
    would unpack to more than DECODED_MAX bytes. Bytes after a zlib stream are ignored as zlib.decompress
    ignores them; after a gzip member only another member or zero padding may follow, as in gzip.decompress."""
    cap = DECODED_MAX
    out, rest = b"", data
    try:
        while True:
            room = cap - len(out)
            if room <= 0:
                return None
            d = zlib.decompressobj(31 if gz else 15)
            out += d.decompress(rest, room)
            if not d.eof:
                return None             # truncated, or stopped at the cap
            rest = d.unused_data
            if not gz or not rest.strip(b"\0"):
                return out
            if rest[:2] != b"\x1f\x8b":
                return None
    except zlib.error:
        return None


def _decodings(payload: bytes, key):
    """(name, bytes) readings of a payload, cheapest first."""
    yield "raw", payload
    if key:
        x = payload.translate(_xor_table(key))
        yield "xor", x
        got = _inflate(x)
        if got is not None:
            yield "xor+zlib", got
    for name, gz in (("zlib", False), ("gzip", True)):
        got = _inflate(payload, gz)
        if got is not None:
            yield name, got
    if payload and re.fullmatch(rb"[A-Za-z0-9+/=\r\n]+", payload):
        try:
            yield "base64", base64.b64decode(payload, validate=False)
        except (binascii.Error, ValueError):
            pass


def _json_object(blob: bytes):
    try:
        obj = json.loads(blob.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    return obj if isinstance(obj, dict) else None


def _best_plain(payload: bytes, key):
    """(decoding, plain, json) of the first decoding that is a JSON object, else the raw reading."""
    for name, plain in _decodings(payload, key):
        obj = _json_object(plain)
        if obj is not None:
            return name, plain, obj
    return "raw", payload, None


def _checked(blob: bytes, at: int, framing: str, endian: str):
    """A verified CRC- or SHA-checked record at `at`, or None."""
    fmt, fields, integrity = FRAMINGS[framing]
    head = struct.calcsize(endian + fmt)
    if at + 4 + head > len(blob) or not TAG.fullmatch(blob[at:at + 4]):
        return None
    vals = dict(zip(fields, struct.unpack_from(endian + fmt, blob, at + 4)))
    if vals.get("version", 0) > VERSION_MAX:
        return None
    n = vals["length"]
    if not n or n > PAYLOAD_MAX or at + 4 + head + n > len(blob):
        return None
    payload = blob[at + 4 + head:at + 4 + head + n]
    key = vals.get("key")
    for name, plain in _decodings(payload, key):
        if integrity == "crc32" and zlib.crc32(plain) & 0xFFFFFFFF == vals["crc"]:
            break
        if integrity == "sha256" and hashlib.sha256(plain).digest() == vals["sha"]:
            break
    else:
        return None
    obj = _json_object(plain)
    if obj is None and key and name in ("zlib", "gzip", "base64"):
        # the check covers the unpacked bytes and the record's own key byte still masks them
        unmasked = plain.translate(_xor_table(key))
        obj = _json_object(unmasked)
        if obj is not None:
            plain, name = unmasked, name + "+xor"
    return Record(at, at + 4 + head + n, framing, endian, blob[at:at + 4].decode("ascii"), vals.get("version"),
                  key, n, payload, plain, name, integrity, obj)


def _tlv_chain(blob: bytes, start: int, endian: str):
    """The tlv32 records that cover blob[start:] exactly (zero padding of at most PAD_MAX at the end), or []."""
    out, at = [], start
    while at + 8 <= len(blob) and TAG.fullmatch(blob[at:at + 4]):
        n = struct.unpack_from(endian + "I", blob, at + 4)[0]
        if not n or at + 8 + n > len(blob):
            return []
        out.append((at, n))
        at += 8 + n
    rest = blob[at:]
    if not out or len(rest) > PAD_MAX or rest.strip(b"\0"):
        return []
    verified = "chain" if len(out) >= 2 else "exact"
    recs = []
    for off, n in out:
        payload = blob[off + 8:off + 8 + n]
        dec, plain, obj = _best_plain(payload, None)
        recs.append(Record(off, off + 8 + n, "tlv32", endian, blob[off:off + 4].decode("ascii"), None, None, n,
                           payload, plain, dec, verified, obj))
    return recs


def _footer(blob: bytes, endian: str):
    """The one footer record that accounts for the whole blob, or None."""
    if len(blob) < 9:
        return None
    for tag_at, len_at in ((len(blob) - 8, len(blob) - 4), (len(blob) - 4, len(blob) - 8)):
        tag = blob[tag_at:tag_at + 4]
        n = struct.unpack_from(endian + "I", blob, len_at)[0]
        if TAG.fullmatch(tag) and n and n == len(blob) - 8:
            payload = blob[:n]
            dec, plain, obj = _best_plain(payload, None)
            return Record(0, len(blob), "footer", endian, tag.decode("ascii"), None, None, n, payload, plain, dec,
                          "exact", obj)
    return None


def records(blob) -> list:
    """Every verified record of a blob, by offset (see the module docstring)."""
    if not isinstance(blob, (bytes, bytearray)) or not blob:
        return []
    blob = bytes(blob)
    start = len(blob) - len(blob.lstrip(b"\0"))
    found = {}

    def keep(rec):
        if rec is not None and (rec.offset, rec.framing) not in found:
            found[(rec.offset, rec.framing)] = rec

    places = set(range(start, min(len(blob), start + SCAN_MAX)))
    places |= set(range(max(start, len(blob) - SCAN_MAX), len(blob)))
    tag_starts = sorted(p for p in places if TAG.fullmatch(blob[p:p + 4]))
    for endian in ("<", ">"):
        for at in tag_starts:
            for framing in ("hdr16crc", "hdr32crc", "len32crc", "len32sha"):
                keep(_checked(blob, at, framing, endian))
        for rec in _tlv_chain(blob, start, endian):
            keep(rec)
        if start == 0:
            keep(_footer(blob, endian))
    # A checked record inside a chained record's payload is the same bytes read twice: keep both, they
    # verify independently. Little-endian first, then offset.
    return sorted(found.values(), key=lambda r: (r.offset, r.endian != "<", r.framing))


_TEXTISH = re.compile(rb"[A-Za-z0-9+/=\s]+")
_B64 = re.compile(rb"[A-Za-z0-9+/]+={0,2}")
_B32 = re.compile(rb"[A-Z2-7]+={0,6}")
_B32HEX = re.compile(rb"[0-9A-V]+={0,6}")


def text_layers(blob) -> list:
    """[(name, bytes)]: the readings of a blob that is, as a whole, base64, base32 or base32hex text (white
    space ignored; base32 forms in either case). A blob of other bytes has none."""
    if not isinstance(blob, (bytes, bytearray)) or not _TEXTISH.fullmatch(blob):
        return []                       # fails at the first byte of a binary member: no copy is made
    text = re.sub(rb"\s+", b"", bytes(blob))
    if len(text) < TEXT_MIN:
        return []
    out = []
    if _B64.fullmatch(text) and len(text) % 4 == 0:
        try:
            out.append(("base64", base64.b64decode(text, validate=True)))
        except (binascii.Error, ValueError):
            pass
    upper = text.upper()
    for name, form, fn in (("base32", _B32, base64.b32decode), ("base32hex", _B32HEX, base64.b32hexdecode)):
        if form.fullmatch(upper) and len(upper) % 8 == 0:
            try:
                out.append((name, fn(upper)))
            except (binascii.Error, ValueError):
                pass
    return out


def config(blobs) -> dict | None:
    """The one distinct JSON object of the verified records across `blobs` and their text_layers, or None."""
    seen = {}
    for blob in blobs:
        for layer in [blob] + [data for _, data in text_layers(blob)]:
            for rec in records(layer):
                if rec.json is not None:
                    seen.setdefault(json.dumps(rec.json, sort_keys=True), rec.json)
    return next(iter(seen.values())) if len(seen) == 1 else None


def _main(argv) -> int:
    if not argv:
        print("usage: overlay_records.py SAMPLE [...]", file=sys.stderr)
        return 2
    for arg in argv:
        data = Path(arg).read_bytes()
        ov = overlay(data)
        if ov is None:
            print(f"{arg}: not a readable ELF, PE or thin Mach-O; records of the whole file:")
            blob = data
        else:
            print(f"{arg}: {ov.container} image ends at {ov.start}, overlay {len(ov.blob)} byte(s)")
            blob = ov.blob
        for r in records(blob):
            print(f"  @{r.offset} {r.framing}{r.endian} tag={r.tag} len={r.length} verified={r.verified} "
                  f"decoding={r.decoding}" + (f" json keys={sorted(r.json)[:8]}" if r.json else ""))
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
