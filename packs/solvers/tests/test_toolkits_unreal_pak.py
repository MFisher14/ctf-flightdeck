"""Unreal .pak reader, unpacker and literal-pool harvest (B-120).

Every archive here is written by this file from the UnrealPak layout (footer, FPakEntry, the legacy
index and the version 10+ path-hash index), independently of the reader's own code.  No real game file
is used or needed.
"""
from __future__ import annotations

import base64
import datetime as dt
import gzip
import hashlib
import json
import os
import struct
import zlib
from pathlib import Path

import pytest

import unreal_pak as up
from ctf import event
from ctf.engines import router
from ctf.result import SolverResult

MAGIC = struct.pack("<I", 0x5A6F12E1)
KEY = bytes(range(32))
needs_aes = pytest.mark.needs_tool("py:cryptography")


# --------------------------------------------------------------------------- a pak writer
def aes_ecb(data: bytes, key: bytes = KEY) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(data) + enc.finalize()


def pad16(data: bytes) -> bytes:
    return data + b"\x00" * (-len(data) % 16)


def fstr(text: str) -> bytes:
    raw = text.encode("ascii") + b"\x00"
    return struct.pack("<i", len(raw)) + raw


def fstr16(text: str) -> bytes:
    raw = (text + "\x00").encode("utf-16-le")
    return struct.pack("<i", -(len(raw) // 2)) + raw


def entry_struct(version, offset, csize, usize, method, blocks, flags, block_size, v8a=False):
    out = struct.pack("<QQQ", offset, csize, usize)
    out += struct.pack("<B", method) if v8a else struct.pack("<I", method)
    if version <= 1:
        out += struct.pack("<Q", 0)                       # timestamp
    out += hashlib.sha1(b"entry").digest()
    if version >= 3:
        if method != 0:
            out += struct.pack("<I", len(blocks)) + b"".join(struct.pack("<QQ", s, e) for s, e in blocks)
        out += struct.pack("<B", flags) + struct.pack("<I", block_size)
    return out


def footer(version, index_offset, index_size, sha1, *, encrypted=False, names=(), v8a=False, frozen=False):
    out = b""
    if version >= 7:
        out += b"\xAB" * 16                               # encryption key guid
    if version >= 4:
        out += bytes([1 if encrypted else 0])
    out += MAGIC + struct.pack("<I", version) + struct.pack("<QQ", index_offset, index_size) + sha1
    if version == 9:
        out += bytes([1 if frozen else 0])
    if version >= 8:
        for slot in range(4 if v8a else 5):
            name = names[slot] if slot < len(names) else ""
            out += name.encode("ascii").ljust(32, b"\x00")
    return out


def store(body: bytearray, version, spec, *, v8a=False, block_size=1024):
    """Append one file's header and data to ``body``; return its index FPakEntry (with real offset)."""
    data, method, codec = spec["data"], spec.get("method", 0), spec.get("codec")
    encrypted = spec.get("encrypted", False)
    flags = (1 if encrypted else 0) | (2 if spec.get("deleted") else 0)
    offset = len(body)
    if codec is None:
        stored = aes_ecb(pad16(data)) if encrypted else data
        blocks: list[tuple[int, int]] = []
        csize = spec.get("declared_csize", len(data))
    else:
        pieces = [data[i:i + block_size] for i in range(0, len(data), block_size)] or [b""]
        packed = [zlib.compress(p) if codec == "zlib" else gzip.compress(p, mtime=0) for p in pieces]
        header_len = len(entry_struct(version, 0, 0, 0, method, [(0, 0)] * len(packed), flags, block_size, v8a))
        position = header_len if version >= 5 else offset + header_len     # relative from version 5
        blocks, stored = [], b""
        for piece in packed:
            blocks.append((position, position + len(piece)))
            on_disk = aes_ecb(pad16(piece)) if encrypted else piece
            stored += on_disk
            position += len(on_disk)
        csize = blocks[-1][1] - blocks[0][0]
    usize = spec.get("declared_usize", len(data))
    body += entry_struct(version, 0, csize, usize, method, blocks, flags, block_size, v8a) + stored
    return entry_struct(version, offset, csize, usize, method, blocks, flags, block_size, v8a)


def build_pak(files, *, version=3, names=(), v8a=False, encrypt_index=False, mount="../../../Game/",
              frozen=False, tamper=False, trailing=b"", utf16_names=False, count=None) -> bytes:
    body = bytearray()
    index = fstr(mount) + struct.pack("<I", len(files) if count is None else count)
    for spec in files:
        record = store(body, version, spec, v8a=v8a)
        index += (fstr16 if utf16_names else fstr)(spec["name"]) + record
    if encrypt_index:
        index = pad16(index)
    sha1 = hashlib.sha1(index).digest()
    if tamper:
        index = index.replace(b"readme", b"README")
    on_disk = aes_ecb(index) if encrypt_index else index
    tail = footer(version, len(body), len(on_disk), sha1, encrypted=encrypt_index, names=names, v8a=v8a,
                  frozen=frozen)
    return bytes(body) + on_disk + tail + trailing


def blocks_pak(region: bytes, blocks, usize, *, name="x.bin", method=1) -> bytes:
    """A version 5 archive with one compressed entry whose blocks are the given ``(start, end)``
    ranges of ``region`` (the bytes written after the entry header), whatever they hold: a layout a
    packer would never write, hostile ones included."""
    version = 5
    header_len = len(entry_struct(version, 0, 0, 0, method, [(0, 0)] * len(blocks), 0, 1024))
    placed = [(header_len + start, header_len + end) for start, end in blocks]   # relative to the entry
    record = entry_struct(version, 0, len(region), usize, method, placed, 0, 1024)
    body = record + region
    index = fstr("../") + struct.pack("<I", 1) + fstr(name) + record
    return body + index + footer(version, len(body), len(index), hashlib.sha1(index).digest())


def encoded_entry(offset, usize, csize, method, block_sizes, *, encrypted=False, block_size=65536, wide=False):
    """One bit-packed entry of the version 10+ index.  ``wide`` writes 64-bit fields: True for all of
    them, or the names of the ones to widen ("offset", "usize", "csize")."""
    wide = {"offset", "usize", "csize"} if wide is True else set(wide or ())
    bits = (method << 23) | ((1 if encrypted else 0) << 22) | (len(block_sizes) << 6)
    explicit = b""
    if block_size % 2048 == 0 and (block_size >> 11) < 0x3F:
        bits |= block_size >> 11
    else:
        bits |= 0x3F
        explicit = struct.pack("<I", block_size)
    fields = b""
    for name, value, bit, wanted in (("offset", offset, 31, True), ("usize", usize, 30, True),
                                     ("csize", csize, 29, method != 0)):
        if not wanted:
            continue
        if name in wide:
            fields += struct.pack("<Q", value)
        else:
            bits |= 1 << bit
            fields += struct.pack("<I", value)
    out = struct.pack("<I", bits) + explicit + fields
    if not (len(block_sizes) == 1 and not encrypted):
        out += b"".join(struct.pack("<I", size) for size in block_sizes)
    return out


def build_pak_v11(files, *, directory=True, path_hash=False, names=("Zlib",), encrypt_index=False,
                  plain_entries=(), extra_directory=(), count=None) -> bytes:
    """files: [{name 'Dir/File', data, codec None|'zlib', wide, block_size}].  ``plain_entries`` are
    files listed through the non-encoded table (a negative directory value).  ``count`` overrides the
    primary index's entry count (by default the number of files listed)."""
    version = 11
    body = bytearray()
    encoded = b""
    listing: list[tuple[str, int]] = []
    for spec in files:
        offset = len(body)
        data, codec = spec["data"], spec.get("codec")
        block_size = spec.get("block_size", 65536)
        secret = spec.get("encrypted", False)
        seal = (lambda blob: aes_ecb(pad16(blob))) if secret else (lambda blob: blob)
        if codec is None:
            body += entry_struct(version, 0, len(data), len(data), 0, [], int(secret), 0) + seal(data)
            row = encoded_entry(offset, len(data), len(data), 0, [], block_size=block_size,
                                wide=spec.get("wide", False), encrypted=secret)
        else:
            pieces = [data[i:i + block_size] for i in range(0, len(data), block_size)] or [b""]
            packed = [zlib.compress(p) for p in pieces]
            base = len(entry_struct(version, 0, 0, 0, 1, [(0, 0)] * len(packed), 0, block_size))
            position, blocks, stored = base, [], b""
            for piece in packed:
                blocks.append((position, position + len(piece)))
                stored += seal(piece)                      # each block padded to 16 bytes when encrypted
                position = base + len(stored)
            csize = sum(len(p) for p in packed)
            body += entry_struct(version, 0, csize, len(data), 1, blocks, int(secret), block_size) + stored
            row = encoded_entry(offset, len(data), csize, spec.get("method", 1), [len(p) for p in packed],
                                block_size=block_size, wide=spec.get("wide", False), encrypted=secret)
        listing.append((spec["name"], len(encoded)))
        encoded += row
    plain = b""
    for number, spec in enumerate(plain_entries):
        record = store(body, version, spec)
        plain += record
        listing.append((spec["name"], -(number + 1)))
    listing.extend(extra_directory)

    folders: dict[str, list[tuple[str, int]]] = {}
    for name, value in listing:
        folder, _, leaf = name.rpartition("/")
        folders.setdefault(folder + "/", []).append((leaf, value))
    fdi = struct.pack("<I", len(folders))
    for folder, rows in folders.items():
        fdi += fstr(folder) + struct.pack("<I", len(rows))
        fdi += b"".join(fstr(leaf) + struct.pack("<i", value) for leaf, value in rows)
    phi = struct.pack("<I", len(listing)) + b"".join(
        struct.pack("<Qi", 0x1000 + number, value) for number, (_name, value) in enumerate(listing))
    if encrypt_index:
        fdi, phi = pad16(fdi), pad16(phi)

    def primary(phi_at, fdi_at):
        out = (fstr("../../../") + struct.pack("<I", len(listing) if count is None else count)
               + struct.pack("<Q", 0xFEED))
        for present, at, blob in ((path_hash, phi_at, phi), (directory, fdi_at, fdi)):
            out += struct.pack("<I", 1 if present else 0)
            if present:
                out += struct.pack("<QQ", at, len(blob)) + hashlib.sha1(blob).digest()
        out += struct.pack("<I", len(encoded)) + encoded
        out += struct.pack("<I", len(plain_entries)) + plain
        return pad16(out) if encrypt_index else out

    size = len(primary(0, 0))
    # the secondary indexes sit before the primary one, so the footer's pointer stays below the magic
    phi_at = len(body)
    fdi_at = phi_at + (len(phi) if path_hash else 0)
    index_at = fdi_at + (len(fdi) if directory else 0)
    index = primary(phi_at, fdi_at)
    assert len(index) == size
    crypt = aes_ecb if encrypt_index else (lambda blob: blob)
    return (bytes(body) + (crypt(phi) if path_hash else b"") + (crypt(fdi) if directory else b"")
            + crypt(index) + footer(version, index_at, len(index), hashlib.sha1(index).digest(),
                                    encrypted=encrypt_index, names=names))


def entries_of(report):
    return {entry["name"]: entry for entry in report["entries"]}


def flags_of(report):
    return {row["flag"] for row in report["flags"]}


class StepClock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        value, self.now = self.now, self.now + 1.0
        return value


README = {"name": "readme.txt", "data": b"hello CSCTF{stored_entry} bye"}


# --------------------------------------------------------------------------- footer and legacy index
@pytest.mark.parametrize("version,kwargs,tail", [
    (1, {}, 44), (2, {}, 44), (3, {}, 44), (4, {}, 44), (6, {}, 44), (7, {}, 44),
    (8, {"v8a": True, "names": ("Zlib",)}, 172), (8, {"names": ("Zlib",)}, 204),
    (9, {"names": ("Zlib",)}, 205)], ids=["v1", "v2", "v3", "v4", "v6", "v7", "v8a", "v8b", "v9"])
def test_footer_and_legacy_index_of_every_version(version, kwargs, tail):
    pak = build_pak([README, {"name": "Config/x.bin", "data": b"\x00\x01\x02"}], version=version, **kwargs)
    report = up.read_pak(pak)
    assert report["version"] == version and report["footer_location"] == "fixed"
    assert report["magic_offset"] == len(pak) - tail
    assert report["mount_point"] == "../../../Game/" and report["entry_count"] == 2
    assert report["index_status"] == "ok" and report["index_sha1_match"] is True
    assert report["index_encrypted"] is False
    assert report["encryption_key_guid"] == ("ab" * 16 if version >= 7 else None)
    entries = entries_of(report)
    assert entries["readme.txt"]["extract_status"] == "ok" and entries["readme.txt"]["compression"] is None
    assert entries["readme.txt"]["uncompressed_size"] == len(README["data"])
    assert entries["readme.txt"]["flags"] == ["CSCTF{stored_entry}"]
    assert entries["Config/x.bin"]["offset"] > 0 and entries["Config/x.bin"]["flags"] == []
    (row,) = report["flags"]
    assert {"entry": "readme.txt", "offset": 6, "encoding": "ascii"} in row["sources"]
    assert report["extract_statuses"] == {"ok": 2}


def test_utf16_entry_names_are_read():
    report = up.read_pak(build_pak([{"name": "Maps/\u00dcbung.umap", "data": b"x"}], utf16_names=True))
    assert list(entries_of(report)) == ["Maps/\u00dcbung.umap"]


def test_footer_found_by_scan_when_bytes_trail_it():
    pak = build_pak([README], version=7, trailing=b"appended by the challenge author" * 3)
    report = up.read_pak(pak)
    assert report["footer_location"] == "scanned" and report["version"] == 7
    assert entries_of(report)["readme.txt"]["extract_status"] == "ok"


def test_the_last_footer_in_the_tail_wins_over_one_embedded_before_it():
    inner = build_pak([{"name": "inner.txt", "data": b"inner"}], version=3)
    trailing = b"appended " * 4
    outer = build_pak([{"name": "nested.pak", "data": inner}, README], version=7, trailing=trailing)
    # the inner archive's footer is a self-consistent magic in the scanned tail too, and comes first
    assert outer.count(MAGIC) == 2 and len(outer) < up.MAX_FOOTER_SCAN
    report = up.read_pak(outer)
    assert report["footer_location"] == "scanned" and report["version"] == 7
    assert report["magic_offset"] == len(outer) - len(trailing) - 44 == outer.rindex(MAGIC)
    assert list(entries_of(report)) == ["nested.pak", "readme.txt"] and report["index_status"] == "ok"


def test_index_entry_counts_past_the_cap_are_refused(monkeypatch):
    monkeypatch.setattr(up, "MAX_ENTRIES", 1)
    assert up.read_pak(build_pak([README]))["index_status"] == "ok"
    legacy = up.read_pak(build_pak([README, {"name": "b.txt", "data": b"b"}]))
    assert legacy["index_status"] == "error: the index did not parse (index entry count exceeds the cap)"
    assert legacy["entries"] == []
    two = [{"name": "Game/a.txt", "data": b"a"}, {"name": "Game/b.txt", "data": b"b"}]
    assert up.read_pak(build_pak_v11(two[:1]))["index_status"] == "ok"
    for pak, message in (
            (build_pak_v11(two), "index entry count exceeds the cap"),
            (build_pak_v11(two, count=1), "directory index lists more files than the cap"),
            (build_pak_v11(two, count=1, directory=False, path_hash=True),
             "path hash index lists more files than the cap"),
            (build_pak_v11([], count=1, plain_entries=two), "non-encoded entry count exceeds the cap")):
        report = up.read_pak(pak)
        assert report["index_status"] == f"error: the index did not parse ({message})", message
        assert report["entries"] == []


def test_not_a_pak_and_bad_inputs():
    with pytest.raises(up.UnrealPakError, match="0x5A6F12E1"):
        up.read_pak(b"PACK" + b"\x00" * 4096)                # a Quake pak: same extension, another format
    forged = b"\x00" * 100 + MAGIC + struct.pack("<I", 3) + struct.pack("<QQ", 5000, 10) + b"\x00" * 20
    with pytest.raises(up.UnrealPakError, match="no UnrealPak footer"):
        up.read_pak(forged)                                  # the index pointer lies past the magic
    with pytest.raises(up.UnrealPakError, match="bytes-like"):
        up.read_pak("text")
    with pytest.raises(up.UnrealPakError, match="aes_key must be 32 bytes"):
        up.read_pak(build_pak([README]), aes_key=b"short")


def test_index_edited_after_packing_is_reported_and_still_read():
    report = up.read_pak(build_pak([README], tamper=True))
    assert report["index_sha1_match"] is False
    assert any("edited after packing" in note for note in report["notes"])
    assert list(entries_of(report)) == ["README.txt"]


def test_index_that_does_not_parse_is_an_error_status_and_the_literal_pool_still_runs():
    pak = build_pak([README], count=9)                       # the index claims nine entries, holds one
    report = up.read_pak(pak)
    assert report["index_status"].startswith("error: the index did not parse") and report["entries"] == []
    assert flags_of(report) == {"CSCTF{stored_entry}"}       # found in the raw archive bytes
    assert "archive_offset" in report["flags"][0]["sources"][0]


def test_frozen_index_and_newer_version_are_named():
    frozen = up.read_pak(build_pak([README], version=9, names=("Zlib",), frozen=True))
    assert frozen["index_status"].startswith("blocked: frozen index") and frozen["entries"] == []
    body = b"x" * 64
    index = fstr("../") + struct.pack("<I", 0)
    newer = body + index + b"\x00" * 16 + b"\x00" + MAGIC + struct.pack("<I", 12) + struct.pack(
        "<QQ", len(body), len(index)) + hashlib.sha1(index).digest() + b"\x00" * 160
    report = up.read_pak(newer)
    assert report["version"] == 12 and "newer than this reader" in report["index_status"]


# --------------------------------------------------------------------------- compression
@pytest.mark.parametrize("version", [3, 4, 5, 7], ids=["v3-absolute", "v4-absolute", "v5-relative", "v7-relative"])
def test_zlib_entry_in_several_blocks_with_absolute_and_relative_offsets(version):
    data = (b"padding " * 300) + b"CSCTF{inside_zlib_blocks}" + bytes(range(256)) * 4
    pak = build_pak([{"name": "first.bin", "data": b"A" * 100},
                     {"name": "big.dat", "data": data, "method": 1, "codec": "zlib"}], version=version)
    payloads = {}
    report = up.read_pak(pak, sink=lambda name, payload: payloads.__setitem__(name, payload))
    entry = entries_of(report)["big.dat"]
    assert entry["extract_status"] == "ok" and entry["compression"] == "zlib" and entry["block_count"] == 4
    assert payloads["big.dat"] == data and payloads["first.bin"] == b"A" * 100
    assert flags_of(report) == {"CSCTF{inside_zlib_blocks}"}
    assert report["flags"][0]["sources"] == [
        {"entry": "big.dat", "offset": data.index(b"CSCTF"), "encoding": "ascii"}]   # not in the raw bytes


def test_gzip_entry_and_legacy_custom_method():
    pak = build_pak([{"name": "g.txt", "data": b"CSCTF{gzip_entry}", "method": 2, "codec": "gzip"},
                     {"name": "o.bin", "data": b"oodle?", "method": 4, "codec": "zlib"}], version=5)
    entries = entries_of(up.read_pak(pak))
    assert entries["g.txt"]["extract_status"] == "ok" and entries["g.txt"]["compression"] == "gzip"
    assert entries["o.bin"]["compression"] == "custom"
    assert entries["o.bin"]["extract_status"] == "unsupported: custom compression is not decoded by this reader"


@pytest.mark.parametrize("v8a", [True, False], ids=["v8a-u8-slot", "v8b-u32-slot"])
def test_version_8_compression_is_a_slot_in_the_footer_name_table(v8a):
    pak = build_pak([{"name": "z.txt", "data": b"CSCTF{named_slot}" * 3, "method": 2, "codec": "zlib"},
                     {"name": "o.bin", "data": b"x" * 40, "method": 1, "codec": "zlib"},
                     {"name": "n.bin", "data": b"y" * 40, "method": 4, "codec": "zlib"}],
                    version=8, v8a=v8a, names=("Oodle", "Zlib"))
    report = up.read_pak(pak)
    assert report["compression_names"][:2] == ["Oodle", "Zlib"]
    assert len(report["compression_names"]) == (4 if v8a else 5)
    entries = entries_of(report)
    assert entries["z.txt"]["compression"] == "zlib" and entries["z.txt"]["extract_status"] == "ok"
    assert entries["o.bin"]["compression"] == "oodle"
    assert entries["o.bin"]["extract_status"].startswith("unsupported: oodle compression")
    assert entries["n.bin"]["compression"] == "unnamed-slot-4"
    assert report["extract_statuses"] == {"ok": 1, "unsupported": 2}


def test_delete_record_is_not_a_file():
    pak = build_pak([{"name": "gone.txt", "data": b"", "deleted": True}, README], version=6)
    entries = entries_of(up.read_pak(pak))
    assert entries["gone.txt"]["deleted"] is True
    assert entries["gone.txt"]["extract_status"] == "skipped: a delete record, not a file"
    assert entries["readme.txt"]["extract_status"] == "ok"
    older = entries_of(up.read_pak(build_pak([{"name": "kept.txt", "data": b"k", "deleted": True}], version=5)))
    assert older["kept.txt"]["deleted"] is False                  # the flag means that only from version 6


def test_extraction_caps_and_lying_sizes(monkeypatch):
    bomb = {"name": "bomb.bin", "data": b"\x00" * 5000, "method": 1, "codec": "zlib", "declared_usize": 100}
    short = {"name": "short.bin", "data": b"abc", "method": 1, "codec": "zlib", "declared_usize": 9}
    entries = entries_of(up.read_pak(build_pak([bomb, short, README], version=5)))
    assert entries["bomb.bin"]["extract_status"] == "error: inflates past the declared uncompressed size"
    assert entries["short.bin"]["extract_status"] == ("error: inflated size differs from the declared "
                                                      "uncompressed size")
    assert entries["readme.txt"]["extract_status"] == "ok"

    monkeypatch.setattr(up, "MAX_EXTRACT_PER_ENTRY", 16)
    capped = entries_of(up.read_pak(build_pak([README, {"name": "s.txt", "data": b"tiny"}])))
    assert capped["readme.txt"]["extract_status"] == "skipped: larger than the 16 byte per-entry cap"
    assert capped["s.txt"]["extract_status"] == "ok"
    monkeypatch.setattr(up, "MAX_EXTRACT_PER_ENTRY", 1 << 20)
    monkeypatch.setattr(up, "MAX_EXTRACT_TOTAL", 30)
    report = up.read_pak(build_pak([README, {"name": "s.txt", "data": b"tiny"}]))
    assert entries_of(report)["s.txt"]["extract_status"] == "skipped: the total extraction cap is spent"
    assert report["extraction_cap_remaining"] == 30 - len(README["data"])


def test_a_compression_block_larger_than_its_entry_can_need_is_not_read():
    data = b"0123456789"
    packed = zlib.compress(data)
    payloads = {}
    honest = up.read_pak(blocks_pak(packed, [(0, len(packed))], len(data)),
                         sink=lambda name, payload: payloads.__setitem__(name, payload))
    assert entries_of(honest)["x.bin"]["extract_status"] == "ok" and payloads == {"x.bin": data}

    # the same stream in a block declared to run on over 4096 more bytes: zlib stops at the end of
    # its stream, so reading the block as declared would "extract" the file and allocate what the
    # archive says (48 MiB for these 10 bytes, in the case this guards against)
    region = packed + bytes(4096)
    payloads.clear()
    fat = up.read_pak(blocks_pak(region, [(0, len(region))], len(data)),
                      sink=lambda name, payload: payloads.__setitem__(name, payload))
    assert entries_of(fat)["x.bin"]["extract_status"] == (
        f"error: a compression block of {len(region)} stored bytes in an entry of 10 bytes: more than "
        "its compression can need, not read")
    assert payloads == {} and fat["extract_statuses"] == {"error": 1}

    # the bound is the entry's size and a quarter, plus 64 for the stream wrapper: 76 for 10 bytes
    assert up._stored_bound(10) == 76 and up._stored_bound(0) == 64 and up._stored_bound(1 << 20) == 1310784
    at_bound = packed + bytes(76 - len(packed))
    assert entries_of(up.read_pak(blocks_pak(at_bound, [(0, 76)], 10)))["x.bin"]["extract_status"] == "ok"
    over = entries_of(up.read_pak(blocks_pak(at_bound + b"\x00", [(0, 77)], 10)))["x.bin"]
    assert over["extract_status"].startswith("error: a compression block of 77 stored bytes")

    # data that does not compress at all still fits: stored deflate blocks, zlib and gzip wrappers
    noise = b"".join(hashlib.sha256(bytes([n])).digest() for n in range(256)) * 16      # 128 KiB
    for method, stored in ((1, zlib.compress(noise, 0)), (2, gzip.compress(noise, 0, mtime=0))):
        assert len(stored) > len(noise)
        entry = entries_of(up.read_pak(blocks_pak(stored, [(0, len(stored))], len(noise), method=method)))
        assert entry["x.bin"]["extract_status"] == "ok", method


def test_the_blocks_of_one_entry_cannot_hold_more_stored_bytes_than_it_can_need():
    data = bytes(range(250)) * 16                              # 4000 bytes: 5064 for one block
    packed = zlib.compress(data)
    idle = zlib.compress(b"") + bytes(2992)                    # 3000 bytes that inflate to nothing
    region = packed + idle
    real, empty = (0, len(packed)), (len(packed), len(region))
    assert len(packed) < 1000 and up._stored_bound(len(data)) == 5064
    payloads = {}
    # one idle block ahead of the real one is within what the entry can need (5064 bytes in all)
    once = up.read_pak(blocks_pak(region, [empty, real], len(data)),
                       sink=lambda name, payload: payloads.__setitem__(name, payload))
    assert entries_of(once)["x.bin"]["extract_status"] == "ok" and payloads == {"x.bin": data}
    # two of them (the same 3000 bytes listed twice) are not: the second is never read
    twice = entries_of(up.read_pak(blocks_pak(region, [empty, empty, real], len(data))))["x.bin"]
    assert twice["extract_status"] == ("error: the compression blocks of an entry of 4000 bytes hold more "
                                       "stored bytes than its compression can need: the rest not read")
    assert twice["block_count"] == 3
    # and 20,000 listings of that range cost no more than two
    many = entries_of(up.read_pak(blocks_pak(region, [empty] * 20_000 + [real], len(data))))["x.bin"]
    assert many["extract_status"] == twice["extract_status"] and many["block_count"] == 20_001


def test_the_cpu_budget_is_read_between_the_blocks_of_one_entry(tmp_path):
    data = bytes(range(256)) * 20                              # 5 blocks of 1024 bytes
    files = [{"name": "big.dat", "data": data, "method": 1, "codec": "zlib"}, README]
    pak = build_pak(files, version=5)
    asked = []

    def stop_at(limit):
        def stop():
            asked.append(len(asked))
            return len(asked) > limit
        return stop

    # never spent: once per entry, once per block of big.dat, once before the literal pool
    whole = up.read_pak(pak, stop=stop_at(1000))
    assert {e["name"]: e["extract_status"] for e in whole["entries"]} == {"big.dat": "ok", "readme.txt": "ok"}
    assert entries_of(whole)["big.dat"]["block_count"] == 5 and len(asked) == 1 + 5 + 1 + 1

    # spent at the fourth reading: before big.dat's third block, not after its last
    asked.clear()
    cut = up.read_pak(pak, stop=stop_at(3))
    assert {e["name"]: e["extract_status"] for e in cut["entries"]} == {
        "big.dat": "skipped: CPU budget spent", "readme.txt": "skipped: CPU budget spent"}
    assert len(asked) == 4 and cut["flags"] == [] and cut["literal_pool"] is None
    assert "the archive's literal pool was not read: CPU budget spent" in cut["notes"]
    assert cut["extract_statuses"] == {"skipped": 2}

    # through the survey's own budget.  Clock readings: 0 at the start, 1 when Game.pak is reached,
    # 2 at its first entry, 3 at that entry's first block, 4 at its second: spent there with 3.5
    root = handout(tmp_path, files, version=5)
    report = up.survey(root, budget=3.5, clock=StepClock())
    (archive,) = report["archives"]
    assert {e["extract_status"] for e in archive["entries"]} == {"skipped: CPU budget spent"}
    assert report["budget"]["spent"] is True
    assert up.survey(root, budget=1000, clock=StepClock())["archives"][0]["extract_statuses"] == {"ok": 2}


def test_stored_entry_sizes_that_disagree():
    # a stored size below the uncompressed size: reading on would take the next entry's bytes
    lying = {"name": "lying.bin", "data": b"abc", "declared_usize": 9}
    # a stored size far above it (48 MiB that are not there): only the uncompressed size is read
    fat = {"name": "fat.bin", "data": b"0123456789", "declared_csize": 48 << 20}
    payloads = {}
    report = up.read_pak(build_pak([lying, fat, README], version=5),
                         sink=lambda name, payload: payloads.__setitem__(name, payload))
    entries = entries_of(report)
    assert entries["lying.bin"]["compressed_size"] == 3 and entries["lying.bin"]["uncompressed_size"] == 9
    assert entries["lying.bin"]["extract_status"] == "truncated: stored data is shorter than its declared size"
    assert entries["fat.bin"]["compressed_size"] == 48 << 20
    assert entries["fat.bin"]["extract_status"] == "ok"
    assert payloads == {"fat.bin": b"0123456789", "readme.txt": README["data"]}
    # the uncompressed size itself running past the archive is still truncated
    past = {"name": "past.bin", "data": b"xy", "declared_usize": 1 << 20, "declared_csize": 1 << 20}
    assert entries_of(up.read_pak(build_pak([past], version=5)))["past.bin"]["extract_status"] == (
        "truncated: stored data is shorter than its declared size")


def test_entry_pointing_outside_the_archive_is_truncated_not_a_crash():
    body = bytearray()
    record = store(body, 5, {"name": "x", "data": b"q" * 64, "method": 1, "codec": "zlib"})
    record = record.replace(struct.pack("<Q", 0), struct.pack("<Q", 1 << 40), 1)     # the offset field
    index = fstr("../") + struct.pack("<I", 1) + fstr("far.bin") + record
    pak = bytes(body) + index + footer(5, len(body), len(index), hashlib.sha1(index).digest())
    entry = entries_of(up.read_pak(pak))["far.bin"]
    assert entry["extract_status"].startswith(("truncated", "error: truncated"))


# --------------------------------------------------------------------------- AES
@needs_aes
def test_encrypted_index_is_blocked_without_a_key_and_read_with_it():
    secret = {"name": "Secret/flag.txt", "data": b"CSCTF{behind_the_index}", "method": 1, "codec": "zlib"}
    pak = build_pak([secret], version=7, encrypt_index=True)
    locked = up.read_pak(pak)
    assert locked["index_encrypted"] is True and locked["entries"] == [] and locked["mount_point"] is None
    assert locked["index_status"] == ("blocked: AES-encrypted index; supply the AES-256 key to read the "
                                      "file names")
    assert locked["index_sha1_match"] is None and locked["flags"] == []

    opened = up.read_pak(pak, aes_key=KEY)
    assert opened["index_status"] == "ok: index decrypted" and opened["index_sha1_match"] is True
    assert list(entries_of(opened)) == ["Secret/flag.txt"] and flags_of(opened) == {"CSCTF{behind_the_index}"}

    wrong = up.read_pak(pak, aes_key=bytes(32))
    assert wrong["index_status"].startswith("blocked: wrong AES key") and wrong["entries"] == []


@needs_aes
def test_encrypted_entries_stored_and_compressed():
    data = b"CSCTF{encrypted_blocks}" + b"z" * 3000
    pak = build_pak([{"name": "plain.txt", "data": b"CSCTF{enc_stored}!", "encrypted": True},
                     {"name": "packed.bin", "data": data, "method": 1, "codec": "zlib", "encrypted": True}],
                    version=7)
    locked = entries_of(up.read_pak(pak))
    assert locked["plain.txt"]["encrypted"] is True
    assert {e["extract_status"] for e in locked.values()} == {
        "blocked: AES-encrypted entry; supply the AES-256 key"}
    payloads = {}
    opened = up.read_pak(pak, aes_key=KEY, sink=lambda n, p: payloads.__setitem__(n, p))
    assert payloads == {"plain.txt": b"CSCTF{enc_stored}!", "packed.bin": data}
    assert flags_of(opened) == {"CSCTF{enc_stored}", "CSCTF{encrypted_blocks}"}


@needs_aes
def test_an_index_marked_encrypted_that_is_not_whole_aes_blocks_is_named():
    pak = bytearray(build_pak([README], version=7))
    report = up.read_pak(bytes(pak))
    assert report["index_size"] % 16 != 0                      # the fixture's index is not block-aligned
    pak[report["magic_offset"] - 1] = 1                         # the footer now claims an encrypted index
    broken = up.read_pak(bytes(pak), aes_key=KEY)
    assert broken["index_status"] == ("blocked: the index did not decrypt (encrypted region is not a "
                                      "multiple of the AES block size)")
    assert broken["entries"] == [] and broken["index_sha1_match"] is None


def test_parse_key_forms():
    assert up.parse_key(KEY.hex()) == KEY and up.parse_key("0x" + KEY.hex().upper()) == KEY
    assert up.parse_key(base64.b64encode(KEY).decode()) == KEY
    for bad in ("", "abcd", "zz" * 32, base64.b64encode(b"short").decode()):
        with pytest.raises(up.UnrealPakError, match="AES key"):
            up.parse_key(bad)


# --------------------------------------------------------------------------- the version 10+ index
def test_path_hash_index_names_entries_through_the_directory_index():
    big = b"CSCTF{v11_blocks}" + bytes(range(256)) * 20
    files = [
        {"name": "Game/Config/DefaultGame.ini", "data": b"[/Script/Abyss.Net]\nServerUrl=https://abyss.example/v1\n"},
        {"name": "Game/Content/one.bin", "data": b"CSCTF{v11_single_block}" * 4, "codec": "zlib"},
        {"name": "Game/Content/many.bin", "data": big, "codec": "zlib", "block_size": 2048},
        {"name": "Engine/wide.bin", "data": b"wide fields", "wide": True},
        {"name": "Engine/odd.bin", "data": b"odd block size " * 20, "codec": "zlib", "block_size": 3000, "wide": True},
        {"name": "Engine/blocks.bin", "data": bytes(range(256)) * 2400, "codec": "zlib", "block_size": 2048},
        {"name": "top.txt", "data": b"a file in the archive root"},
        {"name": "Mixed/offset64.bin", "data": b"only the offset is 64-bit " * 9, "codec": "zlib", "wide": {"offset"}},
        {"name": "Mixed/usize64.bin", "data": b"only the size is 64-bit", "wide": {"usize"}},
        {"name": "Mixed/csize64.bin", "data": b"only the stored size is 64-bit " * 9, "codec": "zlib",
         "wide": {"csize"}},
    ]
    payloads = {}
    report = up.read_pak(build_pak_v11(files), sink=lambda n, p: payloads.__setitem__(n, p))
    assert report["version"] == 11 and report["footer_location"] == "fixed" and report["index_status"] == "ok"
    assert report["mount_point"] == "../../../" and report["notes"] == []
    assert {name: payloads[name] for name in payloads} == {spec["name"]: spec["data"] for spec in files}
    entries = entries_of(report)
    assert entries["Game/Content/many.bin"]["block_count"] == 3
    assert entries["Engine/blocks.bin"]["block_count"] == 300        # a 16-bit count
    assert "top.txt" in entries                                       # the root folder is "/", not a name
    assert entries["Game/Content/many.bin"]["block_size"] == 2048
    assert entries["Engine/odd.bin"]["block_size"] == 3000           # the 0x3f escape: an explicit size
    assert entries["Game/Content/one.bin"]["compression"] == "zlib"
    assert flags_of(report) == {"CSCTF{v11_single_block}", "CSCTF{v11_blocks}"}
    assert report["configs"] == [{"name": "Game/Config/DefaultGame.ini", "urls": ["https://abyss.example/v1"],
                                  "lines": ["ServerUrl=https://abyss.example/v1"]}]


def test_directory_values_that_are_negative_deleted_or_out_of_range():
    plain = [{"name": "Game/plain.txt", "data": b"CSCTF{non_encoded_entry}", "method": 1, "codec": "zlib"}]
    pak = build_pak_v11([{"name": "Game/a.txt", "data": b"a"}], plain_entries=plain,
                        extra_directory=[("Game/pruned.txt", -(1 << 31)), ("Game/lost.txt", -7),
                                         ("Game/bad.txt", 9999)])
    report = up.read_pak(pak)
    entries = entries_of(report)
    assert set(entries) == {"Game/a.txt", "Game/plain.txt"}
    assert entries["Game/plain.txt"]["extract_status"] == "ok"
    assert flags_of(report) == {"CSCTF{non_encoded_entry}"}
    notes = "\n".join(report["notes"])
    assert "Game/pruned.txt: directory entry is the deleted sentinel" in notes
    assert "Game/lost.txt: directory entry points past the non-encoded entries" in notes
    assert "Game/bad.txt: encoded entry not read" in notes


def test_without_a_directory_index_entries_are_named_by_path_hash_or_not_at_all():
    files = [{"name": "Game/a.txt", "data": b"CSCTF{hash_named}"}]
    hashed = up.read_pak(build_pak_v11(files, directory=False, path_hash=True))
    assert list(entries_of(hashed)) == ["<path hash 0x0000000000001000>"]
    assert any("named by path hash" in note for note in hashed["notes"])
    assert entries_of(hashed)["<path hash 0x0000000000001000>"]["flags"] == ["CSCTF{hash_named}"]
    bare = up.read_pak(build_pak_v11(files, directory=False))
    assert bare["entries"] == [] and any("no entry can be located" in note for note in bare["notes"])


@needs_aes
def test_encrypted_path_hash_index_decrypts_its_directory_index_too():
    pak = build_pak_v11([{"name": "Game/s.txt", "data": b"CSCTF{v11_encrypted_index}", "codec": "zlib"}],
                        encrypt_index=True, path_hash=True)
    assert up.read_pak(pak)["index_status"].startswith("blocked: AES-encrypted index")
    opened = up.read_pak(pak, aes_key=KEY)
    assert list(entries_of(opened)) == ["Game/s.txt"] and flags_of(opened) == {"CSCTF{v11_encrypted_index}"}


@needs_aes
def test_encrypted_entries_in_a_path_hash_archive():
    big = b"CSCTF{v11_encrypted_blocks}" + bytes(range(256)) * 20
    files = [{"name": "Game/many.bin", "data": big, "codec": "zlib", "block_size": 2048, "encrypted": True},
             {"name": "Game/one.bin", "data": b"CSCTF{v11_encrypted_one_block}" * 2, "codec": "zlib",
              "encrypted": True},
             {"name": "Game/stored.txt", "data": b"stored and encrypted", "encrypted": True}]
    pak = build_pak_v11(files)
    locked = entries_of(up.read_pak(pak))
    assert all(e["encrypted"] and e["extract_status"].startswith("blocked: AES-encrypted entry")
               for e in locked.values()) and len(locked) == 3
    assert locked["Game/many.bin"]["block_count"] == 3 and locked["Game/one.bin"]["block_count"] == 1
    payloads = {}
    opened = up.read_pak(pak, aes_key=KEY, sink=lambda n, p: payloads.__setitem__(n, p))
    assert payloads == {spec["name"]: spec["data"] for spec in files}
    assert flags_of(opened) == {"CSCTF{v11_encrypted_blocks}", "CSCTF{v11_encrypted_one_block}"}


def test_unsupported_slot_in_an_encoded_entry_is_named():
    pak = build_pak_v11([{"name": "Game/o.bin", "data": b"o" * 50, "codec": "zlib", "method": 2}],
                        names=("Zlib", "Oodle"))
    entry = entries_of(up.read_pak(pak))["Game/o.bin"]
    assert entry["compression"] == "oodle" and entry["extract_status"].startswith("unsupported: oodle")


# --------------------------------------------------------------------------- literal pool
def u16(text: str) -> bytes:
    return text.encode("utf-16-le")


def game_binary() -> bytes:
    """A stand-in for a game module: engine and game /Script/ names, protocol literals, noise."""
    return (b"MZ" + bytes(range(256)) * 2
            + u16("/Script/Engine") + b"\x00\x00" + u16("/Script/CoreUObject") + b"\x00\x00"
            + bytes(200)
            + u16("/v1/session") + b"\x00\x00" + u16("/v1/step") + b"\x00\x00" + u16("guard") + b"\x00\x00"
            + u16("/usr/lib/libssl.so") + b"\x00\x00" + u16("X-Abyss-Token") + b"\x00\x00"
            + u16("/Script/AbyssGame") + b"\x00\x00" + u16("/Script/AbyssGame.DiverPawn") + b"\x00\x00"
            + u16("https://abyss.example:8443/api") + b"\x00\x00"
            + b"\x01\x02ascii url http://plain.example/x.\x00"
            + u16("spooky{utf16_literal}") + b"\x00\x00" + b"\xff" * 64)


def test_literal_pool_of_a_game_module():
    pool = up.literal_pool(game_binary(), profile=event.load("spooky"))
    assert [(hit["flag"], hit["encoding"]) for hit in pool["flags"]] == [("spooky{utf16_literal}", "utf-16-le")]
    assert game_binary()[pool["flags"][0]["offset"]:][:12] == u16("spooky")
    assert {row["url"]: row["encoding"] for row in pool["urls"]} == {
        "https://abyss.example:8443/api": "utf-16-le", "http://plain.example/x": "ascii"}
    assert pool["script_modules"] == [{"module": "AbyssGame", "count": 2}, {"module": "CoreUObject", "count": 1},
                                      {"module": "Engine", "count": 1}]
    assert pool["game_modules"] == ["AbyssGame"]                  # the engine's own modules are not the game
    near = [row["text"] for row in pool["module_literals"]]
    assert {"/v1/session", "/v1/step", "guard", "X-Abyss-Token"} <= set(near)
    assert len(near) == len(set(near))        # the module name is there twice: each literal is listed once
    assert all(row["module"] == "AbyssGame" and row["encoding"] == "utf-16-le" for row in pool["module_literals"])
    assert pool["endpoints"] == ["/v1/session", "/v1/step"]       # a file system path is not a route
    assert pool["flag_scan_truncated"] is False and "strings" not in pool


def test_literal_pool_window_is_bounded(monkeypatch):
    monkeypatch.setattr(up, "LITERAL_WINDOW", 64)
    data = u16("far-away-literal") + bytes(400) + u16("near") + b"\x00\x00" + u16("/Script/TinyGame") + bytes(400)
    texts = [row["text"] for row in up.literal_pool(data)["module_literals"]]
    assert "near" in texts and "far-away-literal" not in texts


def test_flag_hits_ascii_utf16_case_and_overlap():
    ff = up.flagfmt.current()                                    # csctf: prefix-insensitive, loose body
    data = b"\x00junk csctf{lower_prefix} \x01" + u16("CSCTF{wide}") + b"\x00\x00 CSCTF{has_CTF{inside}"
    hits, truncated = up.flag_hits(data, ff)
    assert [(h["flag"], h["encoding"]) for h in hits] == [
        ("csctf{lower_prefix}", "ascii"), ("CSCTF{wide}", "utf-16-le"), ("CSCTF{has_CTF{inside}", "ascii")]
    assert truncated is False
    assert data[hits[0]["offset"]:hits[0]["offset"] + 6] == b"csctf{"
    assert data[hits[1]["offset"]:hits[1]["offset"] + 4] == u16("CS")


def test_flag_hits_drop_a_match_across_binary_and_keep_the_flag_inside_it():
    ff = up.flagfmt.current()
    data = b"flag{\x00\x07\x1b binary CSCTF{real_after_junk} tail"
    hits, _ = up.flag_hits(data, ff)
    assert [h["flag"] for h in hits] == ["CSCTF{real_after_junk}"]


def test_flag_hits_with_no_known_prefix_use_the_bounded_whole_buffer_scan(monkeypatch):
    profile = event.parse({
        "slug": "anyprefix", "name": "any", "dates": {"start": dt.date(2026, 1, 1), "end": dt.date(2026, 1, 2)},
        "platform": {"kind": "ctfd", "base_url": "https://board.ctf.example"}, "flag": {"prefixes": []},
        "rules": {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed",
                  "live_service_scope": []}}, src="<test>")
    ff = up.flagfmt.for_profile(profile)
    data = b"\x00 zeta{ascii_one} \x00" + u16("omega{wide_one}") + b"\x00\x00"
    hits, truncated = up.flag_hits(data, ff)
    assert {(h["flag"], h["encoding"]) for h in hits} == {("zeta{ascii_one}", "ascii"), ("omega{wide_one}", "utf-16-le")}
    assert truncated is False
    monkeypatch.setattr(up, "MAX_SLOW_SCAN", 8)
    assert up.flag_hits(data, ff) == ([], True)                  # cut short, and it says so


def test_find_all_reads_in_steps_without_missing_or_doubling_a_hit(monkeypatch):
    monkeypatch.setattr(up, "_FIND_STEP", 16)
    data = b"." * 14 + b"NEEDLE" + b"." * 13 + b"NEEDLE" + b"." * 3 + b"needle"
    # 14 straddles the first step's edge (16); 33 straddles the next one (32)
    assert up._find_all(data, b"NEEDLE", 100) == [14, 33]
    assert up._find_all(data, b"needle", 100, True) == [14, 33, 42]
    assert up._find_all(data, b"NEEDLE", 1) == [14]


def test_literal_pool_strings_option():
    pool = up.literal_pool(b"\x01abcd\x01\x01" + u16("wxyz") + b"\x01\x01", strings=True)
    assert {(row["text"], row["encoding"]) for row in pool["strings"]} == {("abcd", "ascii"), ("wxyz", "utf-16-le")}


# --------------------------------------------------------------------------- files, unpack, survey
def test_read_pak_file_maps_the_file_and_names_bad_files(tmp_path):
    path = tmp_path / "game.pak"
    path.write_bytes(build_pak([README], version=7))
    assert flags_of(up.read_pak_file(path)) == {"CSCTF{stored_entry}"}
    (tmp_path / "empty.pak").write_bytes(b"")
    with pytest.raises(up.UnrealPakError, match="is empty"):
        up.read_pak_file(tmp_path / "empty.pak")
    (tmp_path / "link.pak").symlink_to(path)
    with pytest.raises(up.UnrealPakError, match="symlink"):
        up.read_pak_file(tmp_path / "link.pak")
    with pytest.raises(up.UnrealPakError, match="could not read"):
        up.read_pak_file(tmp_path / "absent.pak")


def test_unpack_writes_inside_the_destination_only(tmp_path):
    files = [{"name": "Game/Config/a.ini", "data": b"alpha"},
             {"name": "../escape.txt", "data": b"no"}, {"name": "/abs.txt", "data": b"fine"},
             {"name": "C:\\drive.txt", "data": b"no"}, {"name": "Game/Config/a.ini", "data": b"second copy"},
             {"name": "Linked/x.txt", "data": b"no"}, {"name": "Linked/sub/deeper/y.txt", "data": b"no"},
             {"name": "abs.txt/under.txt", "data": b"no"},
             {"name": "big.bin", "data": bytes(range(256)) * 12, "method": 1, "codec": "zlib"}]
    path = tmp_path / "t.pak"
    path.write_bytes(build_pak(files, version=5))
    dest = tmp_path / "out"
    dest.mkdir()
    (tmp_path / "elsewhere").mkdir()
    (dest / "Linked").symlink_to(tmp_path / "elsewhere")
    report = up.unpack(path, dest)
    assert sorted(report["written"]) == ["Game/Config/a.ini", "abs.txt", "big.bin"]
    assert (dest / "Game" / "Config" / "a.ini").read_bytes() == b"alpha"          # the first one wins
    assert (dest / "abs.txt").read_bytes() == b"fine"                              # a leading slash is dropped
    assert (dest / "big.bin").read_bytes() == bytes(range(256)) * 12
    why = {row["name"]: row["why"] for row in report["not_written"]}
    assert "unsafe entry name" in why["../escape.txt"] and "unsafe entry name" in why["C:\\drive.txt"]
    assert why["Game/Config/a.ini"] == "target already exists"
    assert "leaves the destination" in why["Linked/x.txt"]
    # a name that goes on below the symlinked folder is refused before any folder is made behind it
    assert "leaves the destination" in why["Linked/sub/deeper/y.txt"]
    assert why["abs.txt/under.txt"] == "a file is in the way of the target folder"
    assert not (tmp_path / "escape.txt").exists() and list((tmp_path / "elsewhere").iterdir()) == []
    assert (dest / "abs.txt").is_file()


def handout(tmp_path, pak_files=None, **pak_kwargs) -> Path:
    root = tmp_path / "challenge"
    (root / "files").mkdir(parents=True)
    if pak_files is not None:
        (root / "files" / "Game.pak").write_bytes(build_pak(pak_files, **pak_kwargs))
    return root


def test_survey_reads_archives_and_unreal_binaries_once(tmp_path):
    root = handout(tmp_path, [README])
    (root / "files" / "Abyss.exe").write_bytes(game_binary())
    (root / "files" / "plain.exe").write_bytes(b"MZ" + b"no unreal strings here " * 10)
    (root / "files" / "AbyssServer").write_bytes(b"\x7fELF" + game_binary()[2:])
    (root / "files" / "README").write_text("CSCTF{a_text_file_is_not_a_binary}")
    (root / "files" / "Link.pak").symlink_to(root / "files" / "Game.pak")
    (root / "files" / "notes.txt").write_text("CSCTF{not_an_unreal_file}")
    (root / "unpacked").mkdir()
    (root / "unpacked" / "Game.pak").write_bytes((root / "files" / "Game.pak").read_bytes())
    (root / ".ctf").mkdir()
    (root / ".ctf" / "Secret.pak").write_bytes(build_pak([{"name": "t", "data": b"CSCTF{never_read}"}]))
    report = up.survey(root, profile=event.load("csctf"))
    assert [a["file"] for a in report["archives"]] == ["files/Game.pak"]
    # plain.exe has no /Script/ name in it; README is not an executable
    assert [p["file"] for p in report["literal_pools"]] == ["files/Abyss.exe", "files/AbyssServer"]
    assert {"what": "unpacked/Game.pak", "why": "same content as files/Game.pak"} in report["skipped"]
    assert report["files"] == 5                              # .ctf never entered, the symlink not taken


ASSET_TAG = b"\xc1\x83\x2a\x9e"                      # the package tag a cooked asset starts with


def test_cooked_assets_are_read_through_the_literal_pool(tmp_path):
    root = handout(tmp_path / "a")
    files = root / "files"
    (files / "Level.umap").write_bytes(ASSET_TAG + bytes(64) + u16("CSCTF{in_a_cooked_map}") + b"\x00\x00")
    (files / "Menu.uasset").write_bytes(ASSET_TAG + bytes(32) + u16("https://api.abyss.example/login") + b"\x00\x00")
    (files / "Empty.uasset").write_bytes(ASSET_TAG + bytes(64))
    report = up.survey(root)
    assert report["files"] == 3 and report["literal_pools_read"] == 3 and report["iostore"] == []
    assert [pool["file"] for pool in report["literal_pools"]] == ["files/Level.umap", "files/Menu.uasset"]
    level, menu = report["literal_pools"]
    assert [(hit["flag"], hit["encoding"]) for hit in level["flags"]] == [("CSCTF{in_a_cooked_map}", "utf-16-le")]
    assert [row["url"] for row in menu["urls"]] == ["https://api.abyss.example/login"] and menu["flags"] == []
    result = up.solve(root)
    assert result.status == "solved" and result.flags == ("CSCTF{in_a_cooked_map}",)
    assert result.evidence[0].path == "files/Level.umap" and "utf-16-le" in result.evidence[0].detail

    # an asset that holds only a URL is a lead; the same bytes in an executable are not kept
    only_url = handout(tmp_path / "b")
    (only_url / "files" / "Menu.uasset").write_bytes((files / "Menu.uasset").read_bytes())
    lead = up.solve(only_url)
    assert lead.status == "unsure" and lead.flags == ()
    assert [(e.kind, e.path) for e in lead.evidence] == [("url", "files/Menu.uasset")]
    assert "https://api.abyss.example/login" in lead.evidence[0].detail
    exe_only = handout(tmp_path / "c")
    (exe_only / "files" / "tool.exe").write_bytes(b"MZ" + (files / "Menu.uasset").read_bytes())
    assert up.survey(exe_only)["literal_pools"] == []

    # a single asset file is surveyed as an asset too
    assert [pool["file"] for pool in up.survey(files / "Menu.uasset")["literal_pools"]] == ["Menu.uasset"]

    # assets that hold nothing: "none", and it does not claim there was no Unreal file
    empty = handout(tmp_path / "d")
    (empty / "files" / "Empty.uasset").write_bytes(ASSET_TAG + bytes(64))
    nothing = up.solve(empty)
    assert nothing.status == "none" and "no Unreal archive" not in nothing.notes
    assert "1 candidate file(s)" in nothing.notes and "1 read through the literal pool" in nothing.notes


def test_iostore_containers_are_named_when_met(tmp_path, capsys):
    why = "IoStore container: not decoded by this reader, literal pool only"
    root = handout(tmp_path / "a")
    (root / "files" / "Game.utoc").write_bytes(b"-==--==--==--==-" + bytes(128))
    (root / "files" / "Game.ucas").write_bytes(bytes(range(256)) * 4)
    report = up.survey(root)
    assert report["iostore"] == ["files/Game.ucas", "files/Game.utoc"] and report["literal_pools_read"] == 2
    assert [row for row in report["skipped"]] == [{"what": "files/Game.ucas", "why": why},
                                                  {"what": "files/Game.utoc", "why": why}]
    blocked = up.solve(root)
    assert blocked.status == "blocked" and blocked.flags == ()
    assert "IoStore container(s) files/Game.ucas, files/Game.utoc" in blocked.notes
    assert "not decoded by this reader" in blocked.notes and "reads .utoc/.ucas" in blocked.notes
    assert "no Unreal archive" not in blocked.notes and "aes_key" not in blocked.notes

    # a flag in the container's literal pool is still found, and the container is still named
    found = handout(tmp_path / "b")
    (found / "files" / "Game.ucas").write_bytes(bytes(64) + u16("CSCTF{in_the_container_bytes}") + bytes(64))
    solved = up.solve(found)
    assert solved.status == "solved" and solved.flags == ("CSCTF{in_the_container_bytes}",)
    assert "IoStore container(s) files/Game.ucas" in solved.notes

    # beside a readable pak the pak's result stands, with the container named in the notes
    both = handout(tmp_path / "c", [README])
    (both / "files" / "Game.utoc").write_bytes(b"-==--==--==--==-" + bytes(128))
    mixed = up.solve(both)
    assert mixed.status == "solved" and "IoStore container(s) files/Game.utoc" in mixed.notes

    assert up.main([str(root / "files" / "Game.utoc"), "--compact"]) == 1
    captured = capsys.readouterr()
    assert why in captured.err and json.loads(captured.out)["note"] == why


def test_flag_hits_past_the_cap_are_counted_and_said(tmp_path):
    data = b" ".join(b"CSCTF{decoy_%03d}" % n for n in range(300)) + b" CSCTF{the_real_one}"
    cut = "45 flag hit(s) past the cap of 256 were not kept"
    pool = up.literal_pool(data)
    assert len(pool["flags"]) == up.MAX_FLAGS == 256 and "CSCTF{the_real_one}" not in {h["flag"] for h in pool["flags"]}
    assert pool["flag_scan_truncated"] is True and pool["flag_scan_cuts"] == [cut]
    assert up.flag_hits(data, up.flagfmt.current())[1] is True
    whole = up.literal_pool(data[:1000])
    assert whole["flag_scan_truncated"] is False and whole["flag_scan_cuts"] == []

    root = handout(tmp_path / "a", [{"name": "many.txt", "data": data}])
    (root / "files" / "Tool.exe").write_bytes(b"MZ\x00\x00" + data)
    report = up.survey(root)
    (archive,) = report["archives"]
    assert archive["flag_scan_truncated"] is True and archive["entries"][0]["flag_scan_cuts"] == [cut]
    assert archive["flag_scan_cuts"] == [f"flag scan of the archive bytes cut short: {cut}",
                                         f"flag scan cut short in 1 entry(ies), first many.txt: {cut}"]
    assert all(note in archive["notes"] for note in archive["flag_scan_cuts"])
    notes = up.solve(root).notes
    assert f"files/Game.pak: flag scan cut short in 1 entry(ies), first many.txt: {cut}" in notes
    assert f"files/Tool.exe: flag scan cut short: {cut}" in notes


def test_distinct_flags_past_the_archive_cap_are_counted(monkeypatch):
    monkeypatch.setattr(up, "MAX_FLAGS", 2)
    files = [{"name": f"f{n}.txt", "data": b"CSCTF{entry_%d}" % n, "method": 1, "codec": "zlib"} for n in range(3)]
    report = up.read_pak(build_pak(files, version=5))
    assert flags_of(report) == {"CSCTF{entry_0}", "CSCTF{entry_1}"} and report["flags_dropped"] == 1
    assert report["flag_scan_cuts"] == ["1 flag hit(s) past the cap of 2 distinct flags were not kept"]
    assert report["flag_scan_truncated"] is True
    monkeypatch.setattr(up, "MAX_FLAGS", 3)
    whole = up.read_pak(build_pak(files, version=5))
    assert len(whole["flags"]) == 3 and whole["flags_dropped"] == 0 and whole["flag_scan_cuts"] == []


def test_a_flag_lead_found_too_many_times_is_said(monkeypatch):
    monkeypatch.setattr(up, "MAX_NEEDLE_HITS", 2)
    hits, cuts = up.flag_scan(b"CSCTF{a} CSCTF{b} CSCTF{c}", up.flagfmt.current())
    assert [hit["flag"] for hit in hits] == ["CSCTF{a}", "CSCTF{b}"]
    assert len(cuts) == 1 and "csctf{" in cuts[0] and "(ascii) occurs 2 times or more" in cuts[0]
    assert up.flag_scan(b"CSCTF{only}", up.flagfmt.current()) == (
        [{"flag": "CSCTF{only}", "offset": 0, "encoding": "ascii"}], [])


def test_lead_lists_that_a_cap_cut_are_said(tmp_path, monkeypatch):
    extra = b"\x00".join(b"http://h%d.example/x" % n for n in range(3))
    data = game_binary() + b"\x00" + extra + b"\x00" + u16("/Script/OtherGame") + b"\x00\x00"
    whole = up.literal_pool(data)
    assert whole["list_cuts"] == [] and len(whole["urls"]) == 5 and len(whole["module_literals"]) > 3
    assert whole["game_modules"] == ["AbyssGame", "OtherGame"]

    monkeypatch.setattr(up, "MAX_URLS", 2)
    capped = up.literal_pool(data)
    assert len(capped["urls"]) == 2 and capped["list_cuts"] == ["3 more URL(s) past the cap of 2 were not kept"]
    monkeypatch.setattr(up, "MAX_URLS", 500)

    monkeypatch.setattr(up, "MAX_MODULE_LITERALS", 3)
    capped = up.literal_pool(data)
    assert len(capped["module_literals"]) == 3
    assert capped["list_cuts"] == ["more than 3 literals sit next to the game module names: the nearest "
                                   "are listed"]
    monkeypatch.setattr(up, "MAX_MODULE_LITERALS", len(whole["module_literals"]))
    assert up.literal_pool(data)["list_cuts"] == []              # exactly at the cap: nothing was cut
    monkeypatch.setattr(up, "MAX_MODULE_LITERALS", 300)

    monkeypatch.setattr(up, "MAX_GAME_MODULES", 1)
    capped = up.literal_pool(data)
    assert capped["list_cuts"] == ["literals are listed for the first 1 of 2 game modules"]
    assert {row["module"] for row in capped["module_literals"]} == {"AbyssGame"}
    monkeypatch.setattr(up, "MAX_GAME_MODULES", 4)

    monkeypatch.setattr(up, "MAX_NEEDLE_HITS", 1)
    capped = up.literal_pool(data)
    assert "'://' (ascii) occurs 1 times or more: later URLs were not looked at" in capped["list_cuts"]
    assert "'/Script/' (utf-16-le) occurs 1 times or more: later module names were not looked at" in capped["list_cuts"]
    assert [row["url"] for row in capped["urls"] if row["encoding"] == "ascii"] == ["http://plain.example/x"]
    root = handout(tmp_path)
    (root / "files" / "Abyss.exe").write_bytes(data)
    assert "files/Abyss.exe: '://' (ascii) occurs 1 times or more" in up.solve(root).notes


def test_config_harvest_caps_are_said(tmp_path, monkeypatch):
    ini = b"".join(b"Server%d=https://s%d.example/api\n" % (n, n) for n in range(4))
    files = [{"name": "Config/A.ini", "data": ini}, {"name": "Config/B.ini", "data": b"Host=10.0.0.9\n"},
             {"name": "Config/C.ini", "data": b"Port=7777\n"}]
    whole = up.read_pak(build_pak(files))
    assert [c["name"] for c in whole["configs"]] == ["Config/A.ini", "Config/B.ini", "Config/C.ini"]
    assert whole["config_cuts"] == [] and len(whole["configs"][0]["lines"]) == 4

    monkeypatch.setattr(up, "MAX_CONFIG_LINES", 3)
    monkeypatch.setattr(up, "MAX_URLS", 2)
    monkeypatch.setattr(up, "MAX_CONFIGS", 2)
    report = up.read_pak(build_pak(files))
    assert [c["name"] for c in report["configs"]] == ["Config/A.ini", "Config/B.ini"]
    assert len(report["configs"][0]["lines"]) == 3 and len(report["configs"][0]["urls"]) == 2
    assert report["config_cuts"] == [
        "Config/A.ini: 1 more URL or setting line(s) past the cap of 3 were not kept",
        "Config/A.ini: 2 more URL(s) past the cap of 2 were not kept",
        "1 more config file(s) past the cap of 2 were not searched for URLs and settings"]
    assert all(cut in report["notes"] for cut in report["config_cuts"])
    root = handout(tmp_path, files)
    notes = up.solve(root).notes
    assert "files/Game.pak: Config/A.ini: 1 more URL or setting line(s) past the cap of 3" in notes
    assert "files/Game.pak: 1 more config file(s) past the cap of 2" in notes


def test_size_and_count_caps_of_the_reader_are_named(tmp_path, monkeypatch):
    blocks = {"name": "four.bin", "data": bytes(range(256)) * 16, "method": 1, "codec": "zlib"}   # 4 blocks
    pak = build_pak([blocks, README], version=5)
    assert entries_of(up.read_pak(pak))["four.bin"]["block_count"] == 4
    monkeypatch.setattr(up, "MAX_BLOCKS", 3)
    capped = up.read_pak(pak)
    assert capped["index_status"] == ("error: the index did not parse (entry compression block count "
                                      "exceeds the cap)") and capped["entries"] == []
    monkeypatch.setattr(up, "MAX_BLOCKS", 65_535)

    path = tmp_path / "game.pak"
    path.write_bytes(pak)
    monkeypatch.setattr(up, "MAX_PAK_INPUT", len(pak) - 1)
    with pytest.raises(up.UnrealPakError, match="in-memory archive exceeds"):
        up.read_pak(pak)
    assert up.read_pak_file(path)["index_status"] == "ok"        # a mapped file has its own, larger cap
    monkeypatch.setattr(up, "MAX_PAK_FILE", len(pak) - 1)
    with pytest.raises(up.UnrealPakError, match=f"game.pak is larger than the {len(pak) - 1} byte cap"):
        up.read_pak_file(path)
    monkeypatch.setattr(up, "MAX_PAK_FILE", 1 << 36)

    root = handout(tmp_path / "many", [README])
    (root / "files" / "Other.pak").write_bytes(build_pak([{"name": "o.txt", "data": b"CSCTF{other_pak}"}]))
    assert len(up.survey(root)["archives"]) == 2
    monkeypatch.setattr(up, "MAX_WALK_FILES", 1)
    report = up.survey(root)
    assert [a["file"] for a in report["archives"]] == ["files/Game.pak"]
    assert {"what": "discovery", "why": "more than 1 files: the walk stopped early"} in report["skipped"]
    assert "skipped discovery: more than 1 files" in up.solve(root).notes


def test_a_file_that_cannot_be_opened_is_a_named_skip(tmp_path, monkeypatch):
    root = handout(tmp_path, [README])
    (root / "files" / "GameServer").write_bytes(b"\x7fELF" + game_binary()[2:])     # no extension
    real_open = Path.open

    def denied(self, *args, **kwargs):
        if self.name == "GameServer":
            raise PermissionError(13, "Permission denied")
        return real_open(self, *args, **kwargs)

    assert [pool["file"] for pool in up.survey(root)["literal_pools"]] == ["files/GameServer"]
    monkeypatch.setattr(Path, "open", denied)
    report = up.survey(root)
    assert report["literal_pools"] == [] and [a["file"] for a in report["archives"]] == ["files/Game.pak"]
    assert {"what": "files/GameServer", "why": "could not be opened (Permission denied): not checked for "
                                               "an Unreal executable"} in report["skipped"]
    assert "skipped files/GameServer: could not be opened" in up.solve(root).notes


def test_unreadable_files_past_the_row_cap_are_counted(tmp_path, monkeypatch):
    root = handout(tmp_path, [README])
    for number in range(25):
        (root / "files" / f"srv{number:02d}").write_bytes(b"\x7fELF" + bytes(16))      # no extension
    real_open = Path.open

    def denied(limit):
        def opener(self, *args, **kwargs):
            if self.name.startswith("srv") and int(self.name[3:]) < limit:
                raise PermissionError(13, "Permission denied")
            return real_open(self, *args, **kwargs)
        return opener

    def rows(report):
        named = [row["what"] for row in report["skipped"] if "could not be opened (" in row["why"]]
        rest = [row["why"] for row in report["skipped"] if row["what"] == "discovery"]
        return named, rest

    assert up.MAX_UNREADABLE_ROWS == 20
    monkeypatch.setattr(Path, "open", denied(25))
    named, rest = rows(up.survey(root))
    assert named == [f"files/srv{number:02d}" for number in range(20)]         # a row each, up to the cap
    assert rest == ["5 more file(s) could not be opened and were not checked"]
    monkeypatch.setattr(Path, "open", denied(20))
    named, rest = rows(up.survey(root))
    assert len(named) == 20 and rest == []                                    # exactly the cap: all named


def test_a_literal_pool_that_holds_only_a_cut_flag_scan_is_kept(tmp_path, monkeypatch):
    # an executable with flag leads that are not flags (no closing brace), no module name and no URL:
    # nothing to report, unless the scan was cut, which must not be silent
    root = handout(tmp_path)
    (root / "files" / "Tool.exe").write_bytes(b"MZ\x00\x00" + b"CSCTF{\x01 " * 5)
    quiet = up.survey(root)
    assert quiet["literal_pools"] == [] and quiet["literal_pools_read"] == 1
    assert "flag scan cut short" not in up.solve(root).notes

    monkeypatch.setattr(up, "MAX_NEEDLE_HITS", 3)
    report = up.survey(root)
    (pool,) = report["literal_pools"]
    assert pool["file"] == "files/Tool.exe" and pool["flags"] == [] and pool["script_modules"] == []
    assert len(pool["flag_scan_cuts"]) == 1 and "occurs 3 times or more" in pool["flag_scan_cuts"][0]
    result = up.solve(root)
    assert result.flags == ()
    assert "files/Tool.exe: flag scan cut short: the flag lead" in result.notes
    assert "occurs 3 times or more: later occurrences were not looked at" in result.notes


def test_solve_statuses(tmp_path):
    result = up.solve(handout(tmp_path / "a", [README]))
    assert isinstance(result, SolverResult) and result.engine == "toolkits.unreal_pak"
    assert result.status == "solved" and result.flags == ("CSCTF{stored_entry}",)
    assert result.evidence[0].kind == "match" and result.evidence[0].path == "files/Game.pak"
    assert "entry readme.txt offset 6" in result.evidence[0].detail

    two = up.solve(handout(tmp_path / "b", [README, {"name": "b.txt", "data": b"CSCTF{second}"}]))
    assert two.status == "candidate" and set(two.flags) == {"CSCTF{stored_entry}", "CSCTF{second}"}

    config = [{"name": "Config/DefaultGame.ini", "data": b"[Net]\nServerHost=10.1.2.3\nApi=https://abyss.example/v1\n"}]
    root = handout(tmp_path / "c", config)
    (root / "files" / "Abyss-Win64-Shipping.exe").write_bytes(game_binary())
    assert up.survey(root)["archives"][0]["configs"] == [{
        "name": "Config/DefaultGame.ini", "urls": ["https://abyss.example/v1"],
        "lines": ["ServerHost=10.1.2.3", "Api=https://abyss.example/v1"]}]      # a URL, and a server setting
    leads = up.solve(root)
    assert leads.status == "unsure" and leads.flags == ()
    details = {e.kind: e.detail for e in leads.evidence}
    assert "https://abyss.example/v1" in details["config"]
    assert "AbyssGame" in details["module"] and "/v1/session" in details["protocol"]
    assert "https://abyss.example:8443/api" in details["url"]
    assert up.solve(root, event.load("spooky")).flags == ("spooky{utf16_literal}",)

    none = up.solve(handout(tmp_path / "d"))
    assert none.status == "none" and "no Unreal archive" in none.notes

    not_unreal = handout(tmp_path / "e")
    (not_unreal / "files" / "quake.pak").write_bytes(b"PACK" + bytes(4096))
    result = up.solve(not_unreal)
    assert result.status == "none" and "no UnrealPak footer" in result.notes


@needs_aes
def test_solve_blocked_names_the_key_and_the_key_option_opens_it(tmp_path):
    secret = [{"name": "flag.txt", "data": b"CSCTF{needs_the_key}", "method": 1, "codec": "zlib"}]
    root = handout(tmp_path, secret, version=7, encrypt_index=True)
    blocked = up.solve(root)
    assert blocked.status == "blocked" and blocked.flags == ()
    assert "AES-encrypted index" in blocked.notes and "aes_key=0x" in blocked.notes
    opened = up.solve(root, aes_key="0x" + KEY.hex())
    assert opened.status == "solved" and opened.flags == ("CSCTF{needs_the_key}",)
    wrong = up.solve(root, aes_key=bytes(32).hex())
    assert wrong.status == "blocked" and "wrong AES key" in wrong.notes
    with pytest.raises(up.UnrealPakError, match="AES key"):
        up.solve(root, aes_key="nonsense")


def test_solve_options_and_budget(tmp_path):
    root = handout(tmp_path, [README, {"name": "b.txt", "data": b"CSCTF{second}"}])
    out = tmp_path / "report.json"
    up.solve(root, report=str(out), budget=30)
    assert json.loads(out.read_text())["archives"][0]["entry_count"] == 2
    with pytest.raises(up.UnrealPakError, match="unknown option"):
        up.solve(root, key="x")
    for bad in (0, -3, True, "9"):
        with pytest.raises(up.UnrealPakError, match="budget"):
            up.survey(root, budget=bad)

    (root / "files" / "Other.pak").write_bytes(build_pak([{"name": "o.txt", "data": b"CSCTF{other_pak}"}]))
    # readings: start 0; Game.pak reached at 1; its first entry at 2 (>= 1.5): nothing extracted after that
    report = up.survey(root, budget=1.5, clock=StepClock())
    (archive,) = report["archives"]
    assert archive["file"] == "files/Game.pak"
    assert {e["extract_status"] for e in archive["entries"]} == {"skipped: CPU budget spent"}
    assert any("literal pool was not read" in note for note in archive["notes"])
    assert report["budget"]["spent"] is True
    (row,) = [r for r in report["skipped"] if r["what"] == "budget"]
    assert "1 file(s) not reached" in row["why"] and "files/Other.pak" in row["why"]


def test_cli(tmp_path, capsys):
    path = tmp_path / "game.pak"
    path.write_bytes(build_pak([README, {"name": "z.bin", "data": b"q" * 2000, "method": 1, "codec": "zlib"}],
                               version=5))
    assert up.main([str(path), "--compact"]) == 0
    assert json.loads(capsys.readouterr().out)["kind"] == "unreal-pak"
    assert up.main([str(path), "--list"]) == 0
    listing = capsys.readouterr().out
    assert "# pak version 5, index ok" in listing and "readme.txt" in listing and "zlib" in listing
    assert "FLAG CSCTF{stored_entry}" in listing
    assert up.main([str(path), "--extract-to", str(tmp_path / "out"), "--compact"]) == 0
    assert json.loads(capsys.readouterr().out)["written"] == ["readme.txt", "z.bin"]
    assert (tmp_path / "out" / "z.bin").read_bytes() == b"q" * 2000

    binary = tmp_path / "Abyss.exe"
    binary.write_bytes(game_binary())
    assert up.main([str(binary), "--compact", "--event", "spooky"]) == 0
    assert json.loads(capsys.readouterr().out)["game_modules"] == ["AbyssGame"]
    assert up.main([str(binary), "--compact"]) == 1                # no csctf flag in it
    capsys.readouterr()
    assert up.main([str(tmp_path), "--compact"]) == 0              # a folder: the survey
    assert json.loads(capsys.readouterr().out)["kind"] == "unreal-survey"

    assert up.main([str(tmp_path / "absent.pak")]) == 2
    assert "could not read" in capsys.readouterr().err
    assert up.main([str(path), "--key", "tooshort"]) == 2
    assert "AES key" in capsys.readouterr().err
    assert up.main([str(path), "--event", "no-such-event"]) == 2
    assert "no flag format" in capsys.readouterr().err


def test_router_sends_unreal_handouts_here(tmp_path):
    ids = [hit.manifest.id for hit in router.route("reverse", "an unreal engine game with a client-side check")]
    assert "toolkits.unreal_pak" in ids
    (tmp_path / "Game-WindowsNoEditor.pak").write_bytes(build_pak([README]))
    by_file = {hit.manifest.id: hit.reason for hit in router.route("misc", "", tmp_path)}
    assert ".pak" in by_file["toolkits.unreal_pak"]
    assert os.path.basename(up.__file__) == "unreal_pak.py"
    for brief in ("a ue4 game client", "we ship an unreal game", "the uasset holds the answer",
                  "UE4 game client", "UE5", "the client was built with ue5.", "a game (UE4.27) to reverse"):
        assert "toolkits.unreal_pak" in [hit.manifest.id for hit in router.route("reverse", brief)], brief


@pytest.mark.parametrize("category,brief", [
    ("web", "the endpoint returns an unreal amount of debug output"),
    ("misc", "an unrealistic physics puzzle"),
    ("forensics", "a quake .pak with a hidden lump, described but not attached"),
    ("misc", "the queue5 worker reads value4 from the blue4 table"),
])
def test_router_does_not_offer_the_pak_reader_for_briefs_that_are_not_unreal(category, brief):
    assert "toolkits.unreal_pak" not in [hit.manifest.id for hit in router.route(category, brief)]


def test_no_event_is_said_as_such_not_as_a_bad_archive(tmp_path, capsys, monkeypatch):
    path = tmp_path / "game.pak"
    path.write_bytes(build_pak([README]))
    monkeypatch.delenv("CTF_EVENT", raising=False)
    with pytest.raises(event.EventError):
        up.read_pak(path.read_bytes())
    assert up.main([str(path)]) == 2
    assert "no flag format" in capsys.readouterr().err
    assert up.main([str(path), "--event", "csctf", "--compact"]) == 0      # naming the event is enough
