#!/usr/bin/env python3
"""solvers/toolkits/firmware_walk.py: the firmware / flash image content walker.

Offline, no Game Master request, no token. Every fixture is built byte-by-byte in this file (no
mksquashfs / mkfs.jffs2 / dtc on the box), so the generator and the reader agree and the
never-wrong boundary is what is under test.

  .venv/bin/python tests/test_firmware_image_walker.py

  squashfs    a tiny SquashFS-4.0 (gzip) image: the file list, a known file's size and its exact
              inflated content come back; a zstd image => names and sizes present, content None
  jffs2       a JFFS2 image: the file list and a known file's size; a node whose CRC is corrupted
              is dropped (fail-closed)
  dtb         a compiled flattened device tree: a property value is read as exact bytes
  uboot_env   a CRC-valid env => the variable comes back; a CRC-corrupted env => None
  contract    solve_set is never-wrong: a validated env value / file size / DTB property is PLAIN,
              a path is an unsure candidate, a flag inside a file is None

B-069 (pytest only, second half of the file): the redundant-env split and live-copy pick in
firmware_walk.py, and solvers/toolkits/firmware_sections.py (the CRC-confirmed section table, the
zlib preset-dictionary match, cpio, flags, the keyed-XOR lead, the engine, routing and intake).
"""
import struct
import sys
import zlib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))
sys.path.insert(0, str(REPO / "solvers" / "common"))
sys.dont_write_bytecode = True

import firmware_walk as fw                                  # noqa: E402

FAILED = []


def check(label, ok, detail=""):
    print(f"{'ok  ' if ok else 'FAIL'} {label}" + ("" if ok or not detail else f"  [{str(detail)[:400]}]"))
    if not ok:
        FAILED.append(label)


# ---- SquashFS 4.0 fixture ---------------------------------------------------------------------------

def make_squashfs(files, comp_id=1):
    """A minimal, valid SquashFS-4.0 image: one root directory of regular files. Metadata tables are
    stored uncompressed (legal); file data blocks are gzip (zlib) compressed for comp_id 1, or stored
    as opaque 'zstd' bytes marked compressed for comp_id 6 (which the stdlib cannot inflate)."""
    BS = 131072
    NO = 0xFFFFFFFFFFFFFFFF
    archive = bytearray(96)                                 # superblock placeholder
    file_infos = []
    ino = 1
    root_ino = ino
    ino += 1
    for name, content in sorted(files.items()):
        start = len(archive)
        block_sizes = []
        pos = 0
        while pos < len(content):
            chunk = content[pos:pos + BS]
            pos += BS
            if comp_id == 1:
                comp = zlib.compress(chunk, 9)
                if len(comp) < len(chunk):
                    archive += comp
                    block_sizes.append(len(comp))
                else:
                    archive += chunk
                    block_sizes.append(len(chunk) | 0x1000000)
            elif comp_id == 6:                              # opaque bytes, flagged compressed -> None
                fake = b"\x28\xb5\x2f\xfd" + chunk
                archive += fake
                block_sizes.append(len(fake))
            else:
                archive += chunk
                block_sizes.append(len(chunk) | 0x1000000)
        file_infos.append((ino, name, content, start, block_sizes))
        ino += 1

    inode_buf = bytearray()
    inode_pos = {}
    for (fino, name, content, start, block_sizes) in file_infos:
        inode_pos[fino] = len(inode_buf)
        common = struct.pack("<HHHHII", 2, 0o644, 0, 0, 0, fino)
        spec = struct.pack("<IIII", start, 0xFFFFFFFF, 0, len(content))
        bs = b"".join(struct.pack("<I", b) for b in block_sizes)
        inode_buf += common + spec + bs

    base_inum = file_infos[0][0]
    dir_buf = bytearray(struct.pack("<III", len(file_infos) - 1, 0, base_inum))
    for (fino, name, content, start, block_sizes) in file_infos:
        nb = name.encode()
        dir_buf += struct.pack("<HhHH", inode_pos[fino], fino - base_inum, 2, len(nb) - 1) + nb
    listing_len = len(dir_buf)

    inode_pos[root_ino] = len(inode_buf)
    common = struct.pack("<HHHHII", 1, 0o755, 0, 0, 0, root_ino)
    spec = struct.pack("<IIHHI", 0, 2, listing_len + 3, 0, root_ino)
    inode_buf += common + spec

    def meta(buf):
        return struct.pack("<H", 0x8000 | len(buf)) + bytes(buf)

    inode_table = len(archive)
    archive += meta(inode_buf)
    dir_table = len(archive)
    archive += meta(dir_buf)
    id_meta = len(archive)
    archive += meta(struct.pack("<I", 0))
    id_table = len(archive)
    archive += struct.pack("<Q", id_meta)
    bytes_used = len(archive)
    root_ref = (0 << 16) | inode_pos[root_ino]

    sb = struct.pack("<IIIIIHHHHHHQQQQQQQQ",
                     0x73717368, ino - 1, 0, BS, 0, comp_id, 17, 0, 1, 4, 0,
                     root_ref, bytes_used, id_table, NO, inode_table, dir_table, NO, NO)
    archive[0:96] = sb
    return bytes(archive)


def test_squashfs():
    content = b"HUNTRESS firmware readme\n" * 800          # repetitive => really gzip-compressed
    small = b"id=42\nmode=prod\n"
    img = make_squashfs({"readme.txt": content, "config.cfg": small}, comp_id=1)
    res = fw.walk({"rootfs.squashfs": img})
    check("squashfs: one image detected, kind=squashfs, gzip", len(res["images"]) == 1
          and res["images"][0]["kind"] == "squashfs" and res["images"][0]["compression"] == "gzip",
          res["images"])
    entries = {e["name"]: e for e in res["images"][0]["entries"]}
    check("squashfs: the file list is complete", sorted(entries) == ["config.cfg", "readme.txt"], sorted(entries))
    check("squashfs: a known file's SIZE is exact (plain-eligible)", entries["readme.txt"]["size"] == len(content),
          entries["readme.txt"]["size"])
    check("squashfs: a gzip data block inflates to the exact bytes", entries["readme.txt"]["content"] == content)
    check("squashfs: the small file round-trips too", entries["config.cfg"]["content"] == small)
    check("squashfs: paths are rooted", entries["readme.txt"]["path"] == "/readme.txt")


def test_squashfs_zstd():
    content = b"zstd-only payload " * 50
    img = make_squashfs({"blob.bin": content}, comp_id=6)
    res = fw.walk({"zrootfs.squashfs": img})
    e = {x["name"]: x for x in res["images"][0]["entries"]}
    check("squashfs/zstd: compression reported as zstd", res["images"][0]["compression"] == "zstd")
    check("squashfs/zstd: the NAME is present", "blob.bin" in e, list(e))
    check("squashfs/zstd: the SIZE is present (read from metadata)", e["blob.bin"]["size"] == len(content),
          e.get("blob.bin"))
    check("squashfs/zstd: the CONTENT is None (no stdlib codec), never a partial guess",
          e["blob.bin"]["content"] is None and "zstd" in (e["blob.bin"]["reason"] or ""), e["blob.bin"]["reason"])


# ---- JFFS2 fixture ----------------------------------------------------------------------------------

def jffs2_dirent(pino, ino, name, dtype, version):
    nb = name.encode()
    nsize = len(nb)
    totlen = 40 + nsize
    first8 = struct.pack("<HHI", 0x1985, 0xE001, totlen)
    hdr_crc = fw.jffs2_crc(first8)
    block = first8 + struct.pack("<I", hdr_crc) + struct.pack("<IIII", pino, version, ino, 0) \
        + struct.pack("<BBH", nsize, dtype, 0)
    node_crc = fw.jffs2_crc(block)
    name_crc = fw.jffs2_crc(nb)
    node = block + struct.pack("<I", node_crc) + struct.pack("<I", name_crc) + nb
    return node + b"\xff" * ((-len(node)) % 4)


def jffs2_inode(ino, content, version, offset=0, break_crc=False):
    csize = dsize = len(content)
    totlen = 68 + csize
    first8 = struct.pack("<HHI", 0x1985, 0xE002, totlen)
    hdr_crc = fw.jffs2_crc(first8)
    block = (first8 + struct.pack("<I", hdr_crc) + struct.pack("<II", ino, version)
             + struct.pack("<I", 0o100644) + struct.pack("<HH", 0, 0) + struct.pack("<I", len(content))
             + struct.pack("<III", 0, 0, 0) + struct.pack("<I", offset) + struct.pack("<II", csize, dsize)
             + struct.pack("<BBH", 0, 0, 0))
    data_crc = fw.jffs2_crc(content)
    node_crc = fw.jffs2_crc(block + struct.pack("<I", data_crc))
    if break_crc:
        node_crc ^= 0xFFFFFFFF                              # corrupt the node CRC -> must be dropped
    node = block + struct.pack("<I", data_crc) + struct.pack("<I", node_crc) + content
    return node + b"\xff" * ((-len(node)) % 4)


def make_jffs2():
    parts = []
    parts.append(jffs2_dirent(1, 2, "config.txt", 8, 1))
    parts.append(jffs2_inode(2, b"hostname=router\nmtu=1500\n", 1))
    parts.append(jffs2_dirent(1, 3, "firmware.bin", 8, 1))
    parts.append(jffs2_inode(3, b"\x00\x01\x02\x03binary payload", 1))
    # a corrupted node for a fourth file: its dirent survives but its inode CRC is bad -> no size/content.
    parts.append(jffs2_dirent(1, 4, "broken.dat", 8, 1))
    parts.append(jffs2_inode(4, b"should be dropped", 1, break_crc=True))
    return b"".join(parts), {"config.txt": b"hostname=router\nmtu=1500\n"}


def test_jffs2():
    img, known = make_jffs2()
    res = fw.walk({"rootfs.jffs2": img})
    check("jffs2: one image detected, little-endian", len(res["images"]) == 1
          and res["images"][0]["kind"] == "jffs2" and res["images"][0]["endian"] == "little")
    entries = {e["name"]: e for e in res["images"][0]["entries"]}
    check("jffs2: live files are listed", {"config.txt", "firmware.bin", "broken.dat"} <= set(entries),
          sorted(entries))
    check("jffs2: a known file's SIZE is exact", entries["config.txt"]["size"] == len(known["config.txt"]),
          entries.get("config.txt"))
    check("jffs2: a stdlib-readable (compr=none) file's content round-trips",
          entries["config.txt"]["content"] == known["config.txt"])
    check("jffs2: a node whose inode CRC is corrupt yields None size and None content (fail-closed)",
          entries["broken.dat"]["content"] is None and entries["broken.dat"]["size"] is None,
          entries.get("broken.dat"))


# ---- DTB fixture ------------------------------------------------------------------------------------

def make_dtb():
    strings = bytearray()

    def soff(s):
        key = s.encode() + b"\x00"
        idx = bytes(strings).find(key)
        if idx < 0:
            idx = len(strings)
            strings.extend(key)
        return idx

    def pad4(b):
        return b + b"\x00" * ((-len(b)) % 4)

    def begin(name):
        return struct.pack(">I", 1) + pad4(name.encode() + b"\x00")

    def prop(name, val):
        return struct.pack(">III", 3, len(val), soff(name)) + pad4(val)

    sb = bytearray()
    sb += begin("")                                         # root
    sb += prop("compatible", b"test,board\x00")
    sb += prop("#address-cells", struct.pack(">I", 1))
    sb += begin("chosen")
    sb += prop("bootargs", b"console=ttyS0,115200\x00")
    sb += struct.pack(">I", 2)                              # END_NODE chosen
    sb += struct.pack(">I", 2)                              # END_NODE root
    sb += struct.pack(">I", 9)                              # FDT_END

    off_memrsv = 40
    memrsv = struct.pack(">QQ", 0, 0)
    off_struct = off_memrsv + len(memrsv)
    size_struct = len(sb)
    off_strings = off_struct + size_struct
    size_strings = len(strings)
    totalsize = off_strings + size_strings
    header = struct.pack(">IIIIIIIIII", 0xD00DFEED, totalsize, off_struct, off_strings, off_memrsv,
                         17, 16, 0, size_strings, size_struct)
    return header + memrsv + bytes(sb) + bytes(strings)


def test_dtb():
    res = fw.walk({"board.dtb": make_dtb()})
    check("dtb: one image detected, structurally complete", len(res["images"]) == 1
          and res["images"][0]["kind"] == "dtb" and res["images"][0]["complete"], res["images"])
    props = res["images"][0]["properties"]
    check("dtb: node paths include / and /chosen", "/" in props and "/chosen" in props, list(props))
    check("dtb: a string PROPERTY value is read as exact bytes (plain-eligible)",
          props["/"]["compatible"]["text"] == "test,board", props["/"].get("compatible"))
    check("dtb: a numeric property keeps its raw cells", props["/"]["#address-cells"]["cells"] == [1],
          props["/"].get("#address-cells"))
    check("dtb: the child node's property is read too",
          props["/chosen"]["bootargs"]["text"] == "console=ttyS0,115200", props.get("/chosen"))


# ---- U-Boot environment fixture ---------------------------------------------------------------------

def make_uboot_env(size=1024, corrupt=False):
    pairs = [("bootcmd", "bootm 0x80000"), ("bootdelay", "3"),
             ("baudrate", "115200"), ("ethaddr", "00:11:22:33:44:55")]
    body = b"".join((k + "=" + v).encode() + b"\x00" for k, v in pairs) + b"\x00"
    body = body + b"\x00" * (size - 4 - len(body))
    crc = fw.crc32_std(body)
    blob = bytearray(struct.pack("<I", crc) + body)
    if corrupt:
        blob[len(blob) - 20] ^= 0xFF                        # flip a byte deep in the data area
    return bytes(blob)


def test_uboot_env():
    good = fw.walk({"uboot.env": make_uboot_env()})
    img = good["images"][0]
    check("uboot_env: detected and CRC validated", img["kind"] == "uboot_env" and img["crc_valid"] is True, img)
    check("uboot_env: a variable VALUE is read behind a good CRC", img["vars"].get("bootcmd") == "bootm 0x80000",
          img.get("vars"))
    check("uboot_env: every variable name is listed", set(img["names"]) ==
          {"bootcmd", "bootdelay", "baudrate", "ethaddr"}, img.get("names"))

    bad = fw.walk({"uboot.env": make_uboot_env(corrupt=True)})
    bimg = bad["images"][0]
    check("uboot_env: a CRC mismatch is reported", bimg["crc_valid"] is False, bimg)
    check("uboot_env: NO value is read on a CRC mismatch (=> None)", bimg["vars"] == {}, bimg.get("vars"))


# ---- solve_set: the never-wrong contract ------------------------------------------------------------

def q(qid, text, member=""):
    return {"qid": qid, "answer_id": qid, "question": text, "member": member,
            "answer_format": {"kind": "exact_text"}}


def test_contract():
    sq = make_squashfs({"readme.txt": b"HUNTRESS readme line\n" * 400}, comp_id=1)
    dtb = make_dtb()
    env_ok = make_uboot_env()
    env_bad = make_uboot_env(corrupt=True)

    files = {"rootfs.squashfs": sq, "board.dtb": dtb}
    ans = fw.solve_set([
        q("sz", "What is the size in bytes of readme.txt?"),
        q("pp", "What is the full path of readme.txt in the image?"),
        q("dp", "What is the value of the compatible property in the device tree?"),
        q("fl", "What is the flag hidden inside the firmware image?"),
    ], files, {"attempt": {}})
    check("contract: a file SIZE is answered PLAIN", ans["sz"] == len(b"HUNTRESS readme line\n" * 400), ans.get("sz"))
    check("contract: a PATH spelling is UNSURE (candidates), never plain",
          isinstance(ans["pp"], str) and ans["pp"].startswith("??") and "#candidates" in ans["pp"], ans.get("pp"))
    check("contract: a DTB property value is answered PLAIN", ans["dp"] == "test,board", ans.get("dp"))
    check("contract: a flag inside a file is text-is-data => None", ans["fl"] is None, ans.get("fl"))

    ans_ok = fw.solve_set([q("bc", "What is the value of the bootcmd environment variable?")],
                          {"uboot.env": env_ok}, {"attempt": {}})
    check("contract: a validated env VALUE is PLAIN", ans_ok["bc"] == "bootm 0x80000", ans_ok)

    ans_bad = fw.solve_set([q("bc", "What is the value of the bootcmd environment variable?")],
                           {"uboot.env": env_bad}, {"attempt": {}})
    check("contract: a CRC-invalid env VALUE is None (never a guess)", ans_bad["bc"] is None, ans_bad)

    # The unsure path answer carries no plain value a judge could read.
    try:
        import labels
        parsed = labels.parse(ans["pp"]) if labels.is_unsure(ans["pp"]) else None
        check("contract: the unsure path parses back as an unsure answer (gm.session strips it)",
              parsed is not None)
    except Exception as exc:                                # labels prefix unknown is fine (inline fallback)
        check("contract: the unsure path is a '??' wire string regardless of the ledger",
              ans["pp"].startswith("??"), str(exc))


def make_dtb_multi():
    """A device tree where the SAME property name ('compatible') occurs in two sibling nodes with
    DIFFERENT values -> the property is ambiguous by name alone."""
    strings = bytearray()

    def soff(s):
        key = s.encode() + b"\x00"
        idx = bytes(strings).find(key)
        if idx < 0:
            idx = len(strings)
            strings.extend(key)
        return idx

    def pad4(b):
        return b + b"\x00" * ((-len(b)) % 4)

    def begin(name):
        return struct.pack(">I", 1) + pad4(name.encode() + b"\x00")

    def prop(name, val):
        return struct.pack(">III", 3, len(val), soff(name)) + pad4(val)

    sb = bytearray()
    sb += begin("")                                         # root
    sb += begin("cpu@0")
    sb += prop("compatible", b"arm,cortex-a9\x00")
    sb += struct.pack(">I", 2)                              # END cpu@0
    sb += begin("cpu@1")
    sb += prop("compatible", b"arm,cortex-a7\x00")
    sb += struct.pack(">I", 2)                              # END cpu@1
    sb += struct.pack(">I", 2)                              # END root
    sb += struct.pack(">I", 9)                              # FDT_END

    off_memrsv = 40
    memrsv = struct.pack(">QQ", 0, 0)
    off_struct = off_memrsv + len(memrsv)
    size_struct = len(sb)
    off_strings = off_struct + size_struct
    size_strings = len(strings)
    totalsize = off_strings + size_strings
    header = struct.pack(">IIIIIIIIII", 0xD00DFEED, totalsize, off_struct, off_strings, off_memrsv,
                         17, 16, 0, size_strings, size_struct)
    return header + memrsv + bytes(sb) + bytes(strings)


def test_dtb_ambiguous_property():
    res = fw.walk({"soc.dtb": make_dtb_multi()})
    images = res["images"]
    ans = fw._answer(q("x", "What is the value of the compatible property?"), images)
    # two nodes carry 'compatible' with different values: a plain first-match answer would be a guess.
    check("dtb/ambiguous: a property present in two nodes with different values is NOT plain",
          ans is None or (isinstance(ans, str) and ans.startswith("??")), repr(ans))
    check("dtb/ambiguous: specifically it is not the first node's value",
          ans != "arm,cortex-a9" and ans != "arm,cortex-a7", repr(ans))
    # a genuine single-value property on the very same tree must still answer plain.
    single = fw.walk({"board.dtb": make_dtb()})["images"]
    sa = fw._answer(q("y", "What is the value of the compatible property?"), single)
    check("dtb/ambiguous: a single-value 'compatible' still answers PLAIN", sa == "test,board", repr(sa))


def test_signals():
    s = fw.signals([q("x", "Walk the SquashFS firmware image")], {"a.squashfs": make_squashfs({"f": b"hi"})})
    check("signals: a real firmware container signals strongly", s >= 0.8, s)
    s0 = fw.signals([q("x", "What is it?")], {"a.bin": bytes(64)})
    check("signals: a 64-byte blob signals nothing", s0 == 0.0, s0)


# =====================================================================================================
# B-069: redundant U-Boot env split + live copy, and the section-table walker
# (solvers/toolkits/firmware_sections.py). pytest only; every image is built here, byte by byte.
# =====================================================================================================

import datetime as _dt                                      # noqa: E402
import gzip as _gzip                                        # noqa: E402
import json as _json                                        # noqa: E402
import random as _random                                    # noqa: E402

import pytest                                               # noqa: E402

if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from ctf import event, flagfmt                              # noqa: E402

import firmware_sections as fs                              # noqa: E402


def _profile(prefixes=("CSCTF",), slug="b069-test"):
    return event.parse({
        "slug": slug, "name": "firmware sections test",
        "dates": {"start": _dt.date(2026, 1, 1), "end": _dt.date(2026, 1, 2)},
        "platform": {"kind": "manual"},
        "flag": {"prefixes": list(prefixes)},
        "rules": {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed"},
    }, src="<test>")


PROFILE = _profile()
FF = flagfmt.for_profile(PROFILE)
FLAG = "CSCTF{synthetic_section_walk_01}"
LIVE_MAC, STALE_MAC = "02:42:ac:1f:9e:07", "02:42:ac:00:00:01"


def rnd(n, seed=1):
    return _random.Random(seed).randbytes(n)


def env_copy(pairs, flags=None, size=0x400, endian="<", pad=b"\x00", crc_ok=True):
    """One env copy: crc32 | [flags] | name=value NUL ... NUL | padding, `size` bytes in all."""
    body = b"".join(f"{k}={v}".encode() + b"\x00" for k, v in pairs) + b"\x00"
    body += pad * (size - 4 - (flags is not None) - len(body))
    crc = zlib.crc32(body) & 0xFFFFFFFF
    if not crc_ok:
        crc ^= 0x5A5A5A5A
    return struct.pack(endian + "I", crc) + (bytes([flags]) if flags is not None else b"") + body


def env_pairs(mac, extra=()):
    return [("bootcmd", "run recovery"), ("bootdelay", "3"), ("ethaddr", mac), ("baudrate", "115200"), *extra]


# ---- firmware_walk.env_copies / pick_live_env -------------------------------------------------------

def test_env_copies_splits_a_redundant_region_into_its_two_copies():
    a = env_copy(env_pairs(STALE_MAC), flags=1)
    b = env_copy(env_pairs(LIVE_MAC), flags=2)
    copies = fw.env_copies(a + b)
    assert [(c["offset"], c["size"], c["end"], c["flags"], c["crc_valid"], c["redundant"]) for c in copies] == [
        (0, 0x400, 0x400, 1, True, True), (0x400, 0x400, 0x800, 2, True, True)]
    assert [c["data_offset"] for c in copies] == [5, 0x405]
    assert copies[0]["vars"]["ethaddr"] == STALE_MAC and copies[1]["vars"]["ethaddr"] == LIVE_MAC
    assert copies[0]["names"] == ["bootcmd", "bootdelay", "ethaddr", "baudrate"]
    assert copies[0]["crc_endian"] == "little"
    # the unsplit single-region read sees one CRC over both copies and reads nothing
    assert fw._uboot_env(a + b)["crc_valid"] is False and fw._uboot_env(a + b)["vars"] == {}


@pytest.mark.parametrize("first,second,live,word", [
    (1, 2, 1, "higher flags counter (2 over 1)"),
    (2, 1, 0, "higher flags counter (2 over 1)"),
    (7, 200, 1, "higher flags counter (200 over 7)"),
    (255, 0, 1, "wrapped"),
    (0, 255, 0, "wrapped"),
    (3, 3, 0, "keeps the first"),
])
def test_live_copy_follows_the_flags_counter(first, second, live, word):
    region = env_copy(env_pairs("aa:00:00:00:00:01"), flags=first) + env_copy(env_pairs("aa:00:00:00:00:02"), flags=second)
    copies = fw.env_copies(region)
    idx, why = fw.pick_live_env(copies)
    assert idx == live and word in why
    assert copies[idx]["vars"]["ethaddr"] == f"aa:00:00:00:00:0{live + 1}"


def test_a_copy_with_a_bad_crc_is_never_live_and_its_values_are_not_read():
    stale = env_copy(env_pairs(STALE_MAC), flags=9, crc_ok=False)      # the higher counter, but a bad CRC
    good = env_copy(env_pairs(LIVE_MAC), flags=2)
    for region, at in ((stale + good, 1), (good + stale, 0)):
        copies = fw.env_copies(region)
        assert [c["crc_valid"] for c in copies] == ([False, True] if at else [True, False])
        bad = copies[1 - at]
        assert bad["vars"] == {} and bad["flags"] is None and bad["offset"] is None
        assert bad["names"] == ["bootcmd", "bootdelay", "ethaddr", "baudrate"]
        idx, why = fw.pick_live_env(copies)
        assert idx == at and why == "the only copy with a valid CRC"
    assert fw.pick_live_env(fw.env_copies(stale + stale)) == (None, "no copy has a valid CRC")
    assert fw.pick_live_env([]) == (None, "no copy has a valid CRC")


def test_copies_without_a_counter_or_beyond_the_pair_are_said_not_compared(monkeypatch):
    # two crc+data copies carry no flags byte: nothing orders them, the first is taken and the reason says so
    plain = env_copy(env_pairs(STALE_MAC)) + env_copy(env_pairs(LIVE_MAC))
    copies = fw.env_copies(plain)
    assert [(c["offset"], c["redundant"]) for c in copies] == [(0, False), (0x400, False)]
    assert fw.pick_live_env(copies) == (0, "several valid copies but fewer than two carry a flags byte: the first is taken")
    # U-Boot keeps two copies; a third valid one is not part of the comparison, and the reason says so
    three = b"".join(env_copy(env_pairs(f"aa:00:00:00:00:0{i}"), flags=f) for i, f in ((1, 4), (2, 5), (3, 9)))
    idx, why = fw.pick_live_env(fw.env_copies(three))
    assert idx == 1 and why == "higher flags counter (5 over 4) (1 further valid copies not compared)"
    # the search covers MAX_ENV_SCAN bytes of a region and names the cut
    monkeypatch.setattr(fw, "MAX_ENV_SCAN", 0x500)
    notes = []
    assert [c["offset"] for c in fw.env_copies(three, notes=notes)] == [0, 0x400]      # the third starts past the cut
    assert notes == ["env search covered the first 1280 of 3072 bytes"]


def test_env_copies_are_found_off_any_boundary_and_base_shifts_the_offsets():
    tail = rnd(0x333, 4)
    assert tail[0] not in (0x00, 0xFF)                      # the copy's zero padding ends where the tail starts
    region = rnd(0x270, 3) + env_copy(env_pairs(LIVE_MAC), flags=4, size=0x1f0) + tail
    (c,) = fw.env_copies(region)
    assert (c["offset"], c["size"], c["flags"], c["vars"]["ethaddr"]) == (0x270, 0x1f0, 4, LIVE_MAC)
    (shifted,) = fw.env_copies(region, base=0x1000)
    assert (shifted["offset"], shifted["data_offset"], shifted["end"]) == (0x1270, 0x1275, 0x1460)


def test_env_layouts_plain_big_endian_ff_padding_and_a_letter_flags_byte():
    plain = rnd(0x40, 5) + env_copy(env_pairs(LIVE_MAC), size=0x100) + rnd(0x40, 6)
    (c,) = fw.env_copies(plain)
    assert (c["offset"], c["redundant"], c["flags"], c["size"]) == (0x40, False, None, 0x100)
    big = env_copy(env_pairs(LIVE_MAC), flags=1, endian=">", pad=b"\xff")
    (c,) = fw.env_copies(big)
    assert (c["crc_endian"], c["flags"], c["size"], c["vars"]["baudrate"]) == ("big", 1, 0x400, "115200")
    # flags 0x41 is the letter A: it reads as part of the first name, and is still the flags byte
    letter = env_copy(env_pairs(STALE_MAC), flags=0x40) + env_copy(env_pairs(LIVE_MAC), flags=0x41)
    copies = fw.env_copies(letter)
    assert [(c["offset"], c["flags"]) for c in copies] == [(0, 0x40), (0x400, 0x41)]
    assert copies[1]["names"][0] == "bootcmd" and copies[1]["vars"]["ethaddr"] == LIVE_MAC
    assert fw.pick_live_env(copies)[0] == 1


def test_a_copy_with_old_bytes_after_its_terminator_ends_where_the_crc_says():
    # a rewritten env keeps stale bytes behind the double NUL: no padding run marks the end of the copy
    pairs = b"".join(f"{k}={v}".encode() + b"\x00" for k, v in env_pairs(LIVE_MAC)) + b"\x00"

    def dirty(size, flags, seed):
        body = pairs + rnd(size - 5 - len(pairs), seed)
        return struct.pack("<I", zlib.crc32(body)) + bytes([flags]) + body

    # a power-of-two copy, in front of bytes that are not an env
    (c,) = fw.env_copies(dirty(0x800, 3, 91) + rnd(0x555, 92))
    assert (c["offset"], c["size"], c["flags"], c["vars"]["ethaddr"]) == (0, 0x800, 3, LIVE_MAC)
    # two halves of an odd size, the second erased: the copy ends at the middle of the region
    (c,) = fw.env_copies(dirty(0x300, 3, 93) + b"\xa5" * 0x300)
    assert (c["offset"], c["size"]) == (0, 0x300)
    # a size nothing suggests is not guessed: the copy is listed, CRC-invalid, values unread
    (c,) = fw.env_copies(dirty(0x2f1, 3, 94) + rnd(0x400, 95))
    assert c["crc_valid"] is False and c["vars"] == {}
    # ... but the header of the next copy does suggest it (redundant, then the plain crc+data layout)
    copies = fw.env_copies(dirty(0x2f1, 3, 96) + env_copy(env_pairs(STALE_MAC), flags=2) + rnd(0x123, 97))
    assert [(c["offset"], c["size"], c["crc_valid"], c["flags"]) for c in copies] == [(0, 0x2f1, True, 3), (0x2f1, 0x400, True, 2)]
    copies = fw.env_copies(dirty(0x2f1, 3, 98) + env_copy(env_pairs(STALE_MAC)) + rnd(0x123, 99))
    assert [(c["offset"], c["size"], c["redundant"]) for c in copies] == [(0, 0x2f1, True), (0x2f1, 0x400, False)]


def test_a_value_that_is_not_text_does_not_split_one_copy_into_two():
    pairs = env_pairs(LIVE_MAC) + [("blob", "a\x01b"), ("serial", "0042"), ("mode", "field")]
    (c,) = fw.env_copies(rnd(0x30, 7) + env_copy(pairs, flags=6) + rnd(0x30, 8))
    assert c["crc_valid"] and c["offset"] == 0x30 and c["size"] == 0x400
    assert c["names"] == ["bootcmd", "bootdelay", "ethaddr", "baudrate", "blob", "serial", "mode"]
    assert c["vars"]["blob"] == "a\x01b" and c["vars"]["mode"] == "field"


def test_env_search_names_the_cap_that_stopped_it(monkeypatch):
    region = b"".join(rnd(8, i) + b"\x01" + f"k{i}=v\x00j{i}=w\x00".encode() + b"\x01" for i in range(6))
    region += env_copy(env_pairs(LIVE_MAC), flags=1)
    assert [c["crc_valid"] for c in fw.env_copies(region)] == [False] * 6 + [True]
    with monkeypatch.context() as m:
        m.setattr(fw, "MAX_ENV_HEADS", 3)
        notes = []
        cut = fw.env_copies(region, notes=notes)
        assert [c["crc_valid"] for c in cut] == [False] * 3
        assert notes == ["env search stopped at offset 0x45: 3 variable chains tried, 0 valid copies found"]
    # strings that only look like an env (a default env compiled into a boot loader) do not crowd out
    # the real copy behind them: they stop being listed, the search goes on
    with monkeypatch.context() as m:
        m.setattr(fw, "MAX_ENV_INVALID", 2)
        notes = []
        cut = fw.env_copies(region, notes=notes)
        assert [c["crc_valid"] for c in cut] == [False, False, True] and cut[2]["vars"]["ethaddr"] == LIVE_MAC
        assert notes == ["4 further variable chains with no valid CRC are not listed"]
    with monkeypatch.context() as m:
        m.setattr(fw, "MAX_ENV_COPIES", 1)
        notes = []
        two = env_copy(env_pairs(LIVE_MAC), flags=1) + env_copy(env_pairs(STALE_MAC), flags=2)
        assert [c["offset"] for c in fw.env_copies(two, notes=notes)] == [0]
        assert notes == ["env search stopped at offset 0x405: 1 variable chains tried, 1 valid copies found"]
    # a copy ends at the header of one of the chains right behind it; MAX_ENV_NEXT bounds how many are tried
    with monkeypatch.context() as m:
        body = b"".join(f"{k}={v}".encode() + b"\x00" for k, v in env_pairs(LIVE_MAC)) + b"\x00"
        body += rnd(0x2f1 - 5 - len(body), 44)
        dirty = struct.pack("<I", zlib.crc32(body)) + b"\x03" + body
        after = dirty + env_copy(env_pairs(STALE_MAC), flags=2) + rnd(0x123, 45)
        assert [c["crc_valid"] for c in fw.env_copies(after)] == [True, True]
        m.setattr(fw, "MAX_ENV_NEXT", 0)
        assert [c["crc_valid"] for c in fw.env_copies(after)] == [False, True]


def test_walk_reads_a_two_copy_env_file_through_its_live_copy():
    region = env_copy(env_pairs(LIVE_MAC), flags=5) + env_copy(env_pairs(STALE_MAC), flags=4)
    (img,) = fw.walk({"env.bin": region})["images"]
    assert img["kind"] == "uboot_env" and img["crc_valid"] is True and img["redundant"] is True
    assert img["live"] == 0 and len(img["copies"]) == 2 and img["vars"]["ethaddr"] == LIVE_MAC
    ans = fw.solve_set([q("e", "What is the value of the U-Boot environment variable ethaddr?")], {"env.bin": region}, {})
    assert ans == {"e": LIVE_MAC}
    # both copies broken: the image stays CRC-invalid and no value is answered
    broken = env_copy(env_pairs(LIVE_MAC), flags=5, crc_ok=False) + env_copy(env_pairs(STALE_MAC), flags=4, crc_ok=False)
    (bimg,) = fw.walk({"env.bin": broken})["images"]
    assert bimg["crc_valid"] is False and bimg["vars"] == {}
    assert fw.solve_set([q("e", "What is the value of the U-Boot environment variable ethaddr?")],
                        {"env.bin": broken}, {}) == {"e": None}


# ---- the section table ------------------------------------------------------------------------------

LAYOUTS = {     # record stride, name (position, width), and the positions of the three fields
    "name-first": dict(stride=28, name=(0, 16), off=16, size=20, crc=24),
    "name-last": dict(stride=28, name=(12, 16), off=0, size=4, crc=8),
    "split": dict(stride=32, name=(4, 12), off=0, size=16, crc=24, junk=(20, 7)),
    "crc-first": dict(stride=24, name=(12, 12), off=8, size=4, crc=0),
    "size-twice": dict(stride=32, name=(16, 16), off=0, size=4, crc=12, same_as_size=8),
    "name8-first": dict(stride=20, name=(0, 8), off=8, size=12, crc=16),
}


def make_bundle(sections, layout="name-first", endian="<", algo="crc32", magic=b"DWFW", header_extra=b"", spare=0):
    """A vendor bundle: magic, version, record count, reserved (then `header_extra`); the record
    table (then `spare` zeroed record slots); the sections, each padded with 0xFF to 16 bytes.
    Returns (image, [(name, offset, size)])."""
    lay = LAYOUTS[layout]
    table_at = 16 + len(header_extra)
    img = bytearray(magic + struct.pack(endian + "III", 1, len(sections), 0) + header_extra)
    img += bytes(lay["stride"] * (len(sections) + spare))
    img += bytes(-len(img) % 16)
    placed = []
    for i, (name, body) in enumerate(sections):
        off = len(img)
        img += body + b"\xff" * 16
        img += b"\xff" * (-len(img) % 16)
        crc = zlib.crc32(body) & 0xFFFFFFFF
        rec = bytearray(lay["stride"])
        rec[lay["name"][0]:lay["name"][0] + len(name)] = name.encode()
        struct.pack_into(endian + "I", rec, lay["off"], off)
        struct.pack_into(endian + "I", rec, lay["size"], len(body))
        struct.pack_into(endian + "I", rec, lay["crc"], crc ^ 0xFFFFFFFF if algo == "crc32-jamcrc" else crc)
        if "junk" in lay:
            struct.pack_into(endian + "I", rec, lay["junk"][0], lay["junk"][1])
        if "same_as_size" in lay:
            struct.pack_into(endian + "I", rec, lay["same_as_size"], len(body))
        img[table_at + i * lay["stride"]:table_at + (i + 1) * lay["stride"]] = rec
        placed.append((name, off, len(body)))
    return bytes(img), placed


PLAIN = [("boot", rnd(3000, 11)), ("kernel", rnd(5000, 12)), ("msgcat", b"MSG: link up\n" * 90), ("rootfs", rnd(7001, 13))]


@pytest.mark.parametrize("layout", sorted(LAYOUTS))
@pytest.mark.parametrize("endian,algo", [("<", "crc32"), (">", "crc32"), ("<", "crc32-jamcrc")])
def test_the_table_is_found_by_its_crcs_in_any_record_layout(layout, endian, algo):
    img, placed = make_bundle(PLAIN, layout=layout, endian=endian, algo=algo)
    notes = []
    (t,) = fs.find_tables(img, notes=notes)
    assert notes == []
    assert [(e["name"], e["offset"], e["size"]) for e in t["entries"]] == placed      # header words are not records
    assert all(e["crc_ok"] and e["crc_stored"] == e["crc_computed"] for e in t["entries"])
    lay = LAYOUTS[layout]
    base = min(lay["off"], lay["size"], lay["crc"])
    assert (t["stride"], t["endian"], t["checksum"]) == (lay["stride"], "little" if endian == "<" else "big", algo)
    assert t["offset"] == 16 + base and [e["record_offset"] for e in t["entries"]] == [
        16 + base + i * lay["stride"] for i in range(4)]
    assert t["fields"] == {"offset": lay["off"] - base, "size": lay["size"] - base, "crc": lay["crc"] - base}
    assert [e["index"] for e in t["entries"]] == [0, 1, 2, 3]


def test_a_name_that_fills_its_field_stops_at_the_next_field():
    # eight letters in an eight-byte name field: no NUL between the name and the offset word behind it
    sections = [("loader", rnd(111, 14)), ("ubootenv", rnd(4096, 15)), ("msgcat", rnd(258, 16)), ("rootfs", rnd(633, 17))]
    for endian in "<>":
        img, placed = make_bundle(sections, layout="name8-first", endian=endian)
        (t,) = fs.find_tables(img)
        assert [(e["name"], e["offset"], e["size"]) for e in t["entries"]] == placed
        assert t["names"] == "name field -8 bytes from the offset field"


def test_header_text_in_front_of_the_first_record_is_not_taken_for_a_section_name():
    # name-last records: 28 bytes before each name sits the previous record's name -- and, for the
    # first record, header text. That text is not padded out to a field, the real names are.
    extra = b"\x00" * 16 + b"RADIO-X1\x01\x02\x03\x04\x05\x06\x07\x08"
    assert len(extra) == 32
    img, placed = make_bundle(PLAIN, layout="name-last", header_extra=extra)
    (t,) = fs.find_tables(img)
    assert [e["name"] for e in t["entries"]] == ["boot", "kernel", "msgcat", "rootfs"]
    assert t["names"] == "name field +12 bytes from the offset field"
    # a bare magic and zero padding in front of the first record: the file magic is not a section name
    img16, _ = make_bundle(PLAIN, layout="name-last")
    bare = img16[:4] + bytes(12) + img16[16:]
    (t,) = fs.find_tables(bare)
    assert [e["name"] for e in t["entries"]] == ["boot", "kernel", "msgcat", "rootfs"]
    # with no name field at all the sections are numbered, and the table says why
    blank = bytearray(img)
    for i in range(4):
        at = 16 + len(extra) + i * 28 + 12
        blank[at:at + 16] = bytes(16)
    (t,) = fs.find_tables(bytes(blank))
    assert [e["name"] for e in t["entries"]] == ["section0", "section1", "section2", "section3"]
    assert t["names"] == "no name field found: sections are numbered"


def test_an_unconfirmed_record_is_listed_only_when_it_can_be_a_section():
    img, placed = make_bundle(PLAIN, spare=2)
    (t,) = fs.find_tables(img)
    assert len(t["entries"]) == 4                                   # zeroed slots are not records
    slot = 16 + 4 * 28
    gap = placed[3][1] + placed[3][2]                               # the 0xFF padding after the last section

    def with_record(off, size, crc=0x11223344):
        out = bytearray(img)
        out[slot:slot + 28] = b"spare".ljust(16, b"\x00") + struct.pack("<III", off, size, crc)
        return bytes(out)

    (t,) = fs.find_tables(with_record(gap, 8))                      # in bounds, free bytes, wrong CRC
    assert [(e["name"], e["offset"], e["size"], e["crc_ok"]) for e in t["entries"]][4:] == [("spare", gap, 8, False)]
    assert t["entries"][4]["crc_stored"] == 0x11223344 and t["entries"][4]["crc_computed"] == zlib.crc32(b"\xff" * 8)
    for off, size in ((placed[1][1] + 10, 64),                      # inside a confirmed section
                      (placed[0][1] - 4, 8),                        # straddles the start of one
                      (20, 8),                                      # the table itself
                      (4, 8),                                       # the header in front of it
                      (gap, len(img)),                              # runs past the end of the file
                      (gap, 0)):
        (t,) = fs.find_tables(with_record(off, size))
        assert [e["name"] for e in t["entries"]] == ["boot", "kernel", "msgcat", "rootfs"], (off, size)

    # a table BEHIND its sections (a trailer): nothing is ruled out by position there, only by overlap
    body, recs, spots = bytearray(b"TRLR" + bytes(12)), [], []
    for name, blob in PLAIN[:3]:
        spots.append(len(body))
        recs.append(name.encode().ljust(16, b"\x00") + struct.pack("<III", len(body), len(blob), zlib.crc32(blob)))
        body += blob + b"\xff" * 16
        body += b"\xff" * (-len(body) % 16)
    table = len(body)

    def trailer(off, size):
        return bytes(body) + b"".join(recs) + b"spare".ljust(16, b"\x00") + struct.pack("<III", off, size, 1) + bytes(64)

    (t,) = fs.find_tables(trailer(spots[0] + 3000, 8))              # the padding after the first section
    assert t["offset"] == table + 16
    assert [(e["name"], e["crc_ok"]) for e in t["entries"]] == [("boot", True), ("kernel", True), ("msgcat", True),
                                                                 ("spare", False)]
    for off, size in ((table + 4, 8), (table - 8, 64), (spots[2], 4)):      # the table itself (twice), a section
        (t,) = fs.find_tables(trailer(off, size))
        assert [e["name"] for e in t["entries"]] == ["boot", "kernel", "msgcat"], (off, size)


@pytest.mark.parametrize("victim", [0, 1, 3])
def test_a_section_whose_crc_does_not_match_is_listed_as_a_mismatch(victim):
    img, placed = make_bundle(PLAIN)
    name, off, size = placed[victim]
    bad = bytearray(img)
    bad[off + size // 2] ^= 0x01
    (t,) = fs.find_tables(bytes(bad))
    assert [(e["name"], e["offset"], e["size"]) for e in t["entries"]] == placed
    assert [e["crc_ok"] for e in t["entries"]] == [i != victim for i in range(4)]
    e = t["entries"][victim]
    assert e["crc_stored"] == zlib.crc32(img[off:off + size]) and e["crc_computed"] == zlib.crc32(bytes(bad[off:off + size]))
    assert "CRC MISMATCH: " + name in "\n".join(fs.summary(fs.walk_image("fw.bin", bytes(bad), FF)[0]))


def test_a_backup_copy_of_the_table_and_a_second_table_are_told_apart():
    cpio = make_cpio({"etc/hostname": b"radio\n"})
    img, placed = make_bundle(PLAIN[:3] + [("initramfs", _gzip.compress(cpio, mtime=0))], spare=6)
    primary = img[16:16 + 4 * 28]
    slot = 16 + 4 * 28
    # the same four records again, off the stride of the first table: one table, not eight records
    backup = bytearray(img)
    backup[slot + 10:slot + 10 + len(primary)] = primary
    (t,) = fs.find_tables(bytes(backup))
    assert [(e["name"], e["offset"], e["size"]) for e in t["entries"]] == placed and t["offset"] == 32
    # a second table that shares one section and adds one: both are reported, the shared section is walked once
    gap = placed[3][1] + placed[3][2]
    second = bytearray(img)
    second[slot + 10:slot + 10 + 56] = (
        b"initramfs".ljust(16, b"\x00") + struct.pack("<III", placed[3][1], placed[3][2], zlib.crc32(_gzip.compress(cpio, mtime=0)))
        + b"spare".ljust(16, b"\x00") + struct.pack("<III", gap, 12, zlib.crc32(b"\xff" * 12)))
    one, two = fs.find_tables(bytes(second))
    assert [e["name"] for e in one["entries"]] == ["boot", "kernel", "msgcat", "initramfs"]
    assert [(e["name"], e["offset"], e["size"], e["crc_ok"]) for e in two["entries"]] == [
        ("initramfs", placed[3][1], placed[3][2], True), ("spare", gap, 12, True)]
    rep, _ = fs.walk_image("fw.bin", bytes(second), FF)
    assert [(s["section"], s["kind"]) for s in rep["streams"]] == [("initramfs", "gzip")]
    assert [c["members"] for c in rep["containers"]] == [1]


def test_no_table_in_bytes_that_have_none_and_a_single_record_is_numbered():
    assert fs.find_tables(rnd(40000, 21)) == []
    assert fs.find_tables(struct.pack("<2000I", *range(1, 2001))) == []       # every word a plausible offset
    assert fs.find_tables(b"DWFW") == []
    # checksums kept in a block of their own, far from the (offset, size) pairs, are not records
    head, blobs = 16 + 4 * 8 + 200 + 4 * 4, [b for _, b in PLAIN]
    offs = [head + sum(len(b) for b in blobs[:i]) for i in range(4)]
    apart = (b"DWFW" + bytes(12) + b"".join(struct.pack("<II", o, len(b)) for o, b in zip(offs, blobs)) + bytes(200)
             + b"".join(struct.pack("<I", zlib.crc32(b)) for b in blobs) + b"".join(blobs))
    assert apart[offs[3]:] == blobs[3] and fs.find_tables(apart) == []
    img, placed = make_bundle(PLAIN[:1])
    (t,) = fs.find_tables(img)
    assert t["stride"] is None and t["names"].startswith("no record stride")
    assert [(e["name"], e["offset"], e["size"], e["crc_ok"]) for e in t["entries"]] == [("section0", placed[0][1], 3000, True)]


def test_the_table_search_names_the_cap_that_stopped_it(monkeypatch):
    img, _ = make_bundle(PLAIN)
    notes = []
    assert fs.find_tables(img, crc_budget=100, notes=notes) == []
    assert notes == ["section-table search stopped at the checksum budget of 100 bytes: "
                     "a table further in was not looked for"]
    monkeypatch.setattr(fs, "MAX_PAIRS", 1)
    notes = []
    assert fs.find_tables(img, notes=notes) == []
    assert len(notes) == 1 and "1 candidate (offset, size) pairs" in notes[0]


# ---- the wiring: env, FDICT dictionary, cpio, flags, the keyed-XOR lead ----------------------------

def make_cpio(files):
    """A newc cpio archive of regular files."""
    out = bytearray()
    for ino, (name, body) in enumerate(list(files.items()) + [("TRAILER!!!", b"")], 1):
        nb = name.encode() + b"\x00"
        mode = 0 if name == "TRAILER!!!" else 0o100644
        fields = (ino, mode, 0, 0, 1, 0, len(body), 0, 0, 0, 0, len(nb), 0)
        out += b"070701" + b"".join(b"%08X" % v for v in fields) + nb
        out += bytes(-len(out) % 4) + body
        out += bytes(-len(out) % 4)
    return bytes(out)


def fdict(payload, dictionary):
    c = zlib.compressobj(9, zdict=dictionary)
    return c.compress(payload) + c.flush()


def xor_token(flag, mac):
    key = bytes.fromhex(mac.replace(":", ""))
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(flag.encode())).hex()


MSGCAT = b"".join(b"MSG%03d: radio link status message number %d, retry in %d seconds\n" % (i, i, i * 3) for i in range(160))


def make_radio(*, token_mac=LIVE_MAC, live_first=False, live_ok=True, literal=None, dictionary=MSGCAT,
               in_table=True, admin=None):
    """The bundle of the item: boot, a redundant env (the stale copy carries a decoy MAC), a message
    catalogue that is the zlib preset dictionary of the rootfs, and the rootfs (a newc cpio)."""
    admin = admin if admin is not None else (
        "#!/bin/sh\n# S40admin: recovery console\nadmin_token=%s\nstart() { echo console; }\n" % xor_token(FLAG, token_mac))
    files = {"etc/init.d/S40admin": admin.encode(), "etc/motd": b"MSG001: radio link status message number 1\n"}
    if literal:
        files["root/.note"] = literal.encode()
    live = env_copy(env_pairs(LIVE_MAC), flags=2, crc_ok=live_ok)
    stale = env_copy(env_pairs(STALE_MAC), flags=1)
    sections = [("boot", rnd(3000, 31)), ("env", live + stale if live_first else stale + live)]
    if in_table:
        sections.append(("msgcat", dictionary))
    sections.append(("rootfs", fdict(make_cpio(files), dictionary)))
    return make_bundle(sections)


def test_the_bundle_is_walked_end_to_end_table_env_dictionary_cpio_and_the_xor_lead():
    img, placed = make_radio()
    rep, blobs = fs.walk_image("firmware.bin", img, FF)
    where = {name: off for name, off, _ in placed}
    assert rep["magic"] == "DWFW" and rep["notes"] == []
    assert [e["name"] for e in rep["tables"][0]["entries"]] == ["boot", "env", "msgcat", "rootfs"]
    # env: both copies, each inside the env section, the higher counter live
    env = rep["env"]
    assert [(c["offset"], c["flags"], c["crc_valid"], c["section"]) for c in env["copies"]] == [
        (where["env"], 1, True, "env"), (where["env"] + 0x400, 2, True, "env")]
    assert env["live"] == 1 and env["copies"][1]["vars"]["ethaddr"] == LIVE_MAC
    # the dictionary is the section whose Adler-32 the stream names, and the stream inflates with it
    msgcat = rep["tables"][0]["entries"][2]
    assert msgcat["dictionary_for"] == [where["rootfs"]]
    assert all("dictionary_for" not in e for e in rep["tables"][0]["entries"] if e["name"] != "msgcat")
    (s,) = rep["streams"]
    assert (s["section"], s["offset"], s["kind"], s["dictionary"]) == ("rootfs", where["rootfs"], "zlib", "msgcat")
    assert s["dictid"] == zlib.adler32(MSGCAT) and s["end"] == where["rootfs"] + placed[3][2]
    # the inflated payload is a cpio and its members are read
    assert rep["containers"] == [{"in": f"rootfs@{where['rootfs']:#x}.zlib", "kind": "cpio", "members": 2}]
    assert [(m["path"], m["dir"], m["read"]) for m in rep["members"]] == [
        ("etc/init.d/S40admin", False, True), ("etc/motd", False, True)]
    got = dict(blobs)
    assert got[f"rootfs@{where['rootfs']:#x}.zlib/etc/init.d/S40admin"].startswith(b"#!/bin/sh\n# S40admin")
    assert got[f"rootfs@{where['rootfs']:#x}.zlib"][:6] == b"070701" and s["inflated"] == len(got[f"rootfs@{where['rootfs']:#x}.zlib"])
    # no flag is written anywhere; the token XOR the LIVE copy's ethaddr is one, the stale copy's is not
    assert rep["flags"] == []
    x = rep["xor"]
    assert [(h["flag"], h["copy"], h["live"], h["var"], h["form"], h["label"]) for h in x["hits"]] == [
        (FLAG, 1, True, "ethaddr", "hex groups", "admin_token")]
    assert x["tokens"] == 1 and x["tried"] == x["keys"] > 4 and x["token_list"][0]["text"] == xor_token(FLAG, LIVE_MAC)
    res = fs.result_of({"images": [rep], "blobs": {}, "skipped": 0, "notes": []})
    assert res.status == "candidate" and list(res.flags) == [FLAG] and res.engine == "toolkits.firmware_sections"
    assert res.notes.startswith("one flag, from the keyed-XOR lead only")
    assert [(e.kind, e.path) for e in res.evidence] == [("decode", "firmware.bin")]
    assert "the live copy" in res.evidence[0].detail and "NOT" not in res.evidence[0].detail


@pytest.mark.parametrize("live_first", [False, True])
def test_the_live_copy_is_picked_wherever_it_sits_and_the_xor_hit_says_which_copy(live_first):
    img, _ = make_radio(live_first=live_first)
    rep, _ = fs.walk_image("firmware.bin", img, FF)
    live = rep["env"]["live"]
    assert live == (0 if live_first else 1) and rep["env"]["copies"][live]["flags"] == 2
    assert [(h["flag"], h["copy"], h["live"]) for h in rep["xor"]["hits"]] == [(FLAG, live, True)]
    # a token keyed to the STALE copy's address still decodes, and the hit says it is not the live copy
    img, _ = make_radio(live_first=live_first, token_mac=STALE_MAC)
    rep, _ = fs.walk_image("firmware.bin", img, FF)
    assert [(h["flag"], h["copy"], h["live"]) for h in rep["xor"]["hits"]] == [(FLAG, 1 - live, False)]
    res = fs.result_of({"images": [rep], "blobs": {}, "skipped": 0, "notes": []})
    assert res.status == "candidate" and "NOT the live copy" in res.evidence[0].detail


def test_a_decoy_key_gives_garbage_and_garbage_is_never_a_flag():
    # the only CRC-valid copy is the stale one: its address does not open the token, so there is no flag
    img, _ = make_radio(live_ok=False)
    rep, _ = fs.walk_image("firmware.bin", img, FF)
    assert [c["crc_valid"] for c in rep["env"]["copies"]] == [True, False]
    assert rep["env"]["live"] == 0 and rep["env"]["copies"][0]["vars"]["ethaddr"] == STALE_MAC
    assert rep["xor"]["hits"] == [] and rep["xor"]["tried"] == rep["xor"]["keys"] > 0 and rep["flags"] == []
    res = fs.result_of({"images": [rep], "blobs": {}, "skipped": 0, "notes": []})
    assert res.status == "unsure" and list(res.flags) == []
    assert res.notes.startswith("section table / U-Boot env read, no flag in the event format")
    assert "keyed XOR (unsure lead): 1 tokens x" in res.notes and "0 in the flag format" in res.notes
    # a token that decodes to flag-like text with a wrong prefix, or with a tail after the flag, is not one
    for text in ("NOPE{synthetic_section_walk_01}", FLAG + " and more"):
        key = bytes.fromhex(LIVE_MAC.replace(":", ""))
        tok = bytes(b ^ key[i % 6] for i, b in enumerate(text.encode())).hex()
        img, _ = make_radio(admin=f"admin_token={tok}\n")
        assert fs.walk_image("firmware.bin", img, FF)[0]["xor"]["hits"] == []


def test_a_flag_written_in_the_inflated_rootfs_is_solved_and_two_flags_are_candidates():
    other = "CSCTF{written_in_the_rootfs}"
    img, placed = make_radio(literal=f"note: {other}\n", admin="#!/bin/sh\nexit 0\n")
    rep, _ = fs.walk_image("firmware.bin", img, FF)
    assert rep["flags"] == [{"flag": other, "where": f"rootfs@{placed[3][1]:#x}.zlib"}]
    res = fs.result_of({"images": [rep], "blobs": {}, "skipped": 0, "notes": []})
    assert res.status == "solved" and list(res.flags) == [other]
    assert res.evidence[0].kind == "carve" and "read verbatim" in res.evidence[0].detail
    img, _ = make_radio(literal=f"note: {other}\n")
    rep, _ = fs.walk_image("firmware.bin", img, FF)
    res = fs.result_of({"images": [rep], "blobs": {}, "skipped": 0, "notes": []})
    assert res.status == "candidate" and list(res.flags) == [other, FLAG]
    assert res.notes.startswith("several flags: decoys are possible")
    assert [e.kind for e in res.evidence] == ["carve", "decode"]
    # the same flag both written and behind the token is one flag, read verbatim
    img, _ = make_radio(literal=f"note: {FLAG}\n")
    rep, _ = fs.walk_image("firmware.bin", img, FF)
    res = fs.result_of({"images": [rep], "blobs": {}, "skipped": 0, "notes": []})
    assert res.status == "solved" and list(res.flags) == [FLAG] and [e.kind for e in res.evidence] == ["carve"]


def test_a_dictionary_that_is_missing_or_too_long_is_named_not_skipped_silently():
    img, placed = make_radio(in_table=False)
    rep, _ = fs.walk_image("firmware.bin", img, FF)
    assert rep["streams"] == [] and rep["members"] == []
    assert rep["notes"] == [f"section rootfs starts with a zlib preset-dictionary header (DICTID "
                            f"{zlib.adler32(MSGCAT):#010x}) and no section has that Adler-32: the dictionary is not in the table"]
    long = rnd(40000, 41)
    img, placed = make_radio(dictionary=long)
    rep, _ = fs.walk_image("firmware.bin", img, FF)
    assert rep["streams"] == [] and rep["tables"][0]["entries"][2]["dictionary_for"] == [placed[3][1]]
    assert rep["notes"] == [f"section msgcat (40000 bytes) is the preset dictionary of the zlib stream at "
                            f"{placed[3][1]:#x}, but carve_all takes dictionaries up to 32768 bytes: stream not inflated"]


def test_every_cap_that_drops_something_says_what_it_dropped(monkeypatch, tmp_path):
    img, placed = make_radio()
    at = placed[3][1]
    with monkeypatch.context() as m:
        m.setattr(fs, "MAX_DICTS", 0)
        rep, _ = fs.walk_image("firmware.bin", img, FF)
        assert rep["streams"] == [] and rep["notes"] == ["section msgcat is a dictionary, but 0 are already in use: not passed"]
    with monkeypatch.context() as m:
        m.setattr(fs, "CARVE_MAX", 3000)                    # boot is 3000 bytes, the msgcat is longer
        rep, _ = fs.walk_image("firmware.bin", img, FF)
        assert [s["section"] for s in rep["streams"]] == ["rootfs"]
        assert rep["notes"] == [f"section msgcat ({len(MSGCAT)} bytes) not scanned for compressed streams: over the "
                                "3000 byte section cap or the 33554432 byte total"]
    with monkeypatch.context() as m:
        m.setattr(fs, "CARVE_TOTAL", 3000 + 0x800)          # boot and env fit, nothing after them
        rep, _ = fs.walk_image("firmware.bin", img, FF)
        assert rep["streams"] == [] and [n.split(" (")[0] for n in rep["notes"]] == ["section msgcat", "section rootfs"]
    with monkeypatch.context() as m:
        m.setattr(fs, "MAX_INFLATE", 100)
        rep, blobs = fs.walk_image("firmware.bin", img, FF)
        assert [s["inflated"] for s in rep["streams"]] == [None] and blobs == [] and rep["members"] == []
        assert rep["notes"] == [f"stream at {at:#x} (zlib) inflates past 100 bytes: not kept"]
    with monkeypatch.context() as m:
        m.setattr(fs, "MAX_MEMBERS", 1)
        rep, blobs = fs.walk_image("firmware.bin", img, FF)
        assert [x["path"] for x in rep["members"]] == ["etc/init.d/S40admin"]
        assert rep["notes"] == [f"rootfs@{at:#x}.zlib: more than 1 members, the rest not listed"]
    cd = tmp_path / "c"
    (cd / "files").mkdir(parents=True)
    (cd / "files" / "firmware.bin").write_bytes(img)
    with monkeypatch.context() as m:
        m.setattr(fs, "MAX_WRITE_FILES", 1)
        res = fs.solve(cd, PROFILE, out=str(tmp_path / "o1"))
        assert len(list((tmp_path / "o1" / "files_firmware.bin" / "extracted").iterdir())) == 1
        assert res.notes.count("not written: over the 1 file or 16777216 byte write cap") == 2
    with monkeypatch.context() as m:
        m.setattr(fs, "MAX_WRITE_BYTES", 60)
        res = fs.solve(cd, PROFILE, out=str(tmp_path / "o2"))
        assert [p.name for p in (tmp_path / "o2" / "files_firmware.bin" / "extracted").iterdir()] == [
            f"0002_rootfs_{at:#x}.zlib_etc_motd"]
        assert res.notes.count("not written") == 2 and list(res.flags) == [FLAG]
    with monkeypatch.context() as m:
        m.setattr(fs, "MAX_FILE", len(img) - 1)
        res = fs.solve(cd, PROFILE, out=str(tmp_path / "o3"))
        assert res.status == "none" and not (tmp_path / "o3").exists()
        assert res.notes == f"no section table and no U-Boot env in 0 file(s)\nfiles/firmware.bin: over {len(img) - 1} bytes, not read"


def test_gzip_cpio_and_squashfs_sections_reach_their_readers():
    cpio = make_cpio({"init": b"#!/bin/sh\necho CSCTF{in_the_initramfs}\n"})
    sq = make_squashfs({"flag.txt": b"CSCTF{in_the_squashfs}\n" * 3, "pad.txt": b"x" * 500})
    img, placed = make_bundle([("kernel", rnd(2000, 51)), ("initramfs", _gzip.compress(cpio, mtime=0)),
                               ("rootfs", sq), ("raw", make_cpio({"etc/hostname": b"radio\n"}))])
    rep, blobs = fs.walk_image("fw.bin", img, FF)
    assert [(s["section"], s["kind"], s["dictionary"], s["inflated"]) for s in rep["streams"]
            if s["section"] == "initramfs"] == [("initramfs", "gzip", None, len(cpio))]
    kinds = {(c["in"].split("@")[0], c["kind"], c["members"]) for c in rep["containers"]}
    assert {("initramfs", "cpio", 1), ("rootfs", "squashfs", 2), ("raw", "cpio", 1)} <= kinds
    assert {f["flag"] for f in rep["flags"]} == {"CSCTF{in_the_initramfs}", "CSCTF{in_the_squashfs}"}
    assert dict(blobs)["raw/etc/hostname"] == b"radio\n"


def test_a_phase_past_the_time_budget_is_not_run_and_says_so():
    img, _ = make_radio()
    ticks = iter([0.0] + [9.0] * 50)            # the dictionary search is in time, everything after is late
    rep, blobs = fs.walk_image("firmware.bin", img, FF, clock=lambda: next(ticks), deadline=5.0)
    assert rep["tables"] and rep["tables"][0]["entries"][2]["dictionary_for"]
    assert rep["streams"] == [] and rep["members"] == [] and rep["xor"] is None and blobs == []
    assert rep["notes"] == ["time budget spent before the stream carve of section boot: not run",
                            "time budget spent before the archive and filesystem readers: not run",
                            "time budget spent before the flag search: not run",
                            "time budget spent before the keyed-XOR sweep: not run"]
    clock = iter([0.0, 1.0, 100.0, 100.0])
    walked = fs.examine({"a.bin": img, "b.bin": img}, None, seconds=50.0, clock=lambda: next(clock, 100.0))
    assert [r["file"] for r in walked["images"]] == ["a.bin"]
    assert walked["notes"] == ["time budget of 50s spent: b.bin and the files after it not walked"]


def test_tokens_keys_and_the_sweep_without_a_flag_format(monkeypatch):
    text = b'# conf\nadmin_token = "00112233445566778899aabbccddeeff"\nlicense: QUJDREVGR0hJSktMTU5PUA==\nshort=0011\n'
    toks = fs.tokens_in("etc/conf", text)
    assert [(t["label"], t["encoding"], t["raw"]) for t in toks] == [
        ("admin_token", "hex", bytes.fromhex("00112233445566778899aabbccddeeff")),
        ("license", "base64", b"ABCDEFGHIJKLMNOP")]
    assert fs.keys_of("02:42:ac:1f:9e:07") == [("hex groups", bytes.fromhex("0242ac1f9e07")), ("text", b"02:42:ac:1f:9e:07")]
    assert fs.keys_of("0xDEADbeef") == [("hex", bytes.fromhex("deadbeef")), ("text", b"0xDEADbeef")]
    assert fs.keys_of("run recovery") == [("text", b"run recovery")] and fs.keys_of("3") == []
    assert fs.xor_repeat(b"\x01\x02\x03\x04\x05", b"\xff\x0f") == b"\xfe\x0d\xfc\x0b\xfa"
    copies = fw.env_copies(env_copy(env_pairs(LIVE_MAC), flags=1))
    tok = [{"where": "t", "label": "admin_token", "encoding": "hex", "text": xor_token(FLAG, LIVE_MAC),
            "raw": bytes.fromhex(xor_token(FLAG, LIVE_MAC))}]
    blind = fs.keyed_xor_sweep(tok, copies, 0, None)
    assert blind["hits"] == [] and blind["tried"] == 0 and "no flag format" in blind["note"]
    assert [h["flag"] for h in fs.keyed_xor_sweep(tok, copies, 0, FF)["hits"]] == [FLAG]
    # the cap keeps the named hex secret: ahead of unnamed runs, and ahead of a named base64 run
    noise = [{"where": "n", "label": None, "encoding": enc, "text": "x", "raw": rnd(24, i)}
             for i, enc in enumerate(["base64"] * 3 + ["hex"] * 3)]
    dud = [{"where": "d", "label": "password", "encoding": "base64", "text": "x", "raw": rnd(24, 9)}]
    monkeypatch.setattr(fs, "MAX_TOKENS", 1)
    capped = fs.keyed_xor_sweep(noise + dud + tok, copies, 0, FF)
    assert [h["flag"] for h in capped["hits"]] == [FLAG] and capped["tokens"] == 1
    assert capped["note"] == "8 tokens found, the first 1 tried (named secrets and hex first)"


def _xor_tokens(texts, mac=LIVE_MAC):
    key = bytes.fromhex(mac.replace(":", ""))
    return [{"where": f"t{i}", "label": "admin_token", "encoding": "hex", "text": "x",
             "raw": bytes(b ^ key[i % len(key)] for i, b in enumerate(t.encode("latin-1")))}
            for i, t in enumerate(texts)]


def test_a_keyed_xor_result_with_a_control_or_non_ascii_byte_in_the_braces_is_not_a_flag():
    # flagfmt.is_flag accepts these: the printable check in the sweep is the only thing that drops them
    bad = ["CSCTF{ab\x01cdefgh}", "CSCTF{ab\x1bcdefgh}", "CSCTF{ab\x7fcdefgh}", "CSCTF{ab\xe9cdefgh}"]
    assert all(FF.is_flag(t) for t in bad)
    copies = fw.env_copies(env_copy(env_pairs(LIVE_MAC), flags=1))
    x = fs.keyed_xor_sweep(_xor_tokens(bad), copies, 0, FF)
    assert x["hits"] == [] and x["tried"] == 4 * x["keys"] > 0
    good = fs.keyed_xor_sweep(_xor_tokens(["CSCTF{abXcdefgh}"]), copies, 0, FF)
    assert [h["flag"] for h in good["hits"]] == ["CSCTF{abXcdefgh}"]


def test_the_sweep_takes_no_key_from_a_copy_whose_crc_failed_even_when_handed_its_values():
    # env_copies never fills vars behind a bad CRC; the sweep holds the same rule on its own
    (good,) = fw.env_copies(env_copy(env_pairs(LIVE_MAC), flags=1))
    bad = dict(good, crc_valid=False)
    tok = _xor_tokens([FLAG])
    x = fs.keyed_xor_sweep(tok, [bad], 0, FF)
    assert x["hits"] == [] and x["keys"] == 0 and x["tried"] == 0
    assert [h["flag"] for h in fs.keyed_xor_sweep(tok, [good], 0, FF)["hits"]] == [FLAG]


def test_a_keyed_xor_result_needs_the_shape_length_while_the_prefix_is_unknown():
    ff = flagfmt.for_profile(_profile(prefixes=(), slug="b069-unknown"))
    copies = fw.env_copies(env_copy(env_pairs(LIVE_MAC), flags=1))
    short = "ab{cde}"                                       # 7 characters, one under MIN_SHAPE
    assert ff.is_flag(short) and len(short) == fs.MIN_SHAPE - 1
    x = fs.keyed_xor_sweep(_xor_tokens([short, "ab{cdef}"]), copies, 0, ff)
    assert [h["flag"] for h in x["hits"]] == ["ab{cdef}"]
    # the same short value is a hit once the event prefix is known
    known = flagfmt.for_profile(_profile(prefixes=("ab",), slug="b069-short"))
    assert [h["flag"] for h in fs.keyed_xor_sweep(_xor_tokens([short]), copies, 0, known)["hits"]] == [short]


def test_solve_reads_one_file_at_a_time_and_lets_it_go_before_the_next(monkeypatch, tmp_path):
    img, _ = make_radio()
    cd = tmp_path / "c"
    (cd / "files").mkdir(parents=True)
    (cd / "files" / "a_firmware.bin").write_bytes(img)
    (cd / "files" / "b_noise.bin").write_bytes(rnd(5000, 81))
    (cd / "files" / "c_firmware.bin").write_bytes(img)
    events = []

    class Tracked(bytes):
        def __del__(self):
            events.append("free " + self.name)

    def read(p):
        events.append("read " + p.name)
        b = Tracked(p.read_bytes())
        b.name = p.name
        return b

    walk = fs.walk_image

    def walk_image(name, data, *a, **k):
        events.append("walk " + Path(name).name)
        return walk(name, data, *a, **k)

    monkeypatch.setattr(fs, "_read", read)
    monkeypatch.setattr(fs, "walk_image", walk_image)
    res = fs.solve(cd, PROFILE, out=str(tmp_path / "o"))
    assert events == [f"{e} {n}" for n in ("a_firmware.bin", "b_noise.bin", "c_firmware.bin")
                      for e in ("read", "walk", "free")]
    assert list(res.flags) == [FLAG]
    assert sorted(p.name for p in (tmp_path / "o").iterdir()) == ["files_a_firmware.bin", "files_c_firmware.bin"]


def test_an_unknown_flag_prefix_lists_only_printable_shapes_of_some_length():
    ff = flagfmt.for_profile(_profile(prefixes=(), slug="b069-unknown"))
    assert not ff.known
    cpio = make_cpio({"a": b"x{y} \xff{zzzzzzzz} radio{long_enough}\n"})
    img, _ = make_bundle([("boot", rnd(900, 61)), ("rootfs", cpio)])
    rep, _ = fs.walk_image("fw.bin", img, ff)
    assert [f["flag"] for f in rep["flags"]] == ["radio{long_enough}"]
    assert any("flag prefix is not known" in n for n in rep["notes"])


# ---- the engine: solve, outputs, routing, intake, the command --------------------------------------

def test_solve_walks_the_challenge_folder_and_writes_the_report_inside_it(tmp_path):
    img, placed = make_radio()
    cd = tmp_path / "9001-radio"
    (cd / "files").mkdir(parents=True)
    (cd / "files" / "firmware.bin").write_bytes(img)
    (cd / "files" / "readme.txt").write_bytes(b"A recovery bundle. " * 20)
    (cd / "recon").mkdir()
    (cd / "recon" / "old.bin").write_bytes(img)                       # recon output is never an input
    res = fs.solve(cd, PROFILE)
    assert res.status == "candidate" and list(res.flags) == [FLAG]
    out = cd / "recon" / "firmware_sections" / "files_firmware.bin"
    rep = _json.loads((out / "report.json").read_text())
    assert rep["file"] == "files/firmware.bin" and rep["env"]["live"] == 1
    assert [e["name"] for e in rep["tables"][0]["entries"]] == ["boot", "env", "msgcat", "rootfs"]
    assert rep["xor"]["hits"][0]["flag"] == FLAG
    names = sorted(p.name for p in (out / "extracted").iterdir())
    assert names == [f"0000_rootfs_{placed[3][1]:#x}.zlib", f"0001_rootfs_{placed[3][1]:#x}.zlib_etc_init.d_S40admin",
                     f"0002_rootfs_{placed[3][1]:#x}.zlib_etc_motd"]
    assert (out / "extracted" / names[1]).read_bytes().startswith(b"#!/bin/sh\n# S40admin")
    assert ("carve", "recon/firmware_sections/files_firmware.bin/report.json") in [(e.kind, e.path) for e in res.evidence]
    assert sorted(p.name for p in (cd / "recon" / "firmware_sections").iterdir()) == ["files_firmware.bin"]
    with pytest.raises(FileNotFoundError):
        fs.solve(tmp_path / "nope", PROFILE)
    # a bare folder (no files/ or unpacked/): its recon output, bookkeeping files and links are not inputs
    flat = tmp_path / "flat"
    (flat / "recon").mkdir(parents=True)
    for name in ("fw.bin", "recon/copy.bin", "notes.md", ".sweep.json"):
        (flat / name).write_bytes(img)
    (flat / "link.bin").symlink_to(flat / "fw.bin")
    assert sorted(fs.challenge_files(flat)) == ["fw.bin"]


def test_a_token_that_two_files_carry_is_tried_once():
    line = "admin_token=%s\n" % xor_token(FLAG, LIVE_MAC)
    img, _ = make_radio(literal="# backup of the console script\n" + line, admin="#!/bin/sh\n" + line)
    rep, _ = fs.walk_image("firmware.bin", img, FF)
    assert rep["xor"]["tokens"] == 1 and len(rep["xor"]["token_list"]) == 1
    assert [h["flag"] for h in rep["xor"]["hits"]] == [FLAG]


def test_solve_reports_none_when_no_file_is_a_bundle_and_member_names_cannot_leave_the_folder(tmp_path):
    cd = tmp_path / "c"
    (cd / "files").mkdir(parents=True)
    (cd / "files" / "noise.bin").write_bytes(rnd(30000, 71))
    (cd / "files" / "note.txt").write_bytes(b"nothing here\n" * 30)
    (cd / "files" / "tiny.bin").write_bytes(b"DWFW")
    # NUL-separated name=value strings with no CRC in front (any program's environment block) are not an env
    (cd / "files" / "strings.bin").write_bytes(rnd(200, 73) + b"\x01LANG=C\x00PATH=/bin\x00HOME=/root\x00\x00" + rnd(200, 74))
    res = fs.solve(cd, PROFILE)
    assert res.status == "none" and list(res.flags) == [] and not (cd / "recon").exists()
    assert res.notes == "no section table and no U-Boot env in 4 file(s)"
    # ... a lone env with a valid CRC is: it is reported, with nothing else to walk
    (cd / "env").mkdir()
    (cd / "env" / "mtd1.bin").write_bytes(env_copy(env_pairs(LIVE_MAC), flags=1))
    lone = fs.solve(cd / "env", PROFILE, out=str(tmp_path / "lone"))
    assert lone.status == "unsure" and "env copy 0 @0x0: crc ok, flags 1, 4 variables  LIVE" in lone.notes
    hostile = make_cpio({"../../../escape.txt": b"x", "/abs/olute": b"y", ".hidden": b"z"})
    img, _ = make_bundle([("boot", rnd(800, 72)), ("rootfs", hostile)])
    (cd / "files" / "fw.img").write_bytes(img)
    out = tmp_path / "out"
    assert fs.solve(cd, PROFILE, out=str(out)).status == "unsure"
    files = sorted(p.relative_to(tmp_path).as_posix() for p in tmp_path.rglob("*")
                   if p.is_file() and not {"files", "env", "lone"} & set(p.parts))
    assert files == ["out/files_fw.img/extracted/0000_rootfs_.._.._.._escape.txt", "out/files_fw.img/extracted/0001_rootfs__abs_olute",
                     "out/files_fw.img/extracted/0002_rootfs_.hidden", "out/files_fw.img/report.json"]


def test_a_bundle_routes_to_the_engine_by_magic_name_or_words(tmp_path):
    from ctf.engines import router
    img, _ = make_bundle(PLAIN)
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "blob.dat").write_bytes(img)                    # the magic
    (tmp_path / "b").mkdir()
    (tmp_path / "b" / "radio-firmware-v2.bin").write_bytes(rnd(100, 81))   # the name
    (tmp_path / "c").mkdir()
    (tmp_path / "c" / "notes.txt").write_text("plain words")
    for folder in ("a", "b"):
        assert "toolkits.firmware_sections" in [h.manifest.id for h in router.route("misc", "Operation Dawn", tmp_path / folder)]
    assert "toolkits.firmware_sections" not in [h.manifest.id for h in router.route("misc", "Operation Dawn", tmp_path / "c")]
    ids = [h.manifest.id for h in router.route("reverse engineering", "responders pulled a software recovery bundle",
                                               tmp_path / "c")]
    assert "toolkits.firmware_sections" in ids


def test_intake_runs_the_engine_on_a_firmware_file_with_no_model(tmp_path):
    from ctf.engines import manifest
    from ctf.intake import engines as E
    from ctf.intake import guard as G
    ms = manifest.discover()
    img, _ = make_radio()
    cd = tmp_path / "9002-radio"
    (cd / "unpacked").mkdir(parents=True)
    (cd / "unpacked" / "firmware.bin").write_bytes(img)
    guard = G.Guard("hook", (), "test")
    p = E.plan(ms, "reverse engineering", "a software recovery bundle", cd / "unpacked", guard=guard)
    job = next(j for j in p.jobs if j.engine == "toolkits.firmware_sections")
    assert job.manifest.intake.run == "challenge" and job.manifest.intake.select == "files"
    assert not job.manifest.intake.spawns and job.manifest.cost_class == "cheap"
    # select = "files": a category and brief that route nowhere near firmware still run it on the file
    other = E.plan(ms, "web", "a login page", cd / "unpacked", guard=guard)
    assert "toolkits.firmware_sections" in {j.engine for j in other.jobs}
    (cd / "plain").mkdir()
    (cd / "plain" / "page.html").write_text("<html></html>")
    assert "toolkits.firmware_sections" not in {j.engine for j in E.plan(ms, "web", "a login page", cd / "plain", guard=guard).jobs}
    ctx = E.Context(challenge_dir=cd, folder=cd / "unpacked", out_root=cd / "recon" / "engines",
                    profile=event.load("csctf"), guard=guard, root=REPO, python=sys.executable,
                    challenge_id="9002", record=False)
    run = E.run_job(job, ctx)
    assert run.status == "ok", (cd / run.errors).read_text()
    assert run.flags == (FLAG,) and run.result_status == "candidate"
    assert (cd / "recon" / "firmware_sections" / "unpacked_firmware.bin" / "report.json").is_file()


def test_cli_prints_the_walk_and_the_result_json_last(tmp_path, capsys):
    img, placed = make_radio()
    f = tmp_path / "firmware.bin"
    f.write_bytes(img)
    assert fs.main([str(f), "--event", "csctf", "--out", str(tmp_path / "o")]) == 0
    lines = capsys.readouterr().out.strip().splitlines()
    from ctf.result import SolverResult
    res = SolverResult.from_json(lines[-1])
    assert res.status == "candidate" and list(res.flags) == [FLAG]
    text = "\n".join(lines[:-1])
    assert "section table @0x20: 4 records, stride 28, little-endian, crc32" in text
    assert f"[zlib dictionary of the stream at {placed[3][1]:#x}]" in text
    assert "LIVE (higher flags counter (2 over 1))" in text
    assert f"dictionary = section msgcat (DICTID {zlib.adler32(MSGCAT):#010x})" in text
    assert f"written: {tmp_path / 'o' / _safe_name(f) / 'report.json'}" in text
    assert fs.main([str(tmp_path / "missing.bin"), "--event", "csctf"]) == 2
    assert "no such file" in capsys.readouterr().err


def _safe_name(path):
    return fs._safe(str(path))


def main():
    for t in (test_squashfs, test_squashfs_zstd, test_jffs2, test_dtb, test_dtb_ambiguous_property,
              test_uboot_env, test_contract, test_signals):
        t()
    print()
    if FAILED:
        print(f"FAILED {len(FAILED)}: " + ", ".join(FAILED))
        return 1
    print("all firmware_walk checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
