"""B-135: ext volumes in the pull sweep (ctf/recover/extfs.py) -- the file tree with mtimes, orphan inodes,
and validated ELF programs carved from the blocks the block bitmap marks free -- and B-011's decompile
intake picking those carves up from the sweep's scratch copy. Every volume is built in tests/ext_fixture.py.
"""
from __future__ import annotations

import json
import struct

import pytest

import archive_expand
import decompile_intake as di
import ext_fixture as ef
from ctf import event, sweep
from ctf.recover import extfs

CSCTF = event.load("csctf")
ELF = ef.elf(b"\x55\x48\x89\xe5\x90\xc3", extra=b"\x90" * 500, pad_to=2300)       # 2492 bytes


@pytest.fixture(autouse=True)
def _offline(monkeypatch, tmp_path):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "wd"))
    monkeypatch.setattr(archive_expand.pw, "candidates", lambda: [b"infected"])


def _blocks_used(raw: bytes, vol) -> list[bool]:
    fsd = extfs._fsd()
    sb = fsd.parse_ext_superblock(raw[:2048])
    groups = extfs._groups(memoryview(raw), sb, vol.first_data_block)
    return extfs.allocation_bitmap(memoryview(raw), sb, vol.first_data_block, groups, [])


def test_free_block_elf_is_carved_with_its_blocks_and_an_allocated_one_is_not():
    img = ef.Ext(blocks=512)
    d = img.mkdir("usr")
    img.add("tool", ELF, parent=d, mode=0o100755, mtime=1_700_000_123)     # allocated: a file, not a carve
    first = img.free_write(ELF, block=400)[0]
    raw = img.build()
    vol = extfs.read_volume(raw)
    assert [(c.kind, c.blocks, c.data) for c in vol.carves] == [("elf", [(first, 3)], ELF)]
    assert [(f.path, f.mtime, f.data == ELF) for f in vol.files] == [("usr/tool", 1_700_000_123, True)]
    used = _blocks_used(raw, vol)
    assert used[0] and not used[400] and not used[402] and used[img.dir_block[2]]
    assert vol.free_blocks == used.count(False) == 512 - len(img.used)


def test_an_elf_split_around_an_allocated_block_is_joined_like_blkls():
    img = ef.Ext(blocks=512)
    img.free_write(ELF[:2048], block=400)              # blocks 400-401
    img.write_raw(402, b"allocated in between", mark_used=True)
    img.free_write(ELF[2048:], block=403)              # block 403
    vol = extfs.read_volume(img.build())
    assert len(vol.carves) == 1
    c = vol.carves[0]
    assert c.data == ELF and c.blocks == [(400, 2), (403, 1)]
    assert extfs.carve_name(c) == "ext-unallocated/blk00000400.elf"


def test_4k_blocks_64bit_descriptors_and_extents():
    img = ef.Ext(blocks=256, block_size=4096, extents=True, wide=True)
    v = img.mkdir("var")
    img.add("a.cfg.enc", b"x" * 9000, parent=v, mtime=1_790_914_385)
    img.free_write(ELF, block=200)
    vol = extfs.read_volume(img.build())
    assert vol.block_size == 4096 and vol.first_data_block == 0
    assert [(f.path, f.size, f.mtime) for f in vol.files] == [("var/a.cfg.enc", 9000, 1_790_914_385)]
    assert [(c.blocks, c.data) for c in vol.carves] == [([(200, 1)], ELF)]


def _two_groups(csum: bool) -> bytes:
    img = ef.Ext(blocks=1024, bpg=512, csum=csum)
    img.uninit = {1}
    img.free_write(ELF, block=800)                     # in group 1 (blocks 513..1023)
    raw = bytearray(img.build())
    bs = 1024
    raw[img.bitmaps[1] * bs:(img.bitmaps[1] + 1) * bs] = b"\xff" * bs   # a stale, never-initialised bitmap
    return bytes(raw)


def test_block_uninit_group_is_free_only_under_a_checksum_feature():
    with_csum = extfs.read_volume(_two_groups(True))
    assert [c.first_block for c in with_csum.carves] == [800]
    without = extfs.read_volume(_two_groups(False))
    assert without.carves == []                        # the flag is not trusted without gdt/metadata csum


def test_second_group_bitmap_maps_blocks_from_first_data_block():
    img = ef.Ext(blocks=1024, bpg=512)
    img.free_write(ELF, block=600)
    raw = img.build()
    vol = extfs.read_volume(raw)
    used = _blocks_used(raw, vol)
    assert [c.first_block for c in vol.carves] == [600]
    assert not used[600] and not used[602] and used[img.bitmaps[1]]
    # flip the bit for block 601 (group 1, index 601 - 1 - 512 = 88) to "in use": the free stream now
    # skips it, so what is carved there is joined from 600, 602, 603 and is no longer the program
    raw2 = bytearray(raw)
    raw2[img.bitmaps[1] * 1024 + 88 // 8] |= 1 << (88 % 8)
    cut = extfs.read_volume(bytes(raw2)).carves
    assert [c.blocks for c in cut] == [[(600, 1), (602, 2)]] and cut[0].data != ELF


def test_orphan_inodes_are_listed_and_exported_only_when_their_blocks_read():
    img = ef.Ext(blocks=512)
    gone = img.orphan(mode=0o100755, mtime=1_790_914_382)                  # ext4-style: map cleared
    kept = img.orphan(mode=0o100644, mtime=1_790_914_300, data=b"old note\n" * 10)
    vol = extfs.read_volume(img.build())
    by = {o.inode: o for o in vol.orphans}
    assert by[gone].data is None and "zeros" in by[gone].why and by[gone].mode == 0o100755
    assert by[gone].deleted and by[gone].mtime == 1_790_914_382
    assert by[kept].data == b"old note\n" * 10
    doc = json.loads(extfs.listing(vol))
    assert {o["path"] for o in doc["orphans"]} == {f"inode-{gone}", f"inode-{kept}"}


def test_partitions_and_declines():
    vol = ef.Ext(blocks=256)
    vol.mkdir("etc")
    body = vol.build()
    mbr = bytearray(2048 * 512)
    mbr[446 + 4] = 0x83
    struct.pack_into("<II", mbr, 446 + 8, 2048, len(body) // 512)
    mbr[510:512] = b"\x55\xaa"
    disk = bytes(mbr) + body
    assert extfs.find_volumes(disk) == [(2048 * 512, "mbr p1")]
    assert extfs.find_volumes(b"\0" * 4096) == []
    meta = bytearray(body)
    struct.pack_into("<I", meta, 1024 + 96, struct.unpack_from("<I", meta, 1024 + 96)[0] | 0x10)
    with pytest.raises(extfs.ExtError, match="meta_bg"):
        extfs.read_volume(bytes(meta))
    with pytest.raises(extfs.ExtError, match="superblock"):
        extfs.read_volume(b"\0" * 4096)


def test_a_truncated_image_says_so_and_never_carves_past_its_end():
    img = ef.Ext(blocks=512)
    img.free_write(ELF, block=500)
    raw = img.build()[: 480 * 1024]
    vol = extfs.read_volume(raw)
    assert vol.carves == [] and any("bytes end at block 480" in n for n in vol.notes)


def pulled(tmp_path, files: dict, cid=9073):
    ch = tmp_path / "wd" / f"{cid}-x"
    (ch / "files").mkdir(parents=True)
    (ch / "challenge.json").write_text(json.dumps({"id": cid, "name": "x", "category": "Forensics",
                                                   "description": "a historian volume"}))
    for name, data in files.items():
        (ch / "files" / name).write_bytes(data)
    return ch


def test_the_pull_sweep_writes_listing_files_and_carves_and_decompile_intake_takes_the_carve(tmp_path):
    img = ef.Ext(blocks=1024, extents=True)
    var = img.mkdir("var")
    log = img.mkdir("log", parent=var)
    img.add("historian.log", b"2026-10-02 04:13 historian_enc[2761400]: start\n", parent=log, mtime=1_790_914_400)
    img.add("helper", ELF, parent=var, mode=0o100755)           # an allocated ELF: exported, not a carve
    img.orphan(mode=0o100755, mtime=1_790_914_382)
    img.free_write(ELF.replace(b"\x90" * 500, b"\xcc" * 500), block=900)
    ch = pulled(tmp_path, {"evidence-flat.vmdk": img.build()})
    rep = sweep.sweep(ch, CSCTF)
    base = ch / "unpacked" / "evidence-flat.vmdk.unpacked"
    carve = base / "ext-unallocated" / "blk00000900.elf"
    assert carve.read_bytes() == ELF.replace(b"\x90" * 500, b"\xcc" * 500)
    assert (base / "ext" / "var" / "log" / "historian.log").read_bytes().startswith(b"2026-10-02 04:13")
    doc = json.loads((base / "ext-listing.json").read_text())
    assert {"path": "var/log/historian.log", "mtime": 1_790_914_400} .items() <= \
        next(r for r in doc["files"] if r["path"] == "var/log/historian.log").items()
    assert doc["unallocated_carves"] == [{"name": "ext-unallocated/blk00000900.elf", "kind": "elf",
                                          "size": len(ELF), "blocks": [[900, 3]]}]
    chains = {e.to_dict()["chain"] for e in rep.manifest}
    assert "evidence-flat.vmdk -> ext-unallocated/blk00000900.elf" in chains
    assert any("ext volume at offset 0 (bare)" in n and "1 object(s) carved" in n for n in rep.notes)
    cands = [p.relative_to(ch).as_posix() for p in di._candidate_files(ch)]
    assert "unpacked/evidence-flat.vmdk.unpacked/ext-unallocated/blk00000900.elf" in cands
    assert not any(c.endswith("ext/var/helper") for c in cands)   # the rest of the scratch copy stays out


def test_decompile_intake_names_the_same_carve_folder():
    assert extfs.CARVE_DIR in di._CARVE_DIRS


@pytest.mark.needs_tool("radare2")
def test_decompile_intake_decompiles_the_carved_program_statically(tmp_path):
    img = ef.Ext(blocks=512)
    img.free_write(ELF, block=300)
    ch = pulled(tmp_path, {"disk.img": img.build()})
    sweep.sweep(ch, CSCTF)
    res = di.solve(ch, CSCTF, timeout=120)
    assert res.status != "blocked", res.notes
    out = list((ch / "recon" / "decompile").rglob("*.c"))
    assert any("blk00000300.elf" in str(p) for p in out), res.notes


# ----------------------------------------------------------------------------- verification round 1
BIG = ef.elf(b"\x55\x48\x89\xe5\x90\xc3", extra=b"\x90" * 5000, pad_to=5200)       # two 4 KiB blocks


def test_free_space_over_one_window_is_carved_in_overlapping_windows_to_its_last_block():
    # 128 MiB of 4 KiB blocks: the free stream is longer than WINDOW, so it is carved window by window.
    img = ef.Ext(blocks=32768, block_size=4096)
    meta = len(img.used)                               # superblock, descriptors, bitmaps, inode table, root
    assert max(img.used) == meta - 1                   # all metadata sits below the first free block
    seam = extfs.WINDOW // 4096 + meta - 1             # its stream bytes straddle the first window's end
    for block, body in ((100, ELF), (seam, BIG), (32000, ELF)):
        img.free_write(body, block=block)
    vol = extfs.read_volume(img.build())
    assert [(c.first_block, c.data == body) for c, body in zip(vol.carves, (ELF, BIG, ELF))] == \
        [(100, True), (seam, True), (32000, True)]
    assert len(vol.carves) == 3
    assert vol.carves[1].blocks == [(seam, 2)]
    assert (seam - meta) * 4096 < extfs.WINDOW < (seam - meta) * 4096 + len(BIG)
    stream = (32768 - meta) * 4096                     # the fixture's geometry: block 32000 is in the last
    last = (stream - extfs.WINDOW + extfs.STEP - 1) // extfs.STEP * extfs.STEP          # window only
    assert (32000 - meta) * 4096 >= last - extfs.STEP + extfs.WINDOW
    assert any("48 MiB windows" in n for n in vol.notes)


def test_a_gpt_partition_is_found_at_its_first_lba():
    import recover_fixtures as rf
    body = ef.Ext(blocks=256).build()
    assert extfs.find_volumes(rf.gpt(body, first=40)) == [(40 * 512, "gpt p1")]
    assert extfs.find_volumes(rf.gpt(body, first=40, slot=2)) == [(40 * 512, "gpt p3")]   # empty slots skipped
    vol = extfs.read_volume(rf.gpt(body, first=40), 40 * 512, "gpt p1")
    assert vol.how == "gpt p1" and vol.volume_name == "HISTORIAN01"


def test_reserved_inodes_are_not_orphans_and_deleted_is_dtime_or_no_links():
    img = ef.Ext(blocks=512)
    img.reserved(8, b"journal block " * 300)          # an ext3/4 journal: a regular file at inode 8
    live = img.orphan(data=b"lost+found material\n", dtime=0, links=1)
    unlinked = img.orphan(data=b"unlinked\n", dtime=0, links=0)
    dtimed = img.orphan(data=b"dtime set\n", dtime=1_790_914_390, links=1)
    vol = extfs.read_volume(img.build())
    by = {o.inode: o for o in vol.orphans}
    assert set(by) == {live, unlinked, dtimed}
    assert 8 not in {f.inode for f in vol.files}
    assert (by[live].deleted, by[unlinked].deleted, by[dtimed].deleted) == (False, True, True)
    assert by[unlinked].data == b"unlinked\n"


def _huge_count(raw: bytes, count: int) -> bytes:
    out = bytearray(raw)
    struct.pack_into("<I", out, 1024 + 4, count)        # s_blocks_count_lo
    struct.pack_into("<I", out, 1024 + 32, count)       # s_blocks_per_group: one group, the table still fits
    return bytes(out)


def test_a_huge_declared_block_count_costs_only_the_bytes_present():
    img = ef.Ext(blocks=512)
    img.free_write(ELF, block=400)
    raw = _huge_count(img.build(), 1 << 24)
    vol = extfs.read_volume(raw)
    assert vol.blocks_count == 1 << 24
    assert [c.first_block for c in vol.carves] == [400]   # group 0's bitmap is read over the blocks present
    assert any("bytes end at block 512 of 16777216" in n for n in vol.notes)
    fsd = extfs._fsd()
    sb = fsd.parse_ext_superblock(raw[:2048])
    used = extfs.allocation_bitmap(memoryview(raw), sb, 1, extfs._groups(memoryview(raw), sb, 1), [])
    assert len(used) == 512       # never one entry per declared block (that cost ~0.7 s CPU and 190 MB)


def test_a_failing_ext_read_keeps_the_ntfs_members_of_the_same_content(monkeypatch):
    import recover_fixtures as rf
    from ctf import recover
    img = rf.Ntfs()
    img.add("kept.txt", b"kept body")

    def boom(_data):
        raise RuntimeError("ext reader broke")

    monkeypatch.setattr(extfs, "find_volumes", boom)
    notes = []
    got = {sub[0]: body for sub, body, _o in recover.derive(("disk.img",), img.build(), None, notes)}
    assert got["allocated/kept.txt"] == b"kept body" and "ntfs-listing.txt" in got
    assert any("ext volume read failed" in n and "RuntimeError: ext reader broke" in n for n in notes)


def test_an_ext_file_over_the_walks_member_limit_is_listed_unexported_with_the_reason():
    from ctf import recover
    img = ef.Ext(blocks=512)
    img.add("small.txt", b"small body")
    img.add("big.bin", b"B" * 6000)
    walk = archive_expand.Walk(max_member=4096)
    notes = []
    got = {sub[0]: body for sub, body, _o in recover.derive(("disk.img",), img.build(), walk, notes)}
    assert got["ext/small.txt"] == b"small body"
    assert "ext/big.bin" not in got
    rows = {r["path"]: r for r in json.loads(got[extfs.LISTING])["files"]}
    assert rows["small.txt"]["exported"] is True and "why" not in rows["small.txt"]
    assert rows["big.bin"]["exported"] is False
    assert rows["big.bin"]["why"] == "6000 bytes: over the walk's budget"
