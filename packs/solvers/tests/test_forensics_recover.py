"""B-029: ctf/recover — the NTFS walk with deleted-file export, the tracked-change views of a .docx and the
single-byte XOR crib, each on synthetic bytes built in tests/recover_fixtures.py."""
import struct
import types
import zipfile

import pytest

import recover_fixtures as rf
from ctf import event, flagfmt
from ctf.recover import derive, ntfs, ooxml, xorcrib

CSCTF = flagfmt.for_profile(event.load("csctf"))


def by_path(vol):
    return {f.path: f for f in vol.files}


def pattern(n: int, seed: int) -> bytes:
    return bytes((i * 31 + seed * 7 + (i >> 8)) % 251 for i in range(n))


# ---------------------------------------------------------------- NTFS

def test_deleted_and_allocated_files_resident_and_not_are_read_with_paths():
    img = rf.Ntfs()
    users = img.add("Staff", directory=True)
    clerk = img.add("clerk", parent=users, directory=True)
    img.add("small.txt", b"resident body", parent=clerk)
    img.add("gone.txt", b"resident and deleted", parent=clerk, deleted=True)
    big, gone_big = pattern(9000, 1), pattern(12000, 2)
    img.add("big.bin", big, parent=users)
    img.add("audit.log", gone_big, parent=clerk, deleted=True)
    vol = ntfs.read_volume(img.build())
    files = by_path(vol)
    assert files["Staff/clerk/small.txt"].data == b"resident body"
    assert files["Staff/clerk/small.txt"].resident and not files["Staff/clerk/small.txt"].deleted
    assert files["Staff/clerk/gone.txt"].deleted and files["Staff/clerk/gone.txt"].data == b"resident and deleted"
    assert files["Staff/big.bin"].data == big and not files["Staff/big.bin"].deleted
    assert files["Staff/clerk/audit.log"].deleted and files["Staff/clerk/audit.log"].data == gone_big
    assert files["Staff/clerk/audit.log"].size == 12000
    assert files["Staff/clerk"].directory and files["Staff"].directory
    assert {f.path for f in vol.deleted} == {"Staff/clerk/gone.txt", "Staff/clerk/audit.log"}


def test_a_fragmented_file_is_read_in_vcn_order_and_a_sparse_run_is_zeros():
    img = rf.Ntfs()
    data = pattern(3 * rf.CS, 3)
    img.add("frag.bin", data, runs=[(120, 1), (60, 1), (90, 1)])
    sparse = pattern(rf.CS, 4) + bytes(rf.CS) + pattern(100, 5)
    img.add("sparse.bin", sparse, runs=[(130, 1), (None, 1), (131, 1)], flags=0x8000)
    files = by_path(ntfs.read_volume(img.build()))
    assert files["frag.bin"].data == data
    assert files["sparse.bin"].data == sparse


def test_a_fragmented_mft_is_walked_through_record_zeros_runlist():
    # records 0-31 in clusters 4-11, records 32-63 far away in clusters 200-207
    img = rf.Ntfs(mft_runs=[(4, 8), (200, 8)])
    img.cursor = 20
    body = pattern(6000, 6)
    img.add("late.bin", body, deleted=True, num=40)
    raw = img.build()
    vol = ntfs.read_volume(raw)
    assert by_path(vol)["late.bin"].data == body
    assert not vol.notes
    cut = ntfs.read_volume(raw[:200 * rf.CS])                  # the second run of the $MFT is gone
    assert "late.bin" not in by_path(cut)
    assert any("past the end of the image" in n for n in cut.notes)


def test_an_extension_record_and_a_data_attribute_split_over_two_extents_are_joined():
    img = rf.Ntfs()
    body = pattern(2 * rf.CS + 500, 7)
    img.add("split.bin", body, runs=[(150, 1), (70, 2)], split=True)
    vol = ntfs.read_volume(img.build())
    assert by_path(vol)["split.bin"].data == body
    assert [f.path for f in vol.files].count("split.bin") == 1


def test_named_streams_are_their_own_entries():
    img = rf.Ntfs()
    img.add("cover.txt", b"nothing to see", ads={"Zone.Identifier": b"[ZoneTransfer]", "hidden": b"ads body"})
    files = by_path(ntfs.read_volume(img.build()))
    assert files["cover.txt:hidden"].data == b"ads body"
    assert files["cover.txt:hidden"].stream == "hidden"
    assert files["cover.txt"].data == b"nothing to see" and files["cover.txt"].stream is None


def test_a_deleted_file_whose_clusters_were_reused_is_marked_overwritten():
    img = rf.Ntfs()
    img.add("new.bin", pattern(rf.CS, 8), runs=[(100, 1)])
    img.add("old.bin", pattern(2 * rf.CS, 9), runs=[(99, 2)], deleted=True)       # cluster 100 reused
    img.add("intact.bin", pattern(rf.CS, 10), runs=[(140, 1)], deleted=True)
    files = by_path(ntfs.read_volume(img.build()))
    assert files["old.bin"].overwritten and files["old.bin"].data is not None
    assert not files["intact.bin"].overwritten
    assert not files["new.bin"].overwritten


def test_a_deleted_run_that_only_touches_an_allocated_run_is_not_overwritten():
    img = rf.Ntfs()
    img.add("live.bin", pattern(rf.CS, 8), runs=[(100, 1)])                    # cluster 100 allocated
    img.add("after.bin", pattern(rf.CS, 9), runs=[(101, 1)], deleted=True)     # starts where it ends
    img.add("before.bin", pattern(rf.CS, 10), runs=[(99, 1)], deleted=True)    # ends where it starts
    img.add("same.bin", pattern(rf.CS, 11), runs=[(100, 1)], deleted=True)
    files = by_path(ntfs.read_volume(img.build()))
    assert not files["after.bin"].overwritten and not files["before.bin"].overwritten
    assert files["same.bin"].overwritten


def test_an_extension_records_runs_are_allocated_as_its_base_record_is():
    img = rf.Ntfs()
    body = pattern(3 * rf.CS, 7)
    n = img.add("split.bin", body, runs=[(150, 1), (70, 2)], split=True)        # in use
    img.add("old.bin", pattern(rf.CS, 9), runs=[(71, 1)], deleted=True)        # in split.bin's 2nd extent
    gone = img.add("gone.bin", pattern(2 * rf.CS, 3), runs=[(160, 1), (80, 1)], split=True, deleted=True)
    img.add("older.bin", pattern(rf.CS, 4), runs=[(80, 1)], deleted=True)       # in gone.bin's 2nd extent
    x = img.next                    # the extension records build() gives split.bin, then gone.bin
    # their in-use flags disagree with their base records: the base record's state is what counts
    img.raw_record(x, rf.record(x, [rf.nonresident(0x80, [(70, 2)], len(body), start_vcn=1, alloc=3 * rf.CS)],
                                in_use=False, base=n))
    img.raw_record(x + 1, rf.record(x + 1, [rf.nonresident(0x80, [(80, 1)], 2 * rf.CS, start_vcn=1,
                                                           alloc=2 * rf.CS)], in_use=True, base=gone))
    files = by_path(ntfs.read_volume(img.build()))
    # both extents are read (cluster 71 now holds old.bin's bytes: the fixture wrote them last)
    assert files["split.bin"].data[:2 * rf.CS] == body[:2 * rf.CS] and len(files["split.bin"].data) == len(body)
    assert files["old.bin"].overwritten
    assert files["gone.bin"].deleted and not files["older.bin"].overwritten


def test_compressed_encrypted_and_out_of_image_streams_give_a_reason_not_bytes():
    img = rf.Ntfs(clusters=160)
    img.add("packed.bin", pattern(rf.CS, 11), runs=[(100, 1)], flags=0x0001)
    img.add("efs.bin", pattern(rf.CS, 12), runs=[(101, 1)], flags=0x4000)
    img.add("past.bin", pattern(rf.CS, 13), runs=[(100, 1)])
    raw = img.build()
    # point past.bin's run beyond the image: rebuild its record by hand
    img2 = rf.Ntfs(clusters=160)
    img2.raw_record(16, rf.record(16, [rf.file_name("past.bin", rf.ROOT),
                                       rf.nonresident(0x80, [(5000, 1)], rf.CS)]))
    files = by_path(ntfs.read_volume(raw))
    assert files["packed.bin"].data is None and "compressed" in files["packed.bin"].why
    assert files["efs.bin"].data is None and "EFS" in files["efs.bin"].why
    past = by_path(ntfs.read_volume(img2.build()))["past.bin"]
    assert past.data is None and "outside the image" in past.why


def test_a_parent_missing_from_the_mft_puts_the_file_under_orphan():
    img = rf.Ntfs()
    img.add("lost.txt", b"no parent", parent=33)
    assert by_path(ntfs.read_volume(img.build()))["$Orphan/lost.txt"].orphan


def test_the_win32_name_wins_over_the_dos_name_whichever_comes_first():
    img = rf.Ntfs()
    n = img.add("NIGHTA~1.DOC", b"x", names=[("night_audit.docx", 1)])
    # the fixture writes the first name as Win32 (namespace 1): rewrite it as DOS (2) by hand
    img.raw_record(n, rf.record(n, [rf.file_name("NIGHTA~1.DOC", rf.ROOT, 2),
                                    rf.file_name("night_audit.docx", rf.ROOT, 1), rf.resident(0x80, b"x")]))
    assert "night_audit.docx" in by_path(ntfs.read_volume(img.build()))


def test_metafiles_and_extend_are_listed_but_flagged_system():
    img = rf.Ntfs()
    ext = img.add("$Extend", directory=True, num=11)
    img.add("$UsnJrnl", b"usn records", parent=ext, num=24)
    img.add("user.txt", b"user data")
    files = by_path(ntfs.read_volume(img.build()))
    assert files["$MFT"].system and files["$Extend/$UsnJrnl"].system
    assert not files["user.txt"].system


def test_a_broken_record_zero_falls_back_to_a_contiguous_read_and_says_so():
    img = rf.Ntfs()
    img.break_record0 = True
    img.add("still.txt", b"found anyway")
    vol = ntfs.read_volume(img.build())
    assert by_path(vol)["still.txt"].data == b"found anyway"
    assert any("record (0) does not parse" in n for n in vol.notes)


def test_a_record_that_fails_its_checks_is_counted_and_named():
    img = rf.Ntfs()
    img.add("ok.txt", b"fine")
    img.raw_record(30, rf.record(30, [rf.file_name("torn.txt", rf.ROOT), rf.resident(0x80, b"t")],
                                 break_usa=True))
    vol = ntfs.read_volume(img.build())
    assert vol.bad_records == [30]
    assert any("fail the record checks" in n and "30" in n for n in vol.notes)
    assert "torn.txt" not in by_path(vol)


def test_volumes_are_found_bare_in_an_mbr_partition_and_in_a_gpt_partition():
    raw = rf.Ntfs(clusters=64).build()
    assert ntfs.find_volumes(raw) == [(0, "bare")]
    assert ntfs.find_volumes(rf.mbr(raw, lba=63)) == [(63 * 512, "mbr p1")]
    assert ntfs.find_volumes(rf.gpt(raw, first=40)) == [(40 * 512, "gpt p1")]
    assert ntfs.find_volumes(b"\x00" * 4096) == []
    with pytest.raises(ntfs.NtfsError, match="no valid NTFS boot sector"):
        ntfs.read_volume(b"\x00" * 4096)


def test_a_gpt_entry_after_an_empty_slot_is_found():
    raw = rf.Ntfs(clusters=64).build()
    assert ntfs.find_volumes(rf.gpt(raw, first=40, slot=1)) == [(40 * 512, "gpt p2")]
    assert ntfs.find_volumes(rf.gpt(raw, first=40, slot=5)) == [(40 * 512, "gpt p6")]


def test_an_mbr_entry_of_type_zero_is_an_unused_slot():
    raw = rf.Ntfs(clusters=64).build()
    assert ntfs.find_volumes(rf.mbr(raw, lba=63, ptype=0)) == []
    assert ntfs.find_volumes(rf.mbr(raw, lba=63, ptype=0x17)) == [(63 * 512, "mbr p1")]


def test_a_gpt_table_cut_off_inside_an_entry_ends_the_scan():
    disk = rf.gpt(rf.Ntfs(clusters=64).build(), first=40)
    assert ntfs.find_volumes(disk[:1024 + 36]) == []           # entry 1 stops inside its first-LBA field


def test_a_file_name_attribute_too_short_to_hold_a_name_is_skipped():
    # in the walk, filesystem_depth's record check refuses the record first: counted, never a crash
    img = rf.Ntfs()
    img.add("named.txt", b"n")
    img.raw_record(21, rf.record(21, [rf.resident(0x30, b"\x05" * 65), rf.resident(0x80, b"m")]))
    vol = ntfs.read_volume(img.build())
    assert by_path(vol)["named.txt"].data == b"n" and vol.bad_records == [21]
    # _file_names takes any parsed record: one value too short for the name header, one a byte short of
    # the name-length and namespace bytes, then a whole one
    fsd = ntfs._fsd()

    def fn(value: bytes):
        return fsd.NtfsAttribute(0x30, 0, "", True, 0, value, (), len(value), len(value), len(value))

    whole = rf.file_name("named.txt", rf.ROOT)
    value = whole[24:24 + struct.unpack_from("<I", whole, 16)[0]]
    rec = types.SimpleNamespace(attributes=(fn(bytes(range(1, 41))), fn(value[:65]), fn(value)))
    assert ntfs._file_names(rec) == [(rf.ROOT, 1, "named.txt")]


def test_listing_names_each_files_state_and_reasons():
    img = rf.Ntfs()
    img.add("kept.txt", b"k")
    img.add("gone.txt", b"g", deleted=True)
    img.add("packed.bin", pattern(rf.CS, 1), runs=[(100, 1)], flags=0x0001)
    text = ntfs.listing(ntfs.read_volume(img.build()))
    lines = {line.split()[3]: line for line in text.splitlines() if not line.startswith("#")}
    assert "deleted" in lines["gone.txt"] and "in-use" in lines["kept.txt"]
    assert "compressed" in lines["packed.bin"]
    assert "metafile, not exported" in lines["$MFT"]


# ---------------------------------------------------------------- derive (one content)

def test_derive_exports_files_under_deleted_and_allocated_and_writes_a_listing():
    img = rf.Ntfs()
    d = img.add("docs", directory=True)
    img.add("kept.txt", b"kept body", parent=d)
    img.add("gone.txt", pattern(5000, 1), parent=d, deleted=True)
    img.add("packed.bin", pattern(rf.CS, 2), runs=[(100, 1)], flags=0x0001)
    notes = []
    got = {sub[0]: (body, opens) for sub, body, opens in derive(("disk.img",), img.build(), None, notes)}
    assert got["allocated/docs/kept.txt"] == (b"kept body", True)
    assert got["deleted/docs/gone.txt"] == (pattern(5000, 1), True)
    assert got["ntfs-listing.txt"][1] is False and b"gone.txt" in got["ntfs-listing.txt"][0]
    assert not any("packed" in k or "$MFT" in k for k in got)       # no bytes / a metafile: listed only
    assert any("1 deleted file(s)" in n and "2 exported" in n for n in notes)


def test_derive_prefixes_a_partitions_files():
    img = rf.Ntfs()
    img.add("p.txt", b"in a partition")
    got = {sub[0] for sub, _b, _o in derive(("disk.img",), rf.mbr(img.build()), None, [])}
    assert "mbr-p1/allocated/p.txt" in got and "mbr-p1/ntfs-listing.txt" in got


def test_derive_unwraps_a_fixed_vhd_to_its_raw_disk():
    raw = rf.Ntfs(clusters=64).build()
    out = derive(("disk.vhd",), rf.fixed_vhd(raw), None, [])
    assert out == [(("disk.vhd.raw",), raw, True)]


def test_derive_notes_an_ewf2_image_and_an_unreadable_docx():
    notes = []
    assert derive(("x.Ex01",), b"EVF2\r\n\x81\x00" + bytes(100), None, notes) == []
    bad = rf.docx("", raw_document=b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]><w:document/>')
    assert derive(("x.docx",), bad, None, notes) == []
    assert any("EWF2" in n for n in notes) and any("DOCTYPE" in n for n in notes)


def test_derive_counts_against_the_walk_budget():
    import archive_expand
    img = rf.Ntfs()
    for i in range(5):
        img.add(f"f{i}.txt", f"body {i}".encode())
    walk = archive_expand.Walk(max_members=3)
    out = derive(("disk.img",), img.build(), walk, [])
    assert len(out) == 3                      # the listing and two files, then the budget is spent
    assert walk.full and any("budget" in n for n in walk.notes)


def nested_images(levels: int) -> tuple[str, bytes]:
    """(name, bytes) of a .docx inside `levels` NTFS images, each image a file of the next one out."""
    name, data = "memo.docx", rf.docx(rf.para(rf.run("deep "), rf.ins("text")))
    for i in range(levels):
        img = rf.Ntfs(clusters=len(data) // rf.CS + 24)
        img.add(name, data)
        name, data = f"level{levels - i}.img", img.build()
    return name, data


@pytest.mark.parametrize("levels, views", [(3, True), (4, False)])
def test_cascade_derives_exactly_depth_levels_deep(levels, views):
    import archive_expand
    from ctf.recover import DEPTH, cascade
    assert DEPTH == 4
    name, data = nested_images(levels)
    notes = []
    out = cascade([((name,), data)], archive_expand.Walk(), notes, archive_expand)
    chains = [c for c, _b in out]
    docx = [c for c in chains if c[-1].endswith("/memo.docx")]
    assert len(docx) == 1 and len(docx[0]) == levels + 1          # the docx is exported at either depth
    accepted = [c for c in chains if c[-1] == "tracked-changes/accepted.txt"]
    limit = [n for n in notes if "derivation depth limit 4" in n]
    if views:                       # 3 images, then the docx: 4 derivations, its views are made at the limit
        assert accepted == [docx[0] + ("tracked-changes/accepted.txt",)]
        assert any(n.startswith(" -> ".join(accepted[0]) + ":") for n in limit)
        assert not any(n.startswith(" -> ".join(docx[0]) + ":") for n in limit)
    else:                           # 4 images: the docx is made at the limit and not opened for its views
        assert accepted == []
        assert any(n.startswith(" -> ".join(docx[0]) + ":") for n in limit)


def test_cascade_names_a_decoder_failure_and_goes_on(monkeypatch):
    import archive_expand
    from ctf import recover
    real = ooxml.views

    def views(data):                # a decoder that breaks on one content with an error nobody expected
        if b"poison" in data:
            raise struct.error("unpack requires a buffer of 8 bytes")
        return real(data)

    monkeypatch.setattr(ooxml, "views", views)
    bad = rf.docx(rf.para(rf.run("x")), {"word/poison.bin": "poison"})
    good = rf.docx(rf.para(rf.run("CSCTF{"), rf.ins("still_read}")))
    notes = []
    out = recover.cascade([(("bad.docx",), bad), (("good.docx",), good)], archive_expand.Walk(), notes,
                          archive_expand)
    assert [c for c, _b in out if c[0] == "bad.docx"] == []
    assert ("good.docx", "tracked-changes/accepted.txt") in [c for c, _b in out]
    assert any(n.startswith("bad.docx: recovery failed") and "error: unpack requires" in n for n in notes)


# ---------------------------------------------------------------- OOXML views

def test_accepted_and_original_views_of_insertions_and_deletions():
    doc = rf.docx(rf.para(rf.run("The code is "), rf.dele("old"), rf.ins("new"), rf.run(".")))
    v = ooxml.views(doc)
    assert v.accepted == "The code is new.\n"
    assert v.original == "The code is old.\n"
    assert [(c.kind, c.text, c.id, c.author) for c in v.changes] == [("del", "old", "2", "editor"),
                                                                     ("ins", "new", "1", "clerk")]


def test_a_flag_split_across_runs_reads_whole_in_the_views():
    doc = rf.docx(rf.para(rf.run("CSCTF{spl"), rf.run("it_over"), rf.run("_runs}")))
    v = ooxml.views(doc)
    assert CSCTF.find_flags(v.accepted) == ["CSCTF{split_over_runs}"]
    assert [n for n, _b in v.files()] == ["tracked-changes/text.txt"]


def test_two_deletions_around_a_live_run_join_in_deletions_txt():
    doc = rf.docx(rf.para(rf.dele("CSCTF{red", 107), rf.run(" dispatch "), rf.dele("line_two}", 108)))
    files = dict(ooxml.views(doc).files())
    # the live run sits between the pieces in the original view (a flag-shaped span with it inside)
    assert CSCTF.find_flags(files["tracked-changes/original.txt"]) == ["CSCTF{red dispatch line_two}"]
    assert CSCTF.find_flags(files["tracked-changes/deletions.txt"]) == ["CSCTF{redline_two}"]
    assert "tracked-changes/insertions.txt" not in files
    assert b"<w:" not in files["tracked-changes/deletions.txt"]


def test_changes_in_different_paragraphs_join_in_document_order_only():
    doc = rf.docx(rf.para(rf.dele("CSCTF{across_", 1)) + rf.para(rf.dele("paragraphs}", 2)))
    text = dict(ooxml.views(doc).files())["tracked-changes/deletions.txt"].decode()
    per_para = text.split("[joined per paragraph]")[1].split("[joined in document order]")[0]
    assert CSCTF.find_flags(per_para) == []
    assert CSCTF.find_flags(text.split("[joined in document order]")[1]) == ["CSCTF{across_paragraphs}"]
    assert [c.paragraph for c in ooxml.views(doc).changes] == [1, 2]


def test_moves_and_text_inserted_then_deleted():
    move_from = '<w:moveFrom w:id="9" w:author="a"><w:r><w:t>moved </w:t></w:r></w:moveFrom>'
    move_to = '<w:moveTo w:id="10" w:author="a"><w:r><w:t>moved </w:t></w:r></w:moveTo>'
    both = ('<w:ins w:id="11" w:author="a"><w:del w:id="12" w:author="b"><w:r><w:delText>ghost</w:delText>'
            '</w:r></w:del></w:ins>')
    v = ooxml.views(rf.docx(rf.para(move_from, rf.run("x "), move_to, both)))
    assert v.original == "moved x \n"
    assert v.accepted == "x moved \n"
    assert "ghost" not in v.accepted and "ghost" not in v.original
    kinds = {c.kind: c.text for c in v.changes}
    assert kinds["del"] == "ghost" and kinds["ins"] == "ghost"


def test_tab_stops_are_not_text_but_run_tabs_and_breaks_are():
    p = ('<w:p><w:pPr><w:tabs><w:tab w:val="left" w:pos="720"/></w:tabs></w:pPr>'
         '<w:r><w:t>a</w:t><w:tab/><w:t>b</w:t><w:br/><w:t>c</w:t></w:r></w:p>')
    assert ooxml.views(rf.docx(p)).accepted == "a\tb\nc\n"


def test_headers_comments_and_footnotes_are_read_with_a_label():
    parts = {"word/header1.xml": rf.part("hdr", rf.para(rf.run("CSCTF{in_the_"), rf.run("header}"))),
             "word/comments.xml": rf.part("comments", '<w:comment w:id="0">' + rf.para(rf.ins("note", 3))
                                          + "</w:comment>")}
    v = ooxml.views(rf.docx(rf.para(rf.run("body")), parts))
    assert v.parts == ["word/document.xml", "word/comments.xml", "word/header1.xml"]
    assert "[word/header1.xml]\nCSCTF{in_the_header}" in v.accepted
    assert [c.part for c in v.changes] == ["word/comments.xml"]


def test_a_doctype_is_refused_in_the_body_and_noted_in_another_part():
    bad = b'<?xml version="1.0"?><!DOCTYPE d [<!ENTITY e SYSTEM "file:///etc/passwd">]><w:document/>'
    with pytest.raises(ooxml.OoxmlError, match="DOCTYPE"):
        ooxml.views(rf.docx("", raw_document=bad))
    v = ooxml.views(rf.docx(rf.para(rf.run("body text")), {"word/footer1.xml": bad.decode()}))
    assert v.accepted == "body text\n"
    assert any("word/footer1.xml not read" in n and "DOCTYPE" in n for n in v.notes)


def test_a_part_past_the_size_limit_is_refused(monkeypatch):
    monkeypatch.setattr(ooxml, "MAX_PART", 200)
    with pytest.raises(ooxml.OoxmlError, match=r"word/document\.xml is \d+ bytes, over the part limit of 200"):
        ooxml.views(rf.docx(rf.para(rf.run("x" * 400))))


def test_a_stray_deltext_outside_a_deletion_is_still_deleted_text():
    v = ooxml.views(rf.docx(rf.para(rf.run("kept "), "<w:r><w:delText>stray</w:delText></w:r>")))
    assert v.accepted == "kept \n" and v.original == "kept stray\n"


def _member_data_at(doc: bytes, name: bytes) -> int:
    """Where `name`'s compressed data starts in a .docx built by rf.docx."""
    at = doc.index(b"PK\x03\x04")
    while True:
        nlen, xlen = struct.unpack_from("<HH", doc, at + 26)
        if doc[at + 30:at + 30 + nlen] == name:
            return at + 30 + nlen + xlen
        at = doc.index(b"PK\x03\x04", at + 4)


def corrupt_deflate(doc: bytes, name: bytes = b"word/document.xml", offset: int = 0) -> bytes:
    """0xFF over byte `offset` of a member's compressed data: at 0 of a deflate stream, block type 3
    (reserved: zlib.error); at 0 of a bzip2 stream, its 'B' (OSError); at 4 of a zip LZMA member, the
    lc/lp/pb properties byte (lzma.LZMAError)."""
    at = _member_data_at(doc, name) + offset
    return doc[:at] + b"\xff" + doc[at + 1:]


def corrupt_version(doc: bytes) -> bytes:
    cd = doc.index(b"PK\x01\x02")
    return doc[:cd + 6] + b"\xff\x00" + doc[cd + 8:]          # "version needed" 25.5: NotImplementedError


def corrupt_cd_offset(doc: bytes) -> bytes:
    eocd = doc.rindex(b"PK\x05\x06")    # the directory's offset past the end: every member offset goes negative
    return doc[:eocd + 16] + struct.pack("<I", 0x7FFFFFFF) + doc[eocd + 20:]   # ValueError: negative seek


def test_a_damaged_docx_is_refused_with_a_reason_never_an_exception():
    doc = rf.docx(rf.para(rf.run("The code is "), rf.ins("new")) * 5)
    for bad, why in ((corrupt_deflate(doc), r"error: .*invalid block type"),
                     (corrupt_cd_offset(doc), r"ValueError: negative seek")):
        assert ooxml.is_docx(bad)                    # its directory lists word/document.xml
        with pytest.raises(ooxml.OoxmlError, match=r"word/document\.xml: " + why):
            ooxml.views(bad)
        notes = []
        assert derive(("memo.docx",), bad, None, notes) == []
        assert any(n.startswith("memo.docx: a Word document whose text does not read") and
                   ("invalid block type" in n or "negative seek" in n) for n in notes)
    header = corrupt_version(doc)                    # zipfile refuses the directory itself
    assert not ooxml.is_docx(header)
    with pytest.raises(ooxml.OoxmlError, match=r"not a zip \(NotImplementedError\)"):
        ooxml.views(header)
    assert derive(("memo.docx",), header, None, []) == []


@pytest.mark.parametrize("compression, offset, why", [
    (zipfile.ZIP_DEFLATED, 0, "error: Error -3 while decompressing data: invalid block type"),
    (zipfile.ZIP_BZIP2, 0, "OSError: Invalid data stream"),
    (zipfile.ZIP_LZMA, 4, "LZMAError: Invalid or unsupported options"),
])
def test_a_damaged_member_stream_is_a_reason_whatever_its_compression(compression, offset, why):
    parts = {"word/header1.xml": rf.part("hdr", rf.para(rf.run("h" * 300)))}
    doc = rf.docx(rf.para(rf.run("body text")), parts, compression=compression)
    v = ooxml.views(corrupt_deflate(doc, b"word/header1.xml", offset))      # another part: a note
    assert v.accepted == "body text\n" and v.parts == ["word/document.xml"]
    assert any(n == f"word/header1.xml not read: {why}" for n in v.notes)
    with pytest.raises(ooxml.OoxmlError, match=f"^word/document.xml: {why}$"):   # the body: refused
        ooxml.views(corrupt_deflate(doc, b"word/document.xml", offset))


def test_a_member_whose_data_runs_past_the_end_is_a_reason():
    doc = rf.docx(rf.para(rf.run("body text")), {"word/header1.xml": rf.part("hdr", rf.para(rf.run("h")))})
    local = doc.index(b"PK\x03\x04", doc.index(b"word/document.xml") - 30)
    assert doc[local + 30:local + 47] == b"word/document.xml"
    cd = doc.rindex(b"PK\x01\x02", 0, doc.rindex(b"word/header1.xml"))
    # the body's extra field claims 0x6800 bytes (its data starts past the end); the header part's
    # directory offset is huge, which lifts zipfile's overlap bound off the body
    bad = doc[:local + 28] + struct.pack("<H", 0x6800) + doc[local + 30:]
    bad = bad[:cd + 42] + struct.pack("<I", 0xDF000000) + bad[cd + 46:]
    assert ooxml.is_docx(bad)
    with pytest.raises(ooxml.OoxmlError, match="^word/document.xml: EOFError: $"):
        ooxml.views(bad)


def test_an_encrypted_part_is_a_reason():
    doc = rf.docx(rf.para(rf.run("body text")), {"word/footer1.xml": rf.part("ftr", rf.para(rf.run("f")))})
    cd = doc.index(b"PK\x01\x02")
    while doc[cd + 46:cd + 46 + 16] != b"word/footer1.xml":
        cd = doc.index(b"PK\x01\x02", cd + 4)
    locked = doc[:cd + 8] + struct.pack("<H", 1) + doc[cd + 10:]          # general purpose bit 0: encrypted
    v = ooxml.views(locked)
    assert v.accepted == "body text\n"
    assert any(n.startswith("word/footer1.xml not read: RuntimeError: File ") and "is encrypted" in n
               for n in v.notes)


def test_empty_insertions_and_deletions_are_not_changes():
    v = ooxml.views(rf.docx(rf.para(rf.run("same"), '<w:ins w:id="5" w:author="a"/>',
                                    '<w:del w:id="6" w:author="b"><w:r><w:delText></w:delText></w:r></w:del>')))
    assert v.changes == [] and not v.tracked
    assert [n for n, _b in v.files()] == ["tracked-changes/text.txt"]


def test_text_after_the_last_paragraph_is_kept():
    v = ooxml.views(rf.docx(rf.para(rf.run("first")) + rf.run("loose ") + rf.dele("gone")))
    assert v.accepted == "first\nloose \n" and v.original == "first\nloose gone\n"


def test_not_a_docx():
    assert not ooxml.is_docx(b"PK\x03\x04 not a zip at all word/")
    assert not ooxml.is_docx(rf.docx("")[:10])
    assert ooxml.is_docx(rf.docx(""))
    with pytest.raises(ooxml.OoxmlError, match="not a zip"):
        ooxml.views(b"plain text")


# ---------------------------------------------------------------- ranking

def test_rank_puts_tracked_change_only_flags_before_shared_text():
    seen = {"CSCTF{decoy}": {"accepted", "original"}, "CSCTF{real}": {"original", "del"}}
    order, note = ooxml.rank(seen, "")
    assert order == ["CSCTF{real}", "CSCTF{decoy}"] and "tracked change" in note


@pytest.mark.parametrize("brief", ["", "What was removed?"])
def test_rank_puts_a_flag_whole_inside_a_change_before_one_spanning_live_text(brief):
    # given in the reverse of the expected order, so a rule that does not sort leaves them wrong
    seen = {"CSCTF{decoy}": {"accepted", "original"}, "CSCTF{red dispatch line_two}": {"original"},
            "CSCTF{redline_two}": {"original", "del"}}
    assert ooxml.rank(seen, brief)[0] == ["CSCTF{redline_two}", "CSCTF{red dispatch line_two}", "CSCTF{decoy}"]


@pytest.mark.parametrize("one_view", ["original", "accepted"])
def test_rank_puts_a_flag_seen_in_one_view_only_before_shared_text(one_view):
    seen = {"CSCTF{decoy}": {"accepted", "original"}, "CSCTF{span}": {one_view}}
    order, note = ooxml.rank(seen, "")
    assert order == ["CSCTF{span}", "CSCTF{decoy}"] and "tracked change" in note


def test_rank_the_briefs_side_outranks_a_stronger_flag_on_the_other_side():
    # the brief asks for the original: a span seen in the original view only (strength 1) goes before a
    # flag whole inside an insertion (strength 0); and the other way round for the final text
    seen = {"CSCTF{inserted_whole}": {"accepted", "ins"}, "CSCTF{original_span}": {"original"}}
    assert ooxml.rank(seen, "What was removed?")[0] == ["CSCTF{original_span}", "CSCTF{inserted_whole}"]
    seen = {"CSCTF{deleted_whole}": {"original", "del"}, "CSCTF{accepted_span}": {"accepted"}}
    assert ooxml.rank(seen, "Read the final version.")[0] == ["CSCTF{accepted_span}", "CSCTF{deleted_whole}"]


def test_rank_follows_the_briefs_side():
    seen = {"CSCTF{added}": {"accepted", "ins"}, "CSCTF{removed}": {"original", "del"}}
    assert ooxml.rank(seen, "What did the editor strike from the approved draft?")[0][0] == "CSCTF{removed}"
    assert ooxml.rank(seen, "What was inserted into the final version?")[0][0] == "CSCTF{added}"
    order, note = ooxml.rank(seen, "Find what was removed.")
    assert order[0] == "CSCTF{removed}" and "original" in note


def test_rank_leaves_flags_without_tracked_changes_in_their_order():
    seen = {"CSCTF{b}": set(), "CSCTF{a}": {"text"}}
    assert ooxml.rank(seen, "deleted") == (["CSCTF{b}", "CSCTF{a}"], "")


def test_markup_twins_only_when_the_tag_free_text_was_found_too():
    wedged = 'CSCTF{a_</w:t></w:r><w:r><w:t xml:space="preserve">b}'
    assert ooxml.markup_twins([wedged, "CSCTF{a_b}"]) == {wedged: "CSCTF{a_b}"}
    assert ooxml.markup_twins([wedged]) == {}
    assert ooxml.markup_twins(["CSCTF{a<b}", "CSCTF{ab}"]) == {}


def test_brief_side():
    assert ooxml.brief_side("Recover the deleted text") == "original"
    assert ooxml.brief_side("Read the final version") == "accepted"
    assert ooxml.brief_side("A memo") is None
    assert ooxml.brief_side("What was deleted and what was inserted?") is None      # one hint each: a tie


def test_view_of_member_names():
    assert ooxml.view_of("a.docx -> tracked-changes/deletions.txt") == "del"
    assert ooxml.view_of("a.docx -> tracked-changes/accepted.txt") == "accepted"
    assert ooxml.view_of("a.docx -> word/document.xml") is None


# ---------------------------------------------------------------- XOR crib

def test_single_byte_xor_finds_the_key_and_offset():
    data = b"\x10\x20" + bytes(b ^ 0x39 for b in b"CSCTF{xor_crib_57}") + b"\x00"
    assert xorcrib.single_byte(data, CSCTF) == [(0x39, 2, "CSCTF{xor_crib_57}")]


@pytest.mark.parametrize("key", [1, 0x7B ^ 0x7D, 0x80, 0xFF])
def test_every_key_from_1_to_255_is_tried(key):
    data = bytes(b ^ key for b in b"..CSCTF{edge_key}..")
    assert xorcrib.single_byte(data, CSCTF) == [(key, 2, "CSCTF{edge_key}")]


def test_key_zero_is_not_reported_and_a_prefix_alone_is_not_a_flag():
    assert xorcrib.single_byte(b"CSCTF{plain_already}", CSCTF) == []
    assert xorcrib.single_byte(bytes(b ^ 5 for b in b"CSCTF{unclosed"), CSCTF) == []


def test_noise_under_a_key_is_not_a_flag():
    noise = bytes((i * 151 + 7) % 256 | 0x80 for i in range(64))           # never printable
    xor = lambda b: bytes(c ^ 0x5A for c in b)                              # noqa: E731
    # a short body in binary noise: what random tokens give under some key
    assert xorcrib.single_byte(xor(noise[:30] + b"CTF{ab}" + noise[30:]), CSCTF) == []
    # a non-printable byte inside the flag
    assert xorcrib.single_byte(xor(b"text CSCTF{long_enough_body\x01x} text"), CSCTF) == []
    # a long printable body is a flag even in binary noise
    assert xorcrib.single_byte(xor(noise[:30] + b"CSCTF{long_enough_body}" + noise[30:]), CSCTF) == [
        (0x5A, 30, "CSCTF{long_enough_body}")]
    # LONG_BODY (12) is the boundary: a body of exactly 12 characters stands in noise, 11 does not
    assert xorcrib.LONG_BODY == 12
    assert xorcrib.single_byte(xor(noise[:30] + b"CSCTF{twelve_chars}" + noise[30:]), CSCTF) == [
        (0x5A, 30, "CSCTF{twelve_chars}")]
    assert xorcrib.single_byte(xor(noise[:30] + b"CSCTF{eleven_char}" + noise[30:]), CSCTF) == []
    # a short body is a flag when the whole token reads as text
    assert xorcrib.single_byte(xor(b"the audit token is CTF{ab} ok"), CSCTF) == [(0x5A, 19, "CTF{ab}")]


def test_the_crib_is_off_for_an_unknown_format_and_past_the_input_cap(monkeypatch):
    unknown = flagfmt.FlagFormat(event.FlagSpec(prefixes=(), body=CSCTF.spec.body, case="exact"))
    data = bytes(b ^ 9 for b in b"CSCTF{x_y_z}")
    assert xorcrib.single_byte(data, unknown) == []
    monkeypatch.setattr(xorcrib, "MAX_INPUT", 8)
    assert xorcrib.single_byte(data, CSCTF) == []


def test_fixture_runlist_encodes_negative_deltas():
    assert rf.runlist([(100, 1), (60, 1)]) == bytes([0x11, 1, 100, 0x11, 1, (60 - 100) & 0xFF, 0])
    assert struct.unpack_from("<b", rf.runlist([(100, 1), (60, 1)]), 5)[0] == -40
