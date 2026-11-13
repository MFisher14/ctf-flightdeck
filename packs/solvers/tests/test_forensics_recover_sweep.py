"""B-029 in the pull-time sweep (ctf/sweep.py): deleted NTFS files, tracked-change views and the XOR crib
reach the flag search. The two coverage rows it closes, rebuilt synthetically (shapes only, no challenge
data):

  * CSCTF 9071 Night Clerk: a bare NTFS image whose deleted .docx carries a tracked insertion of hex text,
    single-byte XOR of the flag; a deleted log beside it.
  * CSCTF 9078 Redline: a .docx whose live text holds a decoy flag and whose flag is split over two
    tracked deletions with a live run between them.
"""
import dataclasses
import io
import json
import struct
import zipfile

import pytest

import archive_expand
import recover_fixtures as rf
from ctf import event, sweep

CSCTF = event.load("csctf")


@pytest.fixture(autouse=True)
def _offline(monkeypatch, tmp_path):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "wd"))
    monkeypatch.setattr(archive_expand.pw, "candidates", lambda: [b"infected"])


def pulled(tmp_path, files: dict, description="", cid=9071):
    ch = tmp_path / "wd" / f"{cid}-x"
    (ch / "files").mkdir(parents=True)
    (ch / "challenge.json").write_text(json.dumps({"id": cid, "name": "x", "category": "Forensics",
                                                   "description": description}))
    for name, data in files.items():
        (ch / "files" / name).write_bytes(data)
    return ch


def night_clerk_image(flag: bytes, key: int = 0x39) -> bytes:
    hexrun = bytes(b ^ key for b in flag).hex()
    doc = rf.docx(rf.para(rf.run("Night shift handover. Nothing to report.")) +
                  rf.para(rf.run("Audit token: "), rf.ins(hexrun[:24], 41, "night clerk"),
                          rf.ins(hexrun[24:], 42, "night clerk")))
    img = rf.Ntfs(clusters=512)
    users = img.add("Staff", directory=True)
    clerk = img.add("clerk", parent=users, directory=True)
    img.add("handover.txt", b"Shift ended 06:00. All quiet.", parent=clerk)
    img.add("night_audit.docx", doc, parent=clerk, deleted=True)
    img.add("audit-0214.log", b"02:14:07 clock skew detected: +57 s\n" * 30, parent=clerk, deleted=True)
    return img.build()


def test_night_clerk_deleted_docx_insertion_hex_xor_flag_is_found(tmp_path):
    flag = b"CSCTF{night_clerk_clock_skew_57}"
    raw = night_clerk_image(flag)
    hexrun = bytes(b ^ 0x39 for b in flag).hex().encode()
    assert flag not in raw and hexrun[:24] not in raw          # the docx is deflated on the disk
    ch = pulled(tmp_path, {"disk.img": raw}, "The night clerk cleaned up before leaving. Flag: CSCTF{...}")
    rep = sweep.sweep(ch, CSCTF)
    assert rep.result.status == "solved"
    assert rep.result.flags == (flag.decode(),)
    hits = rep.flags[flag.decode()]
    assert all(h.method == "decode:hex>xor:0x39" for h in hits)
    ev = rep.result.evidence[0]
    assert ev.path.startswith("unpacked/disk.img.unpacked/deleted/Staff/clerk/night_audit.docx.unpacked/"
                              "tracked-changes/")
    out = ch / "unpacked" / "disk.img.unpacked"
    assert (out / "deleted/Staff/clerk/audit-0214.log").read_bytes().startswith(b"02:14:07 clock skew")
    assert (out / "allocated/Staff/clerk/handover.txt").is_file()
    listing = (out / "ntfs-listing.txt").read_text()
    assert "deleted" in listing and "Staff/clerk/night_audit.docx" in listing
    report = json.loads((ch / "unpacked" / sweep.REPORT).read_text())
    chains = {m["chain"] for m in report["manifest"]}
    assert "disk.img -> deleted/Staff/clerk/night_audit.docx -> tracked-changes/insertions.txt" in chains
    assert "disk.img -> deleted/Staff/clerk/night_audit.docx -> word/document.xml" in chains
    assert any("2 deleted file(s)" in n for n in rep.notes)


def test_night_clerk_without_the_recovery_step_finds_nothing(tmp_path, monkeypatch):
    """The control: the same image through the B-013 walk alone gives no flag."""
    monkeypatch.setattr(sweep._recover, "cascade", lambda *a, **k: [])
    ch = pulled(tmp_path, {"disk.img": night_clerk_image(b"CSCTF{night_clerk_clock_skew_57}")})
    assert sweep.sweep(ch, CSCTF).result.status == "none"


def redline_docx() -> bytes:
    return rf.docx(rf.para(rf.run("Dispatch code: CSCTF{dispatch_"), rf.run("decoy_live_text}")) +
                   rf.para(rf.run("Approved route: "), rf.dele("CSCTF{red", 107), rf.run(" via depot "),
                           rf.dele("lined_route_9}", 108), rf.run(".")),
                   {"word/comments.xml": rf.part("comments", '<w:comment w:id="1">'
                                                 + rf.para(rf.run("see the redline")) + "</w:comment>")})


def test_redline_split_deletions_rank_before_the_live_text_decoy(tmp_path):
    ch = pulled(tmp_path, {"route.docx": redline_docx()}, "Which route was approved?", cid=9078)
    rep = sweep.sweep(ch, CSCTF)
    assert rep.result.status == "candidate"
    assert rep.result.flags[0] == "CSCTF{redlined_route_9}"
    assert "CSCTF{dispatch_decoy_live_text}" in rep.result.flags
    assert rep.result.flags.index("CSCTF{dispatch_decoy_live_text}") > rep.result.flags.index(
        "CSCTF{red via depot lined_route_9}")
    assert not any("<w:" in f for f in rep.result.flags)          # never a flag with markup inside
    wedged = [f for f in rep.excluded if "<w:" in f]
    assert len(wedged) == 2                                     # the decoy's and the deletions' raw-XML spans
    assert all("XML markup inside it" in rep.excluded[f] for f in wedged)
    assert any("CSCTF{dispatch_decoy_live_text} reads whole" in rep.excluded[f] for f in wedged)
    assert any("tracked change" in n for n in rep.notes)
    where = rep.to_dict()["flags"]["CSCTF{redlined_route_9}"][0]["where"]
    assert where == ["route.docx -> tracked-changes/deletions.txt"]


@pytest.mark.parametrize("brief, first", [
    ("Recover what the editor removed before it was approved.", "CSCTF{was_struck}"),
    ("Read the final version as published.", "CSCTF{was_added}"),
])
def test_the_brief_picks_which_side_of_the_redline_ranks_first(tmp_path, brief, first):
    doc = rf.docx(rf.para(rf.run("Note: "), rf.ins("CSCTF{was_added}", 1), rf.dele("CSCTF{was_struck}", 2)))
    rep = sweep.sweep(pulled(tmp_path, {"memo.docx": doc}, brief), CSCTF)
    assert rep.result.flags[0] == first and len(rep.result.flags) == 2


def test_an_image_inside_a_zip_handout_is_recovered_too(tmp_path):
    img = rf.Ntfs()
    piece = rf.CS
    secret = b"CSCTF{fragments_reversed_on_disk}"
    body = b"A" * (piece - 10) + secret + b"B" * 100           # the flag straddles two clusters
    img.add("carved.bin", body, deleted=True, runs=[(150, 1), (90, 1)])  # second cluster sits before the first
    raw = img.build()
    assert secret not in raw
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("evidence/disk.img", raw)
    rep = sweep.sweep(pulled(tmp_path, {"handout.zip": bio.getvalue()}), CSCTF)
    assert rep.result.flags == (secret.decode(),)
    assert rep.to_dict()["flags"][secret.decode()][0]["where"] == [
        "handout.zip -> evidence/disk.img -> deleted/carved.bin"]


def test_a_vhd_holding_an_mbr_partition_is_unwrapped_and_walked(tmp_path):
    img = rf.Ntfs()
    body = b"x" * (rf.CS - 8) + b"CSCTF{vhd_mbr_" + b"partition}" + b"y" * 50
    img.add("note.bin", body, deleted=True, runs=[(120, 1), (80, 1)])
    disk = rf.fixed_vhd(rf.mbr(img.build(), lba=128))
    rep = sweep.sweep(pulled(tmp_path, {"disk.vhd": disk}), CSCTF)
    assert rep.result.flags == ("CSCTF{vhd_mbr_partition}",)
    assert rep.to_dict()["flags"]["CSCTF{vhd_mbr_partition}"][0]["where"] == [
        "disk.vhd -> disk.vhd.raw -> mbr-p1/deleted/note.bin"]


def test_the_crib_covers_base64_runs_in_any_file_but_not_base32(tmp_path):
    import base64
    secret = bytes(b ^ 0x21 for b in b"CSCTF{base64_under_one_byte}")
    log = (b"GET /x?t=" + base64.b64encode(secret) + b" 200\n" +
           b"GET /y?t=" + base64.b32encode(bytes(b ^ 0x22 for b in b"CSCTF{base32_is_not_cribbed}")) + b" 200\n")
    rep = sweep.sweep(pulled(tmp_path, {"access.log": log}), CSCTF)
    assert rep.result.flags == ("CSCTF{base64_under_one_byte}",)
    assert rep.flags["CSCTF{base64_under_one_byte}"][0].method == "decode:base64>xor:0x21"


def test_an_unknown_flag_format_turns_the_crib_off_and_says_so(tmp_path):
    unknown = dataclasses.replace(CSCTF, flag=event.FlagSpec(prefixes=(), body=CSCTF.flag.body))
    rep = sweep.sweep(pulled(tmp_path, {"disk.img": night_clerk_image(b"CSCTF{night_clerk_clock_skew_57}")}),
                      unknown)
    assert rep.result.status == "none"
    assert any("no single-byte XOR crib" in n for n in rep.notes)
    known = sweep.sweep(pulled(tmp_path / "k", {"a.txt": b"plain"}), CSCTF)
    assert not any("XOR crib" in n for n in known.notes)


def test_a_docx_without_tracked_changes_still_joins_its_runs(tmp_path):
    doc = rf.docx(rf.para(rf.run("CSCTF{split_"), rf.run("across_"), rf.run("three_runs}")))
    rep = sweep.sweep(pulled(tmp_path, {"plain.docx": doc}), CSCTF)
    assert rep.result.flags == ("CSCTF{split_across_three_runs}",)
    assert rep.to_dict()["flags"]["CSCTF{split_across_three_runs}"][0]["where"] == [
        "plain.docx -> tracked-changes/text.txt"]


def test_a_token_that_already_gives_a_flag_is_not_cribbed(tmp_path):
    # one hex run holding a plain flag and, after it, a second flag under XOR 0x21: the run's plain flag
    # is its answer, so the 255 keys are not tried on it
    token = b"CSCTF{plain_in_the_token} " + bytes(b ^ 0x21 for b in b"CSCTF{second_under_xor_key}")
    rep = sweep.sweep(pulled(tmp_path, {"a.txt": b"blob=" + token.hex().encode() + b"\n"}), CSCTF)
    assert set(rep.flags) == {"CSCTF{plain_in_the_token}"}
    assert {h.method for h in rep.flags["CSCTF{plain_in_the_token}"]} == {"decode:hex"}
    alone = bytes(b ^ 0x21 for b in b"CSCTF{second_under_xor_key}").hex().encode()   # the control
    assert set(sweep.sweep(pulled(tmp_path / "c", {"a.txt": alone}), CSCTF).flags) == {
        "CSCTF{second_under_xor_key}"}


def _corrupt(doc: bytes, how: str) -> bytes:
    if how == "deflate":            # the first byte of word/document.xml's deflate stream: block type 3
        at = doc.index(b"PK\x03\x04")
        while True:
            nlen, xlen = struct.unpack_from("<HH", doc, at + 26)
            if doc[at + 30:at + 30 + nlen] == b"word/document.xml":
                at += 30 + nlen + xlen
                return doc[:at] + b"\xff" + doc[at + 1:]
            at = doc.index(b"PK\x03\x04", at + 4)
    eocd = doc.rindex(b"PK\x05\x06")    # the directory's offset past the end: zipfile seeks before the start
    return doc[:eocd + 16] + struct.pack("<I", 0x7FFFFFFF) + doc[eocd + 20:]


@pytest.mark.parametrize("how, why", [("deflate", "invalid block type"), ("zip-header", "negative seek")])
def test_a_damaged_docx_does_not_stop_the_sweep(tmp_path, how, why):
    doc = rf.docx(rf.para(rf.run("Memo: "), rf.dele("struck words")) * 30)
    rep = sweep.sweep(pulled(tmp_path, {"memo.docx": _corrupt(doc, how),
                                        "notes.txt": b"seen: CSCTF{the_sweep_went_on}\n"}), CSCTF)
    assert rep.result.flags == ("CSCTF{the_sweep_went_on}",)
    assert any(n.startswith("memo.docx: a Word document whose text does not read") and why in n
               for n in rep.notes)


def test_recovered_members_count_against_the_walks_budget(tmp_path):
    img = rf.Ntfs()
    for i in range(6):
        img.add(f"f{i}.txt", f"file {i}".encode(), deleted=True)
    walk = archive_expand.Walk(max_members=4)
    rep = sweep.sweep(pulled(tmp_path, {"disk.img": img.build()}), CSCTF, walk=walk)
    assert sum(not e.original for e in rep.manifest) == 4
    assert any("budget" in n for n in rep.notes)
