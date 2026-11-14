"""B-074: harvest candidate passwords from a handout's own bytes (solvers/common/harvest.py).

Every fixture is built in the test; nothing is executed. The module never generates a password -- a
candidate it returns literally appears in the bytes it was given, which is what these tests pin.
"""
import io
import zipfile

import harvest as hv


def _zip(entries, comment=b""):
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w") as z:
        for name, data in entries:
            z.writestr(name, data)
        if comment:
            z.comment = comment
    return bio.getvalue()


def test_overlay_is_bytes_appended_after_a_zip_end():
    data = _zip([("a.txt", "hi")]) + b"\nthe password is Trailing_Secret_42\n"
    over = hv.overlay(data)
    assert b"Trailing_Secret_42" in over
    assert b"PK" not in over                    # only the appended tail, not the archive
    assert "Trailing_Secret_42" in hv.from_bytes(data)


def test_zip_comment_is_harvested_as_an_overlay():
    data = _zip([("a.txt", "hi")], comment=b"pw:CommentedPass9")
    assert b"CommentedPass9" in hv.overlay(data)
    assert "pw:CommentedPass9" in hv.from_bytes(data)


def test_png_overlay_after_iend():
    png = b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\x00IEND\xaeB`\x82" + b"OverlayPass_png"
    assert hv.overlay(png) == b"OverlayPass_png"


def test_jpeg_overlay_after_ffd9():
    jpg = b"\xff\xd8\xff\xe0" + b"\x00" * 16 + b"\xff\xd9" + b"JpegTail_Pass"
    assert hv.overlay(jpg) == b"JpegTail_Pass"


def test_no_overlay_for_an_unknown_or_clean_file():
    assert hv.overlay(b"\x7fELF" + b"\x00" * 40) == b""
    assert hv.overlay(_zip([("a", "b")])) in (b"", _zip([("a", "b")])[-0:])  # nothing appended -> empty tail


def test_ascii_run_is_harvested():
    cands = hv.from_bytes(b"\x01\x02ReadablePass1\x00\xff")
    assert "ReadablePass1" in cands


def test_utf16le_run_is_harvested():
    blob = b"\x00\x00" + "WideSecret9".encode("utf-16-le") + b"\x00\x00"
    assert "WideSecret9" in hv.utf16le_runs(blob)
    assert "WideSecret9" in hv.from_bytes(blob)


def test_whole_run_and_its_tokens_are_both_offered():
    # a passphrase with spaces: the whole line AND each word are candidates
    cands = hv.from_bytes(b"\x00correct horse battery staple\x00")
    assert "correct horse battery staple" in cands
    assert "horse" in cands


def test_candidate_validity_filters_overlong_and_control_runs():
    long = b"\x00" + b"A" * 200 + b"\x00"       # over the 128-char store limit
    assert all(len(c) <= hv.MAX_PW for c in hv.from_bytes(long))
    assert "A" * 200 not in hv.from_bytes(long)


def test_short_runs_below_min_len_are_dropped():
    assert "abc" not in hv.from_bytes(b"\x00abc\x00", min_len=5)


def test_siblings_reads_notes_but_not_the_target_or_binaries(tmp_path):
    target = tmp_path / "secret.zip"
    target.write_bytes(_zip([("a", "b")]))
    (tmp_path / "note.txt").write_text("archive password: SiblingNote_Pw7\n")
    (tmp_path / "blob.bin").write_bytes(b"BinaryPass\x00\x00morebytes")   # has a NUL early -> skipped
    cands = hv.siblings(target)
    assert "SiblingNote_Pw7" in cands
    assert "BinaryPass" not in cands           # a binary sibling is not mined


def test_overlay_candidate_precedes_a_body_only_candidate():
    # The appended overlay is the classic hidden-archive-password slot, so from_bytes must TRY overlay
    # candidates before candidates that appear only in the body. This pins the ordering guarantee of
    # the module docstring: dedup(overlay_first + whole_blob), not dedup(whole_blob). A blob whose
    # stored body holds BodyPw_secret and whose appended overlay holds OverPw_appended must list the
    # overlay candidate first -- in raw byte order the body string comes first, so scanning the whole
    # blob alone would reverse them.
    data = _zip([("a.txt", "use BodyPw_secret please")]) + b"\nOverPw_appended\n"
    over = hv.overlay(data)
    assert b"OverPw_appended" in over and b"BodyPw_secret" not in over   # body is not in the overlay
    cands = hv.from_bytes(data)
    assert "OverPw_appended" in cands and "BodyPw_secret" in cands
    assert cands.index("OverPw_appended") < cands.index("BodyPw_secret")


def test_harvest_puts_own_file_candidates_before_siblings(tmp_path):
    target = tmp_path / "handout.zip"
    target.write_bytes(_zip([("a", "b")]) + b"\nOWN_OverlayPw\n")
    (tmp_path / "readme.txt").write_text("SIBLING_Pw\n")
    cands = hv.harvest(target)
    assert "OWN_OverlayPw" in cands and "SIBLING_Pw" in cands
    assert cands.index("OWN_OverlayPw") < cands.index("SIBLING_Pw")


def test_harvest_data_only_takes_no_siblings():
    cands = hv.harvest(data=b"\x00JustTheseBytes9\x00")
    assert cands == ["JustTheseBytes9"]


def test_candidate_cap_is_enforced():
    blob = b"\x00".join(f"pw{i:05d}".encode() for i in range(hv.MAX_CANDIDATES + 500))
    assert len(hv.from_bytes(blob)) <= hv.MAX_CANDIDATES


def test_cli_prints_candidates(tmp_path, capsys):
    f = tmp_path / "x.bin"
    f.write_bytes(b"\x00CliHarvestPw1\x00")
    assert hv.main([str(f), "--no-siblings"]) == 0
    assert "CliHarvestPw1" in capsys.readouterr().out
    assert hv.main([str(tmp_path / "nope")]) == 1
