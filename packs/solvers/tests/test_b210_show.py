"""B-210: the operator read kit, `python -m ctf show` (ctf.opkit, ctf.cli.show).

Every input is synthetic and built here: question bodies, key/answer files, a ledger written through
ctf.ledger, HCFG samples (a hand-built PE image with a container in its .data section), delivery zips.
None reads a real challenge or contacts a platform. The replay tests are in test_b210_replay.py.
"""
from __future__ import annotations

import hashlib
import json
import struct
import zipfile
import zlib
from pathlib import Path

import pytest

from ctf import cli, ledger
from ctf import opkit as ok


def _run(argv, capsys):
    code = cli.main(argv)
    out = capsys.readouterr()
    return code, out.out, out.err


# ---- questions ---------------------------------------------------------------------------------------

QUESTIONS = {"questions": [
    {"id": "analysis_recover_code", "question": "What is the recover code?",
     "answer_format": {"kind": "integer", "syntax": "digits; use the literal none only when there is no code"}},
    {"id": "analysis_family", "question": "Which family?",
     "answer_format": {"kind": "exact_text", "accepted_values": ["alpha", "beta"]}},
    {"qid": "analysis_hash", "question": "SHA-256 of the dropper",
     "answer_format": {"kind": "exact_text", "syntax": "hex64"}},
]}


def test_question_lines_show_each_question_kind_syntax_none_and_accepted():
    lines = ok.question_lines(QUESTIONS, source="start.json")
    assert lines[0] == "questions start.json (3):"
    assert lines[1] == ("  analysis_recover_code  kind=integer syntax=digits; use the literal none only when "
                        "there is no code none=yes")
    assert lines[2].strip().startswith("What is the recover code?")
    assert lines[3] == "  analysis_family  kind=exact_text none=no accepted=[alpha,beta]"
    assert lines[5] == "  analysis_hash  kind=exact_text syntax=hex64 none=no"


def test_question_lines_filter_by_id_and_refuse_an_unknown_id():
    lines = ok.question_lines(QUESTIONS, ["analysis_hash"])
    assert [ln for ln in lines if ln.startswith("  analysis_")] == ["  analysis_hash  kind=exact_text syntax=hex64 none=no"]
    with pytest.raises(ok.OpKitError, match="no question id analysis_nope"):
        ok.question_lines(QUESTIONS, ["analysis_nope"])
    with pytest.raises(ok.OpKitError, match="no question list"):
        ok.question_lines({"attempt_id": "x"})


def test_question_body_prefers_a_start_with_questions_over_an_attempt(tmp_path):
    d = tmp_path / "chal"
    d.mkdir()
    (d / "start.json").write_text(json.dumps({"attempt_id": "S"}))            # no question list here
    (d / "attempt.json").write_text(json.dumps(QUESTIONS))
    src, body = ok.question_body(d)
    assert src.name == "attempt.json" and len(body["questions"]) == 3
    (d / "start.json").write_text(json.dumps({"questions": [{"id": "only_start"}]}))
    src, body = ok.question_body(d)
    assert src.name == "start.json" and body["questions"][0]["id"] == "only_start"


def test_question_body_names_what_is_missing(tmp_path):
    (tmp_path / "empty").mkdir()
    with pytest.raises(ok.OpKitError, match="no start.json, live_start.json or attempt.json"):
        ok.question_body(tmp_path / "empty")
    d = tmp_path / "noq"
    d.mkdir()
    (d / "attempt.json").write_text("{}")
    with pytest.raises(ok.OpKitError, match="no question list in attempt.json"):
        ok.question_body(d)


def test_show_question_cli_reads_a_folder_and_a_body_file(tmp_path, capsys):
    d = tmp_path / "chal"
    d.mkdir()
    (d / "attempt.json").write_text(json.dumps(QUESTIONS))
    code, out, _ = _run(["show", "question", "--dir", str(d), "--id", "analysis_family"], capsys)
    assert code == 0 and "analysis_family  kind=exact_text" in out and "analysis_hash" not in out
    code, out, err = _run(["show", "question", "--file", str(tmp_path / "missing.json")], capsys)
    assert code == 2 and "not a file" in err


def test_show_question_day_restricts_the_root(tmp_path, capsys):
    for day in (1, 2):
        d = tmp_path / f"day-{day:02d}" / f"binary-{day}-c7"
        d.mkdir(parents=True)
        (d / "attempt.json").write_text(json.dumps({"questions": [{"id": f"from_day_{day}"}]}))
    code, _, err = _run(["show", "question", "c7", "--root", str(tmp_path)], capsys)
    assert code == 2 and "ambiguous" in err                       # without --day: two folders end in -c7
    code, out, _ = _run(["show", "question", "c7", "--root", str(tmp_path), "--day", "2"], capsys)
    assert code == 0 and "from_day_2" in out and "from_day_1" not in out


def test_show_day_without_a_root_names_the_variable(monkeypatch, capsys):
    monkeypatch.delenv("CTF_REAL_CHALLENGES", raising=False)
    code, _, err = _run(["show", "question", "c7", "--day", "1"], capsys)
    assert code == 2 and "CTF_REAL_CHALLENGES" in err


def test_show_day_reads_the_saved_folder_from_the_variable(tmp_path, monkeypatch, capsys):
    d = tmp_path / "saved" / "day-01" / "binary-1-c7"
    d.mkdir(parents=True)
    (d / "attempt.json").write_text(json.dumps({"questions": [{"id": "saved_q"}]}))
    monkeypatch.setenv("CTF_REAL_CHALLENGES", str(tmp_path / "saved"))
    code, out, _ = _run(["show", "question", "c7", "--day", "1"], capsys)
    assert code == 0 and "saved_q" in out
    monkeypatch.setenv("CTF_REAL_CHALLENGES", str(tmp_path / "typo"))
    code, _, err = _run(["show", "question", "c7", "--day", "1"], capsys)
    assert code == 2 and str(tmp_path / "typo") in err and "CTF_REAL_CHALLENGES" in err


# ---- keys --------------------------------------------------------------------------------------------

def test_keys_lines_mark_same_different_and_one_sided(tmp_path):
    d = tmp_path / "chal"
    d.mkdir()
    (d / "key.json").write_text(json.dumps({"q1": "a", "q2": {"value": "b"}, "q3": "only-key"}))
    (d / "answers.submitted.json").write_text(json.dumps({"q1": "a", "q2": "B", "q4": "only-answer"}))
    lines = ok.keys_lines(d)
    assert lines[0] == "keys chal: key=key.json answers=answers.submitted.json (4 id(s), 1 same)"
    assert lines[1:] == ["  = q1  key=a  answer=a", "  ! q2  key=b  answer=B",
                         "  - q3  key=only-key  answer=-", "  - q4  key=-  answer=only-answer"]


def test_keys_lines_need_at_least_one_file(tmp_path):
    (tmp_path / "c").mkdir()
    with pytest.raises(ok.OpKitError, match="neither key.json nor"):
        ok.keys_lines(tmp_path / "c")
    (tmp_path / "c" / "key.json").write_text("[1, 2]")
    with pytest.raises(ok.OpKitError, match="expected a JSON object"):
        ok.keys_lines(tmp_path / "c")


# ---- verdict ledger and timeline ---------------------------------------------------------------------

def _ledger(wd: Path) -> None:
    ledger.append("platform.submit", workdir=wd, event_slug="ev", challenge_id="9", status="incorrect",
                  judged=True, guess=False, confirmed=False, provenance="engine:x", post_stop=False,
                  flag_sha256=hashlib.sha256(b"FLAG{wrong}").hexdigest())
    ledger.append("platform.submit", workdir=wd, event_slug="ev", challenge_id="9#a", status="correct",
                  judged=True, guess=False, confirmed=True, provenance="agent", post_stop=False,
                  flag="FLAG{secret_value}", remaining=0)
    ledger.append("platform.submit", workdir=wd, event_slug="ev", challenge_id="90", status="correct",
                  judged=True, guess=False, confirmed=False, provenance="p", post_stop=False, flag_sha256="ab" * 32)
    ledger.append("submit.done", workdir=wd, event_slug="ev", challenge_id="9#a", status="correct", attempts=1,
                  held_s=0.25, queued=False)
    ledger.append("hof.result", workdir=wd, event_slug="ev", challenge_id="9", attempt_id="T1", status="correct",
                  eligible=True, regular=False, pool="timed", counts={}, note=None)
    ledger.append("engine.run", workdir=wd, engine="binary.hcfg", via="ctf-run", exit_code=0, seconds=1.5,
                  challenge_id="9")
    ledger.append("dispatch", workdir=wd, challenge_id="12", lane="web")


def test_verdict_rows_match_a_challenge_and_its_parts_but_not_a_longer_id(tmp_path):
    _ledger(tmp_path)
    recs = list(ledger.read(tmp_path))
    rows = ok.verdict_rows(recs, cid="9")
    assert [(r["event"], r["challenge_id"]) for r in rows] == [
        ("platform.submit", "9"), ("platform.submit", "9#a"), ("submit.done", "9#a"), ("hof.result", "9")]
    assert [r["challenge_id"] for r in ok.verdict_rows(recs, cid="9#a")] == ["9#a", "9#a"]
    assert [r["challenge_id"] for r in ok.verdict_rows(recs, status="incorrect")] == ["9"]
    assert [r["event"] for r in ok.verdict_rows(recs, events=("hof.result",))] == ["hof.result"]
    assert all(r["event"] != "engine.run" for r in ok.verdict_rows(recs))
    with pytest.raises(ok.OpKitError):
        ok.verdict_rows(recs, events=("engine.run",))


def test_verdict_rows_since_and_slug_filters(tmp_path):
    _ledger(tmp_path)
    recs = list(ledger.read(tmp_path))
    late = recs[3]["ts"]
    assert [r["event"] for r in ok.verdict_rows(recs, since=late)] == ["submit.done", "hof.result"]
    assert ok.verdict_rows(recs, slug="other") == []
    assert len(ok.verdict_rows(recs, slug="ev")) == 5


def test_verdict_lines_never_print_a_flag_and_count_sends(tmp_path):
    _ledger(tmp_path)
    rows = ok.verdict_rows(list(ledger.read(tmp_path)))
    text = "\n".join(ok.verdict_lines(rows))
    assert "FLAG{" not in text and "secret_value" not in text
    assert "flag=sha:" + hashlib.sha256(b"FLAG{secret_value}").hexdigest()[:12] in text
    assert "flag=sha:" + hashlib.sha256(b"FLAG{wrong}").hexdigest()[:12] in text
    assert "remaining=0" in text and "attempts=1" in text and "eligible=true" in text
    assert text.splitlines()[-1] == "sends: 3 (correct 2, incorrect 1)"
    assert ok.verdict_lines([])[0].startswith("verdicts: no matching")


def test_verdict_lines_limit_keeps_the_last(tmp_path):
    _ledger(tmp_path)
    rows = ok.verdict_rows(list(ledger.read(tmp_path)))
    lines = ok.verdict_lines(rows, limit=2)
    assert lines[0] == "verdicts (5 record(s), last 2 shown):"
    assert "submit.done" in lines[1] and "hof.result" in lines[2]


def test_show_verdicts_cli_and_json_redaction(tmp_path, capsys):
    _ledger(tmp_path)
    code, out, _ = _run(["show", "verdicts", "9", "--workdir", str(tmp_path)], capsys)
    assert code == 0 and "9#a" in out and " 90 " not in out and "secret_value" not in out
    code, out, _ = _run(["show", "verdicts", "--workdir", str(tmp_path), "--json", "--kind", "platform.submit"],
                        capsys)
    rows = [json.loads(x) for x in out.splitlines()]
    assert len(rows) == 3 and all("flag" not in r and "flag_sha256" not in r for r in rows)
    assert all(r["flag_ref"].startswith("sha:") for r in rows)
    code, _, err = _run(["show", "verdicts", "--workdir", str(tmp_path / "none")], capsys)
    assert code == 2 and "no ledger" in err


def test_show_verdicts_adds_the_folder_verdicts_file(tmp_path, capsys):
    _ledger(tmp_path)
    d = tmp_path / "chal"
    d.mkdir()
    (d / "verdicts.jsonl").write_text(json.dumps({"kind": "base", "result": "CORRECT"}) + "\n")
    code, out, _ = _run(["show", "verdicts", "9", "--workdir", str(tmp_path), "--dir", str(d)], capsys)
    assert code == 0 and "verdicts.jsonl (1 submission):" in out and "result=CORRECT" in out
    code, _, err = _run(["show", "verdicts", "--workdir", str(tmp_path), "--dir", str(d), "--json"], capsys)
    assert code == 2 and "--json" in err


def test_timeline_for_a_challenge_is_relative_and_hides_flags(tmp_path):
    _ledger(tmp_path)
    rows = ok.timeline_rows(list(ledger.read(tmp_path)), cid="9")
    assert [r["event"] for r in rows] == ["platform.submit", "platform.submit", "submit.done", "hof.result",
                                          "engine.run"]
    lines = ok.timeline_lines(rows, label="9")
    assert lines[0].startswith("timeline 9: 5 record(s) from ")
    assert lines[1].lstrip().startswith("+") and "      0.0s platform.submit [9]" in lines[1]
    assert "secret_value" not in "\n".join(lines) and "flag=sha:" in lines[2]
    assert "engine=binary.hcfg" in lines[5] and "seconds=1.5" in lines[5]


def test_timeline_by_lane_uses_the_lane_field_or_engine_prefix(tmp_path):
    _ledger(tmp_path)
    recs = list(ledger.read(tmp_path))
    assert [r["event"] for r in ok.timeline_rows(recs, lane="binary")] == ["engine.run"]
    assert [r["event"] for r in ok.timeline_rows(recs, lane="web")] == ["dispatch"]
    with pytest.raises(ok.OpKitError, match="challenge id or --lane"):
        ok.timeline_rows(recs)


def test_show_timeline_cli(tmp_path, capsys):
    _ledger(tmp_path)
    code, out, _ = _run(["show", "timeline", "12", "--workdir", str(tmp_path)], capsys)
    assert code == 0 and "dispatch [12] lane=web" in out
    code, out, _ = _run(["show", "timeline", "9", "--workdir", str(tmp_path), "--kind", "engine.run"], capsys)
    assert code == 0 and "1 record(s)" in out


def test_timeline_limit_keeps_the_last(tmp_path):
    _ledger(tmp_path)
    rows = ok.timeline_rows(list(ledger.read(tmp_path)), cid="9")
    lines = ok.timeline_lines(rows, label="9", limit=2)
    assert lines[0].startswith("timeline 9: 5 record(s) from ") and lines[0].endswith(", last 2 shown")
    assert len(lines) == 3
    assert " hof.result [9]" in lines[1] and " engine.run [9]" in lines[2]
    assert "last" not in ok.timeline_lines(rows, label="9", limit=5)[0]


def test_show_timeline_json_redacts_flags(tmp_path, capsys):
    _ledger(tmp_path)
    code, out, _ = _run(["show", "timeline", "9", "--workdir", str(tmp_path), "--json"], capsys)
    assert code == 0 and "secret_value" not in out and "FLAG{" not in out
    rows = [json.loads(x) for x in out.splitlines()]
    assert len(rows) == 5 and all("flag" not in r and "flag_sha256" not in r for r in rows)
    sends = [r for r in rows if r["event"] == "platform.submit"]
    assert len(sends) == 2 and all(r["flag_ref"].startswith("sha:") for r in sends)
    assert any(r["flag_ref"] == "sha:" + hashlib.sha256(b"FLAG{secret_value}").hexdigest()[:12] for r in sends)


def test_parse_since_forms():
    assert ok.parse_since("10m", now=1000.0) == 400.0
    assert ok.parse_since("2h", now=10000.0) == 2800.0
    assert ok.parse_since("1700000000") == 1700000000.0
    assert ok.parse_since("2026-11-07T08:00:00+00:00") == 1794038400.0 == ok.parse_since("2026-11-07T03:00-05:00")
    with pytest.raises(ok.OpKitError, match="no UTC offset"):
        ok.parse_since("2026-11-07T08:00:00")
    with pytest.raises(ok.OpKitError):
        ok.parse_since("yesterday")
    assert ok.parse_since(None) is None


# ---- hcfg dump ---------------------------------------------------------------------------------------

def _container(obj: dict, key: int, version: int = 1, *, rolling: bool = False) -> bytes:
    plain = json.dumps(obj, separators=(",", ":")).encode()
    if rolling:
        enc = bytes(b ^ ((key + i) & 0xFF) for i, b in enumerate(plain))
    else:
        enc = bytes(b ^ key for b in plain)
    return b"HCFG" + bytes([version, key]) + struct.pack("<HI", len(enc), zlib.crc32(plain) & 0xFFFFFFFF) + enc


def _pe_with(blob_at_data: bytes, overlay: bytes = b"") -> bytes:
    """A minimal PE32 image: headers in 0x200 bytes, one .data section at file 0x200 (0x200 bytes)."""
    img = bytearray(0x400)
    img[0:2] = b"MZ"
    struct.pack_into("<I", img, 0x3C, 0x40)
    img[0x40:0x44] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", img, 0x44, 0x14C, 1, 0, 0, 0, 0xE0, 0x102)
    opt = 0x58
    struct.pack_into("<HBB", img, opt, 0x10B, 14, 0)
    struct.pack_into("<IIIHH", img, opt + 56, 0x2000, 0x200, 0, 3, 0)
    struct.pack_into("<I", img, opt + 92, 16)
    sec = opt + 0xE0
    img[sec:sec + 8] = b".data\0\0\0"
    struct.pack_into("<IIII", img, sec + 8, 0x200, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", img, sec + 36, 0xC0000040)
    img[0x210:0x210 + len(blob_at_data)] = blob_at_data
    return bytes(img) + overlay


def test_hcfg_rows_give_carrier_section_offset_layer_key_and_members(tmp_path):
    a = _container({"campaign": "c1", "c2": "h"}, 0x5A)
    b = _container({"campaign": "c2", "port": 8}, 0x21, version=2)
    (tmp_path / "s1.dll").write_bytes(_pe_with(a, overlay=b))
    (tmp_path / "plain.bin").write_bytes(b"junk" + _container({"campaign": "x"}, 0x33, rolling=True) + b"tail")
    (tmp_path / "none.bin").write_bytes(b"nothing here at all")
    rows = ok.hcfg_rows([tmp_path / "s1.dll", tmp_path / "plain.bin", tmp_path / "none.bin"])
    found = [r for r in rows if r["found"]]
    assert [(r["carrier"], r["section"], r["offset"], r["layer"], r["key"], r["crc_ok"]) for r in found] == [
        ("s1.dll", ".data", 0x210, "xor", "5a", True),
        ("s1.dll", "overlay", 0x400, "xor", "21", True),
        ("plain.bin", "-", 4, "rolling_up", "33", True)]
    assert found[0]["members"] == ["c2", "campaign"] and found[1]["version"] == 2
    assert rows[-1] == {"carrier": "none.bin", "found": False, "size": 19}
    text = "\n".join(ok.hcfg_lines(rows))
    assert "hcfg: 3 container(s) in 3 sample(s)" in text
    assert "s1.dll: section=.data offset=0x210 v=1 layer=xor key=0x5a crc32=0x" in text
    assert "none.bin: none" in text


def test_hcfg_plain_only_skips_the_other_encodings(tmp_path):
    (tmp_path / "r.bin").write_bytes(b"junk" + _container({"campaign": "x"}, 0x33, rolling=True))
    assert [r["found"] for r in ok.hcfg_rows([tmp_path / "r.bin"], others=False)] == [False]
    assert [r["layer"] for r in ok.hcfg_rows([tmp_path / "r.bin"])] == ["rolling_up"]


def test_hcfg_reads_zip_members_and_names_a_missing_sample(tmp_path, capsys):
    z = tmp_path / "delivery.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("d03--variant-000.dll", _pe_with(_container({"campaign": "z"}, 0x10)))
        zf.writestr("d03--notes.txt", b"no config")
    rows = ok.hcfg_rows([z])
    assert [(r["carrier"], r["found"]) for r in rows] == [("delivery.zip!d03--variant-000.dll", True),
                                                          ("delivery.zip!d03--notes.txt", False)]
    with pytest.raises(ok.OpKitError, match="sample not found"):
        ok.hcfg_rows([tmp_path / "gone.bin"])
    code, out, _ = _run(["show", "hcfg", str(z), "--json"], capsys)
    assert code == 0 and json.loads(out)[0]["section"] == ".data"


def test_section_of_elf_and_unknown(tmp_path):
    assert ok.section_of(b"plain bytes", 3) == "-"
    # an ELF64 with one PROGBITS section `.rodata` at file 0x100 (0x40 bytes) and its string table
    img = bytearray(0x300)
    img[0:4] = b"\x7fELF"
    img[4], img[5], img[6] = 2, 1, 1
    shoff, shnum = 0x200, 3
    struct.pack_into("<HHIQQQIHHHHHH", img, 16, 2, 62, 1, 0, 0, shoff, 0, 64, 56, 0, 64, shnum, 2)
    names = b"\0.rodata\0.shstrtab\0"
    img[0x180:0x180 + len(names)] = names
    struct.pack_into("<IIQQQQIIQQ", img, shoff + 64, 1, 1, 2, 0, 0x100, 0x40, 0, 0, 1, 0)
    struct.pack_into("<IIQQQQIIQQ", img, shoff + 128, 9, 3, 0, 0, 0x180, len(names), 0, 0, 1, 0)
    assert ok.section_of(bytes(img), 0x120) == ".rodata"
    assert ok.section_of(bytes(img), 0x10) == "-"


def test_section_of_pe_header_section_and_overlay():
    img = _pe_with(b"", overlay=b"tail")
    assert ok.section_of(img, 0x10) == "header"           # inside the 0x200 bytes of headers
    assert ok.section_of(img, 0x1FF) == "header"
    assert ok.section_of(img, 0x200) == ".data"
    assert ok.section_of(img, 0x401) == "overlay"         # past the last section's raw data


# ---- member dump -------------------------------------------------------------------------------------

def _delivery(path: Path) -> dict:
    bodies = {"d03--variant-000.dll": b"A" * 10, "d01--other.bin": b"B" * 3,
              "d03--variant-000.runtimeconfig.json": b"{}", "d030--late.bin": b"C", "readme.txt": b"hi"}
    with zipfile.ZipFile(path, "w") as zf:
        for n, b in bodies.items():          # archive order = this insertion order
            zf.writestr(n, b)
    return bodies


def test_member_rows_keep_archive_order_and_hash_each(tmp_path):
    z = tmp_path / "delivery.zip"
    bodies = _delivery(z)
    rows = ok.member_rows(z)
    assert [r["name"] for r in rows] == list(bodies)
    assert [r["index"] for r in rows] == [0, 1, 2, 3, 4]
    assert rows[0]["sha256"] == hashlib.sha256(b"A" * 10).hexdigest() and rows[0]["size"] == 10
    assert [r["day"] for r in rows] == ["d03", "d01", "d03", "d030", None]


def test_member_rows_prefix_uses_the_lane_rule(tmp_path):
    z = tmp_path / "delivery.zip"
    _delivery(z)
    rows = ok.member_rows(z, prefix="d03")
    assert [r["name"] for r in rows] == ["d03--variant-000.dll", "d03--variant-000.runtimeconfig.json"]
    assert [r["index"] for r in rows] == [0, 1]
    lines = ok.member_lines(rows, label="delivery.zip", prefix="d03")
    assert lines[0] == "members delivery.zip prefix d03: 2"
    assert lines[1].split() == ["0", "d03--variant-000.dll", "10", hashlib.sha256(b"A" * 10).hexdigest()[:16],
                                "day=d03"]


def test_member_rows_from_a_folder_and_errors(tmp_path, capsys):
    d = tmp_path / "unpacked"
    (d / "sub").mkdir(parents=True)
    (d / "b.bin").write_bytes(b"1")
    (d / "sub" / "a.bin").write_bytes(b"22")
    assert [r["name"] for r in ok.member_rows(d)] == ["b.bin", "sub/a.bin"]
    (tmp_path / "x.txt").write_text("not a zip")
    with pytest.raises(ok.OpKitError, match="not a zip"):
        ok.member_rows(tmp_path / "x.txt")
    code, _, err = _run(["show", "members", str(tmp_path / "missing.zip")], capsys)
    assert code == 2 and "delivery not found" in err


@pytest.mark.needs_tool("py:pyzipper")
def test_member_rows_encrypted_members(tmp_path, monkeypatch):
    import pyzipper
    z = tmp_path / "enc.zip"
    with pyzipper.AESZipFile(z, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(b"infected")
        zf.writestr("d05--a.bin", b"known password")
    z2 = tmp_path / "locked.zip"
    with pyzipper.AESZipFile(z2, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(b"nobody-knows-this-one")
        zf.writestr("d05--b.bin", b"locked")
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "work"))
    rows = ok.member_rows(z)
    assert rows[0]["sha256"] == hashlib.sha256(b"known password").hexdigest()
    rows = ok.member_rows(z2)
    assert rows[0]["locked"] is True and rows[0]["sha256"] is None
    assert "unreadable" in ok.member_lines(rows)[1] and "nobody-knows" not in "\n".join(ok.member_lines(rows))
    # no workdir and no event: the built-in candidates still open the first; the locked one is not called
    # "locked" blind, the dump names the unresolved password store
    monkeypatch.delenv("CTF_WORKDIR")
    monkeypatch.setenv("CTF_EVENT", "no-such-event-b210")
    assert ok.member_rows(z)[0]["locked"] is False
    with pytest.raises(ok.OpKitError, match="password store"):
        ok.member_rows(z2)


# ---- one command with `ctf state` --------------------------------------------------------------------

def test_show_passes_the_state_subcommands_through(tmp_path, capsys):
    d = tmp_path / "chal"
    d.mkdir()
    (d / "attempt.json").write_text(json.dumps({"attempt_id": "A7", "kind": "timed"}))
    code, out, _ = _run(["show", "attempt", "--dir", str(d)], capsys)
    assert code == 0 and "attempt_id: A7" in out
    code, _, err = _run(["show", "result", "--dir", str(d)], capsys)
    assert code == 2 and "result.json not found" in err


def test_state_add_arguments_skip_and_returned_action():
    import argparse
    from ctf.cli import state
    p = argparse.ArgumentParser()
    sub = state.add_arguments(p, skip=("verdicts",))
    assert "verdicts" not in sub.choices and "attempt" in sub.choices
    p2 = argparse.ArgumentParser()
    assert "verdicts" in state.add_arguments(p2).choices
