"""B-139 on the real reader registry (openers/readers.toml) and the CLI, with synthetic Day 9 shapes.

Day 9 at Huntress: Metadata stopped on a new id about a PE file whose machine field a reader already read,
and Binary stopped on a field no catalog knew. Here a bank-only pass that knows none of the new ids
(the lane's state before the live fix) is followed by the ask pass over the real readers:

  * Metadata `d09-pe-001-pe-coff-machine-u16-hex` and `...-pe-machine` on a synthetic PE32+: one fact
    (0x8664), offered unsure, never plain.
  * Binary `d09_analysis_entry_point` on the same file: the field catalog's fact, unsure.
  * A field no reader knows: a STOP that names every reader asked (inert, as the Day 10 retro said).
  * Mobile: apk_facts through the `apk` call on a synthetic package.
  * `ctf ask-readers triage | template | probe` (probe against a fake Game Master on 127.0.0.1, its
    verdicts recorded in the lane's labels ledger).
"""
from __future__ import annotations

import io
import json
import struct
import zipfile
from pathlib import Path

import pytest

from ctf import askreaders as ar
from ctf import cli, paths

from test_askreaders import FakeGM, huntress_at, unsure

LABELS = ar.labels_module()


def pe(machine=0x8664, entry=0x1234) -> bytes:
    """A minimal PE32+ (x86-64) header with one .text section."""
    mz = bytearray(b"MZ" + b"\0" * 0x3a + struct.pack("<I", 0x40))
    coff = struct.pack("<HHIIIHH", machine, 1, 0x5f000000, 0, 0, 0xf0, 0x22)
    opt = bytearray(0xf0)
    struct.pack_into("<HBBIIIII", opt, 0, 0x20b, 14, 0, 0x200, 0x200, 0, entry, 0x1000)
    struct.pack_into("<Q", opt, 24, 0x140000000)
    sec = b".text\0\0\0" + struct.pack("<IIIIIIHHI", 0x200, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)
    body = bytes(mz) + b"PE\0\0" + coff + bytes(opt) + sec
    return body + b"\0" * (0x400 - len(body))


def mq(prop, artifact="sample.exe"):
    """A Metadata question in the Day 9 item-id shape."""
    i = "d09-pe-001-" + prop.replace(".", "-").replace("_", "-")
    return {"qid": i, "id": i, "answer_id": i, "question": f"Determine {prop} for {artifact}.",
            "artifact": artifact, "answer_format": {"kind": "exact_text", "syntax": "exact artifact-derived value only"}}


def bq(i):
    return {"qid": i, "id": i, "answer_id": i, "question": f"What is {i} of the sample?",
            "answer_format": {"kind": "exact_text", "syntax": "exact artifact-derived value only"}}


def nothing_banked(questions, files, ctx):
    """The lane's bank-only pass before the day's live fix: no rule for any new id."""
    return {q["qid"]: None for q in questions}


@pytest.fixture
def work(tmp_path, monkeypatch):
    w = tmp_path / "work"
    w.mkdir()
    monkeypatch.setenv("CTF_WORKDIR", str(w))
    monkeypatch.delenv("CTF_JUDGE_LEDGER", raising=False)
    return w


def values(offer):
    return [v for _, v in unsure(offer)[1]]


def test_metadata_day9_shape_a_known_fact_is_offered_unsure_from_the_reader_that_reads_it(work):
    solver = ar.AskingSolver(nothing_banked, "metadata")
    qs = [mq("pe.coff_machine_u16_hex"), mq("pe.machine"), mq("pe.bogus_thing")]
    got = solver.solve_set(qs, {"sample.exe": pe()}, {})
    coff, machine, bogus = (got[q["qid"]] for q in qs)
    assert LABELS.is_unsure(coff) and values(coff) == ["0x8664"]
    assert LABELS.is_unsure(machine) and "0x8664" in values(machine) and "34404" in values(machine)
    assert bogus is None
    rep = solver.last_report
    stop = {a.qid: a for a in rep.asked}[mq("pe.bogus_thing")["qid"]]
    assert stop.outcome == ar.NO_READER
    assert "binary.field_catalog [sample.exe]: none" in stop.reason and "metadata.properties_strict: none" in stop.reason
    # a different machine is a different fact: the offer follows the bytes, not a constant
    other = solver.solve_set([mq("pe.coff_machine_u16_hex")], {"sample.exe": pe(machine=0x014c)}, {})
    assert values(other[mq("pe.coff_machine_u16_hex")["qid"]]) == ["0x014c"]


def test_binary_day9_shape_the_field_catalog_answers_and_an_unknown_field_stops_named(work):
    solver = ar.AskingSolver(nothing_banked, "binary")
    got = solver.solve_set([bq("d09_analysis_entry_point"), bq("d10_analysis_has_bogus_marker")],
                           {"sample.exe": pe(entry=0x2468)}, {})
    key, opts = unsure(got["d09_analysis_entry_point"])
    assert key == "binary.entry_point/pe" and ("rva:hex", "0x2468") in opts and ("va:hex", "0x140002468") in opts
    assert got["d10_analysis_has_bogus_marker"] is None
    (stop,) = solver.last_report.stops()
    assert stop.reason.startswith("no registered reader knows d10_analysis_has_bogus_marker")


def _dex(*strings):
    n = len(strings)
    head = bytearray(b"dex\n035\x00" + b"\x00" * (0x70 - 8))
    struct.pack_into("<II", head, 0x38, n, 0x70)
    data, offs = b"", []
    base = 0x70 + 4 * n
    for s in strings:
        b = s.encode()
        offs.append(base + len(data))
        ln, uleb = len(b), b""
        while True:
            byte = ln & 0x7F
            ln >>= 7
            uleb += bytes([byte | (0x80 if ln else 0)])
            if not ln:
                break
        data += uleb + b + b"\0"
    out = bytearray(head) + b"\x00" * (4 * n) + data
    for i, o in enumerate(offs):
        struct.pack_into("<I", out, 0x70 + 4 * i, o)
    return bytes(out)


def test_mobile_apk_facts_is_asked_through_the_package_members(work):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("classes.dex", _dex("DAY-99:deobf:mapping", "MOB-99-ABCDEF"))
    q = {"qid": "control", "id": "control", "question": "What is the vulnerable control name?"}
    rep = ar.ask_missing([q], {}, {"delivery.apk": buf.getvalue(), "readme.txt": b"not a package"}, "mobile")
    (asked,) = rep.asked
    assert asked.outcome == ar.OFFER
    assert [a.member for a in asked.answers] == ["delivery.apk"]          # only the package is handed over
    key, opts = unsure(asked.offer)
    assert key == "mobile.control/apk" and ("as-written", "deobf") in opts


# ------------------------------------------------------------------------------------------ the CLI

@pytest.fixture
def case(tmp_path, work):
    files = tmp_path / "files"
    files.mkdir()
    (files / "sample.exe").write_bytes(pe())
    qs = [mq("pe.machine"), mq("pe.bogus_thing")]
    (tmp_path / "questions.json").write_text(json.dumps({"questions": qs}))
    (tmp_path / "answers.json").write_text(json.dumps({qs[0]["qid"]: None, qs[1]["qid"]: "banked"}))
    return tmp_path, qs


def test_cli_triage_exit_codes_and_json(case, capsys):
    tmp, qs = case
    base = ["ask-readers", "triage", "--lane", "metadata", "--questions", str(tmp / "questions.json"),
            "--files", str(tmp / "files")]
    assert cli.main(base) == 1                                        # pe.bogus_thing stops the lane
    out = capsys.readouterr().out
    assert f"STOP {qs[1]['qid']}: no registered reader knows" in out and f"OFFER {qs[0]['qid']}" in out
    assert cli.main(base + ["--answers", str(tmp / "answers.json"), "--json"]) == 0   # the bogus id was banked
    rep = json.loads(capsys.readouterr().out)
    assert rep["counts"]["offer"] == 1 and [a["qid"] for a in rep["asked"]] == [qs[0]["qid"]]
    assert cli.main(base + ["--id", "not-a-question"]) == 2
    assert "not among the questions" in capsys.readouterr().err
    assert cli.main(["ask-readers", "triage", "--lane", "metadata", "--questions", str(tmp / "missing.json"),
                     "--files", str(tmp / "files")]) == 2


def test_cli_template_writes_the_one_field_reader_with_what_every_reader_said(case, work, capsys):
    tmp, qs = case
    qid = qs[1]["qid"]
    assert cli.main(["ask-readers", "template", "--lane", "metadata", "--id", qid, "--questions",
                     str(tmp / "questions.json"), "--files", str(tmp / "files")]) == 0
    path = work / "ask-readers" / "metadata" / "field_d09_pe_001_pe_bogus_thing.py"
    text = path.read_text()
    assert f'FIELD_ID = "{qid}"' in text and "metadata.properties_strict: none" in text
    assert "| UNKNOWN PROPERTY pe.bogus_thing" in text                 # the reader's own facts page, for the agent
    assert cli.main(["ask-readers", "template", "--lane", "metadata", "--id", qid]) == 2   # exists


def test_cli_probe_closes_the_id_through_the_gate_and_learns_the_name(case, work, monkeypatch, capsys):
    tmp, qs = case
    for name in ("CTF_TOKEN", "CTF_PLATFORM_URL"):
        monkeypatch.delenv(name, raising=False)
    gm = FakeGM()
    try:
        profile = huntress_at(tmp, gm.url)
        monkeypatch.setattr(paths, "events_root", lambda: profile.path.parent.parent)
        gm.key["metadata-day-09"] = {qs[0]["qid"]: "34404"}
        code = cli.main(["ask-readers", "probe", "--lane", "metadata", "--challenge", "metadata-day-09",
                         "--event", "huntress", "--questions", str(tmp / "questions.json"), "--files",
                         str(tmp / "files"), "--answers", str(tmp / "answers.json"), "--json"])
        posts = list(gm.posts)
    finally:
        gm.close()
    assert code == 0
    rep = json.loads(capsys.readouterr().out)
    accepted = [p for p in rep["probes"] if p["status"] == "accepted"]
    assert [p["value"] for p in accepted] == ["34404"] and posts[-1]["answers"] == {qs[0]["qid"]: "34404"}
    assert all(p["answers"] != {qs[0]["qid"]: "34404"} for p in posts[:-1])    # one option per request
    rows = [json.loads(line) for line in (work / "_ledger" / "metadata.jsonl").read_text().splitlines()]
    assert {(r["key"], r["name"], r["verdict"]) for r in rows} >= {("metadata.format/pe.machine", "integer", "accepted")}


def test_cli_probe_exits_1_when_every_option_is_rejected(case, work, monkeypatch, capsys):
    tmp, qs = case
    for name in ("CTF_TOKEN", "CTF_PLATFORM_URL"):
        monkeypatch.delenv(name, raising=False)
    gm = FakeGM()
    try:
        profile = huntress_at(tmp, gm.url)
        monkeypatch.setattr(paths, "events_root", lambda: profile.path.parent.parent)
        gm.key["metadata-day-09"] = {qs[0]["qid"]: "not-any-option"}
        code = cli.main(["ask-readers", "probe", "--lane", "metadata", "--challenge", "metadata-day-09",
                         "--event", "huntress", "--questions", str(tmp / "questions.json"), "--files",
                         str(tmp / "files"), "--answers", str(tmp / "answers.json"), "--json"])
        posts = list(gm.posts)
    finally:
        gm.close()
    rep = json.loads(capsys.readouterr().out)
    assert rep["probes"] and {p["status"] for p in rep["probes"]} == {"rejected"}
    assert len(posts) == len(rep["probes"])                            # each option was sent and judged
    assert code == 1                                                    # the id is still open


def test_cli_files_skips_a_symlink_and_never_reads_its_target(case, capsys):
    tmp, _qs = case
    outside = tmp / "outside"
    outside.mkdir()
    (outside / "other.exe").write_bytes(pe(entry=0x9999))
    (tmp / "files" / "link.exe").symlink_to(outside / "other.exe")
    (tmp / "bq.json").write_text(json.dumps({"questions": [bq("d09_analysis_entry_point")]}))
    code = cli.main(["ask-readers", "triage", "--lane", "binary", "--questions", str(tmp / "bq.json"),
                     "--files", str(tmp / "files"), "--json"])
    rep = json.loads(capsys.readouterr().out)
    (asked,) = rep["asked"]
    members = [a["member"] for a in asked["answers"] if a["reader"] == "binary.field_catalog"]
    assert members == ["sample.exe"]                                    # link.exe was not handed to any reader
    assert asked["outcome"] == "offer" and code == 0
