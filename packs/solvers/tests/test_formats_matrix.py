"""B-162: the property coverage matrix, the RIFF container pack (readers_riff.py) and `ctf formats`.

The matrix must report every way a format is not covered: a check the readers miss, a nearest-reader
answer that is plain or read by another reader, a sample identified as something else, a namespace with
no reader, a reader that raises on a well-formed file. Each is provoked here on purpose.
"""
import argparse
import dataclasses
import struct

import pytest

from ctf import formats
from ctf.cli import formats as cli
from ctf.formats import corpus as C
from ctf.formats import matrix as X

LANE = X.lane_module()
import labels  # noqa: E402

CATALOG = formats.load()
FMT = {f.id: f for f in CATALOG}


@pytest.fixture
def no_judge(monkeypatch):
    monkeypatch.setenv("CTF_JUDGE_LEDGER", "off")


def _fmt(base, **kw):
    return dataclasses.replace(FMT[base], **kw)


# ------------------------------------------------------------------ the shipped catalog has no problem

@pytest.fixture(scope="module")
def shipped():
    return X.compute(CATALOG, LANE)


def test_the_shipped_matrix_has_no_problem(shipped):
    assert shipped.problems() == []
    assert [f.id for f in shipped.formats] == [f.id for f in CATALOG]
    for f in shipped.formats:
        assert all(n.readers > 0 for n in f.namespaces), f.id
        assert f.checks and all(c.matched for c in f.checks if c.status != "not-run"), f.id


def test_the_matrix_runs_without_the_judge_and_restores_the_environment(monkeypatch, shipped):
    monkeypatch.setenv("CTF_JUDGE_LEDGER", "on")
    m = X.compute((_fmt("msi", samples=("msi_package",), nearest=(), gaps=()),), LANE)
    import os
    assert os.environ["CTF_JUDGE_LEDGER"] == "on"
    row = next(c for c in m.formats[0].checks if c.prop == "msi.product_code_guid")
    assert row.status == "unsure"          # judged plain with the seed, but the matrix asks with no judge


def test_the_markdown_is_deterministic_and_lists_every_format(shipped):
    again = X.compute(CATALOG, LANE)
    text = X.render_markdown(shipped)
    assert text == X.render_markdown(again)
    for f in CATALOG:
        assert f"## {f.rank}. {f.id}: " in text
    assert "## Problems\n\nNone." in text


def test_gaps_are_reported_with_their_answer(shipped):
    gaps = {g.asked: g for f in shipped.formats for g in f.gaps}
    assert gaps["word.title"].status == "none"
    text = X.render_markdown(shipped)
    assert "| word.title | none | no namespace alias" in text


# ------------------------------------------------------------------ every problem is reported

def test_a_missed_check_is_a_problem(no_judge, monkeypatch):
    good = C.BUILDERS["lnk_shortcut"]

    def wrong():
        s = good()
        return dataclasses.replace(s, checks=(C.Check("lnk.target_path", "C:\\elsewhere.exe"),))
    monkeypatch.setitem(C.BUILDERS, "lnk_shortcut", wrong)
    m = X.compute((_fmt("lnk", nearest=(), gaps=()),), LANE)
    assert any("lnk.target_path" in p and "C:\\\\elsewhere.exe" in p for p in m.problems()), m.problems()


def test_a_plain_nearest_answer_is_a_problem(no_judge):
    near = (formats.Nearest("size_bytes", "size_bytes", "lnk_shortcut"),)
    m = X.compute((_fmt("lnk", nearest=near, gaps=()),), LANE)
    assert any("nearest size_bytes is plain" in p for p in m.problems()), m.problems()


def test_a_nearest_answer_by_another_reader_is_a_problem(no_judge):
    near = (formats.Nearest("wave.sample_rate", "wav.channels", "riff_wav"),)
    m = X.compute((_fmt("riff", nearest=near, gaps=()),), LANE)
    assert any("read by wav.sample_rate_hz, the catalog says wav.channels" in p for p in m.problems()), m.problems()


def test_an_unread_nearest_spelling_is_a_problem(no_judge):
    near = (formats.Nearest("word.title", "docx.title", "ooxml_docx"),)
    m = X.compute((_fmt("ooxml", samples=("ooxml_docx",), nearest=near, gaps=()),), LANE)
    assert any("nearest word.title is none" in p for p in m.problems()), m.problems()


def test_a_misidentified_sample_and_a_namespace_with_no_reader_are_problems(no_judge):
    m = X.compute((_fmt("lnk", samples=("riff_webp",), namespaces=("lnk", "nosuchspace"), nearest=(), gaps=()),
                   _fmt("riff", samples=("riff_webp",), nearest=(), gaps=())), LANE)
    problems = m.problems()
    assert not any(p.startswith("riff:") for p in problems), problems
    assert any("sample riff_webp is identified as 'riff'" in p for p in problems), problems
    assert any("namespace nosuchspace has no reader" in p for p in problems), problems


def test_a_reader_that_raises_on_the_corpus_is_a_problem(no_judge, monkeypatch):
    def broken(n, d):
        raise ValueError("bug")
    monkeypatch.setitem(LANE.REG, "lnk_corpus_probe_field", LANE.Prop("lnk.corpus_probe_field", broken, "text", False))
    m = X.compute((_fmt("lnk", nearest=(), gaps=()),), LANE)
    ns = next(n for n in m.formats[0].namespaces if n.namespace == "lnk")
    assert ns.error == 1 and ns.errors == ["lnk.corpus_probe_field (ValueError)"]
    assert any("raised on the corpus" in p for p in m.problems())


def test_a_sample_the_facts_page_cannot_type_is_a_problem(no_judge, monkeypatch):
    real = X.lane_kind
    monkeypatch.setattr(X, "lane_kind", lambda lane, data: None if data[:4] == b"RIFF" else real(lane, data))
    m = X.compute((_fmt("riff", samples=("riff_webp",), nearest=(), gaps=()),
                   _fmt("lnk", nearest=(), gaps=())), LANE)
    assert m.formats[0].facts_kind == {"riff_webp": None} and m.formats[1].facts_kind["lnk_shortcut"] is not None
    assert m.problems() == ["riff: the lane's facts page has no type for sample riff_webp"]


def test_first_says_whether_the_expected_value_is_the_first_option(no_judge):
    avi = C.build("riff_avi")
    answer, _ = X.ask(LANE, "riff.form_type", avi)              # offered as stored ('AVI '), then trimmed
    assert X.matches(answer, "AVI ", labels) == ("unsure", True, True)
    assert X.matches(answer, "AVI", labels) == ("unsure", True, False)
    assert X.matches(answer, "AVIX", labels) == ("unsure", False, False)
    assert X.matches("7", 7, labels) == ("plain", True, True)
    row = X.compute((_fmt("riff", samples=("riff_avi",), nearest=(), gaps=()),), LANE).formats[0]
    form = next(c for c in row.checks if c.prop == "riff.form_type")
    assert (form.matched, form.first) == (True, True)
    text = X.render_markdown(X.Matrix([row]))
    assert "| riff_avi | riff.form_type | AVI  | unsure: AVI  | yes | yes |" in text


def test_first_is_no_when_another_option_comes_before_the_expected_one(no_judge, monkeypatch):
    good = C.BUILDERS["riff_avi"]

    def trimmed():
        s = good()
        return dataclasses.replace(s, checks=(C.Check("riff.form_type", "AVI"),))
    monkeypatch.setitem(C.BUILDERS, "riff_avi", trimmed)
    row = X.compute((_fmt("riff", samples=("riff_avi",), nearest=(), gaps=()),), LANE).formats[0]
    assert [(c.matched, c.first) for c in row.checks] == [(True, False)]
    assert "| riff_avi | riff.form_type | AVI | unsure: AVI  | yes | no |" in X.render_markdown(X.Matrix([row]))


def test_a_check_whose_tool_is_missing_is_not_run_never_matched(no_judge, monkeypatch):
    monkeypatch.setattr(X, "tool_available", lambda spec: False)
    m = X.compute((_fmt("msi", samples=("msi_package_lzx",), nearest=(), gaps=()),), LANE)
    rows = [c for c in m.formats[0].checks if c.status == "not-run"]
    assert [c.prop for c in rows] == ["msi.cabinet_file_sha256_list"] and not rows[0].matched
    assert "needs_tool: 7zz|bsdtar not available" in rows[0].reason
    assert m.problems() == [] and len(m.not_run()) == 1


def test_renderings_cover_the_lanes_forms_and_nothing_else():
    import datetime as dt
    t = dt.datetime(2025, 3, 4, 5, 6, 7, tzinfo=dt.timezone.utc)
    assert {"2025-03-04T05:06:07Z", "2025-03-04T05:06:07", "133855383670000000"} <= X.renderings(t)
    assert X.renderings(["a", "b"]) >= {"a,b", "a, b", '["a","b"]'} and "b,a" not in X.renderings(["a", "b"])
    assert X.renderings(False) == {"false"} and X.renderings(7) == {"7"}


# ------------------------------------------------------------------ readers_riff.py

def _ask(prop, sample):
    answer, _ = X.ask(LANE, prop, sample)
    return X.classify(answer, labels)


def test_riff_pack_is_loaded_by_the_lane():
    assert "readers_riff.py" in LANE.MORE_LOADED and LANE.MORE_LOADED["readers_riff.py"][0] >= 20
    assert "riff" in LANE.NAMESPACES and LANE.NS_ALIAS["riff_file"] == "riff"
    assert "readers_riff.py" not in {c.split(":")[0] for c in LANE.MORE_CLASHES}


def test_a_padded_form_type_is_offered_as_stored_then_trimmed(no_judge):
    status, values, names = _ask("riff.form_type", C.build("riff_avi"))
    assert status == "unsure" and values[:2] == ["AVI ", "AVI"] and names[:2] == ["raw", "trimmed"]


def test_riff_field_of_a_known_form_is_the_forms_own_reader(no_judge):
    assert _ask("riff.sample_rate", C.build("riff_wav"))[1][0] == "22050"
    assert _ask("riff.vp8l_width", C.build("riff_webp"))[1][0] == "97"
    assert _ask("riff.sample_rate", C.build("riff_avi"))[0] == "none"      # an AVI has no sample rate reader
    assert _ask("riff.sample_rate", C.build("riff_other"))[0] == "none"    # RMID: no namespace reads the form


def test_a_chunk_that_runs_past_the_end_establishes_no_chunk_list(no_judge):
    s = C.build("riff_wav")
    cut = s.data[:200]                                  # the data chunk states 8820 bytes; 200 bytes are here
    fixed = cut[:4] + struct.pack("<I", len(cut) - 8) + cut[8:]
    t = dataclasses.replace(s, data=fixed)
    assert _ask("riff.chunk_ids", t)[0] == "none"
    assert _ask("riff.form_type", t)[1][0] == "WAVE"    # what the header says still stands


def test_an_info_tag_given_twice_is_not_answered(no_judge):
    info = b"INFO" + C._chunk(b"INAM", b"one\x00") + C._chunk(b"INAM", b"two\x00")
    data = C._riff(b"RMID", C._chunk(b"data", b"\x00" * 4) + C._chunk(b"LIST", info))
    s = C.Sample("dup", "dup.rmi", data, ())
    assert _ask("riff.info_inam", s)[0] == "none"
    assert _ask("riff.chunk_ids", s)[1][0] == "data,LIST"


def _first(prop, data, name="x.rmi"):
    status, values, _ = _ask(prop, C.Sample("probe", name, data, ()))
    return status, (values[0] if values else None)


def test_an_odd_sized_chunk_is_followed_after_its_pad_byte(no_judge):
    """RIFF pads an odd-sized chunk (and an odd INFO entry) to an even length: the next one starts after it."""
    info = b"INFO" + C._chunk(b"INAM", b"abcd\x00") + C._chunk(b"IART", b"Odd Artist\x00")   # 5 bytes, then 11
    data = C._riff(b"RMID", C._chunk(b"junk", b"abc") + C._chunk(b"next", b"wxyz") + C._chunk(b"LIST", info))
    assert data[12 + 8 + 3] == 0                                  # the pad byte is there
    assert _first("riff.chunk_ids", data) == ("unsure", "junk,next,LIST")
    assert _first("riff.chunk_count", data) == ("unsure", "3")
    assert _first("riff.chunk_next_size_bytes", data) == ("unsure", "4")
    assert _first("riff.chunk_junk_size_bytes", data) == ("unsure", "3")     # the stated size, not the padded one
    assert _first("riff.info_iart", data) == ("unsure", "Odd Artist")
    assert _first("riff.info_tags", data) == ("unsure", "INAM,IART")


def test_two_chunks_with_one_id_have_no_single_size(no_judge):
    data = C._riff(b"RMID", C._chunk(b"data", b"\x00" * 4) + C._chunk(b"data", b"\x00" * 6) + C._chunk(b"once", b"\x00" * 2))
    assert _first("riff.chunk_ids", data) == ("unsure", "data,data,once")
    assert _first("riff.chunk_data_size_bytes", data) == ("none", None)
    assert _first("riff.chunk_once_size_bytes", data) == ("unsure", "2")


def test_a_stated_size_past_the_end_of_the_file_leaves_no_trailing_bytes(no_judge):
    good = C._riff(b"RMID", C._chunk(b"data", b"\x00" * 4))
    longer = good[:4] + struct.pack("<I", len(good) - 8 + 100) + good[8:]       # states 100 bytes it does not have
    assert _first("riff.trailing_bytes", longer) == ("unsure", "0")
    assert _first("riff.file_size_matches", longer) == ("unsure", "false")
    assert _first("riff.size_bytes", longer) == ("unsure", str(len(good) - 8 + 100))
    assert _first("riff.file_size_matches", good) == ("unsure", "true")
    assert _first("riff.trailing_bytes", good + b"xyz") == ("unsure", "3")
    assert _first("riff.file_size_matches", good + b"x") == ("unsure", "false")


def test_riff_field_keeps_only_the_options_a_container_name_can_offer(no_judge, monkeypatch):
    """riff.<field> hands on the form reader's options whose names are forms (FORM_NAMES) and whose
    values are text, and drops the rest; with none left it is not answered."""
    def mixed(n, d):
        raise LANE.Ambiguous([("raw", "kept value"), ("not_a_form_name", "dropped value"), ("trimmed", "also kept")])

    def foreign(n, d):
        raise LANE.Ambiguous([("not_a_form_name", "dropped value"), ("another_odd_name", "dropped too")])
    assert "not_a_form_name" not in LANE.FORM_NAMES and "raw" in LANE.FORM_NAMES
    monkeypatch.setitem(LANE.REG, "wav_corpus_mixed_probe", LANE.Prop("wav.corpus_mixed_probe", mixed, "text", False))
    monkeypatch.setitem(LANE.REG, "wav_corpus_foreign_probe", LANE.Prop("wav.corpus_foreign_probe", foreign, "text", False))
    wav = C.build("riff_wav")
    status, values, names = _ask("riff.corpus_mixed_probe", wav)
    assert status == "unsure" and values[:2] == ["kept value", "also kept"], (values, names)
    assert "dropped value" not in values
    assert _ask("riff.corpus_foreign_probe", wav)[0] == "none"


def test_not_a_riff_file_is_absent_not_a_value(no_judge):
    s = C.build("lnk_shortcut")
    status, values, names = _ask("riff.form_type", s)
    assert status in ("none", "unsure") and values in ([], ["none"])


def test_the_facts_page_of_a_wav_lists_the_containers_facts():
    s = C.build("riff_wav")
    rows = LANE.facts(s.name, s.data, "wav")
    assert "riff.form_type = WAVE" in rows and any(r.startswith("riff.chunk_ids = ") for r in rows)


# ------------------------------------------------------------------ the command

def _args(action, **kw):
    base = {"catalog": None, "json": False, "write": False, "check": False, "samples": [], "out": None, "files": []}
    base.update(kw)
    return argparse.Namespace(action=action, **base)


SMALL = '''
[[format]]
id = "lnk"
rank = 1
label = "shell link"
basis = "test"
extensions = [".lnk"]
namespaces = ["lnk"]
samples = ["lnk_shortcut"]
'''


def test_cli_list_prints_the_catalog_by_rank(capsys):
    assert cli.run(_args("list")) == 0
    out = capsys.readouterr().out
    assert [line.split(".")[0].strip() for line in out.splitlines() if not line.startswith("      ")] == \
        [str(f.rank) for f in CATALOG]


def test_cli_build_writes_the_builders_bytes_and_refuses_to_overwrite(tmp_path, capsys):
    assert cli.run(_args("build", out=tmp_path, samples=["lnk_shortcut", "cab_mszip"])) == 0
    assert (tmp_path / "lnk_shortcut" / "updater.lnk").read_bytes() == C.build("lnk_shortcut").data
    assert (tmp_path / "cab_mszip" / "payload.cab").read_bytes() == C.build("cab_mszip").data
    assert cli.run(_args("build", out=tmp_path, samples=["lnk_shortcut"])) == 2
    assert "exists; not overwritten" in capsys.readouterr().err
    assert cli.run(_args("build", out=tmp_path / "x", samples=["nope"])) == 2


def test_cli_identify(tmp_path, capsys):
    msi = tmp_path / "setup.msi"
    msi.write_bytes(C.build("msi_package").data)
    other = tmp_path / "x.lnk"
    other.write_bytes(b"not a shortcut")
    assert cli.run(_args("identify", files=[msi])) == 0
    assert "msi (sure: structure)" in capsys.readouterr().out
    assert cli.run(_args("identify", files=[other])) == 1
    assert "lnk (unsure: extension .lnk only" in capsys.readouterr().out
    assert cli.run(_args("identify", files=[tmp_path / "absent"])) == 2


def test_cli_identify_maps_the_file_and_names_a_limit_or_a_detector_bug(tmp_path, monkeypatch, capsys):
    docx = tmp_path / "a.docx"
    docx.write_bytes(C.build("ooxml_docx").data)

    def whole(*a, **k):
        raise AssertionError("the file was read whole")
    monkeypatch.setattr(type(docx), "read_bytes", whole)
    assert cli.run(_args("identify", files=[docx])) == 0
    assert "ooxml (sure: structure)" in capsys.readouterr().out
    monkeypatch.setattr(formats, "MAX_ZIP_DIRECTORY_BYTES", 64)
    assert cli.run(_args("identify", files=[docx])) == 2
    assert "over the 64-byte limit identify reads" in capsys.readouterr().err
    monkeypatch.setattr(formats, "MAX_ZIP_DIRECTORY_BYTES", 1 << 24)
    monkeypatch.setitem(formats.DETECTORS, "eml", lambda d: d.no_such_attribute)
    assert cli.run(_args("identify", files=[docx])) == 2
    assert "the eml detector raised AttributeError" in capsys.readouterr().err


def test_cli_matrix_write_then_check(tmp_path, monkeypatch, capsys):
    cat = tmp_path / "small.toml"
    cat.write_text(SMALL, encoding="utf-8")
    doc = tmp_path / "FORMATS.md"
    monkeypatch.setattr(X, "doc_path", lambda: doc)
    assert cli.run(_args("matrix", catalog=cat, check=True)) == 1          # not written yet: stale
    assert cli.run(_args("matrix", catalog=cat, write=True)) == 0
    assert "## 1. lnk: shell link" in doc.read_text(encoding="utf-8")
    assert cli.run(_args("matrix", catalog=cat, check=True)) == 0
    doc.write_text(doc.read_text(encoding="utf-8") + "edited\n", encoding="utf-8")
    assert cli.run(_args("matrix", catalog=cat, check=True)) == 1
    capsys.readouterr()
    assert cli.run(_args("matrix", catalog=cat, json=True)) == 0
    assert '"problems": []' in capsys.readouterr().out


def test_cli_matrix_exits_1_on_a_problem_and_2_on_a_bad_catalog(tmp_path, capsys):
    cat = tmp_path / "bad.toml"
    cat.write_text(SMALL.replace('namespaces = ["lnk"]', 'namespaces = ["lnk", "nosuchspace"]'), encoding="utf-8")
    assert cli.run(_args("matrix", catalog=cat)) == 1
    assert "PROBLEM lnk: namespace nosuchspace has no reader" in capsys.readouterr().err
    cat.write_text(SMALL.replace("rank = 1", "rank = 3"), encoding="utf-8")
    assert cli.run(_args("matrix", catalog=cat)) == 2
