"""B-155: the blind rehearsal corpus (ctf.corpus) and its path resolver (ctf.paths).

A synthetic corpus is built in a temp dir inside each test (never a real challenge, never committed).
Tests cover the index schema, blind staging (the key and answer files never reach the staged tree,
however they are linked or copied), scoring against the key, the pass/fail gates, the fake-CTFd
intake path (engines run, per-engine results), the live-service replay as a reachability check, the
public-repo importer and the CLI. Everything runs on 127.0.0.1; no challenge binary runs and nothing
submits.
"""
from __future__ import annotations

import datetime as dt
import os
import struct
import subprocess
import sys
import types
import zipfile
import zlib
from pathlib import Path

import pytest

from ctf import corpus, event, fakectfd, flagfmt, paths

UTC = dt.timezone.utc
DNS_SVC = ('kind = "dns"\n[records]\n"flag.chal" = ["{flag}"]\n'
           '[probe]\nname = "flag.chal"\nqtype = "TXT"\n')


def profile(categories=("Forensics", "Web", "pwn")):
    return event.parse({
        "slug": "demo", "name": "Demo CTF", "categories": list(categories),
        "dates": {"start": dt.datetime(2030, 3, 1, tzinfo=UTC), "end": dt.datetime(2030, 3, 3, tzinfo=UTC)},
        "platform": {"kind": "ctfd", "base_url": "https://demo.example/"},
        "flag": {"prefixes": ["DEMO"]},
        "rules": {"submit_mode": "auto", "flag_sharing": "allowed", "ai_on_platform": "allowed"},
    })


def ff():
    return flagfmt.for_profile(profile())


def _challenge(root: Path, cid, *, files, key="DEMO{win}", strip_files=None, service=None, path=None):
    d = root / (path or cid)
    d.mkdir(parents=True)
    for name, content in files.items():
        p = d / name
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            p.write_bytes(content)
        else:
            p.write_text(content)
    if key is not None:
        (d / "flag.txt").write_text(key + "\n")
    for name, content in (strip_files or {}).items():
        p = d / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    if service is not None:
        (d / "service.toml").write_text(service)
    return d


def _png_with_text(text: bytes) -> bytes:
    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xffffffff)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 0, 0, 0, 0))
            + chunk(b"tEXt", b"Comment\x00" + text) + chunk(b"IDAT", zlib.compress(b"\x00\x00"))
            + chunk(b"IEND", b""))


# ---------------------------------------------------------------------------- index schema

def test_parse_index_rejects_bad_shapes():
    with pytest.raises(corpus.CorpusError, match="no .*challenge"):
        corpus.parse_index({})
    with pytest.raises(corpus.CorpusError, match="duplicate"):
        corpus.parse_index({"challenge": [{"id": "x", "category": "Web"}, {"id": "x", "category": "Web"}]})
    with pytest.raises(corpus.CorpusError, match="category"):
        corpus.parse_index({"challenge": [{"id": "x"}]})
    with pytest.raises(corpus.CorpusError, match="id"):
        corpus.parse_index({"challenge": [{"category": "Web"}]})


@pytest.mark.parametrize("bad", ["../x", "a/b", "..", ".hidden", "a\\b", "-x", "a..b"])
def test_parse_index_rejects_ids_that_are_not_a_folder_name(bad):
    with pytest.raises(corpus.CorpusError, match="names a folder"):
        corpus.parse_index({"challenge": [{"id": bad, "category": "Web"}]})


def test_parse_index_accepts_a_plain_id():
    [c] = corpus.parse_index({"challenge": [{"id": "csctf2025-logs_1.v2", "category": "Web"}]})
    assert c.id == "csctf2025-logs_1.v2"


def test_parse_index_defaults():
    [c] = corpus.parse_index({"challenge": [{"id": "x", "category": "Web"}]})
    assert c.stage == ("*",) and c.strip == () and c.key_file == "flag.txt" and c.service is None


def test_committed_index_loads():
    idx = corpus.load_index()
    ids = {c.id for c in idx}
    assert {"dns-txt-logs", "socat-print", "web-container", "static-forensics"} <= ids
    assert any(c.service for c in idx)


def test_challenge_path_may_not_escape_the_corpus_root(tmp_path):
    cr = tmp_path / "corpus"
    cr.mkdir()
    (tmp_path / "outside").mkdir()
    [c] = corpus.parse_index({"challenge": [{"id": "c1", "category": "Web", "path": "../outside"}]})
    with pytest.raises(corpus.CorpusError, match="escapes"):
        c.challenge_dir(cr)
    with pytest.raises(corpus.CorpusError, match="escapes"):
        corpus.read_key(c, cr)
    [ok] = corpus.parse_index({"challenge": [{"id": "c2", "category": "Web", "path": "sub/c2"}]})
    assert ok.challenge_dir(cr) == (cr / "sub" / "c2").resolve()


# ---------------------------------------------------------------------------- blind staging

def test_stage_is_blind_key_and_answers_excluded(tmp_path):
    cr = tmp_path / "corpus"
    _challenge(cr, "c1", files={"capture.txt": "noise DEMO{win} noise", "nested/data.bin": "x"},
               key="DEMO{win}", strip_files={"solution/ans.md": "DEMO{win} here", "notes.sol": "DEMO{win}"})
    [c] = corpus.parse_index({"challenge": [{"id": "c1", "category": "Forensics",
                                             "strip": ["solution/**", "*.sol"]}]})
    dest = tmp_path / "staged"
    members = corpus.stage(c, cr, dest)
    assert {m.as_posix() for m in members} == {"capture.txt", "nested/data.bin"}
    assert not (dest / "flag.txt").exists()
    assert not (dest / "solution").exists()
    assert not (dest / "notes.sol").exists()
    blob = b"".join(p.read_bytes() for p in dest.rglob("*") if p.is_file())
    assert blob.count(b"DEMO{win}") == 1


def test_stage_excludes_key_even_when_a_stage_glob_would_match_it(tmp_path):
    cr = tmp_path / "corpus"
    _challenge(cr, "c1", files={"a.txt": "x"}, key="DEMO{k}")
    [c] = corpus.parse_index({"challenge": [{"id": "c1", "category": "Web", "stage": ["*"]}]})
    members = corpus.stage(c, cr, tmp_path / "s")
    assert Path("flag.txt") not in members
    assert not (tmp_path / "s" / "flag.txt").exists()


def test_stage_refuses_a_symlink_to_the_key(tmp_path):
    cr = tmp_path / "corpus"
    d = _challenge(cr, "c1", files={"a.txt": "x"}, key="DEMO{k}")
    (d / "copy").symlink_to(d / "flag.txt")
    [c] = corpus.parse_index({"challenge": [{"id": "c1", "category": "Web"}]})
    with pytest.raises(corpus.CorpusError, match="link to the key file"):
        corpus.stage(c, cr, tmp_path / "s")
    assert not (tmp_path / "s").exists()
    # stripping the link in the index makes the challenge stageable again
    [c2] = corpus.parse_index({"challenge": [{"id": "c1", "category": "Web", "strip": ["copy"]}]})
    assert [m.as_posix() for m in corpus.stage(c2, cr, tmp_path / "s2")] == ["a.txt"]


def test_stage_refuses_a_symlink_to_the_service_spec(tmp_path):
    cr = tmp_path / "corpus"
    d = _challenge(cr, "c1", files={"a.txt": "x"}, service=DNS_SVC.format(flag="DEMO{k}"))
    (d / "spec-link").symlink_to(d / "service.toml")
    [c] = corpus.parse_index({"challenge": [{"id": "c1", "category": "Web", "service": "service.toml"}]})
    with pytest.raises(corpus.CorpusError, match="service spec"):
        corpus.stage(c, cr, tmp_path / "s")


def test_stage_refuses_a_nested_copy_of_the_key(tmp_path):
    cr = tmp_path / "corpus"
    _challenge(cr, "c1", files={"a.txt": "x", "dist/flag.txt": "DEMO{real}\n"}, key="DEMO{real}")
    [c] = corpus.parse_index({"challenge": [{"id": "c1", "category": "Web"}]})
    with pytest.raises(corpus.CorpusError, match="holds the key verbatim"):
        corpus.stage(c, cr, tmp_path / "s")
    assert not (tmp_path / "s").exists()


def test_stage_keeps_a_nested_fake_flag_that_is_not_the_key(tmp_path):
    cr = tmp_path / "corpus"
    _challenge(cr, "c1", files={"dist/flag.txt": "DEMO{fake_flag_for_local_testing}\n"}, key="DEMO{real}")
    [c] = corpus.parse_index({"challenge": [{"id": "c1", "category": "Web"}]})
    assert [m.as_posix() for m in corpus.stage(c, cr, tmp_path / "s")] == ["dist/flag.txt"]


def test_stage_refuses_a_symlink_out_of_the_challenge(tmp_path):
    cr = tmp_path / "corpus"
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "s.txt").write_text("secret bytes")
    d = _challenge(cr, "c1", files={"a.txt": "x"})
    (d / "escape").symlink_to(outside / "s.txt")
    [c] = corpus.parse_index({"challenge": [{"id": "c1", "category": "Web"}]})
    with pytest.raises(corpus.CorpusError, match="escapes the challenge folder"):
        corpus.stage(c, cr, tmp_path / "s")


def test_stage_refuses_a_symlinked_directory(tmp_path):
    cr = tmp_path / "corpus"
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "s.txt").write_text("secret bytes")
    d = _challenge(cr, "c1", files={"a.txt": "x"})
    (d / "linked").symlink_to(outside, target_is_directory=True)
    [c] = corpus.parse_index({"challenge": [{"id": "c1", "category": "Web"}]})
    with pytest.raises(corpus.CorpusError, match="symlinked directory"):
        corpus.stage(c, cr, tmp_path / "s")
    [c2] = corpus.parse_index({"challenge": [{"id": "c1", "category": "Web", "strip": ["linked/**"]}]})
    assert [m.as_posix() for m in corpus.stage(c2, cr, tmp_path / "s2")] == ["a.txt"]


def test_stage_copies_an_inside_symlink_as_a_plain_file(tmp_path):
    cr = tmp_path / "corpus"
    d = _challenge(cr, "c1", files={"a.txt": "handout"})
    (d / "alias.txt").symlink_to(d / "a.txt")
    [c] = corpus.parse_index({"challenge": [{"id": "c1", "category": "Web"}]})
    corpus.stage(c, cr, tmp_path / "s")
    staged = tmp_path / "s" / "alias.txt"
    assert not staged.is_symlink() and staged.read_text() == "handout"


def test_stage_refuses_a_non_empty_destination(tmp_path):
    cr = tmp_path / "corpus"
    _challenge(cr, "c1", files={"a.txt": "x"})
    [c] = corpus.parse_index({"challenge": [{"id": "c1", "category": "Web"}]})
    dest = tmp_path / "s"
    dest.mkdir()
    (dest / "stale.txt").write_text("DEMO{stale}")
    with pytest.raises(corpus.CorpusError, match="not empty"):
        corpus.stage(c, cr, dest)
    empty = tmp_path / "empty"
    empty.mkdir()
    assert corpus.stage(c, cr, empty) == [Path("a.txt")]


def test_read_key_missing_fails_loudly(tmp_path):
    cr = tmp_path / "corpus"
    _challenge(cr, "c1", files={"a.txt": "x"}, key=None)
    [c] = corpus.parse_index({"challenge": [{"id": "c1", "category": "Web"}]})
    with pytest.raises(corpus.CorpusError, match="no key file"):
        corpus.read_key(c, cr)


def test_board_files_flat_or_zipped(tmp_path):
    (tmp_path / "a.txt").write_text("A")
    assert corpus.board_files(tmp_path, [Path("a.txt")], "c1") == {"a.txt": b"A"}
    (tmp_path / "n").mkdir()
    (tmp_path / "n" / "b.txt").write_text("B")
    files = corpus.board_files(tmp_path, [Path("a.txt"), Path("n/b.txt")], "c1")
    assert list(files) == ["c1.zip"]
    import io
    with zipfile.ZipFile(io.BytesIO(files["c1.zip"])) as z:
        assert sorted(z.namelist()) == ["a.txt", "n/b.txt"] and z.read("n/b.txt") == b"B"


# ---------------------------------------------------------------------------- scoring

def test_score_matches_key_with_format_normalisation():
    f = ff()
    assert corpus.score(["DEMO{a}"], "DEMO{a}", f) == "correct"
    assert corpus.score([" DEMO{a} "], "DEMO{a}", f) == "correct"
    assert corpus.score(["DEMO{b}"], "DEMO{a}", f) == "incorrect"
    assert corpus.score([], "DEMO{a}", f) == "no-candidate"


def test_score_finds_the_key_after_a_decoy():
    assert corpus.score(["DEMO{x}", "DEMO{a}"], "DEMO{a}", ff()) == "correct"
    assert corpus.score(["DEMO{x}", "DEMO{y}"], "DEMO{a}", ff()) == "incorrect"


def test_score_notes_a_value_the_flag_format_cannot_normalise():
    notes: list[str] = []
    assert corpus.score(["not-a-flag"], "not-a-flag", ff(), notes) == "correct"
    assert any("the key does not normalise" in n for n in notes)
    assert any("candidate 'not-a-flag'" in n for n in notes)
    quiet: list[str] = []
    corpus.score(["DEMO{a}"], "DEMO{a}", ff(), quiet)
    assert quiet == []


# ---------------------------------------------------------------------------- gates

def _outcome(**kw):
    base = dict(id="c", category="Web", name="c", staged_files=1, engines=["a.one"], expect_engines=["a.one"],
                candidates=["DEMO{k}"], scored="correct", intake_status="solved")
    base.update(kw)
    return corpus.Outcome(**base)


def test_outcome_gates():
    assert _outcome().passed
    assert not _outcome(scored="incorrect").passed
    assert not _outcome(scored="no-key").passed
    assert not _outcome(scored="no-candidate").passed
    assert not _outcome(intake_status="blocked").passed
    assert not _outcome(intake_status=None).passed
    assert not _outcome(live="dns", live_reachable=False, live_published=True).passed
    assert not _outcome(live="dns", live_reachable=True, live_published=False).passed
    assert _outcome(live="dns", live_reachable=True, live_published=True).passed


def test_engines_ok_needs_every_expected_engine():
    o = _outcome(engines=["toolkits.forensics"], expect_engines=["toolkits.forensics", "nonexistent.engine"])
    assert not o.engines_ok and not o.passed
    assert _outcome(engines=["x.a", "x.b"], expect_engines=["x.a"]).engines_ok


def test_report_with_no_outcomes_or_board_trouble_does_not_pass(tmp_path):
    assert not corpus.CorpusReport("demo", tmp_path).passed
    rep = corpus.CorpusReport("demo", tmp_path, outcomes=[_outcome()])
    assert rep.passed
    rep.hygiene.append("POST /api/v1/challenges/attempt (attempt)")
    assert not rep.passed and "BOARD" in rep.render()


def test_intake_results_are_scored_per_engine():
    o = _outcome(candidates=[], scored="no-candidate", intake_status=None)
    run = lambda eng, flags: types.SimpleNamespace(engine=eng, status="ok", flags=tuple(flags))  # noqa: E731
    irep = types.SimpleNamespace(status="candidate", error=None, notes=[],
                                 sweep=types.SimpleNamespace(flags={"DEMO{decoy}": []}),
                                 runs=[run("x.good", ["DEMO{decoy}", "DEMO{k}"]), run("x.bad", ["DEMO{nope}"]),
                                       run("x.none", [])],
                                 flags={"DEMO{decoy}": [], "DEMO{k}": [], "DEMO{nope}": []})
    corpus._intake_into(o, irep, "DEMO{k}", ff())
    by = {r.engine: r for r in o.engine_results}
    assert by["sweep"].scored == "incorrect"
    assert by["x.good"].scored == "correct"
    assert by["x.bad"].scored == "incorrect"
    assert by["x.none"].scored == "no-candidate"
    assert o.intake_status == "candidate" and o.candidates == ["DEMO{decoy}", "DEMO{k}", "DEMO{nope}"]
    rep = corpus.CorpusReport("demo", Path("."), outcomes=[o])
    m = rep.engine_matrix()
    assert m["x.good"] == {"expected": 0, "fired": 0, "ran": 1, "correct": 1}
    assert m["x.bad"]["correct"] == 0 and m["x.bad"]["ran"] == 1


# ---------------------------------------------------------------------------- rehearse (fake CTFd + intake)

def test_rehearse_static_challenge_scores_correct(tmp_path):
    cr = tmp_path / "corpus"
    _challenge(cr, "static-forensics", files={"cap.txt": "lead DEMO{static} tail"}, key="DEMO{static}")
    idx = corpus.parse_index({"challenge": [{"id": "static-forensics", "category": "Forensics",
                                             "expect_engines": ["toolkits.forensics"]}]})
    rep = corpus.rehearse(profile(), idx, cr, tmp_path / "work")
    assert rep.passed, rep.render()
    [o] = rep.outcomes
    assert o.scored == "correct" and o.engines_ok and "toolkits.forensics" in o.engines
    assert o.intake_status == "solved"
    assert [r.scored for r in o.engine_results if r.engine == "sweep"] == ["correct"]
    # the handout went through the fake board: intake's workspace holds the downloaded copy
    assert any((tmp_path / "work" / "board").rglob("cap.txt"))


def test_rehearse_runs_engines_through_intake(tmp_path):
    cr = tmp_path / "corpus"
    _challenge(cr, "img", files={"pic.png": _png_with_text(b"DEMO{in_png}")}, key="DEMO{in_png}")
    idx = corpus.parse_index({"challenge": [{"id": "img", "category": "Forensics"}]})
    rep = corpus.rehearse(profile(), idx, cr, tmp_path / "work")
    [o] = rep.outcomes
    ran = {r.engine: r for r in o.engine_results}
    assert "metadata_forensics.file_properties" in ran, rep.render()
    assert ran["metadata_forensics.file_properties"].status == "ok"
    assert ran["metadata_forensics.file_properties"].scored == "no-candidate"
    assert ran["sweep"].scored == "correct" and o.passed
    assert rep.engine_matrix()["metadata_forensics.file_properties"]["ran"] == 1
    # --no-engines: planned, not run
    rep2 = corpus.rehearse(profile(), idx, cr, tmp_path / "work2", engines=False)
    assert [r.engine for r in rep2.outcomes[0].engine_results] == ["sweep"]


def test_rehearse_nested_handout_is_served_zipped_and_unpacked(tmp_path):
    cr = tmp_path / "corpus"
    _challenge(cr, "nested", files={"a/b/deep.txt": "x DEMO{deep} y", "top.txt": "t"}, key="DEMO{deep}")
    idx = corpus.parse_index({"challenge": [{"id": "nested", "category": "Forensics"}]})
    rep = corpus.rehearse(profile(), idx, cr, tmp_path / "work")
    [o] = rep.outcomes
    assert o.scored == "correct", rep.render()


def test_rehearse_wrong_flag_in_file_scores_incorrect(tmp_path):
    cr = tmp_path / "corpus"
    _challenge(cr, "c1", files={"cap.txt": "DEMO{not_the_key}"}, key="DEMO{the_key}")
    idx = corpus.parse_index({"challenge": [{"id": "c1", "category": "Forensics"}]})
    rep = corpus.rehearse(profile(), idx, cr, tmp_path / "work")
    [o] = rep.outcomes
    assert o.scored == "incorrect" and not o.passed and not rep.passed


def test_rehearse_without_a_key_scores_no_key_and_fails(tmp_path):
    cr = tmp_path / "corpus"
    _challenge(cr, "c1", files={"cap.txt": "DEMO{something}"}, key=None)
    idx = corpus.parse_index({"challenge": [{"id": "c1", "category": "Forensics"}]})
    rep = corpus.rehearse(profile(), idx, cr, tmp_path / "work")
    [o] = rep.outcomes
    assert o.scored == "no-key" and not o.passed and not rep.passed
    assert any("no key file" in n for n in o.notes)


def test_rehearse_live_only_flag_is_a_visible_solver_gap(tmp_path):
    cr = tmp_path / "corpus"
    # NO flag in the static files; only the DNS TXT service holds it
    _challenge(cr, "dns-txt-logs", files={"readme.txt": "query the resolver for the flag"},
               key="DEMO{live_only}", service=DNS_SVC.format(flag="DEMO{live_only}"))
    idx = corpus.parse_index({"challenge": [{"id": "dns-txt-logs", "category": "Forensics",
                                             "service": "service.toml"}]})
    rep = corpus.rehearse(profile(), idx, cr, tmp_path / "work")
    [o] = rep.outcomes
    # the replay ran, its probe reached the key, and intake saw the endpoint as connection_info...
    assert o.live == "dns" and o.live_reachable and o.live_probe_has_key is True
    assert o.live_published and o.live_endpoint.startswith("udp://127.0.0.1:")
    # ...but the probe is not a solve: no tooling reached the service, so the challenge fails
    assert "DEMO{live_only}" not in o.candidates and o.scored == "no-candidate" and not o.passed
    assert any("live-only solver gap" in n for n in o.notes)
    staged = tmp_path / "work" / "staged" / "dns-txt-logs"
    blob = b"".join(p.read_bytes() for p in staged.rglob("*") if p.is_file())
    assert b"DEMO{live_only}" not in blob


def test_rehearse_live_probe_without_the_key_is_not_a_solver_gap(tmp_path):
    cr = tmp_path / "corpus"
    # the replay answers its probe, but with a decoy: the service does not reproduce the key, so the
    # replay is unfaithful and the miss must not be blamed on a missing live solver
    _challenge(cr, "dns-decoy", files={"readme.txt": "query the resolver"},
               key="DEMO{real_key}", service=DNS_SVC.format(flag="DEMO{decoy_value}"))
    idx = corpus.parse_index({"challenge": [{"id": "dns-decoy", "category": "Forensics",
                                             "service": "service.toml"}]})
    rep = corpus.rehearse(profile(), idx, cr, tmp_path / "work")
    [o] = rep.outcomes
    assert o.live == "dns" and o.live_reachable and o.live_published
    assert o.live_probe_has_key is False
    assert o.scored == "no-candidate" and not o.passed
    assert not any("live-only solver gap" in n for n in o.notes)
    assert o.to_dict()["live_probe_has_key"] is False


def test_rehearse_live_challenge_fails_when_the_service_is_unreachable(tmp_path):
    cr = tmp_path / "corpus"
    # the static file carries the flag, but the replay spec has no probe: the live path never answered
    _challenge(cr, "c1", files={"cap.txt": "carved: DEMO{both} end"}, key="DEMO{both}",
               service='kind = "dns"\n[records]\n"flag.chal" = ["DEMO{both}"]\n')
    idx = corpus.parse_index({"challenge": [{"id": "c1", "category": "Forensics", "service": "service.toml"}]})
    rep = corpus.rehearse(profile(), idx, cr, tmp_path / "work")
    [o] = rep.outcomes
    assert o.scored == "correct" and o.live_published
    assert not o.live_reachable and not o.passed and not rep.passed
    assert any("did not answer its probe" in n for n in o.notes)


def test_rehearse_live_challenge_fails_when_the_endpoint_is_not_published(tmp_path, monkeypatch):
    cr = tmp_path / "corpus"
    _challenge(cr, "c1", files={"cap.txt": "carved: DEMO{both} end"}, key="DEMO{both}",
               service=DNS_SVC.format(flag="DEMO{both}"))
    idx = corpus.parse_index({"challenge": [{"id": "c1", "category": "Forensics", "service": "service.toml"}]})
    real = fakectfd.FakeCTFd._detail

    def no_conn(self, c):
        d = real(self, c)
        d["connection_info"] = None
        return d
    monkeypatch.setattr(fakectfd.FakeCTFd, "_detail", no_conn)
    rep = corpus.rehearse(profile(), idx, cr, tmp_path / "work")
    [o] = rep.outcomes
    assert o.scored == "correct" and o.live_reachable and not o.live_published and not o.passed


def test_rehearse_fails_when_an_expected_engine_does_not_fire(tmp_path):
    cr = tmp_path / "corpus"
    _challenge(cr, "c1", files={"cap.txt": "carved: DEMO{win2} end"}, key="DEMO{win2}")
    idx = corpus.parse_index({"challenge": [{"id": "c1", "category": "Forensics",
                                             "expect_engines": ["toolkits.forensics", "nonexistent.engine"]}]})
    rep = corpus.rehearse(profile(), idx, cr, tmp_path / "work")
    [o] = rep.outcomes
    assert o.scored == "correct" and "toolkits.forensics" in o.engines and not o.engines_ok and not o.passed
    assert rep.engine_matrix()["nonexistent.engine"]["fired"] == 0
    assert rep.engine_matrix()["toolkits.forensics"]["fired"] == 1


def test_rehearse_skips_absent_and_rejects_unknown_id(tmp_path):
    cr = tmp_path / "corpus"
    _challenge(cr, "present", files={"a.txt": "carved: DEMO{x1} end"}, key="DEMO{x1}")
    idx = corpus.parse_index({"challenge": [{"id": "present", "category": "Web"},
                                            {"id": "absent", "category": "Web"}]})
    rep = corpus.rehearse(profile(), idx, cr, tmp_path / "work")
    assert len(rep.outcomes) == 1 and rep.skipped and "absent" in rep.skipped[0]
    with pytest.raises(corpus.CorpusError, match="unknown"):
        corpus.rehearse(profile(), idx, cr, tmp_path / "work2", ids=["present", "ghost"])


def test_rehearse_with_every_entry_absent_does_not_pass(tmp_path):
    cr = tmp_path / "corpus"
    cr.mkdir()
    idx = corpus.parse_index({"challenge": [{"id": "a", "category": "Web"}, {"id": "b", "category": "Web"}]})
    rep = corpus.rehearse(profile(), idx, cr, tmp_path / "work")
    assert rep.outcomes == [] and len(rep.skipped) == 2
    assert not rep.passed and "nothing was rehearsed" in rep.render()


def test_rehearse_refuses_a_non_empty_workdir(tmp_path):
    cr = tmp_path / "corpus"
    _challenge(cr, "c1", files={"a.txt": "x"})
    idx = corpus.parse_index({"challenge": [{"id": "c1", "category": "Web"}]})
    work = tmp_path / "work"
    (work / "board").mkdir(parents=True)               # a stale intake folder from an earlier --keep run
    (work / "board" / "old.txt").write_text("DEMO{win}")
    with pytest.raises(corpus.CorpusError, match="rehearsal folder .* not empty"):
        corpus.rehearse(profile(), idx, cr, work)


# ---------------------------------------------------------------------------- importer

def _public_repo(tmp_path, key="DEMO{imported}"):
    src = tmp_path / "public" / "chal"
    (src / "dist").mkdir(parents=True)
    (src / "solution").mkdir()
    (src / "dist" / "handout.txt").write_text("the handout")
    (src / "dist" / "real-flag-copy.txt").write_text(key + "\n")
    (src / "solution" / "solve.py").write_text("print('x')")
    (src / "Writeup.md").write_text("how it was solved: " + key)
    (src / "solve.py").write_text("print('x')")
    (src / "flag.txt").write_text(key + "\n")
    (src / "link").symlink_to(src / "dist" / "handout.txt")
    return src


def test_import_strips_answers_and_writes_the_key(tmp_path):
    src = _public_repo(tmp_path)
    cr = tmp_path / "corpus"
    cr.mkdir()
    res = corpus.import_challenge(src, cr, "pub1", "Misc", description="from a public repo")
    assert res.copied == ["dist/handout.txt"]
    assert "solution/" in res.stripped and "Writeup.md" in res.stripped and "solve.py" in res.stripped
    assert "dist/real-flag-copy.txt" in res.stripped and "flag.txt" in res.stripped
    assert res.links_skipped == ["link"]
    assert (cr / "pub1" / "flag.txt").read_text().strip() == "DEMO{imported}"
    assert not (cr / "pub1" / "solution").exists() and not (cr / "pub1" / "link").exists()
    assert "DEMO{imported}" not in res.stanza
    import tomllib
    [c] = corpus.parse_index(tomllib.loads(res.stanza))
    assert c.id == "pub1" and c.path == "pub1" and c.category == "Misc"
    # the imported entry rehearses blind: the handout carries no flag, so nothing is found
    rep = corpus.rehearse(profile(), [c], cr, tmp_path / "work")
    assert rep.outcomes[0].scored == "no-candidate"


def test_import_refuses_a_corpus_inside_the_repo_and_a_missing_key(tmp_path):
    src = _public_repo(tmp_path)
    # a folder inside the repo that does not exist: even with the guard broken nothing can be written
    inside = paths.repo_root() / "corpus" / "no-such-corpus-b155"
    with pytest.raises(corpus.CorpusError, match="inside this repository"):
        corpus.import_challenge(src, inside, "pub1", "Misc")
    assert not inside.exists()
    cr = tmp_path / "corpus"
    cr.mkdir()
    with pytest.raises(corpus.CorpusError, match="no key file"):
        corpus.import_challenge(src, cr, "pub1", "Misc", key_file="nope.txt")
    with pytest.raises(corpus.CorpusError, match="names a folder"):
        corpus.import_challenge(src, cr, "../pub1", "Misc")
    corpus.import_challenge(src, cr, "pub1", "Misc")
    with pytest.raises(corpus.CorpusError, match="already exists"):
        corpus.import_challenge(src, cr, "pub1", "Misc")


# ---------------------------------------------------------------------------- path resolver

def test_rehearsal_corpus_root_unset_is_none(monkeypatch):
    monkeypatch.delenv("CTF_REHEARSAL_CORPUS", raising=False)
    assert paths.rehearsal_corpus_root() is None
    with pytest.raises(FileNotFoundError, match="CTF_REHEARSAL_CORPUS"):
        paths.require_rehearsal_corpus()


def test_rehearsal_corpus_root_missing_dir_raises(monkeypatch, tmp_path):
    monkeypatch.setenv("CTF_REHEARSAL_CORPUS", str(tmp_path / "nope"))
    with pytest.raises(FileNotFoundError, match="CTF_REHEARSAL_CORPUS"):
        paths.rehearsal_corpus_root()


def test_rehearsal_corpus_root_present(monkeypatch, tmp_path):
    monkeypatch.setenv("CTF_REHEARSAL_CORPUS", str(tmp_path))
    assert paths.rehearsal_corpus_root() == tmp_path.resolve()


# ---------------------------------------------------------------------------- CLI

def _run_ctf(*args, env=None):
    e = dict(os.environ)
    e.setdefault("CTF_EVENT", "csctf")
    if env:
        e.update(env)
    return subprocess.run([sys.executable, "-m", "ctf", *args], capture_output=True, text=True,
                          cwd=str(paths.repo_root()), env=e)


def test_cli_index_runs_without_a_corpus():
    r = _run_ctf("corpus", "index", env={"CTF_REHEARSAL_CORPUS": ""})
    assert r.returncode == 0, r.stderr
    assert "dns-txt-logs" in r.stdout and "NOT SET" in r.stdout


def test_cli_rehearse_without_corpus_exits_2():
    r = _run_ctf("corpus", "rehearse", env={"CTF_REHEARSAL_CORPUS": ""})
    assert r.returncode == 2 and "CTF_REHEARSAL_CORPUS" in r.stderr


def test_cli_rehearse_scores_a_synthetic_corpus(tmp_path):
    cr = tmp_path / "corpus"
    _challenge(cr, "static-forensics", files={"cap.txt": "carved: CSCTF{static_cli} end"}, key="CSCTF{static_cli}")
    r = _run_ctf("corpus", "rehearse", "--id", "static-forensics", "--json",
                 env={"CTF_REHEARSAL_CORPUS": str(cr)})
    assert r.returncode == 0, r.stderr + r.stdout
    assert '"passed": true' in r.stdout


def test_cli_rehearse_live_only_gap_exits_1(tmp_path):
    cr = tmp_path / "corpus"
    _challenge(cr, "dns-txt-logs", files={"readme.txt": "query the resolver"}, key="CSCTF{live_cli}",
               service=DNS_SVC.format(flag="CSCTF{live_cli}"))
    r = _run_ctf("corpus", "rehearse", "--id", "dns-txt-logs", env={"CTF_REHEARSAL_CORPUS": str(cr)})
    assert r.returncode == 1, r.stderr + r.stdout
    assert "live-only solver gap" in r.stdout and "CORPUS REHEARSAL FAILED" in r.stdout


def test_cli_rehearse_with_every_entry_absent_exits_1(tmp_path):
    cr = tmp_path / "corpus"
    cr.mkdir()
    r = _run_ctf("corpus", "rehearse", env={"CTF_REHEARSAL_CORPUS": str(cr)})
    assert r.returncode == 1, r.stderr + r.stdout
    assert "SKIP" in r.stdout and "CORPUS REHEARSAL FAILED" in r.stdout


def test_cli_serve_probe_drives_the_live_service(tmp_path):
    cr = tmp_path / "corpus"
    _challenge(cr, "dns-txt-logs", files={"readme.txt": "x"}, key="CSCTF{served}",
               service=DNS_SVC.format(flag="CSCTF{served}"))
    r = _run_ctf("corpus", "serve", "dns-txt-logs", "--probe", env={"CTF_REHEARSAL_CORPUS": str(cr)})
    assert r.returncode == 0, r.stderr
    assert "CSCTF{served}" in r.stdout


def test_cli_serve_with_a_malformed_spec_exits_2_with_a_named_reason(tmp_path):
    cr = tmp_path / "corpus"
    _challenge(cr, "dns-txt-logs", files={"readme.txt": "x"}, key="CSCTF{served}", service='kind = "dns"\n')
    r = _run_ctf("corpus", "serve", "dns-txt-logs", "--probe", env={"CTF_REHEARSAL_CORPUS": str(cr)})
    assert r.returncode == 2, r.stderr
    assert "records" in r.stderr and "Traceback" not in r.stderr


def test_cli_import_appends_a_loadable_stanza(tmp_path):
    src = _public_repo(tmp_path, key="CSCTF{imp}")
    cr = tmp_path / "corpus"
    cr.mkdir()
    index = tmp_path / "index.toml"
    index.write_text('[[challenge]]\nid = "first"\ncategory = "Web"\n')
    r = _run_ctf("corpus", "import", str(src), "--id", "pub1", "--category", "Misc", "--corpus", str(cr),
                 "--index", str(index), "--engine", "toolkits.forensics")
    assert r.returncode == 0, r.stderr
    assert "stripped solution/" in r.stdout and "symlink not followed link" in r.stdout
    assert [c.id for c in corpus.load_index(index)] == ["first", "pub1"]
    assert "CSCTF{imp}" not in index.read_text() and "CSCTF{imp}" not in r.stdout


def test_cli_import_into_an_index_that_already_has_the_id_writes_nothing(tmp_path):
    src = _public_repo(tmp_path, key="CSCTF{dup}")
    cr = tmp_path / "corpus"
    cr.mkdir()
    index = tmp_path / "index.toml"
    before = '[[challenge]]\nid = "pub1"\ncategory = "Web"\n'
    index.write_text(before)
    r = _run_ctf("corpus", "import", str(src), "--id", "pub1", "--category", "Misc", "--corpus", str(cr),
                 "--index", str(index))
    assert r.returncode == 2 and "already indexed" in r.stderr and "Traceback" not in r.stderr
    assert index.read_text() == before                  # the index is unchanged
    assert not (cr / "pub1").exists()                   # and nothing reached the corpus


def test_cli_import_into_a_broken_index_writes_nothing(tmp_path):
    src = _public_repo(tmp_path, key="CSCTF{brk}")
    cr = tmp_path / "corpus"
    cr.mkdir()
    index = tmp_path / "index.toml"
    before = '[[challenge]]\nid = "a"\ncategory = "Web"\n[[challenge]]\nid = "a"\ncategory = "Web"\n'
    index.write_text(before)
    r = _run_ctf("corpus", "import", str(src), "--id", "pub2", "--category", "Misc", "--corpus", str(cr),
                 "--index", str(index))
    assert r.returncode == 2 and "duplicate challenge id" in r.stderr and "Traceback" not in r.stderr
    assert index.read_text() == before and not (cr / "pub2").exists()


def test_cli_import_into_an_absent_index_creates_it(tmp_path):
    src = _public_repo(tmp_path, key="CSCTF{new}")
    cr = tmp_path / "corpus"
    cr.mkdir()
    index = tmp_path / "index.toml"
    r = _run_ctf("corpus", "import", str(src), "--id", "pub3", "--category", "Misc", "--corpus", str(cr),
                 "--index", str(index))
    assert r.returncode == 0, r.stderr
    assert [c.id for c in corpus.load_index(index)] == ["pub3"] and (cr / "pub3" / "flag.txt").is_file()
