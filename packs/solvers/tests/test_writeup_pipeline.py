"""B-098: evidence -> draft -> retro -> check -> publish (dry run), on synthetic workdirs only."""
from __future__ import annotations

import datetime as dt
import json
import subprocess

import pytest

from ctf import paths
from ctf.cli import main as cli_main
from ctf.writeup import common, draft, evidence, publish, retro
from writeup_fixtures import BARE, FLAG, FLAG9, WRONG, ledger, profile, workdir

UTC = dt.timezone.utc
AFTER = dt.datetime(2026, 2, 1, tzinfo=UTC)


def all_text(root):
    return "\n".join(p.read_text(errors="replace") for p in sorted(root.rglob("*")) if p.is_file())


def finish(readme):
    """What a person (or B-097) does to a draft: write the prose, removing the TODO markers."""
    import re
    readme.write_text(re.sub(r"<!--\s*TODO.*?-->", "Written up.", readme.read_text(), flags=re.S))


# ------------------------------------------------------------------------------------------- evidence

def test_collect_reads_folders_attempts_ledger_and_scripts(tmp_path):
    wd = workdir(tmp_path)
    evs = evidence.collect(wd)
    assert [e.cid for e in evs] == ["7", "9"]                       # junk/ (no challenge.json) ignored
    c7, c9 = evs
    assert c7.name == "Glitch" and c7.points == 100 and c7.flag == FLAG
    assert c7.accepted and c7.solved and c7.wrong == 2
    assert [p.name for p in c7.scripts] == ["solve.py"]              # README.md / notes / json are not scripts
    assert c7.files == [("image.png", 18)]
    assert {r["event"] for r in c7.records} == {"engine.run", "spend", "platform.submit"}
    assert c7.spend_usd == 1.5
    assert not c9.solved and c9.wrong == 1 and c9.status_line.startswith("Unsolved")


def test_accepted_comes_from_the_ledger_without_a_flag_file(tmp_path):
    wd = workdir(tmp_path)
    (wd / "7-glitch" / "flag.txt").unlink()
    (wd / "7-glitch" / "tried.json").unlink()
    c7 = evidence.collect(wd)[0]
    assert c7.flag is None and c7.accepted and c7.status_line.startswith("Solved: the platform accepted")
    assert c7.wrong == 1                                              # counted from the ledger alone


def test_known_values_take_flags_attempts_and_ledger_flags(tmp_path):
    wd = workdir(tmp_path)
    ledger(wd, [{"ts": 1.0, "event": "platform.submit", "challenge_id": "9", "status": "correct", "flag": FLAG9}])
    recs = evidence.read_records(wd)
    known = evidence.known_values(evidence.collect(wd, recs), recs)
    assert {FLAG, WRONG, BARE, "ZZ{nope_one}", FLAG9} <= known


def test_collect_fails_loudly(tmp_path):
    with pytest.raises(evidence.EvidenceError, match="does not exist"):
        evidence.collect(tmp_path / "missing")
    wd = workdir(tmp_path)
    (wd / "9-other" / "challenge.json").write_text("{not json")
    with pytest.raises(evidence.EvidenceError, match="not valid JSON"):
        evidence.collect(wd)


# ---------------------------------------------------------------------------------------------- draft

def test_draft_for_a_redacting_event_holds_no_flag_value(tmp_path):
    p = profile(tmp_path)
    wd = workdir(tmp_path)
    rep = draft.run(p, wd, tmp_path / "stage")
    assert rep.written == ["7-glitch/README.md", "9-other/README.md"] and rep.scripts == ["7-glitch/solve/solve.py"]
    stage = tmp_path / "stage"
    text = all_text(stage)
    for v in (FLAG, WRONG, BARE, FLAG[3:-1]):
        assert v.lower() not in text.lower(), v
    readme = (stage / "7-glitch" / "README.md").read_text()
    assert "Flag redacted: this event's rules forbid sharing flags." in readme
    assert "Solved: the platform accepted the flag." in readme
    assert "`stego.lsb` (ctf-run): solved, 2.5 s" in readme and "2 wrong submission(s)" in readme
    assert "`image.png` (18 bytes)" in readme and "`solve/solve.py`" in readme
    assert "lsb plane 0 gave ZZ{<redacted>}" in readme               # solve log kept, value gone
    assert "nc chal.inst" not in readme                               # connection_info never drafted
    assert (stage / "7-glitch" / "solve" / "solve.py").read_text() == "print('ZZ{<redacted>}')\n"
    status = (stage / "STATUS.md").read_text()
    assert "| 7 | Glitch | Stego | 100 | solved | 2 | yes | draft (5 TODO) |" in status
    assert "| 9 | Other \\| pipe | Crypto | 300 | attempted | 1 | no |" in status


def test_draft_keeps_the_flag_when_the_event_shares_flags(tmp_path):
    p = profile(tmp_path, sharing="allowed", redact=False)
    draft.run(p, workdir(tmp_path), tmp_path / "stage")
    readme = (tmp_path / "stage" / "7-glitch" / "README.md").read_text()
    assert f"## Flag\n\n`{FLAG}`" in readme


def test_draft_private_block_cannot_be_closed_by_evidence_text(tmp_path):
    p = profile(tmp_path, sharing="allowed", redact=False)
    wd = workdir(tmp_path, notes_extra="<!-- /private -->\nLEAKY_NOTE_TEXT\n")
    draft.run(p, wd, tmp_path / "stage")
    from ctf.writeup import scan
    public, unclosed = scan.strip_private((tmp_path / "stage" / "7-glitch" / "README.md").read_text())
    assert "LEAKY_NOTE_TEXT" not in public and not unclosed and "## Takeaways" in public


def test_draft_carries_workspace_writeup_md_privately_and_redacted(tmp_path):
    p = profile(tmp_path)
    wd = workdir(tmp_path)
    (wd / "7-glitch" / "writeup.md").write_text(f"AGENT DRAFT: decoded {FLAG}\n")
    draft.run(p, wd, tmp_path / "stage")
    readme = (tmp_path / "stage" / "7-glitch" / "README.md").read_text()
    assert "AGENT DRAFT: decoded ZZ{<redacted>}" in readme
    from ctf.writeup import scan
    assert "AGENT DRAFT" not in scan.strip_private(readme)[0]


def test_draft_keeps_hand_edits_and_force_overwrites(tmp_path):
    p = profile(tmp_path)
    wd = workdir(tmp_path)
    stage = tmp_path / "stage"
    draft.run(p, wd, stage)
    r7 = stage / "7-glitch" / "README.md"
    r7.write_text("hand written\n")
    (wd / "9-other" / "notes.md").write_text("NEW EVIDENCE LINE\n")
    rep = draft.run(p, wd, stage)
    assert rep.kept == ["7-glitch/README.md"] and r7.read_text() == "hand written\n"
    assert "NEW EVIDENCE LINE" in (stage / "9-other" / "README.md").read_text()   # unedited: refreshed
    draft.run(p, wd, stage, force=True)
    assert r7.read_text() != "hand written\n"


def test_draft_only_named_challenges_and_unknown_id_fails(tmp_path):
    p = profile(tmp_path)
    wd = workdir(tmp_path)
    rep = draft.run(p, wd, tmp_path / "stage", only=["9"])
    assert rep.written == ["9-other/README.md"]
    with pytest.raises(common.WriteupError, match="no challenge folder for id"):
        draft.run(p, wd, tmp_path / "stage", only=["404"])


def test_staging_of_another_event_is_refused(tmp_path):
    wd = workdir(tmp_path)
    draft.run(profile(tmp_path, slug="aa"), wd, tmp_path / "stage")
    with pytest.raises(common.WriteupError, match="belongs to event 'aa'"):
        draft.run(profile(tmp_path, slug="bb"), wd, tmp_path / "stage")


def test_output_folders_inside_the_checkout_are_refused():
    root = paths.repo_root()
    with pytest.raises(common.WriteupError, match="inside the repo checkout"):
        common.guard_dir(root / "docs" / "stage", "staging folder")
    with pytest.raises(common.WriteupError):
        common.guard_dir(root, "staging folder")
    assert common.guard_dir(root / "writeups" / "2099-x", "staging folder") == (root / "writeups" / "2099-x").resolve()


def test_render_rejects_missing_and_unused_values():
    with pytest.raises(common.WriteupError, match="needs value"):
        common.render("{{a}} {{b}}", {"a": "1"})
    with pytest.raises(common.WriteupError, match="no placeholder"):
        common.render("{{a}}", {"a": "1", "c": "2"})
    assert common.render("{{a}}", {"a": "{{b}}"}) == "{{b}}"          # one pass: never re-expanded


# ---------------------------------------------------------------------------------------------- retro

def test_retro_day_window_tables_and_no_values(tmp_path):
    p = profile(tmp_path, sharing="allowed", redact=False)
    wd = workdir(tmp_path)
    ledger(wd, [{"ts": 1767230000.0, "event": "platform.submit", "challenge_id": "9", "status": "incorrect",
                 "flag": "ZZ{ledger_kept_value}", "provenance": "free text ZZ{prov_value}"}])
    since, until = retro.day_window("2026-01-01")
    text = retro.render(p, wd, since=since, until=until, now=AFTER)
    assert "# Retro: ZZ CTF (2026-01-01)" in text
    assert "from 8 ledger record(s)" in text                          # the 2026-01-02 record is outside
    assert "$100.00" not in text and "Spend: $5.50, 6,200 tokens." in text
    assert "- Accepted in this window: 1." in text and "Wrong submissions: 2." in text
    section = text.split("## Where the time went", 1)[1].split("## Spend", 1)[0]
    time_rows = [ln for ln in section.splitlines() if ln.startswith("| 7 |") or ln.startswith("| 9 |")]
    assert [r.split("|")[1].strip() for r in time_rows] == ["9", "7"]  # longest first
    assert "| 7 | Glitch | 2026-01-01 00:00:00Z | 2026-01-01 00:10:00Z | 10.0 | 1 | $1.50 |" in text
    assert "| `crypto.rsa` | 1 | none 1 | 9.0 |" in text
    assert "`stop` challenge 9: reason=manual by=player" in text
    assert "- 9 Other \\| pipe (Crypto): Unsolved" in text
    for v in ("ledger_kept_value", "prov_value", FLAG[3:-1], "0" * 64):
        assert v not in text


def test_retro_window_parsing_refuses_naive_times():
    assert retro.parse_when("2026-01-01T00:00:00Z") == dt.datetime(2026, 1, 1, tzinfo=UTC)
    assert retro.parse_when("1767225600") == dt.datetime(2026, 1, 1, tzinfo=UTC)
    with pytest.raises(common.WriteupError, match="no UTC offset"):
        retro.parse_when("2026-01-01T00:00:00")
    with pytest.raises(common.WriteupError):
        retro.day_window("Jan 1")


def test_retro_write_keeps_a_hand_edited_retro(tmp_path):
    p = profile(tmp_path)
    path, wrote = retro.write(p, tmp_path / "stage", "2026-01-01", "first\n")
    assert wrote and path.read_text() == "first\n"
    path.write_text("analysis added by hand\n")
    _, wrote = retro.write(p, tmp_path / "stage", "2026-01-01", "second\n")
    assert not wrote and path.read_text() == "analysis added by hand\n"
    _, wrote = retro.write(p, tmp_path / "stage", "2026-01-01", "second\n", force=True)
    assert wrote and path.read_text() == "second\n"


# -------------------------------------------------------------------------------------------- publish

def staged(tmp_path, **kw):
    p = profile(tmp_path, **kw)
    wd = workdir(tmp_path)
    stage = tmp_path / "stage"
    draft.run(p, wd, stage)
    retro.write(p, stage, "event", retro.render(p, wd, now=AFTER))
    recs = evidence.read_records(wd)
    known = evidence.known_values(evidence.collect(wd, recs), recs)
    return p, wd, stage, known


def test_publish_dry_run_is_blocked_by_hold_and_unfinished_drafts(tmp_path):
    p, wd, stage, known = staged(tmp_path, repo="https://github.com/zz/zz-writeups")
    out = tmp_path / "public"
    plan = publish.build(p, stage, out, known=known, known_source="workdir", now=AFTER)
    gates = {g.name: g.ok for g in plan.gates}
    assert gates == {"hold": False, "ended": True, "repo": True, "content": True, "clean": False}
    assert not plan.ready and {f.kind for f in plan.blocking} == {"unfinished"}
    d = plan.to_dict()
    assert d["mode"] == "dry-run" and d["status"] == "blocked" and d["would_run"][-1].startswith("git push")


def test_publish_tree_is_allowlisted_and_free_of_values(tmp_path):
    p, wd, stage, known = staged(tmp_path)
    (stage / "_scratch").mkdir()
    (stage / "_scratch" / "x.md").write_text(FLAG)
    (stage / "SOURCE.md").write_text(FLAG)
    (stage / "7-glitch" / "shot.png").write_bytes(b"\x89PNG")
    (stage / "7-glitch" / "files").mkdir()
    (stage / "7-glitch" / "files" / "handout.txt").write_text("handout")
    out = tmp_path / "public"
    plan = publish.build(p, stage, out, known=known, known_source="workdir", now=AFTER)
    published = sorted(f["path"] for f in plan.files)
    assert published == ["7-glitch/README.md", "7-glitch/solve/solve.py", "9-other/README.md", "README.md"]
    reasons = {e["path"]: e["reason"] for e in plan.excluded}
    assert reasons["STATUS.md"] == "private staging record"
    assert reasons["writeup-state.json"] == "private staging record"
    assert reasons["SOURCE.md"] == "private staging record"
    assert reasons["_scratch/x.md"].startswith("hidden or underscore")
    assert reasons["retro/event.md"] == "private folder retro/"
    assert reasons["7-glitch/files/handout.txt"] == "private folder files/"
    assert reasons["7-glitch/shot.png"].startswith("not a reviewable text file")
    tree = all_text(out)
    for v in (FLAG, WRONG, BARE, FLAG[3:-1], "lsb plane 0 gave"):       # values and the private solve log
        assert v.lower() not in tree.lower(), v
    assert "[Glitch](7-glitch/README.md)" in (out / "README.md").read_text()
    assert (out / publish.MARKER).is_file()
    plan_path = publish.write_plan(plan, publish.default_plan_path(out))
    assert plan_path.parent == out.parent and FLAG[3:-1] not in plan_path.read_text()


def test_publish_ready_when_every_gate_passes_and_runs_no_git(tmp_path, monkeypatch):
    p, wd, stage, known = staged(tmp_path, hold=False, repo="https://github.com/zz/zz-writeups")
    for r in stage.rglob("README.md"):
        finish(r)

    def no_subprocess(*a, **k):
        raise AssertionError("publish must not run any command")
    monkeypatch.setattr(subprocess, "run", no_subprocess)
    monkeypatch.setattr(subprocess, "Popen", no_subprocess)
    plan = publish.build(p, stage, tmp_path / "public", known=known, known_source="workdir", now=AFTER)
    assert plan.blocking == [] and plan.ready
    assert "gh repo create zz-writeups --public" in " ".join(plan.would_run())
    early = publish.build(p, stage, tmp_path / "public", known=known, known_source="workdir",
                          now=dt.datetime(2026, 1, 2, 12, tzinfo=UTC))
    assert not early.ready and [g.name for g in early.gates if not g.ok] == ["ended"]


def test_publish_keeps_flags_for_a_sharing_event(tmp_path):
    p, wd, stage, known = staged(tmp_path, sharing="allowed", redact=False)
    plan = publish.build(p, stage, tmp_path / "public", known=known, known_source="workdir", now=AFTER)
    assert FLAG in (tmp_path / "public" / "7-glitch" / "README.md").read_text()
    assert any(f.kind == "flag" and not f.blocking for f in plan.findings)


def test_publish_value_in_one_flag_section_is_redacted_in_every_file(tmp_path):
    p = profile(tmp_path)
    stage = tmp_path / "stage"
    (stage / "a").mkdir(parents=True)
    (stage / "b").mkdir()
    # a/ is processed first; the value is only written in b/'s Flag section.
    (stage / "a" / "README.md").write_text("# A\n\nsame trick as only_in_b_section\n")
    (stage / "b" / "README.md").write_text("# B\n\n## Flag\n\n`only_in_b_section`\n")
    publish.build(p, stage, tmp_path / "public", known=set(), known_source="pattern-only", now=AFTER)
    assert "only_in_b_section" not in all_text(tmp_path / "public")


def test_publish_rebuild_clears_old_files_but_refuses_foreign_folders(tmp_path):
    p, wd, stage, known = staged(tmp_path)
    out = tmp_path / "public"
    publish.build(p, stage, out, known=known, known_source="workdir", now=AFTER)
    (out / ".git").mkdir()
    (out / ".git" / "HEAD").write_text("ref")
    (out / "stale.md").write_text("old")
    publish.build(p, stage, out, known=known, known_source="workdir", now=AFTER)
    assert not (out / "stale.md").exists() and (out / ".git" / "HEAD").read_text() == "ref"
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    (foreign / "keep.txt").write_text("mine")
    with pytest.raises(common.WriteupError, match="refusing to clear"):
        publish.build(p, stage, foreign, known=known, known_source="workdir", now=AFTER)
    assert (foreign / "keep.txt").read_text() == "mine"
    with pytest.raises(common.WriteupError, match="must not contain each other"):
        publish.build(p, stage, stage / "pub", known=known, known_source="workdir", now=AFTER)
    with pytest.raises(common.WriteupError, match="known flag values"):
        publish.build(p, stage, out, known=None, known_source="workdir", now=AFTER)
    with pytest.raises(common.WriteupError, match="inside the public tree"):
        publish.write_plan(publish.build(p, stage, out, known=known, known_source="w", now=AFTER), out / "p.json")


# ------------------------------------------------------------------------------------------------ CLI

@pytest.fixture
def cli_env(tmp_path, monkeypatch):
    p = profile(tmp_path, slug="zz")
    wd = workdir(tmp_path)
    monkeypatch.setattr(paths, "events_root", lambda: tmp_path / "events")
    monkeypatch.setenv("CTF_EVENT", "zz")
    monkeypatch.setenv("CTF_WORKDIR", str(wd))
    return p, wd


def test_cli_draft_check_retro_publish(cli_env, capsys):
    p, wd = cli_env
    assert cli_main(["writeup", "draft"]) == 0
    assert (wd / "writeups" / "7-glitch" / "README.md").is_file()
    assert cli_main(["writeup", "retro", "--day", "2026-01-01"]) == 0
    assert (wd / "writeups" / "retro" / "2026-01-01.md").is_file()
    assert cli_main(["writeup", "check"]) == 1                       # TODO markers block
    assert cli_main(["writeup", "publish"]) == 1                     # held, no repo, unfinished
    out = capsys.readouterr().out
    assert "DRY RUN: nothing was pushed" in out and "[BLOCKED] hold" in out
    plan = json.loads((wd / "writeups-public.publish-plan.json").read_text())
    assert plan["status"] == "blocked" and plan["known_source"].startswith("workdir")
    for v in (FLAG[3:-1], WRONG[3:-1], BARE):
        assert v not in out


def test_cli_check_clean_file_exits_zero_and_bad_file_one(cli_env, tmp_path):
    ok = tmp_path / "ok.md"
    ok.write_text("# fine\n\nnothing here\n")
    bad = tmp_path / "bad.md"
    bad.write_text("Authorization: Bearer abcdefghijklmnopq\n")
    assert cli_main(["writeup", "check", str(ok)]) == 0
    assert cli_main(["writeup", "check", str(bad)]) == 1


def test_cli_publish_without_workdir_needs_pattern_only(cli_env, tmp_path, capsys):
    missing = tmp_path / "nowhere"
    assert cli_main(["writeup", "--workdir", str(missing), "--staging", str(tmp_path / "s"), "publish"]) == 2
    assert "--pattern-only" in capsys.readouterr().err
    (tmp_path / "s" / "x").mkdir(parents=True)
    (tmp_path / "s" / "x" / "README.md").write_text("# X\n\ndone\n")
    rc = cli_main(["writeup", "--workdir", str(missing), "--staging", str(tmp_path / "s"), "publish",
                   "--pattern-only", "--out", str(tmp_path / "pub")])
    assert rc == 1                                                     # held
    assert json.loads((tmp_path / "pub.publish-plan.json").read_text())["known_source"] == "pattern-only"


def test_cli_retro_rejects_until_with_day(cli_env, capsys):
    assert cli_main(["writeup", "retro", "--day", "2026-01-01", "--until", "2026-01-02T00:00:00Z"]) == 2
    assert "--until goes with --since" in capsys.readouterr().err


# ------------------------------------------------------------------ verification round 1 (B-098 fixes)

HASHED = "only_in_l3dger_hash"          # a bare value the ledger holds only as flag_sha256


def _sha(v):
    import hashlib
    return hashlib.sha256(v.encode()).hexdigest()


def test_known_values_take_ledger_candidates(tmp_path):
    wd = workdir(tmp_path)
    ledger(wd, [{"ts": 1.0, "event": "candidate", "challenge_id": "9", "candidate": "cand_v4lue_from_engine"}])
    recs = evidence.read_records(wd)
    assert "cand_v4lue_from_engine" in evidence.known_values(evidence.collect(wd, recs), recs)


def test_known_hashes_come_from_the_ledger_and_malformed_ones_fail(tmp_path):
    wd = workdir(tmp_path)
    ledger(wd, [{"ts": 1.0, "event": "platform.submit", "challenge_id": "9", "status": "incorrect",
                 "flag_sha256": _sha(HASHED).upper()}])
    assert evidence.known_hashes(evidence.read_records(wd)) == {"0" * 64, "1" * 64, _sha(HASHED)}
    ledger(wd, [{"ts": 2.0, "event": "platform.submit", "challenge_id": "9", "flag_sha256": "xyz"}])
    with pytest.raises(evidence.EvidenceError, match="flag_sha256 is not a sha256"):
        evidence.known_hashes(evidence.read_records(wd))


def test_draft_redacts_a_value_known_only_by_its_ledger_hash(tmp_path):
    p = profile(tmp_path)
    wd = workdir(tmp_path, notes_extra=f"submitted {HASHED} on the platform\n")
    ledger(wd, [{"ts": 1.0, "event": "platform.submit", "challenge_id": "7", "status": "incorrect",
                 "flag_sha256": _sha(HASHED)}])
    draft.run(p, wd, tmp_path / "stage")
    assert HASHED not in all_text(tmp_path / "stage")


def test_draft_escapes_a_comment_opener_in_evidence(tmp_path):
    p = profile(tmp_path)
    wd = workdir(tmp_path)
    cj = wd / "7-glitch" / "challenge.json"
    detail = json.loads(cj.read_text())
    detail["name"] = "Glitch <!-- hides the rest"
    cj.write_text(json.dumps(detail))
    draft.run(p, wd, tmp_path / "stage")
    readme = (tmp_path / "stage" / "7-glitch" / "README.md").read_text()
    assert "Glitch &lt;!-- hides the rest" in readme and "<!-- hides" not in readme


def test_publish_excludes_symlinks_out_of_staging(tmp_path):
    p, wd, stage, known = staged(tmp_path)
    outside = tmp_path / "outside-secret.md"
    outside.write_text("OUTSIDE_STAGING_CONTENT\n")
    (stage / "7-glitch" / "link.md").symlink_to(outside)
    out = tmp_path / "public"
    plan = publish.build(p, stage, out, known=known, known_source="workdir", now=AFTER)
    assert {"path": "7-glitch/link.md", "reason": "symlink"} in plan.excluded
    assert not (out / "7-glitch" / "link.md").exists() and "OUTSIDE_STAGING_CONTENT" not in all_text(out)
    assert all(f["path"] != "7-glitch/link.md" for f in plan.files)
    findings, excluded = publish.check(p, [stage], known=known)
    assert any(e["path"].endswith("link.md") and e["reason"] == "symlink" for e in excluded)


def test_publish_size_cap(tmp_path):
    p = profile(tmp_path)
    stage = tmp_path / "stage"
    (stage / "a").mkdir(parents=True)
    line = "word word word word word word word\n"
    body = (line * (publish.MAX_BYTES // len(line) + 1))
    (stage / "a" / "at-cap.md").write_text(body[:publish.MAX_BYTES])
    (stage / "a" / "over-cap.md").write_text(body[:publish.MAX_BYTES + 1])
    plan = publish.build(p, stage, tmp_path / "public", known=set(), known_source="pattern-only", now=AFTER)
    reasons = {e["path"]: e["reason"] for e in plan.excluded}
    assert reasons["a/over-cap.md"] == f"larger than {publish.MAX_BYTES} bytes"
    assert "a/at-cap.md" in {f["path"] for f in plan.files}


def test_publish_redacts_hashed_values_and_counts_hashes(tmp_path):
    p = profile(tmp_path)
    stage = tmp_path / "stage"
    (stage / "a").mkdir(parents=True)
    (stage / "b").mkdir()
    # a/ is processed first and holds the value only embedded in a longer token (no hash match there);
    # b/ holds it as a bare token. Every file's hashes are resolved before any file is redacted.
    (stage / "a" / "solve.py").write_text(f'x = "prefix_{HASHED}_suffix"\n')
    (stage / "b" / "README.md").write_text(f"# B\n\nthe answer was {HASHED}.\n")
    plan = publish.build(p, stage, tmp_path / "public", known=set(), known_source="workdir", now=AFTER,
                         known_hashes={_sha(HASHED)})
    assert HASHED not in all_text(tmp_path / "public")
    assert plan.to_dict()["known_flag_hashes"] == 1
    bare = tmp_path / "bare.md"
    bare.write_text(f"typed {HASHED}\n")
    assert publish.check(p, [bare], known=set(), known_hashes={_sha(HASHED)})[0] == []   # redacted, so clean
    p2 = profile(tmp_path, slug="keep", sharing="allowed", redact=False)
    found, _ = publish.check(p2, [bare], known=set(), known_hashes={_sha(HASHED)})
    assert [f.kind for f in found] == ["known-value"]         # a kept value is still reported


def test_cli_publish_uses_ledger_hashes(cli_env, tmp_path):
    p, wd = cli_env
    ledger(wd, [{"ts": 1.0, "event": "platform.submit", "challenge_id": "9", "status": "incorrect",
                 "flag_sha256": _sha(HASHED)}])
    assert cli_main(["writeup", "draft"]) == 0
    (wd / "writeups" / "9-other" / "extra.md").write_text(f"# extra\n\nwe sent {HASHED}\n")
    cli_main(["writeup", "publish"])
    assert HASHED not in all_text(wd / "writeups-public")
    assert json.loads((wd / "writeups-public.publish-plan.json").read_text())["known_flag_hashes"] == 3


def test_plan_file_inside_the_checkout_is_refused(tmp_path, monkeypatch):
    p, wd, stage, known = staged(tmp_path)
    plan = publish.build(p, stage, tmp_path / "public", known=known, known_source="workdir", now=AFTER)
    fake_repo = tmp_path / "checkout"                 # stands in for the checkout: a broken guard writes here
    (fake_repo / "writeups").mkdir(parents=True)
    monkeypatch.setattr(paths, "repo_root", lambda: fake_repo)
    target = fake_repo / "docs" / "plan.json"
    with pytest.raises(common.WriteupError, match="inside the repo checkout"):
        publish.write_plan(plan, target)
    assert not target.exists()
    ok = publish.write_plan(plan, fake_repo / "writeups" / "plan.json")      # the gitignored folder is fine
    assert json.loads(ok.read_text())["mode"] == "dry-run"


def test_a_plan_without_gates_is_never_ready(tmp_path):
    plan = publish.Plan(event="zz", staging=tmp_path, out=tmp_path / "o", public_repo=None, redacted=True,
                        known_values=0, known_source="pattern-only")
    assert plan.gates == [] and plan.ready is False


# ------------------------------------------------------------------ verification round 2 (B-098 fixes)

HASHED_SHAPED = "QQ{" + "h4sh_0nly_in_l3dger" + "}"      # another prefix: flag-shaped, blocking when redacting


def test_cli_check_uses_ledger_hashes(cli_env, tmp_path, capsys):
    p, wd = cli_env
    profile(tmp_path, slug="kk", sharing="allowed", redact=False)    # an event that keeps flags
    ledger(wd, [{"ts": 1.0, "event": "platform.submit", "challenge_id": "9", "status": "incorrect",
                 "flag_sha256": _sha(HASHED)},
                {"ts": 2.0, "event": "platform.submit", "challenge_id": "9", "status": "incorrect",
                 "flag_sha256": _sha(HASHED_SHAPED)}])
    staged_file = tmp_path / "staged.md"
    staged_file.write_text(f"# staged\n\nwe sent {HASHED}\nand then {HASHED_SHAPED}\n")
    # Forbidding profile: the hashes make both values known, so check redacts them before it scans
    # and nothing blocks. Without them, the other-prefix value stays and blocks as flag-shaped.
    capsys.readouterr()
    assert cli_main(["writeup", "check", str(staged_file)]) == 0
    out = capsys.readouterr().out
    assert "0 blocking" in out and HASHED not in out and HASHED_SHAPED not in out
    assert cli_main(["writeup", "check", "--pattern-only", str(staged_file)]) == 1     # the control
    assert "flag-shaped" in capsys.readouterr().out
    # Keeping profile: no redaction, so each resolved value is reported as a known-value note.
    assert cli_main(["writeup", "--event", "kk", "check", str(staged_file)]) == 0
    out = capsys.readouterr().out
    notes = [ln.strip() for ln in out.splitlines() if " known-value " in ln]
    assert len(notes) == 2 and all(n.startswith("NOTE") for n in notes), out
    assert {n.split(":L")[1].split(":")[0] for n in notes} == {"3", "4"}
    assert HASHED not in out and HASHED_SHAPED[3:-1] not in out
