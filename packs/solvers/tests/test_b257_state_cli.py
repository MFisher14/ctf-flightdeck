"""B-257: `python -m ctf state` lane-state readers and the brief lint (ctf.lanestate, ctf.cli.state).

Every test builds its own synthetic state files; none reads a real challenge or the platform.
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from ctf import lanestate as ls
from ctf.cli import state as state_cli


# ---- locating a challenge folder ---------------------------------------------------------------------

def _mk_attempt(d: Path, attempt_id: str = "A1") -> Path:
    d.mkdir(parents=True, exist_ok=True)
    (d / "attempt.json").write_text(json.dumps({"attempt_id": attempt_id, "kind": "timed",
                                                 "questions": [{"id": "q1"}]}))
    return d


def test_resolve_direct_dir(tmp_path):
    d = _mk_attempt(tmp_path / "chal")
    assert ls.resolve_challenge_dir(None, direct=d) == d


def test_resolve_dir_must_be_a_directory(tmp_path):
    with pytest.raises(ls.LaneStateError):
        ls.resolve_challenge_dir(None, direct=tmp_path / "nope")


def test_resolve_id_flat_under_root(tmp_path):
    _mk_attempt(tmp_path / "day-01" / "web-xyz")
    got = ls.resolve_challenge_dir("web-xyz", root=tmp_path)
    assert got.name == "web-xyz"


def test_resolve_id_suffix_match(tmp_path):
    _mk_attempt(tmp_path / "day-02" / "binary-reverse-abc123")
    got = ls.resolve_challenge_dir("abc123", root=tmp_path)
    assert got.name == "binary-reverse-abc123"


def test_resolve_id_ambiguous_raises(tmp_path):
    _mk_attempt(tmp_path / "day-01" / "web-dup")
    _mk_attempt(tmp_path / "day-02" / "web-dup")
    with pytest.raises(ls.LaneStateError) as e:
        ls.resolve_challenge_dir("web-dup", root=tmp_path)
    assert "ambiguous" in str(e.value)


def test_resolve_id_missing_raises(tmp_path):
    with pytest.raises(ls.LaneStateError) as e:
        ls.resolve_challenge_dir("ghost", root=tmp_path)
    assert "no challenge folder" in str(e.value)


def test_resolve_no_root_names_the_env_var(monkeypatch):
    # no --root and no $CTF_REAL_CHALLENGES -> a named failure, never a guess
    import ctf.paths as paths
    monkeypatch.setattr(paths, "saved_challenges_root", lambda: None)
    with pytest.raises(ls.LaneStateError) as e:
        ls.resolve_challenge_dir("x", root=None)
    assert "CTF_REAL_CHALLENGES" in str(e.value)


# ---- per-challenge readers ---------------------------------------------------------------------------

def test_read_attempt_surfaces_known_fields(tmp_path):
    d = _mk_attempt(tmp_path / "c", attempt_id="ATT-9")
    out = "\n".join(ls.read_attempt(d))
    assert "attempt_id: ATT-9" in out
    assert "kind: timed" in out
    assert "questions: [1 item]" in out   # a container is a count, not a dump


def test_read_result(tmp_path):
    d = tmp_path / "c"
    d.mkdir()
    (d / "result.json").write_text(json.dumps({"result": "CORRECT", "source": "run.py"}))
    out = "\n".join(ls.read_result(d))
    assert "result: CORRECT" in out and "source: run.py" in out


def test_read_start_prefers_start_over_live_start(tmp_path):
    d = tmp_path / "c"
    d.mkdir()
    (d / "start.json").write_text(json.dumps({"attempt_id": "S1"}))
    (d / "live_start.json").write_text(json.dumps({"attempt_id": "LIVE"}))
    out = "\n".join(ls.read_start(d))
    assert "attempt_id: S1" in out and "start.json" in out


def test_read_key_lists_answers(tmp_path):
    d = tmp_path / "c"
    d.mkdir()
    (d / "key.json").write_text(json.dumps({"q2": "flag{b}", "q1": "elf"}))
    out = ls.read_key(d)
    # sorted by answer id, compact one-per-line
    assert out[1].strip() == "q1 = elf"
    assert out[2].strip() == "q2 = flag{b}"


def test_read_key_unwraps_dict_values(tmp_path):
    d = tmp_path / "c"
    d.mkdir()
    (d / "key.json").write_text(json.dumps({"q1": {"value": "42", "verdict": "CORRECT"}}))
    assert ls.read_key(d)[1].strip() == "q1 = 42"


def test_read_answers_picks_submitted_first(tmp_path):
    d = tmp_path / "c"
    d.mkdir()
    (d / "answers.json").write_text(json.dumps({"q1": "x"}))
    (d / "answers.submitted.json").write_text(json.dumps({"q1": "y"}))
    out = "\n".join(ls.read_answers(d))
    assert "answers.submitted.json" in out and "q1 = y" in out


def test_read_verdicts_one_line_per_submission(tmp_path):
    d = tmp_path / "c"
    d.mkdir()
    rows = [{"kind": "bank", "result": "incorrect", "values": {"q1": "no"}},
            {"kind": "bank", "result": "CORRECT", "values": {"q1": "yes"}}]
    (d / "verdicts.jsonl").write_text("\n".join(json.dumps(r) for r in rows))
    out = ls.read_verdicts(d)
    assert "2 submissions" in out[0]
    assert "result=incorrect" in out[1] and "q1:no" in out[1]
    assert "result=CORRECT" in out[2]


def test_read_verdicts_rejects_bad_jsonl(tmp_path):
    d = tmp_path / "c"
    d.mkdir()
    (d / "verdicts.jsonl").write_text('{"ok":1}\nnot json\n')
    with pytest.raises(ls.LaneStateError) as e:
        ls.read_verdicts(d)
    assert "line 2" in str(e.value)


def test_read_ladder_list(tmp_path):
    d = tmp_path / "c"
    d.mkdir()
    (d / "ladder-log.json").write_text(json.dumps([{"op": "bank", "answer_id": "q1", "result": "CORRECT"}]))
    out = ls.read_ladder(d)
    assert "1 step" in out[0]
    assert "op: bank" in out[1]


def test_missing_file_is_a_named_error(tmp_path):
    d = tmp_path / "c"
    d.mkdir()
    with pytest.raises(ls.LaneStateError) as e:
        ls.read_attempt(d)
    assert "attempt.json" in str(e.value)


def test_read_proofs_counts_answered(tmp_path):
    d = tmp_path / "c"
    d.mkdir()
    (d / "proofs.json").write_text(json.dumps({"q1": "SECRET", "q2": None}))
    out = ls.read_proofs(d)
    assert "1/2 answered" in out[0]
    assert "q1 = SECRET" in "\n".join(out)
    assert "q2 = None" in "\n".join(out)


def test_read_proofs_answered_count_polarity(tmp_path):
    # An uneven answered/none split: `is not None` -> count 2, `is None` -> count 1,
    # so the header pins the polarity of the proven filter (a mutant can't pass both).
    d = tmp_path / "c"
    d.mkdir()
    (d / "proofs.json").write_text(json.dumps({"q1": "A", "q2": "B", "q3": None}))
    out = ls.read_proofs(d)
    assert "2/3 answered" in out[0]


def test_read_proofs_missing_names_the_files(tmp_path):
    d = tmp_path / "c"
    d.mkdir()
    with pytest.raises(ls.LaneStateError) as e:
        ls.read_proofs(d)
    assert "proofs.json" in str(e.value)


# ---- lane readers ------------------------------------------------------------------------------------

def test_read_conventions_both_files(tmp_path):
    lane = tmp_path / "solvers" / "mylane"
    lane.mkdir(parents=True)
    (lane / "conventions.json").write_text(json.dumps({
        "fmt/elf": {"accepted": "elf", "rejected": ["ELF", "ELF64"]}}))
    (lane / "id_conventions.toml").write_text('known = ["d01_format", "d01_size"]\n')
    out = "\n".join(ls.read_conventions(lane="mylane", root=tmp_path))
    assert "fmt/elf -> elf (rejected: ELF, ELF64)" in out
    assert "2 known id(s)" in out
    assert "d01_format" in out


def test_read_conventions_none_present_raises(tmp_path):
    (tmp_path / "solvers" / "empty").mkdir(parents=True)
    with pytest.raises(ls.LaneStateError) as e:
        ls.read_conventions(lane="empty", root=tmp_path)
    assert "no conventions" in str(e.value)


def test_read_routes_filters_by_id():
    # the real committed route table; filter down to one engine id
    rows = ls.read_routes(engine_id="binary.binfmt")
    body = "\n".join(rows)
    assert "binary.binfmt" in body
    # every listed route line is binary.binfmt (the header line carries the counts)
    for ln in rows[1:]:
        assert "binary.binfmt" in ln


def test_read_routes_filters_by_lane():
    # the real committed route table, filtered to one lane: only that lane's engine ids survive.
    # A route's lane is its id's first dotted segment; this kills the lane-filter guard.
    rows = ls.read_routes(lane="web")
    assert len(rows) > 1          # the lane has routes (otherwise the assertion below is vacuous)
    for ln in rows[1:]:           # header line carries the counts
        assert " web." in ln      # every listed route id is in the web lane
    body = "\n".join(rows)
    assert "binary.binfmt" not in body   # a known other-lane id is filtered out


def test_read_qdiff_flags_a_kind_change(tmp_path):
    base = tmp_path / "base.json"
    timed = tmp_path / "timed.json"
    base.write_text(json.dumps({"questions": [{"id": "q1", "answer_format": {"kind": "integer"}}]}))
    timed.write_text(json.dumps({"questions": [
        {"id": "q1", "answer_format": {"kind": "exact_text"}},
        {"id": "q2", "answer_format": {"kind": "integer"}}]}))
    out = "\n".join(ls.read_qdiff(base, timed))
    assert "ATTN" in out and "kind" in out
    assert "q2" in out   # the added id


# ---- brief lint --------------------------------------------------------------------------------------

def test_lint_flags_a_cat_reader():
    hits = ls.lint_brief_text("Run `cat challenges/x/attempt.json` to read it.")
    assert len(hits) == 1
    assert hits[0][1] == "attempt.json"


def test_lint_flags_python_json_load():
    hits = ls.lint_brief_text("python3 -c 'import json; json.load(open(\"key.json\"))'")
    assert hits and hits[0][1] == "key.json"


def test_lint_does_not_flag_the_state_command():
    assert ls.lint_brief_text("Use `python -m ctf state attempt <id>` not a reader of attempt.json.") == []


def test_lint_does_not_flag_plain_prose():
    # names the file but no read verb -> not an inline reader
    assert ls.lint_brief_text("The frozen answers live in key.json after a CORRECT verdict.") == []


def test_lint_briefs_walks_a_tree(tmp_path):
    (tmp_path / "a.md").write_text("cat start.json | jq .")
    (tmp_path / "b.md").write_text("nothing here")
    findings = ls.lint_briefs([tmp_path])
    assert len(findings) == 1
    assert findings[0][2] == "start.json"


def test_lint_missing_path_raises(tmp_path):
    with pytest.raises(ls.LaneStateError):
        ls.lint_briefs([tmp_path / "ghost"])


# ---- CLI surface -------------------------------------------------------------------------------------

def test_cli_attempt_via_dir(tmp_path, capsys):
    d = _mk_attempt(tmp_path / "c", attempt_id="CLI-1")
    args = SimpleNamespace(sub="attempt", cid=None, root=None, dir=d)
    assert state_cli.run(args) == 0
    assert "CLI-1" in capsys.readouterr().out


def test_cli_missing_file_exits_2(tmp_path, capsys):
    d = tmp_path / "c"
    d.mkdir()
    args = SimpleNamespace(sub="result", cid=None, root=None, dir=d)
    assert state_cli.run(args) == 2
    assert "result.json" in capsys.readouterr().err


def test_cli_lint_exit_1_on_findings(tmp_path, capsys):
    (tmp_path / "brief.md").write_text("cat attempt.json")
    args = SimpleNamespace(sub="lint", paths=[str(tmp_path)])
    assert state_cli.run(args) == 1
    assert "attempt.json" in capsys.readouterr().out


def test_cli_lint_exit_0_when_clean(tmp_path, capsys):
    (tmp_path / "brief.md").write_text("use python -m ctf state attempt")
    args = SimpleNamespace(sub="lint", paths=[str(tmp_path)])
    assert state_cli.run(args) == 0


# ---- status/journal are wrappers, not second parsers -------------------------------------------------

def test_status_delegates_to_wire_ledger_and_hypothesis(monkeypatch):
    from ctf.cli import wire as wire_cli, ledger as ledger_cli, hypothesis as hyp_cli
    calls = []

    def rec(mod):
        def fn(args):
            calls.append((mod, args.action, getattr(args, "cid", None)))
            return 0
        return fn

    monkeypatch.setattr(wire_cli, "run", rec("wire"))
    monkeypatch.setattr(ledger_cli, "run", rec("ledger"))
    monkeypatch.setattr(hyp_cli, "run", rec("hypothesis"))
    args = SimpleNamespace(sub="status", cid="chal-7", event="huntress", workdir=None)
    assert state_cli.run(args) == 0
    assert ("wire", "status", None) in calls
    assert ("ledger", "summary", None) in calls
    assert ("hypothesis", "list", "chal-7") in calls


def test_status_without_cid_skips_hypotheses(monkeypatch):
    from ctf.cli import wire as wire_cli, ledger as ledger_cli, hypothesis as hyp_cli
    seen = []
    monkeypatch.setattr(wire_cli, "run", lambda a: seen.append("wire") or 0)
    monkeypatch.setattr(ledger_cli, "run", lambda a: seen.append("ledger") or 0)
    monkeypatch.setattr(hyp_cli, "run", lambda a: seen.append("hyp") or 0)
    args = SimpleNamespace(sub="status", cid=None, event=None, workdir=None)
    assert state_cli.run(args) == 0
    assert "hyp" not in seen


def test_journal_forwards_filters_to_wire(monkeypatch):
    from ctf.cli import wire as wire_cli
    captured = {}
    monkeypatch.setattr(wire_cli, "run", lambda a: captured.update(vars(a)) or 0)
    args = SimpleNamespace(sub="journal", event="huntress", workdir=None,
                           since="60", lane="web", op="start", status=429, json=True)
    assert state_cli.run(args) == 0
    assert captured["action"] == "journal"
    assert captured["lane"] == "web" and captured["status"] == 429 and captured["since"] == "60"


def test_status_returns_1_when_a_collaborator_fails(monkeypatch):
    from ctf.cli import wire as wire_cli, ledger as ledger_cli
    monkeypatch.setattr(wire_cli, "run", lambda a: 2)
    monkeypatch.setattr(ledger_cli, "run", lambda a: 0)
    args = SimpleNamespace(sub="status", cid=None, event=None, workdir=None)
    assert state_cli.run(args) == 1
