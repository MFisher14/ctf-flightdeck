"""B-195: `python -m ctf gate` mode rules (full once per batch, impact, lane, warm), exits, and the state
folder resolver ctf.paths.gate_state()."""
from __future__ import annotations

import argparse
import json
import subprocess
import sys

import pytest

from ctf import paths
from ctf.cli import gate
from gate_repo import make_repo, write

FILES = {
    "lib/val.txt": "7\n",
    "lib/other.txt": "x\n",
    "docs/notes.md": "# notes\n",
    "tests/test_ok.py": 'VAL = "lib/val.txt"\ndef test_one():\n    pass\n',
    "tests/test_other.py": 'OTHER = "lib/other.txt"\ndef test_two():\n    pass\n',
    "tests/test_red.py": 'RED = "red.flag"\ndef test_red():\n    assert 0\n',
    "red.flag": "1\n",
}
LANES = '\n[lanes]\nvals = ["lib/val.txt"]\n'


@pytest.fixture
def repo(tmp_path):
    return make_repo(tmp_path / "repo", FILES, extra_config=LANES)


def cli(repo, tmp_path, *argv):
    p = argparse.ArgumentParser()
    gate.add_arguments(p)
    common = ["--root", str(repo), "--config", str(repo / "gate.toml"), "--state", str(tmp_path / "state")]
    args = p.parse_args(common + list(argv))
    return gate.run(args)


def rows(out: str) -> dict:
    """{test file: line} for the per-file lines of a run."""
    got = {}
    for ln in out.splitlines():
        parts = ln.split()
        if len(parts) > 2 and parts[0] in ("PASS", "FAIL", "ERROR", "TIMEOUT", "EMPTY"):
            got[parts[2]] = ln
    return got


def test_no_selector_is_a_usage_error(repo, tmp_path, capsys):
    assert cli(repo, tmp_path, "run") == 2
    assert "say what to gate" in capsys.readouterr().err


def test_batch_first_run_is_full_and_recorded_then_impact(repo, tmp_path, capsys):
    assert cli(repo, tmp_path, "run", "--batch", "b1", "--changed", "lib/val.txt", "--jobs", "1") == 1
    out = capsys.readouterr().out
    assert "full: first run of batch b1" in out and "mode=full" in out
    assert set(rows(out)) == {"tests/test_ok.py", "tests/test_other.py", "tests/test_red.py"}
    assert "batch b1 full run recorded" in out
    rec = json.loads((tmp_path / "state" / "batches" / "b1.json").read_text())
    assert rec["result"] == "fail" and rec["files"] == 3 and rec["red"] == ["tests/test_red.py"]
    # the batch had its full run: no changes given -> refuse, changes given -> impact
    assert cli(repo, tmp_path, "run", "--batch", "b1") == 2
    assert "already had its full run" in capsys.readouterr().err
    write(repo, {"tests/test_red.py": 'RED = "red.flag"\ndef test_red():\n    pass\n'})
    assert cli(repo, tmp_path, "run", "--batch", "b1", "--changed", "tests/test_red.py") == 0
    out = capsys.readouterr().out
    assert "mode=impact" in out and set(rows(out)) == {"tests/test_red.py"}
    assert "batch b1 red files: none" in out
    assert cli(repo, tmp_path, "run", "--batch", "b1", "--changed", "lib/val.txt") == 0
    out = capsys.readouterr().out
    assert "mode=impact" in out and set(rows(out)) == {"tests/test_ok.py"}  # the fixed red file is not carried
    assert "warm" in rows(out)["tests/test_ok.py"]                         # the full run warmed it


def test_a_red_file_from_the_full_run_is_rerun_until_green(repo, tmp_path, capsys):
    """A failure the full run found, in a file the later change does not touch, keeps the batch red."""
    assert cli(repo, tmp_path, "run", "--batch", "b1", "--full") == 1
    capsys.readouterr()
    assert cli(repo, tmp_path, "plan", "--batch", "b1", "--changed", "lib/val.txt", "--json") == 0
    d = json.loads(capsys.readouterr().out)
    assert d["tests"] == ["tests/test_ok.py", "tests/test_red.py"]
    assert d["why"]["tests/test_red.py"] == ["red in batch b1"]
    assert cli(repo, tmp_path, "run", "--batch", "b1", "--changed", "lib/val.txt") == 1
    out = capsys.readouterr().out
    assert set(rows(out)) == {"tests/test_ok.py", "tests/test_red.py"}
    assert rows(out)["tests/test_red.py"].startswith("FAIL")
    assert "GATE result=fail mode=impact" in out and "batch b1 red files: tests/test_red.py" in out
    # an inert-only change still reruns the red file, and so does a lane run whose lane does not hold it
    assert cli(repo, tmp_path, "run", "--batch", "b1", "--changed", "docs/notes.md") == 1
    assert set(rows(capsys.readouterr().out)) == {"tests/test_red.py"}
    assert cli(repo, tmp_path, "run", "--batch", "b1", "--lane", "vals") == 1
    assert set(rows(capsys.readouterr().out)) == {"tests/test_ok.py", "tests/test_red.py"}
    # the fix lands in a file the selection does not otherwise reach: the carried file runs green and leaves
    write(repo, {"tests/test_red.py":'RED = "red.flag"\ndef test_red():\n    pass\n'})
    assert cli(repo, tmp_path, "run", "--batch", "b1", "--changed", "lib/other.txt") == 0
    out = capsys.readouterr().out
    assert set(rows(out)) == {"tests/test_other.py", "tests/test_red.py"} and "batch b1 red files: none" in out
    rec = json.loads((tmp_path / "state" / "batches" / "b1.json").read_text())
    assert rec["red"] == [] and rec["result"] == "fail"                    # the full run's own result is kept


def test_a_new_red_in_a_later_run_joins_the_batch(repo, tmp_path, capsys):
    write(repo, {"tests/test_red.py": 'RED = "red.flag"\ndef test_red():\n    pass\n'})
    assert cli(repo, tmp_path, "run", "--batch", "b2", "--full") == 0
    capsys.readouterr()
    write(repo, {"tests/test_other.py": 'OTHER = "lib/other.txt"\ndef test_two():\n    assert 0\n'})
    assert cli(repo, tmp_path, "run", "--batch", "b2", "--changed", "tests/test_other.py") == 1
    assert "batch b2 red files: tests/test_other.py" in capsys.readouterr().out
    assert cli(repo, tmp_path, "run", "--batch", "b2", "--changed", "lib/val.txt") == 1
    assert set(rows(capsys.readouterr().out)) == {"tests/test_ok.py", "tests/test_other.py"}


# Reads an environment variable the gate config does not list, so one key can be green and later red.
FLIP = {"tests/test_flip.py": "import os\ndef test_flip():\n    assert os.environ.get('B195_FLIP') != '1'\n",
        "tests/test_red.py": 'RED = "red.flag"\ndef test_red():\n    pass\n'}


def test_a_carried_red_file_is_never_reused_warm(repo, tmp_path, capsys, monkeypatch):
    """A green result stored under the same key as the batch's red (a flaky file, or one stored by a run
    outside the batch) must not turn the carried file green without a rerun."""
    write(repo, FLIP)
    t = "tests/test_flip.py"
    monkeypatch.delenv("B195_FLIP", raising=False)
    assert cli(repo, tmp_path, "run", "--changed", t) == 0                # green, stored before the batch
    monkeypatch.setenv("B195_FLIP", "1")
    assert cli(repo, tmp_path, "run", "--batch", "b4", "--full") == 1     # same key, red: carried
    capsys.readouterr()
    monkeypatch.delenv("B195_FLIP")
    assert cli(repo, tmp_path, "run", "--changed", t) == 0                # outside the batch: green, stored again
    assert "warm" not in rows(capsys.readouterr().out)[t]
    monkeypatch.setenv("B195_FLIP", "1")
    assert cli(repo, tmp_path, "plan", "--batch", "b4", "--changed", "docs/notes.md", "--json") == 0
    d = json.loads(capsys.readouterr().out)
    assert d["tests"] == [t] and d["warm"] == []                          # the plan says it will run
    assert cli(repo, tmp_path, "run", "--batch", "b4", "--changed", "docs/notes.md") == 1
    out = capsys.readouterr().out
    assert rows(out)[t].startswith("FAIL") and "warm" not in rows(out)[t]
    assert f"batch b4 red files: {t}" in out


def test_a_warm_row_never_takes_a_file_off_the_red_list(repo, tmp_path, capsys, monkeypatch):
    """Only a file that really ran green leaves the list: if the runner ever hands back a warm row for a
    carried red file, the file stays red."""
    from ctf.gate import runner
    assert cli(repo, tmp_path, "run", "--batch", "b5", "--full") == 1
    capsys.readouterr()

    def fake_run_gate(graph, sel, **kw):
        assert "tests/test_red.py" in kw["no_reuse"]                      # the CLI asks for a rerun
        rep = runner.Report(mode=sel.mode)
        rep.rows = [runner.Row(test=t, status="PASS", passed=1, warm="0" * 12) for t in sel.tests]
        return rep

    monkeypatch.setattr(runner, "run_gate", fake_run_gate)
    assert cli(repo, tmp_path, "run", "--batch", "b5", "--changed", "docs/notes.md") == 0
    assert "batch b5 red files: tests/test_red.py" in capsys.readouterr().out
    assert json.loads((tmp_path / "state" / "batches" / "b5.json").read_text())["red"] == ["tests/test_red.py"]


def test_a_deleted_red_file_is_dropped_with_a_reason(repo, tmp_path, capsys):
    assert cli(repo, tmp_path, "run", "--batch", "b3", "--full") == 1
    capsys.readouterr()
    (repo / "tests" / "test_red.py").unlink()
    assert cli(repo, tmp_path, "run", "--batch", "b3", "--changed", "docs/notes.md") == 0
    out = capsys.readouterr().out
    assert "red file(s) no longer in the tree, dropped: tests/test_red.py" in out and rows(out) == {}
    assert json.loads((tmp_path / "state" / "batches" / "b3.json").read_text())["red"] == []


def test_a_batch_record_without_red_files_fails_loudly(repo, tmp_path, capsys):
    p = tmp_path / "state" / "batches" / "old.json"
    p.parent.mkdir(parents=True)
    p.write_text(json.dumps({"batch": "old", "ts": 1.0, "result": "fail", "files": 3, "seconds": 1.0}))
    assert cli(repo, tmp_path, "plan", "--batch", "old", "--changed", "lib/val.txt") == 2
    assert "no list of red files" in capsys.readouterr().err


def test_full_reuses_nothing_and_impact_reuses(repo, tmp_path, capsys):
    assert cli(repo, tmp_path, "run", "--changed", "lib/val.txt") == 0
    first = rows(capsys.readouterr().out)
    assert "warm" not in first["tests/test_ok.py"]
    assert cli(repo, tmp_path, "run", "--full") == 1
    full = rows(capsys.readouterr().out)
    assert not any("warm" in ln for ln in full.values())
    assert cli(repo, tmp_path, "run", "--changed", "lib/val.txt", "--no-warm") == 0
    assert "warm" not in rows(capsys.readouterr().out)["tests/test_ok.py"]
    assert cli(repo, tmp_path, "run", "--changed", "lib/val.txt") == 0
    assert "warm" in rows(capsys.readouterr().out)["tests/test_ok.py"]


def test_red_selection_exits_1(repo, tmp_path, capsys):
    assert cli(repo, tmp_path, "run", "--changed", "red.flag") == 1
    out = capsys.readouterr().out
    assert rows(out)["tests/test_red.py"].startswith("FAIL")
    assert out.strip().splitlines()[-1].startswith("GATE result=fail")


def test_base_ref_selects_from_git(repo, tmp_path, capsys):
    write(repo, {"lib/other.txt": "y\n"})
    assert cli(repo, tmp_path, "plan", "--base", "HEAD", "--json") == 0
    d = json.loads(capsys.readouterr().out)
    assert d["mode"] == "impact" and d["tests"] == ["tests/test_other.py"]
    assert d["why"] == {"tests/test_other.py": ["lib/other.txt"]}


def test_plan_marks_warm_files(repo, tmp_path, capsys):
    cli(repo, tmp_path, "run", "--changed", "lib/val.txt", "lib/other.txt")
    capsys.readouterr()
    write(repo, {"lib/other.txt": "changed\n"})
    assert cli(repo, tmp_path, "plan", "--changed", "lib/val.txt", "lib/other.txt") == 0
    out = capsys.readouterr().out
    assert "WARM  tests/test_ok.py" in out and "RUN   tests/test_other.py" in out
    assert "PLAN mode=impact files=2 warm=1 run=1" in out


def test_lane_alone_and_as_filter(repo, tmp_path, capsys):
    assert cli(repo, tmp_path, "plan", "--lane", "vals", "--json") == 0
    d = json.loads(capsys.readouterr().out)
    assert (d["mode"], d["tests"]) == ("lane", ["tests/test_ok.py"])
    assert cli(repo, tmp_path, "plan", "--full", "--lane", "vals", "--json") == 0
    assert json.loads(capsys.readouterr().out)["tests"] == ["tests/test_ok.py"]
    assert cli(repo, tmp_path, "plan", "--lane", "nope") == 2
    assert "unknown lane 'nope'" in capsys.readouterr().err


def test_inert_only_change_runs_nothing_and_passes(repo, tmp_path, capsys):
    assert cli(repo, tmp_path, "run", "--changed", "docs/notes.md") == 0
    out = capsys.readouterr().out
    assert "inert (no test reads them): docs/notes.md" in out and "files=0" in out and rows(out) == {}


def test_usage_errors(repo, tmp_path, capsys):
    assert cli(repo, tmp_path, "run", "--full", "--jobs", "0") == 2
    assert cli(repo, tmp_path, "plan", "--changed", "/elsewhere/x.py") == 2
    assert "outside the checkout" in capsys.readouterr().err
    assert cli(repo, tmp_path, "plan", "--batch", "bad id!") == 2
    assert "bad batch id" in capsys.readouterr().err
    (repo / "gate.toml").write_text("version = 3\n")
    assert cli(repo, tmp_path, "plan", "--full") == 2
    assert "version must be 1" in capsys.readouterr().err


def test_inventory_counts_reuse(repo, tmp_path, capsys):
    write(repo, {"lib/mod.py": "import os\n"})
    assert cli(repo, tmp_path, "inventory") == 0
    first = capsys.readouterr().out
    assert first.startswith("INVENTORY") and "parsed=4" in first and "reused=0" in first
    assert cli(repo, tmp_path, "inventory") == 0
    second = capsys.readouterr().out
    assert "parsed=0" in second and "reused=4" in second and "hashed=0" in second


def test_command_is_discovered():
    r = subprocess.run([sys.executable, "-m", "ctf", "gate", "--help"], capture_output=True, text=True,
                       cwd=paths.repo_root(), timeout=120)
    assert r.returncode == 0, r.stderr
    assert "plan" in r.stdout and "inventory" in r.stdout


# -- ctf.paths.gate_state ----------------------------------------------------------------------------------------

def test_gate_state_override(monkeypatch, tmp_path):
    monkeypatch.setenv("CTF_GATE_STATE", str(tmp_path / "st"))
    assert paths.gate_state() == (tmp_path / "st").resolve()


def test_gate_state_in_a_plain_checkout_and_a_worktree(monkeypatch, tmp_path):
    monkeypatch.delenv("CTF_GATE_STATE", raising=False)
    main = tmp_path / "main"
    (main / ".git" / "worktrees" / "w1").mkdir(parents=True)
    assert paths.gate_state(main) == (main / ".git" / "ctf-gate").resolve()
    wt = tmp_path / "wt"
    wt.mkdir()
    (wt / ".git").write_text(f"gitdir: {main / '.git' / 'worktrees' / 'w1'}\n")
    (main / ".git" / "worktrees" / "w1" / "commondir").write_text("../..\n")
    assert paths.gate_state(wt) == (main / ".git" / "ctf-gate").resolve()      # shared by every worktree


def test_gate_state_without_git_names_the_variable(monkeypatch, tmp_path):
    monkeypatch.delenv("CTF_GATE_STATE", raising=False)
    with pytest.raises(FileNotFoundError, match="CTF_GATE_STATE"):
        paths.gate_state(tmp_path)
