"""B-137: a stable record of the gate's last run at a fixed path, so a red is never lost to a pipe. The
Oct 9 incident had a red "never identified because output was piped to tail"; <state>/last-fail.log
always names what failed, whatever happened to stdout."""
from __future__ import annotations

import argparse
import json

import pytest

from ctf.cli import gate
from ctf.gate import faillog
from ctf.gate.faillog import LAST_FAIL, LAST_RUN
from ctf.gate.runner import Report, Row
from gate_repo import make_repo, write


# ------------------------------------------------------------------ faillog.record (unit)

def _rep(rows, mode="full"):
    rep = Report(mode=mode)
    rep.rows = rows
    return rep


def test_records_the_failing_item_by_name(tmp_path):
    rep = _rep([Row(test="tests/test_a.py", status="PASS", passed=3),
                Row(test="tests/test_b.py", status="FAIL", detail="assert 1 == 2", log=str(tmp_path / "b.log"))])
    path = faillog.record(tmp_path / "state", tmp_path / "repo", rep, run_dir=tmp_path / "run", head="abc123")
    text = path.read_text()
    assert path.name == LAST_FAIL
    assert "tests/test_b.py" in text and "assert 1 == 2" in text and "result=fail" in text
    assert "tests/test_a.py" not in text                       # only the non-green files are listed
    doc = json.loads((tmp_path / "state" / LAST_RUN).read_text())
    assert doc["result"] == "fail" and doc["red"] == 1 and doc["head"] == "abc123"
    assert [i["test"] for i in doc["items"]] == ["tests/test_b.py"]


def test_env_is_listed_apart_from_red(tmp_path):
    rep = _rep([Row(test="tests/test_dock.py", status="ENV", detail="docker down [docker-daemon]"),
                Row(test="tests/test_x.py", status="FAIL", detail="boom")])
    faillog.record(tmp_path / "s", tmp_path / "r", rep, run_dir=tmp_path / "run")
    text = (tmp_path / "s" / LAST_FAIL).read_text()
    assert "ENV     tests/test_dock.py" in text and "env=1" in text
    assert "FAIL    tests/test_x.py" in text


def test_a_green_run_overwrites_a_stale_red_log(tmp_path):
    state = tmp_path / "s"
    faillog.record(state, tmp_path / "r", _rep([Row(test="tests/test_b.py", status="FAIL", detail="boom")]),
                   run_dir=tmp_path / "run")
    assert "tests/test_b.py" in (state / LAST_FAIL).read_text()
    faillog.record(state, tmp_path / "r", _rep([Row(test="tests/test_b.py", status="PASS", passed=1)]),
                   run_dir=tmp_path / "run")
    text = (state / LAST_FAIL).read_text()
    assert "all 1 file(s) green" in text and "tests/test_b.py" not in text   # no stale red survives


# ------------------------------------------------------------------ through the CLI (integration)

FILES = {
    "tests/test_ok.py": "def test_ok():\n    assert True\n",
    "tests/test_red.py": "def test_red():\n    assert 0, 'deliberate red'\n",
}


@pytest.fixture
def repo(tmp_path):
    return make_repo(tmp_path / "repo", FILES)


def _cli(repo, state, *argv):
    p = argparse.ArgumentParser()
    gate.add_arguments(p)
    args = p.parse_args(["--root", str(repo), "--config", str(repo / "gate.toml"),
                         "--state", str(state)] + list(argv))
    return gate.run(args)


def test_the_fail_log_names_the_item_even_when_stdout_is_discarded(repo, tmp_path, capsys):
    state = tmp_path / "state"
    rc = _cli(repo, state, "run", "--full", "--jobs", "1")
    capsys.readouterr()                       # drop stdout entirely: the pipe-to-tail case
    assert rc == 1
    log = (state / LAST_FAIL).read_text()
    assert "FAIL" in log and "tests/test_red.py" in log and "result=fail" in log
    # the per-file log path is named too, so the operator can open the full output of the failing item
    assert "tests__test_red.py.log" in log


def test_the_pointer_line_is_printed_before_the_gate_summary(repo, tmp_path, capsys):
    _cli(repo, tmp_path / "state", "run", "--full", "--jobs", "1")
    lines = [ln for ln in capsys.readouterr().out.splitlines() if ln.strip()]
    assert lines[-1].startswith("GATE result=fail")       # the summary stays the final, parseable line
    assert any(ln.startswith("gate: see ") and LAST_FAIL in ln for ln in lines)


def test_a_green_full_run_writes_the_all_green_line(repo, tmp_path, capsys):
    write(repo, {"tests/test_red.py": "def test_red():\n    assert True\n"})
    from gate_repo import git
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "fix")
    rc = _cli(repo, tmp_path / "state", "run", "--full", "--jobs", "1")
    capsys.readouterr()
    assert rc == 0
    assert "file(s) green" in (tmp_path / "state" / LAST_FAIL).read_text()
