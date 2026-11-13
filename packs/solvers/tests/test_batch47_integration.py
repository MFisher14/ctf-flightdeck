"""Batch-47 integration fix.

B-257: `ctf/lanestate.py` (`python -m ctf state`) defaults its challenges root to the saved past-event
attempts (the ctf.paths accessor for $CTF_REAL_CHALLENGES). Every file that reads that root must
be checked for the two cases a typo hides behind (tests/test_saved_sections.py lists this file for
`ctf/lanestate.py`): unset is a named refusal, and set to a folder that is not there fails naming the
folder and the variable, never read as "no saved attempts" and never a traceback.

The command runs in a child process with the real environment variable, so nothing here stands in for
ctf.paths. Offline and synthetic: the saved tree is written by the test. (This file does not spell the
accessor's call: the saved-sections test finds its carriers by that text, and this file is not one.)
"""
import json
import os
import subprocess
import sys

import pytest

from ctf import lanestate, paths

REPO = paths.repo_root()


def _env(tmp_path, saved=None) -> dict:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("PYTEST_", "CTF_"))}
    env.update(CTF_TESTING="1", CTF_WORKDIR=str(tmp_path / "work"), PYTHONDONTWRITEBYTECODE="1")
    if saved is not None:
        env["CTF_REAL_CHALLENGES"] = str(saved)
    return env


def _state(tmp_path, *args, saved=None) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-m", "ctf", "state", *map(str, args)], capture_output=True,
                          text=True, timeout=240, env=_env(tmp_path, saved), cwd=str(REPO))


def _saved_tree(root):
    """<root>/day-01/web-c1/attempt.json, the saved-attempts layout (<root>/day-NN/<lane>-<id>/)."""
    d = root / "day-01" / "web-c1"
    d.mkdir(parents=True)
    (d / "attempt.json").write_text(json.dumps({"attempt_id": "A7", "kind": "timed", "questions": [{"id": "q1"}]}))
    return root


def test_state_without_a_root_names_the_variable(tmp_path):
    r = _state(tmp_path, "attempt", "c1")
    assert r.returncode == 2, r.stderr[-2000:]
    assert "CTF_REAL_CHALLENGES" in r.stderr and "--root" in r.stderr
    assert "Traceback" not in r.stderr and r.stdout == ""


def test_state_reads_the_saved_folder_from_the_variable(tmp_path):
    """No --root: the id is located under $CTF_REAL_CHALLENGES; set to a missing folder it fails, naming it."""
    r = _state(tmp_path, "attempt", "c1", saved=_saved_tree(tmp_path / "saved"))
    assert r.returncode == 0, r.stderr[-2000:]
    assert "attempt_id: A7" in r.stdout
    missing = tmp_path / "no-such-saved-tree"
    r = _state(tmp_path, "attempt", "c1", saved=missing)
    assert r.returncode == 2, r.stderr[-2000:]
    assert "not found" in r.stderr and "CTF_REAL_CHALLENGES" in r.stderr and missing.name in r.stderr
    assert "Traceback" not in r.stderr and r.stdout == ""


def test_a_missing_saved_folder_is_a_lane_state_error_not_an_empty_root(tmp_path, monkeypatch):
    """In process: the library raises its own named error (what the CLI turns into exit 2), and an explicit
    --root still wins over a broken variable."""
    monkeypatch.setenv("CTF_REAL_CHALLENGES", str(tmp_path / "no-such-saved-tree"))
    with pytest.raises(lanestate.LaneStateError) as e:
        lanestate.resolve_challenge_dir("c1")
    assert "no-such-saved-tree" in str(e.value) and "CTF_REAL_CHALLENGES" in str(e.value)
    root = _saved_tree(tmp_path / "saved")
    assert lanestate.resolve_challenge_dir("c1", root=root) == root / "day-01" / "web-c1"
