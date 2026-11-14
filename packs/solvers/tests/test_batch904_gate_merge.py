"""Merge batch 904: B-153 (the pre-arm full gate, lane budgets, baseline ledger), B-196 (strict not-run) and
B-213 (the idle-machine lock) all reshaped `ctf gate`. These pin the joins: `ctf gate prearm` runs strict
about tests that did not run (it accepts only the config's not_run_ok kinds), and it takes the idle-lock
flags `run` takes, since both run files through the same executor. Synthetic checkouts only."""
from __future__ import annotations

import argparse
import sys

from ctf.cli import gate
from gate_repo import git, make_repo

LEDGER = ('version = 1\n[[red]]\nid = "tests/test_ok.py::test_ok"\nkind = "flaky"\n'
          'reason = "the pre-arm preflight needs a ledger to attribute reds"\nsince = 2026-11-01\n')
BASE = {
    ".gitignore": "__pycache__/\n",
    "tests/test_ok.py": "def test_ok():\n    pass\n",
    "base.toml": LEDGER,
}
SKIPS = "import pytest\n\n\ndef test_needs_a_tool():\n    pytest.skip('tool absent')\n"


def _repo(tmp_path, files):
    root = make_repo(tmp_path / "repo", dict(BASE, **files), commit=False)
    toml = (root / "gate.toml").read_text().replace("no_warm =", 'baseline = "base.toml"\nno_warm =')
    (root / "gate.toml").write_text(toml)
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "base")
    return root


def _parse(root, state, *argv):
    p = argparse.ArgumentParser()
    gate.add_arguments(p)
    return p.parse_args(["--root", str(root), "--config", str(root / "gate.toml"), "--state", str(state),
                         "--python", sys.executable, *argv])


def test_prearm_is_strict_about_a_test_that_did_not_run(tmp_path, capsys):
    root = _repo(tmp_path, {"tests/test_skips.py": SKIPS})
    assert gate.run(_parse(root, tmp_path / "st", "prearm", "--no-idle-lock")) == 1
    out = capsys.readouterr().out
    assert "gate: not-run: strict, accepted kinds: none" in out
    assert "NOTRUN" in out and "tests/test_skips.py" in out
    assert "notrun=1" in out


def test_prearm_passes_when_every_test_ran(tmp_path, capsys):
    root = _repo(tmp_path, {})
    assert gate.run(_parse(root, tmp_path / "st", "prearm", "--no-idle-lock")) == 0
    assert "notrun=0" in capsys.readouterr().out


def test_prearm_takes_the_idle_lock_flags_run_takes(tmp_path):
    root = tmp_path
    on = _parse(root, tmp_path / "st", "prearm", "--idle-lock", "--idle-timeout", "5")
    assert on.idle_lock is True and on.idle_timeout == 5.0
    assert _parse(root, tmp_path / "st", "prearm", "--no-idle-lock").idle_lock is False
    assert _parse(root, tmp_path / "st", "prearm").idle_lock is None      # neither: $CTF_IDLE_LOCK decides
