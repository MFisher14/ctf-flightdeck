"""B-196: the real side of every CTF_TESTING branch the fake-branch audit found without a non-fake test.

The suite runs with CTF_TESTING=1 (root conftest), so before these tests every branch below was only
ever exercised on its test-double side. Each test turns the flag OFF (and PYTEST_CURRENT_TEST where the
code reads it), drives the real path with harmless synthetic inputs, and checks the opposite outcome
with the flag ON, so the test fails if the branch is inverted, removed or made unconditional. Nothing
here contacts a platform, starts docker or installs anything: the programs are scripts this test writes.
"""
from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

import evidence      # solvers/binary (root conftest sys.path)
import labels        # solvers/common
import plan_codec    # solvers/script-analysis
from ctf import config as _config
from ctf import doctor, event, toolbox
from ctf.toolchain import images


def _script(path: Path, body: str) -> Path:
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def _ctfd_profile():
    import datetime as dt
    return event.parse({
        "slug": "fakebranch", "name": "Fake branch demo", "categories": ["Web"],
        "dates": {"start": dt.date(2030, 3, 1), "end": dt.date(2030, 3, 3)},
        "platform": {"kind": "ctfd", "base_url": "https://board.fakebranch.test/"},
        "flag": {"prefixes": ["DEMO"]},
        "rules": {"submit_mode": "auto", "flag_sharing": "allowed", "ai_on_platform": "allowed"},
    })


# ------------------------------------------------------------------------------------- ctf/doctor.py

def test_check_token_off_test_takes_the_real_config_path(monkeypatch):
    """With neither CTF_TESTING nor a running pytest, check_token goes to the real config load (here made
    to fail with a named error, so no platform is contacted); under test it skips before that."""
    def no_config():
        raise _config.ConfigError("synthetic: no config in this test")
    monkeypatch.setattr(_config, "load", no_config)
    monkeypatch.delenv("CTF_TESTING", raising=False)
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    real = doctor.check_token(_ctfd_profile(), environ={"PATH": os.defpath})
    assert (real.status, real.detail) == ("fail", "synthetic: no config in this test")


def test_check_token_under_test_skips_before_any_config(monkeypatch):
    def boom():
        raise AssertionError("config.load must not run under test")
    monkeypatch.setattr(_config, "load", boom)
    monkeypatch.setenv("CTF_TESTING", "1")
    skipped = doctor.check_token(_ctfd_profile(), environ={"PATH": os.defpath})
    assert skipped.status == "skip" and "under test" in skipped.detail


# ------------------------------------------------------------------------------------ ctf/toolbox.py

def test_apply_without_the_flag_runs_a_program_that_is_not_a_stub(tmp_path):
    """The real install path: a program with no stub marker runs (it writes a file) when the environ
    handed in has no CTF_TESTING; with the flag on, the same plan is refused before anything runs."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    out = tmp_path / "ran.txt"
    _script(bindir / "fakeinstall", f'echo "$@" > "{out}"\n')
    steps = [toolbox.Step("demo", ("fakeinstall", "--yes", "demo"))]
    res = toolbox.apply(steps, environ={"PATH": str(bindir)})
    assert [r.returncode for r in res] == [0]
    assert out.read_text().strip() == "--yes demo"
    out.unlink()
    with pytest.raises(toolbox.ToolboxError, match="refused under CTF_TESTING"):
        toolbox.apply(steps, environ={"PATH": str(bindir), "CTF_TESTING": "1"})
    assert not out.exists()


# ---------------------------------------------------------------------------- ctf/toolchain/images.py

def test_docker_path_without_the_flag_returns_a_docker_that_is_not_a_stub(tmp_path, monkeypatch):
    """Off test, the docker on PATH is returned whatever it is (nothing is run); under CTF_TESTING the
    same non-stub docker is refused."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    docker = _script(bindir / "docker", "exit 0\n")
    monkeypatch.delenv("CTF_TESTING", raising=False)
    assert images.docker_path({"PATH": str(bindir)}) == str(docker)
    with pytest.raises(images.ImagesError, match="not a test stub"):
        images.docker_path({"PATH": str(bindir), "CTF_TESTING": "1"})


# ------------------------------------------------- CTF_HIDE / CTF_LEDGER_MASK rehearsal knobs (solvers)

def test_the_lane_modules_are_the_ones_audited():
    assert Path(evidence.__file__).as_posix().endswith("solvers/binary/evidence.py")
    assert Path(plan_codec.__file__).as_posix().endswith("solvers/script-analysis/plan_codec.py")
    assert Path(labels.__file__).as_posix().endswith("solvers/common/labels.py")


def test_binary_hidden_is_inert_without_the_flag(monkeypatch):
    monkeypatch.setenv("CTF_HIDE", "d04, D07")
    monkeypatch.delenv("CTF_TESTING", raising=False)
    assert evidence.hidden() == set()
    monkeypatch.setenv("CTF_TESTING", "1")
    assert evidence.hidden() == {"d04", "d07"}


def test_script_analysis_hidden_is_inert_without_the_flag(monkeypatch):
    monkeypatch.setenv("CTF_HIDE", "vbscript,Census")
    monkeypatch.delenv("CTF_TESTING", raising=False)
    assert plan_codec.hidden() == set()
    monkeypatch.setenv("CTF_TESTING", "1")
    assert plan_codec.hidden() == {"vbscript", "census"}


def test_ledger_mask_is_inert_without_the_flag(monkeypatch):
    monkeypatch.setenv("CTF_LEDGER_MASK", "mobile.codec/*, Binary.D04/x")
    monkeypatch.delenv("CTF_TESTING", raising=False)
    assert labels._mask() == []
    monkeypatch.setenv("CTF_TESTING", "1")
    assert labels._mask() == ["mobile.codec/*", "binary.d04/x"]

