"""The scripts under packaging/ that the release workflow runs: each is there, is valid shell,
and stops in one line when it is called wrongly. Building and installing the .deb needs Docker
and the network, so no test does it: the release workflow does (its deb job), and
CONTRIBUTING.md (Releases) has the two commands."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
DEB = REPO / "packaging" / "deb"
SCRIPTS = ("build-deb.sh", "build-in-docker.sh", "test-in-docker.sh")


def sh(script: str, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["sh", str(DEB / script), *args], capture_output=True, text=True, timeout=60)


@pytest.mark.parametrize("script", SCRIPTS)
def test_each_script_is_valid_shell_and_executable(script):
    checked = subprocess.run(["sh", "-n", str(DEB / script)], capture_output=True, text=True, timeout=60)
    assert (checked.returncode, checked.stderr) == (0, "")
    assert os.access(DEB / script, os.X_OK)


@pytest.mark.parametrize("script, usage", [
    ("build-deb.sh", "build-deb: usage: build-deb.sh WHEEL REQUIREMENTS OUT_DIR\n"),
    ("build-in-docker.sh", "build-in-docker: usage: build-in-docker.sh WHEEL OUT_DIR\n"),
    ("test-in-docker.sh", "test-in-docker: usage: test-in-docker.sh DEB VERSION\n"),
])
def test_called_without_its_arguments_a_script_says_its_usage_and_fails(script, usage):
    done = sh(script)
    assert (done.returncode, done.stdout, done.stderr) == (1, "", usage)


def test_a_wheel_or_package_that_is_not_there_is_named_before_anything_starts(tmp_path):
    wheel = tmp_path / "ctf_flightdeck-9.9.9-py3-none-any.whl"
    build = sh("build-in-docker.sh", str(wheel), str(tmp_path / "out"))
    assert (build.returncode, build.stdout, build.stderr) == (1, "", f"build-in-docker: no wheel at {wheel}\n")
    assert not (tmp_path / "out").exists()
    deb = tmp_path / "ctf-flightdeck_9.9.9_amd64.deb"
    test = sh("test-in-docker.sh", str(deb), "9.9.9")
    assert (test.returncode, test.stdout, test.stderr) == (1, "", f"test-in-docker: no package at {deb}\n")


def test_the_release_workflow_runs_scripts_that_exist():
    workflow = (REPO / ".github" / "workflows" / "release.yml").read_text()
    for path in ("packaging/deb/build-in-docker.sh", "packaging/deb/test-in-docker.sh", "packaging/homebrew/render_formula.py"):
        assert path in workflow and (REPO / path).is_file()
    assert "/src/packaging/deb/build-deb.sh" in (DEB / "build-in-docker.sh").read_text()  # the one the container runs
    assert (REPO / "packaging" / "homebrew" / "ctf-flightdeck.rb.in").is_file()
