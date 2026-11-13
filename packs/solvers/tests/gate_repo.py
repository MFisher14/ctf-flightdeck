"""Synthetic git checkouts for the regression-gate tests (B-195). Everything is written by the test: no real
challenge file, no network. The checkout has its own pytest.ini so a child pytest roots there."""
from __future__ import annotations

import subprocess
import textwrap
from pathlib import Path

GIT = ["git", "-c", "user.email=gate@test.invalid", "-c", "user.name=gate-test", "-c", "commit.gpgsign=false",
       "-c", "core.hooksPath=/dev/null", "-c", "init.defaultBranch=main"]

BASE_CONFIG = """\
version = 1
tests = ["tests/test_*.py"]
roots = ["", "lib"]
global = ["pytest.ini", "conftest.py", "gate.toml"]
inert = ["docs/**", "*.md"]
basename_max = 3
env = ["CTF_GATE_TEST_KNOB"]
no_warm = ["tests/test_never_warm*.py"]

[wall]
base_seconds = 120
max_scale = 4.0
{extra}
"""


def git(root: Path, *args: str) -> str:
    r = subprocess.run([*GIT, "-C", str(root), *args], capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)}: {r.stderr}")
    return r.stdout


def write(root: Path, files: dict) -> None:
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(text, bytes):
            p.write_bytes(text)
        else:
            p.write_text(textwrap.dedent(text), encoding="utf-8")


def make_repo(root: Path, files: dict, *, extra_config: str = "", commit: bool = True) -> Path:
    """A git checkout at `root` holding `files` plus pytest.ini and gate.toml, committed once."""
    root.mkdir(parents=True, exist_ok=True)
    base = {"pytest.ini": "[pytest]\ntestpaths = tests\n", "gate.toml": BASE_CONFIG.format(extra=extra_config)}
    base.update(files)
    write(root, base)
    git(root, "init", "-q")
    if commit:
        git(root, "add", "-A")
        git(root, "commit", "-q", "-m", "base")
    return root
