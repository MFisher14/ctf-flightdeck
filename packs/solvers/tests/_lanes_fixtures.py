"""Synthetic fixtures for the B-179 lane tests: a throwaway source repo, a fake venv and a stub
`codex` executable. Nothing here starts a real Codex session or touches ~/.codex."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

CAPS = textwrap.dedent("""\
    # capability map

    Intro text.

    ## Crypto
    - RSA things (`rsa_old`)
    - Lattice things (`lattice_tool.py`)

    ## Misc
    - Sanity (`sanity`)
    """)

EXISTING_ENGINE = 'def solve(challenge_dir, profile, **opts):\n    return None\n'
EXISTING_MANIFEST = textwrap.dedent("""\
    id = "crypto.existing"
    lane = "crypto"
    entry = "solvers.crypto.existing:solve"
    status = "active"
    [[routes]]
    category = ["crypto"]
    keywords = ["existingword"]
    priority = 50
    """)


def manifest(eid: str, base: str, keyword: str | None = "uniqueword", priority: int | None = 50) -> str:
    lane = eid.split(".")[0]
    out = f'id = "{eid}"\nlane = "{lane}"\nentry = "solvers.{lane}.{base}:solve"\nstatus = "active"\n'
    if keyword is not None:
        out += f'[[routes]]\ncategory = ["crypto"]\nkeywords = ["{keyword}"]\n'
        if priority is not None:
            out += f"priority = {priority}\n"
    return out


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True,
                          text=True).stdout.strip()


@pytest.fixture
def git_env(tmp_path, monkeypatch):
    """Isolate git from the user's config: a fixed identity, no hooks, no signing."""
    cfg = tmp_path / "gitconfig"
    cfg.write_text("[user]\n\tname = Lane Test\n\temail = lane@test.invalid\n"
                   "[init]\n\tdefaultBranch = main\n[commit]\n\tgpgsign = false\n")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(cfg))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    return cfg


@pytest.fixture
def src_repo(tmp_path, git_env):
    repo = tmp_path / "src"
    (repo / "docs").mkdir(parents=True)
    (repo / "solvers" / "crypto").mkdir(parents=True)
    (repo / "docs" / "CAPABILITIES.md").write_text(CAPS)
    (repo / "docs" / "CONTRACTS.md").write_text("contracts\n")
    (repo / "docs" / "BUILDING.md").write_text("building\n")
    (repo / "AGENTS.md").write_text("agents\n")
    (repo / "solvers" / "crypto" / "existing.py").write_text(EXISTING_ENGINE)
    (repo / "solvers" / "crypto" / "existing.manifest.toml").write_text(EXISTING_MANIFEST)
    (repo / ".gitignore").write_text(".venv/\n")
    git(repo, "init", "-q")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "base")
    return repo


@pytest.fixture
def fake_venv(tmp_path):
    v = tmp_path / "venv"
    (v / "bin").mkdir(parents=True)
    py = v / "bin" / "python"
    py.write_text("#!/bin/sh\nexit 0\n")
    py.chmod(0o755)
    return v


STUB = r'''#!{python} -I
"""Stub codex for the B-179 tests. Reads its behaviour from $LANE_STUB_DIR/<lane>.json."""
import json, os, re, subprocess, sys, time
argv = sys.argv[1:]
d = os.environ["LANE_STUB_DIR"]
prompt = argv[-1]
lane = re.search(r"^# Lane ([a-z0-9-]+):", prompt, re.M).group(1)
result = re.search(r"Write the result manifest to (\S+) as JSON", prompt).group(1)
cwd = argv[argv.index("-C") + 1]
last = argv[argv.index("-o") + 1]
spec = {{}}
p = os.path.join(d, lane + ".json")
if os.path.exists(p):
    spec = json.load(open(p))
rec = {{"lane": lane, "argv": argv[:-1], "start": time.time(), "cwd_files": sorted(os.listdir(cwd)),
       "has_token": "CTF_TOKEN" in os.environ, "has_cookie": "CTF_COOKIE" in os.environ}}
time.sleep(spec.get("sleep", 0))
for rel, text in spec.get("files", {{}}).items():
    f = os.path.join(cwd, rel)
    os.makedirs(os.path.dirname(f), exist_ok=True)
    open(f, "w").write(text)
sha = None
if spec.get("files") and spec.get("commit", True):
    subprocess.run(["git", "-C", cwd, "add", "-A"], check=True)
    subprocess.run(["git", "-C", cwd, "commit", "-q", "-m", lane + ": work"], check=True)
    sha = subprocess.run(["git", "-C", cwd, "rev-parse", "HEAD"], check=True, capture_output=True,
                         text=True).stdout.strip()
res = spec.get("result", "default")
if res == "default":
    res = {{"schema": 1, "lane": lane, "status": "built", "summary": "stub built " + lane}}
if res is not None:
    res = dict(res)
    if sha and "commit" not in res:
        res["commit"] = sha
    open(result, "w").write(json.dumps(res))
open(last, "w").write("LANE DONE " + lane)
rec["end"] = time.time()
open(os.path.join(d, "calls.jsonl"), "a").write(json.dumps(rec) + "\n")
sys.exit(spec.get("exit", 0))
'''


@pytest.fixture
def stub_codex(tmp_path, monkeypatch):
    """A `codex` on PATH that does what $LANE_STUB_DIR/<lane>.json says. Returns the stub dir;
    calls(stub) lists its invocations."""
    bindir = tmp_path / "stubbin"
    bindir.mkdir()
    exe = bindir / "codex"
    exe.write_text(STUB.format(python=sys.executable))
    exe.chmod(0o755)
    sd = tmp_path / "stubdir"
    sd.mkdir()
    monkeypatch.setenv("LANE_STUB_DIR", str(sd))
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.delenv("CODEX_BIN", raising=False)
    return sd


def behave(stub_dir: Path, lane: str, **spec) -> None:
    (stub_dir / f"{lane}.json").write_text(json.dumps(spec))


def calls(stub_dir: Path) -> list[dict]:
    f = stub_dir / "calls.jsonl"
    return [json.loads(x) for x in f.read_text().splitlines()] if f.exists() else []
