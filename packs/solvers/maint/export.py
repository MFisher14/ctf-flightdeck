#!/usr/bin/env python3
"""Export the public tree of this pack from the maintainer's private master checkout.

    python3 packs/solvers/maint/export.py ~/ctf-tools            # copy the listed paths of the master's HEAD here
    python3 packs/solvers/maint/export.py ~/ctf-tools --check    # only say what would change

Reads the master through `git archive HEAD` (tracked files of the last commit only, so no
untracked notes, tokens or runtime state can come along) and never writes to it. What is
exported is the INCLUDE list below; everything else in the master stays private. Files this
pack owns (OWNED) are never overwritten or removed. An export then applies maint/patches/*.patch,
the pack's few changes to the master's files; flightdeck's commit guard scans what is committed.
"""
from __future__ import annotations

import argparse
import io
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent

# Paths of the master that are public. A folder ends with "/".
INCLUDE = (
    "ctf/", "solvers/", "tools/", "openers/", "docker/", "templates/", "speedrun/", "tests/",
    "conftest.py", "pytest.ini", "requirements.in", "requirements.txt", "requirements.lock.txt",
    "Brewfile", ".githooks/",        # the master's commit guard: its own tests read it (flightdeck's guard is the active one)
    "events/csctf/event.toml", "events/huntress/event.toml", "events/pink/event.toml",
    "events/spooky/event.toml",
    "docs/CONTRACTS.md", "docs/CAPABILITIES.md", "docs/BUILDING.md", "docs/PRIMER.md",
    "docs/OPERATIONS.md", "docs/fence.md", "docs/keysearch.md", "docs/warmups-formats.md",
    "docs/capabilities-carried.md", "docs/coverage-2024.md", "docs/coverage-2025.md",
    "docs/build-sandbox.md", "docs/writeup-pipeline.md",
    "docs/toolkits/", "docs/playbooks/", "docs/coverage/", "docs/examples/", "docs/runbooks/",
)
# Files under an included folder that stay private: tests of what is not exported, which name
# people or teams (flightdeck's commit guard refuses them).
EXCLUDE = (
    "tests/test_legacy_workflows_hm05.py",      # the events' legacy agent workflows (not exported)
    "tests/test_writeup_organizer_briefs.py",   # the organizer-brief writeup tooling's real examples
    "tests/test_writeup_organizer_assemble.py", # the same tooling (docs/writeups/organizer is not exported)
)
# Top-level names this repo owns: an export never touches them.
OWNED = ("maint", "flightdeck", "README.md", "pack.toml", "setup.sh", ".gitignore", ".dockerignore", ".venv",
         "EXPORT.md")
# Top-level names an export manages: removed first, so a file deleted in the master goes here too.
MANAGED = ("ctf", "solvers", "tools", "openers", "docker", "templates", "speedrun", "tests", "events",
           "docs", ".githooks", "conftest.py", "pytest.ini", "requirements.in", "requirements.txt",
           "requirements.lock.txt", "Brewfile")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("master", type=Path)
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    master = args.master.expanduser().resolve()
    if not (master / ".git").exists():
        sys.exit(f"{master} is not a git checkout")
    dirty = subprocess.run(["git", "-C", str(master), "status", "--porcelain", "--untracked-files=no"],
                           capture_output=True, text=True, check=True).stdout.strip()
    if dirty:
        print("note: the master has uncommitted changes; only its last commit is exported", file=sys.stderr)
    head = subprocess.run(["git", "-C", str(master), "rev-parse", "HEAD"], capture_output=True, text=True,
                          check=True).stdout.strip()
    paths = [p.rstrip("/") for p in INCLUDE]
    blob = subprocess.run(["git", "-C", str(master), "archive", "--format=tar", "HEAD", "--", *paths],
                          capture_output=True, check=True).stdout
    tar = tarfile.open(fileobj=io.BytesIO(blob))
    members = [m for m in tar.getmembers() if (m.isfile() or m.isdir() or m.issym()) and m.name not in EXCLUDE]
    for m in members:
        top = m.name.split("/", 1)[0]
        if top in OWNED or top not in MANAGED:
            sys.exit(f"refusing {m.name}: {top} is not a managed path")
    files = sum(1 for m in members if not m.isdir())
    if args.check:
        print(f"would export {files} files of {head[:12]}")
        return 0
    for name in MANAGED:
        target = HERE / name
        if target.is_dir() and not target.is_symlink():
            shutil.rmtree(target)
        elif target.exists() or target.is_symlink():
            target.unlink()
    tar.extractall(HERE, members=members, filter="data")
    for patch in sorted((HERE / "maint" / "patches").glob("*.patch")):
        subprocess.run(["patch", "-p1", "--quiet", "-i", str(patch)], cwd=HERE, check=True)
    (HERE / "EXPORT.md").write_text(
        "# Export record\n\nThis tree was exported by `maint/export.py` from the maintainer's master.\n\n"
        f"- master commit: `{head}`\n- files: {files}\n")
    print(f"exported {files} files of {head[:12]} into {HERE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
