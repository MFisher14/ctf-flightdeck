"""R-12: the root writeups/ ignore rule is anchored, so docs/writeups/organizer/ is tracked.

The staging tree writeups/ at the checkout root holds unredacted writeups and must stay ignored at every
depth. The generic organizer tooling under docs/writeups/organizer/ must be tracked, or the brief and
assembler tests pass only in the checkout that happens to hold the untracked copies.
"""
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
ORGANIZER = ["BRIEF.md", "CHECKS.md", "EXPAND_BRIEF.md", "HEADER.md", "REPRO_BRIEF.md",
             "REVIEW_BRIEF.md", "VERIFY_BRIEF.md", "assemble.py"]

pytestmark = pytest.mark.needs_tool("git")


def _ignored(rel: str) -> bool:
    # --no-index: judge the path by the ignore rules alone, tracked or not, existing or not.
    r = subprocess.run(["git", "-C", str(ROOT), "check-ignore", "-q", "--no-index", rel],
                       capture_output=True, text=True)
    assert r.returncode in (0, 1), f"git check-ignore failed: {r.stderr.strip()}"
    return r.returncode == 0


@pytest.mark.parametrize("rel", [
    "writeups/2026-csctf/event.json",
    "writeups/2026-csctf/cards/1-alpha.md",
    "writeups/_public/some-repo/writeups/README.md",
])
def test_root_staging_tree_stays_ignored(rel):
    assert _ignored(rel), f"{rel} must stay ignored (unredacted staging)"


@pytest.mark.parametrize("rel", [f"docs/writeups/organizer/{n}" for n in ORGANIZER]
                         + ["tools/writeups/organizer/x.py"])
def test_nested_writeups_dirs_are_not_ignored(rel):
    assert not _ignored(rel), f"{rel} is hidden by an unanchored writeups/ rule"


@pytest.mark.parametrize("name", ORGANIZER)
def test_organizer_files_are_tracked(name):
    rel = f"docs/writeups/organizer/{name}"
    r = subprocess.run(["git", "-C", str(ROOT), "ls-files", "--error-unmatch", rel],
                       capture_output=True, text=True)
    assert r.returncode == 0, f"{rel} is not in the git index"
