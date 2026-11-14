"""Where engines live and the sys.path they run with.

The carried engines import their siblings flat (`import network`), so every lane folder is on
sys.path. The precedence below matches the root conftest.py (its inserts put the last-listed folder
first), so `ctf run`, `ctfpy` and the test suite resolve a flat import to the same file. A lane added
later is appended after the known ones.
"""
from __future__ import annotations

import re
from pathlib import Path

from .. import paths

# A module is an engine only if it has something to run or call: a public def/class or a
# `__main__` block. Data-only modules (lookup tables, packed blobs) are helpers.
_CALLABLE_RE = re.compile(r"(?m)^[ \t]*(?:async[ \t]+)?(?:def|class)[ \t]+[A-Za-z]|__main__")

# A day's complex-racer candidate, dNN_<role>_dev.py (B-258, `ctf scaffold racer`): work in progress
# in a lane folder, gitignored, and not an engine until promotion copies it to dNN.py with a manifest.
RACER_CANDIDATE_RE = re.compile(r"d\d{2,3}_[a-z][a-z0-9]{0,15}_dev\.py")

# Highest precedence first. Mirrors conftest.py (minus tests/).
LANE_PRECEDENCE = ("web", "warmups", "script-analysis", "mobile-android", "metadata-forensics",
                   "binary", "toolkits", "common")


def lanes(root: Path | None = None) -> list[str]:
    root = paths.repo_root() if root is None else Path(root)
    base = root / "solvers"
    if not base.is_dir():
        return []
    present = {d.name for d in base.iterdir() if d.is_dir() and not d.name.startswith((".", "_"))}
    known = [n for n in LANE_PRECEDENCE if n in present]
    return known + sorted(present - set(known))


def is_engine_module(p: Path) -> bool:
    n = p.name
    if p.suffix != ".py" or n.startswith(("_", "test_")) or n == "conftest.py":
        return False
    if RACER_CANDIDATE_RE.fullmatch(n):
        return False
    return bool(_CALLABLE_RE.search(p.read_text(encoding="utf-8", errors="replace")))


def engine_modules(root: Path | None = None) -> list[Path]:
    """Every module that must carry a manifest: the top-level .py files of each solvers/<lane>/.

    Sub-folders (data tables, schema packs), `_`/`test_` files and data-only modules (no public
    def/class, no `__main__` block) are helpers, not engines."""
    root = paths.repo_root() if root is None else Path(root)
    out = []
    for lane in lanes(root):
        out.extend(p for p in sorted((root / "solvers" / lane).glob("*.py")) if is_engine_module(p))
    return out


def sys_path(root: Path | None = None) -> list[str]:
    """The import path for an engine run, highest precedence first: tools/, the lanes, the repo root."""
    root = paths.repo_root() if root is None else Path(root)
    out = [str(root / "tools")] if (root / "tools").is_dir() else []
    out += [str(root / "solvers" / lane) for lane in lanes(root)]
    out.append(str(root))
    return out


def flat_owner(basename: str, root: Path | None = None) -> Path | None:
    """The file a flat `import <basename>` resolves to on the engine sys.path (first hit wins)."""
    for d in sys_path(root):
        cand = Path(d) / f"{basename}.py"
        if cand.is_file():
            return cand
    return None
