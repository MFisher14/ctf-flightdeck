"""Small host-path helpers shared by executable test entrypoints.

Tests are intentionally runnable from a linked Git worktree.  Those worktrees
do not duplicate the (large, host-specific) virtual environment; they borrow
the main checkout's ``.venv`` exactly as the production bootstrap code does.
"""

from __future__ import annotations

import subprocess
from pathlib import Path


def repository_python(root: Path) -> Path:
    """Return the executable venv Python for *root* or its main checkout."""

    direct = root / ".venv" / "bin" / "python"
    if direct.is_file():
        return direct
    try:
        common_text = subprocess.run(
            ["git", "rev-parse", "--git-common-dir"],
            cwd=root,
            text=True,
            capture_output=True,
            check=True,
            timeout=5,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return direct
    common = Path(common_text)
    if not common.is_absolute():
        common = (root / common).resolve()
    borrowed = common.parent / ".venv" / "bin" / "python"
    return borrowed if borrowed.is_file() else direct
