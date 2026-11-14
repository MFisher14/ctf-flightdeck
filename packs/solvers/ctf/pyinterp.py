"""Which Python a test run's children use, in a main checkout or a linked worktree (B-153).

Build runs failed on "linked-worktree venv assumptions": a fresh `git worktree` has no `.venv` of its
own, so a recipe written as `.venv/bin/python -m pytest` broke there, and a gate started with the
system Python ran its pytest children without the repo's plugins. `tools/ctfpy` already solved this in
shell; this is the same order for Python callers (`tools/suite.py` and the gate's pytest children):

    1. $CTF_PYTHON                       when set it must be an executable file, else PythonError
                                         names it (never a fall-through to the next source)
    2. <checkout>/.venv/bin/python       the checkout being run
    3. <main checkout>/.venv/bin/python  the checkout that owns the git common dir (a worktree's
                                         parent repo), found by reading .git files, not by running git
    4. the running interpreter           only when none of the above exists; the source says so, and
                                         every caller prints it, so the choice is never silent

`resolve(root)` returns an `Interpreter(path, source)`; callers print `source` with the path.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from . import env

PYTHON_VAR = "CTF_PYTHON"
VENV_PYTHON = Path(".venv") / "bin" / "python"


class PythonError(RuntimeError):
    """A named interpreter source is set but unusable."""


@dataclass(frozen=True)
class Interpreter:
    path: str
    source: str     # why this one: "$CTF_PYTHON", "<checkout>/.venv", "main checkout .venv", "running ..."

    def describe(self) -> str:
        return f"{self.path} ({self.source})"


def _executable(p: Path) -> bool:
    return p.is_file() and os.access(p, os.X_OK)


def git_common_dir(root: Path) -> Path | None:
    """The git common dir of the checkout at `root` (its own .git for a main checkout, the parent
    repo's .git for a linked worktree), read from the .git file/folder; None when there is none."""
    dotgit = Path(root) / ".git"
    if dotgit.is_dir():
        return dotgit.resolve()
    if not dotgit.is_file():
        return None
    try:
        text = dotgit.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if not text.startswith("gitdir:"):
        return None
    gitdir = Path(text[len("gitdir:"):].strip())
    gitdir = gitdir if gitdir.is_absolute() else (Path(root) / gitdir)
    common = gitdir / "commondir"
    if common.is_file():
        try:
            c = Path(common.read_text(encoding="utf-8").strip())
        except OSError:
            return None
        return (c if c.is_absolute() else gitdir / c).resolve()
    return gitdir.resolve()


def main_checkout(root: Path) -> Path | None:
    """The working tree that owns `root`'s git common dir (`root` itself in a main checkout), or None
    when the common dir is not a `.git` folder inside a working tree (a bare repo, no git at all)."""
    common = git_common_dir(root)
    if common is None or common.name != ".git":
        return None
    return common.parent


def resolve(root: Path, *, environ: Mapping[str, str] | None = None,
            running: str | None = None) -> Interpreter:
    """The interpreter for test children of the checkout at `root` (order in the module docstring).
    Raises PythonError when $CTF_PYTHON is set but is not an executable file."""
    root = Path(root).resolve()
    from_env = env.get(PYTHON_VAR, environ=environ)
    if from_env:
        if not _executable(Path(from_env)):
            raise PythonError(f"${PYTHON_VAR}={from_env} is not an executable interpreter "
                              f"(unset it to use the checkout's .venv)")
        return Interpreter(from_env, f"${PYTHON_VAR}")
    own = root / VENV_PYTHON
    if _executable(own):
        return Interpreter(str(own), "the checkout's .venv")
    main = main_checkout(root)
    if main is not None and main.resolve() != root:
        shared = main / VENV_PYTHON
        if _executable(shared):
            return Interpreter(str(shared), f"the main checkout's .venv ({main}); this worktree has none")
    running = running if running is not None else sys.executable
    if not running:
        raise PythonError(f"no interpreter: {own} is missing, no main-checkout .venv was found, and "
                          f"the running interpreter is unknown; set ${PYTHON_VAR}")
    where = f"no .venv in {root}" + (f" or its main checkout {main}" if main is not None and main.resolve() != root
                                     else "")
    return Interpreter(running, f"the running interpreter: {where}")
