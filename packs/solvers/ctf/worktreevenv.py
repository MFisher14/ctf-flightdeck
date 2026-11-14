"""Link the shared master venv into a git worktree (B-187 remainder).

A fresh ``git worktree`` has no ``.venv`` of its own, so ``.venv/bin/python`` — what the build rules and
every carried playbook spell — fails there, and agents fell back to brittle absolute paths or the wrong
interpreter. There is no second environment to build: the master checkout's ``.venv`` already has the
pinned interpreter and every package. This links the worktree's ``.venv`` to it, so the worktree runs the
carried engines and the test suite exactly as the master checkout does, with no editable install.

The link is a symlink, which git sees as a file, so a ``.venv/`` (directory-only) ignore pattern does not
cover it. The repo root ignores ``.venv`` (no slash) for that reason, and :func:`link` checks with
``git check-ignore`` before it links: when no pattern covers ``.venv`` (an older branch, another repo) it
appends ``.venv`` to the repository's ``info/exclude``, so the link is never committed. A worktree that
already has a real ``.venv`` (its own environment) is never touched, even with ``force``; ``force`` only
replaces a symlink that points elsewhere.

The venv to link is chosen loudly — the explicit argument if given, else ``$CTF_VENV`` if set, else the
master checkout's ``.venv`` found through ``git --git-common-dir``. Only the first source that was given
is used: an unusable one is an error naming the source and the reason, never a silent move to the next.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path


class WorktreeVenvError(RuntimeError):
    """The venv to link could not be found, or the worktree's .venv is in the way."""


def _git_common_dir(worktree: Path) -> Path | None:
    """The shared ``.git`` directory for this checkout (the master's ``.git`` for a worktree), or None
    when ``worktree`` is not inside a git checkout."""
    try:
        out = subprocess.run(
            ["git", "-C", str(worktree), "rev-parse", "--path-format=absolute", "--git-common-dir"],
            capture_output=True, text=True, check=False)
    except FileNotFoundError:            # git is not installed
        return None
    line = out.stdout.strip()
    if out.returncode != 0 or not line:
        return None
    return Path(line)


def checkout_root(path: Path) -> Path | None:
    """The top level of the git checkout (master or worktree) that contains ``path``, or None when
    ``path`` is not inside a git working tree. ``ctf worktree-venv`` run from a subdirectory links the
    checkout root's ``.venv`` (where ``.venv/bin/python`` is spelled from), not ``<subdir>/.venv``."""
    try:
        out = subprocess.run(["git", "-C", str(path), "rev-parse", "--show-toplevel"],
                             capture_output=True, text=True, check=False)
    except FileNotFoundError:            # git is not installed
        return None
    line = out.stdout.strip()
    if out.returncode != 0 or not line:
        return None
    return Path(line)


def master_checkout(worktree: Path) -> Path | None:
    """The master checkout a worktree belongs to: the parent of the shared ``.git`` directory. For the
    master checkout itself this is the checkout; for a worktree of a bare repository it is the bare
    repository directory itself. None when not in a git checkout."""
    common = _git_common_dir(worktree)
    if common is None:
        return None
    # common is <master>/.git (a real dir) or, for a worktree of a bare repo, the bare repo dir.
    return common.parent if common.name == ".git" else common


def resolve_venv(worktree: Path, explicit: str | Path | None = None) -> Path:
    """Which venv to link: ``explicit`` if given, else ``$CTF_VENV`` if set, else the master checkout's
    ``.venv``. Only the first of these that was GIVEN is considered: a given venv that is unusable is an
    error, never a reason to move on to the next source, so a mistyped ``--venv`` cannot silently link a
    different environment. The result must hold an executable ``bin/python``. Raises WorktreeVenvError
    naming the source and the reason otherwise."""
    if explicit is not None:
        why, cand = "the --venv argument", Path(explicit)
    elif os.environ.get("CTF_VENV"):
        why, cand = "$CTF_VENV", Path(os.environ["CTF_VENV"])
    else:
        master = master_checkout(worktree)
        if master is None:
            raise WorktreeVenvError(
                f"{worktree} is not inside a git checkout and neither --venv nor $CTF_VENV was given: "
                "cannot find a venv to link")
        why, cand = f"the master checkout venv ({master}/.venv)", master / ".venv"
    cand = cand.resolve()
    py = cand / "bin" / "python"
    if not py.exists():
        raise WorktreeVenvError(f"no usable venv to link: {why}: {cand} has no bin/python")
    if not os.access(py, os.X_OK):
        raise WorktreeVenvError(f"no usable venv to link: {why}: {py} is not executable")
    return cand


def ensure_ignored(checkout: Path) -> str:
    """Make sure git ignores ``<checkout>/.venv`` as a symlink (git sees a file, so a ``.venv/`` pattern
    does not match it). Returns ``"ignored"`` when a pattern already covers it, ``"excluded"`` when this
    appended ``.venv`` to the repository's ``info/exclude``, or ``"not-git"`` outside a git checkout.
    Raises WorktreeVenvError when git cannot answer."""
    if _git_common_dir(checkout) is None:
        return "not-git"
    chk = subprocess.run(["git", "-C", str(checkout), "check-ignore", "-q", "--no-index", ".venv"],
                         capture_output=True, text=True, check=False)
    if chk.returncode == 0:
        return "ignored"
    if chk.returncode != 1:
        raise WorktreeVenvError(f"git check-ignore failed in {checkout}: {chk.stderr.strip()}")
    out = subprocess.run(["git", "-C", str(checkout), "rev-parse", "--path-format=absolute",
                          "--git-path", "info/exclude"], capture_output=True, text=True, check=False)
    if out.returncode != 0 or not out.stdout.strip():
        raise WorktreeVenvError(f"cannot find info/exclude for {checkout}: {out.stderr.strip()}")
    exclude = Path(out.stdout.strip())
    exclude.parent.mkdir(parents=True, exist_ok=True)
    with open(exclude, "a", encoding="utf-8") as fh:
        fh.write("\n# ctf worktree-venv (R-17): the .venv symlink\n.venv\n")
    return "excluded"


def link(worktree: str | Path, venv: str | Path | None = None, *, force: bool = False) -> tuple[str, Path]:
    """Link ``<worktree>/.venv`` to the resolved venv. Returns ``(action, target)`` where action is
    ``"linked"`` (created), ``"exists"`` (already the same link), ``"relinked"`` (``force`` replaced a
    link), or ``"is-master"`` (``<worktree>/.venv`` IS the venv to link: the master checkout itself,
    nothing to do, nothing touched). Refuses a differently-aimed link unless ``force`` and any other real
    ``.venv`` directory always. Before any link is made, kept or replaced, git is made to ignore
    ``.venv`` (:func:`ensure_ignored`)."""
    worktree = Path(worktree).resolve()
    if not worktree.is_dir():
        raise WorktreeVenvError(f"{worktree} is not a directory")
    target = resolve_venv(worktree, venv)
    dest = worktree / ".venv"

    if dest.is_symlink():
        current = Path(os.readlink(dest))
        if not current.is_absolute():
            current = (dest.parent / current)
        if current.resolve() == target:
            ensure_ignored(worktree)
            return "exists", target
        if not force:
            raise WorktreeVenvError(
                f"{dest} already links to {current} (not {target}); pass force to replace it")
        ensure_ignored(worktree)
        dest.unlink()
        dest.symlink_to(target, target_is_directory=True)
        return "relinked", target

    if dest.exists():
        if dest.resolve() == target:
            # The master checkout itself: its .venv is the master venv, already where it belongs.
            return "is-master", target
        # A real directory (the worktree built its own venv) — never silently clobbered.
        if not force:
            raise WorktreeVenvError(
                f"{dest} is a real directory, not a link; leaving it (remove it yourself first if you "
                f"want a link to {target})")
        raise WorktreeVenvError(
            f"{dest} is a real directory; refusing to delete a real venv even with force — remove it "
            "yourself first if you meant to")

    ensure_ignored(worktree)
    dest.symlink_to(target, target_is_directory=True)
    return "linked", target
