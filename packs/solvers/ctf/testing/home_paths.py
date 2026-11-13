"""Find hardcoded home and source-repo paths in the repo's files (R-05).

The master runs on any machine and any checkout: code and tests resolve the per-event workdir and
the corpora through ctf.paths (and ctf.env), and the playbooks run from the checkout root with
`.venv/bin/python` and `python -m ctf ...`. So no file in the repo names a user's home folder or one
of the four 2026 source repos by path. Two shapes are refused:

    home      /Users/<name>, whatever follows the name (/, a quote, a space, : ) , ; ] or the end of
              the line): someone's home folder. <name> is a literal name: /Users/<name>, /Users/$USER
              and /Users/... are placeholders. /Users/Shared and C:/Users/Public are system folders,
              not homes, and are allowed.
    source    a home-relative source-repo path: tilde (or $HOME, ${HOME}) + /2026-ctf-<event>, or the
              Python spelling Path.home() / "2026-ctf-..." (or HOME / '2026-ctf-...').

Allowed, each for a stated reason (and nothing else):

    EXEMPT_PREFIXES   docs/migration/ records how the tree was imported from the source repos.
    EXEMPT_FILES      this scanner and its test, which have to spell the patterns out.
    ALLOWANCES        one exact text in one file: ctf/paths.py's documented realdata default (and the
                      contract test that pins it), and the root agent instructions (CLAUDE.md,
                      AGENTS.md) that name the read-only source repos.
                      An allowance covers only a match inside that exact text, so a new path added to
                      the same file still fails; an allowance that no longer matches anything is stale
                      and fails too (tests/test_no_home_paths.py).

    .venv/bin/python -m ctf.testing.home_paths      # list every finding; exit 1 when there is one
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

# The name runs to the first character a path component cannot hold in prose or code (/, space, quote,
# bracket, : , ; and the like); whatever follows it, the match is a home folder.
HOME_RX = re.compile(r"/Users/(?P<name>[A-Za-z0-9_][^/\s'\"`<>(){}\[\],;:*?$|\\]*)")
SOURCE_RX = re.compile(r"(?:~|\$HOME|\$\{HOME\})/2026-ctf-"
                       r"|(?:Path\.home\(\)|\bHOME\b)\s*/\s*[\"']2026-ctf-")

SYSTEM_USER_DIRS = frozenset({"Shared", "Public"})   # /Users/Shared (macOS), C:/Users/Public (Windows)

EXEMPT_PREFIXES = ("docs/migration/",)
EXEMPT_FILES = frozenset({"ctf/testing/home_paths.py", "tests/test_no_home_paths.py"})


@dataclass(frozen=True)
class Allowance:
    path: str      # repo-relative file
    text: str      # the exact text a match must lie inside
    reason: str


ALLOWANCES: tuple[Allowance, ...] = (
    Allowance("ctf/paths.py", "~/2026-ctf-huntress/challenges/_realdata",
              "the documented default of paths.realdata_root() ($CTF_REALDATA overrides it)"),
    Allowance("tests/test_contracts_env_paths.py", 'Path.home() / "2026-ctf-huntress/challenges/_realdata"',
              "the contract test pins paths.realdata_root()'s documented default independently of paths.py"),
    Allowance("CLAUDE.md", "`~/2026-ctf-*`",
              "the root agent rules name the read-only source repos; changed only by Max"),
    Allowance("AGENTS.md", "`~/2026-ctf-*`",
              "the root agent rules (Codex copy of CLAUDE.md) name the read-only source repos"),
)


@dataclass(frozen=True)
class Hit:
    path: str
    line: int
    kind: str        # "home" | "source"
    match: str
    text: str        # the whole line, stripped and cut to 200 chars
    allowance: Allowance | None = None

    def __str__(self) -> str:
        return f"{self.path}:{self.line}: {self.kind} path {self.match!r}: {self.text}"


def _allowance_for(path: str, line: str, start: int, end: int,
                   allowances: tuple[Allowance, ...]) -> Allowance | None:
    for a in allowances:
        if a.path != path:
            continue
        i = line.find(a.text)
        while i != -1:
            if i <= start and end <= i + len(a.text):
                return a
            i = line.find(a.text, i + 1)
    return None


def scan_text(path: str, text: str, allowances: tuple[Allowance, ...] | None = None) -> list[Hit]:
    """Every home / source path in `text` (the content of repo file `path`), allowed ones marked.
    `allowances` defaults to ALLOWANCES as it is at call time."""
    allowances = ALLOWANCES if allowances is None else allowances
    hits = []
    for n, line in enumerate(text.splitlines(), 1):
        found = []
        for m in HOME_RX.finditer(line):
            if m.group("name") not in SYSTEM_USER_DIRS:
                found.append(("home", m.start(), m.end(), m.group(0)))
        for m in SOURCE_RX.finditer(line):
            found.append(("source", m.start(), m.end(), m.group(0)))
        for kind, s, e, frag in sorted(found, key=lambda f: f[1]):
            hits.append(Hit(path, n, kind, frag, line.strip()[:200],
                            _allowance_for(path, line, s, e, allowances)))
    return hits


def exempt(path: str) -> bool:
    return path in EXEMPT_FILES or path.startswith(EXEMPT_PREFIXES)


def repo_files(root: Path) -> list[str]:
    """Tracked files plus untracked, not-ignored ones (so a file is caught before its first commit).
    No git, or not a git checkout: RuntimeError naming why (never an empty list)."""
    # A hook or wrapper's GIT_DIR / GIT_INDEX_FILE would point git at another repository than `root`.
    env = {k: v for k, v in os.environ.items() if k not in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE")}
    try:
        p = subprocess.run(["git", "-C", str(root), "ls-files", "-z", "--cached", "--others",
                            "--exclude-standard"], capture_output=True, check=False, timeout=120, env=env)
    except FileNotFoundError as e:
        raise RuntimeError("git is not on PATH: cannot list the repo's files to scan") from e
    if p.returncode != 0:
        raise RuntimeError(f"git ls-files failed in {root}: {p.stderr.decode(errors='replace').strip()}")
    names = sorted({n for n in p.stdout.decode("utf-8", "surrogateescape").split("\0") if n})
    if not names:
        raise RuntimeError(f"git ls-files listed no files in {root}")
    return names


def read_for_scan(root: Path, rel: str) -> str | None:
    """A file's bytes as text (latin-1, so binaries are scanned too); a symlink's target, not what it
    points at; None for a tracked file deleted from the working tree."""
    p = root / rel
    try:
        if p.is_symlink():
            return os.readlink(p)
        return p.read_bytes().decode("latin-1")
    except FileNotFoundError:
        return None


def scan_repo(root: Path, allowances: tuple[Allowance, ...] | None = None) -> list[Hit]:
    """Every hit in every non-exempt repo file, allowed ones included (marked)."""
    allowances = ALLOWANCES if allowances is None else allowances
    hits = []
    for rel in repo_files(root):
        if exempt(rel):
            continue
        text = read_for_scan(root, rel)
        if text is not None:
            hits += scan_text(rel, text, allowances)
    return hits


def violations(hits: list[Hit]) -> list[Hit]:
    return [h for h in hits if h.allowance is None]


def stale_allowances(hits: list[Hit], allowances: tuple[Allowance, ...] | None = None) -> list[Allowance]:
    allowances = ALLOWANCES if allowances is None else allowances
    used = {h.allowance for h in hits if h.allowance is not None}
    return [a for a in allowances if a not in used]


def main(argv: list[str] | None = None) -> int:
    from ctf import paths
    root = paths.repo_root()
    hits = scan_repo(root)
    bad, stale = violations(hits), stale_allowances(hits)
    for h in bad:
        print(h)
    for a in stale:
        print(f"stale allowance: {a.path} no longer contains {a.text!r} ({a.reason})")
    if bad or stale:
        print(f"{len(bad)} hardcoded home/source path(s), {len(stale)} stale allowance(s): resolve "
              f"locations through ctf.paths / ctf.env (docs/CONTRACTS.md)", file=sys.stderr)
        return 1
    print(f"no hardcoded home or source-repo paths ({len(hits)} allowed)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
