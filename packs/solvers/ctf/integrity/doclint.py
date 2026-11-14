"""Doc lint (B-196): the maintained docs name only things that exist.

At CSCTF the de-branding sweep of the docs ran in the fork workflow and again overnight (39 docs still
named a deleted `tools/verify.py`), and CAPABILITIES was re-reviewed by hand several times. This lint
makes the sweep a check. Static: nothing is imported but `ctf.cli` (to list the commands). Rules:

    path      a backticked repo path (`` `tools/verify.py` ``, `` `ctf/gate/` ``, `` `x.py:12` ``) whose first
              segment is a top-level folder of the checkout must exist (file or folder). Spans with
              spaces, globs (* ? [ {), placeholders (< > $ ~) or `...` are not paths and are skipped.
    link      a relative Markdown link `[text](path)` must resolve from the doc's folder (anchors and
              URLs are skipped)
    command   `python -m ctf <cmd>` must name a command `ctf` has

Which docs: ROOT_DOCS and the DOCS globs below, the maintained docs. Historic records (docs/build-log/**, docs/migration/**,
docs/retro/**, docs/writeups/**) describe the tree as it was and are not linted. A doc may opt a line
out with `<!-- doclint: skip -->` on that line (for a deliberate reference to a removed file).

    lint(root) -> list[Finding]
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from . import IntegrityError
from ..gate.config import matches

ROOT_DOCS = ("README.md", "CLAUDE.md", "AGENTS.md", "BUILD-PLAN.md")
DOCS = ("docs/*.md", "docs/playbooks/**/*.md", "docs/toolkits/**/*.md", "docs/runbooks/**/*.md",
        "docs/coverage/**/*.md", "docs/examples/**/*.md")
NOT_LINTED = ("docs/build-log/**", "docs/migration/**", "docs/retro/**", "docs/writeups/**")
SKIP_MARK = "doclint: skip"

_SPAN = re.compile(r"`([^`\n]+)`")
_LINK = re.compile(r"\[[^\]\n]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
_CMD = re.compile(r"python3?\s+-m\s+ctf\s+([a-z][a-z0-9_-]*)")
_NOT_PATH = re.compile(r"[\s*?\[\]{}<>$~|,;=()'\"]|\.\.\.")
_LOC = re.compile(r"(?::\d+(?:-\d+)?|::[A-Za-z_][\w.]*)$")


@dataclass(frozen=True)
class Finding:
    doc: str
    line: int
    rule: str
    ref: str

    def text(self) -> str:
        what = {"path": "names a path that does not exist", "link": "links to a file that does not exist",
                "command": "names a ctf command that does not exist"}[self.rule]
        return f"{self.doc}:{self.line}: {self.rule}: {self.ref!r} {what}"


def docs(root: Path) -> list[str]:
    root = Path(root)
    out = []
    for p in root.rglob("*.md"):
        if any(part in (".git", ".venv", "node_modules", ".claude") for part in p.relative_to(root).parts):
            continue
        rel = p.relative_to(root).as_posix()
        if rel in ROOT_DOCS or (matches(rel, DOCS) and not matches(rel, NOT_LINTED)):
            out.append(rel)
    return sorted(out)


def commands() -> set:
    """Every `ctf` command name: the built-ins and each ctf/cli/<name>.py (discovered without importing)."""
    import pkgutil

    from .. import cli
    names = {"me", "list", "pull", "triage", "submit", "status", "check", "doctor", "wait"}
    for info in pkgutil.iter_modules(cli.__path__):
        if not info.name.startswith("_") and not info.ispkg:
            names.add(info.name.replace("_", "-"))
    return names


def _top_dirs(root: Path) -> set:
    return {p.name for p in Path(root).iterdir() if p.is_dir() and not p.name.startswith(".")
            and p.name not in ("__pycache__",)}


def lint_text(root: Path, rel: str, text: str, *, tops: set, cmds: set) -> list[Finding]:
    root = Path(root)
    out = []
    in_fence = False
    for i, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
        if SKIP_MARK in line:
            continue
        for m in _CMD.finditer(line):
            if m.group(1) not in cmds:
                out.append(Finding(rel, i, "command", f"python -m ctf {m.group(1)}"))
        if in_fence:
            continue
        for m in _SPAN.finditer(line):
            span = m.group(1).strip()
            if _NOT_PATH.search(span) or "/" not in span or "://" in span:
                continue
            path = _LOC.sub("", span).rstrip("/")
            if path.startswith("./"):
                path = path[2:]
            first = path.split("/", 1)[0]
            if first not in tops or path == first:
                continue
            if not (root / path).exists():
                out.append(Finding(rel, i, "path", span))
        for m in _LINK.finditer(line):
            target = m.group(1)
            if re.match(r"[a-z][a-z0-9+.-]*:", target) or target.startswith(("#", "/")):
                continue
            target = target.split("#", 1)[0]
            if not target:
                continue
            if not ((root / rel).parent / target).exists():
                out.append(Finding(rel, i, "link", target))
    return out


def lint(root: Path, only: list | None = None) -> list[Finding]:
    """Every finding in the maintained docs of `root` (or in `only`, repo-relative docs)."""
    root = Path(root)
    if not root.is_dir():
        raise IntegrityError(f"no such checkout: {root}")
    files = docs(root) if only is None else list(only)
    tops, cmds = _top_dirs(root), commands()
    out = []
    for rel in files:
        p = root / rel
        if not p.is_file():
            raise IntegrityError(f"doclint: no such doc {rel}")
        out += lint_text(root, rel, p.read_text(encoding="utf-8", errors="replace"), tops=tops, cmds=cmds)
    return out


KNOWN = "tests/doclint_known.toml"


@dataclass
class DocAudit:
    new: list            # findings not in the known list: the lint fails on these
    known: list          # findings listed in tests/doclint_known.toml (reported, not failed)
    stale: list          # known entries that match no finding any more: remove them

    @property
    def ok(self) -> bool:
        return not self.new and not self.stale


def load_known(root: Path) -> dict:
    """{(doc, rule, ref): reason} from tests/doclint_known.toml (`[[known]]` doc, rule, ref, reason).
    Keyed without the line number, so an edit above a known reference does not make it new."""
    import tomllib
    p = Path(root) / KNOWN
    if not p.is_file():
        return {}
    try:
        raw = tomllib.loads(p.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as e:
        raise IntegrityError(f"{KNOWN}: not valid TOML: {e}") from e
    if set(raw) - {"known"}:
        raise IntegrityError(f"{KNOWN}: unknown key(s) {sorted(set(raw) - {'known'})}")
    out = {}
    for i, e in enumerate(raw.get("known", [])):
        if not isinstance(e, dict) or set(e) != {"doc", "rule", "ref", "reason"}:
            raise IntegrityError(f"{KNOWN}: [[known]] #{i + 1} needs exactly doc, rule, ref, reason")
        if e["rule"] not in ("path", "link", "command"):
            raise IntegrityError(f"{KNOWN}: [[known]] #{i + 1}: unknown rule {e['rule']!r}")
        if not isinstance(e["reason"], str) or not e["reason"].strip():
            raise IntegrityError(f"{KNOWN}: [[known]] #{i + 1}: reason must say why")
        out[(e["doc"], e["rule"], e["ref"])] = e["reason"]
    return out


def audit(root: Path, only: list | None = None) -> DocAudit:
    """lint() split against the known list. With `only`, stale entries are judged for those docs only."""
    found = lint(root, only)
    known = load_known(root)
    keys = {(f.doc, f.rule, f.ref) for f in found}
    scope = None if only is None else set(only)
    return DocAudit(new=[f for f in found if (f.doc, f.rule, f.ref) not in known],
                    known=[f for f in found if (f.doc, f.rule, f.ref) in known],
                    stale=sorted(f"{d} {r} {ref!r}" for d, r, ref in known
                                 if (d, r, ref) not in keys and (scope is None or d in scope)))
