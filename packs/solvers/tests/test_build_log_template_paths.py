"""R2-02: build logs name only `templates/...` files that exist.

The doc lint (ctf/integrity/doclint.py, B-196) leaves build logs out on purpose: they are history and
may name files that were later moved or deleted. Template filenames are the exception. A builder reads
a build log to find the template it should copy, so a wrong name there sends them to a file that is not
in the tree. B-165's log called `templates/static-re/vmspec.example.py.tmpl` by its rendered name, and
nothing caught it. This check runs the doc lint's own path rule over every build log and keeps only the
references under `templates/`. Fenced blocks and lines marked `doclint: skip` are left alone, the same as
the lint does elsewhere.
"""
from __future__ import annotations

import posixpath
import re
import textwrap
from pathlib import Path

from ctf import paths
from ctf.integrity import doclint

# Build-log references under templates/ that are allowed to be missing. Each one needs a reason. An
# entry that no longer matches a missing reference fails test_known_missing_entries_are_live: when that
# happens, delete the entry.
KNOWN_MISSING = {
    ("docs/build-log/B-098.md", "templates/writeup/organizer/"):
        "follow-up note: the planned home of the organizer assembler, not built yet",
}


# A list that starts with a full templates/ path and goes on with bare sibling names, as in
# "`templates/static-re/README.md.tmpl`, `agent-task.md.tmpl`, `vmspec.example.py.tmpl`". The bare
# names live in the first path's directory. B-165's wrong name sat in exactly this position.
_RUN = re.compile(r"`(templates/[^`\s]+)`((?:\s*(?:,\s*and|,|and)\s*`[^`/\s]+`)+)")
_SIBLING = re.compile(r"`([^`/\s]+)`")


def _sibling_findings(root: Path, rel: str, text: str) -> list[doclint.Finding]:
    out = []
    in_fence = False
    for i, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
        if in_fence or doclint.SKIP_MARK in line:
            continue
        for m in _RUN.finditer(line):
            if m.group(1).endswith("/"):
                continue   # "`templates/event/` and `fence.toml`": a directory, then a separate item
            base = posixpath.dirname(m.group(1))
            for name in _SIBLING.findall(m.group(2)):
                ref = f"{base}/{name}"
                if not (root / ref).exists():
                    out.append(doclint.Finding(rel, i, "path", ref))
    return out


def template_findings(root: Path) -> list[doclint.Finding]:
    """Path findings under templates/ in every docs/build-log/*.md of `root`: full paths (the doc
    lint's own path rule) and bare sibling names listed after a full path."""
    root = Path(root)
    logs = sorted((root / "docs" / "build-log").glob("*.md"))
    assert logs, f"no build logs under {root / 'docs' / 'build-log'}"
    tops, cmds = doclint._top_dirs(root), doclint.commands()
    out = []
    for p in logs:
        rel = p.relative_to(root).as_posix()
        text = p.read_text(encoding="utf-8", errors="replace")
        for f in doclint.lint_text(root, rel, text, tops=tops, cmds=cmds):
            if f.rule == "path" and f.ref.startswith("templates/"):
                out.append(f)
        out += _sibling_findings(root, rel, text)
    return out


def write(root: Path, files: dict) -> Path:
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(text))
    return root


def test_checker_flags_a_wrong_template_name_and_passes_the_real_one(tmp_path):
    root = write(tmp_path, {
        "templates/static-re/vmspec.example.py.tmpl": "",
        "tools/run.py": "",
        "docs/build-log/B-1.md": """\
            | `templates/static-re/vmspec.example.py` | rendered name, not the tracked one |
            | `templates/static-re/vmspec.example.py.tmpl` | the tracked file |
            | `templates/static-re/` | a directory that exists |
            | `tools/gone.py` | not under templates/: history, not checked here |
            Deliberate: `templates/old.tmpl` <!-- doclint: skip -->
            ```
            `templates/in_a_fence.tmpl`
            ```
            """,
    })
    got = [(f.doc, f.line, f.ref) for f in template_findings(root)]
    assert got == [("docs/build-log/B-1.md", 1, "templates/static-re/vmspec.example.py")]


def test_checker_resolves_bare_sibling_names_against_the_first_path(tmp_path):
    root = write(tmp_path, {
        "templates/static-re/README.md.tmpl": "",
        "templates/static-re/agent-task.md.tmpl": "",
        "templates/static-re/vmspec.example.py.tmpl": "",
        "docs/build-log/B-1.md": """\
            | `templates/static-re/README.md.tmpl`, `agent-task.md.tmpl`, `vmspec.example.py` | old row |
            | `templates/static-re/README.md.tmpl`, `agent-task.md.tmpl`, `vmspec.example.py.tmpl` | fixed |
            | `templates/static-re/README.md.tmpl` and `nope.tmpl` | joined with and |
            Run `tools/ctfpy vmspec.example.py` from the workspace (not a list after a templates path).
            Layout lists `templates/static-re/` and `fence.toml` (a directory, then a separate item).
            Skipped: `templates/static-re/README.md.tmpl`, `old.tmpl` <!-- doclint: skip -->
            """,
    })
    got = [(f.line, f.ref) for f in template_findings(root)]
    assert got == [(1, "templates/static-re/vmspec.example.py"), (3, "templates/static-re/nope.tmpl")]


def test_build_logs_name_only_template_files_that_exist():
    root = paths.repo_root()
    unexpected = [f.text() for f in template_findings(root) if (f.doc, f.ref) not in KNOWN_MISSING]
    assert unexpected == [], "build logs name templates that are not in the tree:\n" + "\n".join(unexpected)


def test_known_missing_entries_are_live():
    root = paths.repo_root()
    live = {(f.doc, f.ref) for f in template_findings(root)}
    stale = sorted(k for k in KNOWN_MISSING if k not in live)
    assert stale == [], f"KNOWN_MISSING entries that no longer match a missing reference: {stale}"
