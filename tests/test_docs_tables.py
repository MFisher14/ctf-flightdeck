"""A lint for the tables in the repository's Markdown.

GitHub's Markdown splits a table row at every `|` that has no backslash before it, before it
looks for code spans. So a row holding `` `--light ollama|mlx` `` ends that cell at "ollama" and
moves the rest into the next column, and cells past the header's count are dropped from the
page. Inside a table, a pipe in a code span must be written `\\|`.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent

_FENCE = re.compile(r"^\s{0,3}(?:>\s?)*\s{0,3}(`{3,}|~{3,})")
_ROW = re.compile(r"^\s{0,3}\|")
_TICKS = re.compile(r"`+")


def code_spans(line: str) -> list[tuple[int, str]]:
    """Each code span of one line as (column of its text, its text), by CommonMark's rule: a run
    of backticks opens a span that the next run of the same length closes."""
    spans = []
    at = 0
    while (opening := _TICKS.search(line, at)) is not None:
        closing = next((run for run in _TICKS.finditer(line, opening.end()) if len(run.group()) == len(opening.group())), None)
        if closing is None:
            at = opening.end()
            continue
        spans.append((opening.end(), line[opening.end():closing.start()]))
        at = closing.end()
    return spans


def unescaped_pipes(text: str) -> list[tuple[int, str]]:
    """(line number, code span) for every code span in a table row that holds a `|` with no
    backslash before it. Rows are the lines that start with `|`, outside fenced code blocks."""
    found = []
    fence = ""
    for number, line in enumerate(text.splitlines(), start=1):
        mark = _FENCE.match(line)
        if mark is not None:
            if not fence:
                fence = mark.group(1)
            elif mark.group(1)[0] == fence[0] and len(mark.group(1)) >= len(fence):
                fence = ""
            continue
        if fence or not _ROW.match(line):
            continue
        for _, span in code_spans(line):
            if re.search(r"(?<!\\)\|", span):
                found.append((number, span))
    return found


def tracked_markdown() -> list[Path]:
    git = shutil.which("git")
    if git is None:
        pytest.skip("git is not installed, and the list of tracked Markdown files comes from git ls-files")
    if not (REPO / ".git").exists():
        pytest.skip(f"{REPO} is not a git checkout, so there is no list of tracked files")
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}  # a hook's GIT_DIR points elsewhere
    listing = subprocess.run([git, "ls-files", "-z", "--", "*.md"], cwd=REPO, env=env, capture_output=True, timeout=60)
    assert listing.returncode == 0, f"git ls-files failed in {REPO}: {listing.stderr.decode('utf-8', 'replace').strip()}"
    paths = [REPO / os.fsdecode(name) for name in listing.stdout.split(b"\0") if name]
    return sorted(path for path in paths if path.is_file())


def test_a_pipe_in_a_code_span_of_a_table_row_is_found():
    text = "| Flag | Job |\n|---|---|\n| `--light ollama|mlx` | the light model |\n"
    assert unescaped_pipes(text) == [(3, "--light ollama|mlx")]


def test_each_span_of_a_row_is_reported_with_its_line():
    text = "intro\n\n| A |\n|---|\n| fine `a` |\n| `x | y` and ``l1 list | run`` |\n"
    assert unescaped_pipes(text) == [(6, "x | y"), (6, "l1 list | run")]


def test_an_escaped_pipe_passes():
    assert unescaped_pipes("| A | B |\n|---|---|\n| `--light ollama\\|mlx` | `a \\| b \\| c` |\n") == []


def test_pipes_between_code_spans_are_cell_borders():
    # the `|` between `a` and `b` is outside both spans: the row has two cells, as written
    assert unescaped_pipes("| A | B |\n|---|---|\n| `a` | `b` |\n") == []


def test_prose_and_fenced_blocks_are_not_table_rows():
    text = (
        "Use `play --agent claude|codex` here.\n\n"
        "```\n| `a|b` | drawn in a code block |\n```\n\n"
        "~~~sh\n| `c|d` |\n~~~\n"
    )
    assert unescaped_pipes(text) == []


def test_a_row_after_a_closed_fence_is_checked_again():
    text = "```\n| `a|b` |\n```\n| H |\n|---|\n| `c|d` |\n"
    assert unescaped_pipes(text) == [(6, "c|d")]


def test_no_tracked_markdown_table_cuts_a_code_span_at_a_pipe():
    files = tracked_markdown()
    names = {path.relative_to(REPO).as_posix() for path in files}
    assert {"README.md", "docs/ARCHITECTURE.md", "docs/DECISIONS.md"} <= names, f"the file list looks wrong: {sorted(names)}"
    problems = [
        f"{path.relative_to(REPO).as_posix()}:{number}: `{span}`"
        for path in files
        for number, span in unescaped_pipes(path.read_text(encoding="utf-8"))
    ]
    assert not problems, (
        "a `|` inside a code span of a table row splits the cell on GitHub; write it `\\|`:\n" + "\n".join(problems)
    )
