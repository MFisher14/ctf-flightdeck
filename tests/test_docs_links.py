"""README.md's links. The README is also the project's page on PyPI, which shows the file
alone: a relative link (docs/MODELS.md, #after-a-run) leads nowhere there. So every link in
it is absolute, and every link into this repository names a file the tree has (and, when it
names a heading, a heading that file has).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
REPO = "https://github.com/MFisher14/ctf-flightdeck"
BLOB = f"{REPO}/blob/main/"
RAW = "https://raw.githubusercontent.com/MFisher14/ctf-flightdeck/main/"

_FENCE = re.compile(r"^(```|~~~).*?^\1[^\n]*$", re.M | re.S)
_CODE = re.compile(r"`[^`\n]*`")
_INLINE = re.compile(r"\]\(\s*<?([^)\s>]*)")  # [text](target) and ![alt](target "title")
_REFERENCE = re.compile(r"^ {0,3}\[[^\]\n]+\]:\s*<?(\S*?)>?(?:\s|$)", re.M)  # [label]: target
_HTML = re.compile(r"""\b(?:href|src)\s*=\s*["']?([^"'\s>]*)""", re.I)
_HEADING = re.compile(r"^#{1,6}[ \t]+(.+?)[ \t]*#*[ \t]*$", re.M)


def prose(markdown: str) -> str:
    """`markdown` without its code: fenced blocks and code spans hold examples, not links."""
    return _CODE.sub("", _FENCE.sub("", markdown))


def targets(markdown: str) -> list[str]:
    """Where every link and image in `markdown` points, in order of kind: inline links and
    images, reference definitions, then HTML href and src attributes."""
    text = prose(markdown)
    return [m.group(1) for pattern in (_INLINE, _REFERENCE, _HTML) for m in pattern.finditer(text)]


def relative(target: str) -> bool:
    """A link PyPI cannot follow: anything that is not a whole https:// address."""
    return not target.startswith("https://")


def anchors(markdown: str) -> set[str]:
    """The anchors GitHub gives the headings of `markdown`: lower-case, punctuation dropped
    (letters, digits, _ and - stay), each space a hyphen; a repeated heading gets -1, -2."""
    seen: dict[str, int] = {}
    found: set[str] = set()
    for match in _HEADING.finditer(_FENCE.sub("", markdown)):
        title = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", match.group(1))  # a linked heading: its text
        title = re.sub(r"[`*]", "", title).strip().lower()
        slug = re.sub(r"[^\w\- ]", "", title).replace(" ", "-")
        count = seen.get(slug, 0)
        seen[slug] = count + 1
        found.add(slug if count == 0 else f"{slug}-{count}")
    return found


def repo_links(markdown: str) -> list[tuple[str, str, str]]:
    """(target, path in the tree, fragment) for each link into this repository's files: a
    blob/main page, a raw file, or the repository's front page (README.md) with a fragment."""
    links = []
    for target in targets(markdown):
        address, _, fragment = target.partition("#")
        if address.startswith(BLOB):
            links.append((target, address[len(BLOB):], fragment))
        elif address.startswith(RAW):
            links.append((target, address[len(RAW):], fragment))
        elif address.rstrip("/") == REPO and fragment:
            links.append((target, "README.md", fragment))
    return links


def broken(markdown: str, root: Path) -> list[str]:
    """What is wrong with the links of `markdown` into the tree at `root`, one line each."""
    problems = []
    for target, path, fragment in repo_links(markdown):
        file = root / path
        if not path or ".." in Path(path).parts or not file.is_file():
            problems.append(f"{target}: no file {path} in the tree")
        elif fragment and fragment not in anchors(file.read_text(encoding="utf-8")):
            problems.append(f"{target}: {path} has no heading with the anchor #{fragment}")
    return problems


# ---------------------------------------------------------------------- the README


def test_readme_has_no_relative_link():
    found = [target for target in targets(README.read_text(encoding="utf-8")) if relative(target)]
    assert not found, (
        "README.md is the PyPI page too, where a relative link leads nowhere; write "
        f"{BLOB}<path> (or {REPO}#<heading> for a heading of the README) instead of: {', '.join(found)}"
    )


def test_readme_links_into_the_repository_name_files_and_headings_the_tree_has():
    text = README.read_text(encoding="utf-8")
    assert repo_links(text), "README.md links none of the repository's files: the check would pass on nothing"
    problems = broken(text, ROOT)
    assert not problems, "README.md links what the tree does not have:\n" + "\n".join(problems)


# ---------------------------------------------------------------------- the checks themselves


@pytest.mark.parametrize(
    "markdown, expected",
    [
        ("See [the models](docs/MODELS.md).", ["docs/MODELS.md"]),
        ("See [After a run](#after-a-run).", ["#after-a-run"]),
        ("![shot](docs/screenshots/fleet.png)", ["docs/screenshots/fleet.png"]),
        ('[a](LICENSE "the licence")', ["LICENSE"]),
        ("[a](<docs/MODELS.md>)", ["docs/MODELS.md"]),
        ("[the models][m]\n\n[m]: docs/MODELS.md\n", ["docs/MODELS.md"]),
        ('<a href="docs/MODELS.md">models</a> <img src=shot.png>', ["docs/MODELS.md", "shot.png"]),
        ("[a](http://example.org/x)", ["http://example.org/x"]),
        ("[a](/docs/MODELS.md) [b](mailto:someone@example.org)", ["/docs/MODELS.md", "mailto:someone@example.org"]),
    ],
)
def test_a_relative_link_is_found_however_it_is_written(markdown, expected):
    assert [target for target in targets(markdown) if relative(target)] == expected


def test_an_absolute_link_and_a_link_inside_code_are_not_relative_links():
    markdown = (
        f"[models]({BLOB}docs/MODELS.md) and `[text](docs/X.md)` in a code span\n\n"
        "```sh\necho '[text](docs/Y.md)'   # in a code block\n```\n\n"
        "~~~\n[m]: docs/Z.md\n~~~\n"
    )
    assert targets(markdown) == [f"{BLOB}docs/MODELS.md"]
    assert not relative(f"{BLOB}docs/MODELS.md")


def test_a_link_to_a_missing_file_or_heading_is_reported(tmp_path):
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "GUIDE.md").write_text("# Guide\n\n## Docker or host\n\n## Keys\n\n## Keys\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("# Project\n\n## After a run\n", encoding="utf-8")
    good = (
        f"[g]({BLOB}docs/GUIDE.md) [h]({BLOB}docs/GUIDE.md#docker-or-host) [k]({BLOB}docs/GUIDE.md#keys-1) "
        f"[r]({REPO}#after-a-run) ![i]({RAW}docs/GUIDE.md) [elsewhere](https://example.org/blob/main/nothing.md)"
    )
    assert broken(good, tmp_path) == []
    bad = (
        f"[a]({BLOB}docs/MISSING.md) [b]({BLOB}docs/GUIDE.md#no-such-heading) [c]({REPO}#before-a-run) "
        f"![d]({RAW}docs/missing.png) [e]({BLOB}docs) [f]({BLOB}../outside.md)"
    )
    problems = broken(bad, tmp_path)
    assert len(problems) == 6, problems
    assert "no file docs/MISSING.md" in problems[0]
    assert "no heading with the anchor #no-such-heading" in problems[1]
    assert "README.md has no heading with the anchor #before-a-run" in problems[2]
    assert "no file docs/missing.png" in problems[3]
    assert "no file docs in the tree" in problems[4]
    assert "no file ../outside.md" in problems[5]


def test_heading_anchors_are_githubs():
    markdown = (
        "# Title\n\n## Docker or host\n\n## Your solvers first (L1)\n\n## `challenge.json`\n\n"
        "## What's in it?\n\n## Keys\n\n### Keys\n\n```sh\n# a comment in a code block, not a heading\n```\n"
    )
    assert anchors(markdown) == {
        "title", "docker-or-host", "your-solvers-first-l1", "challengejson", "whats-in-it", "keys", "keys-1",
    }
