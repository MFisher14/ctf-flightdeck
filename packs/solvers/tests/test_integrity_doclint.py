"""B-196: the doc lint (ctf/integrity/doclint.py): maintained docs name only paths, links and ctf
commands that exist. Synthetic trees; the command list is the real `ctf` one."""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from ctf.integrity import IntegrityError, doclint


def tree(tmp_path: Path, files: dict) -> Path:
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(text))
    return tmp_path


DOC = """\
# Guide

Run `tools/run.py` and `tools/verify.py` (gone). See `ctf/gate/` and `tools/run.py:12`.
Not paths: `tools/*.py`, `a b/c`, `<event>/x.md`, `https://x.test/a/b`, `docs/...`, `~/ctf/x`, `tools`.
A [link](other.md), a [dead one](missing.md#part), an [anchor](#guide), a [site](https://x.test/y).
Commands: python -m ctf gate run, then python3 -m ctf no-such-command.
Deliberate: `tools/old.py` <!-- doclint: skip -->

```
tools/inside_a_fence.py and `tools/fenced.py` are examples
python -m ctf fenced-command
```
"""


@pytest.fixture
def root(tmp_path):
    return tree(tmp_path, {"tools/run.py": "", "ctf/gate/x.py": "", "docs/guide.md": DOC,
                           "docs/other.md": "fine\n", "docs/build-log/B-1.md": "`tools/ancient.py`\n",
                           "README.md": "`tools/run.py`\n", "tests/fixtures/README.md": "`tools/gone.py`\n"})


def test_findings_by_rule(root):
    got = sorted((f.doc, f.line, f.rule, f.ref) for f in doclint.lint(root))
    assert got == [
        ("docs/guide.md", 3, "path", "tools/verify.py"),
        ("docs/guide.md", 5, "link", "missing.md"),
        ("docs/guide.md", 6, "command", "python -m ctf no-such-command"),
        ("docs/guide.md", 11, "command", "python -m ctf fenced-command"),   # commands are checked in fences
    ]


def test_which_docs_are_linted(root):
    assert doclint.docs(root) == ["README.md", "docs/guide.md", "docs/other.md"]   # not build logs or fixtures


def test_the_known_list_is_line_agnostic_and_goes_stale(root):
    tree(root, {"tests/doclint_known.toml": '''\
        [[known]]
        doc = "docs/guide.md"
        rule = "path"
        ref = "tools/verify.py"
        reason = "a carried doc"

        [[known]]
        doc = "docs/guide.md"
        rule = "link"
        ref = "fixed.md"
        reason = "was fixed"
        '''})
    (root / "docs/guide.md").write_text("new first line\n" + DOC)          # every line moves down
    res = doclint.audit(root)
    assert [f.ref for f in res.known] == ["tools/verify.py"]
    assert sorted(f.ref for f in res.new) == ["missing.md", "python -m ctf fenced-command",
                                              "python -m ctf no-such-command"]
    assert res.stale == ["docs/guide.md link 'fixed.md'"] and not res.ok
    only = doclint.audit(root, ["docs/other.md"])
    assert only.ok and only.stale == []                                   # stale is judged per doc linted


def test_commands_are_the_real_ones():
    cmds = doclint.commands()
    assert {"gate", "integrity", "submit", "doctor"} <= cmds and "no-such-command" not in cmds


@pytest.mark.parametrize("text,match", [
    ('[[known]]\ndoc = "a"\nrule = "path"\nref = "x"\n', "exactly doc, rule, ref, reason"),
    ('[[known]]\ndoc = "a"\nrule = "spelling"\nref = "x"\nreason = "y"\n', "unknown rule"),
    ('x = 1\n', "unknown key"),
])
def test_a_bad_known_list_is_loud(root, text, match):
    tree(root, {"tests/doclint_known.toml": text})
    with pytest.raises(IntegrityError, match=match):
        doclint.load_known(root)


def test_a_named_doc_that_is_missing_is_loud(root):
    with pytest.raises(IntegrityError, match="no such doc"):
        doclint.lint(root, ["docs/nope.md"])


def test_finding_text_and_only_folders_are_roots(root):
    tree(root, {"notes": "a file at the top, not a folder\n", "docs/n.md": "`notes/x.txt` and `.hidden/y.md`\n"})
    assert doclint.lint(root, ["docs/n.md"]) == []                        # neither is a top-level folder
    f = doclint.lint(root, ["docs/guide.md"])[0]
    assert f.text() == "docs/guide.md:3: path: 'tools/verify.py' names a path that does not exist"


def test_without_a_known_list_every_finding_is_new(root):
    res = doclint.audit(root)
    assert len(res.new) == 4 and res.known == [] and res.stale == [] and not res.ok
