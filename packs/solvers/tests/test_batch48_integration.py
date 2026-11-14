"""Batch-48 integration fix.

B-138 added the command `python -m ctf backlog` (ctf/cli/backlog.py) without its row in the CLI table of
docs/CONTRACTS.md section 8, so tests/test_contracts_doc.py failed on the merged tree for the command and
for its `set-status` sub-command (the other sub-command names were already words of section 8, from other
commands' rows, so that test could not see them missing). The row was added at merge. These tests hold
the row itself, not the section, to the real parser: the module, every sub-command, every option, and the
exit code the row states for a named error.

Offline and synthetic: the backlog file is written by the test.
"""
import argparse
import json
import re

from ctf import paths
from ctf.cli import backlog as backlog_cli

DOC = paths.repo_root() / "docs" / "CONTRACTS.md"
_SPAN = re.compile(r"`([^`\n]+)`")


def _section_8() -> str:
    text = DOC.read_text(encoding="utf-8")
    start = text.index("\n## 8. CLI\n")
    return text[start:text.index("\n## 9. ", start)]


def _row() -> str:
    rows = [ln for ln in _section_8().splitlines() if ln.startswith("| `backlog` |")]
    assert len(rows) == 1, f"section 8 must have exactly one `backlog` row, found {len(rows)}"
    return rows[0]


def _subparsers() -> dict[str, argparse.ArgumentParser]:
    p = argparse.ArgumentParser()
    backlog_cli.add_arguments(p)
    (sub,) = [a for a in p._actions if isinstance(a, argparse._SubParsersAction)]
    return dict(sub.choices)


def test_the_backlog_row_names_its_module_and_every_subcommand():
    row = _row()
    cells = [c.strip() for c in row.strip("|").split(" | ")]
    assert cells[0] == "`backlog`" and cells[1] == "`ctf/cli/backlog.py`", cells[:2]
    subs = _subparsers()
    assert {"list", "set-status", "sync"} <= set(subs)          # the real parser, not an empty one
    # a sub-command is documented by a code span that starts with its name: `set-status <id> <status>`
    heads = {s.split()[0] for s in _SPAN.findall(cells[2])}
    missing = sorted(set(subs) - heads)
    assert not missing, f"the section 8 backlog row lacks sub-command(s): {', '.join(missing)}"


def test_the_backlog_row_names_every_option_of_every_subcommand():
    spans = " ".join(_SPAN.findall(_row()))
    documented = set(re.findall(r"(?<![\w-])--[a-z][a-z-]*", spans))
    want = set()
    for sub in _subparsers().values():
        for a in sub._actions:
            want |= {o for o in a.option_strings if o.startswith("--") and o != "--help"}
    assert {"--file", "--event", "--check", "--effort-budget"} <= want
    missing = sorted(want - documented)
    assert not missing, f"the section 8 backlog row lacks option(s): {', '.join(missing)}"


def _run(*argv) -> int:
    p = argparse.ArgumentParser()
    backlog_cli.add_arguments(p)
    return backlog_cli.run(p.parse_args([str(a) for a in argv]))


def test_the_exit_code_the_row_states_for_a_named_error(tmp_path, capsys):
    assert "Exit 2 = a named error (unknown status or id, missing or malformed file)" in _row()
    f = tmp_path / "backlog.jsonl"
    f.write_text(json.dumps({"id": "B-900", "title": "a synthetic row", "status": "open"}) + "\n",
                 encoding="utf-8")
    assert _run("list", "--file", f, "--json") == 0
    assert [r["id"] for r in json.loads(capsys.readouterr().out)] == ["B-900"]

    for argv, named in ((("set-status", "B-900", "finished", "--file", f), "finished"),      # unknown status
                        (("set-status", "B-901", "built", "--file", f), "B-901"),            # unknown id
                        (("list", "--file", tmp_path / "absent.jsonl"), "absent.jsonl")):    # missing file
        assert _run(*argv) == 2, argv
        err = capsys.readouterr().err
        assert err.startswith("ctf backlog: ") and named in err, (argv, err)
    bad = tmp_path / "bad.jsonl"
    bad.write_text("{not json\n", encoding="utf-8")
    assert _run("open", "--file", bad) == 2                                                   # malformed file
    assert "bad.jsonl:1" in capsys.readouterr().err
    # none of the refused calls changed the file; a known id and status still does
    assert json.loads(f.read_text(encoding="utf-8").splitlines()[0])["status"] == "open"
    assert _run("set-status", "B-900", "built", "--file", f) == 0
    assert json.loads(f.read_text(encoding="utf-8").splitlines()[0])["status"] == "built"
