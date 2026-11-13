"""B-199: the generated repo primer and file index (ctf.primer), `ctf primer`, and their wiring into
`engines generate` and the per-event agent rules.

The currency test reads the real tree (tests/gate.toml scan rule); every other test renders a
synthetic tree. Each test fails when the behaviour is wrong: a stale committed primer, a command or
module missing from the index, a large file not flagged (or a small one flagged), a primer that the
event rules do not carry.
"""
from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

import pytest

from ctf import event, eventrules, primer
from ctf.cli import primer as cli_primer
from ctf.engines import derived
from ctf.gate import GateError


def test_committed_primer_and_index_are_current():
    assert primer.stale_files() == [], (
        "docs/PRIMER.md / docs/FILE-INDEX.md are stale: run `python -m ctf engines generate`")


def _tree(tmp_path: Path) -> Path:
    r = tmp_path / "repo"
    files = {
        "CLAUDE.md": "rules\n",
        "docs/CONTRACTS.md": "c\n",
        "ctf/__init__.py": '"""Top package."""\n',
        "ctf/alpha.py": '"""Alpha does the first thing. Then more."""\nX = 1\n',
        "ctf/nodoc.py": "X = 1\n",
        "ctf/sub/__init__.py": '"""The sub package (B-1)."""\n',
        "ctf/sub/beta.py": '"""Beta | with a pipe."""\n',
        "ctf/cli/__init__.py": '"""CLI."""\ndef cmd_me(a):\n    pass\ndef cmd_list_all(a):\n    pass\n',
        "ctf/cli/frob.py": 'HELP = "frobnicate the widgets"\ndef add_arguments(p): pass\ndef run(a): return 0\n',
        "ctf/cli/two_words.py": 'HELP = ("a long help " \n        "joined")\n',
        "ctf/cli/computed.py": 'HELP = "x" + str(1)\n',
        "ctf/cli/_private.py": 'HELP = "not a command"\n',
        "ctf/__pycache__/junk.py": '"""Never listed."""\n',
        "tools/tool.py": '"""A tool."""\n',
        "solvers/web/__init__.py": '"""Web lane."""\n',
        "solvers/web/big.py": "x = 1\n" * primer.LARGE_LINES,
        "solvers/web/almost.py": "x = 1\n" * (primer.LARGE_LINES - 1),
        "solvers/binary/huge.py": "x = 1\n" * 7400,
        "solvers/mystery/m.py": "pass\n",
    }
    for rel, text in files.items():
        p = r / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    # a checkout: the primer lists the gate's file list (untracked-not-ignored files count, ignored don't)
    subprocess.run(["git", "init", "-q", str(r)], check=True, capture_output=True)
    return r


def test_gitignored_files_never_change_the_primer_or_index(tmp_path):
    r = _tree(tmp_path)
    brief, idx = primer.render_primer(r), primer.render_index(r)
    (r / ".gitignore").write_text("scratch/\n*_local.py\nsolvers/junklane/\n")
    brief, idx = primer.render_primer(r), primer.render_index(r)       # .gitignore itself is no module
    (r / "ctf" / "notes_local.py").write_text('"""Local scratch."""\n')
    (r / "ctf" / "cli" / "try_local.py").write_text('HELP = "local command"\n')
    (r / "ctf" / "scratch").mkdir()
    (r / "ctf" / "scratch" / "__init__.py").write_text('"""Scratch pkg."""\n')
    (r / "tools" / "big_local.py").write_text("x = 1\n" * 9000)
    (r / "solvers" / "junklane").mkdir()
    (r / "solvers" / "junklane" / "a.py").write_text("pass\n")
    assert primer.render_primer(r) == brief and primer.render_index(r) == idx
    (r / "ctf" / "fresh.py").write_text('"""Fresh module."""\n')       # untracked, not ignored: listed
    assert "- `ctf/fresh.py`: Fresh module." in primer.render_index(r)


def test_a_tree_without_git_lists_every_file(tmp_path):
    r = tmp_path / "plain"
    (r / "ctf" / "__pycache__").mkdir(parents=True)
    (r / "ctf" / "a_local.py").write_text('"""Kept."""\n')
    (r / "ctf" / "__pycache__" / "junk.py").write_text("X = 1\n")
    (r / ".gitignore").write_text("*_local.py\n")              # no checkout: no ignore rules apply
    assert primer.repo_files(r) == {"ctf/a_local.py", ".gitignore"}
    assert "- `ctf/a_local.py`: Kept." in primer.render_index(r)


def test_a_checkout_where_git_fails_is_a_loud_error(tmp_path):
    r = tmp_path / "broken"
    (r / "ctf").mkdir(parents=True)
    (r / "ctf" / "a.py").write_text("X = 1\n")
    (r / ".git").write_text("gitdir: " + str(tmp_path / "nowhere") + "\n")   # a dangling worktree pointer
    with pytest.raises(GateError, match="not a git checkout"):
        primer.render_index(r)
    assert cli_primer.run(_args("--root", str(r), "--write")) == 2
    assert not (r / primer.PRIMER_REL).exists()


def test_index_lists_commands_modules_and_lanes(tmp_path):
    r = _tree(tmp_path)
    idx = primer.render_index(r)
    assert "Built in (`ctf/cli/__init__.py`): `list-all`, `me`." in idx
    assert "- `frob`: frobnicate the widgets" in idx
    assert "- `two-words`: a long help joined" in idx
    assert "- `computed`: (no literal HELP string)" in idx
    assert "_private" not in idx and "not a command" not in idx
    assert "- `ctf/alpha.py`: Alpha does the first thing." in idx
    assert "- `ctf/nodoc.py`\n" in idx
    assert "- `ctf/sub/beta.py`: Beta \\| with a pipe." in idx
    assert "ctf/cli/frob.py" not in idx                     # commands are listed as commands
    assert "__pycache__" not in idx and "Never listed" not in idx
    assert "- `tools/tool.py`: A tool." in idx
    assert "- `solvers/web/`: Web lane." in idx
    assert "- `solvers/binary/`: " + primer.LANE_NOTES["binary"] in idx
    assert "- `solvers/mystery/`: -" in idx


def test_a_file_directly_under_solvers_is_not_a_lane(tmp_path):
    r = _tree(tmp_path)
    (r / "solvers" / "README.md").write_text("lanes live in subfolders\n")
    (r / "solvers" / "conftest.py").write_text("X = 1\n")
    lanes = primer._lanes(r, primer.repo_files(r))
    assert [name for name, _ in lanes] == ["solvers/binary/", "solvers/mystery/", "solvers/web/"]
    for text in (primer.render_index(r), primer.render_primer(r)):
        assert "solvers/README.md/" not in text and "solvers/conftest.py/" not in text


def test_large_files_threshold_and_rounding(tmp_path):
    r = _tree(tmp_path)
    assert primer.large_files(r) == [("solvers/binary/huge.py", "~7k"), ("solvers/web/big.py", "~2k")]
    assert primer.large_files(r, min_lines=primer.HUGE_LINES) == [("solvers/binary/huge.py", "~7k")]
    idx = primer.render_index(r)
    assert "- ~7k lines: `solvers/binary/huge.py`" in idx and "- ~2k lines: `solvers/web/big.py`" in idx
    assert "almost.py" not in idx
    brief = primer.render_primer(r)
    assert "- ~7k lines: `solvers/binary/huge.py`" in brief and "big.py" not in brief


def test_primer_lists_only_what_exists_and_carries_the_reading_rules(tmp_path):
    r = _tree(tmp_path)
    brief = primer.render_primer(r)
    assert "- `CLAUDE.md`: " in brief and "- `docs/CONTRACTS.md`: " in brief
    assert "BUILD-PLAN.md" not in brief                     # not in this tree
    assert "| `ctf/` |" in brief and "| `solvers/` |" in brief and "| `docker/` |" not in brief
    assert "| `ctf/sub/` | The sub package (B-1). |" in brief
    assert "## Reading this repo cheaply" in brief
    assert "python -m ctf research get" in brief and "--symbol NAME" in brief
    assert primer.render_primer(r) == brief                 # deterministic


def test_write_then_check(tmp_path):
    r = _tree(tmp_path)
    assert primer.stale_files(r) == [primer.PRIMER_REL, primer.INDEX_REL]
    primer.write(r)
    assert primer.stale_files(r) == []
    (r / "ctf" / "gamma.py").write_text('"""Gamma."""\n')    # a new module makes the index stale
    assert primer.stale_files(r) == [primer.INDEX_REL]
    assert primer.index_stale(r) and not primer.primer_stale(r)


def test_engines_generate_regenerates_the_primer(tmp_path):
    r = _tree(tmp_path)
    rels = [rel for rel, _, _ in derived.DERIVED]
    assert primer.PRIMER_REL in rels and primer.INDEX_REL in rels
    for rel, write, is_stale in derived.DERIVED:
        if rel in (primer.PRIMER_REL, primer.INDEX_REL):
            assert is_stale(r)
            write(r)
            assert not is_stale(r)
    assert (r / primer.PRIMER_REL).read_text() == primer.render_primer(r)


def _args(*argv):
    p = argparse.ArgumentParser()
    cli_primer.add_arguments(p)
    return p.parse_args(list(argv))


def test_cli_prints_checks_and_writes(tmp_path, capsys):
    r = _tree(tmp_path)
    assert cli_primer.run(_args("--root", str(r))) == 2
    assert "missing" in capsys.readouterr().err
    assert cli_primer.run(_args("--root", str(r), "--check")) == 1
    assert f"stale: {primer.PRIMER_REL}" in capsys.readouterr().out
    assert cli_primer.run(_args("--root", str(r), "--write")) == 0
    assert cli_primer.run(_args("--root", str(r), "--check")) == 0
    capsys.readouterr()
    assert cli_primer.run(_args("--root", str(r))) == 0
    assert capsys.readouterr().out == primer.render_primer(r)
    assert cli_primer.run(_args("--root", str(r), "--index")) == 0
    assert capsys.readouterr().out == primer.render_index(r)


@pytest.mark.parametrize("slug", ["csctf", "pink"])
def test_event_agent_rules_carry_the_reading_rules(slug):
    out = eventrules.render(event.load(slug))
    for name in ("CLAUDE.md", "AGENTS.md"):
        assert primer.rules_md() in out[name]
