"""B-181: the "Attempts ledger" block of the event agent rules (templates/event/agent-rules.md.tmpl).

The rules are how every agent and harness on an event learns to check the shared hypothesis ledger
before a probe and record after it. The block must reach both generated files of every event, every
command it shows must be one the master accepts, and the check -> record -> check flow it describes
must actually gate a re-run when driven through the real CLI. Offline: a tmp workdir, no network."""
from __future__ import annotations

import re
import shlex

import pytest

from ctf import event, eventrules, paths
from ctf.cli import main as ctf_main

PAST = ("csctf", "huntress", "pink", "spooky")
HEADING = "## Attempts ledger"
PREFIX = "python -m ctf hypothesis "


def _section(text: str) -> str:
    body = eventrules.split_header(text)[1]
    start = body.find(HEADING)
    assert start >= 0, f"no {HEADING!r} section in the rules body"
    end = body.find("\n## ", start + len(HEADING))
    return body[start:] if end < 0 else body[start:end]


def _spans(section: str) -> dict[str, str]:
    flat = re.sub(r"\n\s*", " ", section)     # code spans may wrap across a line break
    out: dict[str, str] = {}
    for s in re.findall(r"`([^`]+)`", flat):
        if s.startswith(PREFIX):
            out.setdefault(s[len(PREFIX):].split()[0], s)
    return out


def _argv(span: str, wd, **values) -> list[str]:
    def sub(m):
        name = m.group(1)
        return values.get(name, "x")
    tokens = shlex.split(re.sub(r"<([^>]+)>", sub, span))
    assert tokens[:4] == ["python", "-m", "ctf", "hypothesis"], tokens
    return ["hypothesis", "--workdir", str(wd), *tokens[4:]]


@pytest.mark.parametrize("slug", PAST)
def test_both_files_of_every_event_carry_the_same_ledger_block(slug):
    d = paths.event_dir(slug)
    claude = _section((d / "CLAUDE.md").read_text(encoding="utf-8"))
    agents = _section((d / "AGENTS.md").read_text(encoding="utf-8"))
    assert claude == agents
    assert set(_spans(claude)) >= {"check", "record", "false", "list"}
    for needle in ("exits 1", "Exit 0", "--control", "--family", "--agent"):
        assert needle in claude, needle


@pytest.mark.parametrize("slug", PAST)
def test_fresh_render_matches_committed_block(slug):
    out = eventrules.render(event.load(slug))
    committed = (paths.event_dir(slug) / "CLAUDE.md").read_text(encoding="utf-8")
    assert _section(out["CLAUDE.md"]) == _section(committed)


def test_every_hypothesis_command_in_the_block_is_accepted(capsys):
    spans = _spans(_section((paths.event_dir("csctf") / "CLAUDE.md").read_text(encoding="utf-8")))
    for action, span in spans.items():
        with pytest.raises(SystemExit) as e:
            ctf_main(["hypothesis", action, "--help"])
        out = capsys.readouterr()
        assert e.value.code == 0, f"`{PREFIX}{action}` is not a command: {out.err}"
        for opt in re.findall(r"(--[a-z][a-z-]*)", span):
            assert opt in out.out, f"{opt} in `{span}` is not an option of `hypothesis {action}`"


def test_the_flow_the_block_describes_gates_a_rerun(tmp_path, capsys):
    """Run the block's own commands: check says run, record a negative, check now says skip, and a
    second agent writing the method differently is still told to skip."""
    wd = tmp_path / "work"
    spans = _spans(_section((paths.event_dir("csctf") / "CLAUDE.md").read_text(encoding="utf-8")))
    vals = {"id": "12", "method": "zsteg -a", "your id": "agent-1",
            "negative|positive|inconclusive|error": "negative"}
    assert ctf_main(_argv(spans["check"], wd, **vals)) == 0          # not tried: run it
    assert ctf_main(_argv(spans["record"], wd, **vals)) == 0
    assert ctf_main(_argv(spans["check"], wd, **vals)) == 1          # settled: skip
    assert ctf_main(_argv(spans["check"], wd, **{**vals, "method": "ZSTEG   -a"})) == 1
    out = capsys.readouterr().out
    assert "agent-1" in out                                          # who ran it is reported
    assert ctf_main(_argv(spans["list"], wd, **vals)) == 0
    assert "zsteg -a" in capsys.readouterr().out
