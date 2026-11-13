"""B-211: the "Operating rules" block -- one block of standing rules (preferences, count language,
evidence, time, GUI, patches), kept identical in the event template, the root CLAUDE.md and AGENTS.md,
and every generated events/*/CLAUDE.md and AGENTS.md. Offline: reads tracked files and renders."""
from __future__ import annotations

import re

import pytest

from ctf import event, eventrules, paths
from ctf.cli import main as ctf_main

HEADING = "## Operating rules"
TEMPLATE = paths.repo_root() / "templates" / "event" / "agent-rules.md.tmpl"

# Each rule the item encodes, by the bold lead that names it and a phrase that carries its substance.
RULES = {
    "Preferences go in rules or memory.": "store it the\n  same turn in a rules file or in memory",
    "Count by unit.": "say what each number counts",
    "A retry rejoins; it does not redraw.": "regular start rejoined the open attempt",
    "Evidence over transcript memory.": "`python -m ctf hypothesis list <id>`",
    "Time from the clock.": "`python -m ctf clock`",
    "No GUI or browser control unless asked.": "unless the player asks for it",
    "Patch from a fresh read.": "Read the file again right before editing it",
}


def _section(text: str) -> str:
    start = text.find(HEADING)
    assert start >= 0, f"no {HEADING!r} section"
    assert text.find(HEADING, start + 1) < 0, f"{HEADING!r} appears twice"
    end = text.find("\n## ", start + len(HEADING))
    return (text[start:] if end < 0 else text[start:end]).rstrip("\n") + "\n"


def _template_block() -> str:
    return _section(TEMPLATE.read_text(encoding="utf-8"))


def _event_slugs() -> list[str]:
    return sorted(p.parent.name for p in (paths.repo_root() / "events").glob("*/event.toml"))


def test_template_block_carries_every_rule():
    block = _template_block()
    for lead, substance in RULES.items():
        assert f"**{lead}**" in block, lead
        assert substance in block, substance


def test_count_rule_gives_the_board_summary_shape():
    """The board summary has one shape naming the unit of every count (Huntress: "12" read as the
    whole board when it was 12 first places out of 209 placements)."""
    flat = re.sub(r"\n\s*", " ", _template_block())
    assert ('Board summary shape: "solved X of Y challenges; A first places out of B placements; '
            'P points, rank R"') in flat
    assert '"12 first places out of 209 placements"' in flat


def test_template_block_has_no_template_tags():
    """The block is copied verbatim to the root files, so it must render to itself."""
    assert "{{" not in _template_block()


@pytest.mark.parametrize("name", ["CLAUDE.md", "AGENTS.md"])
def test_root_files_carry_the_template_block_verbatim(name):
    text = (paths.repo_root() / name).read_text(encoding="utf-8")
    assert _section(text) == _template_block()


def test_every_event_is_covered():
    assert set(_event_slugs()) >= {"csctf", "huntress", "pink", "spooky"}


@pytest.mark.parametrize("slug", _event_slugs())
@pytest.mark.parametrize("name", ["CLAUDE.md", "AGENTS.md"])
def test_each_generated_event_file_carries_every_rule(slug, name):
    text = (paths.event_dir(slug) / name).read_text(encoding="utf-8")
    body = eventrules.split_header(text)[1]
    block = _section(body)
    assert block == _template_block()
    for lead, substance in RULES.items():
        assert f"**{lead}**" in block and substance in block, (slug, name, lead)


@pytest.mark.parametrize("slug", _event_slugs())
def test_fresh_render_carries_the_block(slug):
    out = eventrules.render(event.load(slug))
    for name in ("CLAUDE.md", "AGENTS.md"):
        assert _section(eventrules.split_header(out[name])[1]) == _template_block()


def test_commands_the_block_names_exist(capsys):
    """`python -m ctf clock` and `python -m ctf hypothesis list` must be real commands."""
    flat = re.sub(r"\n\s*", " ", _template_block())
    cmds = {s.split()[3] + (" " + s.split()[4] if s.split()[3] == "hypothesis" else "")
            for s in re.findall(r"`(python -m ctf [^`]+)`", flat)}
    assert cmds == {"clock", "hypothesis list"}
    for cmd in cmds:
        with pytest.raises(SystemExit) as e:
            ctf_main([*cmd.split(), "--help"])
        assert e.value.code == 0, (cmd, capsys.readouterr().err)
