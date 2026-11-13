"""B-043: brief discipline (ctf/briefdiscipline.py, ctf/cli/discipline.py) and every generator that
must carry it: the dispatch handout, the orchestrator brief and RULES, the standby plan, the codex
handoff prompt and the event agent-rules template. Plus the denial text naming the fix (the orch
guard) and the sanctioned helper. All fixtures are synthetic; nothing reaches a network or a model."""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from ctf import briefdiscipline as bd
from ctf import cli, dispatch, eventrules, orch, permissions, standby
from ctf import event as _event

REPO = Path(__file__).resolve().parent.parent


def _carries(text: str) -> None:
    assert bd.missing(text) == [], f"brief lacks discipline rules: {bd.missing(text)}"
    assert bd.HEADING.lower() in text.lower()


# ------------------------------------------------------------------------------------------- module

def test_rules_cover_the_four_named_disciplines():
    assert bd.RULE_IDS == ("absolute-paths", "one-command", "literal-program", "plain-git")
    md = bd.rules_md()
    assert md.startswith("## Command discipline\n")
    assert bd.rules_md(heading_level=3).startswith("### Command discipline\n")
    for r in bd.RULES:
        assert f"(`{r.id}`)" in md
    plain = bd.rules_plain()
    assert "#" not in plain.splitlines()[0] and "**" not in plain
    for r in bd.RULES:
        assert f"({r.id})" in plain
    # the substance of each rule, as the spec states it
    flat = " ".join(md.split())
    assert "absolute path" in flat and "`cd DIR && ...`" in flat
    assert "one command" in flat and "`&&`" in flat and "`;`" in flat
    assert "never a variable, `$(...)`" in flat
    assert "/abs/repo/tools/ctfpy -m ctf worktree-commit" in flat


def test_helper_commands_are_spelled_to_run_from_any_folder():
    # ctf is not installed in .venv: a bare `python -m ctf` works only with the checkout as cwd,
    # which rule absolute-paths forbids relying on. Every helper the block names goes through ctfpy.
    for text in (bd.rules_md(), bd.rules_plain()) + tuple(r.fix for r in bd.RULES):
        flat = " ".join(text.split())
        assert "python -m ctf" not in flat.replace("bare `python -m ctf`", ""), text
    flat = " ".join(bd.rules_md().split())
    assert "`/abs/repo/tools/ctfpy -m ctf discipline check -- \"<command>\"`" in flat
    assert "/abs/repo/tools/ctfpy -m ctf worktree-commit" in bd.RULES[3].fix


def test_ctfpy_runs_the_helper_from_outside_the_checkout(tmp_path):
    # the spelling the brief gives works with a cwd that is not the checkout (a challenge workspace)
    r = subprocess.run([str(REPO / "tools" / "ctfpy"), "-m", "ctf", "discipline", "check", "--",
                        "git -C /abs/wt status"], cwd=tmp_path, text=True, capture_output=True,
                       timeout=120)
    assert r.returncode == 0, r.stderr
    assert r.stdout.startswith("ok")


def test_missing_names_each_absent_rule_and_ignores_wrapping():
    md = bd.rules_md()
    assert bd.missing(md) == []
    assert bd.missing(bd.rules_plain()) == []
    rewrapped = "\n    ".join(md.split(" "))                       # any line wrapping still counts
    assert bd.missing(rewrapped) == []
    cut = md.replace(bd.RULES[1].text[:40], "")
    assert bd.missing(cut) == ["one-command"]
    assert bd.missing("") == list(bd.RULE_IDS)


@pytest.mark.parametrize("cmd", [
    "git -C /abs/wt status",
    "/abs/repo/.venv/bin/python -m pytest /abs/repo/tests/test_x.py",
    "cat /abs/file | head -5",
    "grep -n foo /abs/a 2>&1 | sort",
    "python3 -c 'a=1; b=2 && 3'",                      # operators inside quotes are not a chain
    'echo "x; y && z"',
    "FOO=1 /usr/bin/env python3 /abs/s.py",
    "sleep 5 &",                                       # a trailing & chains nothing
    "ls /abs/dir;",
    "python3 /abs/a.py \\\n  --flag x",               # a line continuation is one command
    "ls ~/x",
    "~/bin/tool /abs/x",                               # a ~ program path is absolute to a guard
    'echo "a\\"; b"',                                  # an escaped quote stays inside the quotes
    "/abs/run.sh &> /abs/log",                          # &> and >& are redirections, not chains
    "cat /abs/a |& grep x",
])
def test_clean_commands_pass(cmd):
    assert bd.check(cmd) == []
    assert bd.fix_hint(cmd) == ""


@pytest.mark.parametrize("cmd,rules", [
    ("cd /abs/wt && git status", {"absolute-paths", "one-command", "plain-git"}),
    ("ls ../secrets", {"absolute-paths"}),
    ("pushd /abs/x", {"absolute-paths"}),
    ("ls /abs/x/..", {"absolute-paths"}),
    ("cat ./notes.md", {"absolute-paths"}),
    ("cat /a/b/../c", {"absolute-paths"}),
    ("tools/ctfpy -m ctf status", {"absolute-paths"}),
    (".venv/bin/python -m pytest", {"absolute-paths"}),
    ("echo a; echo b", {"one-command"}),
    ("make || true", {"one-command"}),
    ("echo a\necho b", {"one-command"}),
    ("sleep 1 & echo b", {"one-command"}),
    ("$PY -m ctf status", {"literal-program"}),
    ("${PY} -m ctf", {"literal-program"}),
    ("$(which python3) x.py", {"literal-program"}),
    ("`which python3` x.py", {"literal-program"}),
    ('eval "$CMD"', {"literal-program"}),
    ("timeout 5 $X arg", {"literal-program"}),
    ('bash -c "$(cat /abs/cmd)"', {"literal-program"}),
    ("git add -A && git commit -m x", {"one-command", "plain-git"}),
    ("git status | git log", {"plain-git"}),
    ("cd /abs/wt | git status", {"absolute-paths", "plain-git"}),   # a pipe, not a chain: the cd counts
    ("c\\\nd /abs/wt", {"absolute-paths"}),                       # a line continuation joins `cd`
])
def test_violations_are_named_by_rule(cmd, rules):
    vs = bd.check(cmd)
    assert {v.rule for v in vs} == rules
    hint = bd.fix_hint(cmd)
    assert hint.startswith("Fix the command style")
    for v in vs:
        assert v.fix in hint and v.fix == next(r.fix for r in bd.RULES if r.id == v.rule)


def test_computed_program_is_shown_whole():
    (v,) = bd.check("$(command -v python3) /abs/a.py")
    assert v.rule == "literal-program" and "$(command -v python3)" in v.detail


def test_check_refuses_a_non_string():
    with pytest.raises(TypeError):
        bd.check(["ls"])


# ---------------------------------------------------------------------------------------- generators

def _profile():
    return _event.load("huntress")


def test_dispatch_handout_carries_it(tmp_path):
    h = dispatch.handout_md(dispatch.Detected("7", "Night Clerk", "Forensics"), _profile(), workdir=tmp_path)
    _carries(h)
    assert "## Command discipline" in h


def test_orch_brief_and_rules_carry_it(tmp_path):
    assert any("absolute paths, one command per call" in r for r in orch.RULES)
    text = orch.brief_md(tmp_path, wall=lambda: 0.0)
    _carries(text)
    assert text.index("## Command discipline") < text.index("## Waiting on the player")


def test_standby_plan_carries_it(capsys):
    rows = standby.plan(2)
    for r in rows:
        _carries(r["brief"])
        # plain text, as the docstring promises: the launch prompt is not markdown
        assert r["brief"] == bd.rules_plain()
        assert "**" not in r["brief"] and not any(
            line.startswith("#") for line in r["brief"].splitlines())
    assert cli.main(["standby", "plan", "--size", "2"]) == 0
    out = capsys.readouterr().out
    _carries("\n".join(line.lstrip("#") for line in out.splitlines()))     # printed as comment lines
    assert all(line.startswith("#") or "\t" in line for line in out.splitlines())  # argv rows stay parseable
    assert cli.main(["standby", "plan", "--size", "1", "--json"]) == 0
    _carries(json.loads(capsys.readouterr().out)[0]["brief"])


def test_event_template_renders_it_into_both_agent_files():
    files = eventrules.render(_profile())
    for name in ("CLAUDE.md", "AGENTS.md"):
        _carries(files[name])
        assert "\n## Command discipline\n" in files[name]
    # a change to the discipline marks the generated files stale (it is in the profile digest)
    assert eventrules.context(_profile(), "CLAUDE.md", "t")["brief_discipline"] == bd.rules_md().rstrip("\n")


def test_committed_event_files_carry_it():
    for ev in sorted((REPO / "events").glob("*/event.toml")):
        for name in ("CLAUDE.md", "AGENTS.md"):
            _carries((ev.parent / name).read_text())


def _fake_codex(tmp_path: Path) -> None:
    p = tmp_path / "codex"
    p.write_text("#!/bin/bash\nexit 0\n")
    p.chmod(0o755)


def _handoff_env(tmp_path: Path) -> dict:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("CODEX_", "CTF_EVENT", "CTF_FLAG_HINT"))}
    env.update(CODEX_BIN=str(tmp_path / "codex"), CODEX_PREFLIGHT_DIR=str(tmp_path / "pf"),
               TMPDIR=str(tmp_path), CTF_WORKDIR=str(tmp_path / "ws"))
    return env


def test_codex_handoff_prompt_carries_it(tmp_path):
    _fake_codex(tmp_path)
    ws = tmp_path / "ws" / "42-babyrev"
    ws.mkdir(parents=True)
    r = subprocess.run(["bash", str(REPO / "tools" / "codex_handoff.sh"), "--event", "X", "--challenge",
                        str(ws), "--brief"], input="try xor", text=True, capture_output=True,
                       env=_handoff_env(tmp_path), timeout=120)
    assert r.returncode == 0, r.stderr
    brief = (ws / "codex_brief.md").read_text()
    _carries(brief)
    assert "COMMAND DISCIPLINE" in brief
    # the prompt's own paths obey the rule it states
    assert f"{REPO}/tools/sandbox.py" in brief and f"{REPO}/ctf/triage.py" in brief


_STUB_PY = """#!/bin/bash
# a stand-in .venv python: the real interpreter with the real ctf on its path, except that
# `-m ctf discipline --plain` misbehaves as STUB_DISCIPLINE says
if [ "$1 $2 $3 $4" = "-m ctf discipline --plain" ]; then
  case "$STUB_DISCIPLINE" in
    fail) echo "stub: discipline broke" >&2; exit 3;;
    empty) exit 0;;
  esac
fi
PYTHONPATH={repo} exec {py} "$@"
"""


@pytest.mark.parametrize("mode,reason", [
    ("fail", "cannot render the command discipline"),
    ("empty", "the command discipline rendered empty"),
])
def test_codex_handoff_fails_loudly_without_the_discipline(tmp_path, mode, reason):
    # a copy of the script in a stub checkout whose .venv python cannot render the block: the
    # handoff stops with exit 2 and a named reason, and writes no brief without the discipline
    import sys
    stub = tmp_path / "stubrepo"
    (stub / "tools").mkdir(parents=True)
    (stub / ".venv" / "bin").mkdir(parents=True)
    (stub / "tools" / "codex_handoff.sh").write_text((REPO / "tools" / "codex_handoff.sh").read_text())
    py = stub / ".venv" / "bin" / "python"
    py.write_text(_STUB_PY.replace("{repo}", str(REPO)).replace("{py}", sys.executable))
    py.chmod(0o755)
    _fake_codex(tmp_path)
    ws = tmp_path / "ws" / "42-babyrev"
    ws.mkdir(parents=True)
    env = _handoff_env(tmp_path) | {"STUB_DISCIPLINE": mode}
    r = subprocess.run(["bash", str(stub / "tools" / "codex_handoff.sh"), "--event", "X", "--challenge",
                        str(ws), "--brief"], input="try xor", text=True, capture_output=True,
                       env=env, timeout=120)
    assert r.returncode == 2, (r.stdout, r.stderr)
    assert f"codex_handoff: {reason}" in r.stderr
    assert not (ws / "codex_brief.md").exists()
    # the same stub with a working discipline writes the brief: the failure above is the block's
    env["STUB_DISCIPLINE"] = "ok"
    r = subprocess.run(["bash", str(stub / "tools" / "codex_handoff.sh"), "--event", "X", "--challenge",
                        str(ws), "--brief"], input="try xor", text=True, capture_output=True,
                       env=env, timeout=120)
    assert r.returncode == 0, r.stderr
    _carries((ws / "codex_brief.md").read_text())


# --------------------------------------------------------------------------------- denial and helper

def _guard(tmp_path, command, cwd):
    wd = tmp_path / "event"
    (wd / "7-chal").mkdir(parents=True)
    hook = {"tool_name": "Bash", "tool_input": {"command": command}, "cwd": str(cwd or wd)}
    return orch.guard_decision(hook, workdir=wd)


def test_guard_denial_names_the_style_fix(tmp_path):
    ok, reason = _guard(tmp_path, "cd 7-chal && $PY solve.py", None)
    assert not ok
    assert "orch status" in reason                                   # the orchestrator fix stays
    assert "split the chain into separate tool calls" in reason
    assert "not $VAR" in reason and "drop the `cd` prefix" in reason
    # the style fix comes after the role fix and says it does not lift the role denial
    assert reason.index("orch status") < reason.index("Fix the command style")
    assert reason.endswith(orch.ROLE_DENIAL_STANDS)
    assert "delegate it" in orch.ROLE_DENIAL_STANDS


def test_guard_denial_of_a_clean_command_adds_no_style_hint(tmp_path):
    ok, reason = _guard(tmp_path, f"cat {tmp_path / 'event' / '7-chal' / 'x'}", tmp_path)
    assert not ok
    assert "Fix the command style" not in reason
    assert orch.ROLE_DENIAL_STANDS not in reason


def test_guard_allows_unchanged_and_carries_no_hint(tmp_path):
    ok, reason = _guard(tmp_path, "echo a; echo b", tmp_path)
    assert ok and "Fix the command style" not in reason


def test_discipline_is_a_sanctioned_helper():
    h = permissions.SANCTIONED_HELPERS["discipline"]
    assert "guard-denied" in h.replaces
    discovered = {name for name, mod, err in cli.discover() if mod is not None}
    assert "discipline" in discovered


def test_cli_prints_and_checks(capsys):
    assert cli.main(["discipline"]) == 0
    assert capsys.readouterr().out == bd.rules_md()
    assert cli.main(["discipline", "--plain"]) == 0
    assert capsys.readouterr().out == bd.rules_plain()
    assert cli.main(["discipline", "check", "--", "cd /x && git status"]) == 1
    out = capsys.readouterr().out
    assert "one-command: commands chained with &&" in out and "fix: split the chain" in out
    assert cli.main(["discipline", "check", "--", "git", "-C", "/abs", "status"]) == 0
    assert capsys.readouterr().out.startswith("ok")
    assert cli.main(["discipline", "check"]) == 2
    # argparse leaves the `--` in the REMAINDER list: the CLI strips it, so the program checked is
    # the command's own first word, not `--`
    assert cli.main(["discipline", "check", "--", "$PY -m ctf status"]) == 1
    assert "literal-program: a computed program name: $PY" in capsys.readouterr().out
    assert cli.main(["discipline", "check", "--"]) == 2


@pytest.mark.parametrize("words,rule", [
    (["ls", "../secrets"], "absolute-paths"),            # the problem is in a later word, not the first
    (["echo", "a;", "echo", "b"], "one-command"),
])
def test_cli_checks_every_unquoted_word(capsys, words, rule):
    # the command given as several words (not one quoted argument) is checked whole, not its first word
    assert cli.main(["discipline", "check", "--", *words]) == 1
    out = capsys.readouterr().out
    assert out.startswith(f"{rule}: ")
    assert f"fix: {next(r.fix for r in bd.RULES if r.id == rule)}" in out


# ------------------------------------------------------------------------- helpers spelled absolute

def test_ctf_command_spells_the_helper_from_the_checkout(tmp_path):
    assert bd.ctf_command("orch status") == f"{REPO.resolve()}/tools/ctfpy -m ctf orch status"
    assert bd.ctf_command("  run x ", repo=tmp_path) == f"{tmp_path.resolve()}/tools/ctfpy -m ctf run x"
    assert bd.ctf_command("", repo=tmp_path) == f"{tmp_path.resolve()}/tools/ctfpy -m ctf"
    spaced = tmp_path / "a b"
    assert bd.ctf_command("status", repo=spaced) == f"'{spaced.resolve()}/tools/ctfpy' -m ctf status"
    # the spelling obeys the discipline it serves
    assert bd.check(bd.ctf_command("orch status")) == []


def test_generated_text_names_no_bare_python_m_ctf(tmp_path):
    # denials, the orch rules and brief, and the handout spell each helper to run from any folder
    ctfpy = f"{REPO.resolve()}/tools/ctfpy -m ctf"
    assert f"`{ctfpy} orch status`" in orch._DENY.format("x")
    assert f"`{ctfpy} orch report`" in orch._DENY.format("x")
    text = orch.brief_md(tmp_path, wall=lambda: 0.0)
    h = dispatch.handout_md(dispatch.Detected("7", "Night Clerk", "Forensics"), _profile(), workdir=tmp_path)
    # the handout's own sections; the solver contract section (B-172, ctf/solver_contract.py) is
    # another item's text and is left as it is (a follow-up in docs/build-log/B-043.md)
    h_own = h.split("## solver contract")[0] + h.split("## Command discipline")[1]
    for t in (text, h_own, *orch.RULES):
        # the block's own "a bare `python -m ctf` works only ..." warning is the one allowed mention
        assert "python -m ctf" not in " ".join(t.split()).replace("bare `python -m ctf`", ""), t
    assert f"{ctfpy} orch status\n" in text.split("## Resume")[1]
    assert f"{ctfpy} orch brief" in text
    assert f"{ctfpy} submit 7 '<FLAG>'" in h
    assert f"`{ctfpy} run <engine-id> </abs/file>`" in h
    for r in orch.RULES[:3]:
        assert ctfpy in r


def test_guard_shortcut_takes_the_spelling_the_denial_gives(tmp_path):
    # the command a denial recommends passes the guard even from inside a challenge folder, as
    # `python -m ctf orch status` does; a non-shortcut ctfpy command still gets the full check
    wd = tmp_path / "event"
    ok, reason = _guard(tmp_path, "cat x", wd / "7-chal")         # _guard makes wd/7-chal
    assert not ok
    recommended = reason.split("Read `", 1)[1].split("`", 1)[0]
    assert recommended == bd.ctf_command("orch status")
    hook = {"tool_name": "Bash", "tool_input": {"command": recommended}, "cwd": str(wd / "7-chal")}
    assert orch.guard_decision(hook, workdir=wd)[0]
    bad = f"{REPO}/tools/ctfpy -m ctf run --file {wd}/7-chal/files/a.bin"
    hook = {"tool_name": "Bash", "tool_input": {"command": bad}, "cwd": str(tmp_path)}
    assert not orch.guard_decision(hook, workdir=wd)[0]
    hook = {"tool_name": "Bash", "tool_input": {"command": f"{REPO}/tools/notctfpy -m ctf orch status"},
            "cwd": str(wd / "7-chal")}
    assert not orch.guard_decision(hook, workdir=wd)[0]


def test_event_files_define_the_short_helper_spelling_first():
    files = eventrules.render(_profile())
    for name in ("CLAUDE.md", "AGENTS.md"):
        body = files[name].split("<!-- end of header", 1)[1]
        flat = " ".join(body.split())
        note = "`python -m ctf ...` stands for `/abs/repo/tools/ctfpy -m ctf ...`"
        assert note in flat
        # the note comes before the body's first use of the shorthand
        assert flat.index(note) <= flat.index("python -m ctf")
        assert "run it as `/abs/repo/tools/ctfpy -m ctf`, which works from any directory" in flat
