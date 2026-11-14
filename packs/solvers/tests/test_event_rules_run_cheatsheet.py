"""R-11: the "Running engines" cheat sheet in the event agent rules (templates/event/agent-rules.md.tmpl).

The block must reach both generated files of every event, and every command it shows must be one the
master actually accepts: each `python -m ctf ...` span is parsed by the real CLI, each option it names
is in that command's help, the example engine names resolve, and `tools/ctfpy` does what the block says.
Nothing here touches the network or a challenge file."""
from __future__ import annotations

import os
import re
import shlex
import subprocess
import sys

import pytest

import inspect

from ctf import event, eventrules, paths
from ctf.cli import main as ctf_main
from ctf.engines import _boot

PAST = ("csctf", "huntress", "pink", "spooky")
HEADING = "## Running engines"


def _section(text: str) -> str:
    body = eventrules.split_header(text)[1]
    start = body.find(HEADING)
    assert start >= 0, f"no {HEADING!r} section in the rules body"
    end = body.find("\n## ", start + len(HEADING))
    return body[start:] if end < 0 else body[start:end]


def _flat(section: str) -> str:
    return re.sub(r"\n\s*", " ", section)


def _spans(section: str, prefix: str) -> list[str]:
    # Inline code spans may wrap across a line break in the rendered markdown; join them first.
    flat = re.sub(r"\n\s*", " ", section)
    return [s for s in re.findall(r"`([^`]+)`", flat) if s == prefix.strip() or s.startswith(prefix)]


@pytest.mark.parametrize("slug", PAST)
def test_committed_rules_carry_the_same_cheat_sheet_in_both_files(slug):
    d = paths.event_dir(slug)
    claude = _section((d / "CLAUDE.md").read_text(encoding="utf-8"))
    agents = _section((d / "AGENTS.md").read_text(encoding="utf-8"))
    assert claude == agents
    for needle in ("python -m ctf run --challenge-id", "tools/ctfpy", "python -m ctf engines route",
                   "python -m ctf engines show", "python -m ctf engines list", "*.manifest.toml",
                   f"CTF_EVENT={slug}", f"from `events/{slug}/`"):
        assert needle in claude, needle


@pytest.mark.parametrize("slug", PAST)
def test_fresh_render_matches_committed_section(slug):
    out = eventrules.render(event.load(slug))
    committed = (paths.event_dir(slug) / "CLAUDE.md").read_text(encoding="utf-8")
    assert _section(out["CLAUDE.md"]) == _section(committed)
    assert _section(out["AGENTS.md"]) == _section(out["CLAUDE.md"])


def test_check_event_green_for_all_four(capsys):
    assert ctf_main(["check-event", *PAST]) == 0
    out = capsys.readouterr().out
    for slug in PAST:
        assert f"ok    {slug}" in out


def _help(argv: list[str], capsys) -> str:
    with pytest.raises(SystemExit) as e:
        ctf_main([*argv, "--help"])
    out = capsys.readouterr()
    assert e.value.code == 0, f"`python -m ctf {' '.join(argv)}` is not a command: {out.err}"
    return out.out


def test_every_python_m_ctf_command_in_the_sheet_parses(capsys):
    section = _section(eventrules.render(event.load("spooky"))["CLAUDE.md"])
    checked = set()
    for span in _spans(section, "python -m ctf "):
        words = shlex.split(span)[3:]
        if not words:
            continue
        cmd = words[:2] if words[0] == "engines" else words[:1]
        help_text = _help(cmd, capsys)
        for opt in (w for w in words if w.startswith("--")):
            # Whole option only: "--file" must not pass because "--files" exists.
            assert re.search(rf"(?<![\w-]){re.escape(opt)}(?![\w-])", help_text), \
                f"{opt} is not an option of `python -m ctf {' '.join(cmd)}`"
        checked.add(" ".join(cmd))
    assert {"run", "engines route", "engines list", "engines show"} <= checked


@pytest.mark.parametrize("name", ["toolkits.network", "network"])
def test_example_engine_names_resolve(name, capsys):
    assert ctf_main(["engines", "show", name]) == 0
    assert 'id = "toolkits.network"' in capsys.readouterr().out


def _sheet_exit_code(slug: str = "spooky") -> int:
    """The exit code the sheet states for a bad engine name or missing interpreter."""
    found = re.findall(r"\(exit (\d+)\)", _flat(_section(eventrules.render(event.load(slug))["CLAUDE.md"])))
    assert len(found) == 1, f"the sheet should state one exit code, found {found}"
    return int(found[0])


def test_unknown_engine_exits_with_the_code_the_sheet_states(capsys):
    code = _sheet_exit_code()
    assert code == 2
    assert ctf_main(["run", "--no-ledger", "no-such-engine-r11"]) == code
    assert "no engine 'no-such-engine-r11'" in capsys.readouterr().err


def _ctfpy(*args: str, extra_env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    env = {k: v for k, v in os.environ.items() if not k.startswith("CTF_")}
    env["CTF_PYTHON"] = sys.executable
    env.update(extra_env or {})
    return subprocess.run([str(paths.repo_root() / "tools" / "ctfpy"), *args], env=env,
                          cwd=paths.repo_root().parent, capture_output=True, text=True, timeout=120)


def test_ctfpy_options_named_in_the_sheet_work_from_another_directory():
    section = _section(eventrules.render(event.load("pink"))["CLAUDE.md"])
    spans = _spans(section, "tools/ctfpy ")
    opts = {shlex.split(s)[1] for s in spans}
    assert {"--info", "--challenge-id", "-m", "-c"} <= opts
    ctfpy = paths.repo_root() / "tools" / "ctfpy"
    assert os.access(ctfpy, os.X_OK)

    info = _ctfpy("--info")
    assert info.returncode == 0, info.stderr
    assert str(paths.repo_root()) in info.stdout and "sys.path" in info.stdout

    # The sheet's own snippet: flat engine imports work.
    snippet = next(s for s in spans if s.startswith("tools/ctfpy -c "))
    code = shlex.split(snippet)[2] + "; print(network.__file__)"
    r = _ctfpy("--no-ledger", "-c", code)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip().endswith(os.path.join("solvers", "toolkits", "network.py"))

    # `-m ctf` from any directory, as the sheet says.
    r = _ctfpy("--no-ledger", "-m", "ctf", "engines", "show", "network")
    assert r.returncode == 0, r.stderr
    assert 'id = "toolkits.network"' in r.stdout

    code = _sheet_exit_code("pink")
    bad = _ctfpy("--no-ledger", "--challenge-id", "x", "no-such-engine-r11")
    assert bad.returncode == code and "no engine 'no-such-engine-r11'" in bad.stderr
    gone = _ctfpy("--info", extra_env={"CTF_PYTHON": str(paths.repo_root() / "no-such-python-r11")})
    assert gone.returncode == code and "not an executable interpreter" in gone.stderr


def _boot_grammar() -> tuple[set[str], set[str], set[str]]:
    """(value options, flag options, target options) that _boot.main accepts, read from its source so
    the check follows the parser. --repo and --via are set by the wrapper itself, not by people."""
    src = inspect.getsource(_boot.main)
    valued = set(re.findall(r'a == "(-[\w-]+)" and i \+ 1', src)) - {"--repo", "--via"}
    flags = set(re.findall(r'a == "(-[\w-]+)":', src))
    targets = set(re.findall(r'head == "(-[\w-]+)"', src))
    assert {"--challenge-id"} <= valued and {"--no-ledger"} <= flags
    assert {"--info", "-m", "-c", "--engine"} <= targets
    return valued, flags, targets


def test_every_ctfpy_span_in_the_sheet_uses_options_ctfpy_accepts():
    valued, flags, targets = _boot_grammar()
    section = _section(eventrules.render(event.load("huntress"))["CLAUDE.md"])
    heads = set()
    for span in _spans(section, "tools/ctfpy "):
        words = shlex.split(span)[1:]
        i = 0
        while i < len(words) and (words[i] in valued or words[i] in flags):
            if words[i] in valued:
                assert i + 1 < len(words), f"{span!r}: {words[i]} needs a value"
                i += 2
            else:
                i += 1
        assert i < len(words), f"{span!r}: no target after the options"
        head = words[i]
        if head.startswith("-"):
            assert head in targets, f"{span!r}: {head} is not an option tools/ctfpy accepts"
            if head != "--info":
                assert i + 1 < len(words), f"{span!r}: {head} needs an argument"
            heads.add(head)
        else:
            heads.add("script" if head.endswith(".py") else "engine")
    assert {"--info", "-m", "-c", "script", "engine"} <= heads


def test_ctfpy_runs_a_script_with_its_arguments(tmp_path):
    script = tmp_path / "solve.py"
    script.write_text("import sys, network\nprint('argv', sys.argv[1:])\n", encoding="utf-8")
    r = _ctfpy(str(script), "a1", "--x")
    assert r.returncode == 0, r.stderr
    assert "argv ['a1', '--x']" in r.stdout


def _instantiate(form: str, challenge_dir: str, slug: str) -> list[str]:
    """`<challenge_dir> [--opt key=value]... [--event <slug>]` -> one concrete argument list,
    taking each optional group once."""
    form = re.sub(r"\[([^\]]+)\](?:\.\.\.)?", r"\1", form)
    form = form.replace("<challenge_dir>", challenge_dir).replace("<slug>", slug)
    words = shlex.split(form)
    assert not any("<" in w or "[" in w for w in words), f"unfilled placeholder in {form!r}"
    return words


def test_contract_engine_call_form_in_the_sheet_parses(tmp_path):
    section = _section(eventrules.render(event.load("csctf"))["CLAUDE.md"])
    forms = _spans(section, "<challenge_dir>")
    assert len(forms) == 1, forms
    argv = _instantiate(forms[0], str(tmp_path), "csctf")
    challenge_dir, opts, slug = _boot._parse_opts(argv)     # the parser contract engines run through
    assert challenge_dir == str(tmp_path)
    assert opts == {"key": "value"}
    assert slug == "csctf"


def test_contract_parser_rejects_a_misnamed_option(tmp_path):
    # The check above is only worth something if the parser refuses a wrong option name.
    with pytest.raises(SystemExit):
        _boot._parse_opts([str(tmp_path), "--option", "key=value"])


def test_sheet_states_workdir_precedence_and_ctfpy_follows_it(tmp_path):
    section = _flat(_section(eventrules.render(event.load("pink"))["CLAUDE.md"]))
    assert "(`$CTF_WORKDIR`, else `CTF_EVENT=pink`, selects the workdir)" in section
    both = _ctfpy("--info", extra_env={"CTF_WORKDIR": str(tmp_path), "CTF_EVENT": "pink"})
    assert both.returncode == 0, both.stderr
    assert f"workdir  {tmp_path.resolve()}" in both.stdout
    only_event = _ctfpy("--info", extra_env={"CTF_EVENT": "pink"})
    assert only_event.returncode == 0, only_event.stderr
    assert f"workdir  {(paths.DEFAULT_WORK_BASE / 'pink').expanduser().resolve()}" in only_event.stdout
