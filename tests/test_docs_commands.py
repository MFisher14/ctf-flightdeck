"""What README.md and docs/GUIDE.md tell a player to type, held against the code.

A command a page shows is one a player copies: every `flightdeck ...` line in a code block,
and every one in a code span, names a command flightdeck has and options that command has.
The passages a release got wrong before are pinned one by one below: the scripted `start`
(run here as the guide writes it), what Autopilot needs, where a stuck player is sent, and
which installs exist.

Nothing here reaches a network: `start` is run away from a terminal with a config, a keys
file and a home folder of the test's own, and nothing is launched.
"""

from __future__ import annotations

import re
import shlex
from pathlib import Path

import pytest
import typer
from typer.testing import CliRunner

from ctf_flightdeck import cli, start
from ctf_flightdeck.autopilot import NEEDS_BUDGET, NEEDS_DOCKER
from ctf_flightdeck.setup import Answers, doctor, report, write_config

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
GUIDE = ROOT / "docs" / "GUIDE.md"
SECRET = "ctfd_0123456789abcdef0123456789abcdef"  # synthetic: no site issued it

_FENCE = re.compile(r"^(```|~~~)[^\n]*\n(.*?)^\1[^\n]*$", re.M | re.S)
_SPAN = re.compile(r"`([^`\n]+)`")
_SHELL = {"|", "||", "&&", ";", "<", ">", ">>"}  # where a command line stops being flightdeck's


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def flat(markdown: str) -> str:
    """`markdown` with every run of white space as one space: a sentence reads the same
    however its lines are wrapped."""
    return " ".join(markdown.split())


def block_lines(markdown: str) -> list[str]:
    """The lines of every fenced block, a line that ends in a backslash joined to the next."""
    lines = []
    for block in _FENCE.finditer(markdown):
        lines += [line.strip() for line in re.sub(r"\\\n", " ", block.group(2)).splitlines()]
    return lines


def command_lines(markdown: str) -> list[str]:
    """Every `flightdeck ...` command `markdown` shows: the lines of its fenced blocks (after a
    `$ ` prompt too), and the code spans of its prose (one may wrap onto the next line)."""
    found = [line for line in (re.sub(r"^\$\s+", "", line) for line in block_lines(markdown)) if line.startswith("flightdeck ")]
    prose = re.sub(r"(?<!\n)\n(?!\n)", " ", _FENCE.sub("", markdown))
    return found + [span.group(1) for span in _SPAN.finditer(prose) if span.group(1).startswith("flightdeck ")]


def options_of(command) -> set[str]:
    return {name for param in command.params for name in (*param.opts, *param.secondary_opts) if name.startswith("-")} | {"--help"}


def problems(line: str, root=None) -> list[str]:
    """What is wrong with one `flightdeck ...` command line, one entry each: a command that
    does not exist, or a --option the command it names does not have."""
    root = typer.main.get_command(cli.app) if root is None else root
    try:
        words = shlex.split(line, comments=True)
    except ValueError as exc:
        return [f"cannot be read as a command line ({exc})"]
    command, path, at = root, ["flightdeck"], 1
    while hasattr(command, "commands") and at < len(words) and not words[at].startswith("-"):
        sub = command.commands.get(words[at])
        if sub is None:
            if any(type(param).__name__.endswith("Argument") for param in command.params):
                break  # this group takes an argument of its own (preflight EVENT.toml)
            return [f"{' '.join(path)} has no command {words[at]}"]
        command, at = sub, at + 1
        path.append(words[at - 1])
    known = options_of(command)
    found = []
    for word in words[at:]:
        if word in _SHELL:
            break
        name = word.split("=", 1)[0]
        if name.startswith("--") and len(name) > 2 and name not in known:
            found.append(f"{' '.join(path)} has no option {name}")
    return found


# ---------------------------------------------------------------------- every command shown


@pytest.mark.parametrize("page", [README, GUIDE], ids=lambda page: page.name)
def test_every_flightdeck_command_a_page_shows_names_a_command_and_options_it_has(page):
    lines = command_lines(read(page))
    assert len(lines) >= 10, f"{page.name} shows hardly any flightdeck command: the check would pass on nothing"
    wrong = [f"{problem}: {line}" for line in lines for problem in problems(line)]
    assert not wrong, f"{page.name} shows what flightdeck does not have (see `flightdeck <command> --help`):\n" + "\n".join(wrong)


def test_a_command_or_option_that_does_not_exist_is_reported_and_a_real_line_is_not():
    assert problems("flightdeck start --name X --token-file token.txt --no-launch") == ["flightdeck start has no option --token-file"]
    assert problems("flightdeck strat --name X") == ["flightdeck has no command strat"]
    assert problems("flightdeck pack info --no-such=1") == ["flightdeck pack info has no option --no-such"]
    assert problems("flightdeck vpn sideways ~/ctf/example-ctf") == ["flightdeck vpn has no command sideways"]
    assert problems('flightdeck start --name "Unclosed') == ["cannot be read as a command line (No closing quotation)"]
    for real in (
        "flightdeck",
        "flightdeck --version",
        "flightdeck start --help",
        "flightdeck play ~/ctf/example-ctf --autopilot --budget-dollars 20   # Autopilot, inside a run budget",
        "flightdeck pack install --yes",
        "flightdeck doctor | grep --color FAIL",  # past the pipe it is another program's line
        "flightdeck preflight event.toml",
    ):
        assert problems(real) == [], real


def test_command_lines_come_from_code_blocks_and_code_spans_and_from_nowhere_else():
    markdown = (
        "Run `flightdeck doctor` first, then `flightdeck start\n--help`. The word flightdeck play in prose is not one,\n"
        "nor is `uv tool install ctf-flightdeck`.\n\n"
        "```sh\n$ flightdeck mock\nflightdeck start --name X \\\n    --no-launch\necho flightdeck play\n```\n"
    )
    assert command_lines(markdown) == ["flightdeck mock", "flightdeck start --name X      --no-launch", "flightdeck doctor", "flightdeck start --help"]


# ---------------------------------------------------------------------- a scripted start


def test_start_takes_the_token_from_a_variable_or_a_pipe_never_as_a_value_and_the_guide_and_llms_txt_say_so():
    """A token given as an option's value would stay in the shell's history and show in the
    process list: `start` has --token-env NAME and --token-stdin, and no option that takes the
    token itself. The guide and llms.txt name both."""
    command = typer.main.get_command(cli.app).commands["start"]
    assert sorted(name for name in options_of(command) if "token" in name) == ["--token-env", "--token-stdin"]
    guide = flat(read(GUIDE))
    assert "no option takes it, because a command line stays in your shell's history" in guide
    assert "`--token-env NAME` reads it from the environment variable you name" in guide and "`--token-stdin` from a pipe" in guide
    llms = flat((GUIDE.parent.parent / "llms.txt").read_text(encoding="utf-8"))
    assert "`--token-env NAME` or `--token-stdin`" in llms


# ---------------------------------------------------------------------- the README's own claims


def test_the_readme_says_what_autopilot_needs_and_its_example_gives_the_budget():
    """Autopilot does not engage off Docker or without a run budget (autopilot.py's two
    refusals), so the README says both, and the line it shows carries a budget."""
    readme = read(README)
    assert "needs the Docker runtime" in NEEDS_DOCKER and "needs a run budget" in NEEDS_BUDGET
    assert "`--autopilot` needs Docker lanes and a run budget." in flat(readme)
    budgets = set(re.findall(r"--budget-\w+", NEEDS_BUDGET))
    assert budgets == {"--budget-dollars", "--budget-tokens"}
    shown = [line for line in command_lines(readme) if "--autopilot" in line.split()]
    assert shown, "README.md shows no --autopilot line"
    for line in shown:
        assert budgets & set(shlex.split(line, comments=True)), f"as written this stops with: {NEEDS_BUDGET}\n{line}"
    assert "give its budget in tokens (`--budget-tokens`)" in flat(readme)  # a model with no price: dollars cannot hold it


def test_the_readme_sends_a_stuck_player_to_doctor_which_gives_a_fix_and_not_to_the_home_screen(tmp_path, monkeypatch):
    assert "Stuck? `flightdeck doctor` checks your setup and says how to fix each problem." in flat(read(README))
    monkeypatch.delenv("FLIGHTDECK_TEST_KEY", raising=False)
    made = write_config(Answers("https://openrouter.ai/api/v1", "FLIGHTDECK_TEST_KEY", ("a/b",), "host"), tmp_path / "c.toml")
    checks = doctor(made, environ={"FLIGHTDECK_KEYS": str(tmp_path / "absent.env")})
    key = {check.name: check for check in checks}["api key"]
    assert not key.ok and key.fix
    lines = report(checks)[0].splitlines()
    assert lines[lines.index(f"FAIL api key: {key.detail}") + 1] == f"     fix: {key.fix}"
    # `flightdeck` alone, at a terminal, opens the home screen: it is not where "what to do next" is said
    opened = []
    monkeypatch.setattr(cli, "_at_terminal", lambda: True)
    monkeypatch.setattr(cli, "_at_terminal_out", lambda: True)
    monkeypatch.setattr(cli, "_home", lambda: opened.append("home"))
    alone = CliRunner().invoke(cli.app, [])
    assert alone.exit_code == 0 and opened == ["home"] and "flightdeck doctor" not in alone.output


def test_the_guide_offers_the_deb_a_release_builds_and_no_homebrew_tap_while_there_is_none():
    guide = read(GUIDE)
    section = guide.split("\n### Install with Homebrew or apt\n", 1)[1].split("\n## ", 1)[0]
    shown = block_lines(section)
    assert any(line.startswith("sudo apt install ./ctf-flightdeck_") for line in shown), shown
    # apt: what the release workflow builds and attaches, since the release whose notes say so
    workflow = read(ROOT / ".github" / "workflows" / "release.yml")
    assert "runner: [ubuntu-latest, ubuntu-24.04-arm]  # amd64 and arm64" in workflow and "debs/SHA256SUMS" in workflow
    notes = read(ROOT / "CHANGELOG.md").split("\n## 0.3.0 ", 1)[1].split("\n## ", 1)[0]
    assert "the `.deb` for amd64 or arm64 on the GitHub release" in flat(notes)
    assert "**apt:** from 0.3.0 on, each release's page has a `.deb` for amd64 and for arm64, with a `SHA256SUMS` file" in flat(section)
    # Homebrew: the roadmap says the tap is not made yet, so the guide shows no brew command to copy.
    # When the tap exists, the roadmap, the guide's paragraph and this test change together.
    assert "The tap repository and its token are the maintainer's to create, and no `brew install` of the formula has been run yet." in flat(
        read(ROOT / "docs" / "ROADMAP.md"))
    assert not [line for line in shown if line.split()[:1] == ["brew"]], "a brew command in a code block is one a player copies"
    assert "**Homebrew:** not yet. flightdeck's tap does not exist yet" in flat(section)
    assert "PyPI only" not in section  # 0.2.0 is long past: no release is "the first with a .deb" still to come
