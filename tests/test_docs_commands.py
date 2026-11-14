"""What README.md and docs/GUIDE.md tell a player to type, held against the code.

A command a page shows is one a player copies: every `flightdeck ...` line in a code block,
and every one in a code span, names a command flightdeck has and options that command has.
The guide's scripted `start` is run here as the guide writes it.

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
    assert problems("flightdeck start --name X --token-stdin --no-launch < token.txt") == ["flightdeck start has no option --token-stdin"]
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


def scripted_start() -> str:
    """The guide's passage on `start` from a script: from "For a script" to "By hand"."""
    guide = read(GUIDE)
    assert guide.count("\nFor a script, ") == 1 and "\nBy hand (a site that is not CTFd)" in guide, "the guide's passage on a scripted start has moved"
    return guide.split("\nFor a script, ", 1)[1].split("\nBy hand (a site that is not CTFd)", 1)[0]


def test_start_has_no_option_for_the_token_and_the_guide_says_so_and_where_it_goes_instead():
    """The guide tells a script that the token is the one answer `start` takes no option for.
    The day `start` gets one, this fails: the passage (and llms.txt's line on `start`) is
    rewritten with it, from what the option does."""
    command = typer.main.get_command(cli.app).commands["start"]
    for_the_token = sorted(name for name in options_of(command) if "token" in name)
    assert for_the_token == [], f"start has an option for the token now ({', '.join(for_the_token)}): the guide says it has none"
    passage = flat(scripted_start())
    assert passage.startswith("every question but the token has an option (`flightdeck start --help`)")
    assert f"`{start.token_variable('Example CTF')}` for \"Example CTF\"" in passage
    assert "in your environment or your keys file" in passage


def test_the_guides_scripted_start_runs_as_written_and_reads_the_token_from_the_variable_it_names(tmp_path, monkeypatch):
    lines = block_lines(scripted_start())
    exported = [match.group(1) for line in lines if (match := re.match(r"export (\w+)=", line))]
    starts = [line for line in lines if line.startswith("flightdeck start ")]
    plays = [line for line in lines if line.startswith("flightdeck play ")]
    assert (len(exported), len(starts), len(plays)) == (1, 1, 1), lines
    variable = exported[0]
    arguments = shlex.split(starts[0], comments=True)[1:]
    played = shlex.split(plays[0], comments=True)[2]
    assert played.startswith("~/"), played

    config = tmp_path / "config.toml"
    config.write_text('[models]\nladder = ["m"]\n[lanes]\nruntime = "host"\n')
    keys_file = tmp_path / "keys.env"
    monkeypatch.setenv("FLIGHTDECK_CONFIG", str(config))
    monkeypatch.setenv("FLIGHTDECK_KEYS", str(keys_file))
    monkeypatch.setattr(cli, "_at_terminal", lambda: False)
    launched = []
    monkeypatch.setattr(cli, "play", lambda **kwargs: launched.append(kwargs))

    # as written: the variable is exported, then start
    home = tmp_path / "with"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv(variable, SECRET)
    result = CliRunner().invoke(cli.app, arguments)
    folder = home / played[2:]
    assert result.exit_code == 0, result.output
    assert f"token: {variable} is already set in your environment" in result.output and SECRET not in result.output
    assert (folder / "event.toml").is_file(), "the folder the guide then plays is not the one start made"
    assert f"play: flightdeck play {folder}" in result.output.splitlines() and launched == []
    assert SECRET not in (folder / "event.toml").read_text() and not keys_file.exists()

    # "Without the variable, start still sets the event up and says which variable to put the token in"
    assert "Without the variable, `start` still sets the event up and says which variable to put the token in" in flat(scripted_start())
    home = tmp_path / "without"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv(variable)
    result = CliRunner().invoke(cli.app, arguments)
    assert result.exit_code == 0, result.output
    assert f"token: not set yet. Put {variable}=<your CTFd access token> in {keys_file} (chmod 600)" in result.output
    assert (home / played[2:] / "event.toml").is_file() and launched == []

