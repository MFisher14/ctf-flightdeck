"""What README.md and docs/GUIDE.md tell a player to type, held against the code.

A command a page shows is one a player copies: every `flightdeck ...` line in a code block,
and every one in a code span, names a command flightdeck has and options that command has.
The passages a release got wrong before are pinned one by one below: the scripted `start`
(run here as the guide writes it), what Autopilot needs, where a stuck player is sent, and
which installs exist. So is a new player's first five minutes: the quickstart's commands, the
home screen's choices by the names the home screen gives them, the three keys, and the words
"key" and "token".

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
from words_kit import bare

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


# ---------------------------------------------------------------------- the first five minutes


def section(markdown: str, heading: str) -> str:
    """The text under `heading` (a whole heading line, like "## Quickstart"), up to the next
    heading of its level or above. A `#` line inside a fenced block is a comment, not one."""
    level = len(heading) - len(heading.lstrip("#"))
    lines = markdown.split(f"\n{heading}\n", 1)[1].split("\n")
    fenced = False
    for at, line in enumerate(lines):
        if line.startswith(("```", "~~~")):
            fenced = not fenced
        elif not fenced and re.match(rf"#{{1,{level}}} ", line):
            return "\n".join(lines[:at])
    return "\n".join(lines)


def commands_in(block_text: str) -> list[str]:
    """The command lines of a fenced block's text, without their comments."""
    return [" ".join(shlex.split(line, comments=True)) for line in block_text.splitlines() if line.strip() and not line.lstrip().startswith("#")]


def test_section_stops_at_the_next_heading_of_its_level_and_not_at_a_comment_in_a_code_block():
    markdown = "# T\n\n## A\n\none\n\n```sh\n# not a heading\nrun\n```\n\n### A1\n\ntwo\n\n## B\n\nthree\n"
    assert section(markdown, "## A") == "\none\n\n```sh\n# not a heading\nrun\n```\n\n### A1\n\ntwo\n"
    assert section(markdown, "### A1") == "\ntwo\n" and section(markdown, "## B") == "\nthree\n"


def test_the_quickstart_is_three_commands_uv_first_with_nothing_optional_before_the_first_run():
    """Look, install, run: the README's first block of commands under Quickstart, and the
    guide's under "Install and first run" (which has no mock: its reader has seen it). uv is
    the installer both show; pipx is named in prose, as another way, and in no block before
    the first run. The solver pack is optional, so it is in no block at all."""
    readme, guide = read(README), read(GUIDE)
    quick = section(readme, "## Quickstart")
    blocks = [block.group(2) for block in _FENCE.finditer(quick)]
    assert commands_in(blocks[0]) == ["uvx ctf-flightdeck mock", "uv tool install ctf-flightdeck", "flightdeck"]
    first = section(guide, "## Install and first run")
    assert commands_in(next(_FENCE.finditer(first)).group(2)) == ["uv tool install ctf-flightdeck", "flightdeck"]
    for page, text in (("README.md", quick), ("docs/GUIDE.md", first)):
        shown = [line for block in _FENCE.finditer(text) for line in commands_in(block.group(2))]
        assert not [line for line in shown if line.split()[0] in ("pipx", "pip")], f"{page}: uv is the installer a block shows"
        assert not [line for line in shown if line.startswith("flightdeck pack")], f"{page}: the solver pack is optional: not in a block"
        assert "`pipx install ctf-flightdeck`" in text, f"{page} still says how to install with pipx"
        assert text.index("uv tool install ctf-flightdeck") < text.index("pipx install ctf-flightdeck"), f"{page}: uv comes first"
    assert "`flightdeck pack install`" in quick  # named, in prose, after the event commands
    # the same by command: what the home screen does, in the order a script runs it
    assert commands_in(blocks[1]) == ["flightdeck init", "flightdeck image build", "flightdeck doctor", "flightdeck practice"]
    llms = flat(read(ROOT / "llms.txt"))
    assert "Install: `uv tool install ctf-flightdeck` (recommended: uv brings the Python it needs), or `pipx install ctf-flightdeck`" in llms


def test_the_quickstart_names_the_home_screens_choices_as_the_home_screen_does():
    """"Get started", then "Build the lane image" when Docker lanes need it, then "Practice":
    the README's and the guide's words are the menu's own titles, in the menu's order, and
    `ctrl+s` is the key the setup form saves on."""
    from ctf_flightdeck.console import home

    first = home.items(have_config=False)[0]
    assert (first.title, first.choice) == ("Get started", ("setup", "practice"))
    after = [item.title for item in home.ready_items(home.Ready(build=True))]
    assert after[:2] == ["Build the lane image", "Practice"]
    assert [item.title for item in home.ready_items(home.Ready())][0] == "Practice"  # with the image built, practice is first
    assert any(binding.key == "ctrl+s" and binding.action == "save" for binding in home.SetupForm.BINDINGS)
    quick = flat(section(read(README), "## Quickstart"))
    assert 'flightdeck # open the home screen, and choose "Get started"' in quick
    assert "**Get started** is a form on the home screen:" in quick and "`ctrl+s` saves it." in quick
    assert quick.index("**Get started**") < quick.index("1. **Build the lane image**") < quick.index("2. **Practice**")
    guide = flat(section(read(GUIDE), "## Install and first run"))
    assert 'flightdeck # the home screen: choose "Get started", then "Practice"' in guide
    assert '"Get started", its first choice, is a form:' in guide and "`ctrl+s` saves it" in guide


def test_the_three_keys_the_quickstart_names_do_in_the_console_what_it_says():
    from ctf_flightdeck.console import fleet

    bound = {binding.key: binding.action for binding in fleet.FleetScreen.BINDINGS}
    assert fleet.OPEN_KEY == ("o", "enter", "open") and bound["a"] == "lane('approve')" and bound["question_mark"] == "app.help"
    said = "Enter opens a lane to watch it and talk to it, `a` approves a flag a lane found, and `?` lists every other key"
    assert said in flat(section(read(README), "## Quickstart")).replace("**", "")
    assert said in flat(section(read(GUIDE), "## Install and first run"))


# What the README calls a key with no more said, in the order it says it: each is one the
# player presses. A new sentence that means an API key says "API key"; one about the keyboard
# is added here.
KEYBOARD = [
    "step in with one key.",
    "and one key sends a hint",
    "You need three keys:",
    "lists every other key.",
    "every key the console takes",
    "`?` for every key.",
    "and the keys that apply now.",
]


def test_in_the_readme_a_bare_key_is_one_you_press_and_a_token_says_which_kind_it_is():
    readme = flat(read(README))
    keys = bare(readme, "key")
    unknown = [place for place in keys if not any(phrase in place for phrase in KEYBOARD)]
    assert not unknown, ("README.md says key without saying which (an API key is called one; a key the player presses goes in "
                         "KEYBOARD):\n" + "\n".join(f"...{place}..." for place in unknown))
    assert len(keys) == len(KEYBOARD) and all(phrase in place for place, phrase in zip(keys, KEYBOARD)), keys
    assert bare(readme, "token") == [], "README.md: say access token, or model tokens"
    # and the three kinds are there, each by its name
    for kind in ("an API key for a model API", "your access token for it", "400,000 model tokens"):
        assert kind in readme, kind
    # the check itself: the sentences this README had before would not pass it
    assert bare("Your config and keys stay as they are.", "key") and bare("Lanes have token and dollar caps.", "token")
    assert len(bare("models and keys, the console's keys, boards", "key")) == 2  # two meanings in one sentence, both bare


def test_the_guide_explains_its_words_second_and_names_commands_the_console_has():
    """The glossary comes right after "Install and first run", before any section that uses
    its words, and has the five a new player met undefined: wave, live instance, brief,
    command bar, park. A `/command` it names is one the console takes."""
    from ctf_flightdeck.console import commands

    guide = read(GUIDE)
    headings = re.findall(r"^## (.+)$", _FENCE.sub("", guide), re.M)
    assert headings[:3] == ["Install and first run", "Words used here", "What a run costs"]
    glossary = section(guide, "## Words used here")
    terms = [term.lower() for term in re.findall(r"^- \*\*([^*]+)\*\*", glossary, re.M)]
    assert {"wave", "live instance", "brief", "command bar", "park"} <= set(terms), terms
    assert {"board", "lane", "ladder", "caps", "l1", "light model", "lane image", "event profile", "run folder"} <= set(terms), terms
    for word in ("key", "API key", "access token", "tokens", "setting"):  # the four that are easy to mix up, and the bare one
        assert f"**{word}**" in glossary, word
    named = set(re.findall(r"`/([a-z]+)", glossary))
    assert {"new", "theme", "queue", "kill"} <= named and named <= set(commands.BY_NAME), named - set(commands.BY_NAME)
    assert "`/kill park`" in glossary and commands.BY_NAME["kill"].args == "[park]"
    assert "`/queue` puts it back in the queue" in flat(glossary) and commands.BY_NAME["queue"].help == "queue a parked or new challenge"
    # the first section sends its reader there for the words it uses
    assert "are in [Words used here](#words-used-here), the next section." in flat(section(guide, "## Install and first run"))


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
