"""The `flightdeck` command line: options, the live console it opens, and the headless
screenshot mode.

Opening the live console is tested by replacing FlightdeckApp.run, so the app is built
exactly as the CLI builds it but no UI starts. Screenshot runs are slow (3 to 7 s each),
so each one runs once per module and several tests read its files:

- the default scenario, plain;
- the default scenario with --solo --host --max-lanes 12 (one run for three overrides);
- the flag scenario twice, into nested directories that do not exist yet.

One more flag run, with a literal "~" in the path, belongs to its own test.
"""

from __future__ import annotations

import errno
import html
import os
import re
import sys
import tomllib
import types
from dataclasses import dataclass
from pathlib import Path

import pytest
from rich.cells import cell_len
from typer.testing import CliRunner

from ctf_flightdeck import cli
from ctf_flightdeck.console.app import FlightdeckApp
from ctf_flightdeck.core.model import COURSE_ALERTS
from ctf_flightdeck.mock import scenarios, screenshots
from ctf_flightdeck.mock.scenarios import ReleaseAt

ROOT = Path(__file__).resolve().parents[1]
runner = CliRunner()

# The default scenario's moments, in the order they are shot. "alert" is alert-<tag>.
MOMENTS = (
    "open", "wave-drop", "alert", "command-menu", "focus-lane", "chat", "focus-after", "diff",
    "approve-pending", "approve-submit", "team-stop", "attention-sort", "narrow-120x36",
    "fork-prompt", "kill-prompt", "take-over", "challenge-card", "help",
)
COURSE_TAGS = {kind.tag: kind for kind in COURSE_ALERTS}
ALERT_SHOT = rf"alert-(?:{'|'.join(COURSE_TAGS)})"


def invoke(*args: str, prog: str = "flightdeck"):
    return runner.invoke(cli.app, list(args), prog_name=prog)


def flat(output: str) -> str:
    """CLI output without Rich's box lines, whitespace collapsed: a wrapped message reads as one line."""
    return " ".join(re.sub(r"[│╭╮╰╯─]", " ", output).split())


# ---------------------------------------------------------------------- SVG screenshots as text

SPAN = re.compile(r'<text class="[^"]*-r\d+" x="([\d.]+)" y="([\d.]+)" textLength="([\d.]+)"[^>]*>(.*?)</text>')
CLIP = re.compile(r'-clip-terminal">\s*<rect x="0" y="0" width="([\d.]+)"')


def _span(x: str, length: str, body: str) -> tuple[int, str, float]:
    """(column, text, cell width) of one <text> span. Rich puts a span at x = column * cell
    width with textLength = cell width * len(text), and draws no span for runs of spaces."""
    text = html.unescape(body).replace("\xa0", " ")
    cell = float(length) / len(text)
    return round(float(x) / cell), text, cell


def rows(path: Path) -> list[list[str]]:
    """The screenshot's lines as lists of terminal cells (a wide character's second cell is "")."""
    lines: dict[float, list[str]] = {}
    for x, y, length, body in SPAN.findall(path.read_text(encoding="utf-8")):
        col, text, _ = _span(x, length, body)
        cells = [part for ch in text for part in ((ch, "") if cell_len(ch) == 2 else (ch,))]
        line = lines.setdefault(float(y), [])
        line.extend(" " * (col - len(line)))
        line[col : col + len(cells)] = cells
    return [lines[y] for y in sorted(lines)]


def screen_text(path: Path) -> str:
    return "\n".join("".join(line) for line in rows(path))


def widest(path: Path) -> int:
    """Cells in the screenshot's longest line (up to its last visible character)."""
    return max(len(line) for line in rows(path))


def columns(path: Path) -> int:
    """The terminal width the screenshot was taken at (Rich clips the SVG to cell width * columns - 1)."""
    svg = path.read_text(encoding="utf-8")
    _, _, cell = _span(*SPAN.search(svg).group(1, 3, 4))
    return round((float(CLIP.search(svg).group(1)) + 1) / cell)


def header(path: Path) -> list[str]:
    """The header's segments (the first line, cut apart at ╱)."""
    return [part.strip() for part in "".join(rows(path)[0]).split("╱")]


def shot(out: Path, moment: str) -> Path:
    """The screenshot in `out` named NN-<moment>.svg (`moment` is a regex)."""
    found = [p for p in out.iterdir() if re.fullmatch(rf"\d\d-{moment}\.svg", p.name)]
    assert len(found) == 1, f"no single {moment} shot in {sorted(p.name for p in out.iterdir())}"
    return found[0]


# ---------------------------------------------------------------------- the live console, not started


@dataclass(frozen=True)
class Opened:
    """What the console would have opened on."""

    max_lanes: int
    team: bool
    containerized: bool
    tick_seconds: float | None
    mock: str
    challenges: frozenset[str]
    clock_moves: bool  # the console's ticker advances the deck's clock


@pytest.fixture
def opened(monkeypatch) -> list[Opened]:
    calls: list[Opened] = []

    def run(self: FlightdeckApp, *args, **kwargs) -> None:
        cfg = self.deck.config
        challenges, before = frozenset(self.deck.challenges), self.deck.now
        if self._ticker is not None:
            self._ticker()  # one tick of the clock the live console would run
        calls.append(
            Opened(
                cfg.max_lanes, cfg.team, cfg.containerized, self._tick_seconds, self.mock,
                challenges, self.deck.now > before,
            )
        )

    monkeypatch.setattr(FlightdeckApp, "run", run)
    return calls


def settings(calls: list[Opened]) -> list[tuple[int, bool, bool, float | None]]:
    return [(c.max_lanes, c.team, c.containerized, c.tick_seconds) for c in calls]


def on_the_board_at_open(scenario: scenarios.Scenario) -> frozenset[str]:
    """Challenges the scenario has released by the time the console opens (after its prerun)."""
    return frozenset(
        cid for at, event in scenario.timeline if isinstance(event, ReleaseAt) and at <= scenario.prerun for cid in event.ids
    )


# ---------------------------------------------------------------------- options


@pytest.mark.parametrize("prog", ["flightdeck", "ctfdeck"])
def test_version_names_the_program_it_runs_as(prog):
    result = invoke("--version", prog=prog)
    assert result.exit_code == 0
    assert result.stdout == f"{prog} 0.0.0\n"


def test_version_is_the_one_pyproject_declares():
    declared = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
    assert invoke("--version").stdout == f"flightdeck {declared}\n"


def test_no_command_shows_the_help_and_exits_2():
    result = invoke()
    assert result.exit_code == 2
    text = flat(result.output)
    assert "Usage: flightdeck [OPTIONS] COMMAND" in text
    assert "mock Open the console on fake, scripted data" in text  # the command list, not just usage


def test_mock_help_lists_every_scenario_with_its_summary():
    result = invoke("mock", "--help")
    assert result.exit_code == 0
    text = flat(result.stdout)
    for name, build in scenarios.SCENARIOS.items():
        assert f"{name}: {build().summary}" in text


def test_an_unknown_scenario_is_a_usage_error_naming_the_choices(opened):
    result = invoke("mock", "--scenario", "nope")
    assert result.exit_code == 2
    message = flat(result.stderr)
    assert "--scenario" in message and "'nope'" in message
    for name in scenarios.SCENARIOS:
        assert f"'{name}'" in message
    assert opened == []


@pytest.mark.parametrize("name", list(scenarios.SCENARIOS))
def test_every_scenario_opens_by_name(opened, name):
    result = invoke("mock", "--scenario", name)
    assert result.exit_code == 0, result.output
    assert [c.mock for c in opened] == [f"MOCK · {name}"]
    assert opened[0].challenges == on_the_board_at_open(scenarios.get(name))


def test_s_is_short_for_scenario(opened):
    result = invoke("mock", "-s", "team")
    assert result.exit_code == 0, result.output
    assert [c.mock for c in opened] == ["MOCK · team"]


def test_max_lanes_must_be_at_least_one(opened):
    result = invoke("mock", "--max-lanes", "0")
    assert result.exit_code == 2
    assert "--max-lanes" in flat(result.stderr)
    assert opened == []
    assert invoke("mock", "--max-lanes", "1").exit_code == 0
    assert [c.max_lanes for c in opened] == [1]


def test_speed_zero_is_a_usage_error_not_a_crash(opened):
    result = invoke("mock", "--speed", "0")
    assert result.exit_code == 2
    assert "--speed" in flat(result.stderr)
    assert opened == []


def test_screenshot_into_a_file_is_a_usage_error(tmp_path, opened):
    target = tmp_path / "shots.svg"
    target.write_text("keep me")
    result = invoke("mock", "--screenshot", str(target))
    assert result.exit_code == 2
    message = flat(result.stderr)
    assert "--screenshot" in message and "is a file" in message
    assert target.read_text() == "keep me"
    assert [p.name for p in tmp_path.iterdir()] == ["shots.svg"]
    assert opened == []


def test_a_screenshot_dir_that_cannot_be_made_is_a_usage_error_with_the_reason(tmp_path, opened):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    result = invoke("mock", "--screenshot", str(blocker / "shots"))
    assert result.exit_code == 2
    message = flat(result.stderr)  # the path itself may be folded mid-word in the panel
    assert "--screenshot" in message and "cannot create" in message
    assert message.endswith(f": {os.strerror(errno.ENOTDIR)}")
    assert opened == []


def test_a_literal_tilde_in_the_screenshot_dir_saves_where_it_says(tmp_path, monkeypatch):
    # bash and zsh pass --screenshot=~/shots on unexpanded. Expanding "~" or keeping it
    # literal are both fine; making one directory and writing into another is not.
    home, work = tmp_path / "home", tmp_path / "work"
    home.mkdir()
    work.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(work)
    result = invoke("mock", "--scenario", "flag", "--screenshot=~/shots")
    assert result.exit_code == 0, f"{result.output}{result.exception!r}"
    saved = [Path(line) for line in result.stdout.splitlines()]
    assert saved and all(path.is_file() for path in saved)
    (folder,) = {path.resolve().parent for path in saved}
    root = tmp_path.resolve()
    made = {path.resolve() for path in root.rglob("*") if path.is_dir()}
    assert made == {root / "home", root / "work", folder, *(p for p in folder.parents if p.is_relative_to(root) and p != root)}


# ---------------------------------------------------------------------- the live console


def test_plain_mock_opens_the_default_scenario_with_its_own_settings(opened):
    result = invoke("mock")
    assert result.exit_code == 0, result.output
    assert settings(opened) == [(16, True, True, 1.0)]
    assert opened[0].mock == "MOCK · default"
    assert opened[0].clock_moves  # the console's clock drives the scenario


def test_options_override_the_scenario_settings(opened):
    team = scenarios.team()
    assert (team.max_lanes, team.team, team.containerized) == (4, True, True)  # what each option changes
    result = invoke("mock", "--scenario", "team", "--max-lanes", "3", "--solo", "--host", "--speed", "4")
    assert result.exit_code == 0, result.output
    assert settings(opened) == [(3, False, False, 0.25)]


def test_team_and_docker_switch_a_solo_scenario_to_team(opened):
    assert scenarios.wave().team is False
    result = invoke("mock", "--scenario", "wave", "--team", "--docker")
    assert result.exit_code == 0, result.output
    assert [(c.team, c.containerized) for c in opened] == [(True, True)]


# ---------------------------------------------------------------------- packaging


def test_pyproject_installs_both_command_names():
    scripts = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["scripts"]
    assert scripts["flightdeck"] == "ctf_flightdeck.cli:main"
    assert scripts["ctfdeck"] == "ctf_flightdeck.cli:main"


def test_main_runs_the_cli_under_the_name_it_was_started_as(monkeypatch, capsys):
    # As an installed script runs it: argv[0] is the script, __main__ is a plain file.
    monkeypatch.setattr(sys, "argv", ["/opt/bin/ctfdeck", "--version"])
    monkeypatch.setitem(sys.modules, "__main__", types.ModuleType("__main__"))
    monkeypatch.setattr(sys, "excepthook", sys.excepthook)  # Typer replaces it; restore after
    with pytest.raises(SystemExit) as exit_:
        cli.main()
    assert exit_.value.code == 0
    assert capsys.readouterr().out == "ctfdeck 0.0.0\n"


# ---------------------------------------------------------------------- screenshot mode


@pytest.fixture(scope="module")
def default_run(tmp_path_factory):
    out = tmp_path_factory.mktemp("default") / "shots"
    return invoke("mock", "--screenshot", str(out)), out


@pytest.fixture(scope="module")
def overridden_run(tmp_path_factory):
    out = tmp_path_factory.mktemp("overridden") / "shots"
    return invoke("mock", "--solo", "--host", "--max-lanes", "12", "--screenshot", str(out)), out


@pytest.fixture(scope="module")
def flag_runs(tmp_path_factory):
    runs = []
    for name in ("first", "second"):
        base = tmp_path_factory.mktemp(f"flag-{name}")
        out = base / "not" / "made" / "yet"
        assert not (base / "not").exists()
        runs.append((invoke("mock", "--scenario", "flag", "--screenshot", str(out)), out))
    return runs


def test_screenshot_mode_saves_every_key_moment_numbered_in_order(default_run):
    result, out = default_run
    assert result.exit_code == 0, result.output
    names = sorted(p.name for p in out.iterdir())
    alert = shot(out, ALERT_SHOT).stem[3:]
    expected = [f"{i:02d}-{alert if moment == 'alert' else moment}.svg" for i, moment in enumerate(MOMENTS, 1)]
    assert names == expected
    assert all((out / name).read_text(encoding="utf-8").startswith("<svg") for name in names)


def test_no_two_screenshots_are_the_same(default_run):
    _, out = default_run
    by_content: dict[bytes, list[str]] = {}
    for path in sorted(out.iterdir()):
        by_content.setdefault(path.read_bytes(), []).append(path.name)
    assert len(by_content) == len(MOMENTS)
    assert [names for names in by_content.values() if len(names) > 1] == []


def test_stdout_lists_exactly_the_saved_files_in_order(default_run):
    result, out = default_run
    lines = result.stdout.splitlines()
    assert len(lines) == len(MOMENTS)
    assert lines == [str(path) for path in sorted(out.iterdir())]


def accounted(saved: list[str], skipped: list[str]) -> list[str]:
    """The moments a run covered: each saved file's moment, and each moment a skip line names."""
    names = []
    for name in saved:
        stem = Path(name).stem[3:]
        names.append("alert" if re.fullmatch(ALERT_SHOT, stem) else stem)
    for line in skipped:
        head, sep, _ = line.partition(": ")
        assert sep, f"a skip line says why: {line!r}"
        names += [part.strip() for part in head.split(",")]
    return names


@pytest.mark.parametrize("scenario", ["sstv", "team"])
def test_every_moment_is_either_saved_or_reported_as_skipped(scenario, tmp_path):
    result = screenshots.capture(scenario, tmp_path)
    assert sorted(accounted([p.name for p in result.saved], result.skipped)) == sorted(MOMENTS)


def test_the_cli_runs_account_for_every_moment_too(default_run, flag_runs):
    for result, _ in (default_run, flag_runs[0]):
        skipped = [line.removeprefix("skipped ") for line in result.stderr.splitlines() if line.startswith("skipped ")]
        assert sorted(accounted(result.stdout.splitlines(), skipped)) == sorted(MOMENTS)


def test_the_default_scenario_skips_no_moment(default_run):
    result, _ = default_run
    assert result.exit_code == 0, result.output
    assert "skipped" not in result.stderr


def test_wave_drop_shows_the_wave_on_the_board_and_in_the_queue(default_run):
    _, out = default_run
    before, after = screen_text(shot(out, "open")), screen_text(shot(out, "wave-drop"))
    board = re.compile(r"board (\d+)")
    assert int(board.search(after).group(1)) > int(board.search(before).group(1))
    assert int(re.search(r"queue (\d+)", after).group(1)) > 0


def test_alert_shot_shows_that_alerts_label(default_run):
    _, out = default_run
    path = shot(out, ALERT_SHOT)
    kind = COURSE_TAGS[path.stem.split("-", 2)[2]]
    assert kind.label in screen_text(path)


def test_focus_lane_opens_the_alerted_lane_and_shows_what_it_needs(default_run):
    _, out = default_run
    alerted = re.search(r"▌(L\d+) ▲ ", screen_text(shot(out, ALERT_SHOT))).group(1)
    focus = screen_text(shot(out, "focus-lane"))
    assert "needs you now" in focus
    assert f"─ {alerted} · " in focus  # the focus view's title names the lane


def test_diff_shot_shows_a_unified_diff(default_run):
    _, out = default_run
    assert "+++ b/" in screen_text(shot(out, "diff"))


def test_approve_submit_shows_the_challenge_solved_on_the_board(default_run):
    _, out = default_run
    text = screen_text(shot(out, "approve-submit"))
    outcome = re.search(r"\S+ is correct: (.+?) solved by (L\d+)", text)
    assert outcome is not None, text
    name, lane = outcome.groups()
    assert re.search(rf"{re.escape(name)}\s+\d+\s+✓\s+{lane}\b", text), f"no ✓ row for {name}"
    assert re.search(rf"{re.escape(name)}  \w+ \d+ · \d+ solves · ✓ solved", text)  # selected on the board


def test_team_stop_shows_the_teammate_solve_on_the_stopped_lane(default_run):
    _, out = default_run
    text = screen_text(shot(out, "team-stop"))
    assert "wren solved Night Shift" in text
    assert "stopped: wren solved Night Shift" in text  # the stopped lane is the selected one


def test_narrow_shot_has_no_line_longer_than_120_cells(default_run):
    _, out = default_run
    assert widest(shot(out, "attention-sort")) > 120  # the same fleet at full width, just before
    assert widest(shot(out, "narrow-120x36")) <= 120


def test_only_the_narrow_shot_is_narrow(default_run):
    _, out = default_run
    widths = {path.name: columns(path) for path in out.iterdir()}
    narrow = shot(out, "narrow-120x36").name
    assert widths.pop(narrow) == 120
    assert set(widths.values()) == {screenshots.SIZE[0]}


@pytest.mark.parametrize(
    ("moment", "shows"),
    [
        ("command-menu", "suggested"),
        ("approve-pending", "waiting for you: submit"),
        ("fork-prompt", "Fork L"),
        ("kill-prompt", "Kill L"),
        ("take-over", "Take over L"),
        ("challenge-card", "about"),
        ("help", "/redirect"),
        ("help", "Keys (fleet)"),
    ],
)
def test_each_prompt_shot_shows_its_prompt(default_run, moment, shows):
    _, out = default_run
    assert shows in screen_text(shot(out, moment))


def test_docker_is_the_default_runtime_in_the_header(default_run):
    _, out = default_run
    first = header(sorted(out.iterdir())[0])
    assert "docker" in first and "host" not in first


def test_solo_on_the_default_scenario_skips_the_team_stop(overridden_run):
    result, out = overridden_run
    assert result.exit_code == 0, result.output
    assert "skipped team-stop: solo mode" in result.stderr.splitlines()
    names = [p.name for p in out.iterdir()]
    assert names and not [name for name in names if "team-stop" in name]
    first = header(shot(out, "open"))
    assert "solo" in first and "team" not in first


def test_host_shows_host_in_the_first_shots_header(overridden_run):
    result, out = overridden_run
    assert result.exit_code == 0, result.output
    first = header(sorted(out.iterdir())[0])
    assert "host" in first and "docker" not in first


def test_max_lanes_reaches_the_screenshots(overridden_run):
    _, out = overridden_run
    assert any(re.fullmatch(r"lanes \d+/12 · queue \d+", part) for part in header(shot(out, "open")))


def test_screenshot_creates_missing_parent_directories(flag_runs):
    for result, out in flag_runs:
        assert result.exit_code == 0, result.output
        assert out.is_dir() and any(out.glob("*.svg"))


def test_the_flag_scenario_reports_the_moments_it_does_not_have(flag_runs):
    result, out = flag_runs[0]
    assert result.exit_code == 0, result.output
    skipped = result.stderr.splitlines()
    assert any(line.startswith("skipped wave-drop: ") for line in skipped), skipped
    assert any(line.startswith("skipped alert, command-menu, focus-lane, chat, focus-after, diff: ") for line in skipped), skipped
    names = [p.name for p in out.iterdir()]
    assert not [name for name in names if "wave-drop" in name or "-alert-" in name]
    assert any(name.endswith("-approve-submit.svg") for name in names)  # it did play


def test_screenshots_are_byte_identical_on_every_run(flag_runs):
    (first, a), (second, b) = flag_runs
    assert first.exit_code == second.exit_code == 0
    names = sorted(p.name for p in a.iterdir())
    assert len(names) >= 5
    assert names == sorted(p.name for p in b.iterdir())
    for name in names:
        assert (a / name).read_bytes() == (b / name).read_bytes(), name


MOUNTED = {
    ("preflight",): "event profile",
    ("ctfd", "pull"): "CTFd",
    ("team", "init"): "",
    ("team", "status"): "",
    ("l1", "list"): "",
    ("l1", "route"): "",
    ("l1", "run"): "",
    ("l1", "import"): "",
    ("report",): "report",
    ("writeups",): "writeup",
    ("score",): "Score",
    ("eval-local",): "",
    ("gaps",): "L1",
}


@pytest.mark.parametrize("command", sorted(MOUNTED), ids=" ".join)
def test_every_component_command_is_mounted_and_explains_itself(command):
    result = CliRunner().invoke(cli.app, [*command, "--help"])
    assert result.exit_code == 0, result.output
    assert MOUNTED[command].lower() in result.output.lower()


def test_the_root_help_groups_the_commands():
    out = CliRunner().invoke(cli.app, ["--help"], terminal_width=200).output
    for panel in ("Play", "Set up", "Before and during an event", "Solvers (L1)", "After a run"):
        assert panel in out
    for name in ("preflight", "ctfd", "team", "l1", "report", "writeups", "score", "eval-local", "gaps"):
        assert f" {name} " in out
