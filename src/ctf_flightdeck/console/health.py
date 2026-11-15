"""Settings and health, a screen of the home screen (home.py) and, as `/settings`, of a
running console (P90): the main settings of the player's config, each with where it is set,
and `flightdeck doctor`'s checks, each with its state and what fixes it. In a run it also
shows the run's own settings, which `/config` changes (c opens it), and the lanes that need
the player; the checks it found are kept for the run, so opening it again costs nothing
until the player asks for them again (r).

It reads and shows; it changes nothing (the console's /theme and /layout save a look, and
`flightdeck init` writes a config). The settings are read when the screen opens, from the
config file itself. The checks run in a child process (health.py) while the screen stays the
player's, and leaving the screen stops them. A key is "set" or "not set" and where, never its
value; an API's address is shown without any user, password or query it carries.
"""

from __future__ import annotations

import os
import time
import tomllib
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import VerticalScroll
from textual.screen import Screen
from textual.widgets import Static

from .. import health
from ..setup import Check
from ..text import untrusted
from . import theme

# The checks wait on Docker (up to a minute for the lane image) and on model servers; the cap is
# health.CHECKS_TIMEOUT, so the wait promised here is that cap, never a shorter one.
WAIT = ("Checking your setup… Docker or a server that does not answer can hold the checks up to "
        f"{health.CHECKS_TIMEOUT / 60:g} minutes, then they stop and say so. "
        "You can leave at any time: esc stops the checks.")


@dataclass(frozen=True)
class Row:
    name: str  # what it is, in a word or two
    value: str  # what it is set to
    where: str  # where that comes from, and how to change it


def _on(value: bool) -> str:
    return "on" if value else "off"


def settings(path: Path | None = None) -> list[Row]:
    """The main settings of a config, each with where it is set: the line of the config, or
    the default when the config has none. `path`: the config a run started with (None: the
    one flightdeck reads, config.default_config_path). A config that cannot be read is one
    row that says why (the checks say it too)."""
    from .. import keys
    from ..config import CONFIG_ENV, ConfigError, default_config_path, load_config
    from ..setup import _shown

    try:
        usual: Path | None = default_config_path()
    except ConfigError as exc:
        if path is None:
            return [Row("Config", "cannot be found", str(exc))]
        usual = None
    if path is not None and (usual is None or path.expanduser().resolve() != usual.expanduser().resolve()):
        named = "the config this run started with (--config)"
    else:
        path = usual
        named = f"named by ${CONFIG_ENV}" if os.environ.get(CONFIG_ENV) else "the usual place"
    rows =[Row("Config", str(path), named)]
    if not path.exists():
        return [*rows, Row("Settings", "none yet", "there is no config: \"Get started\" on the home screen writes one, "
                                                   "or `flightdeck init`")]
    try:
        config = load_config(path)
        with path.open("rb") as file:
            raw = tomllib.load(file)  # which keys the file sets itself: load_config has just read it as TOML
    except (ConfigError, OSError, tomllib.TOMLDecodeError) as exc:
        return [*rows, Row("Settings", "cannot be read", str(exc))]

    def where(table: str, key: str, otherwise: str = "") -> str:
        section = raw.get(table)
        if isinstance(section, dict) and key in section:
            said = f"your config: [{table}] {key}"
        else:
            said = f"the default: your config has no [{table}] {key}"
        return f"{said}. {otherwise}" if otherwise else said

    api = config.api
    rows.append(Row("Model API", f"{api.provider}, {_shown(api.base_url)}", where("api", "base_url")))
    variable = api.key_env
    if not variable:
        rows.append(Row("API key", "none needed", where("api", "key_env")))
    else:
        try:
            found = keys.source(variable)
        except keys.KeysError as exc:
            rows.append(Row("API key", f"{variable}: cannot tell", str(exc)))
        else:
            if found == "keys file":
                said = f"in your keys file, {keys.keys_path()}"
            elif found == "environment":
                said = "in your environment (export), which a run uses before the keys file"
            else:
                said = f"put {variable}=<your key> in {keys.keys_path()}, or export it"
            rows.append(Row("API key", f"{variable}: {'set' if found else 'not set'}", said))
    rows.append(Row("Models", ", ".join(config.models) + " (weakest first)", where("models", "ladder")))
    rows.append(Row("Lanes run", "in Docker" if config.lanes.runtime == "docker" else "on this machine (host)",
                    where("lanes", "runtime")))
    look = config.console
    rows.append(Row("Layout", look.layout, where("console", "layout", "In a run: /layout, then s saves one.")))
    rows.append(Row("Theme", look.theme, where("console", "theme", "In a run: /theme, then s saves one.")))
    rows.append(Row("Bell", _on(look.bell), where("console", "bell", "Rings once when more lanes need you.")))
    rows.append(Row("Title", _on(look.title), where("console", "title", "The terminal's title counts the lanes that need you.")))
    rows.append(Row("Mouse", _on(look.mouse), where("console", "mouse", "Off: your terminal keeps the mouse for selecting text.")))
    return rows


NAME_WIDTH = 10


def settings_text(rows: list[Row], heading: str = "Settings") -> Text:
    text = Text()
    text.append(heading + "\n", style="bold")
    for row in rows:
        text.append(f"{row.name:<{NAME_WIDTH}}", style="bold")
        text.append(untrusted(row.value, one_line=True) + "\n")
        text.append(" " * NAME_WIDTH + untrusted(row.where, one_line=True) + "\n", style=theme.MUTED)
    return text


def verdict(checks: list[Check]) -> tuple[str, str]:
    """What the checks come to, in one line, and its colour's name: what stops a run (a FAIL
    line), what does not (a warning), or ready."""
    failed = sum(1 for c in checks if not c.ok and c.essential)
    warned = sum(1 for c in checks if not c.ok and not c.essential)
    warnings = f"{warned} warning{'' if warned == 1 else 's'}"
    if failed:
        said = f"{failed} thing{'' if failed == 1 else 's'} to fix before a run: the FAIL line{'' if failed == 1 else 's'} below."
        if warned:
            said += f" Besides, {warnings}, which a run does not wait for."
        return said, "RED"
    if warned:
        return f"Ready, with {warnings} below that a run does not wait for.", "YELLOW"
    return "Ready: nothing to fix.", "GREEN"


def checks_text(checks: list[Check]) -> Text:
    """Each check as doctor prints it: ok, FAIL (stops a run) or warn, what was found, and
    under a check that is not ok, what fixes it."""
    said, colour = verdict(checks)
    text = Text()
    text.append("Health\n", style="bold")
    text.append(said + "\n", style=getattr(theme, colour))
    for check in checks:
        mark, colour = ("ok  ", "GREEN") if check.ok else (("FAIL", "RED") if check.essential else ("warn", "YELLOW"))
        text.append(mark, style=f"bold {getattr(theme, colour)}")
        text.append(f" {untrusted(check.name, one_line=True)}: ", style="bold")
        text.append(untrusted(check.detail, one_line=True) + "\n")
        if not check.ok and check.fix:
            text.append(f"     fix: {untrusted(check.fix, one_line=True)}\n", style=theme.MUTED)
    return text


Runner = Callable[..., Awaitable[list[Check]]]  # (columns, lines[, config=path]): health.run_checks


@dataclass
class InRun:
    """What the screen needs from a running console (P90), kept by the console for the whole
    run. `rows`: the run's own settings as they are now, which /config changes; `needing`:
    how many lanes need the player; `change`: opens /config's dialog; `config`: the run's
    config file (None: the one flightdeck reads, as in the mock). `checked` and `at`
    (time.monotonic) are the checks the screen last found in this run, shown again when it
    opens until the player asks for new ones (r)."""

    rows: Callable[[], list[Row]]
    needing: Callable[[], int]
    change: Callable[[], None]
    config: Path | None = None
    checked: list[Check] | None = None
    at: float = 0.0


def ago(seconds: float) -> str:
    minutes = int(seconds // 60)
    if minutes < 1:
        return "less than a minute ago"
    if minutes < 120:
        return f"{minutes} minute{'' if minutes == 1 else 's'} ago"
    return f"{minutes // 60} hours ago"


def waiting_line(count: int) -> Text:
    """The line under the title in a run: the lanes keep running, and how many need the player."""
    if not count:
        return Text("Your lanes keep running while this is open; esc goes back to them.", style=theme.MUTED)
    return Text(f"{count} lane{' needs' if count == 1 else 's need'} you: esc goes back to the lanes.",
                style=f"bold {theme.YELLOW}")


THIS_RUN = "This run (/config changes these; c opens it)"


class HealthScreen(Screen):
    """Settings and health. `run`: what runs the checks for a terminal of a size (columns,
    lines, and in a run the config to check); by default health.run_checks, the child
    process. `in_run`: the running console's part (P90); None on the home screen."""

    DEFAULT_CSS = """
    HealthScreen { background: $fd-page; align: center top; padding: 1 2; }
    HealthScreen #formtitle, HealthScreen #waiting, HealthScreen #formkeys { width: 110; max-width: 100%; padding: 0 3; height: auto; }
    HealthScreen #formkeys { margin-top: 1; }
    HealthScreen #form { width: 110; max-width: 100%; height: 1fr; border: round $fd-border; padding: 0 3 1 3; }
    HealthScreen #form .q { margin-top: 1; }
    """
    BINDINGS = [Binding("escape", "back", "back"), Binding("q", "back", "back"), Binding("r", "again", "check again"),
                Binding("c", "change", "change this run's")]
    TICK = 1.0  # seconds: how often the line of the lanes that need the player is drawn again

    def __init__(self, run: Runner | None = None, *, in_run: InRun | None = None) -> None:
        super().__init__()
        self.run_checks = run or health.run_checks
        self.in_run = in_run
        self.checked: list[Check] | None = None  # the checks last shown; None while they run, or when they could not

    def compose(self) -> ComposeResult:
        yield Static(Text("Settings and health", style="bold"), id="formtitle")
        if self.in_run is not None:
            yield Static(waiting_line(self.in_run.needing()), id="waiting")
        with VerticalScroll(id="form"):
            if self.in_run is not None:
                yield Static(Text(""), id="thisrun", classes="q")
            yield Static(Text(""), id="settings", classes="q")
            yield Static(Text(""), id="checks", classes="q")
        keys = Text()
        shown: tuple[tuple[str, str], ...] = (("r", "check again"), ("↑↓", "scroll"), ("esc", "back"))
        if self.in_run is not None:
            shown = (("c", "change this run's"), *shown)
        for key, what in shown:
            keys.append_text(theme.key_chip(key))
            keys.append(f" {what}   ")
        yield Static(keys, id="formkeys")

    def on_mount(self) -> None:
        run = self.in_run
        if run is not None:
            self.query_one("#thisrun", Static).update(settings_text(run.rows(), THIS_RUN))
            self.set_interval(self.TICK, self._tick)
        self.query_one("#settings", Static).update(settings_text(settings(run.config if run else None),
                                                                 "Your setup" if run else "Settings"))
        self.query_one("#form", VerticalScroll).focus()
        if run is not None and run.checked is not None:  # found earlier in this run: shown again, not run again
            self.checked = run.checked
            said = Text(f"Checked {ago(time.monotonic() - run.at)}: r checks again.", style=theme.MUTED)
            self.query_one("#checks", Static).update(Text.assemble(checks_text(run.checked), said))
            return
        self.action_again()

    def _tick(self) -> None:
        if self.in_run is not None and self.is_mounted:
            self.query_one("#waiting", Static).update(waiting_line(self.in_run.needing()))

    def check_action(self, action: str, parameters: tuple[object, ...]) -> bool | None:
        return self.in_run is not None if action == "change" else True  # c is a run's: the home screen has no run

    def action_again(self) -> None:
        """Run the checks (again): the last ones are replaced by the wait, then by what the
        checks found. A run still going is stopped first (exclusive), so only one runs."""
        self.checked = None
        if self.in_run is not None:
            self.in_run.checked = None
        self.query_one("#checks", Static).update(Text.assemble(("Health\n", "bold"), (WAIT, theme.MUTED)))
        self.run_worker(self._check(), name="checks", group="checks", exclusive=True)  # this screen's: stopped when it closes

    async def _check(self) -> None:
        size = self.app.size
        config = self.in_run.config if self.in_run is not None else None
        try:
            if config is None:
                found = await self.run_checks(size.width, size.height)
            else:
                found = await self.run_checks(size.width, size.height, config=str(config))
        except health.HealthError as exc:
            shown = Text.assemble(("Health\n", "bold"), (f"The checks could not be run: {untrusted(str(exc), one_line=True)}",
                                                          theme.YELLOW))
        else:
            self.checked = found
            if self.in_run is not None:
                self.in_run.checked, self.in_run.at = found, time.monotonic()
            shown = checks_text(found)
        if self.is_mounted:
            self.query_one("#checks", Static).update(shown)

    def action_change(self) -> None:
        """In a run: /config's dialog, in this screen's place: it changes the run, which this
        screen only shows."""
        if self.in_run is None:
            return
        change = self.in_run.change
        self.app.pop_screen()
        change()

    def action_back(self) -> None:
        self.app.pop_screen()
