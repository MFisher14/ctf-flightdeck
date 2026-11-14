"""Settings and health, a screen of the home screen (home.py): the main settings of the
player's config, each with where it is set, and `flightdeck doctor`'s checks, each with its
state and what fixes it.

It reads and shows; it changes nothing (the console's /theme and /layout save a look, and
`flightdeck init` writes a config). The settings are read when the screen opens, from the
config file itself. The checks run in a child process (health.py) while the screen stays the
player's, and leaving the screen stops them. A key is "set" or "not set" and where, never its
value; an API's address is shown without any user, password or query it carries.
"""

from __future__ import annotations

import os
import tomllib
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

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

WAIT = ("Checking your setup… Docker can take up to 20 s to answer, and the lane image a few more. "
        "You can leave at any time: esc stops the checks.")


@dataclass(frozen=True)
class Row:
    name: str  # what it is, in a word or two
    value: str  # what it is set to
    where: str  # where that comes from, and how to change it


def _on(value: bool) -> str:
    return "on" if value else "off"


def settings() -> list[Row]:
    """The main settings of the config flightdeck reads (config.default_config_path), each
    with where it is set: the line of the config, or the default when the config has none.
    A config that cannot be read is one row that says why (the checks say it too)."""
    from .. import keys
    from ..config import CONFIG_ENV, ConfigError, default_config_path, load_config
    from ..setup import _shown

    try:
        path = default_config_path()
    except ConfigError as exc:
        return [Row("Config", "cannot be found", str(exc))]
    named = f"named by ${CONFIG_ENV}" if os.environ.get(CONFIG_ENV) else "the usual place"
    rows = [Row("Config", str(path), named)]
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


def settings_text(rows: list[Row]) -> Text:
    text = Text()
    text.append("Settings\n", style="bold")
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


Runner = Callable[[int, int], Awaitable[list[Check]]]


class HealthScreen(Screen):
    """Settings and health. `run`: what runs the checks for a terminal of a size (columns,
    lines); by default health.run_checks, the child process."""

    BINDINGS = [Binding("escape", "back", "back"), Binding("q", "back", "back"), Binding("r", "again", "check again")]

    def __init__(self, run: Runner | None = None) -> None:
        super().__init__()
        self.run_checks = run or health.run_checks
        self.checked: list[Check] | None = None  # the checks last shown; None while they run, or when they could not

    def compose(self) -> ComposeResult:
        yield Static(Text("Settings and health", style="bold"), id="formtitle")
        with VerticalScroll(id="form"):
            yield Static(Text(""), id="settings", classes="q")
            yield Static(Text(""), id="checks", classes="q")
        keys = Text()
        for key, what in (("r", "check again"), ("↑↓", "scroll"), ("esc", "back")):
            keys.append_text(theme.key_chip(key))
            keys.append(f" {what}   ")
        yield Static(keys, id="formkeys")

    def on_mount(self) -> None:
        self.query_one("#settings", Static).update(settings_text(settings()))
        self.query_one("#form", VerticalScroll).focus()
        self.action_again()

    def action_again(self) -> None:
        """Run the checks (again): the last ones are replaced by the wait, then by what the
        checks found. A run still going is stopped first (exclusive), so only one runs."""
        self.checked = None
        self.query_one("#checks", Static).update(Text.assemble(("Health\n", "bold"), (WAIT, theme.MUTED)))
        self.run_worker(self._check(), name="checks", group="checks", exclusive=True)  # this screen's: stopped when it closes

    async def _check(self) -> None:
        size = self.app.size
        try:
            found = await self.run_checks(size.width, size.height)
        except health.HealthError as exc:
            shown = Text.assemble(("Health\n", "bold"), (f"The checks could not be run: {untrusted(str(exc), one_line=True)}",
                                                          theme.YELLOW))
        else:
            self.checked = found
            shown = checks_text(found)
        if self.is_mounted:
            self.query_one("#checks", Static).update(shown)

    def action_back(self) -> None:
        self.app.pop_screen()

