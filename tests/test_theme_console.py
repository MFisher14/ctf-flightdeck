"""Themes in the console: one palette (themes.Palette) colours everything it draws.

The colours are read from the screen as a player would see it (the SVG export: text fills and
the backgrounds behind them), not from the code. Nothing here needs a model or a network, and
every theme and config file is the test's own, under tmp_path.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ctf_flightdeck import cli, themes
from ctf_flightdeck.console import home as homes
from ctf_flightdeck.console import theme
from ctf_flightdeck.console.app import FlightdeckApp
from ctf_flightdeck.console.fleet import FleetScreen
from ctf_flightdeck.console.focus import FocusScreen
from ctf_flightdeck.console.home import HomeApp, Menu
from ctf_flightdeck.core.model import AlertKind
from ctf_flightdeck.mock import scenarios
from ctf_flightdeck.mock.world import FakeWorld
from test_console import SVG_FRAME, bar, color_of, open_focus, press, screen_colors, screen_lines, step_until

TESTS = Path(__file__).resolve().parent
SIZE = (160, 46)

# 17 colours, each its own and none of them the default theme's: whatever is drawn in one of
# the default's colours while this palette is in use was not drawn from the palette.
STRANGE = themes.Palette(
    name="strange", dark=True, syntax="nord",
    page="#101820", surface="#1c2a38", border="#5a4b7a", text="#d7e3c0", muted="#8a9a70", accent="#ff66cc",
    selected="#223d2a", selected_focus="#2f5a3a", brand="#7a3fd0", segment="#40304a", ok="#33d6c0", error="#ff7043",
    warn="#d4e157", info="#6f9bff", pending="#e05cff", ink="#0a1410", ink_light="#fff8e7",
)
NORD = themes.BUILTIN["nord"]


def colours(palette: themes.Palette) -> dict[str, str]:
    return {role: getattr(palette, role) for role in themes.ROLES}


def row_of(app, needle: str) -> int:
    """The screen row that shows `needle`."""
    rows = [row for row, line in enumerate(screen_lines(app)) if needle in line]
    assert rows, f"{needle!r} is not on the screen"
    return rows[0]


def busy_console(palette: themes.Palette | None = None, **kw) -> tuple[FakeWorld, FlightdeckApp]:
    """The mock's default scenario in `palette`: once it is `busy`, it shows every kind of
    thing the console draws."""
    world = FakeWorld(scenarios.get("default"))
    return world, FlightdeckApp(world.deck, ticker=world.tick, mock="MOCK · test", refresh_seconds=None, palette=palette, **kw)


def busy(world: FakeWorld) -> bool:
    lanes = list(world.deck.lanes.values())
    return (any(lane.files for lane in lanes) and any(lane.alerts for lane in lanes)
            and any(lane.pending for lane in lanes) and any(lane.finished for lane in lanes))


def console_colours(palette: themes.Palette, handout: Path) -> dict[str, set[str]]:
    """Every colour on each screen of the console, opened in `palette`: the fleet, the command
    menu, a lane with a diff open, help, the /config and /new dialogs (/new with `handout`,
    a file, attached)."""
    async def adder(new):
        return True, "added"

    world, app = busy_console(palette, adder=adder)
    seen: dict[str, set[str]] = {}

    async def main() -> None:
        async with app.run_test(size=SIZE) as pilot:
            await pilot.pause()
            await step_until(pilot, app, lambda: busy(world), "files, an alert, an approval and a finished lane", limit=400)
            app.warn("a warning in the status line")
            await pilot.pause()
            seen["fleet"] = screen_colors(app)
            bar(app).start("/")
            await pilot.pause()
            assert bar(app).menu_open
            seen["command menu"] = screen_colors(app)
            await press(pilot, "escape")
            lane = next(lane for lane in world.deck.lanes.values() if lane.files and lane.alerts)
            await open_focus(pilot, app, lane.id)
            app.run_command("a message to the lane", lane.id)
            app.open_lane(lane.id, "")  # its newest file's diff
            await pilot.pause()
            app.refresh_view()
            await pilot.pause()
            assert "a message to the lane" in "\n".join(screen_lines(app))
            seen["focus"] = screen_colors(app)
            app.show_fleet()
            await pilot.pause()
            for name, command in (("help", "/help"), ("config", "/config"), ("new", "/new")):
                app.run_command(command, None)
                await pilot.pause()
                await pilot.pause()
                assert type(app.screen).__name__ == {"help": "HelpScreen", "config": "ConfigPrompt", "new": "NewChallengePrompt"}[name]
                if name == "new":
                    assert app.screen.add_files([handout])
                    await pilot.pause()
                    assert f"attached {handout.name}" in "\n".join(screen_lines(app))
                seen[name] = screen_colors(app)
                await press(pilot, "escape")
                assert isinstance(app.screen, FleetScreen)

    asyncio.run(main())
    return seen


def home_colours(palette: themes.Palette) -> dict[str, set[str]]:
    """Every colour on the home screen and on its new-event form, opened in `palette`."""
    menu = homes.items(have_config=True, events=())
    assert menu[0].choice == ("new",)
    app = HomeApp(menu, "solvers (L1): none installed", palette)
    seen: dict[str, set[str]] = {}

    async def main() -> None:
        async with app.run_test(size=(140, 60)) as pilot:
            await pilot.pause()
            seen["home"] = screen_colors(app)
            await pilot.press("enter")
            await pilot.pause()
            assert type(app.screen).__name__ == "NewEventForm"
            seen["new event form"] = screen_colors(app)

    asyncio.run(main())
    return seen


# ---------------------------------------------------------------------- the palette in use (console/theme.py)


def test_the_strange_palette_shares_no_colour_with_the_default_and_repeats_none():
    strange, default = colours(STRANGE), colours(themes.DEFAULT)
    assert len(set(strange.values())) == len(themes.ROLES) == 17
    assert not set(strange.values()) & set(default.values())
    assert STRANGE.syntax != themes.DEFAULT.syntax


def test_a_colours_name_gives_the_palette_in_uses_colour_for_its_role_when_it_is_read():
    assert theme.active() is themes.DEFAULT  # each test starts in the default theme (conftest)
    assert set(theme.NAMES.values()) <= set(themes.ROLES) and len(set(theme.NAMES.values())) == len(theme.NAMES) == 15
    assert (theme.GREEN, theme.RED, theme.PAGE) == ("#4ebf71", "#e0475b", "#121212")
    theme.use(STRANGE)
    assert theme.active() is STRANGE
    for name, role in theme.NAMES.items():
        assert getattr(theme, name) == getattr(STRANGE, role), name
    assert theme.key_chip("a").style.color.name == STRANGE.ink and theme.key_chip("a").style.bgcolor.name == STRANGE.accent
    line = theme.segments([("one", "#000001", "#000002", True), ("two", "#000003", "#000004", False)])
    assert [span.style.color.name for span in line.spans] == ["#000001", STRANGE.border, "#000003"]  # the ╱ between is the border's
    with pytest.raises(AttributeError, match="MAGENTA"):
        theme.MAGENTA  # a colour no role has: not the default's in silence
    with pytest.raises(AttributeError):
        theme.no_such_thing


def test_alert_and_approval_chips_take_their_colours_from_the_palette_in_use():
    theme.use(STRANGE)
    assert theme.alert_colors(AlertKind.FLAG) == (STRANGE.ink, STRANGE.ok)
    assert theme.alert_colors(AlertKind.BUDGET) == (STRANGE.ink, STRANGE.accent)
    assert theme.alert_colors(AlertKind.TEAMMATE) == (STRANGE.ink, STRANGE.info)
    for kind in (AlertKind.LOOP, AlertKind.STALL, AlertKind.HINT, AlertKind.DIRECTION, AlertKind.EFFORT):
        assert theme.alert_colors(kind) == (STRANGE.ink_light, STRANGE.error)  # a course alert
    assert theme.pending_colors() == (STRANGE.ink_light, STRANGE.pending)
    theme.use(NORD)
    assert theme.alert_colors(AlertKind.FLAG) == (NORD.ink, NORD.ok) and theme.pending_colors() == (NORD.ink_light, NORD.pending)


def test_the_palette_in_use_is_what_textual_is_given_as_its_theme_and_as_the_styles_variables():
    theme.use(STRANGE)
    assert theme.css_variables() == {
        "fd-page": STRANGE.page, "fd-surface": STRANGE.surface, "fd-border": STRANGE.border, "fd-muted": STRANGE.muted,
        "fd-accent": STRANGE.accent, "fd-selected": STRANGE.selected, "fd-selected-focus": STRANGE.selected_focus,
    }
    made = theme.textual()
    assert (made.name, made.dark, made.variables) == ("fd-strange", True, theme.css_variables())
    assert (made.primary, made.accent, made.warning, made.error, made.success) == (
        STRANGE.brand, STRANGE.accent, STRANGE.warn, STRANGE.error, STRANGE.ok)
    assert (made.foreground, made.background, made.surface) == (STRANGE.text, STRANGE.page, STRANGE.surface)
    assert made.secondary is None and made.panel is None  # left for Textual to derive
    theme.use(themes.BUILTIN["light"])
    assert (theme.textual().name, theme.textual().dark) == ("fd-light", False)


def test_the_palettes_are_plain_data_the_console_does_not_change():
    before = dataclasses.asdict(NORD)
    theme.use(NORD)
    theme.textual()
    theme.css_variables()
    assert dataclasses.asdict(NORD) == before and themes.BUILTIN["nord"] is NORD


def test_no_console_module_reads_a_colour_when_it_is_imported():
    """A colour read at import (a module-level table, a default argument, a class attribute)
    would stay the default theme's whatever the player chose. A fresh interpreter imports
    every module of the package and reports each read of a colour's name."""
    spy = (
        "import importlib, pkgutil, traceback\n"
        "import ctf_flightdeck\n"
        "from ctf_flightdeck.console import theme\n"
        "real, reads = theme.__getattr__, []\n"
        "def spy(name):\n"
        "    if name in theme.NAMES:\n"
        "        frame = traceback.extract_stack()[-2]\n"
        "        reads.append(f'{name} at {frame.filename}:{frame.lineno}')\n"
        "    return real(name)\n"
        "theme.__getattr__ = spy\n"
        "names = [m.name for m in pkgutil.walk_packages(ctf_flightdeck.__path__, 'ctf_flightdeck.')]\n"
        "for name in names:\n"
        "    if not name.endswith('__main__'):\n"
        "        importlib.import_module(name)\n"
        "assert 'ctf_flightdeck.console.views' in names and 'ctf_flightdeck.console.screens' in names\n"
        "assert theme.GREEN == '#4ebf71' and reads, 'the spy sees no read at all'\n"
        "print('\\n'.join(reads[:-1]))\n"
    )
    done = subprocess.run([sys.executable, "-c", spy], capture_output=True, text=True, timeout=120)
    assert done.returncode == 0, done.stderr
    assert done.stdout.strip() == "", f"colours read at import:\n{done.stdout}"


# ---------------------------------------------------------------------- every screen, in the palette


def test_nothing_on_any_screen_is_drawn_in_a_colour_the_palette_did_not_give(tmp_path):
    """The same screens in the default theme and in a palette that shares no colour with it:
    a colour on both was not drawn from the palette (a hex in a style sheet, a colour's name
    like "green", a table filled when its module was imported). Only the picture's own window
    frame is on both."""
    handout = tmp_path / "handout.bin"
    handout.write_bytes(b"synthetic")
    default = console_colours(themes.DEFAULT, handout) | home_colours(themes.DEFAULT)
    assert theme.active() is themes.DEFAULT
    strange = console_colours(STRANGE, handout) | home_colours(STRANGE)
    assert list(strange) == ["fleet", "command menu", "focus", "help", "config", "new", "home", "new event form"]
    for screen, seen in strange.items():
        assert seen & default[screen] == SVG_FRAME, f"{screen}: drawn the same in both themes: {sorted(seen & default[screen] - SVG_FRAME)}"
        assert not seen & set(colours(themes.DEFAULT).values()), screen
        assert themes.DEFAULT.page in default[screen] and STRANGE.page in seen, screen  # each really is in its own theme
    # and what the palette gives is what is drawn: each role where it belongs
    assert {STRANGE.segment, STRANGE.brand, STRANGE.border, STRANGE.muted, STRANGE.text, STRANGE.selected_focus, STRANGE.ok,
            STRANGE.error, STRANGE.warn, STRANGE.pending, STRANGE.info, STRANGE.accent, STRANGE.ink, STRANGE.ink_light} <= strange["fleet"]
    assert STRANGE.surface in strange["command menu"] and STRANGE.surface in strange["new event form"]
    assert STRANGE.ok in strange["new"]  # "attached ..."
    assert {STRANGE.selected, STRANGE.brand, STRANGE.accent, STRANGE.muted, STRANGE.ink} <= strange["home"]
    nord_diff, monokai_diff = {"#bf616a", "#a3be8c"}, {"#ff4689", "#a6e22e"}  # a removed and an added line, in each Pygments style
    assert nord_diff <= strange["focus"] and not monokai_diff & strange["focus"]
    assert monokai_diff <= default["focus"]


def test_two_consoles_in_two_palettes_each_show_their_own_colours():
    shown = {}
    for palette in (STRANGE, NORD):
        world, app = busy_console(palette)

        async def main(world=world, app=app, palette=palette) -> None:
            async with app.run_test(size=SIZE) as pilot:
                await pilot.pause()
                await step_until(pilot, app, lambda: busy(world), "a busy console", limit=400)
                header = app.screen.query_one("#header").region.y
                shown[palette.name] = (color_of(app, "flightdeck", header), color_of(app, "lane", row_of(app, "last action")),
                                       palette.page in screen_colors(app))

        asyncio.run(main())
    assert shown == {"strange": (STRANGE.ink_light, STRANGE.muted, True), "nord": (NORD.ink_light, NORD.muted, True)}
    assert shown["strange"][:2] != shown["nord"][:2]


# ---------------------------------------------------------------------- $TEXTUAL_THEME


def dialog_colours() -> dict[str, list[str]]:
    """The colours of the fleet, of a dialog over it and of the home screen, in the default
    theme. Dialogs are drawn in Textual's own variables ($surface, $background), which
    $TEXTUAL_THEME would set."""
    world, app = busy_console()
    seen = {}

    async def main() -> None:
        async with app.run_test(size=SIZE) as pilot:
            await pilot.pause()
            await step_until(pilot, app, lambda: busy(world), "a busy console", limit=400)
            seen["fleet"] = sorted(screen_colors(app))
            app.run_command("/config", None)
            await pilot.pause()
            await pilot.pause()
            assert type(app.screen).__name__ == "ConfigPrompt"
            seen["config"] = sorted(screen_colors(app))
            seen["theme"] = [app.theme]

    asyncio.run(main())
    return seen | {name: sorted(found) for name, found in home_colours(themes.DEFAULT).items()}


def test_TEXTUAL_THEME_in_the_environment_changes_no_colour():
    """Textual reads $TEXTUAL_THEME once, when it is imported, so the console that has it is
    opened in an interpreter of its own, and its colours are compared with this one's."""
    code = ("import json, sys\nsys.path.insert(0, sys.argv[1])\nimport textual.constants\nimport test_theme_console\n"
            "print(json.dumps({'textual': textual.constants.DEFAULT_THEME} | test_theme_console.dialog_colours()))\n")
    env = {**os.environ, "TEXTUAL_THEME": "textual-light"}
    done = subprocess.run([sys.executable, "-c", code, str(TESTS)], capture_output=True, text=True, env=env, timeout=120)
    assert done.returncode == 0, done.stderr
    there = json.loads(done.stdout.splitlines()[-1])
    assert there.pop("textual") == "textual-light"  # Textual did read it: its own default would have been the light theme
    here = dialog_colours()
    assert there == here and here["theme"] == ["fd-flightdeck"]
    assert themes.DEFAULT.page in here["config"] and themes.DEFAULT.page in here["home"]


# ---------------------------------------------------------------------- the home screen


def test_the_home_screen_opens_no_command_palette():
    """Textual's command palette has a theme picker of Textual's own themes, which would
    repaint only the half of the screen its styles draw."""
    app = HomeApp(homes.items(have_config=True, events=()), "")

    async def main() -> None:
        async with app.run_test(size=(140, 60)) as pilot:
            await pilot.pause()
            assert isinstance(app.screen, Menu) and len(app.screen_stack) == 1
            await pilot.press("ctrl+p")
            await pilot.pause()
            assert isinstance(app.screen, Menu) and len(app.screen_stack) == 1
            assert app.theme == "fd-flightdeck"

    asyncio.run(main())
