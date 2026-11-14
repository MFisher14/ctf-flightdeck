"""/theme and /layout alone: a list that is tried as the cursor moves, kept with Enter, saved with s.
And /config's Console group: the same two, set in the settings dialog and saved from there.

Read from the screen as a player sees it (test_console's helpers rebuild the terminal from the
SVG export). Every theme and config file is the test's own, under tmp_path; nothing needs a
model or a network.
"""

from __future__ import annotations

import asyncio
import os
import re
from pathlib import Path

import pytest
from textual.widgets import OptionList

from ctf_flightdeck import themes
from ctf_flightdeck.config import load_config, load_console
from ctf_flightdeck.console import theme
from ctf_flightdeck.console.fleet import FleetScreen
from ctf_flightdeck.console.focus import FocusScreen
from ctf_flightdeck.console.screens import Choice, ConfigPrompt, Picker, Settings
from ctf_flightdeck.core.attention import SortMode
from test_console import assert_warning, bar, color_of, columns, cursor_key, drive, lane_rows, open_focus, press, prompt_text, region_text, \
    screen_colors, screen_lines, status_line, step_until
from test_layout import DECK_COLUMNS, SIMPLE_COLUMNS, three_lanes
from test_theme_console import NORD, STRANGE, busy, busy_console, colours, own_themes, row_of

SIZE = (160, 46)
CONFIG = '[api]\nbase_url = "http://127.0.0.1:11434/v1"\nkey_env = ""\n\n[models]\nladder = ["local-model"]\n\n[lanes]\nruntime = "host"\n'
DEFAULT = themes.DEFAULT


def a_config(tmp_path: Path, text: str = CONFIG) -> Path:
    path = tmp_path / "config.toml"
    path.write_text(text, encoding="utf-8")
    return path


async def typed(pilot, app, text: str) -> None:
    """Run `text` as the command bar would on Enter. (Not pasted, as test_console's send() does: a paste that starts
    with / is first read as a dropped file's path.)"""
    app.run_command(text, app.screen.lane_id if isinstance(app.screen, FocusScreen) else None)
    await pilot.pause()
    await pilot.pause()


def picker(app) -> Picker:
    assert isinstance(app.screen, Picker), type(app.screen).__name__
    return app.screen


def dialog(app) -> list[str]:
    """The picker's rows as the screen shows them, without its border and the list's scrollbar."""
    return [re.sub(r"[│╭╮╰╯─▔▁▂▃▄▅▆▇█]", " ", line).strip() for line in region_text(app, "Vertical").splitlines()]


def rows(app) -> list[str]:
    """The list's rows, as the screen shows them."""
    return [line.strip() for line in region_text(app, "#picker-list").splitlines()]


def keys(app) -> list[str]:
    """The dialog's key rows, each as `key what it does`."""
    return [" ".join(line.split()) for line in region_text(app, "#picker-keys").splitlines() if line.strip()]


def note(app) -> str:
    """The muted lines under the list, without their spaces: a path has no space to wrap at, so
    it is cut at the dialog's edge."""
    return "".join(region_text(app, "#picker-note").split())


ALL_KEYS = ["↑↓ try a theme on the console behind this", "enter keep it for this run", "s keep it, and save it in your config",
            "esc back to what it was"]


def said_in(app) -> str:
    """Everything the picker says, as one line."""
    return " ".join(" ".join(dialog(app)).split())


def cursor(app) -> str | None:
    option = picker(app).query_one(OptionList).highlighted_option
    return None if option is None else str(option.id)


def not_default(palette: themes.Palette) -> set[str]:
    """The colours of the default theme that `palette` does not have: none of them is on a
    screen drawn in `palette`."""
    return set(colours(DEFAULT).values()) - set(colours(palette).values())


# ---------------------------------------------------------------------- /theme


def test_theme_alone_lists_every_theme_marks_the_one_in_use_and_says_why_one_cannot_be_used(tmp_path):
    folder = own_themes(tmp_path)
    world, app = busy_console(NORD, themes_folder=folder, config_path=str(a_config(tmp_path)))

    async def main() -> None:
        async with app.run_test(size=SIZE) as pilot:
            await pilot.pause()
            await typed(pilot, app, "/theme")
            assert region_text(app, "#picker-title").strip() == "Theme"
            listed = rows(app)
            assert listed[:6] == ["flightdeck  built in", "light  built in", "nord  built in, in use", "gruvbox  built in", "dracula  built in",
                                  "broken  yours"]
            # why it cannot be used, under its name; the file by its name, since its folder is said under the list
            assert " ".join(listed[6:-1]) == ('cannot be used: broken.toml: colors.accent must be a colour written as # and six hex digits, '
                                              'like "#ffa62b"')
            assert listed[-1] == "dusk  yours"
            assert note(app) == f"Your own themes are NAME.toml files in {folder}".replace(" ", "")
            assert keys(app) == ALL_KEYS
            assert cursor(app) == "nord" and theme.active() is NORD  # the cursor is on the theme in use; nothing is drawn anew
            assert app._status is None  # and nothing is said: the list is the answer
            await press(pilot, "escape")
            assert isinstance(app.screen, FleetScreen) and theme.active() is NORD

    asyncio.run(main())


def test_the_cursor_draws_the_console_behind_the_list_in_the_theme_it_is_on_and_esc_puts_the_old_one_back(tmp_path):
    folder = own_themes(tmp_path)
    config = a_config(tmp_path)
    world, app = busy_console(themes_folder=folder, config_path=str(config))

    async def main() -> None:
        async with app.run_test(size=SIZE) as pilot:
            await pilot.pause()
            await step_until(pilot, app, lambda: busy(world), "a busy console", limit=400)
            lane = next(lane for lane in world.deck.lanes.values() if lane.files)
            focus = await open_focus(pilot, app, lane.id)
            app.run_command("written before the list", lane.id)
            await pilot.pause()
            app.refresh_view()
            await pilot.pause()
            said = app._status
            before, lines = screen_colors(app), screen_lines(app)
            written = row_of(app, "written before the list")
            assert color_of(app, "written before the list", written) == DEFAULT.accent

            await typed(pilot, app, "/theme")
            assert cursor(app) == "flightdeck" and theme.active() is DEFAULT
            assert DEFAULT.page in screen_colors(app)  # the console behind is not dimmed: the page's own colour is on screen
            seen = {}
            for name in ("light", "nord", "gruvbox", "dracula", "dusk"):  # down from dracula: past `broken`, which cannot be chosen
                await press(pilot, "down")
                assert cursor(app) == name and theme.active().name == name and app.theme == f"fd-{name}"
                palette = theme.active()
                seen[name] = screen_colors(app)
                assert palette.page in seen[name] and not seen[name] & not_default(palette), name
                # what was on screen already, a transcript's line too, and the dialog's own rows and keys
                assert color_of(app, "written before the list", written) == palette.accent, name
                assert color_of(app, "built in", row_of(app, "flightdeck  built in")) == palette.muted, name
                assert color_of(app, "enter", row_of(app, "keep it for this run")) == palette.ink, name
            assert theme.active().accent == "#ff5fd7" and "#ff5fd7" in seen["dusk"]  # the player's own file
            await press(pilot, "up")  # and back up, past it again
            assert cursor(app) == "dracula" and theme.active() is themes.BUILTIN["dracula"]

            await press(pilot, "escape")
            assert app.screen is focus and theme.active() is DEFAULT and app.theme == "fd-flightdeck"
            assert screen_colors(app) == before and screen_lines(app) == lines  # as it was, to the last cell
            assert app._status == said and config.read_text() == CONFIG  # nothing said, nothing written

    asyncio.run(main())


def test_enter_keeps_the_theme_for_this_run_and_writes_nothing(tmp_path):
    config = a_config(tmp_path)
    world, app = busy_console(themes_folder=own_themes(tmp_path), config_path=str(config))

    async def main() -> None:
        async with app.run_test(size=SIZE) as pilot:
            await pilot.pause()
            await typed(pilot, app, "/theme")
            await press(pilot, "down", "down")
            assert cursor(app) == "nord"
            await press(pilot, "enter")
            assert isinstance(app.screen, FleetScreen) and theme.active() is NORD and app.theme == "fd-nord"
            assert app._status[:2] == ("theme nord for this run. To keep it: /theme, then s", "information")
            assert NORD.page in screen_colors(app) and not screen_colors(app) & not_default(NORD)
            assert config.read_text() == CONFIG
            # the list again: the cursor is on what is in use now, and enter there changes nothing
            await typed(pilot, app, "/theme")
            assert cursor(app) == "nord" and "nord  built in, in use" in dialog(app)
            await press(pilot, "enter")
            assert theme.active() is NORD and config.read_text() == CONFIG

    asyncio.run(main())


def test_s_keeps_the_theme_and_saves_it_and_the_next_console_opens_in_it(tmp_path):
    config = a_config(tmp_path)
    world, app = busy_console(themes_folder=own_themes(tmp_path), config_path=str(config))

    async def main() -> None:
        async with app.run_test(size=SIZE) as pilot:
            await pilot.pause()
            await typed(pilot, app, "/theme")
            await press(pilot, "end")
            assert cursor(app) == "dusk"
            await press(pilot, "s")
            assert isinstance(app.screen, FleetScreen) and theme.active().name == "dusk"
            assert app._status[:2] == (f"theme dusk, saved in your config file: {config}", "information")
            assert config.read_text() == CONFIG + '\n[console]\ntheme = "dusk"\n'
            # saved again from the list, where the cursor is on it: the file says so already
            stamp = os.stat(config).st_mtime_ns
            await typed(pilot, app, "/theme")
            await press(pilot, "s")
            assert app._status[0] == f"theme dusk, saved in your config file: {config}" and os.stat(config).st_mtime_ns == stamp
            # and another one over it: the same line, changed
            await typed(pilot, app, "/theme")
            await press(pilot, "home", "down", "s")
            assert theme.active().name == "light" and config.read_text() == CONFIG + '\n[console]\ntheme = "light"\n'

    asyncio.run(main())
    loaded = load_config(config)  # what a run reads: the whole config still loads, in the theme saved
    assert loaded.console.theme == "light" and loaded.console.palette is themes.BUILTIN["light"]
    world, again = busy_console(loaded.console.palette, themes_folder=config.parent / "themes", config_path=str(config))

    async def main() -> None:
        async with again.run_test(size=SIZE) as pilot:
            await pilot.pause()
            assert themes.BUILTIN["light"].page in screen_colors(again) and not screen_colors(again) & not_default(themes.BUILTIN["light"])
            await typed(pilot, again, "/theme")
            assert cursor(again) == "light" and "light  built in, in use" in dialog(again)

    asyncio.run(main())


@pytest.mark.parametrize("config_text, reason", [
    ('console.mouse = false\n' + CONFIG,
     'flightdeck could not place the line in {path}, which was left as it is: write theme = "nord" under [console] yourself'),
    (CONFIG + "[console\n", '{path} is not valid TOML, so it was left as it is: mend it, or write theme = "nord" under [console] yourself'),
    (None, "there is no config at {path}: run `flightdeck init` first"),
], ids=["a table flightdeck cannot edit", "not TOML", "no file"])
def test_a_save_that_fails_says_why_leaves_the_file_as_it_was_and_the_run_keeps_the_theme(tmp_path, config_text, reason):
    config = tmp_path / "config.toml"
    if config_text is not None:
        config.write_text(config_text)
    world, app = busy_console(config_path=str(config))

    async def main() -> None:
        async with app.run_test(size=SIZE) as pilot:
            await pilot.pause()
            await typed(pilot, app, "/theme")
            await press(pilot, "down", "down", "s")
            assert isinstance(app.screen, FleetScreen)
            assert app._status[:2] == (f"theme nord for this run; it was not saved: {reason.format(path=config)}", "warning")
            assert_warning(app, "theme nord for this run; it was not saved:")
            assert theme.active() is NORD and NORD.page in screen_colors(app)  # the run keeps it either way
            assert (config.read_text() if config_text is not None else None) == config_text and config.exists() is (config_text is not None)

    asyncio.run(main())


def test_a_config_that_cannot_be_written_keeps_the_theme_for_the_run_and_says_so(tmp_path):
    config = a_config(tmp_path)
    config.chmod(0o400)
    if os.access(config, os.W_OK):  # whoever runs this may write any file (root): the refusal cannot be shown
        pytest.fail("this test needs a user a read-only file refuses; it was not run as one")
    world, app = busy_console(config_path=str(config))

    async def main() -> None:
        async with app.run_test(size=SIZE) as pilot:
            await pilot.pause()
            await typed(pilot, app, "/theme")
            await press(pilot, "down", "s")
            assert app._status[:2] == (f"theme light for this run; it was not saved: cannot write the config {config} (Permission denied): "
                                       "it is as it was", "warning")
            assert theme.active() is themes.BUILTIN["light"]

    try:
        asyncio.run(main())
    finally:
        config.chmod(0o600)
    assert config.read_text() == CONFIG


def test_a_theme_file_that_stops_loading_after_it_was_listed_is_not_saved(tmp_path):
    """The list read the file when it opened; the save loads the config as a console will."""
    folder, config = own_themes(tmp_path), a_config(tmp_path)
    world, app = busy_console(themes_folder=folder, config_path=str(config))

    async def main() -> None:
        async with app.run_test(size=SIZE) as pilot:
            await pilot.pause()
            await typed(pilot, app, "/theme")
            await press(pilot, "end")
            (folder / "dusk.toml").write_text('base = "nord"\n[colors]\naccent = "pink"\n')
            await press(pilot, "s")
            assert app._status[1] == "warning" and app._status[0] == (
                "theme dusk for this run; it was not saved: the config did not load with the theme in it, so it was put back as it was: "
                f'{folder / "dusk.toml"}: colors.accent must be a colour written as # and six hex digits, like "#ffa62b"')
            assert theme.active().accent == "#ff5fd7" and config.read_text() == CONFIG  # the colours it was listed with, for this run

    asyncio.run(main())


def test_with_no_config_file_the_list_has_no_save_key_and_s_says_why(tmp_path):
    world, app = busy_console()  # the mock with no config: no config file, and no themes folder

    async def main() -> None:
        async with app.run_test(size=SIZE) as pilot:
            await pilot.pause()
            await typed(pilot, app, "/theme")
            assert rows(app) == ["flightdeck  built in, in use", "light  built in", "nord  built in", "gruvbox  built in", "dracula  built in"]
            assert note(app) == "This console has no config file, so a theme lasts for this run.".replace(" ", "")
            assert keys(app) == [key for key in ALL_KEYS if not key.startswith("s ")]
            await press(pilot, "down", "s")
            assert isinstance(app.screen, Picker) and cursor(app) == "light"  # still open, on the same row
            said = " ".join(region_text(app, "#picker-said").split())
            assert said == "Nothing to save it in: this console has no config file. Enter keeps the theme for this run."
            assert color_of(app, "Nothing to save it in", app.screen.query_one("#picker-said").region.y) == theme.active().warn
            await press(pilot, "down")  # the line goes when the cursor moves on
            assert not app.screen.query_one("#picker-said").display and "Nothing to save it in" not in "\n".join(dialog(app))
            await press(pilot, "enter")
            assert app._status[:2] == ("theme nord for this run (this console has no config file)", "information")
            assert theme.active() is NORD

    asyncio.run(main())


def test_a_console_in_a_theme_the_list_does_not_have_starts_with_no_row_chosen(tmp_path):
    """A theme whose file is gone since the console opened, or one the app was given: nothing is
    in use in the list, s has nothing to save until the cursor is on a row, and esc keeps it."""
    config = a_config(tmp_path)
    world, app = busy_console(STRANGE, config_path=str(config))

    async def main() -> None:
        async with app.run_test(size=SIZE) as pilot:
            await pilot.pause()
            await typed(pilot, app, "/theme")
            assert cursor(app) is None and not any("in use" in line for line in dialog(app)) and theme.active() is STRANGE
            await press(pilot, "s")
            assert isinstance(app.screen, Picker) and theme.active() is STRANGE and config.read_text() == CONFIG
            assert " ".join(region_text(app, "#picker-said").split()) == "No theme is chosen yet: move to one with ↑ or ↓."
            await press(pilot, "down")
            assert cursor(app) == "flightdeck" and theme.active() is DEFAULT
            await press(pilot, "escape")
            assert theme.active() is STRANGE and STRANGE.page in screen_colors(app) and not screen_colors(app) & set(colours(DEFAULT).values())

    asyncio.run(main())


def test_the_list_reads_a_theme_file_as_it_is_now(tmp_path):
    """The theme in use, its file changed since: the list shows it as the file is, and esc goes
    back to the colours the console had."""
    folder = own_themes(tmp_path)
    world, app = busy_console(themes_folder=folder)

    async def main() -> None:
        async with app.run_test(size=SIZE) as pilot:
            await pilot.pause()
            app.run_command("/theme dusk", None)
            await pilot.pause()
            had = theme.active()
            assert had.border == NORD.border
            (folder / "dusk.toml").write_text('base = "nord"\n[colors]\naccent = "#ff5fd7"\nborder = "#aa55cc"\n')
            await typed(pilot, app, "/theme")
            await pilot.pause()
            assert cursor(app) == "dusk" and theme.active().border == "#aa55cc" and "#aa55cc" in screen_colors(app)
            await press(pilot, "escape")
            assert theme.active() is had and "#aa55cc" not in screen_colors(app)
            (folder / "dusk.toml").write_text("not a theme\n")  # and one that broke meanwhile cannot be chosen: no row is
            await typed(pilot, app, "/theme")
            assert cursor(app) is None and theme.active() is had
            assert "dusk yours, in use cannot be used: dusk.toml: Expected '=' after a key in a key/value pair (at line 1, column 5)" in said_in(app)

    asyncio.run(main())


@pytest.mark.parametrize("size", [(80, 24), (80, 16), (56, 20), (40, 14)], ids=lambda size: f"{size[0]}x{size[1]}")
def test_the_lists_keys_are_on_screen_on_a_short_terminal_and_the_list_scrolls_to_the_cursor(tmp_path, size):
    folder = tmp_path / "themes"
    folder.mkdir()
    for n in range(30):
        (folder / f"mine-{n:02}.toml").write_text('base = "nord"\n')
    world, app = busy_console(themes_folder=folder, config_path=str(a_config(tmp_path)))

    async def main() -> None:
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            await typed(pilot, app, "/theme")
            screen = picker(app)

            def whole(selector: str) -> bool:
                region = screen.query_one(selector).region
                return region.height > 0 and 0 <= region.y and region.bottom <= size[1]

            def shown_keys() -> str:
                return " ".join(region_text(app, "#picker-keys").split())

            assert whole("#picker-title") and whole("#picker-keys") and whole("#picker-list")
            for key in ALL_KEYS:  # a key's meaning may wrap under itself on a narrow terminal: the same words, in order
                assert key in shown_keys(), (key, shown_keys())
            assert rows(app)[0] == "flightdeck  built in, in use"
            await press(pilot, "end")
            assert cursor(app) == "mine-29" and theme.active().name == "mine-29"
            assert rows(app)[-1] == "mine-29  yours" and "flightdeck  built in" not in rows(app)  # scrolled to it
            assert whole("#picker-keys") and "esc back to what it was" in shown_keys()

    asyncio.run(main())


def test_a_click_keeps_a_row_and_a_row_that_cannot_be_used_takes_no_click(tmp_path):
    world, app = busy_console(themes_folder=own_themes(tmp_path), config_path=str(a_config(tmp_path)))

    async def main() -> None:
        async with app.run_test(size=SIZE) as pilot:
            await pilot.pause()
            await typed(pilot, app, "/theme")
            rows = picker(app).query_one(OptionList).region
            await pilot.click(OptionList, offset=(4, row_of(app, "broken  yours") - rows.y))
            await pilot.pause()
            assert isinstance(app.screen, Picker) and cursor(app) == "flightdeck" and theme.active() is DEFAULT
            await pilot.click(OptionList, offset=(4, row_of(app, "gruvbox  built in") - rows.y))
            await pilot.pause()
            assert isinstance(app.screen, FleetScreen) and theme.active() is themes.BUILTIN["gruvbox"]
            assert app._status[0] == "theme gruvbox for this run. To keep it: /theme, then s"

    asyncio.run(main())


# ---------------------------------------------------------------------- /layout


def test_layout_alone_lists_both_layouts_tries_the_one_under_the_cursor_and_esc_puts_the_old_one_back(tmp_path):
    config = a_config(tmp_path)
    deck, app = three_lanes("simple", config_path=str(config))

    async def script(pilot):
        app.fleet.set_filter("a")  # every lane: Alpha, Beta, Gamma
        app.fleet.set_sort(SortMode.LANE)
        app.fleet.select_lane("L03")
        await pilot.pause()
        before, said = lane_rows(app), app._status
        await typed(pilot, app, "/layout")
        assert region_text(app, "#picker-title").strip() == "Layout"
        assert rows(app) == ["simple  the lanes and what needs you, in use", "deck  the board and every column"]
        assert keys(app) == [key.replace("theme", "layout") for key in ALL_KEYS]
        assert not app.screen.query("#picker-note")  # a config file, and a terminal with the room: nothing to add
        assert cursor(app) == "simple" and app.layout == "simple" and columns(app, "lanes") == SIMPLE_COLUMNS
        await press(pilot, "down")
        await pilot.pause()
        assert cursor(app) == "deck" and app.layout == "deck" and columns(app, "lanes") == DECK_COLUMNS and not app.fleet.board_hidden
        assert "board 3" in "\n".join(screen_lines(app))  # the board is on screen behind the list
        await press(pilot, "up")
        await pilot.pause()
        assert app.layout == "simple" and columns(app, "lanes") == SIMPLE_COLUMNS and app.fleet.board_hidden
        await press(pilot, "down", "escape")
        await pilot.pause()
        assert isinstance(app.screen, FleetScreen) and app.layout == "simple" and columns(app, "lanes") == SIMPLE_COLUMNS
        assert (app.fleet.selected_lane, cursor_key(app), lane_rows(app)) == ("L03", "L03", before)
        assert (app.fleet.filter_text, app.fleet.sort) == ("a", SortMode.LANE)
        assert app._status == said and config.read_text() == CONFIG  # nothing said, nothing written

    drive(app, script, SIZE)


def test_enter_keeps_the_layout_for_this_run_and_s_saves_it(tmp_path):
    config = a_config(tmp_path, CONFIG + '\n[console]\n# layout = "simple"\ntheme = "nord"\n')
    deck, app = three_lanes("simple", config_path=str(config))

    async def script(pilot):
        await typed(pilot, app, "/layout")
        await press(pilot, "down", "enter")
        await pilot.pause()
        assert isinstance(app.screen, FleetScreen) and app.layout == "deck" and columns(app, "lanes") == DECK_COLUMNS
        assert "layout deck for this run. To keep it: /layout, then s" in status_line(app)
        assert config.read_text() == CONFIG + '\n[console]\n# layout = "simple"\ntheme = "nord"\n'
        await typed(pilot, app, "/layout")
        assert cursor(app) == "deck" and "deck  the board and every column, in use" in dialog(app)
        await press(pilot, "s")  # on the layout in use: saved as it is
        assert app.layout == "deck" and app._status[:2] == (f"layout deck, saved in your config file: {config}", "information")
        assert config.read_text() == CONFIG + '\n[console]\n# layout = "simple"\nlayout = "deck"\ntheme = "nord"\n'
        assert (load_console(config).layout, load_console(config).theme) == ("deck", "nord")
        await typed(pilot, app, "/layout")
        await press(pilot, "up", "s")
        await pilot.pause()
        assert app.layout == "simple" and columns(app, "lanes") == SIMPLE_COLUMNS
        assert config.read_text() == CONFIG + '\n[console]\n# layout = "simple"\nlayout = "simple"\ntheme = "nord"\n'

    drive(app, script, SIZE)


def test_the_layout_list_opens_over_a_lanes_view_and_lays_that_view_out_too(tmp_path):
    deck, app = three_lanes("simple")

    async def script(pilot):
        focus = await open_focus(pilot, app, "L01")
        bar(app).start("a draft to keep")
        await pilot.pause()
        bar(app).clear()
        await typed(pilot, app, "/layout")
        assert isinstance(app.screen, Picker) and "This console has no config file, so a layout lasts for this run." in said_in(app)
        simple = [line[:60] for line in screen_lines(app)]
        await press(pilot, "down")
        await pilot.pause()
        assert app.layout == "deck" and [line[:60] for line in screen_lines(app)] != simple  # the lane's view behind, in deck
        await press(pilot, "escape")
        await pilot.pause()
        assert app.screen is focus and isinstance(focus, FocusScreen) and app.layout == "simple"
        assert [line[:60] for line in screen_lines(app)] == simple

    drive(app, script, SIZE)


def test_on_a_narrow_terminal_the_layout_list_says_the_compact_layout_shows_in_both():
    deck, app = three_lanes("simple")

    async def script(pilot):
        assert app.fleet.compact
        await typed(pilot, app, "/layout")
        assert "This terminal is narrow, so the compact layout shows in both." in said_in(app)
        await press(pilot, "down", "enter")
        await pilot.pause()
        assert app.layout == "deck" and app._status[0] == (
            "layout deck for this run (this console has no config file); this terminal is narrow, so the compact layout shows")

    drive(app, script, (60, 30))


def test_layout_with_a_word_still_switches_at_once_and_opens_no_list(tmp_path):
    config = a_config(tmp_path)
    deck, app = three_lanes("simple", config_path=str(config))

    async def script(pilot):
        await typed(pilot, app, "/layout deck")
        assert isinstance(app.screen, FleetScreen) and app.layout == "deck" and config.read_text() == CONFIG
        await typed(pilot, app, "/theme nord")
        assert isinstance(app.screen, FleetScreen) and theme.active() is NORD and config.read_text() == CONFIG

    drive(app, script, SIZE)


# ---------------------------------------------------------------------- the dialog itself


def test_a_picker_hands_each_row_the_cursor_reaches_to_preview_and_answers_with_the_row_and_whether_to_save():
    deck, app = three_lanes("simple")
    tried, answers = [], []
    choices = [Choice("one", "the first"), Choice("two", "", "two.toml: is not a theme\x1b[2J"), Choice("three", "the third")]

    async def script(pilot):
        for keys, answer in ((("down", "enter"), ("three", False)), (("down", "s"), ("three", True)), (("escape",), None),
                             (("enter",), ("one", False)), (("s",), ("one", True))):
            tried.clear()
            app.push_screen(Picker("thing", choices, in_use="one", preview=tried.append, save_to="/somewhere/config.toml"), answers.append)
            await pilot.pause()
            assert tried == ["one"]  # the row the cursor starts on: whoever opened it decides whether that draws anything
            await press(pilot, *keys)
            assert answers[-1] == answer and not isinstance(app.screen, Picker)
            assert tried == (["one", "three"] if "down" in keys else ["one"]), keys  # never the row that cannot be used
        app.push_screen(Picker("thing", choices, in_use="one", preview=tried.append), answers.append)
        await pilot.pause()
        shown = "\n".join(dialog(app))
        assert "Thing" in shown and "one  the first, in use" in shown and "try a thing on the console behind this" in shown
        assert "cannot be used: two.toml: is not a theme^[[2J" in shown and "\x1b" not in shown  # a problem's text is made safe to show

    drive(app, script, SIZE)


# ---------------------------------------------------------------------- /config: the Console group


def settings(app) -> ConfigPrompt:
    assert isinstance(app.screen, ConfigPrompt), type(app.screen).__name__
    return app.screen


def field(app, name: str):
    return settings(app).query_one(f"#config-{name}")


def options(app, name: str) -> list[str]:
    """What a list of the settings dialog offers, by value."""
    return [value for _, value in field(app, name)._options]


def test_config_shows_the_layout_and_the_theme_in_use_and_every_theme_by_name(tmp_path):
    folder, config = own_themes(tmp_path), a_config(tmp_path)
    deck, app = three_lanes("simple", config_path=str(config), themes_folder=folder, palette=NORD)

    async def script(pilot):
        await typed(pilot, app, "/config")
        assert (field(app, "layout").value, field(app, "theme").value, field(app, "save").value) == ("simple", "nord", False)
        assert options(app, "layout") == ["simple", "deck"] and options(app, "save") == [False, True]
        # by name only: no theme file is opened for the list, so one that cannot be used is offered, and refused when it is asked for
        assert options(app, "theme") == ["flightdeck", "light", "nord", "gruvbox", "dracula", "broken", "dusk"]
        said = prompt_text(app)
        for part in ("Settings", "Console: its layout and its colours (/layout and /theme try each one first):",
                     "simple: the lanes and what needs you", "Keep that layout and those colours:", "for this run",
                     "enter apply ctrl+s apply from any field tab next field esc cancel"):
            assert part in said, (part, said)
        # (a path has no space to wrap at: the same letters, in order)
        assert f"Lanes and flags last for this run. Your config file keeps their defaults: {config}".replace(" ", "") in said.replace(" ", "")
        await press(pilot, "escape")
        assert isinstance(app.screen, FleetScreen) and app.layout == "simple" and theme.active() is NORD and config.read_text() == CONFIG

    drive(app, script, SIZE)


def test_config_with_no_config_file_has_nothing_to_save_in_and_a_theme_the_lists_do_not_have_is_still_shown():
    deck, app = three_lanes("deck", palette=STRANGE)

    async def script(pilot):
        await typed(pilot, app, "/config")
        assert not settings(app).query("#config-save") and "Keep that layout" not in prompt_text(app)
        assert "These last for this run: this console has no config file." in prompt_text(app)
        assert options(app, "theme") == ["flightdeck", "light", "nord", "gruvbox", "dracula", "strange"]
        assert (field(app, "layout").value, field(app, "theme").value) == ("deck", "strange")
        field(app, "layout").value = "simple"
        await press(pilot, "ctrl+s")
        assert app.layout == "simple" and theme.active() is STRANGE
        assert app._status[:2] == ("Layout simple for this run (this console has no config file)", "information")

    drive(app, script, SIZE)


def test_config_sets_the_layout_and_the_theme_for_this_run_beside_the_runs_other_settings(tmp_path):
    config = a_config(tmp_path)
    deck, app = three_lanes("simple", config_path=str(config), themes_folder=own_themes(tmp_path))

    async def script(pilot):
        await typed(pilot, app, "/config")
        field(app, "theme").value = "dusk"
        await press(pilot, "enter")  # in the lanes field, where the dialog opens
        assert theme.active().name == "dusk" and "#ff5fd7" in screen_colors(app) and app.layout == "simple"
        assert app._status[:2] == ("Theme dusk for this run", "information") and config.read_text() == CONFIG
        await typed(pilot, app, "/config")
        assert field(app, "theme").value == "dusk"
        field(app, "lanes").value = "6"
        field(app, "layout").value = "deck"
        field(app, "theme").value = "light"
        await press(pilot, "tab", "ctrl+s")  # from a list: Enter there opens it
        await pilot.pause()
        assert (app.layout, theme.active().name, deck.config.max_lanes) == ("deck", "light", 6)
        assert columns(app, "lanes") == DECK_COLUMNS and themes.BUILTIN["light"].page in screen_colors(app)
        assert app._status[:2] == ("Lanes at once: 6 for the rest of this run. Layout deck and theme light for this run", "information")
        assert config.read_text() == CONFIG

    drive(app, script, SIZE)


def test_config_saves_the_layout_and_the_theme_when_asked_to_and_what_is_in_use_when_nothing_else_changed(tmp_path):
    config = a_config(tmp_path, CONFIG + '\n[console]\nmouse = false\n')
    deck, app = three_lanes("simple", config_path=str(config), themes_folder=own_themes(tmp_path))

    async def script(pilot):
        await typed(pilot, app, "/config")
        field(app, "theme").value = "nord"
        field(app, "save").value = True
        await press(pilot, "ctrl+s")
        assert theme.active() is NORD and app.layout == "simple"
        # both, as the dialog showed them: the config then says what the console is in
        assert app._status[:2] == (f"Layout simple and theme nord, saved in your config file: {config}", "information")
        assert config.read_text() == CONFIG + '\n[console]\nmouse = false\nlayout = "simple"\ntheme = "nord"\n'
        app.run_command("/layout deck", None)  # for this run
        app.run_command("/theme dusk", None)
        await pilot.pause()
        await typed(pilot, app, "/config")
        assert (field(app, "layout").value, field(app, "theme").value, field(app, "save").value) == ("deck", "dusk", False)
        field(app, "save").value = True  # and nothing else: keep what the console is in
        await press(pilot, "ctrl+s")
        assert app._status[0] == f"Layout deck and theme dusk, saved in your config file: {config}"
        assert config.read_text() == CONFIG + '\n[console]\nmouse = false\nlayout = "deck"\ntheme = "dusk"\n'
        console = load_console(config)
        assert (console.layout, console.theme, console.mouse, console.palette.accent) == ("deck", "dusk", False, "#ff5fd7")

    drive(app, script, SIZE)


def test_config_changes_nothing_when_the_theme_asked_for_cannot_be_used(tmp_path):
    folder, config = own_themes(tmp_path), a_config(tmp_path)
    deck, app = three_lanes("simple", config_path=str(config), themes_folder=folder)

    async def script(pilot):
        for name, why in (("broken", f'{folder / "broken.toml"}: colors.accent must be a colour written as # and six hex digits, like "#ffa62b"'),
                          ("dusk", "theme dusk names no theme: built in are flightdeck, light, nord, gruvbox, dracula; "
                                   f"your own is NAME.toml in {folder}")):
            await typed(pilot, app, "/config")
            if name == "dusk":
                (folder / "dusk.toml").unlink()  # gone since the dialog listed it
            field(app, "lanes").value = "6"
            field(app, "submit").value = "auto"
            field(app, "layout").value = "deck"
            field(app, "theme").value = name
            field(app, "save").value = True
            await press(pilot, "ctrl+s")
            assert app._status[:2] == (f"{why}; nothing was changed", "warning"), name
            assert (deck.config.max_lanes, deck.config.submit, app.layout, theme.active()) == (4, "confirm", "simple", DEFAULT), name
            assert config.read_text() == CONFIG, name

    drive(app, script, SIZE)


def test_a_save_from_config_that_fails_is_a_warning_and_the_run_keeps_what_was_set(tmp_path):
    config = a_config(tmp_path, "console.mouse = false\n" + CONFIG)
    deck, app = three_lanes("simple", config_path=str(config))

    async def script(pilot):
        await typed(pilot, app, "/config")
        field(app, "lanes").value = "6"
        field(app, "layout").value = "deck"
        field(app, "save").value = True
        await press(pilot, "ctrl+s")
        await pilot.pause()
        assert (deck.config.max_lanes, app.layout) == (6, "deck") and columns(app, "lanes") == DECK_COLUMNS
        assert app._status[:2] == (
            "Lanes at once: 6 for the rest of this run. Layout deck and theme flightdeck for this run; it was not saved: flightdeck could "
            f'not place the line in {config}, which was left as it is: write layout = "deck" and theme = "flightdeck" under [console] yourself',
            "warning")
        assert config.read_text() == "console.mouse = false\n" + CONFIG

    drive(app, script, SIZE)


@pytest.mark.parametrize("size", [(80, 24), (56, 20), (120, 36)], ids=lambda size: f"{size[0]}x{size[1]}")
def test_the_settings_keys_are_on_screen_and_tab_reaches_every_field_on_a_short_terminal(tmp_path, size):
    deck, app = three_lanes("simple", config_path=str(a_config(tmp_path)))

    async def script(pilot):
        await typed(pilot, app, "/config")
        keys = settings(app).query_one(".keys")

        def on_screen(widget) -> bool:
            return widget.region.height > 0 and widget.region.y >= 0 and widget.region.bottom <= size[1]

        for name in ("lanes", "submit", "layout", "theme", "save"):
            assert app.focused is field(app, name), name
            assert on_screen(field(app, name)) and on_screen(keys), name  # the field in use is scrolled to, over the keys
            assert field(app, name).region.bottom <= settings(app).query_one("#config-foot").region.y, name
            assert field(app, name).region.height == 3, name  # no label wraps its list a row taller
            assert "esc cancel" in " ".join(region_text(app, ".keys").split())
            await press(pilot, "tab")
        assert app.focused is field(app, "lanes")

    drive(app, script, size)


def test_a_settings_answer_is_what_the_fields_hold_and_the_theme_in_use_is_always_among_the_themes():
    deck, app = three_lanes("simple")
    answers = []

    async def script(pilot):
        now = Settings("4", "confirm", "deck", "mine")
        app.push_screen(ConfigPrompt(now, themes=("flightdeck", "light"), config_path="/somewhere/config.toml"), answers.append)
        await pilot.pause()
        assert options(app, "theme") == ["flightdeck", "light", "mine"] and field(app, "theme").value == "mine"
        await press(pilot, "ctrl+s")
        assert answers == [now]
        app.push_screen(ConfigPrompt(now, themes=("flightdeck", "light"), config_path="/somewhere/config.toml"), answers.append)
        await pilot.pause()
        field(app, "lanes").value = " unlimited "
        field(app, "submit").value = "auto"
        field(app, "layout").value = "simple"
        field(app, "theme").value = "light"
        field(app, "save").value = True
        await press(pilot, "ctrl+s")
        assert answers[-1] == Settings("unlimited", "auto", "simple", "light", True)
        app.push_screen(ConfigPrompt(now, themes=("flightdeck",)), answers.append)  # no config file: never an answer that saves
        await pilot.pause()
        await press(pilot, "escape")
        assert answers[-1] is None

    drive(app, script, SIZE)
