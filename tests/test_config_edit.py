"""config_edit: the one place a config file is changed in, and what the console keeps there.

Every file is the test's own, under tmp_path. Nothing here opens a console.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from ctf_flightdeck import config_edit, themes
from ctf_flightdeck.config import ConfigError, ConsoleConfig, example_config, load_config, load_console
from ctf_flightdeck.config_edit import EditError, rewrite, save_console, set_keys

LADDER = '[api]\nbase_url = "http://127.0.0.1:11434/v1"\nkey_env = ""\n\n[models]\nladder = ["local-model"]\n\n[lanes]\nruntime = "host"\n'


def write(tmp_path: Path, text: str, name: str = "config.toml") -> Path:
    path = tmp_path / name
    path.write_bytes(text.encode("utf-8"))  # bytes: the line endings are the test's
    return path


def read(path: Path) -> str:
    return path.read_bytes().decode("utf-8")


# ---------------------------------------------------------------------- set_keys


def test_set_keys_changes_a_line_that_is_there_and_no_other():
    before = ('# mine\n[api]\ntheme = "not this one"\n\n[console]\n# how it looks\nlayout = "deck"  # the dashboard\n'
              'theme = "light"\nmouse = false\n\n[run]\ndir = "~/runs"\n')
    after = set_keys(before, "console", {"theme": 'theme = "nord"'})
    assert after == before.replace('theme = "light"', 'theme = "nord"')
    assert set_keys(after, "console", {"theme": 'theme = "nord"'}) == after  # said already: the same text
    both = set_keys(before, "console", {"layout": 'layout = "simple"', "theme": 'theme = "nord"'})
    assert both == before.replace('layout = "deck"  # the dashboard', 'layout = "simple"').replace('theme = "light"', 'theme = "nord"')


def test_set_keys_puts_a_new_key_under_its_commented_example_or_at_the_tables_end():
    before = '[console]\n# theme: the colours\n# theme = "flightdeck"\nmouse = false\n\n# the run\n[run]\ndir = "~/runs"\n'
    assert set_keys(before, "console", {"theme": 'theme = "nord"'}) == (
        '[console]\n# theme: the colours\n# theme = "flightdeck"\ntheme = "nord"\nmouse = false\n\n# the run\n[run]\ndir = "~/runs"\n')
    # no example of it: after the table's last line, above the blank ones and the next table's own comments
    assert set_keys(before, "console", {"layout": 'layout = "deck"'}) == (
        '[console]\n# theme: the colours\n# theme = "flightdeck"\nmouse = false\nlayout = "deck"\n\n# the run\n[run]\ndir = "~/runs"\n')
    spaced = '[console]\nmouse = false\n\n\n[run]\ndir = "~/runs"\n'
    assert set_keys(spaced, "console", {"layout": 'layout = "deck"'}) == '[console]\nmouse = false\nlayout = "deck"\n\n\n[run]\ndir = "~/runs"\n'
    # comments with no blank line over them are the table's own, and so are the ones a file ends with
    own = '[console]\nmouse = false\n# and the mouse stays off\n[run]\ndir = "~/runs"\n'
    assert set_keys(own, "console", {"layout": 'layout = "deck"'}) == own.replace("stays off\n", 'stays off\nlayout = "deck"\n')
    only = '[console]\n# nothing set yet\n[run]\ndir = "~/runs"\n'
    assert set_keys(only, "console", {"layout": 'layout = "deck"'}) == only.replace("yet\n", 'yet\nlayout = "deck"\n')
    ends = '[console]\nmouse = false\n\n# the end\n'
    assert set_keys(ends, "console", {"layout": 'layout = "deck"'}) == ends + 'layout = "deck"\n'
    apart = '[console]\n\n# the run\n[run]\ndir = "~/runs"\n'  # an empty table over another's comments
    assert set_keys(apart, "console", {"layout": 'layout = "deck"'}) == '[console]\nlayout = "deck"\n\n# the run\n[run]\ndir = "~/runs"\n'


def test_set_keys_adds_the_table_at_the_end_when_the_file_has_none():
    assert set_keys("[api]\nx = 1\n", "console", {"theme": 'theme = "nord"'}) == '[api]\nx = 1\n\n[console]\ntheme = "nord"\n'
    assert set_keys("[api]\nx = 1", "console", {"theme": 'theme = "nord"'}) == '[api]\nx = 1\n\n[console]\ntheme = "nord"\n'
    assert set_keys("[api]\nx = 1\n\n", "console", {"theme": 'theme = "nord"'}) == '[api]\nx = 1\n\n[console]\ntheme = "nord"\n'
    assert set_keys("", "console", {"theme": 'theme = "nord"'}) == '[console]\ntheme = "nord"\n'
    # a commented table is an example, not the table: the lines under it are still some other table's
    example = '[run]\ndir = "~/runs"\n\n# [console]\n# theme = "flightdeck"\n'
    assert set_keys(example, "console", {"theme": 'theme = "nord"'}) == example + '\n[console]\ntheme = "nord"\n'
    # nothing to set and no table to comment a line out of: the text as it is
    assert set_keys("[api]\nx = 1", "console", {"theme": None}) == "[api]\nx = 1"


def test_set_keys_comments_a_line_out_and_leaves_a_missing_one_alone():
    before = '[l1]\npack = "/p"\n  image = "p:1"\n'
    assert set_keys(before, "l1", {"image": None}) == '[l1]\npack = "/p"\n# image = "p:1"\n'
    assert set_keys(before, "l1", {"lane_tools": None}) == before


def test_set_keys_ends_a_table_at_an_array_of_tables_too_and_reads_a_header_with_spaces_or_a_comment():
    before = '[ console ]  # the look\nmouse = false\n[[prices.extra]]\nmodel = "m"\n'
    assert set_keys(before, "console", {"theme": 'theme = "nord"'}) == (
        '[ console ]  # the look\nmouse = false\ntheme = "nord"\n[[prices.extra]]\nmodel = "m"\n')
    # an array of tables with the table's name is not the table
    assert set_keys('[[console]]\nx = 1\n', "console", {"theme": 'theme = "nord"'}) == '[[console]]\nx = 1\n\n[console]\ntheme = "nord"\n'


def test_set_keys_keeps_the_line_endings_the_file_has():
    before = '[api]\r\nx = 1\r\n\r\n[console]\r\nmouse = false\r\n'
    assert set_keys(before, "console", {"theme": 'theme = "nord"'}) == '[api]\r\nx = 1\r\n\r\n[console]\r\nmouse = false\r\ntheme = "nord"\r\n'
    assert set_keys('[api]\r\nx = 1\r\n', "console", {"theme": 'theme = "nord"'}) == '[api]\r\nx = 1\r\n\r\n[console]\r\ntheme = "nord"\r\n'
    # a line separator that is not a newline (legal inside a TOML comment) does not split a line
    odd = '[console]\n# one line\nmouse = false\n'
    assert set_keys(odd, "console", {"theme": 'theme = "nord"'}) == odd + 'theme = "nord"\n'


# ---------------------------------------------------------------------- rewrite


def test_rewrite_writes_the_change_and_says_when_there_was_none(tmp_path):
    path = write(tmp_path, "a = 1\r\n")
    checked = []
    assert rewrite(path, lambda text: text + "b = 2\r\n", lambda: checked.append(read(path)), what="b") is True
    assert read(path) == "a = 1\r\nb = 2\r\n" and checked == ["a = 1\r\nb = 2\r\n"]  # checked after the write, endings as they were
    before = os.stat(path).st_mtime_ns
    assert rewrite(path, lambda text: text, lambda: checked.append("again"), what="b") is False
    assert os.stat(path).st_mtime_ns == before and len(checked) == 1  # not written, and nothing to check


def test_rewrite_puts_the_file_back_when_the_check_refuses_it(tmp_path):
    path = write(tmp_path, "a = 1\r\n# kept\r\n")

    def refuse() -> None:
        assert read(path) == "a = 1\r\n# kept\r\nb = 2\n"  # the change was on disk when it was checked
        raise ConfigError(f"{path}: b is not known")

    with pytest.raises(EditError) as caught:
        rewrite(path, lambda text: text + "b = 2\n", refuse, what="the pack")
    assert str(caught.value) == f"the config did not load with the pack in it, so it was put back as it was: {path}: b is not known"
    assert read(path) == "a = 1\r\n# kept\r\n"


def test_rewrite_needs_a_config_it_can_read_and_changes_nothing_when_the_change_refuses(tmp_path):
    def never(text: str) -> str:
        raise AssertionError("nothing to change")

    with pytest.raises(EditError) as caught:
        rewrite(tmp_path / "none.toml", never, lambda: None, what="x")
    assert str(caught.value) == f"there is no config at {tmp_path / 'none.toml'}: run `flightdeck init` first"
    assert not (tmp_path / "none.toml").exists()
    with pytest.raises(EditError, match="^there is no config at .*: run `flightdeck init` first, then this again$"):
        rewrite(tmp_path / "none.toml", never, lambda: None, what="x", first="run `flightdeck init` first, then this again")
    (tmp_path / "folder.toml").mkdir()
    with pytest.raises(EditError, match=f"^cannot read the config {tmp_path / 'folder.toml'}: "):
        rewrite(tmp_path / "folder.toml", never, lambda: None, what="x")
    latin = tmp_path / "latin.toml"
    latin.write_bytes(b"# caf\xe9\n")
    with pytest.raises(EditError, match=f"^cannot read the config {latin}: "):
        rewrite(latin, never, lambda: None, what="x")
    assert latin.read_bytes() == b"# caf\xe9\n"

    path = write(tmp_path, "a = 1\n")

    def refuse(text: str) -> str:
        raise ValueError("not this one")

    with pytest.raises(ValueError, match="not this one"):
        rewrite(path, refuse, lambda: None, what="x")
    assert read(path) == "a = 1\n"


def test_a_config_that_cannot_be_written_is_said_and_is_as_it_was(tmp_path):
    path = write(tmp_path, "a = 1\n")
    if os.geteuid() == 0:
        pytest.skip("not run: as root, a file's mode does not stop a write to it")
    path.chmod(0o400)
    try:
        with pytest.raises(EditError) as caught:
            rewrite(path, lambda text: text + "b = 2\n", lambda: None, what="x")
    finally:
        path.chmod(0o600)
    assert str(caught.value) == f"cannot write the config {path} (Permission denied): it is as it was"
    assert read(path) == "a = 1\n"


def test_a_write_that_fails_part_way_is_put_back(tmp_path, monkeypatch):
    """A disk that fills while the new text is written: what is there is half a config, and
    the old text goes back over it."""
    path = write(tmp_path, "a = 1\n")
    real, calls = config_edit._write, []

    def half(target: Path, text: str) -> None:
        calls.append(text)
        if len(calls) == 1:
            target.write_bytes(text.encode()[:3])
            raise OSError(28, "No space left on device")
        real(target, text)

    monkeypatch.setattr(config_edit, "_write", half)
    with pytest.raises(EditError) as caught:
        rewrite(path, lambda text: text + "b = 2\n", lambda: None, what="x")
    assert str(caught.value) == f"cannot write the config {path} (No space left on device): it was put back as it was"
    assert read(path) == "a = 1\n" and calls == ["a = 1\nb = 2\n", "a = 1\n"]

    def never(target: Path, text: str) -> None:
        target.write_bytes(b"a =")
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(config_edit, "_write", never)  # and the old text cannot be written either: said, never passed over
    with pytest.raises(EditError) as caught:
        rewrite(path, lambda text: text + "b = 2\n", lambda: None, what="x")
    assert str(caught.value) == (f"cannot write the config {path} (No space left on device): it could not be put back as it was "
                                 "(No space left on device): look at it before the next run")


def test_a_check_that_fails_with_another_error_puts_the_config_back(tmp_path):
    """Not only a ConfigError: a check that meets an OSError (a themes folder it cannot look
    in, say) still has the old text written back, and is said as an EditError."""
    path = write(tmp_path, "a = 1\n")

    def check() -> None:
        raise PermissionError(13, "Permission denied")

    with pytest.raises(EditError) as caught:
        rewrite(path, lambda text: text + "b = 2\n", check, what="the theme")
    assert str(caught.value) == "the config did not load with the theme in it, so it was put back as it was: Permission denied"
    assert read(path) == "a = 1\n"


def test_the_config_is_replaced_in_one_step_and_keeps_its_mode(tmp_path, monkeypatch):
    """The new text goes to a file beside the config and is renamed over it: while it is being
    written, and when that write fails, the config holds the old text, never an empty or half
    one, and no new file is left beside it."""
    path = write(tmp_path, LADDER)
    path.chmod(0o640)
    seen, real = [], os.fsync

    def full(descriptor: int) -> None:
        seen.append(read(path))
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(os, "fsync", full)
    with pytest.raises(EditError) as caught:
        rewrite(path, lambda text: text + "# more\n", lambda: None, what="x")
    assert seen == [LADDER] and read(path) == LADDER
    assert str(caught.value) == f"cannot write the config {path} (No space left on device): it is as it was"
    assert sorted(entry.name for entry in tmp_path.iterdir()) == ["config.toml"]
    monkeypatch.setattr(os, "fsync", real)
    assert save_console(path, theme="nord") is True
    assert read(path) == LADDER + '\n[console]\ntheme = "nord"\n' and (path.stat().st_mode & 0o777) == 0o640
    assert sorted(entry.name for entry in tmp_path.iterdir()) == ["config.toml"]


def test_a_config_that_is_a_link_stays_a_link(tmp_path):
    (tmp_path / "dotfiles").mkdir()
    real = write(tmp_path / "dotfiles", LADDER)
    real.chmod(0o640)
    link = tmp_path / "config.toml"
    link.symlink_to(real)
    assert save_console(link, theme="nord") is True
    assert link.is_symlink() and os.readlink(link) == str(real)
    assert read(real) == LADDER + '\n[console]\ntheme = "nord"\n' and (real.stat().st_mode & 0o777) == 0o640
    assert sorted(entry.name for entry in (tmp_path / "dotfiles").iterdir()) == ["config.toml"]


def test_a_config_whose_folder_cannot_take_a_new_file_is_refused_and_says_why(tmp_path):
    """The file can be written but its folder cannot: the new text cannot be put in place in
    one step, and it is never written in place instead. The message names the folder (for a
    link, the folder of the file it points at), and the config is as it was."""
    if os.geteuid() == 0:
        pytest.skip("not run: as root, a folder's mode does not stop a new file in it")
    (tmp_path / "dotfiles").mkdir()
    real = write(tmp_path / "dotfiles", "a = 1\n")
    link = tmp_path / "config.toml"
    link.symlink_to(real)
    (tmp_path / "dotfiles").chmod(0o500)
    try:
        for path in (real, link):
            with pytest.raises(EditError) as caught:
                rewrite(path, lambda text: text + "b = 2\n", lambda: None, what="x")
            assert str(caught.value) == (
                f"cannot write the config {path} (its folder {tmp_path / 'dotfiles'} does not let a new file be made in it, "
                "and the config is only ever replaced whole, never written over in place): it is as it was")
            assert read(real) == "a = 1\n"
    finally:
        (tmp_path / "dotfiles").chmod(0o700)
    assert sorted(entry.name for entry in (tmp_path / "dotfiles").iterdir()) == ["config.toml"]


# ---------------------------------------------------------------------- save_console


def test_save_console_writes_the_theme_and_the_layout_and_the_config_then_opens_in_them(tmp_path):
    path = write(tmp_path, LADDER)
    assert save_console(path, theme="nord") is True
    assert read(path) == LADDER + '\n[console]\ntheme = "nord"\n'
    assert load_config(path).console == ConsoleConfig(theme="nord", palette=themes.BUILTIN["nord"])
    assert save_console(path, layout="deck") is True
    assert read(path) == LADDER + '\n[console]\ntheme = "nord"\nlayout = "deck"\n'
    assert save_console(path, theme="light", layout="simple") is True
    assert read(path) == LADDER + '\n[console]\ntheme = "light"\nlayout = "simple"\n'
    assert load_console(path) == ConsoleConfig(layout="simple", theme="light", palette=themes.BUILTIN["light"])
    stamp = os.stat(path).st_mtime_ns
    assert save_console(path, theme="light", layout="simple") is False and os.stat(path).st_mtime_ns == stamp  # said already


def test_save_console_fills_the_example_config_where_its_examples_are(tmp_path):
    """`flightdeck config --example` with its [console] table turned on, as a player would."""
    example = example_config()
    assert "\n# [console]\n" in example and '\n# theme = "flightdeck"\n' in example and '\n# layout = "simple"\n' in example
    on = example.replace("\n# [console]\n", "\n[console]\n")
    path = write(tmp_path, on)
    assert save_console(path, theme="gruvbox", layout="deck") is True
    assert read(path) == on.replace('\n# layout = "simple"\n', '\n# layout = "simple"\nlayout = "deck"\n').replace(
        '\n# theme = "flightdeck"\n', '\n# theme = "flightdeck"\ntheme = "gruvbox"\n')
    # and with the table still an example: a table of its own, at the end
    path = write(tmp_path, example, "example.toml")
    assert save_console(path, theme="gruvbox") is True
    assert example.endswith("\n") and not example.endswith("\n\n")
    assert read(path) == example + '\n[console]\ntheme = "gruvbox"\n'
    assert load_console(path).theme == "gruvbox"


def test_save_console_keeps_the_players_own_theme_and_refuses_one_that_does_not_load(tmp_path):
    path = write(tmp_path, LADDER + '\n[console]\nmouse = false\n')
    (tmp_path / "themes").mkdir()
    (tmp_path / "themes" / "dusk.toml").write_text('base = "nord"\n[colors]\naccent = "#ff5fd7"\n')
    (tmp_path / "themes" / "broken.toml").write_text('base = "nord"\n[colors]\naccent = "pink"\n')
    assert save_console(path, theme="dusk") is True
    assert load_console(path).palette.accent == "#ff5fd7" and load_console(path).mouse is False
    kept = read(path)
    for name, why in (("broken", f'{tmp_path / "themes" / "broken.toml"}: colors.accent must be a colour written as # and six hex digits, '
                                 'like "#ffa62b"'),
                      ("gone", f"{path}: console.theme names no theme: built in are flightdeck, light, nord, gruvbox, dracula; "
                               f"your own is NAME.toml in {tmp_path / 'themes'}")):
        with pytest.raises(EditError) as caught:
            save_console(path, theme=name)
        assert str(caught.value) == f"the config did not load with the theme in it, so it was put back as it was: {why}"
        assert read(path) == kept


def test_save_console_looks_at_the_console_table_only_so_an_unfinished_config_keeps_a_look(tmp_path):
    """The mock opens in the look of a config that is not finished (config.load_console); what
    it can read there it can keep there."""
    unfinished = '[api]\nbase_url = 3\n\n[console]\nlayout = "deck"\n'
    path = write(tmp_path, unfinished)
    with pytest.raises(ConfigError):
        load_config(path)
    assert save_console(path, layout="simple", theme="light") is True
    assert read(path) == '[api]\nbase_url = 3\n\n[console]\nlayout = "simple"\ntheme = "light"\n'


@pytest.mark.parametrize("config, why", [
    ('console.layout = "deck"\n' + LADDER, "could not place"),  # the table written as dotted keys: a [console] after it is a second one
    ('console = { layout = "deck" }\n' + LADDER, "could not place"),  # an inline table: closed
    (LADDER + '\n["console"]\nlayout = "deck"\n', "could not place"),  # a quoted header: not seen, so a second table
    (LADDER + '\n[console]\n"theme" = "light"\n', "could not place"),  # a quoted key: not seen, so a second key
    (LADDER + '\n[run]\ndir = """\n[console]\n"""\n', "could not place"),  # a header that is a line of a string: the line would go in the string
    ("console = 3\n" + LADDER, "could not place"),
    (LADDER + "[console\n", "not TOML"),
    ("", "bare"),  # an empty file is valid TOML and takes the table
], ids=["dotted", "inline", "quoted header", "quoted key", "in a string", "not a table", "not TOML", "empty"])
def test_save_console_never_touches_a_config_it_cannot_edit_by_lines(tmp_path, config, why):
    path = write(tmp_path, config)
    stamp = os.stat(path).st_mtime_ns
    if why == "bare":
        assert save_console(path, theme="nord") is True and read(path) == '[console]\ntheme = "nord"\n'
        return
    with pytest.raises(EditError) as caught:
        save_console(path, theme="nord", layout="simple")
    by_hand = 'write layout = "simple" and theme = "nord" under [console] yourself'
    assert str(caught.value) == (
        f"{path} is not valid TOML, so it was left as it is: mend it, or {by_hand}" if why == "not TOML"
        else f"flightdeck could not place the line in {path}, which was left as it is: {by_hand}")
    assert read(path) == config and os.stat(path).st_mtime_ns == stamp  # never written, not written and put back


def test_save_console_takes_only_a_layout_and_a_themes_name(tmp_path):
    path = write(tmp_path, LADDER)
    for bad in ({"theme": 'x"\n[api]\nkey = "y'}, {"theme": "Nord"}, {"theme": "../dusk"}, {"theme": ""}, {"layout": "wide"}, {"layout": ""}, {}):
        with pytest.raises(ValueError):
            save_console(path, **bad)
    assert read(path) == LADDER
    with pytest.raises(EditError, match="^there is no config at "):
        save_console(tmp_path / "none.toml", theme="nord")


# ---------------------------------------------------------------------- save_lanes (#55)


def test_save_lanes_writes_max_lanes_under_lanes_and_the_next_run_reads_it(tmp_path):
    path = write(tmp_path, LADDER)
    assert config_edit.save_lanes(path, 6) is True
    assert read(path) == LADDER + "max_lanes = 6\n"
    assert load_config(path).lanes.max_lanes == 6
    assert config_edit.save_lanes(path, 2) is True and read(path) == LADDER + "max_lanes = 2\n"  # the same line, changed
    stamp = os.stat(path).st_mtime_ns
    assert config_edit.save_lanes(path, 2) is False and os.stat(path).st_mtime_ns == stamp  # said already: not written


def test_save_lanes_writes_unlimited_as_the_word_a_config_takes(tmp_path):
    from ctf_flightdeck.core.model import UNLIMITED_LANES

    path = write(tmp_path, LADDER)
    assert config_edit.save_lanes(path, UNLIMITED_LANES) is True
    assert read(path) == LADDER + 'max_lanes = "unlimited"\n'
    assert load_config(path).lanes.max_lanes == UNLIMITED_LANES


def test_save_lanes_fills_the_example_config_where_its_line_is_and_adds_a_table_when_there_is_none(tmp_path):
    example = write(tmp_path, example_config(), "example.toml")
    assert config_edit.save_lanes(example, 7) is True
    text = read(example)
    assert "max_lanes = 7" in text and "max_lanes = 4" not in text and text.count("[lanes]") == 1
    bare = write(tmp_path, '[models]\nladder = ["m"]\n', "bare.toml")
    assert config_edit.save_lanes(bare, 3) is True
    assert read(bare) == '[models]\nladder = ["m"]\n\n[lanes]\nmax_lanes = 3\n'


@pytest.mark.parametrize("text, reason", [
    (LADDER + "[console\n", "is not valid TOML, so it was left as it is: mend it, or write max_lanes = 5 under [lanes] yourself"),
    ("lanes.max_lanes = 2\n" + '[models]\nladder = ["m"]\n',
     "flightdeck could not place the line in {path}, which was left as it is: write max_lanes = 5 under [lanes] yourself"),
], ids=["not TOML", "a table flightdeck cannot edit"])
def test_save_lanes_refuses_a_config_it_cannot_edit_and_leaves_it_as_it_was(tmp_path, text, reason):
    path = write(tmp_path, text)
    with pytest.raises(EditError) as caught:
        config_edit.save_lanes(path, 5)
    assert reason.format(path=path) in str(caught.value)
    assert read(path) == text


@pytest.mark.parametrize("most", [0, -1, True, 2.5, "4"])
def test_save_lanes_takes_only_a_whole_number_of_one_or_more(tmp_path, most):
    path = write(tmp_path, LADDER)
    with pytest.raises(ValueError):
        config_edit.save_lanes(path, most)
    assert read(path) == LADDER
