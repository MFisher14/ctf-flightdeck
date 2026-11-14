"""The console's palettes (themes.py): the built-in themes, a player's own theme file, and the
contrast floor that refuses a theme the console could not be read in.

Every theme file is a real file a test writes under tmp_path; the colours are made up.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest

from ctf_flightdeck import themes
from ctf_flightdeck.themes import BUILTIN, CONTRAST, ROLES, NoSuchTheme, Palette, ThemeError, contrast

# The look before themes: console/theme.py's colours as they were, the focused cursor of
# console/app.py's CSS (selected_focus) and Textual's own dark surface.
THE_LOOK_BEFORE_THEMES = {
    "page": "#121212",
    "surface": "#1e1e1e",
    "border": "#3c4146",
    "text": "#e0e0e0",
    "muted": "#7d8590",
    "accent": "#ffa62b",
    "selected": "#1b2633",
    "selected_focus": "#22324a",
    "brand": "#0178d4",
    "segment": "#2f3437",
    "ok": "#4ebf71",
    "error": "#e0475b",
    "warn": "#e5c07b",
    "info": "#3fb8e0",
    "pending": "#a66bff",
    "ink": "#0b0b0b",
    "ink_light": "#ffffff",
}

DUSK = """\
dark = true
syntax = "monokai"

[colors]
page = "#1a1b26"
surface = "#24283b"
border = "#414868"
text = "#c0caf5"
muted = "#7f88b0"
accent = "#ff9e64"
selected = "#283457"
selected_focus = "#33467c"
brand = "#3d6fd9"
segment = "#2f334d"
ok = "#9ece6a"
error = "#e0566f"
warn = "#e0af68"
info = "#7dcfff"
pending = "#9d7cd8"
ink = "#15161e"
ink_light = "#ffffff"
"""
BASED = 'base = "flightdeck"\n'


def theme_file(tmp_path: Path, text: str | bytes, name: str = "dusk") -> Path:
    folder = tmp_path / "themes"
    folder.mkdir(exist_ok=True)
    file = folder / f"{name}.toml"
    file.write_bytes(text if isinstance(text, bytes) else text.encode("utf-8"))
    return file


def error(tmp_path: Path, text: str | bytes, name: str = "dusk") -> str:
    theme_file(tmp_path, text, name)
    with pytest.raises(ThemeError) as caught:
        themes.load(name, tmp_path / "themes")
    return str(caught.value)


def colours(palette: Palette) -> dict[str, str]:
    return {role: getattr(palette, role) for role in ROLES}


# ---------------------------------------------------------------------- the built-in themes


def test_the_flightdeck_theme_is_the_look_the_console_had_before_themes():
    palette = BUILTIN["flightdeck"]
    assert colours(palette) == THE_LOOK_BEFORE_THEMES
    assert (palette.name, palette.dark, palette.syntax) == ("flightdeck", True, "monokai")
    assert themes.DEFAULT is palette


def test_a_palette_has_the_17_roles_in_the_order_a_theme_file_gives_them():
    assert ROLES == tuple(THE_LOOK_BEFORE_THEMES) and len(ROLES) == 17
    assert tuple(field.name for field in dataclasses.fields(Palette)) == ("name", "dark", "syntax", *ROLES)


def test_the_built_in_themes_are_the_five_and_each_is_under_its_own_name():
    assert list(BUILTIN) == ["flightdeck", "light", "nord", "gruvbox", "dracula"]
    assert all(palette.name == name for name, palette in BUILTIN.items())
    assert [name for name, palette in BUILTIN.items() if not palette.dark] == ["light"]
    assert len({tuple(colours(palette).values()) for palette in BUILTIN.values()}) == 5  # five looks, not one five times


@pytest.mark.parametrize("name", list(BUILTIN))
def test_every_built_in_theme_passes_every_contrast_pair_and_names_a_pygments_style(name):
    from pygments.styles import get_all_styles

    palette = BUILTIN[name]
    ratios = {(fg, bg): contrast(getattr(palette, fg), getattr(palette, bg)) for fg, bg, _what in CONTRAST}
    assert len(ratios) == 19
    assert {pair: ratio for pair, ratio in ratios.items() if ratio < themes.MIN_CONTRAST} == {}
    assert themes.weak_pairs(palette) == []
    assert palette.syntax in set(get_all_styles())
    assert all(themes._COLOUR.fullmatch(colour) and colour == colour.lower() for colour in colours(palette).values())


def test_the_contrast_pairs_are_what_the_player_must_read():
    pairs = [(fg, bg) for fg, bg, _what in CONTRAST]
    assert pairs == [
        ("ink", "ok"), ("ink", "warn"), ("ink", "accent"), ("ink", "info"),  # the dark text of a chip on its chip
        ("ink_light", "error"), ("ink_light", "pending"), ("ink_light", "brand"),  # and the light text
        ("text", "page"), ("text", "surface"), ("text", "segment"), ("text", "selected_focus"),
        ("muted", "page"),
        ("ok", "page"), ("error", "page"), ("warn", "page"), ("info", "page"), ("pending", "page"), ("accent", "page"),
        ("brand", "page"),  # each state's colour on the page
    ]
    assert all(what.strip() for _fg, _bg, what in CONTRAST) and themes.MIN_CONTRAST == 3.0


def test_contrast_is_the_wcag_ratio():
    assert contrast("#000000", "#ffffff") == pytest.approx(21.0)
    assert contrast("#3fb8e0", "#3fb8e0") == pytest.approx(1.0)
    assert contrast("#777777", "#ffffff") == pytest.approx(4.478, abs=0.001)  # the grey WCAG's 4.5 just refuses
    assert contrast("#ffffff", "#e0475b") == pytest.approx(4.022, abs=0.001)
    assert contrast("#e0475b", "#ffffff") == contrast("#ffffff", "#e0475b")  # either way round
    assert contrast("#FFA62B", "#0b0b0b") == contrast("#ffa62b", "#0b0b0b")


# ---------------------------------------------------------------------- loading by name


def test_a_built_in_theme_loads_by_name_with_or_without_a_themes_folder(tmp_path):
    assert themes.load("nord", None) is BUILTIN["nord"]
    assert themes.load("nord", tmp_path / "themes") is BUILTIN["nord"]  # no such folder: nothing to read
    theme_file(tmp_path, DUSK)
    assert themes.load("light", tmp_path / "themes") is BUILTIN["light"]  # another file there is not looked at


def test_a_whole_theme_of_the_players_own_is_read_from_its_file(tmp_path):
    theme_file(tmp_path, DUSK)
    palette = themes.load("dusk", tmp_path / "themes")
    assert (palette.name, palette.dark, palette.syntax) == ("dusk", True, "monokai")
    assert palette.page == "#1a1b26" and palette.ink_light == "#ffffff" and palette.pending == "#9d7cd8"
    assert set(colours(palette).values()).isdisjoint({"#121212", "#ffa62b", "#0178d4"})  # nothing left of the default
    assert themes.weak_pairs(palette) == []


def test_a_base_and_one_colour_change_that_role_only(tmp_path):
    theme_file(tmp_path, BASED + '[colors]\naccent = "#ff5fd7"\n', "pink")
    palette = themes.load("pink", tmp_path / "themes")
    base = BUILTIN["flightdeck"]
    assert palette.accent == "#ff5fd7" != base.accent
    assert palette == dataclasses.replace(base, name="pink", accent="#ff5fd7")  # every other role, dark and syntax: the base's


def test_a_base_other_than_the_default_gives_its_own_colours_and_dark_and_syntax_can_be_set_over_it(tmp_path):
    theme_file(tmp_path, 'base = "light"\n', "paper")
    assert themes.load("paper", tmp_path / "themes") == dataclasses.replace(BUILTIN["light"], name="paper")
    theme_file(tmp_path, 'base = "nord"\ndark = false\nsyntax = "default"\n', "frost")
    frost = themes.load("frost", tmp_path / "themes")
    assert frost == dataclasses.replace(BUILTIN["nord"], name="frost", dark=False, syntax="default")


def test_a_colour_is_kept_in_lower_case_however_the_file_writes_it(tmp_path):
    theme_file(tmp_path, BASED + '[colors]\naccent = "#FF5FD7"\n', "pink")
    assert themes.load("pink", tmp_path / "themes").accent == "#ff5fd7"


def test_a_name_that_is_no_theme_says_what_there_is_and_never_repeats_the_name(tmp_path):
    with pytest.raises(NoSuchTheme) as caught:
        themes.load("zqsentinel4471", tmp_path / "themes")
    assert str(caught.value) == (
        f"names no theme: built in are flightdeck, light, nord, gruvbox, dracula; your own is NAME.toml in {tmp_path / 'themes'}")
    with pytest.raises(NoSuchTheme) as caught:
        themes.load("zqsentinel4471", None)
    assert str(caught.value) == "names no theme: built in are flightdeck, light, nord, gruvbox, dracula"


@pytest.mark.parametrize("name", ["../dusk", "Dusk", "", "dusk.toml", "-dusk", "a" * 33, "themes/dusk", "du sk"])
def test_a_name_that_is_not_a_themes_name_reads_no_file(tmp_path, name):
    theme_file(tmp_path, DUSK)
    (tmp_path / "dusk.toml").write_text(DUSK)  # where ../dusk would point
    with pytest.raises(ThemeError) as caught:
        themes.load(name, tmp_path / "themes")
    assert str(caught.value) == "a theme's name is lower-case letters, digits, - and _, at most 32 characters"
    assert not isinstance(caught.value, NoSuchTheme)


def test_the_longest_name_and_a_name_that_starts_with_a_digit_are_names(tmp_path):
    for name in ("a" * 32, "3024-night", "my_theme"):
        theme_file(tmp_path, BASED, name)
        assert themes.load(name, tmp_path / "themes").name == name


def test_names_lists_the_built_in_themes_and_the_players_own_files(tmp_path):
    assert themes.names(None) == (["flightdeck", "light", "nord", "gruvbox", "dracula"], [])
    assert themes.names(tmp_path / "themes") == (list(BUILTIN), [])  # no folder yet
    for name in ("dusk", "amber", "light"):  # light: a built-in's name, which no file can take
        theme_file(tmp_path, BASED, name)
    (tmp_path / "themes" / "Loud.toml").write_text(BASED)  # not a theme's name
    (tmp_path / "themes" / "notes.txt").write_text("not a theme")
    (tmp_path / "themes" / "dusk.toml.bak").write_text(BASED)
    assert themes.names(tmp_path / "themes") == (list(BUILTIN), ["amber", "dusk"])


# ---------------------------------------------------------------------- a theme that is refused

ROLE_LIST = ", ".join(ROLES)
BROKEN = {
    "unknown colour": (
        BASED + '[colors]\nacent = "#ff5fd7"\n',
        f"{{file}}: unknown key colors.acent (known in colors: {ROLE_LIST})"),
    "unknown key": (
        BASED + 'darkk = true\n',
        "{file}: unknown key darkk (known: base, dark, syntax, colors)"),
    "colour without a #": (
        BASED + '[colors]\naccent = "ff5fd7"\n',
        '{file}: colors.accent must be a colour written as # and six hex digits, like "#ffa62b"'),
    "colour of three digits": (
        BASED + '[colors]\naccent = "#f5d"\n',
        '{file}: colors.accent must be a colour written as # and six hex digits, like "#ffa62b"'),
    "colour by name": (
        BASED + '[colors]\nok = "green"\n',
        '{file}: colors.ok must be a colour written as # and six hex digits, like "#ffa62b"'),
    "colour with an alpha": (
        BASED + '[colors]\npage = "#12121280"\n',
        '{file}: colors.page must be a colour written as # and six hex digits, like "#ffa62b"'),
    "colour a number": (
        BASED + "[colors]\npage = 121212\n",
        '{file}: colors.page must be a colour written as # and six hex digits, like "#ffa62b"'),
    "colours missing with no base": (
        DUSK.replace('pending = "#9d7cd8"\n', "").replace('ink = "#15161e"\n', ""),
        '{file}: missing colors: pending, ink (give every colour, or set base = "flightdeck" to start from a built-in theme)'),
    "no colours and no base": (
        'dark = true\nsyntax = "monokai"\n',
        f'{{file}}: missing colors: {ROLE_LIST} (give every colour, or set base = "flightdeck" to start from a built-in theme)'),
    "base not a built-in": (
        'base = "solarized"\n',
        '{file}: base must be "flightdeck", "light", "nord", "gruvbox" or "dracula"'),
    "base a theme of the player's own": (
        'base = "amber"\n',
        '{file}: base must be "flightdeck", "light", "nord", "gruvbox" or "dracula"'),
    "base not a string": (
        "base = true\n",
        '{file}: base must be "flightdeck", "light", "nord", "gruvbox" or "dracula"'),
    "syntax not a style": (
        BASED + 'syntax = "monokay"\n',
        "{file}: syntax names no Pygments style"),
    "syntax a module's name": (
        BASED + 'syntax = "os.path"\n',
        "{file}: syntax names no Pygments style"),
    "syntax not a string": (
        BASED + "syntax = 3\n",
        "{file}: syntax names no Pygments style"),
    "no syntax and no base": (
        DUSK.replace('syntax = "monokai"\n', ""),
        '{file}: syntax is required without base: the Pygments style of the diff view, like "monokai"'),
    "no dark and no base": (
        DUSK.replace("dark = true\n", ""),
        "{file}: dark is required without base: true for a dark theme, false for a light one"),
    "dark not true or false": (
        BASED + 'dark = "yes"\n',
        "{file}: dark must be true or false"),
    "colors not a table": (
        BASED + 'colors = "#ff5fd7"\n',
        "{file}: colors must be a table ([colors])"),
    "need you cannot be read": (
        BASED + '[colors]\nerror = "#ff8a9a"\n',
        '{file}: colors.ink_light on colors.error has contrast 2.2, under 3.0: "▲ N need you" could not be read'),
    "a state's colour too close to the page": (
        BASED + '[colors]\nerror = "#7a3a44"\n',
        "{file}: colors.error on colors.page has contrast 2.2, under 3.0: a killed lane and a blocked challenge could not be read"),
    "a contrast just under the floor is not rounded up to it": (
        BASED + '[colors]\nmuted = "#606060"\n',
        "{file}: colors.muted on colors.page has contrast 2.9, under 3.0: labels and hints could not be read"),
    "text the colour of the page": (
        BASED + '[colors]\ntext = "#121212"\n',
        "{file}: colors.text on colors.page has contrast 1.0, under 3.0: the console's text could not be read"),
    "not TOML": (
        "base = \n",
        "{file}: Invalid value (at line 1, column 8)"),
    "a table twice": (
        BASED + "[colors]\n[colors]\n",
        "{file}: Cannot declare ('colors',) twice (at line 3, column 8)"),
}


@pytest.mark.parametrize("text, message", BROKEN.values(), ids=BROKEN.keys())
def test_a_broken_theme_is_refused_with_its_file_and_its_key(tmp_path, text, message):
    file = theme_file(tmp_path, text)
    assert error(tmp_path, text) == message.format(file=file)


def test_a_contrast_at_the_floor_passes(tmp_path):
    theme_file(tmp_path, BASED + '[colors]\nmuted = "#616161"\n')  # 3.02 on the page; #606060 is 2.98
    assert themes.load("dusk", tmp_path / "themes").muted == "#616161"


def test_a_file_with_a_built_in_themes_name_is_refused_not_read_in_its_place(tmp_path):
    file = theme_file(tmp_path, DUSK, "nord")
    assert error(tmp_path, DUSK, "nord") == f"{file} has a built-in theme's name: rename the file"
    with pytest.raises(ThemeError) as caught:
        themes.parse(DUSK, file)
    assert str(caught.value) == f"{file} has a built-in theme's name: rename the file"


def test_a_file_over_64_kib_is_refused_and_one_of_64_kib_is_read(tmp_path):
    padding = "# " + "x" * 98 + "\n"  # 101 bytes a line
    big = BASED + padding * 700
    assert len(big) > themes.MAX_BYTES == 65536
    file = theme_file(tmp_path, big)
    assert error(tmp_path, big) == f"{file}: larger than 64 KiB"
    exact = BASED + "#" * (themes.MAX_BYTES - len(BASED) - 1) + "\n"
    assert len(exact) == themes.MAX_BYTES
    theme_file(tmp_path, exact)
    assert themes.load("dusk", tmp_path / "themes") == dataclasses.replace(BUILTIN["flightdeck"], name="dusk")


def test_a_file_that_is_not_text_or_not_a_file_is_refused(tmp_path):
    file = theme_file(tmp_path, b"base = \"flightdeck\"\n\xff\xfe")
    assert error(tmp_path, b"base = \"flightdeck\"\n\xff\xfe") == f"{file}: is not UTF-8 text"
    (tmp_path / "themes" / "folder.toml").mkdir()
    with pytest.raises(ThemeError) as caught:
        themes.load("folder", tmp_path / "themes")
    assert str(caught.value) == f"{tmp_path / 'themes' / 'folder.toml'}: is a directory, not a theme file"
    (tmp_path / "themes" / "gone.toml").symlink_to(tmp_path / "themes" / "nowhere.toml")
    with pytest.raises(ThemeError) as caught:
        themes.load("gone", tmp_path / "themes")
    message = str(caught.value)
    assert message.startswith(f"{tmp_path / 'themes' / 'gone.toml'}: cannot read it (") and not isinstance(caught.value, NoSuchTheme)


SENTINEL = "zqSentinelValue4471"  # as tests/test_config.py: letters and digits only, like many real keys

SECRETS = {
    "base": f'base = "{SENTINEL}"\n',
    "syntax": BASED + f'syntax = "{SENTINEL}"\n',
    "dark": BASED + f'dark = "{SENTINEL}"\n',
    "a colour": BASED + f'[colors]\naccent = "{SENTINEL}"\n',
    "a colour that starts like one": BASED + f'[colors]\naccent = "#ff5fd7{SENTINEL}"\n',
    "colors": BASED + f'colors = "{SENTINEL}"\n',
    "an unknown key's value": BASED + f'[colors]\nacent = "{SENTINEL}"\n',
    "a value beside a missing colour": DUSK.replace('ink = "#15161e"\n', "").replace("monokai", SENTINEL),
    "a value TOML cannot read": BASED + f'[colors]\naccent = "{SENTINEL}\n',
    "a value given twice": BASED + f'syntax = "{SENTINEL}"\nsyntax = "{SENTINEL}"\n',
    "a value in a theme with too little contrast": BASED + f'syntax = "{SENTINEL}"\n[colors]\ntext = "#121212"\n',
}


@pytest.mark.parametrize("text", SECRETS.values(), ids=SECRETS.keys())
def test_no_error_shows_a_value_from_the_file(tmp_path, text):
    """A string in a file of the player's could be a key pasted into the wrong place."""
    file = theme_file(tmp_path, text)
    message = error(tmp_path, text)
    assert message.startswith(str(file))
    assert SENTINEL not in message and SENTINEL.lower() not in message.lower()


def test_no_contrast_error_shows_a_colour_of_the_file(tmp_path):
    message = error(tmp_path, BASED + '[colors]\nerror = "#ff8a9a"\n')
    assert "contrast" in message and "#ff8a9a" not in message and "#ffffff" not in message
