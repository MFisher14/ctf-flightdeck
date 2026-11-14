"""A challenge the player hands over: /new in the console, `flightdeck add`, and a run that
takes it. The model is the fake server (no spend); every file is the test's own."""

from __future__ import annotations

import asyncio
import json
from dataclasses import replace
from pathlib import Path

import pytest
from textual import events
from typer.testing import CliRunner

from ctf_flightdeck import addchallenge, cli, start
from ctf_flightdeck.addchallenge import AddError, NewChallenge
from ctf_flightdeck.core.model import LaneState
from ctf_flightdeck.platform.manual import load_board, load_challenge
from ctf_flightdeck.run import RunError, RunOptions, prepare_run
from fake_model import FakeModelServer, tool_call_reply
from test_run import config

FLAG = "t{handed_over}"


@pytest.fixture(autouse=True)
def a_plain_local_terminal(monkeypatch):
    """Not over SSH, not under WSL, not in tmux and not VS Code's terminal, wherever the tests
    run: the line said for a dropped file that is not there, and the drop sentence, are chosen
    by those (addchallenge.not_there_line, drop_hint)."""
    for name in ("SSH_CONNECTION", "SSH_TTY", "WSL_DISTRO_NAME", "WSL_INTEROP", "TERM_PROGRAM", "TMUX", "XDG_SESSION_TYPE"):
        monkeypatch.delenv(name, raising=False)


# ---------------------------------------------------------------------- the pasted text


def test_the_text_is_kept_as_given_and_only_addresses_on_lines_of_their_own_are_read_from_it(tmp_path):
    shot, spaced = tmp_path / "shot.png", tmp_path / "my notes.txt"
    shot.write_bytes(b"png")
    spaced.write_text("n")
    text = (f"Find the flag in the service.\n{shot}\n'{spaced}'\nnc chal.example.org 1337\n"
            "https://web.example.org:8443/login?x=1\nSee https://en.wikipedia.org/wiki/RSA for background.")
    description, urls = addchallenge.parse(text + "\n")
    assert description == text  # every line as it was given: a path on a line of its own is text too, and attaches nothing
    assert urls == ("tcp://chal.example.org:1337", "https://web.example.org:8443")  # a link inside a sentence is not an instance


def test_a_path_inside_a_description_is_text_never_a_file(tmp_path):
    """A description names paths all the time (/etc/passwd, /bin/sh, ~/.ssh). One that
    happens to exist on the player's machine stays in the text and attaches nothing."""
    secret, folder = tmp_path / "id_rsa", tmp_path / "Documents"
    secret.write_text("the player's own")
    folder.mkdir()
    for text in [f"Can you read {secret} through the viewer? The admin keeps notes in {folder}.",
                 f"spawn {secret} to win", f"The flag is at {secret}, go.", f"cat {secret} | nc host 1",
                 "AES key: 16 bytes read from /dev/null at boot.", f"Hint:\n{secret} is where it lives"]:
        assert addchallenge.parse(text) == (text, ())
        assert addchallenge.dropped(text) == []  # prose with a path in it is not a drop either


def test_a_paste_that_is_only_paths_is_a_drop_whatever_way_the_terminal_wrote_them(tmp_path):
    one, two, three = tmp_path / "a b.bin", tmp_path / "c.txt", tmp_path / "it's.txt"
    for file in (one, two, three):
        file.write_bytes(b"1")
    escaped = str(one).replace(" ", "\\ ")
    assert addchallenge.dropped(f"{escaped} {two}\n") == [one, two]  # side by side, spaces escaped
    assert addchallenge.dropped(f"'{one}' \"{two}\"") == [one, two]  # quoted
    assert addchallenge.dropped(f"{one}\n{two}\n") == [one, two]  # a line each, the spaces as they are
    assert addchallenge.dropped(f"file://{two}") == [two]
    assert addchallenge.dropped(f"{two} {two}") == [two]  # the same file twice is one file
    assert addchallenge.dropped("'" + str(three).replace("'", "'\\''") + "'") == [three]  # a quote in a quoted name, as a shell writes it
    for file in (one, two, three):
        assert addchallenge.dropped(addchallenge.quote(file)) == [file]  # what the console writes on the command bar reads back


NNBSP = " "  # NARROW NO-BREAK SPACE: what macOS writes before AM or PM in a screenshot's name on a 12-hour clock


def backslashed(path, special: str) -> str:
    """`path` with a backslash before each character of `special`, as a terminal that escapes those writes it."""
    return "".join("\\" + c if c in special else c for c in str(path))


ITERM2 = "\\ ()\"&'!$<>;|*?[]#`\t{}^+=@~"  # the characters iTerm2 escapes in a dropped file's path (ASCII only)
GHOSTTY = "\\ ()[]{}<>\"'`!#$&;|*?\t"  # and Ghostty on macOS


def single_quoted(path) -> str:
    return "'" + str(path).replace("'", "'\\''") + "'"  # GNOME Terminal, VS Code, Windows Terminal for WSL


def double_quoted(path) -> str:
    return '"' + str(path).replace("\\", "\\\\").replace('"', '\\"') + '"'  # iTerm2's "wrap it in double quotes"


def spaces_only(path) -> str:
    return str(path).replace(" ", "\\ ")  # WezTerm's default: a backslash before each space and before nothing else


def test_a_screenshot_named_as_macos_names_it_is_a_drop_from_a_terminal_that_escapes_ascii_only(tmp_path):
    """The character before AM is not ASCII, so iTerm2 and Ghostty send it bare. It is a
    character of the name: only an ASCII space or tab parts two words of a drop."""
    shot = tmp_path / f"Screenshot 2026-11-14 at 9.41.12{NNBSP}AM.png"
    other = tmp_path / f"Screenshot 2026-11-14 at 9.41.20{NNBSP}PM.png"
    for file in (shot, other):
        file.write_bytes(b"png")
    assert NNBSP.isspace()  # which is why str.isspace() must not be what parts the words
    for write in (lambda p: backslashed(p, ITERM2), lambda p: backslashed(p, GHOSTTY), spaces_only, single_quoted,
                  double_quoted, str):
        assert addchallenge.dropped(write(shot)) == [shot], write(shot)
        assert addchallenge.dropped(write(shot) + " ") == [shot]  # iTerm2, WezTerm and Alacritty end a drop with a space
    for write in (lambda p: backslashed(p, ITERM2), lambda p: backslashed(p, GHOSTTY), spaces_only, single_quoted, double_quoted):
        assert addchallenge.dropped(f"{write(shot)} {write(other)}") == [shot, other]  # two files, side by side
    assert addchallenge.dropped(f"{shot}\n{other}\n") == [shot, other]  # kitty: a line each, nothing escaped
    assert addchallenge.dropped(addchallenge.quote(shot)) == [shot]
    assert addchallenge.attach_arg(f"static-hiss {backslashed(shot, ITERM2)} ") == ("static-hiss", [shot])
    # the same characters between two paths do not part them: both names are then one word, which is no file
    assert addchallenge.dropped(f"{backslashed(shot, ITERM2)}{NNBSP}{backslashed(other, ITERM2)}") == []


@pytest.mark.parametrize("name", ["my file (1).png", "it's.png", "John's notes.pdf", 'say "hi".txt', "a&b $HOME.bin",
                                  "tab\there.txt", "naïve café.txt", "back\\slash.txt", "both ' and \".txt",
                                  f"Screenshot 2026-11-14 at 9.41.12{NNBSP}AM.png"])
def test_a_dropped_file_is_taken_in_each_terminals_way_of_writing_it(tmp_path, name):
    """One row for each way a terminal writes a dropped file, for names that are awkward in at least one of them."""
    folder = tmp_path / "mnt" / "c" / "My Files"  # (a folder with a space in it, standing in for /mnt/c/...)
    folder.mkdir(parents=True)
    file, second = folder / name, folder / "second.txt"
    file.write_bytes(b"1")
    second.write_bytes(b"2")
    ways = {
        "iTerm2": backslashed(file, ITERM2) + " ",
        "iTerm2, two files": f"{backslashed(file, ITERM2)} {backslashed(second, ITERM2)} ",
        "iTerm2, wrapped in double quotes": double_quoted(file) + " ",
        "Ghostty on macOS": backslashed(file, GHOSTTY),
        "Ghostty on macOS, two files": f"{backslashed(file, GHOSTTY)} {backslashed(second, GHOSTTY)}",
        "kitty": str(file),
        "kitty, two files": f"{file}\n{second}",
        "Alacritty": f"{file} ",
        "GNOME Terminal, Ptyxis": single_quoted(file) + " ",
        "GNOME Terminal, two files": f"{single_quoted(file)} {single_quoted(second)} ",
        "Windows Terminal for WSL": single_quoted(file),
        "VS Code": single_quoted(file),
        "a file:// address": "file://" + "".join(c if c.isascii() and (c.isalnum() or c in "/.-_") else "".join(
            f"%{byte:02X}" for byte in c.encode()) for c in str(file)),
    }
    if "\t" not in name:  # Ghostty's GTK build leaves a tab as it is, and ends each path with a line end
        ways["Ghostty on Linux"] = backslashed(file, "\\\"'$`*? |()") + "\n"
        ways["Ghostty on Linux, two files"] = backslashed(file, "\\\"'$`*? |()") + "\n" + backslashed(second, "\\\"'$`*? |()") + "\n"
    if "\\" not in name:  # WezTerm leaves a backslash as it is: one in a name cannot be told from its own escape
        ways["WezTerm"] = spaces_only(file) + " "
        ways["WezTerm, two files"] = f"{spaces_only(file)} {spaces_only(second)} "
    for terminal, text in ways.items():
        expected = [file, second] if "two files" in terminal else [file]
        assert addchallenge.dropped(text) == expected, (terminal, text)


def test_the_second_reading_of_a_drop_never_makes_a_file_of_text(tmp_path):
    """WezTerm's way (a backslash before a space, a quote as it is) is read only when the
    first reading names no file, and counts only when every word of it is a file that exists."""
    folder = tmp_path / "My Drive"
    folder.mkdir()
    notes, plain = folder / "John's notes.pdf", folder / "plain.txt"
    notes.write_bytes(b"1")
    plain.write_bytes(b"2")
    assert addchallenge.dropped(f"{spaces_only(notes)} {spaces_only(plain)} ") == [notes, plain]
    assert addchallenge.dropped(f"{spaces_only(notes)} and words") == []  # a word that is no file: text
    assert addchallenge.dropped(f"{spaces_only(notes)} /no/such/file.bin") == []
    assert addchallenge.dropped(f"see {spaces_only(notes)}") == []
    assert addchallenge.dropped(spaces_only(folder / "John's other notes.pdf")) == []  # no such file
    with pytest.raises(AddError, match="no such file"):  # /attach names the word that is no file, as it was written
        addchallenge.attach_arg(f"doll {spaces_only(notes)} /no/such/file.bin")
    assert addchallenge.attach_arg(f"doll {spaces_only(notes)} ") == ("doll", [notes])


def test_inside_double_quotes_a_backslash_is_read_only_before_a_quote_or_a_backslash(tmp_path):
    quoted, slashed, plain = tmp_path / 'say "hi".txt', tmp_path / "a\\b.txt", tmp_path / "a\\nb.txt"
    for file in (quoted, slashed, plain):
        file.write_bytes(b"1")
    assert addchallenge.dropped(f'"{tmp_path}/say \\"hi\\".txt"') == [quoted]
    assert addchallenge.dropped(f'"{tmp_path}/a\\\\b.txt"') == [slashed]
    assert addchallenge.dropped(f'"{tmp_path}/a\\nb.txt"') == [plain]  # any other backslash is a character of the name
    assert addchallenge.dropped(f'"{tmp_path}/say \\"hi\\".txt') == []  # a quote that never closes
    assert addchallenge.dropped(f'"{tmp_path}/a\\b.txt\\"') == []  # its last quote is escaped: it never closes either


def test_a_paste_that_reads_as_dropped_files_names_the_one_that_is_not_there_and_any_other_text_names_none(tmp_path):
    there = tmp_path / "there.bin"
    there.write_bytes(b"1")
    gone = tmp_path / "TemporaryItems" / f"Screenshot 2026-11-14 at 9.41.12{NNBSP}AM.png"  # as a thumbnail's file, gone
    for write in (lambda p: backslashed(p, ITERM2) + " ", lambda p: backslashed(p, GHOSTTY), single_quoted, double_quoted,
                  lambda p: spaces_only(p) + " ", str, lambda p: f"{p} "):
        assert addchallenge.not_there(write(gone)) == str(gone), write(gone)
        assert addchallenge.dropped(write(gone)) == []
    assert addchallenge.not_there(f"{there} {single_quoted(gone)}") == str(gone)  # one of two is not there
    assert addchallenge.not_there(f"{there}\n{gone}\n") == str(gone)
    assert addchallenge.not_there("file:///no/such%20folder/shot.png") == "/no/such folder/shot.png"
    assert addchallenge.not_there("~/no-such-folder-of-flightdecks-tests/a.bin") == "~/no-such-folder-of-flightdecks-tests/a.bin"
    for text in [str(there), f"{there} {there}",  # a drop: nothing is missing
                 "/help", "/new Crab Walk", "/hint L01 look at /etc/passwd", "/attach doll /no/such/file.bin",  # commands
                 "/flag.txt",  # one name under the root: no dropped file is written so
                 f"see {gone}", f"{backslashed(gone, ITERM2)} is the file", "/api/v1/flag returns the admin's token",
                 "/var/www/html holds the site", "relative/shot.png", "just some words", "", "  \n",
                 f"Find the flag.\n{gone}\n", f"{single_quoted(gone)} " * 5000]:
        assert addchallenge.not_there(text) == "", text
    assert addchallenge.windows_path("C:\\Users\\me\\shot.png") == "C:\\Users\\me\\shot.png"
    assert addchallenge.windows_path('"C:\\Users\\me\\my shot.png" "D:\\b.bin"') == '"C:\\Users\\me\\my shot.png" "D:\\b.bin"'
    for text in ["C: is the drive", "see C:\\Users\\me\\shot.png", str(gone), "c:\\ ", ""]:
        assert addchallenge.windows_path(text) == "", text


CHOOSE = "press ctrl+o to choose it"
GENERIC_DROP = "Drag a file onto this window to attach it. If nothing lands, your terminal kept the drop: press ctrl+o to choose it."
VSCODE_DROP = ("VS Code's terminal types only the first file of a drop, and leaves ` $ | & > ~ # ! ^ * ; < out of its name: "
               "drop one file at a time, or press ctrl+o to choose it.")
ITERM2_DROP = ("In iTerm2, drag the file with no key held: with Option iTerm2 offers an upload or takes nothing, and with "
               "Command it types a cd line. If nothing lands, press ctrl+o to choose it.")
TMUX_DROP = ("Inside tmux, drop the file on the terminal tmux runs in: tmux passes its path on as a paste (flightdeck cannot "
             "tell which terminal that is). If nothing lands, press ctrl+o to choose it.")
SSH_DROP = ("Over SSH a file you drop stays on the machine your terminal runs on: copy it here first (scp), then /attach "
            "its path.")
WEZTERM_X11_DROP = "WezTerm takes a dropped file on X11 only in its nightly builds: press ctrl+o to choose it."


@pytest.mark.parametrize(("program", "said"), [
    ("vscode", VSCODE_DROP),
    ("iTerm.app", ITERM2_DROP),
    ("tmux", TMUX_DROP),
    # nothing in their own source or documentation that this sentence could name: the generic one
    ("Apple_Terminal", GENERIC_DROP),
    ("ghostty", GENERIC_DROP),
    ("kitty", GENERIC_DROP),
    ("WezTerm", GENERIC_DROP),  # off X11 its drops paste as any other terminal's
    ("WarpTerminal", GENERIC_DROP),
    ("gnome-terminal", GENERIC_DROP),
    ("Hyper", GENERIC_DROP),
    ("", GENERIC_DROP),
    (None, GENERIC_DROP),  # GNOME Terminal, kitty and Alacritty set no TERM_PROGRAM at all
])
def test_the_drop_sentence_is_the_one_for_the_terminal_program(program, said):
    env = {} if program is None else {"TERM_PROGRAM": program}
    assert addchallenge.drop_hint(choose=CHOOSE, env=env) == said


def test_the_drop_sentence_inside_tmux_or_over_ssh_wins_over_the_terminal_program():
    hint = lambda **env: addchallenge.drop_hint(choose=CHOOSE, env=env)  # noqa: E731
    # tmux sets TERM_PROGRAM to its own name in a pane, but a shell started before it may keep the outer one
    assert hint(TMUX="/tmp/tmux-501/default,4242,0", TERM_PROGRAM="iTerm.app") == TMUX_DROP
    assert hint(TMUX="/tmp/tmux-501/default,4242,0") == TMUX_DROP
    assert hint(TMUX="") == GENERIC_DROP  # set but empty is no tmux
    # over SSH the file is on the other machine, in tmux or not, whatever the terminal
    assert hint(SSH_CONNECTION="192.0.2.1 50000 192.0.2.2 22", TMUX="/tmp/tmux-501/default,1,0") == SSH_DROP
    assert hint(SSH_TTY="/dev/pts/3", TERM_PROGRAM="vscode") == SSH_DROP
    # WezTerm's own sentence is for X11 only, where its documentation says drops need a nightly build
    assert hint(TERM_PROGRAM="WezTerm", XDG_SESSION_TYPE="x11") == WEZTERM_X11_DROP
    assert hint(TERM_PROGRAM="WezTerm", XDG_SESSION_TYPE="wayland") == GENERIC_DROP
    assert hint(TERM_PROGRAM="ghostty", XDG_SESSION_TYPE="x11") == GENERIC_DROP


class _Recording(dict):
    """An environment that remembers every name a function asks it for."""

    def __init__(self, **values):
        super().__init__(values)
        self.asked: set[str] = set()

    def get(self, name, default=None):
        self.asked.add(name)
        return super().get(name, default)


def test_the_guide_names_every_variable_the_drop_sentences_are_chosen_by(tmp_path):
    """docs/GUIDE.md says which variables pick the drop sentence and the not-there line; one
    the code reads that the guide leaves out fails here."""
    asked: set[str] = set()
    for values in ({}, {"TERM_PROGRAM": "WezTerm"}, {"TMUX": "x"}, {"SSH_TTY": "x"}):
        env = _Recording(**values)
        addchallenge.drop_terminal(env)
        asked |= env.asked
    gone = str(tmp_path / "gone.png")
    for text, values in ((gone, {}), ("C:\\Users\\a\\b.png", {}), (gone, {"SSH_TTY": "x"})):
        env = _Recording(**values)
        addchallenge.not_there_line(text, choose=CHOOSE, env=env)
        asked |= env.asked
    assert {"SSH_CONNECTION", "SSH_TTY", "TMUX", "TERM_PROGRAM", "XDG_SESSION_TYPE",
            "WSL_DISTRO_NAME", "WSL_INTEROP"} <= asked  # the probe reached every branch
    guide = (Path(__file__).parents[1] / "docs" / "GUIDE.md").read_text()
    paragraph = guide[guide.index("It picks that sentence from"):guide.index("- **Over SSH:** the file you drop")]
    assert [name for name in sorted(asked) if f"`{name}`" not in paragraph] == []
    assert "nothing else depends on them" not in guide


@pytest.mark.parametrize(("env", "said"), [
    ({}, "drag them in, or ctrl+o if none lands"),
    ({"TERM_PROGRAM": "Apple_Terminal"}, "drag them in, or ctrl+o if none lands"),
    ({"TERM_PROGRAM": "vscode"}, "drag one at a time (VS Code types one), or ctrl+o"),
    ({"TERM_PROGRAM": "iTerm.app"}, "drag them in with no key held, or ctrl+o"),
    ({"TERM_PROGRAM": "tmux"}, "drop them on the terminal tmux runs in, or ctrl+o"),
    ({"TERM_PROGRAM": "WezTerm", "XDG_SESSION_TYPE": "x11"}, "ctrl+o (a drop needs a nightly WezTerm on X11)"),
    ({"SSH_TTY": "/dev/pts/3", "TERM_PROGRAM": "iTerm.app"}, "over SSH, scp them here and paste the path"),
])
def test_the_forms_files_line_is_the_short_one_for_the_same_terminal(env, said):
    assert addchallenge.form_files_line(env) == f"Files: {said}; the line under the box names them."


def test_the_drop_sentence_shows_nothing_from_the_environment():
    """Fixed words only: a TERM_PROGRAM or a TMUX value never reaches the screen."""
    for env in ({"TERM_PROGRAM": "\x1b]0;owned\x07"}, {"TMUX": "\x1b[2J/tmp/x,1,0"}, {"TERM_PROGRAM": "vscode\x1b[31m"}):
        said = addchallenge.drop_hint(choose=CHOOSE, env=env)
        assert "\x1b" not in said and "owned" not in said, env
    assert addchallenge.drop_hint(choose=CHOOSE, env={"TERM_PROGRAM": "vscode\x1b[31m"}) == GENERIC_DROP  # only the exact name


def test_the_line_for_a_dropped_file_that_is_not_there_says_why_it_is_not_where_the_console_runs(tmp_path):
    gone, windows = str(tmp_path / "gone" / "shot.png"), '"C:\\Users\\me\\my shot.png"'
    shown = "..." + gone[-45:]  # a long path shows its end, where the name is
    assert len(gone) > 48
    line = lambda text, **env: addchallenge.not_there_line(text, choose="press ctrl+o to choose it", env=env)  # noqa: E731
    assert line(gone) == (f"no such file: {shown}. A dropped file may have been a temporary one, gone by now: drag the "
                          "saved file, or press ctrl+o to choose it")
    assert line(gone, TERM_PROGRAM="vscode") == (f"no such file: {shown}. VS Code's terminal leaves ` $ | & > ~ # ! ^ * ; < "
                                                 "out of a dropped file's name: press ctrl+o to choose it")
    over_ssh = ("Over SSH a dropped file stays on the machine your terminal runs on: copy it here first (scp), "
                "then /attach its path")
    assert line(gone, SSH_CONNECTION="192.0.2.1 50000 192.0.2.2 22") == f"not on this machine: {shown}. {over_ssh}"
    assert line(gone, SSH_TTY="/dev/pts/3", TERM_PROGRAM="vscode") == f"not on this machine: {shown}. {over_ssh}"
    assert line(windows, SSH_TTY="/dev/pts/3", WSL_DISTRO_NAME="Ubuntu") == f"not on this machine: {windows}. {over_ssh}"
    assert line(windows, WSL_DISTRO_NAME="Ubuntu") == line(windows, WSL_INTEROP="/run/WSL/8_interop") == (
        f'{windows} is a Windows path. Set "pathTranslationStyle": "wsl" on this Windows Terminal profile and drop the '
        "file again, or /attach its /mnt/c/... path")
    assert line(windows) == ""  # a Windows path anywhere else is text
    for text in ["/help", "see " + gone, "just words", str(tmp_path)]:  # no drop but for a missing file: nothing to say
        assert line(text) == line(text, SSH_TTY="/dev/pts/3") == line(text, WSL_DISTRO_NAME="Ubuntu") == "", text
    assert line("/no/such/\x1b[31mred.png") == ("no such file: /no/such/^[[31mred.png. A dropped file may have been a temporary one, "
                                                "gone by now: drag the saved file, or press ctrl+o to choose it")


def test_a_word_a_path_that_does_not_exist_or_a_path_among_words_is_not_a_drop(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "flag").write_text("x")  # a file named like a word of the text, in the folder flightdeck runs in
    there = tmp_path / "there.bin"
    there.write_bytes(b"1")
    for text in ["flag", "/no/such/file.bin", f"{there} /no/such/file.bin", f"see {there}", f"{there} is it", f"'{there}", "", "  \n"]:
        assert addchallenge.dropped(text) == []
    assert addchallenge.dropped(f"{there} " * 5000) == []  # too long to be a drop
    assert addchallenge.parse("flag\n/no/such/file.bin\n") == ("flag\n/no/such/file.bin", ())


# ---------------------------------------------------------------------- the folder


def test_a_handed_over_challenge_is_a_folder_the_board_loads(tmp_path):
    handout = tmp_path / "postcard.txt"
    handout.write_text("hello")
    folder = addchallenge.create(tmp_path, NewChallenge(name="Crab  Walk!", category="crypto", points=50, description='say "hi"',
                                                        files=(handout,), urls=("tcp://chal.example.org:1337",)))
    assert folder == tmp_path / "crab-walk"
    item = load_challenge(folder)
    assert (item.challenge.name, item.challenge.points, item.challenge.description) == ("Crab Walk!", 50, 'say "hi"')
    assert item.challenge.files == ("postcard.txt",) and item.urls == ("tcp://chal.example.org:1337",)
    assert (folder / "postcard.txt").read_text() == "hello" and handout.exists()  # copied, the player's own left alone


def test_two_challenges_of_one_name_get_folders_of_their_own_and_a_bare_one_is_misc(tmp_path):
    first = addchallenge.create(tmp_path, NewChallenge(name="Same"))
    second = addchallenge.create(tmp_path, NewChallenge(name="Same"))
    assert (first.name, second.name) == ("same", "same-2")
    assert json.loads((second / "challenge.json").read_text())["category"] == "misc"
    assert len(load_board(tmp_path).challenges) == 2


@pytest.mark.parametrize("new", [NewChallenge(name="  "), NewChallenge(name="!!!"), NewChallenge(name="x", points=-1),
                                 NewChallenge(name="x", files=(Path("/no/such/file"),))])
def test_a_challenge_that_cannot_be_written_leaves_nothing_behind(tmp_path, new):
    with pytest.raises(AddError):
        addchallenge.create(tmp_path, new)
    assert list(tmp_path.iterdir()) == []


def test_an_add_that_loses_the_race_for_a_name_leaves_the_winners_folder_alone(tmp_path, monkeypatch):
    """Two adds of one name at once (the console's /new and `flightdeck add` in another
    terminal): the folder is there by the time this one makes its own. It belongs to the
    other add, so this one takes the next name and removes nothing."""
    board = tmp_path / "board"
    board.mkdir()
    handout = tmp_path / "note.txt"
    handout.write_text("mine")
    real_mkdir = Path.mkdir

    def mkdir(self, *args, **kwargs):
        if self == board / "baby-rsa" and not self.exists():  # the other add gets there first
            real_mkdir(self)
            (self / "theirs.bin").write_bytes(b"the other add's file")
        return real_mkdir(self, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", mkdir)
    made = addchallenge.create(board, NewChallenge(name="Baby RSA", files=(handout,)))
    assert made == board / "baby-rsa-2" and (made / "note.txt").read_text() == "mine"
    assert (board / "baby-rsa" / "theirs.bin").read_bytes() == b"the other add's file"


def test_a_folder_that_cannot_be_filled_is_removed_but_only_the_one_this_add_made(tmp_path):
    board, handout = tmp_path / "board", tmp_path / "handout"
    (board / "doll").mkdir(parents=True)
    (board / "doll" / "theirs.bin").write_bytes(b"1")
    handout.mkdir()
    (handout / "a.txt").write_text("a")
    import os

    os.mkfifo(handout / "pipe")  # found only while the folder is copied
    with pytest.raises(AddError, match="named pipe"):
        addchallenge.create(board, NewChallenge(name="Doll", files=(handout,)))
    assert [entry.name for entry in board.iterdir()] == ["doll"] and (board / "doll" / "theirs.bin").exists()


def test_a_file_that_cannot_be_read_is_named_in_the_refusal_and_nothing_is_left(tmp_path):
    import os

    if os.geteuid() == 0:
        pytest.skip("root reads any file, so no copy fails this way")
    board, good, locked = tmp_path / "board", tmp_path / "good.txt", tmp_path / "locked.bin"
    board.mkdir()
    good.write_text("good")
    locked.write_bytes(b"x")
    locked.chmod(0)
    with pytest.raises(AddError, match=r"cannot write .*/board/doll: Permission denied \(.*locked\.bin\)"):
        addchallenge.create(board, NewChallenge(name="Doll", files=(good, locked)))
    assert list(board.iterdir()) == []


# ---------------------------------------------------------------------- a drop's files, kept in the run folder


def test_a_dropped_file_is_copied_under_its_own_name_and_outlives_the_file_it_was(tmp_path):
    staging = tmp_path / "run" / "dropped"
    shot, twin, folder = tmp_path / "a" / "shot.png", tmp_path / "b" / "shot.png", tmp_path / "handout"
    for file, data in ((shot, b"one"), (twin, b"two")):
        file.parent.mkdir()
        file.write_bytes(data)
    (folder / "src").mkdir(parents=True)
    (folder / "src" / "main.c").write_text("int main;")
    copies = addchallenge.stage(staging, [shot, twin, folder])
    assert copies == [staging / "1" / "shot.png", staging / "2" / "shot.png", staging / "3" / "handout"]  # two of one name: a folder each
    shot.unlink()  # a screenshot's thumbnail, or a terminal's temporary file: gone before the player attaches it
    assert copies[0].read_bytes() == b"one" and copies[1].read_bytes() == b"two"
    assert (copies[2] / "src" / "main.c").read_text() == "int main;"
    assert addchallenge.stage(staging, [twin]) == [staging / "4" / "shot.png"]  # a later drop takes the next number
    board = tmp_path / "board"
    board.mkdir()
    made = addchallenge.create(board, NewChallenge(name="Doll", files=(copies[0], copies[2])))  # a copy attaches as any file does
    assert (made / "shot.png").read_bytes() == b"one" and (made / "handout" / "src" / "main.c").is_file()


def test_a_drop_that_cannot_be_copied_names_the_file_and_leaves_no_copy(tmp_path, monkeypatch):
    import os

    staging, good, broken = tmp_path / "run" / "dropped", tmp_path / "good.txt", tmp_path / "broken"
    good.write_text("good")
    broken.mkdir()
    os.mkfifo(broken / "pipe")  # a folder may be attached, but one with a named pipe in it cannot be copied
    with pytest.raises(AddError, match=r"broken/pipe is a named pipe: a folder with one in it cannot be attached"):
        addchallenge.stage(staging, [good, broken])
    assert list(staging.iterdir()) == []  # the first file's copy is gone again too
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    for file, why in ((home, "is your home folder itself"), (tmp_path / "gone.bin", "no such file"),
                      (Path("/dev/null"), "is a device"), (tmp_path / "run", "holds the folder it would be copied into")):
        with pytest.raises(AddError, match=why):  # checked before anything is copied, as a file is before it is attached
            addchallenge.stage(staging, [good, file])
    assert list(staging.iterdir()) == []

    def full(source, target, made=None):
        raise OSError(28, "No space left on device", str(target))

    monkeypatch.setattr(addchallenge, "_copy", full)
    with pytest.raises(AddError, match=r"cannot copy .*/good\.txt: No space left on device \(.*/dropped/1/good\.txt\)"):
        addchallenge.stage(staging, [good])
    assert list(staging.iterdir()) == []


def test_only_a_drops_own_copy_is_ever_removed(tmp_path):
    staging, own = tmp_path / "run" / "dropped", tmp_path / "7" / "own.bin"
    own.parent.mkdir()
    own.write_bytes(b"the player's own")
    one, two = addchallenge.stage(staging, [own, own])
    nested = staging / "9" / "deep" / "file.bin"  # not a copy `stage` made: two folders down
    nested.parent.mkdir(parents=True)
    nested.write_bytes(b"x")
    addchallenge.unstage(staging, [one, own, nested, staging / "nope" / "x", tmp_path / "run" / "eventlog.jsonl"])
    assert not one.parent.exists() and two.read_bytes() == b"the player's own"  # the copy named, and only that
    assert own.read_bytes() == b"the player's own" and nested.is_file()  # a file in a numbered folder of the player's stays
    addchallenge.unstage(staging, [two])
    assert sorted(entry.name for entry in staging.iterdir()) == ["9"]


# ---------------------------------------------------------------------- what may be attached


def test_only_a_regular_file_or_a_folder_is_attached_and_each_refusal_names_its_reason(tmp_path, monkeypatch):
    import os
    import socket

    home, keys = tmp_path / "home", tmp_path / "elsewhere" / "keys.env"
    config = home / ".config" / "ctf-flightdeck"
    config.mkdir(parents=True)
    (config / "config.toml").write_text("")
    keys.parent.mkdir()
    keys.write_text("")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("FLIGHTDECK_KEYS", str(keys))
    pipe, sock, link = tmp_path / "pipe", tmp_path / "s", tmp_path / "innocent.txt"
    os.mkfifo(pipe)
    listener = socket.socket(socket.AF_UNIX)
    monkeypatch.chdir(tmp_path)  # a socket's path is short: bound by its name alone
    listener.bind("s")
    link.symlink_to(keys)  # a link the player names is followed: it is the keys file
    try:
        for path, why in [(Path("/dev/null"), "is a device"), (pipe, "is a named pipe"), (sock, "is a socket"),
                          (Path("/"), "is the root folder"), (home, "is your home folder itself"),
                          (config, "is flightdeck's config folder"), (home / ".config", "holds flightdeck's config folder"),
                          (config / "config.toml", "is in flightdeck's config folder"), (keys, "is flightdeck's keys file"),
                          (keys.parent, "holds flightdeck's keys file"), (link, "is flightdeck's keys file"),
                          (tmp_path / "gone.bin", "no such file")]:
            said = addchallenge.refusal(path)
            assert said is not None and why in said and str(path) in said, (path, said)
            with pytest.raises(AddError, match=why):
                addchallenge.create(tmp_path / "elsewhere", NewChallenge(name="X", files=(path,)))
    finally:
        listener.close()
    assert sorted(entry.name for entry in keys.parent.iterdir()) == ["keys.env"]  # no challenge folder was left
    handout = home / "ctf" / "handout"
    handout.mkdir(parents=True)
    (handout / "a.txt").write_text("a")
    assert addchallenge.refusal(handout) is None and addchallenge.refusal(handout / "a.txt") is None


def test_a_folder_that_holds_the_board_is_not_copied_into_it(tmp_path):
    board = tmp_path / "ctf" / "event" / "board"
    board.mkdir(parents=True)
    with pytest.raises(AddError, match="holds the folder it would be copied into"):
        addchallenge.create(board, NewChallenge(name="X", files=(tmp_path / "ctf",)))
    assert list(board.iterdir()) == []


def test_a_copied_folder_keeps_a_link_as_a_link_and_a_link_the_player_names_gives_the_file(tmp_path):
    outside, handout, board = tmp_path / "outside.txt", tmp_path / "handout", tmp_path / "board"
    outside.write_text("not the challenge's")
    (handout / "sub").mkdir(parents=True)
    (handout / "sub" / "real.txt").write_text("real")
    (handout / "sub" / "out").symlink_to(outside)
    named = tmp_path / "named.txt"
    named.symlink_to(handout / "sub" / "real.txt")
    board.mkdir()
    made = addchallenge.create(board, NewChallenge(name="Links", files=(handout, named)))
    copied = made / "handout" / "sub" / "out"
    assert copied.is_symlink() and (made / "handout" / "sub" / "real.txt").read_text() == "real"  # never followed
    assert not (made / "named.txt").is_symlink() and (made / "named.txt").read_text() == "real"
    assert load_challenge(made).challenge.files == ("handout/sub/real.txt", "named.txt")


# ---------------------------------------------------------------------- the addresses


@pytest.mark.parametrize("line", ["http://chal.example.org:1337.", "https://example.org,", "http://exämple.org", "http://a.org:99999",
                                  "nc 10.0.0.256 1337", "http://player@example.org"])
def test_an_address_the_board_could_not_load_is_not_taken_as_one(tmp_path, line):
    """What add writes, the board loads: a line that looks like an address but is not one
    manual.py takes stays description, and the challenge still loads."""
    description, urls = addchallenge.parse(f"Reach it here:\n{line}\n")
    assert urls == () and line in description
    result = CliRunner().invoke(cli.app, ["add", str(tmp_path), "--name", "Odd", "--text", f"Reach it here:\n{line}\n"])
    assert result.exit_code == 0, result.output
    item = load_challenge(tmp_path / "odd")
    assert item.urls == () and line in item.challenge.description
    refused = CliRunner().invoke(cli.app, ["add", str(tmp_path), "--name", "Odd Url", "--url", line])
    assert refused.exit_code == 2 and "--url" in refused.output and not (tmp_path / "odd-url").exists()


def test_an_address_is_kept_in_the_form_the_board_loads_and_create_refuses_any_other(tmp_path):
    assert addchallenge.address("https://Web.Example.org:8443/login?x=1") == "https://web.example.org:8443"
    assert addchallenge.address("`nc Chal.example.org 01337`") == "tcp://chal.example.org:1337"
    assert addchallenge.address("http://chal.example.org:1337/x.") == "http://chal.example.org:1337"
    for url in ["http://chal.example.org:1337.", "https://example.org/path", "tcp://chal.example.org", "ftp://example.org", "HTTP://EXAMPLE.org"]:
        with pytest.raises(AddError, match="not an address the board can hold"):
            addchallenge.create(tmp_path, NewChallenge(name="X", urls=(url,)))
    assert list(tmp_path.iterdir()) == []
    made = addchallenge.create(tmp_path, NewChallenge(name="X", urls=("https://example.org", "tcp://h.example.org:9", "https://example.org")))
    assert load_challenge(made).urls == ("https://example.org", "tcp://h.example.org:9")  # one given twice is kept once


# ---------------------------------------------------------------------- the command


def test_flightdeck_add_puts_a_challenge_on_an_events_board(tmp_path):
    start.write(tmp_path / "event", start.EventAnswers(name="One", platform="manual"))
    handout = tmp_path / "capture.pcap"
    handout.write_bytes(b"pcap")
    result = CliRunner().invoke(cli.app, ["add", str(tmp_path / "event"), "--name", "Wire Tap", "--text", "-", "--file", str(handout),
                                          "--url", "nc chal.example.org 9", "--category", "forensics", "--points", "100"],
                                input="Listen in.\n")
    assert result.exit_code == 0, result.output
    item = load_challenge(tmp_path / "event" / "board" / "wire-tap")
    assert (item.challenge.description, item.challenge.files, item.urls) == ("Listen in.", ("capture.pcap",), ("tcp://chal.example.org:9",))
    assert "attached capture.pcap (4 B)" in result.output.splitlines()  # every file attached is shown


def test_flightdeck_add_keeps_the_text_as_given_and_attaches_only_what_file_names(tmp_path):
    """The description is the event's text. A path in it that exists on this machine is not
    copied into the handout the lanes read, and is not cut out of the text."""
    secret, handout = tmp_path / "private" / "id_rsa", tmp_path / "given.bin"
    secret.parent.mkdir()
    secret.write_text("the player's own")
    handout.write_bytes(b"x" * 2048)
    text = f"Can you read {secret} through the viewer?\nThe admin keeps his notes in {secret.parent}.\n{secret}\nread from /dev/null at boot."
    board = tmp_path / "board"
    board.mkdir()
    result = CliRunner().invoke(cli.app, ["add", str(board), "--name", "Viewer", "--text", "-"], input=text + "\n")
    assert result.exit_code == 0, result.output
    assert json.loads((board / "viewer" / "challenge.json").read_text())["description"] == text
    assert sorted(entry.name for entry in (board / "viewer").iterdir()) == ["challenge.json"]
    assert "no file attached" in result.output and "id_rsa" not in result.output
    result = CliRunner().invoke(cli.app, ["add", str(board), "--name", "Viewer", "--text", text, "--file", str(handout), "--file", str(handout)])
    assert result.exit_code == 0, result.output
    assert sorted(entry.name for entry in (board / "viewer-2").iterdir()) == ["challenge.json", "given.bin"]
    assert [line for line in result.output.splitlines() if line.startswith("attached")] == ["attached given.bin (2.0 KB)"]


def test_flightdeck_add_refuses_a_file_that_is_not_one_with_the_reason_and_writes_nothing(tmp_path):
    result = CliRunner().invoke(cli.app, ["add", str(tmp_path), "--name", "X", "--file", "/dev/null"])
    assert result.exit_code == 2 and "/dev/null is a device" in result.output and list(tmp_path.iterdir()) == []


def test_flightdeck_add_refuses_an_address_it_cannot_use_and_writes_nothing(tmp_path):
    result = CliRunner().invoke(cli.app, ["add", str(tmp_path), "--name", "X", "--url", "somewhere"])
    assert result.exit_code == 2 and "--url" in result.output and list(tmp_path.iterdir()) == []


# ---------------------------------------------------------------------- a run


def event(tmp_path: Path) -> Path:
    start.write(tmp_path / "event", start.EventAnswers(name="Hand CTF", platform="manual", flag_format=r"t\{[a-z_]+\}"))
    return tmp_path / "event"


def options(tmp_path: Path, server) -> RunOptions:
    folder = event(tmp_path)
    board, profile = start.resolve(folder, None)
    return RunOptions(board=board, event=profile, config=config(tmp_path, server.base_url), folder_seconds=0.05)


def test_a_by_hand_events_empty_board_plays_but_a_plain_empty_folder_does_not(tmp_path):
    with FakeModelServer([]) as server:
        run = prepare_run(options(tmp_path, server))
        assert run.board.challenges == () and run.watches_folder
        assert any("/new adds a challenge" in note for note in run.notes())
        run.close()
        (tmp_path / "plain").mkdir()
        with pytest.raises(RunError, match="no challenge directories"):
            prepare_run(RunOptions(board=tmp_path / "plain", config=config(tmp_path, server.base_url)))


def test_new_in_the_console_hands_a_challenge_with_its_file_to_a_lane_that_solves_it(tmp_path):
    handout = tmp_path / "note.txt"
    handout.write_text(f"the flag is {FLAG}\n")
    server = FakeModelServer([tool_call_reply("shell", {"command": "cat note.txt"}), tool_call_reply("submit_flag", {"flag": FLAG})])

    async def main():
        with server:
            run = prepare_run(options(tmp_path, server))
            app = run.app(refresh_seconds=None)
            async with app.run_test(size=(160, 46)) as pilot:
                await pilot.pause()
                page = str(app.screen.query_one("#empty").render())  # in the page itself: a status line expires
                assert not run.deck.lanes and "Type /new to hand one over" in page and app.screen.query_one("#empty").display
                await pilot.press(*"/new Read Me", "enter")
                await pilot.pause()
                box = app.screen.query_one("#new-text")
                box.text = "Read the note.\n"
                form = app.screen
                await app.on_event(events.Paste(f"{handout}\n"))  # the file dropped on the terminal
                await until(pilot, lambda: form.files == [copy_of(run, "note.txt")])  # the run's own copy of it is what is attached
                assert box.text == "Read the note.\n"
                await pilot.press("ctrl+s")
                for _ in range(500):
                    lanes = list(run.deck.lanes.values())
                    if lanes and lanes[0].pending is not None:
                        break
                    await pilot.pause(0.01)
                (lane,) = run.deck.lanes.values()
                assert lane.challenge_id == "read-me" and lane.pending.flag == FLAG
                assert "added read-me: 1 file" in app._status[0]
                spec = json.loads((run.options.board / "read-me" / "challenge.json").read_text())
                assert spec["description"] == "Read the note." and spec["name"] == "Read Me"
                brief = server.chats()[0]["json"]["messages"][1]["content"]
                assert "Read the note." in brief and "note.txt" in brief
            await run.shutdown()
            run.close()

    asyncio.run(main())


def test_new_without_a_name_says_so_and_adds_nothing(tmp_path):
    async def main():
        with FakeModelServer([]) as server:
            run = prepare_run(options(tmp_path, server))
            app = run.app(refresh_seconds=None)
            async with app.run_test(size=(160, 46)) as pilot:
                await pilot.pause()
                await pilot.press(*"/new", "enter")
                await pilot.pause()
                await pilot.press("ctrl+s")
                await pilot.pause()
                assert "name" in str(app.screen.query_one("#new-problem").render())
                await pilot.press("escape")
                await pilot.pause()
                assert not run.deck.challenges and list(run.options.board.iterdir()) == []
            await run.shutdown()
            run.close()

    asyncio.run(main())


def test_a_folder_added_while_the_run_plays_gets_a_lane_and_a_broken_one_is_a_warning_until_fixed(tmp_path):
    server = FakeModelServer([tool_call_reply("submit_flag", {"flag": FLAG})])

    async def main():
        with server:
            run = prepare_run(options(tmp_path, server))
            warnings = []
            run.deck.subscribe(lambda e: warnings.append(e.text) if e.kind.value == "warning" else None)
            run.release()
            board = run.options.board
            (board / "bad").mkdir()
            (board / "bad" / "challenge.json").write_text("{not json")
            addchallenge.create(board, NewChallenge(name="Later", description="d"))  # as `flightdeck add` does, from another terminal
            for _ in range(400):
                if run.deck.lanes and any("bad" in w for w in warnings):
                    break
                await asyncio.sleep(0.01)
            assert [lane.challenge_id for lane in run.deck.lanes.values()] == ["later"]
            assert sum("bad" in w for w in warnings) == 1
            await asyncio.sleep(0.2)
            assert sum("bad" in w for w in warnings) == 1  # said once while the file stays as it is
            (board / "bad" / "challenge.json").write_text(json.dumps({"name": "Bad", "category": "misc", "points": 1}))
            import os
            os.utime(board / "bad" / "challenge.json", (1, 1))  # a different time than the one it was read at
            for _ in range(400):
                if "bad" in run.deck.challenges:
                    break
                await asyncio.sleep(0.01)
            assert "bad" in run.deck.challenges
            await run.shutdown()
            run.close()

    asyncio.run(main())


def test_new_is_refused_on_the_mocks_board(tmp_path):
    from ctf_flightdeck.console.app import FlightdeckApp
    from ctf_flightdeck.mock import scenarios
    from ctf_flightdeck.mock.world import FakeWorld

    async def main():
        world = FakeWorld(scenarios.get("default"))
        app = FlightdeckApp(world.deck, ticker=world.tick, tick_seconds=None, refresh_seconds=None, mock="MOCK")
        async with app.run_test(size=(160, 46)) as pilot:
            await pilot.pause()
            await pilot.press(*"/new", "enter")
            await pilot.pause()
            assert "scripted" in app._status[0] and app._status[1] == "warning"

    asyncio.run(main())


# ---------------------------------------------------------------------- screenshots


PNG = bytes.fromhex("89504e470d0a1a0a") + b"synthetic image bytes"


def test_the_anthropic_client_sends_a_pasted_image_as_an_image_block():
    from ctf_flightdeck import imageread
    from ctf_flightdeck.agent.anthropic_client import to_anthropic

    import tempfile

    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / "shot.png"
        path.write_bytes(PNG)
        turns = to_anthropic(imageread.message(path)[1:])
    (turn,) = turns
    kinds = [block["type"] for block in turn["content"]]
    assert kinds == ["text", "image"]
    source = turn["content"][1]["source"]
    import base64

    assert (source["type"], source["media_type"]) == ("base64", "image/png") and base64.b64decode(source["data"]) == PNG


def test_an_image_that_is_no_image_or_too_big_is_refused_before_any_model_is_asked(tmp_path):
    from ctf_flightdeck import imageread

    (tmp_path / "notes.txt").write_text("x")
    big = tmp_path / "big.png"
    big.write_bytes(b"0" * (imageread.MAX_BYTES + 1))
    for path, why in [(tmp_path / "notes.txt", "not a PNG"), (big, "at most 4 MB")]:
        with pytest.raises(imageread.ImageError, match=why):
            imageread.message(path)


@pytest.mark.parametrize(("platform", "tools", "code", "out", "error"), [
    ("linux", {"xclip"}, 0, PNG, None),
    ("linux", {"wl-paste", "xclip"}, 1, b"", "no image on the clipboard"),
    ("linux", set(), 0, PNG, "needs wl-paste"),
    ("darwin", set(), 0, b"", "needs osascript"),
])
def test_the_clipboards_image_is_saved_as_a_file_or_the_reason_is_said(tmp_path, platform, tools, code, out, error):
    from types import SimpleNamespace

    from ctf_flightdeck import imageread

    calls = []

    def run(argv, **kwargs):
        calls.append(argv[0])
        return SimpleNamespace(returncode=code, stdout=out)

    which = lambda tool: f"/usr/bin/{tool}" if tool in tools else None  # noqa: E731
    if error:
        with pytest.raises(imageread.ImageError, match=error):
            imageread.clipboard_image(tmp_path / "pasted", platform=platform, which=which, run=run)
        assert not list((tmp_path / "pasted").glob("*.png"))  # nothing half-written is left
    else:
        saved = imageread.clipboard_image(tmp_path / "pasted", platform=platform, which=which, run=run)
        assert saved.read_bytes() == PNG and saved.name == "screenshot-1.png" and calls == ["xclip"]
        assert imageread.clipboard_image(tmp_path / "pasted", platform=platform, which=which, run=run).name == "screenshot-2.png"


def test_a_screenshot_pasted_into_new_is_read_by_the_model_and_its_text_reaches_the_lane(tmp_path):
    from fake_model import text_reply

    shot = tmp_path / "clip.png"
    shot.write_bytes(PNG)
    server = FakeModelServer([text_reply("Unholy Trinity\ncrypto 200\nRecover the key.\nPicture: a dark page."),
                              tool_call_reply("submit_flag", {"flag": FLAG})])

    async def main():
        with server:
            run = prepare_run(options(tmp_path, server))
            app = run.app(refresh_seconds=None)
            app.paster = lambda: shot  # the clipboard, as the run would save it
            async with app.run_test(size=(160, 46)) as pilot:
                await pilot.pause()
                await pilot.press(*"/new Trinity", "enter")
                await pilot.pause()
                await pilot.press("ctrl+v")
                for _ in range(200):
                    if app.screen.files:
                        break
                    await pilot.pause(0.01)
                assert app.screen.files == [shot] and app.screen.query_one("#new-text").text == ""
                assert "1 file attached: clip.png" in str(app.screen.query_one("#new-attached").render())
                await pilot.press("ctrl+s")
                for _ in range(500):
                    if run.deck.lanes:
                        break
                    await pilot.pause(0.01)
                (lane,) = run.deck.lanes.values()
                for _ in range(500):
                    if len(server.chats()) >= 2:
                        break
                    await pilot.pause(0.01)
            await run.shutdown()
            run.close()
            asked, brief = server.chats()[0]["json"]["messages"], server.chats()[1]["json"]["messages"][1]["content"]
            assert asked[1]["content"][1]["image_url"]["url"].startswith("data:image/png;base64,")  # the image went to the model once
            assert "Recover the key." in brief and "clip.png" in brief  # and its text, and the file, to the lane
            spec = json.loads((run.options.board / "trinity" / "challenge.json").read_text())
            assert "[Text read from the image clip.png by fake/small:]" in spec["description"]
            assert (run.options.board / "trinity" / "clip.png").read_bytes() == PNG

    asyncio.run(main())


def test_an_image_the_model_cannot_read_is_a_warning_and_the_challenge_is_added_with_the_file(tmp_path):
    from fake_model import FakeReply

    shot = tmp_path / "clip.png"
    shot.write_bytes(PNG)
    server = FakeModelServer([FakeReply(status=400, body={"error": {"message": "this model takes no images"}})])

    async def main():
        with server:
            run = prepare_run(options(tmp_path, server))
            warnings = []
            run.deck.subscribe(lambda e: warnings.append(e.text) if e.kind.value == "warning" else None)
            run.release()
            ok, told = await run.add_challenge(NewChallenge(name="Blind", description="typed text", files=(shot,)))
            assert ok and "reading 1 image" in told
            for _ in range(500):
                if "blind" in run.deck.challenges:
                    break
                await asyncio.sleep(0.01)
            assert run.deck.challenges["blind"].description == "typed text"
            assert any("could not read clip.png" in w and "without that image's text" in w for w in warnings)
            await run.shutdown()
            run.close()

    asyncio.run(main())


def test_a_challenge_with_an_image_is_checked_before_the_model_is_asked_to_read_it(tmp_path):
    """The refusal comes back while the form is open, not as a warning after "reading 1
    image..." closed it."""
    shot, twin = tmp_path / "clip.png", tmp_path / "other" / "clip.png"
    twin.parent.mkdir()
    for file in (shot, twin):
        file.write_bytes(PNG)

    async def main():
        with FakeModelServer([]) as server:
            run = prepare_run(options(tmp_path, server))
            run.release()
            for new, why in [(NewChallenge(name="N" * 121, files=(shot,)), "at most 120 characters"),
                             (NewChallenge(name="Twins", files=(shot, twin)), "two files named clip.png"),
                             (NewChallenge(name="Odd", files=(shot,), urls=("http://chal.example.org:1337.",)), "not an address")]:
                ok, told = await run.add_challenge(new)
                assert not ok and why in told
            await asyncio.sleep(0.1)
            await run.shutdown()
            run.close()
            assert server.chats() == [] and not run.deck.challenges and list(run.options.board.iterdir()) == []

    asyncio.run(main())


def test_a_path_in_the_middle_of_a_line_stays_in_the_text_quoted_or_escaped_or_bare(tmp_path):
    plain, spaced = tmp_path / "matryoshka.bin", tmp_path / "Screenshot 2026 at 4.38 PM.png"
    plain.write_bytes(b"1")
    spaced.write_bytes(b"2")
    escaped = str(spaced).replace(" ", "\\ ")
    text = f"Open the doll {plain} and look inside. Also see '{spaced}'\nand {escaped}."
    assert addchallenge.parse(text + "\n") == (text, ()) and addchallenge.dropped(text) == []


def test_the_form_says_what_it_found(tmp_path):
    file = tmp_path / "a.bin"
    file.write_bytes(b"x" * 2048)
    assert addchallenge.attached_text((file,), ("tcp://h:1",)) == "1 file attached: a.bin (2.0 KB) · target: tcp://h:1"
    assert addchallenge.attached_text((), ()) == "no file attached"


# ---------------------------------------------------------------------- what is attached, and /attach


def in_console(tmp_path, body, server=None, *, run_dir: Path | None = None) -> None:
    """Run `body(run, app, pilot)` in the console of a run on an empty by-hand board; with
    `run_dir`, its folder goes there (as --run-dir gives it) and not where the config says."""
    async def main():
        with server or FakeModelServer([]) as model:
            run = prepare_run(replace(options(tmp_path, model), run_dir=run_dir))
            app = run.app(refresh_seconds=None)
            try:
                async with app.run_test(size=(160, 46)) as pilot:
                    await pilot.pause()
                    await body(run, app, pilot)
            finally:
                await run.shutdown()
                run.close()

    asyncio.run(main())


def busy_lanes() -> FakeModelServer:
    """A model whose lanes stay at work, so one is there to restart."""
    return FakeModelServer(responder=lambda request: tool_call_reply("shell", {"command": "sleep 0.2"}))


async def until(pilot, done, tries: int = 500) -> None:
    for _ in range(tries):
        if done():
            return
        await pilot.pause(0.01)
    app = pilot.app
    field = app.screen.query("#bar-input")
    raise AssertionError(f"waited too long: the console is on {type(app.screen).__name__}, its status line says "
                         f"{app._status[0]!r} and its command bar holds {field.first().value if field else None!r}")


async def command(pilot, text: str) -> None:
    """Send the command `text` from the bar: its `/` typed (the key opens the bar wherever
    the focus is), the rest put in the way a terminal paste arrives, then Enter.

    For the commands that name a file under tmp_path, whose path is over a hundred characters.
    Typed key by key next to a lane at work they took 12 s each: Textual's pilot waits after
    every key for the process to be idle, and a working lane leaves it idle only now and then
    (0.1 s a key, measured). A paste that is not only paths is text (addchallenge.dropped), so
    the bar holds exactly what the keys would have put there."""
    assert text.startswith("/") and not addchallenge.dropped(text[1:])
    await pilot.press("/")
    pilot.app.post_message(events.Paste(text[1:]))
    await pilot.pause()
    assert pilot.app.screen.query_one("#bar-input").value == text
    await pilot.press("enter")


def said(form) -> str:
    return str(form.query_one("#new-problem").render())


def copy_of(run, name: str, n: int = 1) -> Path:
    """Where the run keeps its copy of a dropped file: the n-th file its console took, under its own name."""
    return run.dir / "dropped" / str(n) / name


async def on_bar(pilot, value: str) -> None:
    """Wait until the command bar holds `value`: a drop lands on it once its files are copied, in a thread.

    Then until the console has nothing left to do: the drop gives the bar the focus too, and
    Textual sets a focus on the console's next turn (Widget.focus), after the value is there.
    A test that asked for the focus as soon as it saw the value failed now and then when
    the suite ran in parallel."""
    await until(pilot, lambda: pilot.app.screen.query_one("#bar-input").value == value)
    await pilot.pause()


def test_the_name_takes_any_character_and_a_file_dropped_while_it_has_the_focus_is_attached(tmp_path):
    handout = tmp_path / "doll.bin"
    handout.write_bytes(b"x" * 10)

    async def body(run, app, pilot):
        await pilot.press(*"/new", "enter")
        await pilot.pause()
        form = app.screen
        shown = lambda: str(form.query_one("#new-attached").render())  # noqa: E731
        assert shown() == "no file attached"
        name = form.query_one("#new-name")
        await pilot.press(*"~home /dev/null /")  # a name may start with ~ or /, and be a path that exists
        await pilot.pause()
        assert name.value == "~home /dev/null /" and form.files == [] and form.query_one("#new-text").text == ""
        assert shown() == "no file attached"
        await app.on_event(events.Paste(f"{handout} "))  # a drop, while the name has the focus
        await until(pilot, lambda: form.files == [copy_of(run, "doll.bin")])
        assert name.value == "~home /dev/null /"
        assert shown() == "1 file attached: doll.bin (10 B)" and "attached doll.bin" in said(form)
        await pilot.press("ctrl+r")  # and off again: the run's copy goes with it
        await until(pilot, lambda: not copy_of(run, "doll.bin").parent.exists())
        assert form.files == [] and shown() == "no file attached" and "removed doll.bin" in said(form)
        assert handout.read_bytes() == b"x" * 10  # the player's own file is never touched
        await pilot.press("escape")

    in_console(tmp_path, body)


def test_a_description_with_paths_in_it_attaches_nothing_and_reaches_the_board_as_given(tmp_path):
    secret = tmp_path / "private" / "id_rsa"
    secret.parent.mkdir()
    secret.write_text("the player's own")
    pasted = f"Can you read {secret} through the viewer?\nThe admin keeps notes in {secret.parent}. Pop a shell: /dev/null"
    typed = f"\n{secret}"  # typed, on a line of its own: text all the same

    async def body(run, app, pilot):
        await pilot.press(*"/new Viewer", "enter")
        await pilot.pause()
        form = app.screen
        box = form.query_one("#new-text")
        await app.on_event(events.Paste(pasted))  # prose: an ordinary paste, into the box
        await pilot.pause()
        box.text = box.text + typed
        await pilot.pause()
        assert box.text == pasted + typed and form.files == []
        assert str(form.query_one("#new-attached").render()) == "no file attached"
        await pilot.press("ctrl+s")
        await until(pilot, lambda: "viewer" in run.deck.challenges)
        assert run.deck.challenges["viewer"].description == pasted + typed
        assert sorted(entry.name for entry in (run.options.board / "viewer").iterdir()) == ["challenge.json"]
        assert "with NO file" in app._status[0]

    in_console(tmp_path, body)


def test_a_refused_challenge_keeps_the_form_open_with_everything_typed_and_says_why(tmp_path):
    handout, other = tmp_path / "a" / "Dockerfile", tmp_path / "b" / "Dockerfile"
    for file in (handout, other):
        file.parent.mkdir()
        file.write_text("FROM scratch")

    async def body(run, app, pilot):
        await pilot.press(*"/new", "enter")
        await pilot.pause()
        form = app.screen
        name, box = form.query_one("#new-name"), form.query_one("#new-text")
        name.value, box.text = "N" * 121, "Open the doll.\nnc chal.example.org 1337"
        form.query_one("#new-category").value = "rev"
        assert form.add_files([handout]) and not form.add_files([other])  # a second file of that name: said at once
        assert form.files == [handout] and "a file named Dockerfile is already attached" in said(form)

        def kept() -> bool:
            return (app.screen is form and box.text == "Open the doll.\nnc chal.example.org 1337" and form.files == [handout]
                    and form.query_one("#new-category").value == "rev" and list(run.options.board.iterdir()) == [])

        await pilot.press("ctrl+s")
        await until(pilot, lambda: "at most 120 characters" in said(form))
        assert kept() and name.value == "N" * 121
        name.value = "Doll"
        handout.unlink()  # the file went away after it was attached
        await pilot.press("ctrl+s")
        await until(pilot, lambda: "no such file" in said(form))
        assert kept() and not run.deck.challenges
        handout.write_text("FROM scratch")
        await pilot.press("ctrl+s")
        await until(pilot, lambda: "doll" in run.deck.challenges)
        await until(pilot, lambda: app.screen is not form)  # added: now the form closes
        assert "added doll: 1 file, 1 address" in app._status[0] and app._status[1] == "information"

    in_console(tmp_path, body, busy_lanes())


def test_points_that_are_not_ascii_digits_are_refused_not_a_crash(tmp_path):
    async def body(run, app, pilot):
        await pilot.press(*"/new Squared", "enter")
        await pilot.pause()
        form = app.screen
        for points in ["²", "①", "٣", "1e3", "-1"]:  # isdigit() is true of the first three; int() cannot read the first two
            form.query_one("#new-points").value = points
            await pilot.press("ctrl+s")
            await pilot.pause()
            assert "points must be a whole number" in said(form) and app.screen is form
        assert not run.deck.challenges and list(run.options.board.iterdir()) == []
        await pilot.press("escape")

    in_console(tmp_path, body)


def test_the_file_window_does_not_hold_the_keys_up_while_it_is_open(tmp_path, monkeypatch):
    import threading

    from ctf_flightdeck import filepick

    handout = tmp_path / "doll.bin"
    handout.write_bytes(b"inside")
    opened, close, closed = threading.Event(), threading.Event(), threading.Event()

    def choose(**kwargs):  # the window: it stays open until the player closes it
        opened.set()
        close.wait(5)
        closed.set()
        return [handout]

    monkeypatch.setattr(filepick, "choose", choose)

    async def body(run, app, pilot):
        try:
            await pilot.press(*"/new", "enter")
            await pilot.pause()
            form = app.screen
            await pilot.press("ctrl+o")
            await until(pilot, opened.is_set)
            await pilot.press(*"Doll")  # the keys go on working: typed while the window is open
            await pilot.pause()
            assert form.query_one("#new-name").value == "Doll" and not closed.is_set()
            assert "the file window is open" in said(form)
            await pilot.press("ctrl+o")
            await pilot.pause()
            assert "already open" in said(form) and not closed.is_set()
            close.set()
            await until(pilot, lambda: form.files == [handout])
            assert "1 file attached: doll.bin" in str(form.query_one("#new-attached").render())
            opened.clear(), close.clear(), closed.clear()
            await pilot.press("ctrl+o")
            await until(pilot, opened.is_set)
            await pilot.press("escape")  # and esc closes the form with the window still open
            await pilot.pause()
            assert app.screen is not form and not closed.is_set()
        finally:
            close.set()

    in_console(tmp_path, body)


def test_the_clipboard_tool_runs_off_the_ui_thread_and_the_keys_go_on(tmp_path):
    import threading

    shot = tmp_path / "clip.png"
    shot.write_bytes(PNG)
    started, go, threads = threading.Event(), threading.Event(), []

    def paster():  # a clipboard tool that is slow to answer
        threads.append(threading.current_thread())
        started.set()
        go.wait(5)
        return shot

    async def body(run, app, pilot):
        app.paster = paster
        try:
            await pilot.press(*"/new", "enter")
            await pilot.pause()
            form = app.screen
            await pilot.press("ctrl+v")
            await until(pilot, started.is_set)
            await pilot.press(*"Shot")
            await pilot.pause()
            assert len(threads) == 1 and threads[0] is not threading.main_thread()
            assert form.query_one("#new-name").value == "Shot" and "reading the clipboard" in said(form)
            assert form.files == []
            go.set()
            await until(pilot, lambda: form.files == [shot])
            assert "pasted the clipboard's image as clip.png" in said(form)
            await pilot.press("escape")
        finally:
            go.set()

    in_console(tmp_path, body)


def test_a_paste_of_nothing_in_the_form_pastes_the_clipboards_image_and_elsewhere_says_where_one_goes(tmp_path):
    """Windows Terminal and Alacritty send an empty paste when their paste key is pressed and
    the clipboard holds no text. ctrl+v is that key in Windows Terminal, so flightdeck never
    sees the key itself: the empty paste is what is left of it."""
    shot = tmp_path / "clip.png"
    shot.write_bytes(PNG)
    calls = []

    def paster():
        calls.append(1)
        return shot

    async def body(run, app, pilot):
        app.paster = paster
        bar = app.screen.query_one("#bar-input")
        await app.on_event(events.Paste(""))  # outside the form: nothing is read, and a line says where an image goes
        await pilot.pause()
        assert calls == [] and bar.value == ""
        assert app._status == ("nothing to paste: the clipboard holds no text. A screenshot on it: /new, then ctrl+v in "
                               "the form; a file: drag it onto this window", "information", app._status[2])
        await pilot.press(*"/new Shot", "enter")
        await pilot.pause()
        form = app.screen
        await app.on_event(events.Paste(""))  # in the form: what ctrl+v does
        await until(pilot, lambda: form.files == [shot])
        assert calls == [1] and form.query_one("#new-text").text == ""
        assert "pasted the clipboard's image as clip.png" in said(form)
        await app.on_event(events.Paste(" "))  # a space is text, not nothing
        await pilot.pause()
        assert calls == [1] and form.query_one("#new-text").text == " "
        await pilot.press("escape")

    in_console(tmp_path, body)


def test_a_paste_of_nothing_is_nothing_on_a_board_that_takes_no_files(tmp_path):
    from ctf_flightdeck.console.app import FlightdeckApp
    from ctf_flightdeck.mock import scenarios
    from ctf_flightdeck.mock.world import FakeWorld

    async def main():
        world = FakeWorld(scenarios.get("sstv"))
        app = FlightdeckApp(world.deck, ticker=world.tick, mock="MOCK · test", refresh_seconds=None)
        async with app.run_test(size=(160, 46)) as pilot:
            await pilot.pause()
            app._status = None
            await app.on_event(events.Paste(""))
            await pilot.pause()
            assert app._status is None and app.screen is app.fleet

    asyncio.run(main())


def test_new_and_attach_copy_in_a_thread_and_say_so_while_the_console_goes_on(tmp_path, monkeypatch):
    import threading

    handout, more = tmp_path / "doll.bin", tmp_path / "more.bin"
    handout.write_bytes(b"inside")
    more.write_bytes(b"more")
    go, threads = threading.Event(), []

    def slow(copy):  # a copy that takes its time, as a disk image's would
        def copying(*args):
            threads.append(threading.current_thread())
            go.wait(5)
            return copy(*args)
        return copying

    monkeypatch.setattr(addchallenge, "create", slow(addchallenge.create))
    monkeypatch.setattr(addchallenge, "attach", slow(addchallenge.attach))

    async def body(run, app, pilot):
        try:
            await pilot.press(*"/new Doll", "enter")
            await pilot.pause()
            form = app.screen
            form.add_files([handout])
            await pilot.press("ctrl+s")
            await until(pilot, lambda: len(threads) == 1)
            assert app.screen is form and "adding it: copying 1 file..." in said(form)  # open, and saying so
            await pilot.press("ctrl+s")
            await pilot.pause()
            assert "still adding it" in said(form) and len(threads) == 1  # not added twice
            await pilot.press("escape")  # the keys work: the form closes, the copy goes on
            await pilot.pause()
            assert app.screen is not form and "still adding the challenge" in app._status[0]
            assert not run.deck.challenges and threads[0] is not threading.main_thread()
            go.set()
            await until(pilot, lambda: "added doll: 1 file" in app._status[0])
            assert (run.options.board / "doll" / "doll.bin").read_bytes() == b"inside"
            # the simple layout (a run's default) opens the run's first lane: wait until its chat box has the
            # focus. Not until anything has it: as the view opens the focus is on its transcript for a moment,
            # and a `/` pressed then is lost if the focus moves on before the key has reached the view (the
            # rest of the command then went to the lane as a message, and nothing was attached)
            await until(pilot, lambda: type(app.screen).__name__ == "FocusScreen" and getattr(app.focused, "id", None) == "bar-input")
            go.clear()
            await command(pilot, f"/attach doll {more}")
            await until(pilot, lambda: len(threads) == 2)
            assert app._status[0] == "copying 1 file into doll..." and threads[1] is not threading.main_thread()
            await pilot.press(*"/sort")  # the command bar takes keys meanwhile
            await pilot.pause()
            assert app.screen.query_one("#bar-input").value == "/sort"
            go.set()
            await until(pilot, lambda: "attached more.bin to doll" in app._status[0])
            assert (run.options.board / "doll" / "more.bin").read_bytes() == b"more"
        finally:
            go.set()

    in_console(tmp_path, body, busy_lanes())


def test_a_challenge_added_with_nothing_says_so_and_its_lane_is_told_to_stop_not_wait(tmp_path):
    from fake_model import text_reply

    server = FakeModelServer([text_reply("A sample file is missing.")] * 3)

    async def main():
        with server:
            run = prepare_run(options(tmp_path, server))
            run.release()
            ok, told = await run.add_challenge(NewChallenge(name="Matryoshka", description="Open the doll."))
            assert ok and "with NO file and no target" in told and "/attach matryoshka" in told
            for _ in range(500):
                if server.chats():
                    break
                await asyncio.sleep(0.01)
            brief = server.chats()[0]["json"]["messages"][1]["content"]
            assert "came with no files and no live instance" in brief and "do not wait" in brief
            await run.shutdown()
            run.close()

    asyncio.run(main())


def test_attach_puts_a_file_in_the_challenge_and_restarts_its_lane_with_it(tmp_path):
    """Typed in the lane's own view: the lane restarts with the file, the status line names the
    fresh lane, the view is on it, and the ended lane's result says what it restarted with."""
    from fake_model import text_reply

    handout = tmp_path / "doll.bin"
    handout.write_bytes(b"inside")
    server = FakeModelServer(responder=lambda request: tool_call_reply("shell", {"command": "sleep 0.2"}))

    async def main():
        with server:
            run = prepare_run(options(tmp_path, server))
            app = run.app(refresh_seconds=None)
            async with app.run_test(size=(160, 46)) as pilot:
                await pilot.pause()
                await run.add_challenge(NewChallenge(name="Matryoshka", description="Open the doll."))
                for _ in range(500):
                    if run.deck.lanes:
                        break
                    await pilot.pause(0.01)
                (first,) = run.deck.lanes
                app.open_lane(first)
                await until(pilot, lambda: type(app.screen).__name__ == "FocusScreen" and getattr(app.focused, "id", None) == "bar-input")
                await command(pilot, f"/attach {handout}")  # no challenge named: the open lane's
                for _ in range(500):
                    if len(run.deck.lanes) == 2 and "attached" in app._status[0]:
                        break
                    await pilot.pause(0.01)
                second = [lane for lane in run.deck.lanes.values() if lane.id != first][0]
                assert app._status[0] == f"attached doll.bin to matryoshka; {first} restarted as {second.id}"
                assert (run.options.board / "matryoshka" / "doll.bin").read_bytes() == b"inside"
                assert run.deck.lanes[first].result == "to restart with doll.bin; re-queued fresh"
                await pilot.pause()
                assert type(app.screen).__name__ == "FocusScreen" and app.screen.lane_id == second.id  # the view went with it
                for _ in range(500):
                    if second.id in run.driver.runs and run.driver.runs[second.id].messages:
                        break
                    await pilot.pause(0.01)
                assert "doll.bin" in run.driver.runs[second.id].messages[1]["content"]
            await run.shutdown()
            run.close()

    asyncio.run(main())


def test_attach_names_the_fresh_lane_of_each_lane_it_restarts_and_says_when_none_has_started_yet(tmp_path):
    from ctf_flightdeck.core import interventions as iv

    files = [tmp_path / name for name in ("one.bin", "two.bin", "three.bin", "four.bin", "five.bin", "six.bin")]
    for file in files:
        file.write_bytes(b"x")

    async def main():
        with busy_lanes() as server:
            run = prepare_run(options(tmp_path, server))
            run.release()
            await run.add_challenge(NewChallenge(name="Doll", description="d"))
            for _ in range(500):
                if run.deck.lanes:
                    break
                await asyncio.sleep(0.01)
            deck = run.deck
            assert await run.attach_files("doll", files[:1]) == (True, "attached one.bin to doll; L01 restarted as L02")
            assert deck.apply(iv.Fork("L02", approach="the other way")).ok and [lane.id for lane in deck.lanes_on("doll")] == ["L02", "L03"]
            assert await run.attach_files("doll", files[1:2]) == (True, "attached two.bin to doll; L02, L03 restarted as L04, L05")
            assert [lane.id for lane in deck.lanes_on("doll")] == ["L04", "L05"]
            deck.hold_queue("the model API refuses the key")  # no lane starts: the fresh lanes wait in the queue
            ok, told = await run.attach_files("doll", files[2:])
            assert ok and told == ("attached three.bin, four.bin, five.bin, six.bin to doll; "
                                   "L04, L05 ended, a fresh lane starts when one is free")
            assert len(deck.lanes) == 5 and deck.queued("doll")
            results = {lane.id: lane.result for lane in deck.lanes.values()}
            await run.shutdown()
            run.close()
            assert results == {
                "L01": "to restart with one.bin; re-queued fresh",
                "L02": "to restart with two.bin; re-queued fresh",
                "L03": "to restart with two.bin; re-queued fresh",
                "L04": "to restart with three.bin, four.bin, five.bin and 1 more; re-queued fresh",  # the first three of many
                "L05": "to restart with three.bin, four.bin, five.bin and 1 more; re-queued fresh",
            }

    asyncio.run(main())


def test_attach_says_so_when_only_some_fresh_lanes_started_and_when_none_could(tmp_path):
    from ctf_flightdeck.core import interventions as iv

    files = [tmp_path / name for name in ("one.bin", "two.bin")]
    for file in files:
        file.write_bytes(b"x")

    async def main():
        with busy_lanes() as server:
            run = prepare_run(options(tmp_path, server))
            run.release()
            await run.add_challenge(NewChallenge(name="Doll", description="d"))
            for _ in range(500):
                if run.deck.lanes:
                    break
                await asyncio.sleep(0.01)
            deck = run.deck
            assert deck.apply(iv.Fork("L01", approach="the other way")).ok and len(deck.lanes_on("doll")) == 2
            apply = deck.apply

            def held_after_the_first(what, **kw):  # the queue is held once the first lane has restarted
                outcome = apply(what, **kw)
                deck.hold_queue("the model API refuses the key")
                return outcome

            deck.apply = held_after_the_first
            ok, told = await run.attach_files("doll", files[:1])
            deck.apply = apply
            assert ok and told == "attached one.bin to doll; L01, L02 restarted as L03, and 1 more starts when a lane is free"
            assert [lane.id for lane in deck.lanes_on("doll")] == ["L03"] and deck.queued("doll")
            assert deck.release_hold().ok and [lane.id for lane in deck.lanes_on("doll")] == ["L03", "L04"]
            assert deck.apply(iv.Kill("L04", requeue=False)).ok  # one lane left, and the next one cannot start

            def no_room(lane, challenge):
                raise RuntimeError("no room for a workspace")

            start, run.driver.start = run.driver.start, no_room
            ok, told = await run.attach_files("doll", files[1:])
            run.driver.start = start
            await run.shutdown()
            run.close()
            assert ok and told == ("attached two.bin to doll; no fresh lane started: "
                                   "Killed L03; a fresh lane could not start on Doll: no room for a workspace")
            assert not deck.lanes_on("doll") and not deck.queued("doll") and "a lane starts" not in told

    asyncio.run(main())


# ---------------------------------------------------------------------- a drop anywhere, and the file window


def test_attach_refuses_two_sources_of_one_name_and_never_copies_over_a_file(tmp_path):
    import os

    folder = tmp_path / "board" / "crab"
    folder.mkdir(parents=True)
    one, two, tree_a, tree_b = tmp_path / "a" / "data.bin", tmp_path / "b" / "data.bin", tmp_path / "a" / "src", tmp_path / "b" / "src"
    for file, text in ((one, "from a"), (two, "from b")):
        file.parent.mkdir()
        file.write_text(text)
    for tree in (tree_a, tree_b):
        tree.mkdir()
        (tree / "main.c").write_text(tree.parent.name)
    for pair in ([one, two], [tree_a, tree_b]):
        with pytest.raises(AddError, match="two files named"):
            addchallenge.attach(folder, pair)
        assert list(folder.iterdir()) == []  # refused before anything was copied
    assert addchallenge.attach(folder, [one, tree_a]) == ["data.bin", "src"]
    with pytest.raises(AddError, match="already has a file of that name"):
        addchallenge.attach(folder, [two])
    assert (folder / "data.bin").read_text() == "from a" and (folder / "src" / "main.c").read_text() == "a"
    piped, good = tmp_path / "piped", tmp_path / "good.txt"
    piped.mkdir()
    good.write_text("good")
    os.mkfifo(piped / "pipe")
    with pytest.raises(AddError, match="named pipe"):
        addchallenge.attach(folder, [good, piped])  # the second fails while it is copied
    assert sorted(entry.name for entry in folder.iterdir()) == ["data.bin", "src"]  # the first went out again: a retry is clean
    with pytest.raises(AddError, match="is a device"):
        addchallenge.attach(folder, [Path("/dev/null")])


def test_attachs_argument_is_a_challenge_then_files_and_a_file_that_is_not_there_is_said(tmp_path):
    one, two = tmp_path / "a b.bin", tmp_path / "c.txt"
    one.write_bytes(b"1")
    two.write_text("2")
    assert addchallenge.attach_arg("") == ("", []) and addchallenge.attach_arg("Crab Walk") == ("Crab Walk", [])
    assert addchallenge.attach_arg(f"Crab Walk '{one}' {two}") == ("Crab Walk", [one, two])
    assert addchallenge.attach_arg(f"{addchallenge.quote(one)} {addchallenge.quote(two)} ") == ("", [one, two])
    assert addchallenge.attach_arg(f"crab {one}") == ("crab", [one])  # one path, its spaces as they are
    with pytest.raises(AddError, match="/no/such/doll.bin: no such file"):
        addchallenge.attach_arg(f"crab {two} /no/such/doll.bin")


def test_attach_to_a_challenge_no_lane_can_start_on_says_so_instead_of_promising_one(tmp_path):
    from ctf_flightdeck.core import interventions as iv

    more, last = tmp_path / "more.bin", tmp_path / "last.bin"
    more.write_bytes(b"more")
    last.write_bytes(b"last")

    async def main():
        with busy_lanes() as server:
            run = prepare_run(options(tmp_path, server))
            run.release()
            await run.add_challenge(NewChallenge(name="Done", description="d"))
            for _ in range(500):
                if run.deck.lanes:
                    break
                await asyncio.sleep(0.01)
            apply = run.deck.apply
            run.deck.apply = lambda what, **kw: iv.Outcome(False, "not now") if isinstance(what, iv.Kill) else apply(what, **kw)
            ok, told = await run.attach_files("done", [more])  # the deck would not restart its lane: said, not "restarted"
            assert ok and told == "attached more.bin to done; its lane was not restarted: not now" and len(run.deck.lanes) == 1
            run.deck.apply = apply
            run.deck.platform_solved("done", "you")  # solved meanwhile: its lane stops, and none may start
            ok, told = await run.attach_files("done", [last])
            await run.shutdown()
            run.close()
            assert ok and (run.options.board / "done" / "last.bin").read_bytes() == b"last"
            assert told.startswith("attached last.bin to done; no lane was started on it: Done is already solved")
            assert "a lane starts" not in told and len(run.deck.lanes) == 1

    asyncio.run(main())


def test_a_pasted_path_never_replaces_what_was_typed_in_the_command_bar(tmp_path, monkeypatch):
    handout, home = tmp_path / "rockyou.txt", tmp_path / "home"
    handout.write_text("words")
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))

    async def body(run, app, pilot):
        bar = app.screen.query_one("#bar-input")
        await pilot.press(*"/hint L01 look at the header of ")
        await app.on_event(events.Paste(str(handout)))  # an existing path, meant as text
        await pilot.pause()
        assert bar.value == f"/hint L01 look at the header of {handout}"  # an ordinary paste, where the cursor is
        bar.value = "a half-written message"
        app.screen.set_focus(None)  # a drop while the bar holds text and something else has the focus
        await app.on_event(events.Paste(str(handout)))
        await pilot.pause()
        assert bar.value == "a half-written message"
        assert "1 file not taken: the command bar holds what you typed" in app._status[0] and app._status[1] == "warning"
        assert not (run.dir / "dropped").exists()  # and a drop that is not taken is not copied either
        bar.value = "/attach doll "  # an /attach being written: the file is added to it
        await app.on_event(events.Paste(str(handout)))
        await on_bar(pilot, f"/attach doll '{copy_of(run, 'rockyou.txt')}' ")
        assert bar.has_focus
        bar.value = "/att"  # the start of that very command: nothing is lost by finishing it
        await app.on_event(events.Paste(str(handout)))
        await on_bar(pilot, f"/attach '{copy_of(run, 'rockyou.txt', 2)}' ")
        bar.value = "/hint L01 "
        await app.on_event(events.Paste("~"))  # the home folder is never an attachment: said, and pasted as the text it is
        await pilot.pause()
        assert bar.value == "/hint L01 ~" and "is your home folder itself" in app._status[0]

    in_console(tmp_path, body)


def test_a_drop_in_the_fleet_names_the_challenge_enter_attaches_to(tmp_path):
    handout = tmp_path / "doll.bin"
    handout.write_bytes(b"x")
    calls = []

    async def attacher(cid, files):
        calls.append((cid, files))
        return True, f"attached to {cid}"

    async def body(run, app, pilot):
        await run.add_challenge(NewChallenge(name="Static Hiss", description="d"))
        await until(pilot, lambda: app.fleet.selected_lane in run.deck.lanes)
        app.attacher = attacher
        await app.on_event(events.Paste(f"{handout} "))  # the lanes table has the focus, and a lane is selected
        await on_bar(pilot, f"/attach static-hiss '{copy_of(run, 'doll.bin')}' ")  # the bar says where Enter sends it
        bar = app.screen.query_one("#bar-input")
        assert bar.has_focus
        assert app._status[0].startswith("got doll.bin (1 B): press Enter to attach to static-hiss")  # the drop landed: said
        await pilot.press("enter")
        await until(pilot, lambda: calls)
        assert calls == [("static-hiss", [copy_of(run, "doll.bin")])]
        await until(pilot, lambda: app._status[0] == "attached to static-hiss")
        app.open_lane(app.fleet.selected_lane)  # the same in a lane's own view
        await pilot.pause()
        await app.on_event(events.Paste(f"{handout} "))
        await on_bar(pilot, f"/attach static-hiss '{copy_of(run, 'doll.bin', 2)}' ")

    in_console(tmp_path, body, busy_lanes())


def test_files_dropped_on_the_console_go_to_the_new_form_or_onto_an_attach_whatever_has_the_focus(tmp_path):
    handout = tmp_path / "my doll.bin"
    handout.write_bytes(b"x")
    dropped = str(handout).replace(" ", "\\ ") + " "  # as a terminal pastes a dropped file

    async def main():
        with FakeModelServer(responder=lambda request: tool_call_reply("shell", {"command": "sleep 0.2"})) as server:
            run = prepare_run(options(tmp_path, server))
            app = run.app(refresh_seconds=None)
            async with app.run_test(size=(160, 46)) as pilot:
                await pilot.pause()
                await app.on_event(events.Paste(dropped))  # the fleet: the board has the focus, not the bar
                await on_bar(pilot, f"/attach '{copy_of(run, 'my doll.bin')}' ")
                bar = app.screen.query_one("#bar-input")
                assert bar.has_focus
                assert app._status[0] == "got my doll.bin (1 B): type the challenge's name after /attach, then Enter"
                bar.value = ""
                await app.on_event(events.Paste("just some words"))  # not files: an ordinary paste
                await pilot.pause()
                assert bar.value == "just some words"
                bar.value = ""
                await pilot.press(*"/new Doll", "enter")
                await pilot.pause()
                app.screen.query_one("#new-category").focus()  # the focus is not on the box
                form = app.screen
                await app.on_event(events.Paste(dropped))
                await until(pilot, lambda: form.files == [copy_of(run, "my doll.bin", 2)])
                assert app.screen.query_one("#new-category").value == ""
                assert app.screen.query_one("#new-text").text == ""  # attached, not written into the description
                assert "1 file attached: my doll.bin" in str(app.screen.query_one("#new-attached").render())
                assert said(app.screen).startswith("attached my doll.bin (1 B)")  # the drop landed: the form says so
                await pilot.press("escape")
            await run.shutdown()
            run.close()

    asyncio.run(main())


def test_a_dropped_file_that_is_not_there_is_said_with_the_reason_and_pasted_as_the_text_it_is(tmp_path, monkeypatch):
    gone = tmp_path / "TemporaryItems" / "my shot.png"  # as a screenshot's thumbnail: gone when the paste arrives
    text = str(gone).replace(" ", "\\ ") + " "
    why = "my shot.png. A dropped file may have been a temporary one, gone by now: drag the saved file, or "

    async def body(run, app, pilot):
        bar = app.screen.query_one("#bar-input")
        await app.on_event(events.Paste(text))  # the lanes table has the focus: a paste has nowhere to go
        await pilot.pause()
        assert bar.value == "" and app._status[1] == "warning"
        assert app._status[0].startswith("no such file: ...") and app._status[0].endswith(why + "type /attach with no file to choose it")
        app._status = None
        await pilot.press("slash")
        await app.on_event(events.Paste(text))  # in the command bar: the same line, and the text where the cursor is
        await pilot.pause()
        assert bar.value == "/" + text and app._status[0].endswith(why + "type /attach with no file to choose it")
        bar.value, app._status = "", None
        for words in ("hint L01 look at /etc/passwd", f"hint L01 open {gone}", "help"):  # text, and a command: nothing is said
            await app.on_event(events.Paste(words))
            await pilot.pause()
            assert bar.value == words and app._status is None
            bar.value = ""
        await pilot.press(*"/new Shot", "enter")
        await pilot.pause()
        form = app.screen
        box = form.query_one("#new-text")
        await app.on_event(events.Paste(text))  # in the form: said on the form's own line, with the form's key
        await pilot.pause()
        assert box.text == text and form.files == []
        assert said(form).startswith("no such file: ...") and said(form).endswith(why + "press ctrl+o to choose it")
        monkeypatch.setenv("SSH_CONNECTION", "192.0.2.1 50000 192.0.2.2 22")
        await app.on_event(events.Paste(text))
        await pilot.pause()
        assert "Over SSH a dropped file stays on the machine your terminal runs on" in said(form)
        await pilot.press("escape")

    in_console(tmp_path, body)


def test_a_board_that_takes_no_files_says_nothing_about_a_path_that_is_not_there(tmp_path):
    from ctf_flightdeck.console.app import FlightdeckApp
    from ctf_flightdeck.mock import scenarios
    from ctf_flightdeck.mock.world import FakeWorld

    async def main():
        world = FakeWorld(scenarios.get("sstv"))
        app = FlightdeckApp(world.deck, ticker=world.tick, mock="MOCK · test", refresh_seconds=None)
        async with app.run_test(size=(160, 46)) as pilot:
            await pilot.pause()
            app._status = None
            await pilot.press("slash")
            await app.on_event(events.Paste(f"{tmp_path}/gone/shot.png "))
            await pilot.pause()
            assert app.screen.query_one("#bar-input").value == f"/{tmp_path}/gone/shot.png " and app._status is None

    asyncio.run(main())


def test_a_file_that_is_gone_after_it_was_dropped_is_still_added_and_still_attached(tmp_path):
    """The file behind a drop may be a temporary one: the console copies it when the drop
    lands, not when the player presses the key that attaches it."""
    shot, more = tmp_path / "TemporaryItems" / "shot.bin", tmp_path / "TemporaryItems" / "more.bin"
    shot.parent.mkdir()
    shot.write_bytes(b"what the thumbnail showed")
    more.write_bytes(b"more of it")

    async def body(run, app, pilot):
        await pilot.press(*"/new Doll", "enter")
        await pilot.pause()
        form = app.screen
        await app.on_event(events.Paste(f"{shot} "))
        await until(pilot, lambda: form.files == [copy_of(run, "shot.bin")])
        assert said(form).startswith("attached shot.bin (25 B)")
        await app.on_event(events.Paste(f"{shot} "))  # dropped again: the same file, said, and not copied twice
        await pilot.pause()
        assert said(form) == "already attached" and form.files == [copy_of(run, "shot.bin")] and not form.copying
        assert sorted(entry.name for entry in (run.dir / "dropped").iterdir()) == ["1"]
        shot.unlink()  # gone before ctrl+s
        await pilot.press("ctrl+s")
        await until(pilot, lambda: "doll" in run.deck.challenges)
        assert (run.options.board / "doll" / "shot.bin").read_bytes() == b"what the thumbnail showed"
        await until(pilot, lambda: not copy_of(run, "shot.bin").parent.exists())  # on the board: the run's copy is not kept
        await until(pilot, lambda: app.screen.query("#bar-input") and app.focused is not None)
        app.screen.set_focus(None)
        await app.on_event(events.Paste(f"{more} "))  # the same outside the form: onto an /attach, as a copy
        await on_bar(pilot, f"/attach doll '{copy_of(run, 'more.bin')}' ")
        more.unlink()  # gone before Enter
        await pilot.press("enter")
        await until(pilot, lambda: "attached more.bin to doll" in app._status[0])
        assert (run.options.board / "doll" / "more.bin").read_bytes() == b"more of it"
        await until(pilot, lambda: not copy_of(run, "more.bin").parent.exists())

    in_console(tmp_path, body, busy_lanes())


def test_a_drop_attaches_when_the_run_folder_was_given_as_a_relative_path(tmp_path, monkeypatch):
    """`flightdeck run --run-dir runs`: the command bar reads only a full path as a file, so
    the copy a drop puts on it is named by its full path whatever the run folder was given as."""
    monkeypatch.chdir(tmp_path)
    shot, more = tmp_path / "shot.bin", tmp_path / "more.bin"
    shot.write_bytes(b"in the form")
    more.write_bytes(b"on the bar")

    async def body(run, app, pilot):
        assert not run.dir.is_absolute() and run.dir.parent == Path("relruns")
        kept = tmp_path / run.dir / "dropped"  # where the copies are, by its full path
        await pilot.press(*"/new Doll", "enter")
        await pilot.pause()
        form = app.screen
        await app.on_event(events.Paste(f"{shot} "))
        await until(pilot, lambda: form.files == [kept / "1" / "shot.bin"])
        await pilot.press("ctrl+s")
        await until(pilot, lambda: "doll" in run.deck.challenges)
        assert (run.options.board / "doll" / "shot.bin").read_bytes() == b"in the form"
        await until(pilot, lambda: not (kept / "1").exists())  # on the board: the run's copy is not kept
        await until(pilot, lambda: app.screen.query("#bar-input") and app.focused is not None)
        app.screen.set_focus(None)
        await app.on_event(events.Paste(f"{more} "))
        await on_bar(pilot, f"/attach doll '{kept / '1' / 'more.bin'}' ")
        await pilot.press("enter")
        await until(pilot, lambda: "attached more.bin to doll" in app._status[0])
        assert (run.options.board / "doll" / "more.bin").read_bytes() == b"on the bar"
        await until(pilot, lambda: not (kept / "1").exists())

    in_console(tmp_path, body, busy_lanes(), run_dir=Path("relruns"))
    assert len(list(tmp_path.glob("relruns/*"))) == 1 and list(tmp_path.glob("relruns/*/dropped")) == []  # gone with the run


def test_three_files_that_arrive_as_three_pastes_are_one_attach_in_the_order_they_came(tmp_path):
    """Alacritty sends each dropped file as a paste of its own, one straight after the other."""
    files = [tmp_path / name for name in ("a.bin", "b.bin", "c.bin")]
    for file in files:
        file.write_bytes(b"x")

    async def body(run, app, pilot):
        for file in files:
            await app.on_event(events.Paste(f"{file} "))  # the next before the first one's copy is made
        await on_bar(pilot, "/attach " + " ".join(f"'{copy_of(run, file.name, n)}'" for n, file in enumerate(files, 1)) + " ")
        assert app._status[0] == "got c.bin (1 B): added to the /attach in the command bar, Enter attaches"
        app.screen.query_one("#bar-input").value = ""
        await pilot.press(*"/new Three", "enter")
        await pilot.pause()
        form = app.screen
        for file in files:
            await app.on_event(events.Paste(f"{file} "))
        await until(pilot, lambda: form.files == [copy_of(run, file.name, n) for n, file in enumerate(files, 4)])
        assert str(form.query_one("#new-attached").render()) == "3 files attached: a.bin (1 B), b.bin (1 B), c.bin (1 B)"
        await pilot.press("escape")

    in_console(tmp_path, body)


def test_what_the_player_is_told_does_not_wait_for_a_drops_copy_to_be_removed(tmp_path, monkeypatch):
    import threading

    handout = tmp_path / "disk.img"
    handout.write_bytes(b"big")
    go, started, unstage = threading.Event(), threading.Event(), addchallenge.unstage

    def slow(folder, files):  # removing a big folder takes its time
        started.set()
        go.wait(5)
        unstage(folder, files)

    monkeypatch.setattr(addchallenge, "unstage", slow)

    async def body(run, app, pilot):
        try:
            await pilot.press(*"/new Disk", "enter")
            await pilot.pause()
            form = app.screen
            await app.on_event(events.Paste(f"{handout} "))
            await until(pilot, lambda: form.files == [copy_of(run, "disk.img")])
            await pilot.press("ctrl+s")
            await until(pilot, lambda: app._status is not None and "added disk: 1 file" in app._status[0])  # said, and the form closed
            await until(pilot, started.is_set)
            assert app.screen is not form and copy_of(run, "disk.img").is_file()  # while the copy is still there
            go.set()
            await until(pilot, lambda: not copy_of(run, "disk.img").parent.exists())
        finally:
            go.set()

    in_console(tmp_path, body, busy_lanes())


def test_a_drop_is_copied_off_the_ui_thread_and_ctrl_s_waits_for_it(tmp_path):
    import threading

    handout = tmp_path / "disk.img"
    handout.write_bytes(b"big")
    go, threads = threading.Event(), []

    async def body(run, app, pilot):
        stage = app.stager

        def slow(files):  # a copy that takes its time, as a disk image's would
            threads.append(threading.current_thread())
            go.wait(5)
            return stage(files)

        app.stager = slow
        try:
            await pilot.press(*"/new Disk", "enter")
            await pilot.pause()
            form = app.screen
            await app.on_event(events.Paste(f"{handout} "))
            await until(pilot, lambda: len(threads) == 1)
            assert threads[0] is not threading.main_thread() and form.files == []
            assert said(form) == "copying disk.img (3 B)..."
            await pilot.press(*"ok")  # the keys go on: typed into the box while the copy is made
            await pilot.pause()
            assert form.query_one("#new-text").text == "ok"
            await pilot.press("ctrl+s")  # not added without the file that is on its way
            await pilot.pause()
            assert "still copying the files you dropped" in said(form) and not form.adding and not run.deck.challenges
            go.set()
            await until(pilot, lambda: form.files == [copy_of(run, "disk.img")])
            assert said(form).startswith("attached disk.img (3 B)")
            go.clear()
            await pilot.press("escape")  # cancelled: nothing will attach the copy now, so it goes
            await until(pilot, lambda: not copy_of(run, "disk.img").parent.exists())
            await pilot.press(*"/new Disk", "enter")
            await pilot.pause()
            form = app.screen
            await app.on_event(events.Paste(f"{handout} "))
            await until(pilot, lambda: len(threads) == 2)
            await pilot.press("escape")  # closed while the copy is made: the copy is removed once it is there
            await pilot.pause()
            assert app.screen is app.fleet
            go.set()
            await until(pilot, lambda: (run.dir / "dropped").is_dir() and list((run.dir / "dropped").iterdir()) == [])
            assert handout.read_bytes() == b"big"
        finally:
            go.set()

    in_console(tmp_path, body)


def test_what_is_typed_while_a_drop_is_copied_is_never_replaced_and_a_copy_that_fails_is_said(tmp_path):
    import threading

    handout = tmp_path / "doll.bin"
    handout.write_bytes(b"x")
    go, calls = threading.Event(), []

    async def body(run, app, pilot):
        stage = app.stager

        def slow(files):
            calls.append(files)
            go.wait(5)
            return stage(files)

        def failing(files):
            raise AddError(f"cannot copy {files[0]}: No space left on device")

        app.stager = slow
        try:
            bar = app.screen.query_one("#bar-input")
            await app.on_event(events.Paste(f"{handout} "))
            await until(pilot, lambda: len(calls) == 1)
            assert bar.value == "" and app._status[0] == "copying doll.bin (1 B)..."
            await pilot.press(*"/hint L01 wait")  # typed while the copy is made
            go.set()
            await until(pilot, lambda: "1 file not taken: the command bar holds what you typed" in app._status[0])
            assert bar.value == "/hint L01 wait" and app._status[1] == "warning"
            await until(pilot, lambda: list((run.dir / "dropped").iterdir()) == [])  # and the copy is not kept
            bar.value = ""
            app.stager = failing
            await app.on_event(events.Paste(f"{handout} "))
            await until(pilot, lambda: app._status[0] == f"not attached: cannot copy {handout}: No space left on device")
            assert bar.value == "" and app._status[1] == "warning"
            await pilot.press(*"/new Doll", "enter")
            await pilot.pause()
            form = app.screen
            await app.on_event(events.Paste(f"{handout} "))
            await until(pilot, lambda: said(form) == f"not attached: cannot copy {handout}: No space left on device")
            assert form.files == [] and not form.copying
            await pilot.press("escape")
        finally:
            go.set()

    in_console(tmp_path, body)


def test_copies_of_dropped_files_that_were_never_attached_go_when_the_run_closes(tmp_path):
    handout = tmp_path / "doll.bin"
    handout.write_bytes(b"x")

    async def main():
        with FakeModelServer([]) as model:
            run = prepare_run(options(tmp_path, model))
            app = run.app(refresh_seconds=None)
            async with app.run_test(size=(160, 46)) as pilot:
                await pilot.pause()
                await app.on_event(events.Paste(f"{handout} "))  # onto an /attach that is never sent
                await on_bar(pilot, f"/attach '{copy_of(run, 'doll.bin')}' ")
            await run.shutdown()
            assert copy_of(run, "doll.bin").is_file()
            (run.dir / "pasted").mkdir()  # a pasted screenshot's folder is not a drop's: it stays
            run.close()
            assert not (run.dir / "dropped").exists() and (run.dir / "pasted").is_dir() and handout.is_file()

    asyncio.run(main())


# ---------------------------------------------------------------------- a drop that arrives as typed keys


GAP = 0.25  # seconds: the burst gap these tests run with, so a slow machine cannot split a burst or join two keys


def key_drops(app, monkeypatch) -> None:
    """Watch typed keys for a dropped path, as with a real terminal (off under a script, where every key comes at once)."""
    from ctf_flightdeck.console import app as console_app

    monkeypatch.setattr(console_app, "BURST_GAP", GAP)
    app.key_drops = True


async def burst(pilot, text: str, enter: bool = False) -> None:
    """`text` as a terminal with no bracketed paste sends a dropped file: typed, all at once. `enter`: and Enter with it."""
    from textual.keys import _character_to_key

    await pilot.pause(GAP * 1.5)  # a drop comes after a pause: nobody types while they drag
    for character in text:  # every key is in the queue before the first is read, as when a terminal writes them at once
        pilot.app.post_message(events.Key(_character_to_key(character), character))
    if enter:
        pilot.app.post_message(events.Key("enter", "\r"))
    await pilot.pause(GAP * 2)
    # a burst that is no drop is typed a key at a time, each once the last has acted: on a busy machine that outlasts any fixed wait
    app = pilot.app
    await until(pilot, lambda: not app._burst and not app._to_type and app._typing is None)
    await pilot.pause()


def escaped(path) -> str:
    return str(path).replace(" ", "\\ ") + " "  # as Terminal.app writes a dropped file's path


def test_a_path_typed_all_at_once_into_any_field_of_the_form_is_a_dropped_file(tmp_path, monkeypatch):
    handout, second = tmp_path / "my doll.bin", tmp_path / "notes.txt"
    handout.write_bytes(b"x" * 10)
    second.write_text("abc")

    async def body(run, app, pilot):
        key_drops(app, monkeypatch)
        await pilot.press(*"/new", "enter")
        await pilot.pause(GAP * 2)
        form = app.screen
        fields = {name: form.query_one(name) for name in ("#new-name", "#new-text", "#new-category", "#new-points")}
        value = lambda field: field.text if hasattr(field, "text") else field.value  # noqa: E731
        ways = [escaped(handout), f"'{handout}'", f'"{handout}"', f"{escaped(handout)}{second} "]
        for (name, field), dropped in zip(fields.items(), ways, strict=True):
            field.focus()
            await pilot.pause()
            await burst(pilot, dropped)
            await until(pilot, lambda: form.files and not form.copying)
            assert value(field) == "", (name, value(field))  # not one character of it was typed into the field
            assert form.files[0].name == "my doll.bin" and form.files[0].parent.parent == run.dir / "dropped", name
            assert said(form).startswith("attached "), (name, said(form))
            form.files.clear()
        assert said(form).startswith("attached my doll.bin (10 B), notes.txt (3 B)")  # the last one: two files
        await pilot.press("escape")

    in_console(tmp_path, body)


def test_typing_is_never_a_drop_and_a_burst_that_is_not_only_files_is_typed_as_it_came(tmp_path, monkeypatch):
    handout = tmp_path / "doll.bin"
    handout.write_bytes(b"x")

    async def body(run, app, pilot):
        key_drops(app, monkeypatch)
        await burst(pilot, "/new Doll")  # a burst, and no path: the keys it was, in order
        bar = app.screen.query_one("#bar-input")
        assert bar.value == "/new Doll"
        await pilot.press("enter")  # a key that is not text
        await pilot.pause()
        form = app.screen
        box = form.query_one("#new-text")
        assert box.has_focus
        for key in "/tmp":  # typed: a path that exists, a key at a time
            await pilot.press(key)
            await pilot.pause(GAP * 1.5)
        await pilot.pause()
        assert box.text == "/tmp" and form.files == []
        box.text = ""
        await burst(pilot, f"see {handout} ")  # all at once, but it does not start as a path does: never held
        assert box.text == f"see {handout} " and form.files == []
        box.text = ""
        await burst(pilot, f"{handout} is the file")  # all at once and starts with a path, but is not only paths
        assert box.text == f"{handout} is the file" and form.files == []
        box.text = ""
        assert said(form) == ""
        await burst(pilot, f"{handout}.gone ")  # no such file: the text it is, and the form says what it looks like
        assert box.text == f"{handout}.gone " and form.files == []
        assert said(form).startswith("no such file: ") and said(form).endswith("or press ctrl+o to choose it")
        box.text = ""
        form.problem("")
        await burst(pilot, str(handout), enter=True)  # Enter straight after it: typed, and the line end with it
        assert box.text == f"{handout}\n" and form.files == []
        box.text = ""
        await burst(pilot, "/")  # the root folder exists, and one key is never a drop
        assert box.text == "/" and form.files == [] and said(form) == ""
        await pilot.press("escape")

    in_console(tmp_path, body)


def test_a_path_typed_all_at_once_in_the_fleet_goes_onto_an_attach_and_none_of_its_keys_acts(tmp_path, monkeypatch):
    handout = tmp_path / "park kill quit.bin"  # every letter of it is a key of the fleet
    handout.write_bytes(b"x" * 2048)

    async def body(run, app, pilot):
        key_drops(app, monkeypatch)
        await run.add_challenge(NewChallenge(name="Static Hiss", description="d"))
        await until(pilot, lambda: app.fleet.selected_lane in run.deck.lanes)
        lane = run.deck.lanes[app.fleet.selected_lane]
        assert not app.screen.query_one("#bar-input").has_focus  # the lanes table has the focus: letters are its keys
        await burst(pilot, escaped(handout))
        await on_bar(pilot, f"/attach static-hiss '{copy_of(run, 'park kill quit.bin')}' ")
        bar = app.screen.query_one("#bar-input")
        assert app.screen is app.fleet and not lane.finished and lane.state is not LaneState.PAUSED  # no key of it acted
        assert bar.has_focus
        assert app._status[0].startswith("got park kill quit.bin (2.0 KB): press Enter to attach to static-hiss")
        bar.value = "a half-written message"  # the bar has the focus and holds text: the path is text there, as a paste is
        bar.cursor_position = len(bar.value)
        await burst(pilot, f"'{handout}'")
        assert bar.value == f"a half-written message'{handout}'"
        bar.value = "a half-written message"
        app.screen.set_focus(None)  # and with the focus elsewhere it is not taken, and the console says why
        await burst(pilot, f"'{handout}'")
        assert bar.value == "a half-written message" and app.screen is app.fleet
        assert "1 file not taken: the command bar holds what you typed" in app._status[0]

    in_console(tmp_path, body, busy_lanes())


def test_a_typed_path_of_a_file_that_is_not_there_is_said_and_none_of_its_keys_acts(tmp_path, monkeypatch):
    """VS Code's terminal types a dropped file's path and leaves characters out of its name, so
    the path it types may name nothing. Its letters are still not keys of the lane list."""
    gone = tmp_path / "park kill quit.bin"  # every letter of it is a key of the fleet, and the file is not there
    monkeypatch.setenv("TERM_PROGRAM", "vscode")

    async def body(run, app, pilot):
        key_drops(app, monkeypatch)
        await run.add_challenge(NewChallenge(name="Static Hiss", description="d"))
        await until(pilot, lambda: app.fleet.selected_lane in run.deck.lanes)
        lane = run.deck.lanes[app.fleet.selected_lane]
        bar = app.screen.query_one("#bar-input")
        for typed in (f"'{gone}'", escaped(gone)):  # as VS Code types it, and as Warp does
            app._status = None
            await burst(pilot, typed)
            assert app.screen is app.fleet and not lane.finished and lane.state is not LaneState.PAUSED  # no key of it acted
            assert bar.value == "" and not bar.has_focus  # not even its first: `/` opens the command bar
            assert app._status[0].startswith("no such file: ...") and app._status[1] == "warning"
            assert app._status[0].endswith("park kill quit.bin. VS Code's terminal leaves ` $ | & > ~ # ! ^ * ; < out of a "
                                           "dropped file's name: type /attach with no file to choose it")
        await pilot.press("slash")  # with the command bar open it is text there, as a paste is, and said all the same
        await pilot.pause(GAP * 2)
        app._status = None
        await burst(pilot, f"'{gone}'")
        assert bar.value == f"/'{gone}'" and app._status[0].startswith("no such file: ...")

    in_console(tmp_path, body, busy_lanes())


def test_files_dropped_on_a_board_that_takes_none_are_refused_aloud_and_their_keys_do_not_act(tmp_path, monkeypatch):
    from ctf_flightdeck.console.app import FlightdeckApp
    from ctf_flightdeck.mock import scenarios
    from ctf_flightdeck.mock.world import FakeWorld

    handout = tmp_path / "park kill quit.bin"
    handout.write_bytes(b"x")

    async def main():
        world = FakeWorld(scenarios.get("sstv"))
        app = FlightdeckApp(world.deck, ticker=world.tick, mock="MOCK · test", refresh_seconds=None)
        async with app.run_test(size=(160, 46)) as pilot:
            await pilot.pause()
            key_drops(app, monkeypatch)
            before = {lane.id: lane.state for lane in world.deck.lanes.values()}
            await burst(pilot, escaped(handout))
            assert app.screen is app.fleet and {lane.id: lane.state for lane in world.deck.lanes.values()} == before
            assert app._status[:2] == ("not attached: files are attached on a board you fill yourself; this board is the mock's", "warning")
            app._status = None
            await app.on_event(events.Paste(escaped(handout)))  # the same as a paste
            await pilot.pause()
            assert app._status[0].startswith("not attached: files are attached on a board you fill yourself")
            app._status = None
            await pilot.press("slash")  # in the command bar it is text, and nothing is said
            await pilot.pause(GAP * 2)
            await burst(pilot, f"'{handout}'")
            assert app.screen.query_one("#bar-input").value == f"/'{handout}'" and app._status is None

    asyncio.run(main())


def test_the_form_and_the_attach_command_say_what_to_do_when_a_dropped_file_does_not_land(tmp_path):
    """A terminal may keep a drop to itself, and flightdeck is then sent nothing: the way that always works is on screen."""
    from test_console import screen_text

    async def body(run, app, pilot):
        await pilot.press(*"/new", "enter")
        await pilot.pause()
        shown = " ".join(" ".join(str(part.render()).split()) for part in app.screen.query("Static"))
        assert "Files: drag them in, or ctrl+o if none lands; the line under the box names them." in shown
        assert "ctrl+o choose files" in " ".join(shown.split())
        await pilot.press("escape")
        await pilot.press(*"/att")  # the command menu, at /attach
        await pilot.pause()
        assert "add files to a challenge (drag them here, or none to choose)" in " ".join(screen_text(app).split())

    in_console(tmp_path, body)


def test_the_form_and_help_say_how_a_drop_works_in_the_terminal_flightdeck_runs_in(tmp_path, monkeypatch):
    """Where the player looks to learn how to attach: the /new form and help, each with the sentence for this terminal."""
    from test_console import prompt_text

    from ctf_flightdeck.console.screens import FILES_CHOOSE, HelpScreen

    monkeypatch.setenv("TERM_PROGRAM", "iTerm.app")

    def shown(app) -> str:
        return " ".join(" ".join(str(part.render()).split()) for part in app.screen.query("Static"))

    async def body(run, app, pilot):
        await pilot.press(*"/new", "enter")
        await pilot.pause()
        assert "Files: drag them in with no key held, or ctrl+o; the line under the box names them." in shown(app)
        assert "Files: drag them in, or ctrl+o if none lands" not in shown(app)
        await pilot.press("escape")
        await pilot.pause()
        app.action_help()
        await pilot.pause()
        assert isinstance(app.screen, HelpScreen)
        body, seen = app.screen.query_one("#help-body"), []
        while True:  # help is longer than the screen: read it a page at a time, to its end
            seen.append(prompt_text(app))
            if body.scroll_y >= body.max_scroll_y:
                break
            body.scroll_page_down(animate=False)
            await pilot.pause()
        said = " ".join(seen)
        assert "Files, in this terminal (/new and /attach)" in said
        assert ITERM2_DROP.replace(CHOOSE, FILES_CHOOSE) in said
        assert "press ctrl+o in the /new form, or type /attach with no file, to choose it" in said

    in_console(tmp_path, body)


def test_ctrl_o_and_a_bare_attach_open_the_file_window_and_take_what_was_chosen(tmp_path, monkeypatch):
    from ctf_flightdeck import filepick

    handout = tmp_path / "doll.bin"
    handout.write_bytes(b"inside")
    asked = []
    monkeypatch.setattr(filepick, "choose", lambda **kw: asked.append(kw) or [handout])

    async def main():
        with FakeModelServer(responder=lambda request: tool_call_reply("shell", {"command": "sleep 0.2"})) as server:
            run = prepare_run(options(tmp_path, server))
            app = run.app(refresh_seconds=None)
            async with app.run_test(size=(160, 46)) as pilot:
                await pilot.pause()
                await pilot.press(*"/new Doll", "enter")
                await pilot.pause()
                await pilot.press("ctrl+o")
                for _ in range(200):
                    if app.screen.files:
                        break
                    await pilot.pause(0.01)
                assert app.screen.files == [handout] and app.screen.query_one("#new-text").text == ""
                assert "1 file attached: doll.bin" in str(app.screen.query_one("#new-attached").render())
                await pilot.press("escape")
                await run.add_challenge(NewChallenge(name="Bare", description="d"))
                await pilot.pause()
                await pilot.press(*"/attach bare", "enter")
                for _ in range(300):
                    if (run.options.board / "bare" / "doll.bin").exists():
                        break
                    await pilot.pause(0.01)
                assert (run.options.board / "bare" / "doll.bin").read_bytes() == b"inside" and len(asked) == 2
            await run.shutdown()
            run.close()

    asyncio.run(main())


@pytest.mark.parametrize(("platform", "tools", "code", "out", "expected"), [
    ("darwin", {"osascript"}, 0, "{a}\n{b}\n", 2),
    ("darwin", {"osascript"}, 1, "", 0),  # cancelled
    ("linux", {"zenity"}, 0, "{a}\n/no/such/file\n", 1),
])
def test_the_file_window_returns_the_files_chosen_that_exist(tmp_path, platform, tools, code, out, expected):
    from types import SimpleNamespace

    from ctf_flightdeck import filepick

    a, b = tmp_path / "a.bin", tmp_path / "b c.txt"
    a.write_bytes(b"1")
    b.write_text("2")
    run = lambda argv, **kw: SimpleNamespace(returncode=code, stdout=out.format(a=a, b=b))  # noqa: E731
    chosen = filepick.choose(platform=platform, which=lambda t: t if t in tools else None, run=run)
    assert len(chosen) == expected and all(path.exists() for path in chosen)


def test_no_file_window_on_this_machine_is_said():
    from ctf_flightdeck import filepick

    with pytest.raises(filepick.PickError, match="paste the file's full path"):
        filepick.choose(platform="linux", which=lambda t: None)
