"""ctrl+g: the command bar's text in the player's own editor, and back (P71).

The editor is the one `$VISUAL` names, else the one `$EDITOR` names, the order shells and
git use. Neither set is an error that says so: there is no editor the console picks for
the player. One that is set but cannot be run is an error too, and the other variable is
not tried in its place.

The editor gets the terminal the way a take-over's shell does (takeover.run_in_terminal):
the console is suspended, its lanes keep working, and it is drawn again when the editor
exits. The text goes through a file of the player's own (mode 0600), removed afterwards.
What the editor leaves in it comes back as the bar's text, nothing is sent: the bar is one
line, so lines are joined by spaces, and a control character shows as text.untrusted()
draws it (ESC as ^[), never raw to the terminal. A file left empty is given up, as git
takes an empty message, and the bar keeps what it had.
"""

from __future__ import annotations

import os
import shlex
import shutil
import signal
import tempfile
from collections.abc import Mapping

from textual.app import App, SuspendNotSupported

from ..text import untrusted
from . import takeover

EDITOR_VARIABLES = ("VISUAL", "EDITOR")
NO_EDITOR = "ctrl+g needs an editor: set VISUAL or EDITOR to one (neither is set)"


class EditorError(Exception):
    """The editor could not be opened, or did not finish well: the bar keeps what it had."""


def editor_command(environ: Mapping[str, str]) -> list[str]:
    """The editor's command line, from the first of VISUAL and EDITOR that is set. Raises
    EditorError, naming the variable, when neither is set or the one set cannot be run."""
    for name in EDITOR_VARIABLES:
        value = environ.get(name, "").strip()
        if not value:
            continue
        try:
            argv = shlex.split(value)
        except ValueError as exc:
            raise EditorError(f"{name} is not a command line ({exc})") from None
        if not argv or not argv[0]:
            raise EditorError(f"{name} is set but names no program")
        if shutil.which(argv[0], path=environ.get("PATH")) is None:
            raise EditorError(f"{name} names {argv[0]!r}, which is not a program on PATH")
        return argv
    raise EditorError(NO_EDITOR)


def one_line(text: str) -> tuple[str, int]:
    """What an editor wrote, as the bar's one line, and how many lines it had: each line with
    no blanks at its ends, the empty ones left out, joined by single spaces."""
    lines = [line.strip() for line in text.replace("\t", " ").splitlines()]
    lines = [line for line in lines if line]
    return untrusted(" ".join(lines)), len(lines)


async def edit(app: App, text: str, environ: Mapping[str, str] | None = None) -> tuple[str, int]:
    """Open `text` in the player's editor and return what it holds when the editor exits, as
    one_line gives it. Raises EditorError with the reason when there is no editor, the file
    cannot be made or read back, the editor cannot have the terminal, it exits with a status
    other than 0, or it leaves the file empty (both as git takes them: given up)."""
    environ = os.environ if environ is None else environ
    argv = editor_command(environ)
    try:
        handle, path = tempfile.mkstemp(prefix="flightdeck-bar-", suffix=".txt")
    except OSError as exc:
        raise EditorError(f"no file for the editor could be made ({exc}): the box keeps what it had") from None
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as file:
            file.write(text + "\n" if text else "")
        try:
            ended = await takeover.run_in_terminal(app, [*argv, path], None, None)
        except SuspendNotSupported:
            raise EditorError("this console cannot hand the terminal to an editor") from None
        except OSError as exc:
            raise EditorError(f"the editor did not start: {exc}") from None
        if ended.status < 0:
            try:
                name = signal.Signals(-ended.status).name
            except ValueError:
                name = f"signal {-ended.status}"
            raise EditorError(f"the editor ({argv[0]}) was ended by {name}: the box keeps what it had")
        if ended.status != 0:
            raise EditorError(f"the editor ({argv[0]}) exited with status {ended.status}: the box keeps what it had")
        try:
            with open(path, encoding="utf-8", errors="replace") as file:
                written = file.read()
        except OSError as exc:
            raise EditorError(f"the editor's file could not be read back ({exc}): the box keeps what it had") from None
        line, lines = one_line(written)
        if not lines:
            raise EditorError("the editor left the file empty: the box keeps what it had")
        return line, lines
    finally:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
