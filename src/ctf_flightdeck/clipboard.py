"""Text to the clipboard of the machine flightdeck runs on, by the tool it has for that.

The console copies what the player selects with the mouse and what /copy names. A terminal
program has two ways to a clipboard. One is the terminal's own (OSC 52), which the console
always writes: it reaches the machine the player sits at, over SSH too, but nothing says
whether the terminal took it (Terminal.app does not). The other is the operating system's
tool, which says so when it fails: pbcopy on macOS; on Linux wl-copy (Wayland), xclip or
xsel (X11), the first of them that takes the text.

Over SSH no tool is run: it would fill the clipboard of the machine flightdeck runs on,
which is not the one the player pastes on.

`put` is what the console calls: it copies, and returns what the player must be told when no
tool took the text ("" when one did). A copy never ends in a quiet nothing.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from collections.abc import Mapping

TIMEOUT = 2.0  # seconds a tool gets: each takes the text and returns at once (the Linux ones stay behind it to serve the clipboard)
LINUX_TOOLS = (
    ["wl-copy"],
    ["xclip", "-selection", "clipboard"],
    ["xsel", "--clipboard", "--input"],
)
SENT = "sent to the terminal's clipboard (OSC 52). If paste is empty, this terminal does not take it: "
OWN_SELECTION = "hold fn (Terminal.app), Option (iTerm2) or Shift while you drag"
INSTALL = "install xclip or wl-copy, or "


class ClipboardError(Exception):
    """This machine has a clipboard tool and it did not take the text; the message names each
    tool tried and says why."""


def remote(environ: Mapping[str, str]) -> bool:
    """Whether flightdeck runs in an SSH session: the player's clipboard is on another machine."""
    return bool(environ.get("SSH_CONNECTION") or environ.get("SSH_TTY"))


def copy_text(text: str, *, platform: str = sys.platform, which=shutil.which, run=subprocess.run,
              environ: Mapping[str, str] | None = None) -> str | None:
    """Put `text` on this machine's clipboard and return the name of the tool that took it.
    None when no tool was run: over SSH, or this machine has none. ClipboardError when it has
    one and none took the text."""
    environ = os.environ if environ is None else environ
    if remote(environ):
        return None
    if platform == "darwin":
        commands, env = [["pbcopy"]], {**environ, "LC_CTYPE": "UTF-8"}  # pbcopy reads its input in the locale's encoding
    else:
        commands, env = [list(argv) for argv in LINUX_TOOLS], dict(environ)
    commands = [argv for argv in commands if which(argv[0])]
    if not commands:
        return None
    data = text.encode("utf-8", "replace")
    failed = []
    for argv in commands:
        try:
            # no pipe for what the tool says: the Linux tools stay behind to serve the clipboard, and would hold it open
            done = run(argv, input=data, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=TIMEOUT, env=env)
        except subprocess.TimeoutExpired:
            failed.append(f"{argv[0]} did not end in {TIMEOUT:g} s")
            continue
        except (OSError, subprocess.SubprocessError) as exc:
            failed.append(f"{argv[0]} did not start ({type(exc).__name__})")
            continue
        if done.returncode == 0:
            return argv[0]
        failed.append(f"{argv[0]} failed (exit {done.returncode})")
    raise ClipboardError(", ".join(failed))


def put(text: str, *, platform: str = sys.platform, which=shutil.which, run=subprocess.run,
        environ: Mapping[str, str] | None = None) -> str:
    """Copy `text` (copy_text). "" when a tool took it; otherwise what the player must be told:
    the text went to the terminal's clipboard only (the console writes OSC 52 with every copy),
    which may not have taken it, and what to do then. Installing a tool is named only where one
    would help: on a Linux machine the player sits at that has none."""
    environ = os.environ if environ is None else environ
    try:
        if copy_text(text, platform=platform, which=which, run=run, environ=environ) is not None:
            return ""
    except ClipboardError as exc:
        return f"{exc}; {SENT}{OWN_SELECTION}"
    install = INSTALL if platform != "darwin" and not remote(environ) else ""
    return f"{SENT}{install}{OWN_SELECTION}"
