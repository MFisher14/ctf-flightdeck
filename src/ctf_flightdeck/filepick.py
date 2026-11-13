"""Choose files with the operating system's own window, for a terminal where a drop does
not arrive: Finder's "choose file" on macOS (osascript), zenity on Linux when it is there.

It blocks until the window closes, so the console calls it in a thread. [] when the player
cancelled; PickError when this machine has no such window.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path


class PickError(Exception):
    """No file window on this machine; the message says what to do instead."""


def choose(prompt: str = "Choose the challenge's files", *, many: bool = True, platform: str = sys.platform,
           which=shutil.which, run=subprocess.run) -> list[Path]:
    if platform == "darwin" and which("osascript"):
        script = (f'set chosen to choose file with prompt "{prompt}"' + (" with multiple selections allowed" if many else "") + "\n"
                  + ('set out to ""\nrepeat with f in chosen\nset out to out & POSIX path of f & linefeed\nend repeat\nreturn out'
                     if many else "return POSIX path of chosen"))
        argv = ["osascript", "-e", script]
    elif platform != "darwin" and which("zenity"):
        argv = ["zenity", "--file-selection", f"--title={prompt}", "--separator=\n"] + (["--multiple"] if many else [])
    else:
        raise PickError("this machine has no file window flightdeck can open: paste the file's full path instead")
    try:
        done = run(argv, capture_output=True, text=True, timeout=600)
    except (OSError, subprocess.SubprocessError) as exc:
        raise PickError(f"the file window could not be opened ({type(exc).__name__}): paste the file's full path instead") from None
    if done.returncode != 0:
        return []  # cancelled
    return [Path(line) for line in done.stdout.splitlines() if line.strip() and Path(line).exists()]
