"""The one flag a lane claims, looked for in the whole of the challenge's own text before it
goes out without the player (submit auto).

A flag the challenge's own text holds (its description, a handout file as it came: a decoy
flag.txt, an example in a readme, a stand-in in a binary) is often not the flag, and a wrong
try can cost one of a challenge's limited attempts, so such a flag waits for the player even
when the lane gives it as its answer. When a lane starts, the drivers note the flag-format
matches in that text (agent/driver.py, agent/external.py: planted), but that search is
bounded (part of a big file, so many bytes and files in all, so many seconds) and can miss
one. So before a flag a lane claims goes out on its own, this looks for that flag itself in
all of it: the description, and every regular file in the handout folder the lane's copy
was made from (workspace.handout: what the lane does in its own copy never changes it), read
to its end and searched as bytes, linear in the handout's size. Never through a symlink
(copy_handout copies none), and never in a FIFO, a socket or a device (it is not content).

It looks for the flag's own text in the encodings a file holds text in: UTF-8, as JSON
writes it (challenge.json), Latin-1 (when the flag has a non-ASCII character Latin-1 has),
and UTF-16 little and big endian (the strings of a Windows or .NET binary, of a memory
dump). Never a transformation a challenge may ask a player to undo (base64, hex, rot13): a
hit means the challenge hands that flag out as it is.

No limit lets a flag through. A search that cannot cover all of the handout (a file or a
folder it cannot read, a handout folder that is gone, SEARCH_SECONDS run out) holds the flag
for the player as a hit does, and says why.
"""

from __future__ import annotations

import asyncio
import json
import os
import stat
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from ..text import untrusted
from .workspace import open_dir

SEARCH_SECONDS = 60.0  # one flag's search of the whole handout; past this the flag waits for the player
CHUNK = 1024 * 1024  # bytes of a file read at a time
SHOWN = 120  # characters of a handout path in a note
OWN_TEXT = "is written in the challenge's own text (its description or a handout file)"
UNSEARCHED = "was never looked for in the challenge's own text"  # a flightdeck bug: such a flag waits

_FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK  # NONBLOCK: opening a FIFO must not hang


@dataclass(frozen=True)
class Found:
    """What the search of the challenge's own text found for one flag. Both are made safe to
    show: a handout's names are the challenge's."""

    where: str = ""  # "the description", or the handout file (relative) that holds the flag; "" for none
    problem: str = ""  # why not all of the handout could be searched; "" when it all was

    @property
    def held(self) -> bool:
        """The flag waits for the player: the challenge's own text holds it, or may."""
        return bool(self.where or self.problem)

    def says(self) -> str:
        """Why the flag waits, for a note that names the flag first ("" when it need not)."""
        if self.where:
            return OWN_TEXT
        if self.problem:
            return f"may be written in the challenge's own text: flightdeck could not search all of it ({self.problem})"
        return ""


def forms(flag: str) -> tuple[bytes, ...]:
    """The flag's text as a handout file may hold it: UTF-8, as JSON writes it (both ways
    json.dumps does), Latin-1 when it can be, and UTF-16 (LE, BE). Each once."""
    found = [flag.encode("utf-8")]
    found += [json.dumps(flag, ensure_ascii=escaped)[1:-1].encode("utf-8") for escaped in (True, False)]
    try:
        found.append(flag.encode("latin-1"))
    except UnicodeEncodeError:
        pass
    found += [flag.encode("utf-16-le"), flag.encode("utf-16-be")]
    return tuple(dict.fromkeys(form for form in found if form))


async def look_for(description: str, handout: Path | None, flag: str, *, seconds: float | None = None) -> Found:
    """search() in a thread, for at most `seconds` (SEARCH_SECONDS). A cancelled caller (the
    lane ended) stops the thread at its next chunk."""
    stop = threading.Event()
    limit = SEARCH_SECONDS if seconds is None else seconds
    try:
        return await asyncio.to_thread(search, description, handout, flag, seconds=limit, stop=stop)
    finally:
        stop.set()


def search(description: str, handout: Path | None, flag: str, *, seconds: float, stop: threading.Event | None = None) -> Found:
    """Where the challenge's own text holds `flag`: its description, else the first file of
    the handout folder (in name order, depth first) that holds one of its forms(). Blocking."""
    if flag in description:
        return Found(where="the description")
    if handout is None:
        return Found(problem="this lane's workspace names no handout folder")
    needles = forms(flag)
    if not needles:
        return Found(problem="the flag is empty")
    return _folder(Path(handout), needles, time.monotonic() + seconds, seconds, stop)


def _folder(root: Path, needles: tuple[bytes, ...], deadline: float, seconds: float, stop: threading.Event | None) -> Found:
    """Every folder is opened afresh from the handout folder, a part at a time, never through
    a symlink (workspace.open_dir), so at most two descriptors are open however deep it goes."""
    keep = max(len(needle) for needle in needles) - 1  # a flag cut by a chunk's end is found in the next
    pending: list[tuple[str, ...]] = [()]
    while pending:
        parts = pending.pop()
        late = _late(deadline, seconds, stop)
        if late:
            return late
        try:
            dir_fd = open_dir(root, parts)
        except OSError as exc:
            what = f"the folder {_shown(parts)}/" if parts else f"the handout folder {_shown((str(root),))}"
            return Found(problem=f"{what} could not be opened: {exc.strerror or exc}")
        try:
            try:
                with os.scandir(dir_fd) as listing:
                    entries = sorted(listing, key=lambda e: e.name)
            except OSError as exc:
                return Found(problem=f"the folder {_shown(parts) or '.'}/ could not be listed: {exc.strerror or exc}")
            folders: list[tuple[str, ...]] = []
            for entry in entries:
                late = _late(deadline, seconds, stop)
                if late:
                    return late
                path = (*parts, entry.name)
                try:
                    if entry.is_symlink():
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        folders.append(path)
                        continue
                    regular = entry.is_file(follow_symlinks=False)
                except OSError as exc:
                    return Found(problem=f"{_shown(path)} could not be looked at: {exc.strerror or exc}")
                if regular:
                    found = _file(dir_fd, entry.name, path, needles, keep, deadline, seconds, stop)
                    if found.held:
                        return found
            pending.extend(reversed(folders))  # depth first, in name order
        finally:
            os.close(dir_fd)
    return Found()


def _file(dir_fd: int, name: str, path: tuple[str, ...], needles: tuple[bytes, ...], keep: int, deadline: float,
          seconds: float, stop: threading.Event | None) -> Found:
    try:
        fd = os.open(name, _FILE, dir_fd=dir_fd)
    except OSError as exc:
        return Found(problem=f"{_shown(path)} could not be opened: {exc.strerror or exc}")
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return Found()  # no longer a file (it changed since the listing): not content
        os.set_blocking(fd, True)
        tail = b""
        while True:
            late = _late(deadline, seconds, stop)
            if late:
                return late
            try:
                chunk = os.read(fd, CHUNK)
            except OSError as exc:
                return Found(problem=f"{_shown(path)} could not be read: {exc.strerror or exc}")
            if not chunk:
                return Found()
            window = tail + chunk if tail else chunk
            if any(needle in window for needle in needles):
                return Found(where=_shown(path))
            tail = window[-keep:] if keep else b""
    finally:
        os.close(fd)


def _late(deadline: float, seconds: float, stop: threading.Event | None) -> Found | None:
    if stop is not None and stop.is_set():
        return Found(problem="the search was stopped")
    if time.monotonic() > deadline:
        return Found(problem=f"the search took longer than {seconds:g} s")
    return None


def _shown(parts: tuple[str, ...]) -> str:
    """A handout path for a note: made safe, its end kept when it is long (the file's name)."""
    text = untrusted("/".join(parts), one_line=True)
    return text if len(text) <= SHOWN else "…" + text[1 - SHOWN:]
