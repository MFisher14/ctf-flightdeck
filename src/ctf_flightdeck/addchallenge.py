"""A challenge the player hands over: a folder on the board from a name and whatever they have.

The console's /new and `flightdeck add` both end here. The player gives a name and one piece
of free text: the challenge's description as the site shows it, with the files they dragged
in (a terminal pastes a dropped file as its path) and the addresses of its instance on lines
of their own. `parse` sorts that text into description, files and addresses; `create` writes
the challenge folder (challenge.json and a copy of each file) that a board holds. A run that
plays the board picks the folder up (Run.scan_board).

The text is the player's own, typed at their console, but the description in it is the
event's: it goes into challenge.json and is handled as challenge text from there on
(untrusted data, never instructions).
"""

from __future__ import annotations

import json
import re
import shlex
import shutil
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote, urlsplit

from .platform.manual import CHALLENGE_FILE, ID, MAX_ID

MAX_NAME = 120
_NC = re.compile(r"(?:nc|ncat|netcat)\s+(?:-\S+\s+)*([A-Za-z0-9.\-]+)\s+(\d{1,5})")
_URL = re.compile(r"https?://[^\s<>\"']+")


class AddError(ValueError):
    """The challenge cannot be added; the message says why and what to give instead."""


@dataclass(frozen=True)
class NewChallenge:
    name: str
    category: str = ""
    points: int = 0
    description: str = ""
    files: tuple[Path, ...] = ()
    urls: tuple[str, ...] = ()  # origins (scheme://host[:port]) and tcp://host:port services


def slug(name: str) -> str:
    """A challenge id from a name: what manual.ID accepts."""
    text = re.sub(r"[^a-z0-9]+", "-", name.strip().lower()).strip("-")[:MAX_ID].strip("-")
    if not text or ID.fullmatch(text) is None:
        raise AddError("give the challenge a name with some letters or digits in it")
    return text


def _path_of(token: str) -> Path | None:
    """`token` as a file or folder that exists on this machine, or None."""
    text = token.strip()
    if not text or "\n" in text or len(text) > 4096:
        return None
    if text.startswith("file://"):
        text = unquote(urlsplit(text).path)
    try:
        path = Path(text).expanduser()
        if not path.is_absolute():
            return None  # a word of the description must not become a file because one of that name is in this folder
        return path if path.exists() else None
    except (OSError, RuntimeError, ValueError):
        return None


def _paths_on(line: str) -> list[Path] | None:
    """The files a line names when the whole line is paths (one, or several a terminal
    pasted side by side: quoted, or with spaces escaped), else None."""
    whole = _path_of(line.strip().strip("'\""))
    if whole is not None:
        return [whole]
    try:
        tokens = shlex.split(line)
    except ValueError:
        return None
    found = [_path_of(token) for token in tokens]
    return found if tokens and all(path is not None for path in found) else None


def _address_on(line: str) -> str | None:
    """The instance a line names when the whole line is one: a web address, or `nc host port`."""
    text = line.strip().strip("`")
    match = _NC.fullmatch(text)
    if match and 0 < int(match.group(2)) < 65536:
        return f"tcp://{match.group(1).lower()}:{int(match.group(2))}"
    if _URL.fullmatch(text):
        parts = urlsplit(text)
        if parts.hostname and not parts.username:
            return f"{parts.scheme}://{parts.netloc.lower()}"
    return None


def parse(text: str) -> tuple[str, tuple[Path, ...], tuple[str, ...]]:
    """(description, files, addresses) from what the player pasted. A line that is only
    paths that exist names files; a line that is only a web address or `nc host port` names
    the challenge's instance (and stays in the description, where the lane reads it as the
    site wrote it); everything else is the description."""
    described: list[str] = []
    files: list[Path] = []
    urls: list[str] = []
    for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        paths = _paths_on(line) if line.strip() else None
        if paths is not None:
            files += [path for path in paths if path not in files]
            continue
        address = _address_on(line)
        if address is not None and address not in urls:
            urls.append(address)
        described.append(line.rstrip())
    return "\n".join(described).strip(), tuple(files), tuple(urls)


def create(board: Path, new: NewChallenge) -> Path:
    """Write the challenge's folder under `board` and return it: challenge.json and a copy of
    each file (a folder is copied whole; a link is copied as a link, never followed). The
    folder's name is the challenge's id: the name's slug, numbered when one is taken. Nothing
    is left behind when it cannot be written."""
    name = " ".join(new.name.split())
    if not name or len(name) > MAX_NAME:
        raise AddError(f"give the challenge a name (one line, at most {MAX_NAME} characters)")
    if new.points < 0:
        raise AddError("points must be 0 or more")
    base = slug(name)
    if not board.is_dir():
        raise AddError(f"{board} is not a folder: it should be the board's folder")
    for file in new.files:
        if not file.exists():
            raise AddError(f"{file}: no such file")
        if file.name in (CHALLENGE_FILE, "") or sum(1 for other in new.files if other.name == file.name) > 1:
            raise AddError(f"{file}: two files of one name, or one named {CHALLENGE_FILE}; rename one")
    folder, n = board / base, 1
    while folder.exists():
        n += 1
        folder = board / f"{base[:MAX_ID - 4]}-{n}"
    data: dict[str, object] = {"name": name, "category": new.category.strip() or "misc", "points": new.points,
                               "description": new.description}
    if new.urls:
        data["urls"] = list(new.urls)
    try:
        folder.mkdir()
        for file in new.files:
            if file.is_dir() and not file.is_symlink():
                shutil.copytree(file, folder / file.name, symlinks=True)
            else:
                shutil.copy2(file, folder / file.name, follow_symlinks=True)
        (folder / CHALLENGE_FILE).write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    except OSError as exc:
        shutil.rmtree(folder, ignore_errors=True)
        raise AddError(f"cannot write {folder}: {exc.strerror or type(exc).__name__}") from None
    return folder
