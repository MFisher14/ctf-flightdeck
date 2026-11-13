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
import shutil
from collections.abc import Sequence
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


# A path as a terminal pastes a dropped file: in quotes, or bare with each space (and other
# special character) escaped by a backslash; it starts at / or ~/.
_DROPPED = re.compile(r"""'((?:/|~/)[^'\n]*)'|"((?:/|~/)[^"\n]*)"|(?<![^\s])((?:/|~/)(?:\\.|[^\s\\'"])+)""")


def _take_paths(line: str) -> tuple[str, list[Path]]:
    """(the line without the files it names, those files). A dropped file is taken wherever
    it lands on the line: at the cursor, which may be after a word of the description. Only
    an absolute path that exists is one; anything else on the line stays as it is."""
    whole = _path_of(line.strip().strip("'\""))
    if whole is not None:
        return "", [whole]
    found: list[Path] = []

    def taken(match: re.Match[str]) -> str:
        quoted = match.group(1) or match.group(2)
        text = quoted if quoted is not None else re.sub(r"\\(.)", r"\1", match.group(3))
        path = _path_of(text)
        if path is None and quoted is None:  # a sentence's full stop or comma right after the path
            trimmed = text.rstrip(".,;:)")
            path = _path_of(trimmed) if trimmed != text else None
            if path is not None:
                found.append(path)
                return text[len(trimmed):]
        if path is None:
            return match.group(0)
        found.append(path)
        return ""

    rest = _DROPPED.sub(taken, line)
    return (" ".join(rest.split()) if found else line), found


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
    """(description, files, addresses) from what the player pasted. An absolute path that
    exists names a file, wherever it is on its line (and is taken out of the description); a line that is only a web address or `nc host port` names
    the challenge's instance (and stays in the description, where the lane reads it as the
    site wrote it); everything else is the description."""
    described: list[str] = []
    files: list[Path] = []
    urls: list[str] = []
    for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line, paths = _take_paths(line) if line.strip() else (line, [])
        files += [path for path in paths if path not in files]
        if paths and not line.strip():
            continue
        address = _address_on(line)
        if address is not None and address not in urls:
            urls.append(address)
        described.append(line.rstrip())
    return "\n".join(described).strip(), tuple(files), tuple(urls)


def size_text(path: Path) -> str:
    """A file's size for the player: 12 KB, 3.4 MB; "folder" for one."""
    try:
        if path.is_dir():
            return "folder"
        size = path.stat().st_size
    except OSError:
        return "?"
    for unit, step in (("GB", 1 << 30), ("MB", 1 << 20), ("KB", 1 << 10)):
        if size >= step:
            return f"{size / step:.1f} {unit}" if size < 10 * step else f"{size // step} {unit}"
    return f"{size} B"


def attached_text(files: Sequence[Path], urls: Sequence[str]) -> str:
    """What the form shows under the box: the files and addresses it found in it."""
    names = ", ".join(f"{file.name} ({size_text(file)})" for file in files)
    parts = [f"{len(files)} file{'' if len(files) == 1 else 's'} attached: {names}" if files else "no file attached"]
    if urls:
        parts.append("target: " + ", ".join(urls))
    return " · ".join(parts)


def attach(folder: Path, files: Sequence[Path]) -> list[str]:
    """Copy `files` into an existing challenge folder; the names copied. AddError when one
    is missing or its name is taken there."""
    if not files:
        raise AddError("no file to attach: drag one in, or paste its path (an absolute path to a file that exists)")
    for file in files:
        if not file.exists():
            raise AddError(f"{file}: no such file")
        if file.name == CHALLENGE_FILE or (folder / file.name).exists():
            raise AddError(f"{file.name}: the challenge already has a file of that name")
    try:
        for file in files:
            if file.is_dir() and not file.is_symlink():
                shutil.copytree(file, folder / file.name, symlinks=True)
            else:
                shutil.copy2(file, folder / file.name)
    except OSError as exc:
        raise AddError(f"cannot copy into {folder}: {exc.strerror or type(exc).__name__}") from None
    return [file.name for file in files]


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
