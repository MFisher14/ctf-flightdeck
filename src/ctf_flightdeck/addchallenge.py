"""A challenge the player hands over: a folder on the board from a name and whatever they have.

The console's /new and `flightdeck add` both end here. The player gives a name, the
challenge's description as the site shows it, and its files. `create` writes the challenge
folder (challenge.json and a copy of each file) that a board holds. A run that plays the
board picks the folder up (Run.scan_board).

The description is the event's text. It is kept as the player gave it and is never searched
for file paths: a description that says "read /etc/passwd" must not put the player's own
/etc/passwd in the handout a lane reads. The one thing read out of it is the instance's
address, when a line is nothing else (`parse`).

A file is attached only when the player hands it over as a file: `--file`, the file window,
the clipboard's image, /attach, or a drop. A terminal sends a drop as a paste that is nothing
but paths, and only a paste of that shape is one (`dropped`). What may be attached is a
regular file or a folder (`refusal` names why anything else is not), and nothing is copied
over a file that is already there.

The text is the player's own, typed at their console, but the description in it is the
event's: it goes into challenge.json and is handled as challenge text from there on
(untrusted data, never instructions).
"""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote, urlsplit

from .keys import KeysError, keys_path
from .platform.manual import CHALLENGE_FILE, ID, MAX_ID, _origin, tcp_service

MAX_NAME = 120
MAX_DROP = 20_000  # characters: a longer paste is text, not a drop
MAX_SAME_NAME = 999  # folders of one name on a board: name, name-2 ... name-999
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


# ---------------------------------------------------------------------- a drop: a paste that is only paths


# A piece of one word of a drop, as a terminal writes a path: in quotes, or bare with each
# space (and other special character) escaped by a backslash. Pieces side by side are one
# word, as in a shell: 'it'\''s.txt' is it's.txt.
_PIECE = re.compile(r"""'([^'\n]*)'|"([^"\n]*)"|((?:\\.|[^\s\\'"])+)""")
# Where the files start in /attach's argument: the first word written as an absolute path.
_FIRST_PATH = re.compile(r"""(?:^|(?<=\s))['"]?(?:/|~/|~(?=['"]?(?:\s|$))|file://)""")


def _path_of(word: str) -> Path | None:
    """`word` as a file or folder that exists on this machine, or None. Only an absolute
    path is one (/..., ~/..., file://...): a word must not become a file because one of that
    name is in the folder flightdeck runs in."""
    text = word.strip()
    if not text or "\n" in text or len(text) > 4096:
        return None
    if text.startswith("file://"):
        text = unquote(urlsplit(text).path)
    if not (text.startswith(("/", "~/")) or text == "~"):
        return None
    try:
        path = Path(text).expanduser()
        return path if path.is_absolute() and path.exists() else None
    except (OSError, RuntimeError, ValueError):
        return None


def _words(line: str) -> list[str] | None:
    """The words of a line, quotes and backslashes taken off; None when it is not made of
    whole words (a quote that never closes, say)."""
    words: list[str] = []
    at, end = 0, len(line)
    while at < end:
        if line[at].isspace():
            at += 1
            continue
        word = ""
        while at < end and not line[at].isspace():
            match = _PIECE.match(line, at)
            if match is None:
                return None
            quoted = match.group(1) if match.group(1) is not None else match.group(2)
            word += quoted if quoted is not None else re.sub(r"\\(.)", r"\1", match.group(3))
            at = match.end()
        words.append(word)
    return words


def _drop(text: str) -> tuple[list[Path], str]:
    """(the paths `text` is made of, "") when the whole text is paths that exist; else
    ([], the word that is not one)."""
    found: list[Path] = []
    for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        if not line.strip():
            continue
        whole = _path_of(line)  # one path, pasted bare with its spaces as they are
        if whole is not None:
            paths = [whole]
        else:
            words = _words(line)
            if words is None:
                return [], line.strip()
            paths = []
            for word in words:
                path = _path_of(word)
                if path is None:
                    return [], word
                paths.append(path)
        for path in paths:
            if path not in found:
                found.append(path)
    return found, ""


def dropped(text: str) -> list[Path]:
    """The files a paste hands over: its paths, when the WHOLE text is one or more absolute
    paths that exist, separated by spaces or line ends, each quoted or with its spaces
    escaped (what a terminal sends for files dropped on it). [] for any other text: a path
    inside a sentence is text, and nothing is ever taken out of text."""
    if not text.strip() or len(text) > MAX_DROP:
        return []
    return _drop(text)[0]


def attach_arg(arg: str) -> tuple[str, list[Path]]:
    """/attach's argument as (the challenge named before the files, the files). The files
    start at the first word written as an absolute path and run to the end; AddError names
    one of them that is not a file that exists. No such word: no file was named."""
    start = _FIRST_PATH.search(arg)
    if start is None:
        return arg.strip(), []
    files, missing = _drop(arg[start.start():])
    if missing:
        raise AddError(f"{missing}: no such file. Give the full path of a file that exists (in quotes if it has spaces), "
                       "or /attach with no file to choose one")
    return arg[:start.start()].strip(), files


def quote(path: Path) -> str:
    """A path as one word that `dropped` and `attach_arg` read back."""
    text = str(path)
    return f"'{text}'" if "'" not in text else re.sub(r"""([\s\\'"])""", r"\\\1", text)


# ---------------------------------------------------------------------- what may be attached


_SYSTEM = (Path("/proc"), Path("/sys"))  # kernel files: /proc/self/environ is this process's environment, keys and all


def _kind(mode: int) -> str:
    if stat.S_ISCHR(mode) or stat.S_ISBLK(mode):
        return "a device"
    if stat.S_ISFIFO(mode):
        return "a named pipe"
    if stat.S_ISSOCK(mode):
        return "a socket"
    return "not a regular file"


def _own_places() -> list[tuple[Path, str, bool]]:
    """(path, what it is, whether what is inside it is kept out too): flightdeck's config
    folder and its keys file, which never go into a handout a lane reads."""
    places: list[tuple[Path, str, bool]] = []
    try:
        places.append((Path.home() / ".config" / "ctf-flightdeck", "flightdeck's config folder", True))
    except RuntimeError:  # no home directory: there is no such folder to keep out
        pass
    try:
        places.append((keys_path(), "flightdeck's keys file", False))
    except KeysError:
        pass
    resolved = []
    for path, what, inside in places:
        try:
            resolved.append((path.resolve(), what, inside))
        except (OSError, RuntimeError):
            continue
    return resolved


def refusal(path: Path, *, into: Path | None = None) -> str | None:
    """Why `path` cannot be attached, or None when it can: it must be a regular file or a
    folder (a link the player names is followed to what it points at). Never attached: a
    device, a named pipe or a socket (a copy of one may never end); the root folder and the
    home folder itself; the system's own /proc and /sys (this process's environment is a
    file there); anything that is, holds or is inside flightdeck's config folder, or is or
    holds its keys file; and a folder that holds `into`, the folder it would be copied into."""
    try:
        real = path.resolve(strict=True)
        mode = real.stat().st_mode
    except (OSError, RuntimeError):
        return f"{path}: no such file"
    if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
        return f"{path} is {_kind(mode)}, not a file or a folder: it cannot be attached"
    if real == Path(real.anchor):
        return f"{path} is the root folder: attach the challenge's own files or folder"
    try:
        home = Path.home().resolve()
    except (OSError, RuntimeError):
        home = None
    if real == home:
        return f"{path} is your home folder itself: attach the challenge's own files, or a folder inside it"
    for system in _SYSTEM:
        if real == system or system in real.parents:
            return f"{path} is in {system}, the system's own files, not a challenge's: it cannot be attached"
    for place, what, inside in _own_places():
        if real == place or real in place.parents:
            return f"{path} {'is' if real == place else 'holds'} {what}: it is never attached"
        if inside and place in real.parents:
            return f"{path} is in {what}: it is never attached"
    if into is not None and stat.S_ISDIR(mode):
        try:
            target = into.resolve()
        except (OSError, RuntimeError):
            target = into
        if real == target or real in target.parents:
            return f"{path} holds the folder it would be copied into ({into}): attach the challenge's own files or folder"
    return None


def _sources(files: Sequence[Path], into: Path) -> list[tuple[Path, str]]:
    """(what to copy, the name it gets) for each file, checked: each may be attached
    (`refusal`), and no two have one name. AddError names the first that fails."""
    sources: list[tuple[Path, str]] = []
    for file in files:
        why = refusal(file, into=into)
        if why is not None:
            raise AddError(why)
        real = file.resolve()
        name = file.name if file.name not in ("", "..") else real.name
        if name == CHALLENGE_FILE:
            raise AddError(f"{file}: a handout file cannot be named {CHALLENGE_FILE}; rename it")
        if any(name == taken for _, taken in sources):
            raise AddError(f"{file}: two files named {name}; rename one")
        sources.append((real, name))
    return sources


def _copy_file(source: Path, target: Path, made: list[Path] | None = None) -> None:
    """Copy one regular file to `target`, which must not exist. It is opened without
    waiting and checked again once open, so a pipe or a device that took the file's place
    is refused, not read."""
    fd = os.open(source, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as src:
        mode = os.fstat(src.fileno()).st_mode
        if not stat.S_ISREG(mode):
            raise AddError(f"{source} is {_kind(mode)}: it is not copied")
        with open(target, "xb") as dst:
            if made is not None:
                made.append(target)
            shutil.copyfileobj(src, dst, 1 << 20)
    shutil.copystat(source, target, follow_symlinks=False)


def _copy(source: Path, target: Path, made: list[Path] | None = None) -> None:
    """Copy a file or a folder to `target`, which must not exist (`made` gets it once this
    call has made it). In a folder a link is copied as a link, never followed, and a device,
    pipe or socket stops the copy (AddError)."""
    if not source.is_dir():
        _copy_file(source, target, made)
        return
    os.mkdir(target)
    if made is not None:
        made.append(target)
    pending = [(source, target)]
    while pending:  # iterative, so a deeply nested folder cannot hit the recursion limit
        src, dst = pending.pop()
        with os.scandir(src) as listing:
            entries = list(listing)
        for entry in entries:
            to = dst / entry.name
            if entry.is_symlink():
                os.symlink(os.readlink(entry.path), to)
            elif entry.is_dir(follow_symlinks=False):
                os.mkdir(to)
                pending.append((Path(entry.path), to))
            elif entry.is_file(follow_symlinks=False):
                _copy_file(Path(entry.path), to)
            else:
                raise AddError(f"{entry.path} is {_kind(entry.stat(follow_symlinks=False).st_mode)}: "
                               "a folder with one in it cannot be attached")


def _why(exc: OSError) -> str:
    """What went wrong in a copy, with the file it went wrong on (it may be the player's own, not the folder written)."""
    reason = exc.strerror or type(exc).__name__
    return f"{reason} ({exc.filename})" if exc.filename else reason


def _remove(path: Path) -> None:
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path, ignore_errors=True)
    else:
        path.unlink(missing_ok=True)


# ---------------------------------------------------------------------- the text


def address(text: str) -> str | None:
    """The instance `text` names, as the board keeps it, or None when it names none: a web
    address (scheme://host[:port]; a path after it is dropped) or `nc host port`
    (tcp://host:port). Only an address manual.py loads is one, so a challenge that was added
    is one the board can read."""
    text = text.strip().strip("`")
    match = _NC.fullmatch(text)
    if match:
        return tcp_service(f"tcp://{match.group(1)}:{int(match.group(2))}")
    if _URL.fullmatch(text):
        try:
            parts = urlsplit(text)
        except ValueError:
            return None
        return _origin(f"{parts.scheme}://{parts.netloc}")
    return None


def parse(text: str) -> tuple[str, tuple[str, ...]]:
    """(description, addresses) from the text the player gave. The description is that text
    as it is (line ends as \\n, the blank space around it trimmed): nothing is taken out of
    it and it is never searched for files. A line that is only a web address or `nc host
    port` also names the challenge's instance (and stays in the description, where the lane
    reads it as the site wrote it); a link inside a sentence does not."""
    description = text.replace("\r\n", "\n").replace("\r", "\n").strip()
    urls: list[str] = []
    for line in description.split("\n"):
        found = address(line)
        if found is not None and found not in urls:
            urls.append(found)
    return description, tuple(urls)


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
    """What the form shows under the box: the files attached (name and size) and the target."""
    names = ", ".join(f"{file.name} ({size_text(file)})" for file in files)
    parts = [f"{len(files)} file{'' if len(files) == 1 else 's'} attached: {names}" if files else "no file attached"]
    if urls:
        parts.append("target: " + ", ".join(urls))
    return " · ".join(parts)


# ---------------------------------------------------------------------- the folder


def attach(folder: Path, files: Sequence[Path]) -> list[str]:
    """Copy `files` into an existing challenge folder; the names copied. AddError when one
    cannot be attached (`refusal`), two have one name, or a name is taken there; nothing is
    copied over a file that is there, and what this call copied is removed again when a
    later file fails."""
    if not files:
        raise AddError("no file to attach: drag one in, or give its path (an absolute path to a file that exists)")
    sources = _sources(files, folder)
    for _, name in sources:
        if os.path.lexists(folder / name):
            raise AddError(f"{name}: the challenge already has a file of that name")
    made: list[Path] = []
    try:
        for real, name in sources:
            _copy(real, folder / name, made)
    except (OSError, AddError) as exc:
        for target in made:
            _remove(target)
        if isinstance(exc, AddError):
            raise
        raise AddError(f"cannot copy into {folder}: {_why(exc)}") from None
    return [name for _, name in sources]


def check(board: Path, new: NewChallenge) -> tuple[str, list[tuple[Path, str]], list[str]]:
    """Everything `create` refuses a challenge for, checked without writing anything:
    (its name, what to copy under which name, its addresses). AddError says what is wrong."""
    name = " ".join(new.name.split())
    if not name or len(name) > MAX_NAME:
        raise AddError(f"give the challenge a name (one line, at most {MAX_NAME} characters)")
    if new.points < 0:
        raise AddError("points must be 0 or more")
    slug(name)
    if not board.is_dir():
        raise AddError(f"{board} is not a folder: it should be the board's folder")
    sources = _sources(new.files, board)
    urls: list[str] = []
    for url in new.urls:
        if (_origin(url) or tcp_service(url)) != url:
            raise AddError(f"{url!r} is not an address the board can hold: give a web address (https://host[:port]) or `nc host port`")
        if url not in urls:
            urls.append(url)
    return name, sources, urls


def create(board: Path, new: NewChallenge) -> Path:
    """Write the challenge's folder under `board` and return it: challenge.json and a copy of
    each file (a folder is copied whole; a link in it is copied as a link, never followed).
    The folder's name is the challenge's id: the name's slug, numbered when one is taken.
    Making the folder decides whose it is: one that is already there is another add's and is
    left alone, and only the folder this call made is removed when it cannot be filled."""
    name, sources, urls = check(board, new)
    base = slug(name)
    data: dict[str, object] = {"name": name, "category": new.category.strip() or "misc", "points": new.points,
                               "description": new.description}
    if urls:
        data["urls"] = urls
    folder, n = board / base, 1
    while True:
        try:
            folder.mkdir()
            break
        except FileExistsError:
            n += 1
            if n > MAX_SAME_NAME:
                raise AddError(f"{board} has {MAX_SAME_NAME} challenges named {base}: give this one another name") from None
            folder = board / f"{base[:MAX_ID - 4]}-{n}"
        except OSError as exc:
            raise AddError(f"cannot write {folder}: {_why(exc)}") from None
    try:
        for real, file_name in sources:
            _copy(real, folder / file_name)
        (folder / CHALLENGE_FILE).write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    except (OSError, AddError) as exc:
        shutil.rmtree(folder, ignore_errors=True)
        if isinstance(exc, AddError):
            raise
        raise AddError(f"cannot write {folder}: {_why(exc)}") from None
    return folder
