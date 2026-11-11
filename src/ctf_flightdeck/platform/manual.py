"""The folder board: challenges laid out as directories, each with a challenge.json.

This is how flightdeck plays a board without a platform API (M1, and the practice set).
Every immediate subdirectory of the board folder that holds a challenge.json is a
challenge, and the rest of that directory is its handout. An optional board.json names
the event and its flag format; an optional answers file holds the sha256 of each flag.

Everything in a board folder is untrusted data, challenge.json included. It is checked
field by field and an unknown key is an error, so a typo fails loudly. No path in it may
leave its challenge directory, symlinks are never followed, and nothing in it is run.
Error messages never show a value from the folder (but a bad flag format, escaped and cut
short: flagformat.py), and show its names and paths only made safe, since a directory name
could carry terminal escape sequences.

The answers file must sit outside every challenge directory: a lane works in a copy of
its challenge directory and must never find the answers there. It holds hashes, never
flags.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import re
import stat
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

from ..core.model import Challenge
from ..flagformat import problem as flag_format_problem
from ..text import untrusted

CHALLENGE_FILE = "challenge.json"
BOARD_FILE = "board.json"
ANSWERS_FILE = "answers.sha256.json"
DS_STORE = ".DS_Store"  # Finder's folder settings: litter, left out of the default files list
MAX_JSON_BYTES = 1_000_000  # a challenge.json, board.json or answers file bigger than this is refused
MAX_ID = 64  # ids name folders and containers
ID = re.compile(r"[a-z0-9][a-z0-9_.-]*")
ID_RULE = "lower-case letters, digits and _ . - (not first), at most 64 characters"
SHA256 = re.compile(r"[0-9a-f]{64}")

CHALLENGE_KEYS = ("name", "category", "points", "solves", "description", "files", "urls", "id")
BOARD_KEYS = ("event", "flag_format")

CATEGORY_CODES = {
    "web": "web",
    "crypto": "cry",
    "cryptography": "cry",
    "rev": "rev",
    "reverse": "rev",
    "reversing": "rev",
    "pwn": "pwn",
    "binary": "pwn",
    "forensics": "for",
    "misc": "misc",
    "osint": "osint",
}
"""Category names to the console's short codes. Any other name is kept, lower-cased."""

_HOST = re.compile(r"[a-z0-9_.-]+")
_NUMBER = re.compile(r"[0-9]+|0x[0-9a-f]*")  # a last label a browser reads as part of an IPv4 address
_MISSING = object()


@dataclass(frozen=True)
class BoardChallenge:
    challenge: Challenge  # built from challenge.json (status NEW)
    handout: Path  # the challenge directory
    urls: tuple[str, ...]  # its live instance(s): web origins, scheme://host[:port], or TCP services, tcp://host:port


@dataclass(frozen=True)
class Board:
    event: str
    flag_format: str | None
    challenges: tuple[BoardChallenge, ...]  # sorted by directory name
    answers: Path | None  # the answers file in use, if any
    skipped: tuple[str, ...]  # subdirectories without a challenge.json, and symlinks to directories


class BoardError(Exception):
    """The board cannot be used. The message names the file and what is wrong."""


def category_code(category: str) -> str:
    """The console's short code for a category: Crypto -> cry, forensics -> for, hardware -> hardware."""
    name = category.strip().lower()
    return CATEGORY_CODES.get(name, name)


def load_board(folder: Path, *, answers: Path | None = None) -> Board:
    """Read a board folder. `answers` names an answers file; without it, the folder's own
    answers.sha256.json is used if there is one."""
    try:
        folder = Path(folder).expanduser()
    except RuntimeError:  # ~user for a user that does not exist
        raise BoardError(f"{_show(folder)}: starts with ~ for a user that does not exist") from None
    try:
        if not folder.is_dir():
            raise BoardError(f"{_show(folder)}: {'is not a directory' if folder.exists() else 'no such directory'}")
        root = folder.resolve()
        event, flag_format = _settings(root)
    except OSError as exc:  # a folder that can be listed but not searched, say
        raise BoardError(f"{_show(folder)}: cannot read it ({exc.strerror or exc})") from None
    challenges: list[BoardChallenge] = []
    skipped: list[str] = []
    seen: dict[str, Path] = {}
    try:
        entries = sorted(root.iterdir(), key=lambda entry: entry.name)
    except OSError as exc:
        raise BoardError(f"{_show(root)}: cannot list it ({exc.strerror})") from None
    for entry in entries:
        spec = entry / CHALLENGE_FILE
        try:
            if entry.is_symlink():  # never followed: listed so the player sees it was left out
                if entry.is_dir():
                    skipped.append(entry.name)
                continue
            if not entry.is_dir():
                continue
            if not _present(spec):
                skipped.append(entry.name)
                continue
            item = _challenge(entry)
        except OSError as exc:
            raise BoardError(f"{_show(spec)}: cannot read it ({exc.strerror})") from None
        cid = item.challenge.id
        if cid in seen:
            raise BoardError(f"{_show(spec)}: id {cid} is also the id of {_show(seen[cid])}")
        seen[cid] = spec
        challenges.append(item)
    if not challenges:
        hint = ""
        if _present(root / CHALLENGE_FILE):
            hint = f"; it has a {CHALLENGE_FILE} of its own, so point at the folder that holds it"
        raise BoardError(f"{_show(root)}: no challenge directories (subdirectories with a {CHALLENGE_FILE}){hint}")
    used = _answers(root, answers, challenges)
    return Board(event, flag_format, tuple(challenges), used, tuple(skipped))


class AnswerVerifier:
    """Checks a candidate flag against an answers file: {challenge id: sha256 hex of the exact flag}.

    It is the deck's Verifier for a board with answers: True or False for a challenge in
    the file, None for one that is not (the player then submits by hand and says how it went).
    """

    def __init__(self, path: Path) -> None:
        self.path = Path(path).expanduser()
        data = _read_json(self.path, follow=True)
        where = _show(self.path)
        if not isinstance(data, dict):
            raise BoardError(f"{where}: must be a JSON object of challenge id to the sha256 hex of its flag")
        for cid, digest in data.items():
            if not _valid_id(cid):
                raise BoardError(f"{where}: {_quote(cid)} is not a challenge id ({ID_RULE})")
            if not isinstance(digest, str) or not SHA256.fullmatch(digest):
                # never shown: it could be a flag written where its hash belongs
                raise BoardError(
                    f"{where}: the answer for {cid} must be the sha256 of its flag, as 64 lower-case hex "
                    "characters (the file holds hashes, never flags)"
                )
        self._digests: dict[str, str] = dict(data)

    @property
    def ids(self) -> frozenset[str]:
        """The challenges this file has an answer for."""
        return frozenset(self._digests)

    def __call__(self, challenge_id: str, flag: str) -> bool | None:
        expected = self._digests.get(challenge_id)
        if expected is None:
            return None
        # surrogatepass: a flag with a lone surrogate (valid in JSON from a model) is wrong, not a crash
        actual = hashlib.sha256(flag.encode("utf-8", "surrogatepass")).hexdigest()
        return hmac.compare_digest(actual, expected)

    def __repr__(self) -> str:
        return f"AnswerVerifier({str(self.path)!r}, {len(self._digests)} answers)"


def cannot_check(challenge_id: str, flag: str) -> None:
    """The Verifier for a board with no answers: it never knows, so the player submits by hand."""
    return None


# ---------------------------------------------------------------------- board.json and challenge.json


def _settings(root: Path) -> tuple[str, str | None]:
    """The event name and flag format from board.json; the folder name and None without one."""
    path = root / BOARD_FILE
    if not _present(path):
        return root.name, None
    data = _object(path)
    where = _show(path)
    _known(path, data, BOARD_KEYS)
    event = data.get("event", root.name)
    if not isinstance(event, str) or not event.strip():
        raise BoardError(f'{where}: "event" must be a non-empty string')
    flag_format = data.get("flag_format")
    if flag_format is not None:
        if not isinstance(flag_format, str) or not flag_format:
            raise BoardError(f'{where}: "flag_format" must be a non-empty string (a regular expression)')
        broken = flag_format_problem(flag_format)  # one line, nothing hidden, short, compiles (flagformat.py)
        if broken is not None:
            raise BoardError(f'{where}: "flag_format" {broken}')
    return event, flag_format


def _challenge(directory: Path) -> BoardChallenge:
    path = directory / CHALLENGE_FILE
    where = _show(path)
    data = _object(path)
    _known(path, data, CHALLENGE_KEYS)
    name = _field(path, data, "name", _text, "a non-empty string")
    category = _field(path, data, "category", _string, "a string")
    points = _field(path, data, "points", _count, "a whole number, 0 or more")
    solves = _field(path, data, "solves", _count, "a whole number, 0 or more", default=0)
    description = _field(path, data, "description", _string, "a string", default="")
    if "id" in data:
        cid = _field(path, data, "id", _valid_id, f"a challenge id ({ID_RULE})")
    else:
        cid = directory.name
        if not _valid_id(cid):
            raise BoardError(
                f'{where}: the directory name {_quote(cid)} is not a valid challenge id ({ID_RULE}); '
                'rename the directory or give an "id"'
            )
    files = _files(directory, path, data.get("files", _MISSING))
    urls = _urls(path, data.get("urls", _MISSING))
    challenge = Challenge(
        id=cid,
        name=name,
        category=category_code(category),
        points=points,
        solves=solves,
        description=description,
        files=files,
        live=bool(urls),
    )
    return BoardChallenge(challenge=challenge, handout=directory, urls=urls)


def _files(directory: Path, path: Path, value: object) -> tuple[str, ...]:
    """The handout files: as listed (each checked, and kept as given), or by default every
    regular file under the challenge directory (see _default_files)."""
    if value is _MISSING:
        return _default_files(directory)
    if not isinstance(value, list):
        raise BoardError(f'{_show(path)}: "files" must be a list of paths inside the challenge directory')
    files: list[str] = []
    for i, item in enumerate(value):
        rel = _handout_file(directory, f'{_show(path)}: "files"[{i}]', item)
        if rel in files:
            raise BoardError(f'{_show(path)}: "files" lists {_quote(rel)} twice')
        files.append(rel)
    return tuple(files)


def _default_files(directory: Path) -> tuple[str, ...]:
    """Every regular file under the challenge directory, in subfolders too, as relative posix
    paths, sorted, so a lane's brief names what its copy of the handout holds. Left out:
    challenge.json itself, Finder's .DS_Store files, and symlinks, which are never entered
    either (one could point anywhere on this machine)."""
    found: list[str] = []
    pending: list[tuple[Path, str]] = [(directory, "")]
    while pending:  # iterative, so a deeply nested handout cannot hit the recursion limit
        current, prefix = pending.pop()
        try:
            for entry in current.iterdir():
                rel = prefix + entry.name
                if entry.is_symlink():
                    continue
                if entry.is_dir():
                    pending.append((entry, rel + "/"))
                elif entry.is_file() and rel != CHALLENGE_FILE and entry.name != DS_STORE:
                    found.append(rel)
        except OSError as exc:
            raise BoardError(f"{_show(current)}: cannot list it ({exc.strerror})") from None
    return tuple(sorted(found))


def _handout_file(directory: Path, where: str, item: object) -> str:
    """`item` as a relative posix path to a regular file inside `directory`, through no symlink."""
    if not isinstance(item, str) or not item.strip():
        raise BoardError(f"{where} must be a non-empty string")
    if "\x00" in item:
        raise BoardError(f"{where} contains a NUL character")
    rel = PurePosixPath(item)
    if rel.is_absolute() or ".." in rel.parts:
        raise BoardError(f"{where} {_quote(item)} must be a relative path inside the challenge directory")
    if not rel.parts:
        raise BoardError(f"{where} {_quote(item)} names the challenge directory itself, not a file in it")
    current = directory
    for part in rel.parts:
        current = current / part
        if current.is_symlink():
            raise BoardError(f"{where} {_quote(item)} is a symlink or inside one; flightdeck does not follow symlinks")
    if not current.is_file():
        raise BoardError(f"{where} {_quote(item)} {'is not a regular file' if current.exists() else 'does not exist'}")
    return rel.as_posix()


def _urls(path: Path, value: object) -> tuple[str, ...]:
    if value is _MISSING:
        return ()
    if not isinstance(value, list):
        raise BoardError(
            f'{_show(path)}: "urls" must be a list of origins and services, like ["http://127.0.0.1:8080"] or '
            '["tcp://127.0.0.1:1337"]'
        )
    urls: list[str] = []
    for i, item in enumerate(value):
        url = _origin(item) or tcp_service(item)
        if url is None:
            raise BoardError(
                f'{_show(path)}: "urls"[{i}] must be an http:// or https:// origin, scheme://host[:port], or a TCP '
                "service, tcp://host:port (what `nc host port` reaches): in printable ASCII with no spaces, and with "
                "no path, query or user name; a host that ends in a number must be an IPv4 address, four numbers "
                "from 0 to 255"
            )
        if url in urls:
            raise BoardError(f'{_show(path)}: "urls" lists {url} twice')
        urls.append(url)
    return tuple(urls)


def tcp_service(value: object) -> str | None:
    """`value` as a TCP service, tcp://host:port with a lower-case host, or None if it is not
    one: the port is required, and the host follows the same rule as an origin's."""
    return _origin(value, schemes=("tcp",), port=True)


def _origin(value: object, *, schemes: tuple[str, ...] = ("http", "https"), port: bool = False) -> str | None:
    """`value` as an origin with a lower-case scheme and host and no trailing "/", or None if
    it is not an http(s) origin (one of `schemes`; `port`: one that names its port). The tools
    compare origins, so they must be in one form."""
    if not isinstance(value, str) or not _printable_ascii(value):
        # urlsplit quietly drops a tab or newline anywhere and spaces and control characters in
        # front, and lower-cases a Kelvin sign to k: the origin would not be the one written
        return None
    try:
        url = urlsplit(value)
        number = url.port
    except ValueError:
        return None
    host = url.hostname  # lower-cased by urlsplit
    if url.scheme not in schemes or not host or (port and not number):
        return None
    if url.username is not None or url.password is not None:
        return None
    if url.path not in ("", "/") or url.query or url.fragment:
        return None
    if ":" in host:
        try:
            ipaddress.IPv6Address(host)
        except ValueError:
            return None
        host = f"[{host}]"
    elif not _HOST.fullmatch(host):
        return None
    elif _NUMBER.fullmatch(host.removesuffix(".").rpartition(".")[2]) and not _ipv4(host):
        # read as an IPv4 address, so only a valid one in the usual form is taken: the lane's
        # tools refuse 10.0.0.256 (it would fail only when a lane starts), and 127.1 or
        # 2130706433 is 127.0.0.1 in disguise
        return None
    return f"{url.scheme}://{host}" + ("" if number is None else f":{number}")


def _ipv4(host: str) -> bool:
    """`host` is an IPv4 address written as four numbers from 0 to 255, with no leading zeros."""
    try:
        ipaddress.IPv4Address(host)
    except ValueError:
        return False
    return True


# ---------------------------------------------------------------------- answers


def _answers(root: Path, given: Path | None, challenges: list[BoardChallenge]) -> Path | None:
    """The answers file in use, checked: outside every challenge directory, well formed, and
    with no answer for a challenge that is not on the board (a stale or mistyped id)."""
    if given is not None:
        path = Path(given).expanduser()
        if not path.is_file():
            raise BoardError(f"{_show(path)}: {'is not a regular file' if path.exists() else 'no such answers file'}")
        path = path.resolve()  # the player named it: a symlink is theirs to follow
    else:
        path = root / ANSWERS_FILE
        if not _present(path):
            return None
        if path.is_symlink():
            raise BoardError(
                f"{_show(path)}: is a symlink; flightdeck does not follow symlinks in a board "
                "(name the answers file explicitly instead)"
            )
    handouts = {inode: item.handout for item in challenges if (inode := _inode(item.handout)) is not None}
    for parent in path.parents:  # compared by inode, so a differently cased path cannot slip past
        inode = _inode(parent)
        inside = handouts.get(inode) if inode is not None else None
        if inside is not None:
            raise BoardError(
                f"{_show(path)}: is inside the challenge directory {_show(inside)}, where a lane would "
                "see it; keep the answers outside every challenge directory"
            )
    unknown = sorted(AnswerVerifier(path).ids - {item.challenge.id for item in challenges})
    if unknown:
        raise BoardError(f"{_show(path)}: has answers for challenges that are not on the board: {', '.join(unknown)}")
    return path


def _inode(path: Path) -> tuple[int, int] | None:
    try:
        info = path.stat()
    except OSError:
        return None
    return info.st_dev, info.st_ino


# ---------------------------------------------------------------------- reading and checking


class _Duplicate(ValueError):
    def __init__(self, key: str) -> None:
        super().__init__(key)
        self.key = key


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """json object hook: a key given twice is an error (json would keep the last one silently)."""
    out: dict[str, object] = {}
    for key, value in pairs:
        if key in out:
            raise _Duplicate(key)
        out[key] = value
    return out


def _read_json(path: Path, *, follow: bool = False) -> object:
    """The JSON in `path`: a regular file (a symlink only with follow=True) of at most MAX_JSON_BYTES."""
    where = _show(path)
    try:
        info = path.stat() if follow else path.lstat()
    except FileNotFoundError:
        raise BoardError(f"{where}: no such file") from None
    except OSError as exc:
        raise BoardError(f"{where}: cannot read it ({exc.strerror})") from None
    if stat.S_ISLNK(info.st_mode):
        raise BoardError(f"{where}: is a symlink; flightdeck does not follow symlinks in a board")
    if not stat.S_ISREG(info.st_mode):
        raise BoardError(f"{where}: is not a regular file")
    if info.st_size > MAX_JSON_BYTES:
        raise BoardError(f"{where}: is over {MAX_JSON_BYTES:,} bytes, too big for a {path.name}")
    try:
        text = path.read_bytes().decode("utf-8-sig")
    except OSError as exc:
        raise BoardError(f"{where}: cannot read it ({exc.strerror})") from None
    except UnicodeDecodeError:
        raise BoardError(f"{where}: is not UTF-8 text") from None
    try:
        return json.loads(text, object_pairs_hook=_unique)
    except _Duplicate as exc:
        raise BoardError(f"{where}: has the key {_quote(exc.key)} twice") from None
    except json.JSONDecodeError as exc:
        raise BoardError(f"{where}: is not valid JSON ({exc.msg} at line {exc.lineno}, column {exc.colno})") from None
    except (ValueError, RecursionError):  # a number too long to convert, or nesting too deep
        raise BoardError(f"{where}: is not JSON flightdeck can read (a number too long or nesting too deep)") from None


def _object(path: Path) -> dict:
    data = _read_json(path)
    if not isinstance(data, dict):
        raise BoardError(f"{_show(path)}: must be a JSON object")
    return data


def _known(path: Path, data: dict, known: tuple[str, ...]) -> None:
    unknown = [key for key in data if key not in known]
    if unknown:
        names = ", ".join(_quote(key) for key in unknown)
        raise BoardError(f"{_show(path)}: unknown key {names} (known: {', '.join(known)})")


def _field(path: Path, data: dict, key: str, check: Callable[[object], bool], what: str, default: object = _MISSING):
    if key not in data:
        if default is _MISSING:
            raise BoardError(f'{_show(path)}: "{key}" is missing; it must be {what}')
        return default
    value = data[key]
    if not check(value):
        raise BoardError(f'{_show(path)}: "{key}" must be {what}')
    return value


def _string(value: object) -> bool:
    return isinstance(value, str)


def _text(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _count(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _valid_id(value: object) -> bool:
    return isinstance(value, str) and len(value) <= MAX_ID and ID.fullmatch(value) is not None


def _printable_ascii(text: str) -> bool:
    """Only the printable ASCII characters, and no space."""
    return all("!" <= ch <= "~" for ch in text)


def _present(path: Path) -> bool:
    """There is something at `path`, a dangling symlink included."""
    return path.is_symlink() or path.exists()


def _show(value: object) -> str:
    """A path or message from the board, safe to print: control and invisible characters made visible."""
    return untrusted(str(value), one_line=True)


def _quote(text: str) -> str:
    """Untrusted text quoted for an error message: made safe, and cut short."""
    safe = untrusted(text, one_line=True)
    return json.dumps(safe if len(safe) <= 60 else safe[:57] + "...", ensure_ascii=False)
