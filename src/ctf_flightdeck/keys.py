"""The player's keys file: API keys and tokens kept in one place outside the repository.

`~/.config/ctf-flightdeck/keys.env` (or the file $FLIGHTDECK_KEYS names) holds lines like

    OPENROUTER_API_KEY=sk-or-...
    ANTHROPIC_API_KEY=sk-ant-...
    CTFD_TOKEN=ctfd_...

with `#` comments and blank lines allowed, an optional `export ` in front, and the value
optionally in quotes. The config file still names each key's variable and never holds a key;
flightdeck looks a variable up in its own environment first, then in this file, so a key set
in the shell wins.

The file must be readable by its owner only (chmod 600), like an SSH key: flightdeck refuses
it otherwise. Nothing here ever prints, logs or returns a value in an error: a bad line is
named by its number only. Lane processes never get these values: their environment is an
allowlist (agent/workspace.py), and a coding-agent CLI gets only its own credential, by name.
"""

from __future__ import annotations

import os
import re
import stat
import tempfile
import time
import unicodedata
from collections.abc import Iterator, Mapping
from contextlib import contextmanager, suppress
from pathlib import Path

KEYS_ENV = "FLIGHTDECK_KEYS"
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")
MAX_BYTES = 64 * 1024
LOCK_SUFFIX = ".lock"  # keys.env.lock, beside the keys file: held while the file is rewritten
LOCK_WAIT = 10.0  # seconds a save waits for another save to finish
_LINE_BREAKS = frozenset("\n\r\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029")  # every character str.splitlines() splits at


class KeysError(Exception):
    """The keys file cannot be used; the message names the file and the line, never a value."""


def keys_path() -> Path:
    """$FLIGHTDECK_KEYS, else ~/.config/ctf-flightdeck/keys.env (from this process's environment)."""
    named = os.environ.get(KEYS_ENV)
    try:
        if named:
            return Path(named).expanduser()
        return Path.home() / ".config" / "ctf-flightdeck" / "keys.env"
    except RuntimeError:  # ~user that does not exist, or no home directory
        raise KeysError(f"cannot find the keys file: ${KEYS_ENV} or the home directory cannot be resolved") from None


def load_keys(path: Path | None = None) -> dict[str, str]:
    """The keys in the file, {} when there is no file. KeysError when it is readable by
    others, too big, or has a line that is not NAME=value."""
    path = keys_path() if path is None else path
    try:
        info = path.stat()
    except FileNotFoundError:
        return {}
    except OSError as exc:
        raise KeysError(f"{path}: cannot read it ({exc.strerror})") from None
    if not stat.S_ISREG(info.st_mode):
        raise KeysError(f"{path}: is not a regular file")
    if info.st_mode & 0o077:
        raise KeysError(f"{path}: other users can read it; keep it to yourself with: chmod 600 {path}")
    if info.st_size > MAX_BYTES:
        raise KeysError(f"{path}: is over {MAX_BYTES // 1024} KB; it should hold a few keys")
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        raise KeysError(f"{path}: is not UTF-8 text") from None
    except OSError as exc:
        raise KeysError(f"{path}: cannot read it ({exc.strerror})") from None
    keys: dict[str, str] = {}
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        name, sep, value = line.partition("=")
        name = name.strip()
        if not sep or not _NAME.fullmatch(name):
            raise KeysError(f"{path}: line {number} is not NAME=value")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        keys[name] = value
    return keys


def environment(environ: Mapping[str, str] = os.environ, *, path: Path | None = None) -> dict[str, str]:
    """`environ` with the keys file's values added under names it does not set (a variable
    set in the environment wins)."""
    merged = dict(load_keys(path))
    merged.update({name: value for name, value in environ.items()})
    return merged


def source(name: str, environ: Mapping[str, str] = os.environ, *, path: Path | None = None) -> str | None:
    """Where `name` is set: "environment", "keys file", or None. Never the value."""
    if environ.get(name, "").strip():
        return "environment"
    if load_keys(path).get(name, "").strip():
        return "keys file"
    return None


def value_problem(value: str) -> str | None:
    """Why `value` cannot be a value in the keys file, as words that follow "the value for
    NAME" (None: it can). The file is read a line at a time (str.splitlines), so a value with
    any line break in it (a newline, but also U+2028, U+0085, a form feed...) would be read as
    two lines: the rest of it as another key, or as a line that makes the whole file unreadable.
    A control or invisible character is never part of a key, and arrives unseen in a paste.
    The reason names the kind of character and its code point, never the value."""
    text = value.strip()
    if not text:
        return "is empty"
    for ch in text:
        category = unicodedata.category(ch)
        if ch in _LINE_BREAKS or category in ("Zl", "Zp"):
            return f"has a line break in it (U+{ord(ch):04X}): a key is one line"
        if category == "Cc":
            return f"has a control character in it (U+{ord(ch):04X}): copy the key again, or type it"
        if category in ("Cf", "Cs"):
            return f"has an invisible character in it (U+{ord(ch):04X}): copy the key again, or type it"
    if text[0] == text[-1] and text[0] in "\"'":
        return "is in quotes: give it without them"
    return None


@contextmanager
def _locked(path: Path, wait: float) -> Iterator[None]:
    """One save at a time: an exclusive lock on the lock file beside the keys file, so two
    saves at once (the home screen's form and `flightdeck start` in another terminal) cannot
    each read the old lines and one drop what the other added. The lock file stays (taking it
    away would let a third save in between two others); the lock itself ends with the save,
    or with the process."""
    import fcntl  # POSIX only: macOS and Linux (Windows through WSL), as flightdeck supports

    lock = path.with_name(path.name + LOCK_SUFFIX)
    try:
        descriptor = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except OSError as exc:
        raise KeysError(f"{lock}: cannot open the keys file's lock ({exc.strerror})") from None
    try:
        deadline = time.monotonic() + wait
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise KeysError(f"{path}: another flightdeck is writing it (its lock, {lock.name}, is held); "
                                    "nothing was saved: try again when that one is done") from None
                time.sleep(0.05)
            except OSError as exc:
                raise KeysError(f"{lock}: cannot lock the keys file ({exc.strerror})") from None
        yield
    finally:
        os.close(descriptor)


def _replace(path: Path, text: str) -> None:
    """Put `text` in place of the keys file in one step: written to a file of the owner's only
    in the same folder, flushed to the disk, then renamed over it. A write that fails (a full
    disk, a killed process) leaves the keys that were there; a reader sees the old file or the
    new one, never half of one. OSError when it cannot be done."""
    descriptor, name = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".", suffix=".tmp")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, path)
    except BaseException:
        with suppress(OSError):
            os.unlink(name)
        raise
    with suppress(OSError):  # the rename itself reaches the disk: best effort, the keys are in place either way
        folder = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(folder)
        finally:
            os.close(folder)


def save(name: str, value: str, *, path: Path | None = None, wait: float = LOCK_WAIT) -> Path:
    """Put NAME=value in the keys file, replacing the line that sets NAME when there is one,
    and keep the file to its owner (0600; made with its folder when missing). The value is
    written and nothing else: never returned, shown or put in an error. The file is replaced
    in one step (_replace) under a lock (_locked), so a save that fails or runs beside another
    loses no key; a keys file that is a link stays one, and what it points at is replaced.
    KeysError when the name is not a variable's name, the value cannot be one line of the
    file (value_problem), another save holds the lock for `wait` seconds, or the file cannot
    be used as it is (load_keys' refusals)."""
    path = keys_path() if path is None else path
    if not _NAME.fullmatch(name):
        raise KeysError("the key's name must be a variable's name (letters, digits and _)")
    problem = value_problem(value)
    if problem is not None:
        raise KeysError(f"the value for {name} {problem}")
    value = value.strip()
    target = Path(os.path.realpath(path))
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise KeysError(f"{path}: cannot write it ({exc.strerror})") from None
    with _locked(target, wait):
        load_keys(target)  # refuses a file others can read or with a bad line, before anything is added to it
        try:
            lines = target.read_text(encoding="utf-8").splitlines() if target.exists() else []
        except OSError as exc:
            raise KeysError(f"{path}: cannot read it ({exc.strerror})") from None
        kept = []
        for raw in lines:
            line = raw.strip()
            if line.startswith("export "):
                line = line[len("export "):].lstrip()
            if not line.startswith("#") and line.partition("=")[0].strip() == name:
                continue  # the old value of this name
            kept.append(raw)
        kept.append(f"{name}={value}")
        try:
            _replace(target, "\n".join(kept) + "\n")
        except OSError as exc:
            raise KeysError(f"{path}: cannot write it ({exc.strerror})") from None
    return path
