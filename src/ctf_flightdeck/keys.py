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
from collections.abc import Mapping
from pathlib import Path

KEYS_ENV = "FLIGHTDECK_KEYS"
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")
MAX_BYTES = 64 * 1024


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


def save(name: str, value: str, *, path: Path | None = None) -> Path:
    """Put NAME=value in the keys file, replacing the line that sets NAME when there is one,
    and keep the file to its owner (0600; made with its folder when missing). The value is
    written and nothing else: never returned, shown or put in an error. KeysError when the
    name is not a variable's name, the value cannot be one line of the file, or the file
    cannot be used as it is (load_keys' refusals)."""
    path = keys_path() if path is None else path
    if not _NAME.fullmatch(name):
        raise KeysError("the key's name must be a variable's name (letters, digits and _)")
    value = value.strip()
    if not value or any(ch in value for ch in "\r\n\0") or (value[0] == value[-1] and value[0] in "\"'"):
        raise KeysError(f"the value for {name} must be one line, not empty and not in quotes")
    load_keys(path)  # refuses a file others can read or with a bad line, before anything is added to it
    try:
        lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
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
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write("\n".join(kept) + "\n")
        os.chmod(path, 0o600)
    except OSError as exc:
        raise KeysError(f"{path}: cannot write it ({exc.strerror})") from None
    return path
