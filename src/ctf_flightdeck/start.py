"""What `flightdeck start` writes: an event folder that `flightdeck play FOLDER` opens.

    FOLDER/event.toml   the event profile (preflight.py), from the player's answers
    FOLDER/board/       the board: pulled from CTFd by the run, or filled by hand

This module is the answers and the file; the questions are in start_cli.py. The profile holds
no secret: a token goes to the player's keys file (keys.py) under the variable named here.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

EVENT_FILE = "event.toml"
BOARD_DIR = "board"
PLATFORMS = ("ctfd", "manual")
SUBMITS = ("confirm", "auto")


class StartError(ValueError):
    """An answer that cannot be used; the message says what to give instead."""


@dataclass(frozen=True)
class EventAnswers:
    name: str
    platform: str  # "ctfd" | "manual"
    url: str | None = None  # ctfd
    token_env: str | None = None  # ctfd: the variable's name, never the token
    flag_format: str | None = None  # a regular expression, or None for flightdeck's default
    submit: str = "confirm"
    team: bool = False


def slug(name: str) -> str:
    """A folder name for an event's name: lower case, letters and digits joined by "-"."""
    text = re.sub(r"[^a-z0-9]+", "-", name.strip().lower()).strip("-")
    if not text:
        raise StartError("give the event's name (some letters or digits), like \"Example CTF 2026\"")
    return text[:60].strip("-")


def name_answer(text: str) -> str:
    name = " ".join(text.split())
    if not name or len(name) > 100 or any(ord(ch) < 32 for ch in name):
        raise StartError("give the event's name on one line, like \"Example CTF 2026\"")
    slug(name)
    return name


def token_variable(name: str) -> str:
    """The keys-file variable for this event's CTFd token: one per event, so the token of
    last month's event is never sent to this one's site."""
    return "CTFD_TOKEN_" + slug(name).upper().replace("-", "_")


def platform_answer(text: str) -> str:
    choice = text.strip().lower()
    choice = {"1": "ctfd", "2": "manual", "by hand": "manual", "hand": "manual", "other": "manual"}.get(choice, choice)
    if choice not in PLATFORMS:
        raise StartError("answer 1 (ctfd) or 2 (by hand)")
    return choice


def submit_answer(text: str) -> str:
    choice = text.strip().lower()
    choice = {"1": "confirm", "2": "auto"}.get(choice, choice)
    if choice not in SUBMITS:
        raise StartError("answer 1 (confirm) or 2 (auto)")
    return choice


def url_answer(text: str) -> str:
    """The event site's address: http(s), a host, no login in it; a bare host gets https://."""
    from urllib.parse import urlsplit

    url = text.strip().rstrip("/")
    if url and "://" not in url:
        url = "https://" + url
    try:
        parts = urlsplit(url)
        host = parts.hostname
    except ValueError:
        host = None
    if not host or parts.scheme not in ("http", "https") or parts.username or parts.password or any(ch.isspace() for ch in url):
        raise StartError("give the event site's address, like https://ctf.example.org")
    return url


def flag_format_answer(text: str) -> str | None:
    """A flag format from what the player typed: nothing (flightdeck's default), a prefix
    ("PP" or "PP{" for PP{...}), or a regular expression of their own (anything with a
    backslash, a bracket or a brace pair in it)."""
    typed = text.strip()
    if not typed:
        return None
    if re.fullmatch(r"[A-Za-z0-9_\-]{1,32}\{?(\.\.\.\}?)?", typed):
        prefix = typed.split("{")[0]
        return re.escape(prefix).replace("\\-", "-") + r"\{[^}]+\}"
    try:
        re.compile(typed)
    except re.error as exc:
        raise StartError(f"that is neither a prefix (like PP) nor a regular expression ({exc.msg})") from None
    return typed


def render(answers: EventAnswers) -> str:
    """The event profile for these answers (preflight.load_profile reads it back)."""

    def q(text: str) -> str:
        return json.dumps(text, ensure_ascii=False)

    lines = [
        "# ctf-flightdeck event profile, written by `flightdeck start` from your answers. Edit it as the",
        "# event's rules say; `flightdeck preflight event.toml` checks it and says what flightdeck will do.",
        "# It holds no secret: a token stays in your keys file, under the variable token_env names.",
        "",
        "[event]",
        f"name = {q(answers.name)}",
        f"platform = {q(answers.platform)}",
    ]
    if answers.platform == "ctfd":
        lines += [f"url = {q(answers.url or '')}", f"token_env = {q(answers.token_env or '')}"]
    else:
        lines.append(f"board = {q(BOARD_DIR)}  # the folder of challenge folders, beside this file")
    if answers.flag_format:
        lines.append(f"flag_format = {q(answers.flag_format)}")
    lines += [
        f"team = {'true' if answers.team else 'false'}",
        "",
        "[rules]",
        "ai_allowed = true            # you said the event's rules allow AI tools",
        f"platform_automation = {'true' if answers.platform == 'ctfd' else 'false'}   # may flightdeck pull and submit through the site's API",
        'live_targets = "confirm"     # a lane asks you before it reaches a challenge\'s instance ("allowed": never asks; "off": never reaches)',
        "",
        "[policies]",
    ]
    if answers.platform == "ctfd":
        lines.append(f'submit = "{answers.submit}"' + ("           # a flag a lane claims goes to the site at once" if answers.submit == "auto"
                                                         else "        # you approve each flag before it is sent"))
    else:
        lines.append("# submit is by hand: flightdeck shows each flag, you submit it on the site and say if it was accepted")
    return "\n".join(lines) + "\n"


def event_file(folder: Path) -> Path:
    return folder / EVENT_FILE


def is_event_folder(folder: Path) -> bool:
    return event_file(folder).is_file()


def resolve(board: Path | None, event: Path | None) -> tuple[Path | None, Path | None]:
    """`play FOLDER` for a folder `start` made: its event.toml is the event profile and its
    board/ the board, with no --event to remember. Anything else is returned as it came."""
    if board is None or event is not None or not is_event_folder(board):
        return board, event
    inner = board / BOARD_DIR
    return (inner if inner.is_dir() else board), event_file(board)


def write(folder: Path, answers: EventAnswers) -> Path:
    """Make the event folder with its board/ and write event.toml; never over one that is there."""
    target = event_file(folder)
    if target.exists():
        raise StartError(f"{target} exists: `flightdeck play {folder}` plays that event (edit the file to change it)")
    try:
        (folder / BOARD_DIR).mkdir(parents=True, exist_ok=True)
        with open(target, "x", encoding="utf-8") as handle:
            handle.write(render(answers))
    except OSError as exc:
        raise StartError(f"cannot write {target}: {exc.strerror or type(exc).__name__}") from None
    return target
