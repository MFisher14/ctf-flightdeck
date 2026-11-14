"""What `flightdeck start` writes: an event folder that `flightdeck play FOLDER` opens.

    FOLDER/event.toml   the event profile (preflight.py), from the player's answers
    FOLDER/board/       the board: pulled from CTFd by the run, or filled by hand

This module is the answers and the file; the questions are in start_cli.py. The profile holds
no secret: a token goes to the player's keys file (keys.py) under the variable named here.
A token belongs to a site: the variable an event names is one that no event at another site
names (token_variable_for), so one site's token is never sent to another's address.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from .text import untrusted

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
    """The first name tried for an event's CTFd token variable, from the event's name alone.
    Two names can give the same one ("Example CTF" this year and last, "Example CTF!"), so
    this is not yet the event's variable: token_variable_for chooses that, by the site."""
    return "CTFD_TOKEN_" + slug(name).upper().replace("-", "_")


def site_of(url: str | None) -> str | None:
    """The site an address belongs to, as "host:port" (the port the scheme means when none is
    given), or None for what is no http(s) address. A token is one site's: two addresses are
    the same site only when this is equal."""
    from urllib.parse import urlsplit

    try:
        parts = urlsplit((url or "").strip())
        host, port = parts.hostname, parts.port
    except ValueError:
        return None
    if not host or parts.scheme not in ("http", "https"):
        return None
    return f"{host.rstrip('.')}:{port or (443 if parts.scheme == 'https' else 80)}"


def site_name(site: str | None) -> str:
    """A site (site_of) as the player reads it: the host, with its port unless it is https's own."""
    return untrusted(site.removesuffix(":443"), one_line=True) if site else "a site its event file does not name"


@dataclass(frozen=True)
class TokenUse:
    """An event that names a token variable: the site its event.toml gives, and its folder."""

    site: str | None  # site_of(its url); None when its event file has no usable address
    folder: Path


def token_uses(known: Sequence | None = None) -> dict[str, list[TokenUse]]:
    """Which site each token variable belongs to, from the events this player has set up
    (events.known(): the ones flightdeck noted, and the folders in ~/ctf): each event.toml's
    token_env beside its url. An event file that cannot be read names no variable."""
    import tomllib

    from . import events

    uses: dict[str, list[TokenUse]] = {}
    for event in events.known() if known is None else known:
        try:
            table = tomllib.loads(event_file(event.folder).read_text(encoding="utf-8")).get("event")
        except (OSError, ValueError, AttributeError):
            continue
        if not isinstance(table, dict) or not isinstance(table.get("token_env"), str) or not table["token_env"]:
            continue
        url = table.get("url")
        uses.setdefault(table["token_env"], []).append(TokenUse(site_of(url) if isinstance(url, str) else None, event.folder))
    return uses


@dataclass(frozen=True)
class TokenVariable:
    name: str  # the variable this event's token is kept under
    source: str | None  # where it is set now: "environment", "keys file", or None (not set: the token is asked for)
    passed: tuple[str, ...] = ()  # the names tried before it and why each is not this event's, a line each


def token_variable_for(name: str, url: str, *, uses: Mapping[str, Sequence[TokenUse]] | None = None,
                       source: Callable[[str], str | None] | None = None) -> TokenVariable:
    """The keys-file variable for this event's CTFd token, bound to the event's site.

    The first of CTFD_TOKEN_<NAME>, CTFD_TOKEN_<NAME>_2, ... that is this site's or nobody's:

    - a variable an event at another site names is that site's token, set or not: it is never
      read for this event (its value would go to this site's address) and never written (this
      event's token would go to that site's);
    - a variable that is set (in the environment or the keys file) while no event names it is
      a token for a site flightdeck cannot tell, last year's event of the same name as likely
      as this one: it is not used either;
    - a variable only events at this same site name is this site's token, and is used again.

    So a variable that is set is used only when an event file says it is this site's, and a
    new site always gets a variable of its own, whose token is asked for. keys.KeysError when
    the keys file cannot be read."""
    from . import keys

    site = site_of(url)
    if site is None:
        raise StartError("give the event site's address, like https://ctf.example.org")
    uses = token_uses() if uses is None else uses
    source = keys.source if source is None else source
    base, passed = token_variable(name), []
    for number in range(1, 100):
        candidate = base if number == 1 else f"{base}_{number}"
        named_by = uses.get(candidate, ())
        where = source(candidate)
        other = next((use for use in named_by if use.site != site), None)
        if other is not None:
            passed.append(f"{candidate} is the token for {site_name(other.site)} "
                          f"(the event in {untrusted(str(other.folder), one_line=True)})")
        elif where is not None and not named_by:
            passed.append(f"{candidate} is set in your {where}, and no event of yours says it is the token for {site_name(site)}")
        else:
            return TokenVariable(candidate, where, tuple(passed))
    raise StartError(f"every token variable from {base} to {base}_99 belongs to another site: give this event another name")


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


_PREFIX = r"[A-Za-z0-9_\-]{1,32}"
# PP, PP{, PP{...}, or an example flag pasted from the rules: PP{ and a body with nothing in it
# that a regular expression is written with (a backslash, a bracket, a quantifier, a brace)
_PREFIX_OR_EXAMPLE = re.compile(rf"({_PREFIX})(?:\.\.\.\}}?|\{{([^{{}}\\\[\]()|^$*+?]*)\}}?)?")


def flag_format_read(text: str) -> tuple[str | None, str]:
    """A flag format from what the player typed, and what was understood, in words for them.

    - nothing: None (the board's format if it has one, else flightdeck's default);
    - a prefix ("PP", "PP{" or "PP{...}"): PP{, any text, };
    - an example flag ("PP{s0me_t3xt}", "flag{}"): the same, from its prefix. Kept as typed it
      would be a regular expression that matches that one text and no real flag;
    - anything else (a backslash, a bracket, a quantifier in it): a regular expression of the
      player's own, kept as it is.
    """
    typed = text.strip()
    if not typed:
        return None, "no flag format: flags are found by the board's format if it has one, else by flightdeck's usual patterns"
    found = _PREFIX_OR_EXAMPLE.fullmatch(typed)
    if found:
        prefix, body = found.group(1), found.group(2)
        pattern = re.escape(prefix).replace("\\-", "-") + r"\{[^}]+\}"
        shape = f"flags look like {prefix}{{...}}, with any text between the braces (the regular expression {pattern})"
        if body and body.strip("."):
            return pattern, f"read {untrusted(typed, one_line=True)} as an example flag: {shape}"
        return pattern, shape
    try:
        re.compile(typed)
    except re.error as exc:
        raise StartError(f"that is neither a prefix (like PP) nor a regular expression ({exc.msg})") from None
    return typed, (f"kept as your own regular expression, exactly as typed: {untrusted(typed, one_line=True)} "
                   "(for a prefix, give only what comes before the {)")


def flag_format_answer(text: str) -> str | None:
    """The flag format flag_format_read makes of what the player typed (None: none given)."""
    return flag_format_read(text)[0]


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


def folder_problem(folder: Path) -> str | None:
    """Why an event cannot be set up in `folder` (None: it can), found without making
    anything: it is an event already, it is a file, or it (or the nearest folder above it that
    exists, where it would be made) is not a folder this player can write in."""
    if is_event_folder(folder):
        return f"{folder} is already an event: resume it, or give another folder"
    here = folder
    try:
        while not here.exists():
            if here.is_symlink():
                return f"{folder} cannot be made: {here} is a link to nothing"
            if here.parent == here:
                return f"{folder} cannot be made: nothing above it exists"
            here = here.parent
        if not here.is_dir():
            return f"{here} is a file, not a folder" if here == folder else f"{folder} cannot be made: {here} is a file, not a folder"
        if not os.access(here, os.W_OK | os.X_OK):
            return f"you cannot write in {here}" if here == folder else f"{folder} cannot be made: you cannot write in {here}"
    except OSError as exc:
        return f"{folder} cannot be used: {exc.strerror or type(exc).__name__}"
    return None


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
