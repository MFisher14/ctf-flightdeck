"""What `flightdeck start` writes: an event folder that `flightdeck play FOLDER` opens.

    FOLDER/event.toml   the event profile (preflight.py), from the player's answers
    FOLDER/board/       the board: pulled from CTFd or a JSON-API platform by the run, or filled by hand

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
PLATFORMS = ("ctfd", "manual", "http")  # http: a platform with a JSON API, by one of its presets (platform/http_presets)
SIGNS_IN = ("ctfd", "http")  # the platforms whose event has a site, a token and a submit policy
SUBMITS = ("confirm", "auto")


class StartError(ValueError):
    """An answer that cannot be used; the message says what to give instead."""


@dataclass(frozen=True)
class EventAnswers:
    name: str
    platform: str  # "ctfd" | "manual" | "http"
    url: str | None = None  # ctfd, http
    token_env: str | None = None  # ctfd, http: the variable's name, never the token
    flag_format: str | None = None  # a regular expression, or None for flightdeck's default
    submit: str = "confirm"
    team: bool = False
    label: str | None = None  # the label the team declared to the event for its AI use (rules.declared_label), or None
    preset: str | None = None  # http: which platform's routes (platform.http.PRESETS)
    game: str | None = None  # http, GZCTF: the game's number, the value of {game} in its routes


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


CTFD_PREFIX = "CTFD_TOKEN_"


def token_prefix(platform: str, preset: str | None = None) -> str:
    """What an event's token variable starts with: CTFD_TOKEN_ for CTFd; for a JSON-API
    platform, the preset's own prefix and TOKEN_ (RCTF_TOKEN_, NOCTF_TOKEN_), a name the http
    platform takes for its token (preflight.http_token_env) and that names no other secret."""
    if platform != "http":
        return CTFD_PREFIX
    from .platform.http import variable_prefix

    return variable_prefix(preset_answer(preset or "")) + "TOKEN_"


def token_variable(name: str, prefix: str = CTFD_PREFIX) -> str:
    """The first name tried for an event's token variable, from the event's name alone.
    Two names can give the same one ("Example CTF" this year and last, "Example CTF!"), so
    this is not yet the event's variable: token_variable_for chooses that, by the site."""
    return prefix + slug(name).upper().replace("-", "_")


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
                       source: Callable[[str], str | None] | None = None, prefix: str = CTFD_PREFIX) -> TokenVariable:
    """The keys-file variable for this event's token, bound to the event's site.

    The first of CTFD_TOKEN_<NAME>, CTFD_TOKEN_<NAME>_2, ... (`prefix`, token_prefix: an rCTF
    event's are RCTF_TOKEN_<NAME>, ...) that is this site's or nobody's:

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
    base, passed = token_variable(name, prefix), []
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
    choice = {"1": "ctfd", "2": "manual", "by hand": "manual", "hand": "manual", "other": "manual",
              "3": "http", "json": "http", "json api": "http"}.get(choice, choice)
    if choice not in PLATFORMS:
        raise StartError("answer 1 (ctfd), 2 (by hand) or 3 (rCTF, rCTF v2, noCTF or GZCTF)")
    return choice


PRESET_LABELS = {"rctf": "rCTF", "rctf2": "rCTF v2", "noctf": "noCTF", "gzctf": "GZCTF"}  # each platform's name as it writes it


def preset_answer(text: str) -> str:
    """Which JSON-API platform: its number in the menu (1 to 4, in platform.http.PRESETS's
    order), its preset's name (rctf2) or the platform's own (rCTF v2), in any case."""
    from .platform.http import PRESETS

    choice = " ".join(text.split()).lower()
    names = {str(number): preset for number, preset in enumerate(PRESETS, 1)}
    names.update({PRESET_LABELS[preset].lower(): preset for preset in PRESETS})
    choice = names.get(choice, choice)
    if choice not in PRESETS:
        raise StartError("answer " + ", ".join(f"{number} ({PRESET_LABELS[preset]})" for number, preset in enumerate(PRESETS, 1)))
    return choice


_ROOT_API = ("rctf", "rctf2", "gzctf")  # their routes are under the site's root (/api/...): a page's path is not part of the address
_GAME_PATH = re.compile(r"/games/([0-9]{1,9})(?:/.*)?")  # a GZCTF game's page, or a page under it: https://site/games/3/challenges


def http_url_read(preset: str, text: str) -> tuple[str, str | None, str | None]:
    """The address of an event on a JSON-API platform, from what the player typed or pasted:
    (the url its routes are under, the game the address names (GZCTF) or None, what was made
    of it in words, or None when it was taken as typed).

    rCTF's and GZCTF's routes are under the site's root, so a page's address pasted from the
    browser (https://site/challs, https://site/games/3/challenges) is cut to the site's, and
    that is said; GZCTF's /games/N also gives the game. noCTF's address is its API's, which
    may have a path of its own, so it is taken as typed."""
    from urllib.parse import urlsplit

    url = url_answer(text)
    if preset not in _ROOT_API:
        return url, None, None
    parts = urlsplit(url)
    if parts.path in ("", "/") and not parts.query and not parts.fragment:
        return url, None, None
    site = f"{parts.scheme}://{parts.netloc}"
    said = f"{PRESET_LABELS[preset]}'s routes are under the site's root, so the address is {untrusted(site, one_line=True)}"
    game = _GAME_PATH.fullmatch(parts.path) if preset == "gzctf" else None
    if game is not None:
        number = str(int(game.group(1)))
        if number != "0":
            return site, number, f"{said}, and the game is {number}, from its page's address"
    return site, None, said


def game_answer(text: str) -> str:
    """A GZCTF game's number, as its page's address shows it (https://.../games/3)."""
    typed = text.strip()
    if not re.fullmatch(r"[0-9]{1,9}", typed) or int(typed) == 0:
        raise StartError("give the game's number, as its page's address on the site shows it (3 for https://.../games/3)")
    return str(int(typed))


TOKEN_HELP = {  # where each platform's token is: what the token question asks for
    "ctfd": "your CTFd access token (on the event's site: Settings, then Access Tokens, then Generate)",
    "rctf": ("your team's login link, whole (the site's profile page, under Team Invite: https://.../login?token=...), "
             "or the token alone"),
    "noctf": ("your noCTF session token (sign in on the site; the browser's storage for the site keeps it under "
              "noctf-session-token; it lasts a week)"),
    "gzctf": ("the value of the GZCTF_Token cookie (sign in on the site; the browser's developer tools show it under "
              "Storage or Application, then Cookies; it lasts 7 days from your last visit)"),
}
TOKEN_HELP["rctf2"] = TOKEN_HELP["rctf"]


def token_help(platform: str, preset: str | None = None) -> str:
    """Where an event's token is on its site, in words."""
    return TOKEN_HELP[preset if platform == "http" and preset in TOKEN_HELP else "ctfd"]


def token_name(platform: str, preset: str | None = None) -> str:
    """The event's token in a few words, as in "put NAME=<your rCTF token> in your keys file"."""
    return f"your {PRESET_LABELS[preset]} token" if platform == "http" and preset in PRESET_LABELS else "your CTFd access token"


def submit_answer(text: str) -> str:
    choice = text.strip().lower()
    choice = {"1": "confirm", "2": "auto"}.get(choice, choice)
    if choice not in SUBMITS:
        raise StartError("answer 1 (confirm) or 2 (auto)")
    return choice


LABEL_QUESTION = ("Label your team declared to the event for its AI use, in the event's words (like Human-Led AI); "
                  "Enter if the event asks for none")
AI_QUESTION = ("Do this event's rules allow AI agents to work on the challenges, with each challenge's text and files given to "
               "a model? (flightdeck's lanes do both, and it does not play an event that forbids either)")
AI_REFUSED = ("flightdeck's lanes are AI agents that are given each challenge's text and files, and this event's rules do not "
              "allow that")


def label_answer(text: str) -> str | None:
    """The label the team declared to the event, as rules.declared_label takes it; None for
    no answer (the event asks for none)."""
    from .preflight import LABEL_SHAPE, is_label

    label = text.strip(" ")
    if not label:
        return None
    if not is_label(label):
        raise StartError(f"give the label as {LABEL_SHAPE}, or nothing")
    return label


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
    if answers.platform in SIGNS_IN:
        lines += [f"url = {q(answers.url or '')}", f"token_env = {q(answers.token_env or '')}"]
    if answers.platform != "ctfd":
        lines.append(f"board = {q(BOARD_DIR)}  # the folder of challenge folders, beside this file"
                     + (": the run pulls the challenges into it" if answers.platform == "http" else ""))
    if answers.flag_format:
        lines.append(f"flag_format = {q(answers.flag_format)}")
    lines += [
        f"team = {'true' if answers.team else 'false'}",
        "",
        "[rules]",
        "ai_allowed = true            # you said the event's rules allow AI agents on the challenges...",
        "material_to_models = true    # ...and giving a model each challenge's text and files (every lane does)",
        f"platform_automation = {'true' if answers.platform in SIGNS_IN else 'false'}   # may flightdeck pull and submit through the site's API",
        'live_targets = "confirm"     # a lane asks you before it reaches a challenge\'s instance ("allowed": never asks; "off": never reaches)',
        (f"declared_label = {q(answers.label)}   # what your team declared to the event for its AI use: shown before a run and on its flight card"
         if answers.label else
         '# declared_label = "Human-Led AI"   # if the event has teams declare a label for their AI use: yours, in the event\'s words'),
        "",
        "[policies]",
    ]
    if answers.platform in SIGNS_IN:
        lines.append(f'submit = "{answers.submit}"' + ("           # a flag a lane claims goes to the site at once" if answers.submit == "auto"
                                                         else "        # you approve each flag before it is sent"))
    else:
        lines.append("# submit is by hand: flightdeck shows each flag, you submit it on the site and say if it was accepted")
    if answers.platform == "http":  # the [http] table `flightdeck http example --preset NAME` writes, with this event's game
        from .http_cli import preset_table

        lines += ["", preset_table(answers.preset or "", answers.game, keys_file=True).rstrip("\n")]
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
