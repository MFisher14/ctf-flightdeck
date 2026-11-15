"""A platform with a JSON API, played from a table of routes: platform = "http".

An event profile on a platform flightdeck has no adapter for can say how its API is asked, in
an [http] table (docs/BOARDS.md), and flightdeck then pulls the board, submits flags and reads
the solved list itself, with no code of the player's:

    [event]
    platform = "http"
    url = "https://ctf.example.org"
    token_env = "RCTF_TOKEN"

    [http]
    preset = "rctf"         # a table that ships with flightdeck (http_presets/); a key written here wins

The table is data, never code, so unlike a plugin (plugins/) a profile may carry it, a
teammate's profile too. What keeps that safe is in this module:

- One origin. A route is a path under event.url: no scheme, no host, no "..". Every request
  that carries the token is checked to be on event.url's origin before it leaves, and a
  redirect is never followed with it. So no table can send the token anywhere but the address
  the pre-flight shows.
- A closed set of placeholders: {ref} (the platform's id for the challenge), {flag}, {game}
  (a value of the table's own), {submission} (the poll step's id) and {token} (the sign-in
  request only). Nothing else of a challenge (its name, its text, a file's name) can be put
  into a request. Where a placeholder stands decides how it is written: percent-encoded in a
  path, a JSON string in a body ({ref:int}: a JSON number).
- No headers of the table's choosing but the one that carries the token.
- The token is the variable's value as it stands, unless the table says the platform hands
  it out in a link (auth.link_param: rCTF's /login?token=...). Then the variable may hold the
  link or the token as the link writes it, percent-encoded, and the link's host must be
  event.url's: a link to another site holds that site's token, and nothing is sent.
- A file a challenge lists is fetched from event.url's origin (with the token only when the
  table says files_auth = true) or, over https only, from another host, and then with no
  token, no cookie and no header of the platform's. Its redirects are followed the same way.
- The answer is untrusted: every answer has a size limit, the token and the session token are
  cut out of every string, and what is shown is made safe (text.untrusted).
- A verdict is one of five words (plugins.call.VERDICTS), and `incorrect` is reached only
  through a rule the table writes: an answer no rule matches is `unjudged`, so the flag comes
  back to the player and is never recorded as wrong.
- One request per flag, never sent again from here (a second send could spend a try); the
  resend of a rate-limited flag is the run's (platform/plugin_run.py), as for a plugin.
- A platform can say it wants something of a flag this engine cannot give (GZCTF's encrypted
  submissions): [http.refuse] names a request, made without the token, and a path whose
  value means "do not send". It is asked before every flag, and a value there, or no answer
  to read, keeps the flag back with the table's reason. A pull and the dry run say so too.
- A cookie's value may be pasted with the cookie's name in front of it (NAME=value, as a
  browser's tools copy it): the name is taken off, so the platform is not sent NAME=NAME=value.

parse_config() checks the table (ValueError naming the key; a string value of the profile is
never shown). HttpCaller is the engine: the same three calls a plugin answers (pull, submit,
solved: plugins.call.PlatformCaller), in process, so the run's link, its queue and the board
writer (plugins/board.py) are the plugin's own. plan() is what the pre-flight prints: each
request, and where the token goes. HttpCaller.check() is the dry run behind
`flightdeck http check`: the sign-in, the list and the solved list, what each path matched,
and nothing submitted or downloaded.

Paths into an answer are a small subset of JSONPath (RFC 9535): `$`, `.name`, `['name']`,
`[n]`, `[*]` and `.*`. No filters, no functions, no `..`.

What it does not do, each said by name when asked for: HTML pages (a web page where JSON is
expected is a stop for a human, never worked around), passwords and captchas, encrypted
requests, pages of a listing, a download route per challenge, form-encoded bodies, a CSRF
header. Those are a plugin's or a built-in adapter's.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import re
import time
import tomllib
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from http import HTTPStatus
from importlib.resources import files as package_files
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit

import httpx

from .. import __version__
from ..plugins.call import MAX_CHALLENGES, MAX_SHOWN, TOKEN_MARK, VERDICTS, CallFailed, PullReply, Verdict, valid_ref
from ..text import untrusted
from .ctfd import API, CONNECT_TIMEOUT, MAX_FILE_BYTES, MAX_REDIRECTS, _message, _retry_after
from .instances import (
    ON_DEMAND, InstanceBusy, InstanceClient, InstanceError, InstanceFailed, InstancePending, InstancesConfig,
)

NAME = "http"  # event.platform, and the name on the board's record (plugin.json): no plugin can take it (config.RESERVED_PLATFORMS)
LABEL = "the http adapter"  # how messages name it, where a plugin's say "the NAME plugin"
PULL_COMMAND = "flightdeck http pull"
PRESETS = ("rctf", "rctf2", "noctf", "gzctf")  # http_presets/NAME.toml
PRESET_CHOICE = "preset = " + " or ".join(f'"{name}"' for name in PRESETS)  # for messages: preset = "rctf" or "rctf2" or "noctf" or "gzctf"
GAME_HINTS = {"gzctf": " (GZCTF: the game's number, as its address shows it: https://.../games/3)"}
PRESET_DIR = "platform/http_presets"
TOKEN_VARIABLE = "HTTP_TOKEN"  # event.token_env of a profile with no preset: this, or this and _NAME (HttpConfig.names_token)

AUTH_KINDS = ("bearer", "token", "header", "cookie", "exchange")
SCHEMES = ("Bearer", "Token")
UNITS = {"s": 1.0, "ms": 0.001}
FIELDS = ("name", "category", "points", "solves", "description", "max_attempts", "file_urls", "file_names", "instance")
"""A challenge's fields a list item or a detail answer may give, each by a path. `name` is
required of the list; the rest are optional, as in a plugin's pull. `instance` marks the
challenge as one whose instance the platform starts when asked (challenge.json's "instance":
"on-demand"): a value there that is not null, false, 0 or "" (rCTF v2's instancerLifetime), or,
when the table gives `instance_values`, one of those (GZCTF's type: StaticContainer or
DynamicContainer)."""
MAX_INSTANCE_VALUES = 16

MAX_LIST_BYTES = 8_000_000  # the list of challenges (a plugin's pull answer has the same room)
MAX_ANSWER_BYTES = 1_000_000  # any other answer
MAX_SESSION = 4096  # characters of a session token
MAX_PATH = 200  # characters of a route or a JSONPath
MAX_STEPS = 16  # steps of a JSONPath
MAX_MATCHES = 20_000  # values one path may match in one answer
MAX_BODY_DEPTH = 4
MAX_TABLE_KEYS = 64  # keys of a body or a verdict table
MAX_PROBLEMS = 20  # challenges a pull names as left out; the rest are counted
MAX_VALUE = 200  # characters of a verdict value, a game or a pending word
MAX_REASON = 300  # characters of [http.refuse]'s reason
TIMEOUT = 20.0  # seconds a request may wait for a connection, and for each part of its answer
DEADLINE = 30.0  # seconds a request and its whole answer may take (a plugin's submit has as long)
FILE_SECONDS = 600.0  # seconds one file's download may take
RELOGIN_SECONDS = 300.0  # an exchanged session the platform refuses (401) is asked for again, this often at most
POLL_EVERY = (0.2, 30.0)  # seconds between two looks at a submission
POLL_AT_MOST = (1, 30)  # looks at a submission

_ROUTE = re.compile(r"/[A-Za-z0-9_./{}?=&~-]*")
_PLACEHOLDER = re.compile(r"\{([a-z]+)(?::([a-z]+))?\}")
_HEADER = re.compile(r"[A-Za-z][A-Za-z0-9-]{0,63}")
_COOKIE = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}")
_LINK_PARAM = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}")
_HEADER_VALUE = re.compile(r"[\x21-\x7e]+")  # what a header may carry of a token: printable ASCII, no spaces
_COOKIE_VALUE = re.compile(r"[\x21\x23-\x2b\x2d-\x3a\x3c-\x5b\x5d-\x7e]+")  # RFC 6265's cookie-octet
_WHOLE_NUMBER = re.compile(r"-?[0-9]{1,18}")
_STEP = re.compile(
    r"""\.(?P<name>[A-Za-z_][A-Za-z0-9_-]*)|(?P<all>\.\*|\[\*\])|\[(?P<index>-?[0-9]{1,6})\]"""
    r"""|\['(?P<single>[^'\\\x00-\x1f]*)'\]|\["(?P<double>[^"\\\x00-\x1f]*)"\]"""
)
# Headers the token may not be sent as: each means something else to a server or to httpx.
_HEADERS_REFUSED = frozenset({
    "host", "cookie", "content-length", "content-type", "transfer-encoding", "connection", "accept", "user-agent",
    "accept-encoding", "upgrade", "te", "trailer", "expect", "proxy-authorization",
})
_PATH_PLACEHOLDERS = {"list": ("game",), "solved": ("game",), "detail": ("ref", "game"), "submit": ("ref", "game"),
                      "poll": ("ref", "game", "submission"), "auth": ("game",), "refuse": ("game",)}
_BODY_PLACEHOLDERS = {"auth": ("token", "game"), "submit": ("ref", "flag", "game")}
_METHODS = {"list": ("GET",), "solved": ("GET",), "detail": ("GET",), "poll": ("GET",), "submit": ("POST", "PUT", "PATCH"),
            "auth": ("POST",), "refuse": ("GET",)}
_NOT_JSON = object()
_ALL = "*"  # a step that takes every child


# ---------------------------------------------------------------------- paths into an answer


@dataclass(frozen=True)
class JsonPath:
    """A path into a JSON answer, parsed. `steps`: a name (str), an index (int), or _ALL in a
    one-element tuple for every child."""

    text: str
    steps: tuple[object, ...]

    def find(self, doc: object) -> list:
        """Every value the path matches in `doc`, in order. A step that does not apply to a
        value (a name of a list, an index past its end) matches nothing there."""
        nodes = [doc]
        for step in self.steps:
            found: list = []
            for node in nodes:
                if step == (_ALL,):
                    if isinstance(node, list):
                        found.extend(node)
                    elif isinstance(node, dict):
                        found.extend(node.values())
                elif isinstance(step, str):
                    if isinstance(node, dict) and step in node:
                        found.append(node[step])
                elif isinstance(node, list) and -len(node) <= step < len(node):
                    found.append(node[step])
                if len(found) > MAX_MATCHES:
                    raise CallFailed(f"the path {self.text} matches more than {MAX_MATCHES:,} values in the platform's answer")
            nodes = found
        return nodes

    def shaped(self, doc: object) -> str | None:
        """Why `doc` is not shaped as the path expects, or None: the part of the path before
        its first `*` must be there and be a list or an object. A list that is there and
        empty is an answer (nothing listed); a key that is missing is the wrong answer."""
        for i, step in enumerate(self.steps):
            if step == (_ALL,):
                before = JsonPath(_path_text(self.steps[:i]), self.steps[:i])
                found = before.find(doc)
                if not found:
                    return f"{before.text} is not in the answer"
                if not isinstance(found[0], (list, dict)):
                    return f"{before.text} is {_kind(found[0])} in the answer, not a list"
                return None
        return None


def parse_path(where: str, value: object) -> JsonPath:
    """A JSONPath of the subset this module reads. ValueError naming `where` when it is not one."""
    rule = f'{where} must be a path into the answer, like "$.data[*].id": $ then .name, [\'name\'], [n], [*] or .*'
    if not isinstance(value, str) or not value.startswith("$") or len(value) > MAX_PATH:
        raise ValueError(rule)
    steps: list[object] = []
    at = 1
    while at < len(value):
        match = _STEP.match(value, at)
        if match is None:
            raise ValueError(rule + " (no filters, no functions, no ..)")
        if match["all"] is not None:
            steps.append((_ALL,))
        elif match["index"] is not None:
            steps.append(int(match["index"]))
        else:
            name = next(part for part in (match["name"], match["single"], match["double"]) if part is not None)
            if untrusted(name, one_line=True) != name:  # the pre-flight and `http check` show the path as it is written
                raise ValueError(f"{where}: a quoted name holds a control or invisible character (bidi, zero-width, C1): "
                                 "a path may hold only characters that show as themselves")
            steps.append(name)
        at = match.end()
    if len(steps) > MAX_STEPS:
        raise ValueError(f"{where} has more than {MAX_STEPS} steps")
    return JsonPath(value, tuple(steps))


def _path_text(steps: Sequence[object]) -> str:
    out = "$"
    for step in steps:
        if step == (_ALL,):
            out += "[*]"
        elif isinstance(step, int):
            out += f"[{step}]"
        else:
            out += f".{step}" if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", str(step)) else f"['{step}']"
    return out


# ---------------------------------------------------------------------- the table


@dataclass(frozen=True)
class Route:
    method: str
    path: str  # under event.url; may hold placeholders

    def __str__(self) -> str:
        return f"{self.method} {self.path}"


@dataclass(frozen=True)
class Auth:
    """[http.auth]: how the token is sent."""

    kind: str  # one of AUTH_KINDS
    header: str | None = None  # kind "header": the header's name
    cookie: str | None = None  # kind "cookie": the cookie's name
    request: Route | None = None  # kind "exchange": the request that turns the token into a session token
    body: Mapping[str, object] | None = field(default=None, hash=False)  # its JSON body, with {token} in it
    token_path: JsonPath | None = None  # where its answer holds the session token
    scheme: str = "Bearer"  # kind "exchange": the session token goes as Authorization: SCHEME TOKEN
    link_param: str | None = None  # the platform hands the token out in a link, as this query parameter (_token_from)


@dataclass(frozen=True)
class Listing:
    """[http.list]: the request that lists the challenges, and where each field is in one item."""

    request: Route
    items: JsonPath  # one match per challenge
    ref: JsonPath  # from here on, paths are relative to one item
    fields: Mapping[str, JsonPath] = field(hash=False)  # FIELDS -> path; `name` is always there
    instance_values: tuple[str, ...] | None = None  # the values at `instance` that mark it on-demand; None: any but an empty one


@dataclass(frozen=True)
class Detail:
    """[http.detail]: one more request per new challenge, for what the list leaves out."""

    request: Route
    fields: Mapping[str, JsonPath] = field(hash=False)  # relative to the answer; a field here wins over the list's
    instance_values: tuple[str, ...] | None = None  # as Listing's


@dataclass(frozen=True)
class Poll:
    """[http.submit.poll]: the submission is looked at again while the platform has not judged it."""

    request: Route
    id_path: JsonPath  # in the submit's answer: the submission's id, for {submission}
    pending: tuple[str, ...]  # the values that mean "not judged yet"
    every: float = 1.0
    at_most: int = 10
    verdict_path: JsonPath | None = None  # in a look's answer; None: submit.verdict_path


@dataclass(frozen=True)
class Submit:
    """[http.submit]: the request that sends a flag, and how its answer is read."""

    request: Route
    body: Mapping[str, object] = field(hash=False)
    verdict_path: JsonPath | None = None
    detail_path: JsonPath | None = None
    retry_after_path: JsonPath | None = None
    retry_after_unit: str = "s"
    tries_left_path: JsonPath | None = None
    verdicts: Mapping[str, str] = field(default_factory=dict, hash=False)  # the value at verdict_path -> one of VERDICTS
    status: Mapping[int, str] = field(default_factory=dict, hash=False)  # an HTTP status -> one of VERDICTS, when no value decided
    poll: Poll | None = None


@dataclass(frozen=True)
class Solved:
    """[http.solved]: the request that lists what the account has solved."""

    request: Route
    refs: JsonPath


@dataclass(frozen=True)
class Refuse:
    """[http.refuse]: how the platform says it wants something of a flag that flightdeck
    cannot give. The request is made without the token; a value at `path` (anything but
    null, false, or an empty string, list or object) means no flag is sent, for `reason`."""

    request: Route
    path: JsonPath
    reason: str


@dataclass(frozen=True)
class HttpConfig:
    """An event profile's [http] table, checked."""

    auth: Auth
    list: Listing
    solved: Solved
    submit: Submit | None = None  # None: the table sends no flag (the submit policy must then be by hand)
    detail: Detail | None = None
    game: str | None = None  # the value of {game}
    files_auth: bool = False  # whether a file on event.url's origin is asked for with the token
    preset: str | None = None  # the preset it started from, for messages
    refuse: Refuse | None = None  # asked before each flag: whether the platform wants what flightdeck cannot send

    @property
    def variable_prefix(self) -> str | None:
        """With a preset, what the name of the event's token variable may start with: the
        preset's name in capitals and a _ (RCTF_), with no version number: rctf2's is RCTF_ too."""
        return variable_prefix(self.preset) if self.preset else None

    def names_token(self, name: str) -> bool:
        """Whether `name` is a variable named for an event's token on this platform:
        TOKEN_VARIABLE, a name that starts with it and a _ (HTTP_TOKEN_QUALS) or, with a
        preset, a name that starts with the preset's (RCTF_TOKEN). HTTP_ alone is not enough:
        it names no platform, and other programs' settings start with it (HTTP_PROXY is a
        proxy's address, often with its password; a CGI server's HTTP_AUTHORIZATION)."""
        prefix = self.variable_prefix
        return name == TOKEN_VARIABLE or name.startswith(f"{TOKEN_VARIABLE}_") or (prefix is not None and name.startswith(prefix))

    @property
    def variable_example(self) -> str:
        """A name the event's token variable can have, for messages."""
        prefix = self.variable_prefix
        return f"{prefix}TOKEN" if prefix else TOKEN_VARIABLE


_TOP = ("preset", "game", "files_auth", "auth", "list", "detail", "submit", "solved", "refuse")
_AUTH = ("kind", "header", "cookie", "request", "body", "token_path", "scheme", "link_param")
_LIST = ("request", "items", "ref", *FIELDS, "instance_values")
_DETAIL = ("request", *FIELDS, "instance_values")
_SUBMIT = ("request", "body", "verdict_path", "detail_path", "retry_after_path", "retry_after_unit", "tries_left_path",
           "verdicts", "status", "poll")
_POLL = ("request", "id_path", "pending", "every", "at_most", "verdict_path")
_SOLVED = ("request", "refs")
_REFUSE = ("request", "path", "reason")
NOT_BUILT = {
    "list.next_path": "pages of a listing", "list.page_param": "pages of a listing", "files": "a download route per challenge",
    "submit.form": "a form-encoded body", "auth.csrf_cookie": "a CSRF header", "auth.csrf_header": "a CSRF header",
    "list.tries_used": "the tries already used",
}
"""Keys a table for another platform may want, which this engine does not have: named, with
what they stand for, so the answer is never "unknown key" alone."""


def variable_prefix(preset: str) -> str:
    """What the name of a token variable for `preset` may start with: its name in capitals
    and a _, with no version number (RCTF_ for rctf and rctf2)."""
    return re.sub(r"[0-9]+$", "", preset).upper().replace("-", "_") + "_"


def preset_text(name: str) -> str:
    """The preset's own file, as it ships."""
    if name not in PRESETS:
        raise ValueError(f"no preset of that name (known: {', '.join(PRESETS)})")
    return package_files("ctf_flightdeck").joinpath(PRESET_DIR, f"{name}.toml").read_text(encoding="utf-8")


def parse_config(table: object) -> HttpConfig:
    """The [http] table of an event profile, a preset's keys under its own. ValueError naming
    the key when it is wrong; a string the table holds is never in the message."""
    if not isinstance(table, Mapping):
        raise ValueError("http must be a table ([http])")
    preset = table.get("preset")
    if preset is not None:
        if not isinstance(preset, str) or preset not in PRESETS:
            raise ValueError(f"http.preset is not a preset flightdeck has (known: {', '.join(PRESETS)}); leave it out and "
                             "write the routes ([http.auth], [http.list], [http.submit], [http.solved])")
        table = _merged(tomllib.loads(preset_text(preset)), {key: value for key, value in table.items() if key != "preset"})
    _keys("http", table, _TOP)
    game = table.get("game")
    if game is not None and not (isinstance(game, str) and game and len(game) <= MAX_VALUE and game.isprintable()):
        raise ValueError(f"http.game must be a string of 1 to {MAX_VALUE} printable characters: the value of {{game}} in a route")
    files_auth = table.get("files_auth", False)
    if not isinstance(files_auth, bool):
        raise ValueError("http.files_auth must be true or false: whether a file on the event's own address is asked for with the token")
    missing = [f"[http.{name}]" for name in ("auth", "list", "solved") if name not in table]
    if missing:
        raise ValueError(f"http needs {', '.join(missing)}" + ("" if preset else f" (or {PRESET_CHOICE}, which have them)"))
    config = HttpConfig(
        auth=_auth(_sub(table, "auth")),
        list=_listing(_sub(table, "list")),
        solved=_solved(_sub(table, "solved")),
        submit=_submit(_sub(table, "submit")) if "submit" in table else None,
        detail=_detail(_sub(table, "detail")) if "detail" in table else None,
        game=game, files_auth=files_auth, preset=preset,
        refuse=_refuse(_sub(table, "refuse")) if "refuse" in table else None,
    )
    if game is None:
        for name, route in config_routes(config):
            if "{game}" in route.path:
                raise ValueError(f"http.{name}.request has {{game}} in its path, and the table has no game: set http.game"
                                 + GAME_HINTS.get(preset or "", ""))
        for name, body in (("auth", config.auth.body), ("submit", config.submit.body if config.submit is not None else None)):
            if body is not None and "{game}" in json.dumps(body):
                raise ValueError(f"http.{name}.body has {{game}} in it, and the table has no game: set http.game")
    return config


def config_routes(config: HttpConfig) -> list[tuple[str, Route]]:
    """(the table's name for it, the route) of every request the table can make, in the order a run makes them."""
    routes: list[tuple[str, Route]] = []
    if config.auth.request is not None:
        routes.append(("auth", config.auth.request))
    routes.append(("list", config.list.request))
    if config.refuse is not None:
        routes.append(("refuse", config.refuse.request))
    if config.detail is not None:
        routes.append(("detail", config.detail.request))
    if config.submit is not None:
        routes.append(("submit", config.submit.request))
        if config.submit.poll is not None:
            routes.append(("submit.poll", config.submit.poll.request))
    routes.append(("solved", config.solved.request))
    return routes


def _merged(base: Mapping, over: Mapping) -> dict:
    """`base` with `over`'s keys on top; a table of both is merged key by key."""
    out = dict(base)
    for key, value in over.items():
        out[key] = _merged(out[key], value) if isinstance(value, Mapping) and isinstance(out.get(key), Mapping) else value
    return out


def _keys(where: str, table: Mapping, known: Sequence[str]) -> None:
    for key in table:
        if key in known:
            continue
        inner = f"{where.removeprefix('http.')}.{key}" if where != "http" else str(key)
        if inner in NOT_BUILT:
            raise ValueError(f"{where}.{key}: {NOT_BUILT[inner]} is not something the http platform does yet; a plugin can "
                             "(docs/PLUGINS.md)")
        raise ValueError(f"{where}.{_show(key)[:64]} is not a key flightdeck knows (known in [{where}]: {', '.join(known)})")


def _sub(table: Mapping, name: str) -> Mapping:
    value = table[name]
    if not isinstance(value, Mapping):
        raise ValueError(f"http.{name} must be a table ([http.{name}])")
    return value


def _route(where: str, kind: str, value: object) -> Route:
    """[METHOD, PATH]: a path under event.url, with the placeholders a request of this kind may have."""
    methods = _METHODS[kind]
    if not isinstance(value, list) or len(value) != 2 or not all(isinstance(part, str) for part in value):
        raise ValueError(f'{where} must be [METHOD, PATH], such as ["{methods[0]}", "/api/..."]')
    method, path = value[0].upper(), value[1]
    if method not in methods:
        raise ValueError(f"{where}: the method must be {' or '.join(methods)}")
    if len(path) > MAX_PATH or not _ROUTE.fullmatch(path) or path.startswith("//") or ".." in path:
        raise ValueError(f"{where}: the path must start with / and name a route under event.url: no scheme, no host, no .. "
                         "(letters, digits and _ . / ? = & ~ - only)")
    _placeholders(where, path, _PATH_PLACEHOLDERS[kind], kinds=False)
    return Route(method, path)


def _placeholders(where: str, text: str, allowed: Sequence[str], *, kinds: bool) -> None:
    """Refuse a placeholder that may not stand in `text`, and a brace that is not one."""
    for match in _PLACEHOLDER.finditer(text):
        name, kind = match.group(1), match.group(2)
        if name not in allowed:
            what = "is not a placeholder flightdeck knows" if name not in ("ref", "flag", "token", "game", "submission") else "may not stand here"
            why = {"token": ": the token goes only where [http.auth] says", "flag": ": a flag goes in the body, never in an address"}
            raise ValueError(f"{where}: {{{name}}} {what}{why.get(name, '')} (here: {', '.join('{' + a + '}' for a in allowed) or 'none'})")
        if kind is not None and not (kinds and name == "ref" and kind == "int" and match.group(0) == text):
            raise ValueError(f"{where}: only {{ref:int}} takes a kind, and only as a body's whole value (the ref as a JSON number)")
    if "{" in _PLACEHOLDER.sub("", text) or "}" in _PLACEHOLDER.sub("", text):
        raise ValueError(f"{where}: a {{ or }} that is not one of flightdeck's placeholders")


def _body(where: str, value: object, allowed: Sequence[str], depth: int = 0) -> object:
    """A JSON body as the table writes it: strings may hold placeholders, the rest is sent as it is."""
    if isinstance(value, str):
        if len(value) > MAX_VALUE:
            raise ValueError(f"{where}: a string of the body is over {MAX_VALUE} characters")
        _placeholders(where, value, allowed, kinds=True)
        return value
    if isinstance(value, bool) or value is None or (isinstance(value, (int, float)) and value == value and abs(value) != float("inf")):
        return value
    if depth >= MAX_BODY_DEPTH:
        raise ValueError(f"{where}: the body is nested more than {MAX_BODY_DEPTH} deep")
    if isinstance(value, list) and len(value) <= MAX_TABLE_KEYS:
        return [_body(where, item, allowed, depth + 1) for item in value]
    if isinstance(value, Mapping) and len(value) <= MAX_TABLE_KEYS and all(isinstance(key, str) and len(key) <= MAX_VALUE for key in value):
        return {key: _body(where, item, allowed, depth + 1) for key, item in value.items()}
    raise ValueError(f"{where} must be a table of JSON values (strings, numbers, true and false, lists, tables)")


def _auth(table: Mapping) -> Auth:
    _keys("http.auth", table, _AUTH)
    kind = table.get("kind")
    if kind not in AUTH_KINDS:
        raise ValueError(f"http.auth.kind must be one of {', '.join(AUTH_KINDS)}")
    wanted = {"bearer": (), "token": (), "header": ("header",), "cookie": ("cookie",),
              "exchange": ("request", "body", "token_path", "scheme")}[kind]
    extra = [key for key in table if key not in ("kind", "link_param") and key not in wanted]
    if extra:
        raise ValueError(f'http.auth.{extra[0]} is not for kind = "{kind}"' + (f" (it takes: {', '.join(wanted)})" if wanted else ""))
    link = table.get("link_param")
    if link is not None and (not isinstance(link, str) or not _LINK_PARAM.fullmatch(link)):
        raise ValueError("http.auth.link_param must be the name of the query parameter that holds the token in the platform's "
                         "login link (letters, digits, _ and -)")
    if kind == "header":
        name = table.get("header")
        if not isinstance(name, str) or not _HEADER.fullmatch(name) or name.lower() in _HEADERS_REFUSED:
            raise ValueError("http.auth.header must be the name of the header that carries the token (letters, digits and -), "
                             "and not one that means something else to a server (Host, Cookie, Content-Type, ...)")
        return Auth(kind, header=name, link_param=link)
    if kind == "cookie":
        name = table.get("cookie")
        if not isinstance(name, str) or not _COOKIE.fullmatch(name):
            raise ValueError("http.auth.cookie must be the name of the cookie that carries the token (letters, digits, _ . and -)")
        return Auth(kind, cookie=name, link_param=link)
    if kind != "exchange":
        return Auth(kind, link_param=link)
    for key in ("request", "body", "token_path"):
        if key not in table:
            raise ValueError(f'http.auth.{key} is required for kind = "exchange"')
    scheme = table.get("scheme", "Bearer")
    if scheme not in SCHEMES:
        raise ValueError(f"http.auth.scheme must be {' or '.join(SCHEMES)}: how the session token is sent in the Authorization header")
    body = _body("http.auth.body", table["body"], _BODY_PLACEHOLDERS["auth"])
    if not isinstance(body, dict) or "{token}" not in json.dumps(body):
        raise ValueError("http.auth.body must be a table with {token} in one of its values: where the token goes in the sign-in request")
    return Auth(kind, request=_route("http.auth.request", "auth", table["request"]), body=body,
                token_path=parse_path("http.auth.token_path", table["token_path"]), scheme=scheme, link_param=link)


def _fields(where: str, table: Mapping) -> dict[str, JsonPath]:
    found = {name: parse_path(f"{where}.{name}", table[name]) for name in FIELDS if name in table}
    if "file_names" in found and "file_urls" not in found:
        raise ValueError(f"{where}.file_names names the files of {where}.file_urls, which is missing")
    return found


def _listing(table: Mapping) -> Listing:
    _keys("http.list", table, _LIST)
    for key in ("request", "items", "ref", "name"):
        if key not in table:
            raise ValueError(f"http.list.{key} is required")
    return Listing(_route("http.list.request", "list", table["request"]), parse_path("http.list.items", table["items"]),
                   parse_path("http.list.ref", table["ref"]), _fields("http.list", table), _instance_values("http.list", table))


def _detail(table: Mapping) -> Detail:
    _keys("http.detail", table, _DETAIL)
    if "request" not in table:
        raise ValueError("http.detail.request is required")
    route = _route("http.detail.request", "detail", table["request"])
    if "{ref}" not in route.path:
        raise ValueError("http.detail.request must say which challenge it asks for: {ref} in its path")
    fields = _fields("http.detail", table)
    if not fields:
        raise ValueError(f"http.detail names no field to read from its answer (one of {', '.join(FIELDS)})")
    return Detail(route, fields, _instance_values("http.detail", table))


def _instance_values(where: str, table: Mapping) -> tuple[str, ...] | None:
    """`instance_values`: the values at `instance` that mark a challenge on-demand, when not
    every value does (GZCTF's type names its attachments too)."""
    if "instance_values" not in table:
        return None
    if "instance" not in table:
        raise ValueError(f"{where}.instance_values names values of {where}.instance, which is missing")
    values = table["instance_values"]
    if not isinstance(values, list) or not values or len(values) > MAX_INSTANCE_VALUES or len(set(values)) != len(values) \
            or not all(isinstance(v, str) and v and len(v) <= MAX_VALUE and untrusted(v, one_line=True) == v for v in values):
        raise ValueError(f'{where}.instance_values must be a list of 1 to {MAX_INSTANCE_VALUES} distinct strings, such as '
                         '["StaticContainer", "DynamicContainer"]: the values at instance that mean the platform starts one')
    return tuple(values)


def _verdict_table(where: str, value: object, *, numbers: bool) -> dict:
    if not isinstance(value, Mapping) or len(value) > MAX_TABLE_KEYS:
        raise ValueError(f"{where} must be a table of at most {MAX_TABLE_KEYS} rules")
    out: dict = {}
    for key, word in value.items():
        if word not in VERDICTS:
            raise ValueError(f"{where}: a rule's verdict must be one of {', '.join(VERDICTS)}")
        if numbers:
            if not (isinstance(key, str) and re.fullmatch(r"[1-5][0-9]{2}", key)):
                raise ValueError(f"{where}: a rule's key must be an HTTP status, 100 to 599")
            out[int(key)] = word
        elif not isinstance(key, str) or not key or len(key) > MAX_VALUE:
            raise ValueError(f"{where}: a rule's key must be the value the platform answers with, at most {MAX_VALUE} characters")
        else:
            out[key] = word
    return out


def _submit(table: Mapping) -> Submit:
    _keys("http.submit", table, _SUBMIT)
    for key in ("request", "body"):
        if key not in table:
            raise ValueError(f"http.submit.{key} is required")
    route = _route("http.submit.request", "submit", table["request"])
    body = _body("http.submit.body", table["body"], _BODY_PLACEHOLDERS["submit"])
    if not isinstance(body, dict):
        raise ValueError("http.submit.body must be a table: the JSON body that carries the flag")
    text = json.dumps(body)
    if "{flag}" not in text:
        raise ValueError("http.submit.body must have {flag} in one of its values: where the flag goes")
    if "{ref}" not in route.path and "{ref" not in text:
        raise ValueError("http.submit must say which challenge the flag is for: {ref} in the request's path or in the body")
    paths = {key: parse_path(f"http.submit.{key}", table[key])
             for key in ("verdict_path", "detail_path", "retry_after_path", "tries_left_path") if key in table}
    unit = table.get("retry_after_unit", "s")
    if unit not in UNITS:
        raise ValueError(f"http.submit.retry_after_unit must be {' or '.join(json.dumps(u) for u in UNITS)}")
    verdicts = _verdict_table("http.submit.verdicts", table.get("verdicts", {}), numbers=False)
    status = _verdict_table("http.submit.status", table.get("status", {}), numbers=True)
    if verdicts and "verdict_path" not in paths:
        raise ValueError("http.submit.verdicts needs http.submit.verdict_path: where the answer holds the value the rules look at")
    if not verdicts and not status:
        raise ValueError("http.submit needs a rule that reads the answer: [http.submit.verdicts] (with verdict_path) or "
                         "[http.submit.status]. With none, no flag would ever be judged")
    poll = _poll(table["poll"], "verdict_path" in paths) if "poll" in table else None
    return Submit(route, body, paths.get("verdict_path"), paths.get("detail_path"), paths.get("retry_after_path"), unit,
                  paths.get("tries_left_path"), verdicts, status, poll)


def _poll(table: object, has_verdict_path: bool) -> Poll:
    if not isinstance(table, Mapping):
        raise ValueError("http.submit.poll must be a table ([http.submit.poll])")
    _keys("http.submit.poll", table, _POLL)
    for key in ("request", "id_path", "pending"):
        if key not in table:
            raise ValueError(f"http.submit.poll.{key} is required")
    route = _route("http.submit.poll.request", "poll", table["request"])
    if "{submission}" not in route.path:
        raise ValueError("http.submit.poll.request must say which submission it looks at: {submission} in its path")
    pending = table["pending"]
    if not isinstance(pending, list) or not pending or len(pending) > MAX_TABLE_KEYS \
            or not all(isinstance(word, str) and word and len(word) <= MAX_VALUE for word in pending):
        raise ValueError("http.submit.poll.pending must be a list of the values that mean the platform has not judged the flag yet")
    every = table.get("every", 1.0)
    if isinstance(every, bool) or not isinstance(every, (int, float)) or not POLL_EVERY[0] <= every <= POLL_EVERY[1]:
        raise ValueError(f"http.submit.poll.every must be a number of seconds from {POLL_EVERY[0]:g} to {POLL_EVERY[1]:g}")
    at_most = table.get("at_most", 10)
    if isinstance(at_most, bool) or not isinstance(at_most, int) or not POLL_AT_MOST[0] <= at_most <= POLL_AT_MOST[1]:
        raise ValueError(f"http.submit.poll.at_most must be a whole number from {POLL_AT_MOST[0]} to {POLL_AT_MOST[1]}: how many looks")
    verdict_path = parse_path("http.submit.poll.verdict_path", table["verdict_path"]) if "verdict_path" in table else None
    if verdict_path is None and not has_verdict_path:
        raise ValueError("http.submit.poll needs a verdict_path (its own, or http.submit's): where a look's answer holds the value")
    return Poll(route, parse_path("http.submit.poll.id_path", table["id_path"]), tuple(pending), float(every), at_most, verdict_path)


def _refuse(table: Mapping) -> Refuse:
    _keys("http.refuse", table, _REFUSE)
    for key in _REFUSE:
        if key not in table:
            raise ValueError(f"http.refuse.{key} is required")
    reason = table["reason"]
    if not isinstance(reason, str) or not reason.strip() or len(reason) > MAX_REASON or untrusted(reason, one_line=True) != reason:
        raise ValueError(f"http.refuse.reason must be one line of at most {MAX_REASON} printable characters: what the player is "
                         "told when no flag is sent")
    return Refuse(_route("http.refuse.request", "refuse", table["request"]), parse_path("http.refuse.path", table["path"]), reason)


def _solved(table: Mapping) -> Solved:
    _keys("http.solved", table, _SOLVED)
    for key in ("request", "refs"):
        if key not in table:
            raise ValueError(f"http.solved.{key} is required")
    return Solved(_route("http.solved.request", "solved", table["request"]), parse_path("http.solved.refs", table["refs"]))


# ---------------------------------------------------------------------- what a run will send


def plan(config: HttpConfig, instances: InstancesConfig | None = None) -> list[str]:
    """What the table makes flightdeck send, a line for each request: the method, the route
    under event.url, and where the token goes. Shown before anything runs (pre-flight), so a
    table from someone else is read first. Every string here passed parse_config's checks.
    `instances`: the profile's [instances] table, whose routes are asked the same way."""
    auth = config.auth
    if auth.kind == "exchange":
        carried = f"with the session token (Authorization: {auth.scheme})"
    elif auth.kind == "header":
        carried = f"with your token (the {auth.header} header)"
    elif auth.kind == "cookie":
        carried = f"with your token (the {auth.cookie} cookie)"
    else:
        carried = f"with your token (Authorization: {'Bearer' if auth.kind == 'bearer' else 'Token'})"
    lines = []
    if config.preset:
        lines.append(f"the {config.preset} preset's routes, with the [http] table's own keys on top")
    if config.game is not None:
        lines.append(f"{{game}} is {untrusted(config.game, one_line=True)}")
    if auth.link_param is not None:
        lines.append(f"link      the token variable may hold your login link (its ?{auth.link_param}= is taken) or the token as the "
                     "link writes it (%2B is read as +)")
    if auth.request is not None:
        lines.append(f"sign in   {auth.request}: your token in the request's body; the answer's {auth.token_path.text} is the "
                     "session token")
    lines.append(f"list      {config.list.request}, {carried}")
    if config.refuse is not None:
        lines.append(f"refuse    {config.refuse.request}, without your token: before each flag; a value at {config.refuse.path.text} "
                     "means no flag is sent")
    if config.detail is not None:
        lines.append(f"detail    {config.detail.request}, {carried}: once for each new challenge")
    urls = (config.detail.fields.get("file_urls") if config.detail is not None else None) or config.list.fields.get("file_urls")
    if urls is not None:
        on_site = "with your token" if config.files_auth and auth.kind != "exchange" else \
            "with the session token" if config.files_auth else "without your token"
        lines.append(f"files     each address at {urls.text}: on the event's own address {on_site}; on another host over https "
                     "only, and never with a token")
    if config.submit is not None:
        lines.append(f"submit    {config.submit.request}, {carried}: the flag in the request's body, sent once")
        if config.submit.poll is not None:
            poll = config.submit.poll
            lines.append(f"poll      {poll.request}, {carried}: at most {poll.at_most} looks, {poll.every:g} s apart, while the "
                         "platform has not judged the flag")
    else:
        lines.append("submit    no route: flightdeck sends no flag (the submit policy must be manual or off)")
    lines.append(f"solved    {config.solved.request}, {carried}")
    if instances is not None:  # the [instances] table's routes go the same way, with the same token
        under = API if instances.routes.api else ""  # InstanceClient asks these paths under /api/v1 when `api` is true
        for action in ("status", "start", "renew", "stop"):
            method, path = getattr(instances.routes, action)
            path = under + path
            lines.append(f"instance  {action} {method} {path}, {carried}: only for an on-demand challenge of the board")
    return lines


# ---------------------------------------------------------------------- the engine


class _Skip(Exception):
    """Why one challenge of a pull is left out."""


class _NoAnswer(CallFailed):
    """The platform gave no answer at all to a request (the network, a timeout)."""


@dataclass
class _Answer:
    endpoint: str  # "GET /api/v1/challs": the route as the table writes it
    status: int
    headers: httpx.Headers
    doc: object  # the parsed JSON, the token cut out of every string; _NOT_JSON
    page: bool  # a web page for a person (HTML), not an API answer


@dataclass
class Checked:
    """What `flightdeck http check` found."""

    lines: list[str]  # what was asked and what each path matched, made safe to show
    problems: int  # paths that matched nothing or the wrong thing
    instance: int = 0  # what the [instances] table's status found that a run could not use (counted apart: no path of the table)


class HttpCaller:
    """The [http] table's platform for one event: pull(), submit() and solved(), as a plugin's
    Caller has them (plugins.call.PlatformCaller), in process. Each call opens its own
    connections and closes them, so one caller serves any event loop. `token` is what the
    event's variable holds: the token, or with auth.link_param the link it is handed out in
    (_token_from; ValueError when that gives no token for this event). With auth.kind "exchange" it is turned into a session token once, and again (at
    most every RELOGIN_SECONDS) after the platform refuses the session with a 401."""

    label = LABEL
    pull_command = PULL_COMMAND
    source = NAME

    def __init__(self, config: HttpConfig, url: str, token: str, *, timeout: float = TIMEOUT, deadline: float = DEADLINE,
                 file_seconds: float = FILE_SECONDS, max_file_bytes: int = MAX_FILE_BYTES) -> None:
        self.config = config
        self.url = url
        self.timeout = timeout
        self.deadline = deadline  # a server that answers a byte at a time never outlasts it
        self.file_seconds = file_seconds
        self.max_file_bytes = max_file_bytes
        self.sleep: Callable[[float], Awaitable[None]] = asyncio.sleep  # between two looks at a submission
        self._base = _base_url(url)
        self._session: str | None = None  # the exchanged session token
        self._signed_in = 0.0  # time.monotonic() when it was last asked for
        kind, link = config.auth.kind, config.auth.link_param
        if not token:
            raise ValueError("the http platform needs the event's token: the variable event.token_env names is empty")
        self.token = token if link is None else _token_from(token, link, self._base)
        if kind == "cookie" and self.token.startswith(f"{config.auth.cookie}="):  # NAME=value, as a browser's tools copy a cookie
            self.token = self.token.removeprefix(f"{config.auth.cookie}=").strip()
            if not self.token:
                raise ValueError(f"the variable event.token_env names holds the cookie's name ({config.auth.cookie}=) and no value "
                                 "after it: put the cookie's value in it")
        written = quote(self.token, safe="")  # as a link of the platform's would write it: cut out of what is shown, too
        self._written = written if link is not None and written != self.token else None
        if (kind in ("bearer", "token", "header") and not _HEADER_VALUE.fullmatch(self.token)) or \
                (kind == "cookie" and not _COOKIE_VALUE.fullmatch(self.token)):
            raise ValueError("the event's token holds characters a request header cannot carry (spaces, line breaks, "
                             "non-ASCII): check the variable event.token_env names")

    # ------------------------------------------------------------------ the three calls

    async def pull(self, files_dir: Path, known: Sequence[str] = ()) -> PullReply:
        """The platform's challenges, as plugins.board takes them. The files of each challenge
        whose ref is not in `known` are downloaded into `files_dir`. A challenge that cannot
        be read or whose file cannot be fetched is left out and named in the reply's problems
        (a later pull asks again); CallFailed when the list itself cannot be read."""
        on_board = set(known)
        challenges: list[dict] = []
        problems: list[str] = []
        left = 0
        async with self._clients() as (http, bare):
            items = self._items(await self._read(http, self.config.list.request, {}, limit=MAX_LIST_BYTES))
            for n, item in enumerate(items):
                try:
                    found = self._challenge(item)
                    if found["ref"] not in on_board:
                        if self.config.detail is not None:
                            answer = await self._read(http, self.config.detail.request, {"ref": found["ref"]})
                            detail = self._read_fields("detail", self.config.detail.fields, answer.doc)
                            if "file_urls" in detail and "file_names" not in detail:  # the list's names are of the list's files
                                found.pop("file_names", None)
                            found.update(detail)
                        urls, names = found.pop("file_urls", []), found.pop("file_names", None)
                        found["files"] = await self._download(http, bare, Path(files_dir), f"{n:04d}", urls, names)
                    else:  # on the board already: its files were fetched when it was added
                        found.pop("file_urls", None)
                        found.pop("file_names", None)
                except _NoAnswer as exc:  # the platform is not answering: the rest would each wait as long
                    rest = len(items) - n
                    problems.append(f"{rest:,} challenge{'' if rest == 1 else 's'} not read: {exc}; the next pull asks again")
                    break
                except (_Skip, CallFailed) as exc:
                    left += 1
                    if left <= MAX_PROBLEMS:
                        problems.append(f"{self._label(item)}: {self._scrub(exc, limit=2 * MAX_SHOWN)}")
                    continue
                challenges.append(found)
            notes: tuple[str, ...] = ()
            if self.config.refuse is not None:
                try:
                    reason = await self._refusal(http)
                except CallFailed as exc:
                    notes = (f"{exc}; each flag asks again before it is sent",)
                else:
                    if reason is not None:
                        notes = (f"no flag is sent from here: {reason}",)
        if left > MAX_PROBLEMS:
            more = left - MAX_PROBLEMS
            problems.append(f"{more:,} more challenge{' was' if more == 1 else 's were'} left out too: the first {MAX_PROBLEMS} "
                            "are named, and they may share a cause")
        return PullReply(tuple(challenges), notes, tuple(problems))

    async def submit(self, ref: str, flag: str) -> Verdict:
        """Send one flag, once, and read the platform's word by the table's rules. CallFailed
        when there is no answer to read (timed_out: the flag may have reached the platform)."""
        cfg = self.config.submit
        if cfg is None:
            raise CallFailed("the [http] table has no [http.submit], so flightdeck has no route to send a flag by")
        values = {"ref": ref, "flag": flag}
        path = cfg.verdict_path
        async with self._clients() as (http, _):
            if self.config.refuse is not None:
                reason = await self._refusal(http)
                if reason is not None:
                    raise CallFailed(f"flightdeck did not send the flag: {reason}")
            answer = await self._send(http, cfg.request, values, body=cfg.body, sends_flag=True)
            try:
                self._refuse_page(answer)
            except CallFailed as exc:  # the flag left: a proxy's page may stand in front of a platform that took it
                raise CallFailed(f"the flag was sent, and then: {exc}", timed_out=True) from None
            word, value = self._word(cfg, path, answer)
            if word is None and cfg.poll is not None and 200 <= answer.status < 300:
                submission = self._scalar(cfg.poll.id_path, answer.doc)
                if submission is not None:  # the platform took the flag and will judge it: look until it has
                    path = cfg.poll.verdict_path or path
                    answer, word, value = await self._poll(http, cfg, path, {**values, "submission": submission})
        detail = self._text(cfg.detail_path, answer.doc)
        if word is None:
            said = f"HTTP {answer.status}"
            if path is not None:
                said += f", {path.text} is {json.dumps(value, ensure_ascii=False)}" if value is not None else f", nothing at {path.text}"
            return Verdict("unjudged", self._scrub(f"{said}: {detail}" if detail else said))
        retry_after = self._retry_after(cfg, answer) if word == "rate_limited" else None
        return Verdict(word, self._scrub(detail), self._count(cfg.tries_left_path, answer.doc), retry_after)

    def instance_wire(self) -> InstanceWire:
        """How the event's [instances] table reaches this platform (platform/instances.py): the
        same address and the same auth as the three calls, a sign-in's session included."""
        return InstanceWire(self)

    def session_refused(self) -> None:
        """The platform answered 401 to the exchanged session: it is forgotten, so the next
        request signs in again (at most every RELOGIN_SECONDS)."""
        if self._session is not None and time.monotonic() - self._signed_in >= RELOGIN_SECONDS:
            self._session = None

    async def solved(self) -> set[str]:
        """The refs of the challenges the platform lists as solved for this account."""
        cfg = self.config.solved
        async with self._clients() as (http, _):
            answer = await self._read(http, cfg.request, {})
        return set(self._refs(cfg.refs, answer))

    # ------------------------------------------------------------------ the dry run

    async def check(self, show: int = 2, instances: InstancesConfig | None = None) -> Checked:
        """`flightdeck http check`: the sign-in, the list and the solved list, and what each
        path matched for the first `show` challenges. Nothing is submitted and no file is
        downloaded. With `instances` (the profile's [instances] table) the instancer's status
        is asked for the first challenge marked on-demand, when that route is a GET: nothing
        is ever started, renewed or stopped. CallFailed when a request gets no answer to read."""
        cfg, lines, problems = self.config, [], 0
        marked: list[str] = []  # the refs of the challenges the table marks on-demand, in the list's order
        async with self._clients() as (http, _):
            if cfg.auth.request is not None:
                await self._auth(http)
                lines.append(f"sign in  {cfg.auth.request}: {cfg.auth.token_path.text} matched a session token "
                             f"({len(self._session or '')} characters)")
            answer = await self._read(http, cfg.list.request, {}, limit=MAX_LIST_BYTES)
            items = self._items(answer)
            lines.append(f"list     {cfg.list.request}: HTTP {answer.status}, {cfg.list.items.text} matched "
                         f"{len(items):,} challenge{'' if len(items) == 1 else 's'}")
            listed: list[str] = []
            unreadable = 0  # of the challenges past the first `show`
            for n, item in enumerate(items):
                ref = self._scalar(cfg.list.ref, item)
                if ref is not None and valid_ref(ref):
                    listed.append(ref)
                    if self._marked("list", cfg.list.fields, item):
                        marked.append(ref)
                if n >= show:
                    try:
                        self._challenge(item)
                    except _Skip:
                        unreadable += 1
                    continue
                lines.append(f"  challenge {n + 1}")
                problems += self._show_fields(lines, "list", {"ref": cfg.list.ref, **cfg.list.fields}, item, required=("ref", "name"))
                if ref is None or not valid_ref(ref):
                    continue
                if cfg.detail is not None:
                    try:
                        detail = await self._read(http, cfg.detail.request, {"ref": ref})
                    except _NoAnswer:
                        raise
                    except CallFailed as exc:
                        lines.append(f"    detail  {exc}")
                        problems += 1
                        continue
                    lines.append(f"    detail  {cfg.detail.request}: HTTP {detail.status}")
                    problems += self._show_fields(lines, "detail", cfg.detail.fields, detail.doc, required=())
                    if ref not in marked and self._marked("detail", cfg.detail.fields, detail.doc):
                        marked.append(ref)
            if len(items) > show:
                lines.append(f"  the other {len(items) - show:,}: " + ("each has a ref and a name" if not unreadable else
                             f"{unreadable:,} cannot be read (a pull names each, with the reason)"))
                problems += unreadable
            if cfg.refuse is not None:
                try:
                    reason = await self._refusal(http)
                except CallFailed as exc:
                    lines.append(f"refuse   {exc}: a run sends no flag while this lasts")
                    problems += 1
                else:
                    if reason is None:
                        lines.append(f"refuse   {cfg.refuse.request}: nothing at {cfg.refuse.path.text}, so flags can be sent")
                    else:
                        lines.append(f"refuse   no flag would be sent: {reason}")
                        problems += 1
            answer = await self._read(http, cfg.solved.request, {})
            refs = self._refs(cfg.solved.refs, answer)
            on_list = len(set(refs) & set(listed))
            lines.append(f"solved   {cfg.solved.request}: HTTP {answer.status}, {cfg.solved.refs.text} matched {len(refs):,} "
                         f"ref{'' if len(refs) == 1 else 's'}, {on_list:,} of them on the list")
            if refs and not on_list and listed:
                lines.append("  none of the solved refs is a ref on the list: is solved.refs the same id as list.ref?")
                problems += 1
        instance = 0
        if instances is not None:  # after the clients are closed: the instancer is asked from a worker thread, on its own loop
            instance = await self._check_instance(lines, instances, marked)
        return Checked(lines, problems, instance)

    def _marked(self, where: str, fields: Mapping[str, JsonPath], node: object) -> bool:
        """Whether the table's `instance` path marks this challenge on-demand."""
        if "instance" not in fields:
            return False
        try:
            return "instance" in self._read_fields(where, {"instance": fields["instance"]}, node)
        except _Skip:
            return False

    async def _check_instance(self, lines: list[str], instances: InstancesConfig, marked: Sequence[str]) -> int:
        """The [instances] table's status route, asked once for the first challenge marked
        on-demand, as a run asks it (InstanceClient, through instance_wire). Only a GET is
        sent: a status route of another method is named and not asked, since nothing here may
        change anything. How many problems it found."""
        method, path = instances.routes.status
        route = f"{method} {(API if instances.routes.api else '') + path}"
        if method != "GET":
            lines.append(f"instance {route}: not asked: the status route is a {method}, and check sends only requests that "
                         "change nothing (a GET)")
            return 0
        if not marked:
            paths = [where for where, table in (("list", self.config.list.fields),
                     ("detail", self.config.detail.fields if self.config.detail is not None else {})) if "instance" in table]
            if not paths:
                lines.append(f"instance {route}: not asked: the [http] table has no list.instance or detail.instance path, so a "
                             "run marks no challenge on-demand and starts no instance")
                return 1
            lines.append(f"instance {route}: not asked: no challenge is marked on-demand ({', '.join(f'{w}.instance' for w in paths)} "
                         "matched no value)")
            return 0
        ref = marked[0]
        shown = untrusted(ref, one_line=True)
        how = f"for {shown}, the first of {len(marked):,} on-demand"
        client = InstanceClient(None, None, {ref: ref}, instances, wire=self.instance_wire(), timeout=self.timeout)
        try:
            got = await asyncio.to_thread(client.status, ref)
        except (InstancePending, InstanceFailed, InstanceBusy) as exc:  # the platform answered, and said what its instance does
            lines.append(f"instance {route} {how}: {exc}")
            return 0
        except InstanceError as exc:  # a refusal, an answer the table does not read, no answer
            lines.append(f"instance {route} {how}: {exc}")
            return 1
        finally:
            client.close()
        if got is None:
            lines.append(f"instance {route} {how}: no instance runs for it, and none was started (a 400 or a 404 reads so too: "
                         "if one runs on the site, the status route is wrong)")
            return 0
        ends = f", ends in {max(0, round(got.expires_at - time.time())):,} s" if got.expires_at is not None else ""
        left = f"; left out: {'; '.join(got.left_out)}" if got.left_out else ""
        lines.append(f"instance {route} {how}: running at {untrusted(', '.join(got.urls(web=False)), one_line=True)}{ends}{left}")
        return 0

    def _show_fields(self, lines: list[str], where: str, fields: Mapping[str, JsonPath], node: object, *, required: Sequence[str]) -> int:
        """A line for each field's path and what it matched in `node`; how many are problems."""
        problems = 0
        for name, path in fields.items():
            found = [value for value in path.find(node) if value is not None]
            many = name in ("file_urls", "file_names")
            if not found and many:
                said = "no values"  # a challenge with no files
            elif not found:
                said = "matched nothing" + (": REQUIRED" if name in required else " (left out)")
                problems += name in required
            elif many:
                said = f"{len(found)} value{'' if len(found) == 1 else 's'}: {', '.join(self._shape(v) for v in found[:3])}" \
                       + (", ..." if len(found) > 3 else "")
            elif len(found) > 1:
                said = f"matched {len(found)} values, and one is wanted"
                problems += 1
            else:
                said = self._shape(found[0])
            lines.append(f"    {name:<13}{path.text:<26} {said}")
        if not problems:  # each path matched one thing: is it the kind of thing a pull takes?
            try:
                self._read_fields(where, {k: v for k, v in fields.items() if k != "ref"}, node)
            except _Skip as exc:
                lines.append(f"    a pull would leave it out: {self._scrub(exc)}")
                problems += 1
        return problems

    def _shape(self, value: object) -> str:
        """A value of the answer for the dry run: short, the token cut out, safe to show."""
        if isinstance(value, str):
            return json.dumps(self._scrub(value, limit=60), ensure_ascii=False) if len(value) <= 60 else \
                f"a string of {len(value):,} characters, starting {json.dumps(self._scrub(value[:40], limit=44), ensure_ascii=False)}"
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, (int, float)):
            return repr(value)
        return _kind(value)

    # ------------------------------------------------------------------ reading an answer

    def _items(self, answer: _Answer) -> list:
        """The list's challenges. CallFailed when the answer is not shaped as list.items says,
        or lists more than one pull takes."""
        path = self.config.list.items
        wrong = path.shaped(answer.doc)
        if wrong is not None:
            raise CallFailed(f"{answer.endpoint} answered, but list.items ({path.text}) does not fit its answer: {wrong}. "
                             f"`{CHECK_COMMAND} EVENT.toml` shows what each path matches")
        items = path.find(answer.doc)
        if len(items) > MAX_CHALLENGES:
            raise CallFailed(f"the platform lists {len(items):,} challenges, more than the {MAX_CHALLENGES:,} flightdeck takes "
                             "from one pull: nothing was added")
        return items

    def _refs(self, path: JsonPath, answer: _Answer) -> list[str]:
        wrong = path.shaped(answer.doc)
        if wrong is not None:
            raise CallFailed(f"{answer.endpoint} answered, but solved.refs ({path.text}) does not fit its answer: {wrong}")
        refs = [_as_ref(value) for value in path.find(answer.doc)]
        if not all(valid_ref(ref) for ref in refs):
            raise CallFailed(f"{answer.endpoint} answered, but solved.refs ({path.text}) matched a value that is not a "
                             "challenge's ref (a string or a whole number)")
        return refs

    def _challenge(self, item: object) -> dict:
        """One challenge of the list, with the keys plugins.board takes (and file_urls,
        file_names for the download). _Skip when a required path matches nothing."""
        cfg = self.config.list
        ref = _as_ref(self._one("list.ref", cfg.ref, item, (str, int), "a string or a whole number", required=True))
        if not valid_ref(ref):
            raise _Skip(f"list.ref ({cfg.ref.text}) matched a value that is not a challenge's ref")
        return {"ref": ref, **self._read_fields("list", cfg.fields, item)}

    def _read_fields(self, where: str, fields: Mapping[str, JsonPath], node: object) -> dict:
        out: dict = {}
        for name, path in fields.items():
            label = f"{where}.{name}"
            if name in ("file_urls", "file_names"):
                found = [value for value in path.find(node) if value is not None]
                if not all(isinstance(value, str) for value in found):
                    raise _Skip(f"{label} ({path.text}) matched a value that is not a string")
                out[name] = found
            elif name == "instance":  # one value or none; any value but null, false, 0 and "" means it has an instancer
                found = [value for value in path.find(node) if value not in (None, False, 0, "")]
                if len(found) > 1:
                    raise _Skip(f"{label} ({path.text}) matched {len(found)} values, and one is wanted")
                table = self.config.list if where == "list" else self.config.detail
                wanted = table.instance_values if table is not None else None
                if found and (wanted is None or (isinstance(found[0], str) and found[0] in wanted)):
                    out[name] = ON_DEMAND
            elif name in ("name", "category", "description"):
                value = self._one(label, path, node, (str,), "a string", required=name == "name" and where == "list")
                if value is not None:
                    out[name] = value
            else:  # points, solves, max_attempts: the board checks that each is a whole number, 0 or more
                value = self._one(label, path, node, (int, float), "a number")
                if value is not None:
                    out[name] = int(value) if isinstance(value, float) and value.is_integer() else value
        if "file_names" in out and len(out["file_names"]) != len(out.get("file_urls", ())):
            raise _Skip(f"{where}.file_names matched {len(out['file_names'])} values and {where}.file_urls "
                        f"{len(out.get('file_urls', ()))}: each file needs one of each")
        return out

    def _one(self, where: str, path: JsonPath, node: object, kinds: tuple, wanted: str, *, required: bool = False) -> object:
        found = [value for value in path.find(node) if value is not None]
        if not found:
            if required:
                raise _Skip(f"{where} ({path.text}) matched nothing")
            return None
        if len(found) > 1:
            raise _Skip(f"{where} ({path.text}) matched {len(found)} values, and one is wanted")
        if isinstance(found[0], bool) or not isinstance(found[0], kinds):
            raise _Skip(f"{where} ({path.text}) matched {_kind(found[0])}, not {wanted}")
        return found[0]

    def _scalar(self, path: JsonPath | None, doc: object) -> str | None:
        """The one string, number or boolean at `path`, as the text a rule's key is compared
        with (true, false, a number's digits); None when the path matches anything else."""
        if path is None or doc is _NOT_JSON:
            return None
        found = [value for value in path.find(doc) if value is not None]
        if len(found) != 1:
            return None
        value = found[0]
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, int) or (isinstance(value, float) and value.is_integer()):
            return str(int(value))
        return value if isinstance(value, str) and len(value) <= MAX_VALUE else None

    def _text(self, path: JsonPath | None, doc: object) -> str:
        value = self._scalar(path, doc) if path is not None else None
        return value if value is not None else ""

    def _count(self, path: JsonPath | None, doc: object) -> int | None:
        value = self._scalar(path, doc)
        return int(value) if value is not None and re.fullmatch(r"[0-9]{1,9}", value) else None

    def _word(self, cfg: Submit, path: JsonPath | None, answer: _Answer) -> tuple[str | None, str | None]:
        """(the verdict the table's rules give this answer, or None; the value the rules looked at)."""
        value = self._scalar(path, answer.doc)
        word = cfg.verdicts.get(value) if value is not None else None
        return (word if word is not None else cfg.status.get(answer.status)), value

    def _retry_after(self, cfg: Submit, answer: _Answer) -> float | None:
        if cfg.retry_after_path is not None and answer.doc is not _NOT_JSON:
            found = [v for v in cfg.retry_after_path.find(answer.doc) if isinstance(v, (int, float)) and not isinstance(v, bool)]
            if len(found) == 1 and 0 <= found[0] < 1e12:
                return float(found[0]) * UNITS[cfg.retry_after_unit]
        asked = _retry_after(answer.headers.get("retry-after"))
        return max(0.0, asked) if asked is not None else None

    async def _poll(self, http: httpx.AsyncClient, cfg: Submit, path: JsonPath | None,
                    values: dict[str, str]) -> tuple[_Answer, str | None, str | None]:
        """Look at the submission until the platform has judged it, at most poll.at_most
        times. CallFailed (the flag may have been accepted since) when it is pending still."""
        poll = cfg.poll
        assert poll is not None and path is not None
        value = None
        for look in range(poll.at_most):
            if look:
                await self.sleep(poll.every)
            try:
                answer = await self._send(http, poll.request, values)
                self._refuse_page(answer)
            except CallFailed as exc:
                raise CallFailed(f"the flag was sent, and then: {exc}", timed_out=True) from None
            word, value = self._word(cfg, path, answer)
            if value not in poll.pending:
                return answer, word, value
        raise CallFailed(f"the flag was sent, and the platform had not judged it after {poll.at_most} looks, "
                         f"{poll.every:g} s apart ({path.text} is {json.dumps(self._scrub(value), ensure_ascii=False)})", timed_out=True)

    async def _refusal(self, http: httpx.AsyncClient) -> str | None:
        """[http.refuse]'s reason when the platform's answer says it wants what flightdeck
        cannot send, else None. Asked without the token, each time, so a setting the site
        changes is seen at the next flag. CallFailed when there is no answer to read: then
        nobody knows, and no flag goes."""
        refuse = self.config.refuse
        assert refuse is not None
        why = "flightdeck could not tell whether the platform takes a flag as flightdeck sends it"
        try:
            answer = await self._request(http, refuse.request, {}, None, auth=False)
        except CallFailed as exc:
            raise CallFailed(f"{why}: {exc}") from None
        if answer.page or answer.doc is _NOT_JSON or not 200 <= answer.status < 300:
            raise CallFailed(f"{why}: {answer.endpoint} was answered with HTTP {answer.status}{_phrase(answer.status)}"
                             + ("" if answer.doc is not _NOT_JSON else ", not JSON"))
        found = [value for value in refuse.path.find(answer.doc) if value is not None and value is not False and value not in ("", [], {})]
        return f"{_show(refuse.reason)} ({refuse.request}: {refuse.path.text} has a value)" if found else None

    def _refuse_page(self, answer: _Answer) -> None:
        """A web page where JSON is expected is a stop for a human: never read as an answer, never worked around."""
        if answer.page:
            raise CallFailed(
                f"{answer.endpoint} was answered with a web page for a person, not an API answer (not JSON, HTTP "
                f"{answer.status}{_phrase(answer.status)}): a login page, or a check that wants a human (a CAPTCHA), unless "
                "event.url or the route is not the platform's. Open it in a browser; flightdeck does not try to pass such a page")

    async def _read(self, http: httpx.AsyncClient, route: Route, values: Mapping[str, str], *,
                    limit: int = MAX_ANSWER_BYTES) -> _Answer:
        """A GET whose answer must be JSON with a 2xx status. CallFailed otherwise, with the platform's own words."""
        answer = await self._send(http, route, values, limit=limit)
        self._refuse_page(answer)
        if not 200 <= answer.status < 300:
            said = self._scrub(_message(answer.doc)) if answer.doc is not _NOT_JSON else ""
            raise CallFailed(f"{answer.endpoint} was answered with HTTP {answer.status}{_phrase(answer.status)}" + (f": {said}" if said else ""))
        if answer.doc is _NOT_JSON:
            raise CallFailed(f"{answer.endpoint} was answered with something that is not JSON (HTTP {answer.status})")
        return answer

    # ------------------------------------------------------------------ the wire

    @contextlib.asynccontextmanager
    async def _clients(self) -> AsyncIterator[tuple[httpx.AsyncClient, httpx.AsyncClient]]:
        """(the client for event.url's origin, the client for a file on another host). Neither
        has the token in it: each request to the origin is given it by _auth, the other
        client never. Neither follows a redirect by itself."""
        timeout = httpx.Timeout(self.timeout, connect=min(self.timeout, CONNECT_TIMEOUT))
        agent = {"User-Agent": f"ctf-flightdeck/{__version__}"}
        async with httpx.AsyncClient(headers={**agent, "Accept": "application/json"}, timeout=timeout, follow_redirects=False) as http, \
                httpx.AsyncClient(headers=agent, timeout=timeout, follow_redirects=False) as bare:
            yield http, bare

    def _address(self, route: Route, values: Mapping[str, str]) -> httpx.URL:
        """The route's address under event.url, each placeholder percent-encoded whole (a ref
        of "../x" is one path segment). CallFailed unless it is on event.url's origin, and
        for a value of "." or "..", which no encoding keeps as one segment (httpx folds it)."""
        filled = {**values, **({"game": self.config.game} if self.config.game is not None else {})}
        for match in _PLACEHOLDER.finditer(route.path):
            if filled[match.group(1)] in (".", ".."):
                raise CallFailed(f"{route}: {{{match.group(1)}}} is {filled[match.group(1)]}, which would name another route, "
                                 "so flightdeck did not send it")
        path = _PLACEHOLDER.sub(lambda match: quote(filled[match.group(1)], safe=""), route.path)
        target = None
        with contextlib.suppress(httpx.InvalidURL):
            target = httpx.URL(str(self._base).rstrip("/") + path)
        if target is None or not _same_origin(target, self._base) or target.userinfo:
            raise CallFailed(f"{route} does not stay on the event's address, so flightdeck did not send it")
        return target

    async def _auth(self, http: httpx.AsyncClient) -> dict[str, str]:
        """The header that carries the token, for a request to event.url's origin."""
        auth = self.config.auth
        if auth.kind == "bearer":
            return {"Authorization": f"Bearer {self.token}"}
        if auth.kind == "token":
            return {"Authorization": f"Token {self.token}"}
        if auth.kind == "header":
            return {str(auth.header): self.token}
        if auth.kind == "cookie":
            return {"Cookie": f"{auth.cookie}={self.token}"}
        if self._session is None:
            session = await self._sign_in(http)
            if self._session is None:  # another sign-in (the instancer's thread, another call) may have ended first
                self._session = session
        return {"Authorization": f"{auth.scheme} {self._session}"}

    async def _sign_in(self, http: httpx.AsyncClient) -> str:
        """The session token the platform gives for the event's token (auth.kind "exchange")."""
        auth = self.config.auth
        assert auth.request is not None and auth.body is not None and auth.token_path is not None
        self._signed_in = time.monotonic()
        try:
            answer = await self._request(http, auth.request, {}, _filled(auth.body, {"token": self.token, **self._game()}), auth=False)
        except CallFailed as exc:
            raise type(exc)(f"could not sign in: {exc}") from None
        self._refuse_page(answer)
        if not 200 <= answer.status < 300 or answer.doc is _NOT_JSON:
            said = self._scrub(_message(answer.doc)) if answer.doc is not _NOT_JSON else ""
            raise CallFailed(f"could not sign in: {answer.endpoint} was answered with HTTP {answer.status}{_phrase(answer.status)}"
                             + (f": {said}" if said else "") + " (is the token the right one for this event?)")
        found = auth.token_path.find(answer.doc)
        session = found[0] if len(found) == 1 else None
        if session == TOKEN_MARK and self._session is not None:
            # the answer was cut (_cut) of the session another sign-in got meanwhile: the platform gave that one again
            return self._session
        if not isinstance(session, str) or not _HEADER_VALUE.fullmatch(session) or len(session) > MAX_SESSION:
            raise CallFailed(f"could not sign in: {answer.endpoint} answered, but auth.token_path ({auth.token_path.text}) "
                             "matched no session token in its answer")
        return session

    def _game(self) -> dict[str, str]:
        return {"game": self.config.game} if self.config.game is not None else {}

    async def _send(self, http: httpx.AsyncClient, route: Route, values: Mapping[str, str], *,
                    body: Mapping[str, object] | None = None, limit: int = MAX_ANSWER_BYTES, sends_flag: bool = False) -> _Answer:
        """One request with the token, once. A 401 to an exchanged session forgets it, so a
        later call signs in again; this one is answered as it was."""
        content = None
        if body is not None:
            try:
                content = _filled(body, {**values, **self._game()})
            except ValueError as exc:
                raise CallFailed(str(exc)) from None
        answer = await self._request(http, route, values, content, auth=True, limit=limit, sends_flag=sends_flag)
        if answer.status == 401:
            self.session_refused()
        return answer

    async def _request(self, http: httpx.AsyncClient, route: Route, values: Mapping[str, str], content: object, *, auth: bool,
                       limit: int = MAX_ANSWER_BYTES, sends_flag: bool = False) -> _Answer:
        """One request to event.url's origin and its answer, read up to `limit` bytes. Never
        sent twice, and a redirect is an answer flightdeck refuses, not a new place to send
        the token. `sends_flag`: a failure after the request left says the flag may have arrived."""
        endpoint = str(route)
        target = self._address(route, values)
        headers = await self._auth(http) if auth else {}
        data = None
        if content is not None:
            data = json.dumps(content, ensure_ascii=True).encode("ascii")
            headers["Content-Type"] = "application/json"
        failure, sent = None, False
        try:
            async with asyncio.timeout(self.deadline):
                async with http.stream(route.method, target, headers=headers, content=data) as response:
                    status, got = response.status_code, response.headers
                    raw = await _read_body(response, limit)
        except httpx.HTTPError as exc:  # never chained: its request holds the token
            failure, sent = type(exc).__name__, not isinstance(exc, (httpx.ConnectError, httpx.ConnectTimeout))
        except TimeoutError:
            failure, sent = f"no whole answer within {self.deadline:g} s", True
        if failure is not None:
            raise _NoAnswer(f"{endpoint} got no answer ({failure})", timed_out=sends_flag and sent)
        if raw is None:
            raise CallFailed(f"{endpoint} was answered with more than {limit:,} bytes", timed_out=sends_flag)
        if 300 <= status < 400:
            raise CallFailed(f"{endpoint} was answered with a redirect (HTTP {status}), which flightdeck does not follow with "
                             "your token: is event.url the platform's own address?", timed_out=sends_flag)
        doc = self._cut(_parse(raw))
        kind_of = got.get("content-type", "").lower()
        head = raw[:512].lstrip().lower()
        page = doc is _NOT_JSON and (kind_of.startswith(("text/html", "application/xhtml")) or head.startswith((b"<!doctype html", b"<html")))
        return _Answer(endpoint, status, got, doc, page)

    # ------------------------------------------------------------------ files

    async def _download(self, http: httpx.AsyncClient, bare: httpx.AsyncClient, files_dir: Path, sub: str, urls: Sequence[str],
                        names: Sequence[str] | None) -> list[str]:
        """Fetch a challenge's files into files_dir/sub; their paths relative to files_dir.
        _Skip (the challenge is left out) when one cannot be fetched."""
        if not urls:
            return []
        folder = files_dir / sub
        folder.mkdir(parents=True, exist_ok=True)
        fetched: list[str] = []
        for i, raw in enumerate(urls):
            target = self._file_address(raw)
            name = _file_name(names[i] if names is not None else unquote(target.path.rsplit("/", 1)[-1]))
            if name in [Path(rel).name for rel in fetched]:
                raise _Skip(f"two of its files are named {_quote(name)}")
            await self._fetch(http, bare, target, folder / name, name)
            fetched.append(f"{sub}/{name}")
        return fetched

    def _file_address(self, raw: str) -> httpx.URL:
        """A file's address as the platform lists it: a path under event.url's origin, or a
        whole URL. _Skip for one flightdeck does not fetch."""
        target = None
        if raw.strip() and raw == untrusted(raw, one_line=True) and len(raw) <= 2048:
            with contextlib.suppress(httpx.InvalidURL):
                target = self._base.join(raw.strip())
        if target is None or target.scheme not in ("http", "https") or not target.host or target.userinfo:
            raise _Skip("one of its file addresses is not a URL flightdeck can use")
        return target

    async def _fetch(self, http: httpx.AsyncClient, bare: httpx.AsyncClient, target: httpx.URL, dest: Path, name: str) -> None:
        """One file, its redirects followed (MAX_REDIRECTS). The token goes along only while
        the address is on event.url's origin and the table says files_auth; once the download
        is on another host it never comes back to the token."""
        left_origin = False
        for _ in range(MAX_REDIRECTS + 1):
            left_origin = left_origin or not _same_origin(target, self._base)
            if left_origin and target.scheme != "https":
                raise _Skip(f"its file {_quote(name)} is on another host ({_origin_text(target)}) over http; flightdeck fetches "
                            "a file from another host only over https: fetch it by hand")
            client = bare if left_origin else http
            headers = await self._auth(http) if not left_origin and self.config.files_auth else {}
            failure = location = None
            try:
                async with asyncio.timeout(self.file_seconds):
                    async with client.stream("GET", target, headers={**headers, "Accept": "*/*"}) as response:
                        status = response.status_code
                        if 300 <= status < 400:
                            location = response.headers.get("location") or ""
                        elif 200 <= status < 300:
                            await self._save(response, dest, name)
                            return
            except httpx.HTTPError as exc:  # never chained: its request may hold the token
                failure = type(exc).__name__
            except TimeoutError:
                raise _Skip(f"its file {_quote(name)} was not all here within {self.file_seconds:g} s: fetch it by hand") from None
            if failure is not None:
                if left_origin:
                    raise _Skip(f"its file {_quote(name)} could not be fetched from {_origin_text(target)} ({failure})")
                raise _NoAnswer(f"the download of {_quote(name)} got no answer ({failure})")
            if location is None:
                raise _Skip(f"its file {_quote(name)} could not be fetched: HTTP {status}{_phrase(status)} from {_origin_text(target)}")
            moved = None
            with contextlib.suppress(httpx.InvalidURL):
                moved = target.join(location)
            if not location or moved is None or moved.scheme not in ("http", "https") or not moved.host or moved.userinfo:
                raise _Skip(f"its file {_quote(name)} was answered with a redirect flightdeck cannot follow")
            target = moved
        raise _Skip(f"its file {_quote(name)} was answered with more than {MAX_REDIRECTS} redirects")

    async def _save(self, response: httpx.Response, dest: Path, name: str) -> None:
        too_big = _Skip(f"its file {_quote(name)} is over {self.max_file_bytes:,} bytes, more than flightdeck downloads by itself: "
                        "fetch it by hand")
        length = response.headers.get("content-length", "")
        if length.isdigit() and int(length) > self.max_file_bytes:
            raise too_big
        done = False
        try:
            with open(dest, "xb") as out:
                size = 0
                async for chunk in response.aiter_bytes():
                    size += len(chunk)
                    if size > self.max_file_bytes:
                        raise too_big
                    out.write(chunk)
            done = True
        except OSError as exc:
            raise _Skip(f"its file {_quote(name)} could not be written ({exc.strerror or type(exc).__name__})") from None
        finally:
            if not done:
                with contextlib.suppress(OSError):
                    os.unlink(dest)

    # ------------------------------------------------------------------ what is shown

    def _secrets(self) -> list[str]:
        return [secret for secret in (self._written, self.token, self._session) if secret]

    def _cut(self, value: object) -> object:
        """`value` (parsed JSON) with the token and the session token cut out of every string, keys included."""
        if isinstance(value, str):
            for secret in self._secrets():
                value = value.replace(secret, TOKEN_MARK)
            return value
        if isinstance(value, list):
            return [self._cut(item) for item in value]
        if isinstance(value, dict):
            return {self._cut(key): self._cut(item) for key, item in value.items()}
        return value

    def _scrub(self, text: object, *, limit: int = MAX_SHOWN) -> str:
        """The platform's words for a message: no token, safe to show, one line, cut short."""
        shown = str(self._cut("" if text is None else str(text)))
        shown = untrusted(shown, one_line=True).strip()
        return shown if len(shown) <= limit else shown[:limit - 3] + "..."

    def _label(self, item: object) -> str:
        """What a challenge of the list is called in a problem: its name, else its ref."""
        cfg = self.config.list
        for path in (cfg.fields["name"], cfg.ref):
            found = path.find(item)
            if len(found) == 1 and isinstance(found[0], (str, int)) and not isinstance(found[0], bool) and str(found[0]).strip():
                return self._scrub(str(found[0]).strip(), limit=80)
        return "a challenge with no name and no ref"


class InstanceWire:
    """The http platform as platform/instances.InstanceClient reaches it: event.url's address,
    and the header that carries the token as the [http] table's auth sends it. With auth.kind
    "exchange" that is the session the sign-in gives, asked for when there is none yet: the
    same session as the three calls'. Called from a worker thread (a run's instances are asked
    there), so the sign-in runs on a loop of its own in that thread. Nothing of the token is
    ever in a message (short())."""

    def __init__(self, caller: HttpCaller) -> None:
        self._caller = caller
        self.root = str(caller._base).rstrip("/")
        self.game = caller.config.game  # {game} in an [instances] route (GZCTF's)

    def __repr__(self) -> str:
        return f"InstanceWire({self.root!r}, token=set)"

    def headers(self) -> dict[str, str]:
        try:
            carried = asyncio.run(self._carried())
        except CallFailed as exc:
            raise InstanceError(self._caller._scrub(exc)) from None
        return {"User-Agent": f"ctf-flightdeck/{__version__}", "Accept": "application/json", **carried}

    async def _carried(self) -> dict[str, str]:
        async with self._caller._clients() as (http, _):
            return await self._caller._auth(http)

    def short(self, text: str) -> str:
        return self._caller._scrub(text)

    def unauthorized(self) -> None:
        self._caller.session_refused()


CHECK_COMMAND = "flightdeck http check"


def _as_ref(value: object) -> object:
    """A ref as the board keeps it: the platform's string, or its whole number as digits."""
    return str(value) if isinstance(value, int) and not isinstance(value, bool) else value


def _filled(body: object, values: Mapping[str, str]) -> object:
    """The body with its placeholders filled: each value a JSON string, {ref:int} a JSON
    number. ValueError when {ref:int} is asked of a ref that is not a whole number."""
    if isinstance(body, str):
        if body == "{ref:int}":
            if not _WHOLE_NUMBER.fullmatch(values["ref"]):
                raise ValueError("the table sends the challenge's ref as a number ({ref:int}), and this challenge's ref is not one")
            return int(values["ref"])
        return _PLACEHOLDER.sub(lambda match: values[match.group(1)], body)
    if isinstance(body, list):
        return [_filled(item, values) for item in body]
    if isinstance(body, Mapping):
        return {key: _filled(item, values) for key, item in body.items()}
    return body


def _token_from(value: str, param: str, base: httpx.URL) -> str:
    """The token in what the event's variable holds, for a table whose auth.link_param says
    the platform hands its token out in a link (rCTF: /login?token=...). `value` is that
    link, the token as the link writes it (percent-encoded: rCTF's is base64, so its + / =
    stand there as %2B %2F %3D) or the token itself; a + is never read as a space.
    ValueError, which never shows the value: a link with no such parameter, and a link to
    another site than event.url (told by its host), whose token is another event's."""
    where, fix = "the variable event.token_env names", "put your login link in it, or the token alone"
    written = value
    if value.lower().startswith(("http://", "https://")):
        try:
            link, query = httpx.URL(value), urlsplit(value).query
        except (httpx.InvalidURL, ValueError):
            link, query = None, ""
        if link is None or not link.host:
            raise ValueError(f"{where} holds a link flightdeck cannot read: {fix}")
        if link.host != base.host:
            raise ValueError(f"{where} holds a link to another site ({_origin_text(link)}, and event.url is {_origin_text(base)}): "
                             f"flightdeck does not send one site's token to another. Put this event's login link in it, or the "
                             "token alone")
        written = next((raw for key, _, raw in (part.partition("=") for part in query.split("&")) if unquote(key) == param), "")
        if not written:
            raise ValueError(f"{where} holds a link with no {param} parameter in it: {fix}")
    try:
        return unquote(written, errors="strict")
    except UnicodeDecodeError:
        raise ValueError(f"{where} holds a %XX that stands for no character: {fix}") from None


def _base_url(url: object) -> httpx.URL:
    """event.url as the origin every route is under; its path ends in "/"."""
    parsed = None
    if isinstance(url, str) and url.lower().startswith(("http://", "https://")):
        with contextlib.suppress(httpx.InvalidURL):
            parsed = httpx.URL(url)
    if parsed is None or not parsed.host or parsed.userinfo or parsed.query or parsed.fragment:
        raise ValueError("event.url must be the platform's address: http(s), a host, no user name, no query")
    return parsed.copy_with(path=parsed.path.rstrip("/") + "/")


def _same_origin(a: httpx.URL, b: httpx.URL) -> bool:
    return (a.scheme, a.host, a.port) == (b.scheme, b.host, b.port)


def _origin_text(url: httpx.URL) -> str:
    """scheme://host[:port], safe to show: never a path or a query (a file's may hold a credential)."""
    host = f"[{url.host}]" if ":" in url.host else url.host
    return untrusted(f"{url.scheme}://{host}" + (f":{url.port}" if url.port is not None else ""), one_line=True)


def _file_name(name: str) -> str:
    """A file's name as it lands in the challenge's folder. _Skip unless it is a plain name."""
    if not name or name in (".", "..") or "/" in name or "\\" in name or "\x00" in name \
            or untrusted(name, one_line=True) != name or name.strip() != name or len(name.encode("utf-8", "replace")) > 255:
        raise _Skip("one of its files has a name that is not a plain file name (a path, hidden characters, or none at all)")
    return name


async def _read_body(response: httpx.Response, limit: int) -> bytes | None:
    """The body, or None when it is longer than `limit` bytes."""
    chunks, size = [], 0
    async for chunk in response.aiter_bytes():
        size += len(chunk)
        if size > limit:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


def _parse(raw: bytes) -> object:
    try:
        return json.loads(raw, parse_constant=_no_constant)
    except (ValueError, RecursionError):  # also UnicodeDecodeError
        return _NOT_JSON


def _no_constant(name: str) -> float:
    raise ValueError(f"{name} is not JSON")


def _kind(value: object) -> str:
    """What a JSON value is, in words."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true or false"
    if isinstance(value, (int, float)):
        return "a number"
    if isinstance(value, str):
        return "a string"
    if isinstance(value, list):
        return f"a list of {len(value):,}"
    if isinstance(value, dict):
        return f"an object ({', '.join(untrusted(str(key), one_line=True)[:24] for key in list(value)[:6])}{', ...' if len(value) > 6 else ''})"
    return type(value).__name__


def _phrase(code: int) -> str:
    try:
        return f" ({HTTPStatus(code).phrase})"
    except ValueError:
        return ""


def _quote(text: str) -> str:
    safe = untrusted(text, one_line=True)
    return json.dumps(safe if len(safe) <= 60 else safe[:57] + "...", ensure_ascii=False)


def _show(value: object) -> str:
    return untrusted(str(value), one_line=True)
