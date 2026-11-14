"""A challenge's own container on CTFd: started, renewed and stopped through a container plugin.

Some CTFd challenges have no fixed address: the platform starts a container for the team when
asked, a few at a time (a small cap per team), and stops it after a while. A board lists no
`urls` for such a challenge; its challenge.json says `"instance": "on-demand"` instead, and an
event profile's [instances] table says how to ask (BOARDS.md):

    [instances]
    plugin = "docker_per_team"      # a named plugin shape (PLUGINS), or the four routes below
    types = ["container"]           # CTFd challenge types whose challenges need one (a pull marks them)
    max_running = 3                 # the most flightdeck keeps running at once (the plugin's cap, or less)
    # start = ["POST", "/containers/api/request"]   # without `plugin`: each route, [METHOD, PATH]
    # stop = ["POST", "/containers/api/stop"]
    # renew = ["POST", "/containers/api/renew"]
    # status = ["POST", "/containers/api/view_info"]
    # body_key = "chal_id"          # the JSON key that carries the challenge's number (a path with {id} carries it itself)
    # api = false                   # true: the paths are under /api/v1; false: under the site's root
    # address_key = "connectionInfo"  # the answer's key that holds the address: one name, or a list tried in order
    # port_key = "port"             # ... the port, when the address has none
    # expires_key = "until"         # ... the seconds left, or the moment it ends (a number or a timestamp)

Plugins differ in their paths and answers, so nothing is assumed: an [instances] table with
neither a plugin name nor all four routes is an error. The named shapes (PLUGINS):

- `docker_per_team`: CTFd-Docker-Plugin and its forks. Seen working at an event.
- `ctfd_owl`: ctfd-owl. One container per account, a start that answers only "done" (the
  address is in the status), refusals as HTTP 200 with `msg`.
- `chall_manager`: ctfd-chall-manager. The number in the query for the status and in a JSON
  body for the rest; the address is a line the organiser wrote, the end a timestamp.

The last two were built from the plugins' public source against fakes of it (tests/
fake_instance_plugins.py) and have not met a real site. ctfd-whale has no shape yet
(NOT_BUILT; BOARDS.md says why).

InstanceClient is the wire: start(), status(), renew(), stop() for one challenge, by the
board's id. What it guarantees:

- Scope. It acts only on a challenge that is on the board (`ids`: board id -> CTFd number).
  Any other id is refused before a request is made, so nothing here can touch another
  team's container, an unreleased challenge, the scoreboard or a hint.
- A request is sent once, never again: a second "start" could take a second slot. Each
  request takes at most `timeout` seconds in all (the same worker-thread deadline as a
  flag's submit). Two calls ask more than once, and only the status, which changes nothing:
  a start whose answer names no address asks the status, up to STATUS_TRIES times
  STATUS_GAP seconds apart, before it gives up; and a stop on a plugin that keeps one
  container per account (whose stop takes whatever runs) asks the status first and stops
  only when it is this challenge's.
- A refused start is an InstanceRefused with the plugin's own words, made safe to show
  (`full` when they say the team's cap or budget is reached), never a container with no
  address.
- The token goes only to the event's CTFd, in the Authorization header, and is never in a
  message.

The plugin's answer is untrusted: the host must look like a host name or an address, the
port must be a port, and what is shown of it is one line with control characters made
visible. An answer that names no address is an error, never an instance. Only a host and a
port are ever taken out of it, HTML and commands included: nothing in it is run or followed.

It never touches asyncio (a run calls it from a worker thread), never runs anything the
platform hands back, and spends no points: it calls the plugin's own container routes only.
"""

from __future__ import annotations

import json
import math
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone

import httpx

from ..text import untrusted
from .ctfd import API, CONNECT_TIMEOUT, MAX_API_BYTES, _by, _describe, _is_number, _LATE, _parse, _read_sync, _Site

ACTIONS = ("start", "stop", "renew", "status")
METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")
ON_DEMAND = "on-demand"  # challenge.json's "instance": the platform starts its instance when asked
DEFAULT_MAX_RUNNING = 3
HOST_KEYS = ("hostname", "host", "ip", "connect", "url", "address")
PORT_KEYS = ("port",)
REMAINING_KEYS = ("remaining_time", "remaining", "expires", "timeout")
ERROR_KEYS = ("error", "errors", "message", "msg")
STATUS_TRIES = 3  # how often a start whose answer names no address asks the status before it gives up
STATUS_GAP = 2.0  # seconds between those asks
_HOST = re.compile(r"[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?")
# a refusal that means "the team's slots or budget are used", in the plugins' own words: docker_per_team's cap,
# ctfd-owl's one container per account and its site-wide count, ctfd-chall-manager's mana
_FULL = re.compile(
    r"max(imum)?\b.{0,40}\b(container|instance)|limit reached|too many (container|instance)|you have boot\b|used up all your mana",
    re.I,
)
_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")
_PATH = re.compile(r"/[A-Za-z0-9_./{}?=&-]*")


class InstanceError(Exception):
    """An instance could not be started, read, renewed or stopped. One line, safe to show.

    `maybe_done`: the request that changes something went out and the platform may have done
    it all the same: no answer came in time, the line dropped, the answer was not the
    plugin's, or a start was taken and its status then gave no address. False when the
    platform said no, when nothing was sent, and for an instance that runs at an address
    flightdeck will not use. A run reads it after a start (instancerun.py): an instance of
    that challenge that turns up next is then its own, not a teammate's."""

    def __init__(self, message: str, *, maybe_done: bool = False) -> None:
        super().__init__(message)
        self.maybe_done = maybe_done


class InstanceRefused(InstanceError):
    """The plugin answered and said no. `full`: because the team's cap on containers is reached."""

    def __init__(self, message: str, *, full: bool = False) -> None:
        super().__init__(message)
        self.full = full


@dataclass(frozen=True)
class Routes:
    """How one plugin is asked: each action's method and path, and where the challenge's
    number goes (`body_key` in a JSON body, or `{id}` in the path)."""

    start: tuple[str, str]
    stop: tuple[str, str]
    renew: tuple[str, str]
    status: tuple[str, str]
    body_key: str | None = None  # for the routes whose path has no {id}
    api: bool = False  # the paths are under /api/v1 (True) or the site's root (False)


@dataclass(frozen=True)
class Answers:
    """How one plugin's answers are read: the keys that hold the address, the port and the
    end, each looked for in the answer and then in its `data`, the first with a value."""

    address: tuple[str, ...] = HOST_KEYS
    port: tuple[str, ...] = PORT_KEYS
    expires: tuple[str, ...] = REMAINING_KEYS
    # (key, value): an answer whose `key` is `value` names a web server, so a bare host is http:// whatever the category
    web: tuple[str, str] | None = None
    # the address is a line a person wrote ("curl http://host:8080", a link): the first URL, nc line or host:port in it
    loose: bool = False


@dataclass(frozen=True)
class Shape:
    """A named plugin: its routes, how its answers read, and what its source says of its limits."""

    routes: Routes
    answers: Answers = Answers()
    single: bool = False  # one container per account, and its stop takes whatever runs: max_running is 1, a stop asks first
    gap: float = 0.0  # seconds the plugin wants between two requests that change something; the client waits them


_CONTAINERS = "/containers/api"
_OWL = "/plugins/ctfd-owl/container?challenge_id={id}"
_CHALL_MANAGER = "/plugins/ctfd-chall-manager/instance"

PLUGINS: dict[str, Shape] = {
    # CTFd-Docker-Plugin (github.com/andyjsmith/CTFd-Docker-Plugin) and its forks; seen working at an event in
    # November 2026. The original has no view_info: its 404 there reads as "no instance".
    "docker_per_team": Shape(Routes(
        start=("POST", f"{_CONTAINERS}/request"), stop=("POST", f"{_CONTAINERS}/stop"),
        renew=("POST", f"{_CONTAINERS}/renew"), status=("POST", f"{_CONTAINERS}/view_info"),
        body_key="chal_id",
    )),
    # ctfd-owl (github.com/D0g3-Lab/H1ve, CTFd/plugins/ctfd-owl/__init__.py), read from its source, not met.
    # The status answers `ip` and `port`, or `domain` with type "http"; a start answers {"success": true} only.
    # Its changing routes refuse a second request within the second (control_utils.frequency_limit).
    "ctfd_owl": Shape(
        Routes(start=("POST", _OWL), stop=("DELETE", _OWL), renew=("PATCH", _OWL), status=("GET", _OWL)),
        Answers(address=("ip", "domain"), port=("port",), expires=("remaining_time",), web=("type", "http")),
        single=True, gap=1.0,
    ),
    # ctfd-chall-manager (github.com/ctfer-io/ctfd-chall-manager, api/instance.py), read from its source, not met.
    # data.connectionInfo is the organiser's own line; data.until is an RFC 3339 timestamp, absent with no timeout.
    "chall_manager": Shape(
        Routes(start=("POST", _CHALL_MANAGER), stop=("DELETE", _CHALL_MANAGER), renew=("PATCH", _CHALL_MANAGER),
               status=("GET", _CHALL_MANAGER + "?challengeId={id}"), body_key="challengeId", api=True),
        Answers(address=("connectionInfo",), port=(), expires=("until",), loose=True),
    ),
}
# names a profile may still carry, and what to write instead
REMOVED = {
    "ctfd_docker": "its routes were a guess that matches no plugin whose source was read. CTFd-Docker-Plugin and its forks "
                   "are docker_per_team",
}
# plugins a player may name that have no shape, and why
NOT_BUILT = dict.fromkeys(
    ("ctfd_whale", "whale"),
    "ctfd-whale has no shape yet: its start removes whatever container the account runs, and its address comes in forms "
    "flightdeck does not read yet (BOARDS.md, Instances on demand). Start its instances on the site yourself",
)


@dataclass(frozen=True)
class InstancesConfig:
    """An event profile's [instances] table, checked."""

    routes: Routes
    types: tuple[str, ...] = ()  # CTFd challenge types whose challenges need an instance started
    max_running: int = DEFAULT_MAX_RUNNING
    plugin: str | None = None  # the named shape it came from, for messages
    answers: Answers = Answers()
    single: bool = False  # Shape.single
    gap: float = 0.0  # Shape.gap


_ANSWER_KEYS = {"address_key": "address", "port_key": "port", "expires_key": "expires"}
_KEYS = ("plugin", "types", "max_running", *ACTIONS, "body_key", "api", *_ANSWER_KEYS)


def parse_config(table: object) -> InstancesConfig:
    """The [instances] table of an event profile. ValueError naming the key when it is wrong."""
    if not isinstance(table, Mapping):
        raise ValueError("instances must be a table")
    unknown = [key for key in table if key not in _KEYS]
    if unknown:
        raise ValueError(f"instances.{_show(unknown[0])} is not a key flightdeck knows (known: {', '.join(_KEYS)})")
    plugin = table.get("plugin")
    if isinstance(plugin, str) and plugin in REMOVED:
        raise ValueError(f"instances.plugin {plugin} is no longer a plugin flightdeck knows: {REMOVED[plugin]}; for any other "
                         f"plugin give the four routes (start, stop, renew, status). Known: {', '.join(PLUGINS)}")
    if plugin is not None and not (isinstance(plugin, str) and plugin in PLUGINS):
        why = NOT_BUILT.get(plugin) if isinstance(plugin, str) else None
        raise ValueError(f"instances.plugin {_show(plugin)} is not a plugin flightdeck knows (known: {', '.join(PLUGINS)}); "
                         + (why or "give the four routes instead (start, stop, renew, status)"))
    shape = PLUGINS[plugin] if plugin is not None else None
    base = shape.routes if shape is not None else None
    given = {action: _route(action, table[action]) for action in ACTIONS if action in table}
    if base is None:
        missing = [action for action in ACTIONS if action not in given]
        if missing:
            raise ValueError(f"instances needs plugin (one of {', '.join(PLUGINS)}) or all four routes; missing: {', '.join(missing)}")
    body_key = table.get("body_key", base.body_key if base is not None else None)
    if body_key is not None and not (isinstance(body_key, str) and _KEY.fullmatch(body_key)):
        raise ValueError("instances.body_key must be a JSON key name (letters, digits and _)")
    api = table.get("api", base.api if base is not None else False)
    if not isinstance(api, bool):
        raise ValueError("instances.api must be true or false")
    routes = Routes(**{action: given.get(action) or getattr(base, action) for action in ACTIONS}, body_key=body_key, api=api)
    for action in ACTIONS:
        path = getattr(routes, action)[1]
        if body_key is None and "{id}" not in path:
            raise ValueError(f"instances.{action}: without body_key the path must say where the challenge's number goes, as {{id}}")
    types = table.get("types", [])
    if not isinstance(types, list) or not all(isinstance(t, str) and t.strip() and len(t) <= 64 for t in types) or len(set(types)) != len(types):
        raise ValueError("instances.types must be a list of distinct CTFd challenge type names")
    single = shape.single if shape is not None else False
    most = table.get("max_running", 1 if single else DEFAULT_MAX_RUNNING)
    if isinstance(most, bool) or not isinstance(most, int) or not 1 <= most <= 64:
        raise ValueError("instances.max_running must be a whole number from 1 to 64")
    if single and most != 1:
        raise ValueError(f"instances.max_running must be 1 with plugin {plugin}: it runs one container per account "
                         "(per team in team mode), and a start past it is refused")
    answers = shape.answers if shape is not None else Answers()
    named = {part: _keys(key, table[key]) for key, part in _ANSWER_KEYS.items() if key in table}
    if "address" in named and not named["address"]:
        raise ValueError("instances.address_key must name at least one key: an answer with no address is no instance")
    return InstancesConfig(routes, tuple(types), most, plugin, replace(answers, **named), single, shape.gap if shape is not None else 0.0)


def _keys(name: str, value: object) -> tuple[str, ...]:
    """An answer key of the table: one JSON key name, or a list of them tried in order."""
    keys = [value] if isinstance(value, str) else value
    if not isinstance(keys, list) or len(keys) > 8 or not all(isinstance(key, str) and _KEY.fullmatch(key) for key in keys) \
            or len(set(keys)) != len(keys):
        raise ValueError(f'instances.{name} must be a JSON key name (letters, digits and _), or a list of up to 8 distinct ones, '
                         'such as "connectionInfo" or ["ip", "domain"]')
    return tuple(keys)


def _route(action: str, value: object) -> tuple[str, str]:
    if not isinstance(value, list) or len(value) != 2 or not all(isinstance(part, str) for part in value):
        raise ValueError(f'instances.{action} must be [METHOD, PATH], such as ["POST", "/containers/api/request"]')
    method, path = value[0].upper(), value[1]
    if method not in METHODS:
        raise ValueError(f"instances.{action}: the method must be one of {', '.join(METHODS)}")
    if not _PATH.fullmatch(path) or ".." in path or "//" in path:
        raise ValueError(f"instances.{action}: the path must start with / and name a route of the site (no host, no ..)")
    return method, path


@dataclass(frozen=True)
class Instance:
    """A running instance: where it is, and when the platform stops it if it said."""

    challenge: str  # the board's id
    host: str
    port: int | None
    scheme: str | None = None  # "http" or "https" when the plugin gave a URL; None when it gave a host and a port
    expires_at: float | None = None  # time.time() when the platform stops it; None: it did not say, or not so flightdeck can read it
    said: str = field(default="", compare=False)  # the plugin's words, safe to show

    def url(self, web: bool) -> str:
        """The instance as a board's `urls` entry: the plugin's own scheme when it gave one,
        else http for a web challenge and tcp for any other (what `nc host port` reaches)."""
        scheme = self.scheme or ("http" if web else "tcp")
        if self.port is None:
            return f"{scheme}://{self.host}"
        return f"{scheme}://{self.host}:{self.port}"


class InstanceClient:
    """Asks one CTFd's container plugin for the board's challenges' instances."""

    def __init__(self, base_url: str, token: str, ids: Mapping[str, int], config: InstancesConfig, *, timeout: float = 20.0,
                 transport: httpx.BaseTransport | None = None, clock=time.time, sleep: Callable[[float], None] = time.sleep,
                 monotonic: Callable[[], float] = time.monotonic) -> None:
        self._site = _Site(base_url, token)
        if not timeout > 0:
            raise ValueError(f"timeout must be a positive number of seconds, got {timeout}")
        self.ids: dict[str, int] = {}
        for key, value in ids.items():
            if not isinstance(key, str) or not _is_number(value):
                raise ValueError("ids must map board ids (strings) to CTFd challenge ids (whole numbers, 1 or more)")
            self.ids[key] = value
        self.config = config
        self.timeout = timeout
        self._clock = clock
        self._sleep = sleep  # in the caller's thread: a run calls this client from a worker thread
        self._monotonic = monotonic
        self._changed_at: float | None = None  # when the last request that changes something was answered (config.gap)
        self._http = httpx.Client(
            headers=self._site.headers(),
            timeout=httpx.Timeout(timeout, connect=min(timeout, CONNECT_TIMEOUT)),
            transport=transport,
            follow_redirects=False,
        )

    def __repr__(self) -> str:
        return f"InstanceClient({self._site.root!r}, token=set, {len(self.ids)} challenges)"

    def close(self) -> None:
        self._http.close()

    def start(self, challenge_id: str) -> Instance:
        """Ask the plugin for the challenge's instance: the running one's address. The start
        is sent once. Some plugins answer it with the address, and the same for an instance
        that already runs; others answer only that it is done, and name the address in the
        status: that is asked then, up to STATUS_TRIES times STATUS_GAP seconds apart.

        What a start does to an instance that already runs is the plugin's own business (one
        answers the same, one refuses, one replaces it): ask status() first, as a run does."""
        doc = self._ask("start", challenge_id)
        assert doc is not None
        if self._names_address(doc):
            return self._instance(challenge_id, doc)
        try:
            for asked in range(STATUS_TRIES):
                if asked:
                    self._sleep(STATUS_GAP)
                found = self.status(challenge_id)
                if found is not None:
                    return found
        except InstanceError as exc:
            exc.maybe_done = True  # the start was taken: whatever the status said, an instance may run
            raise
        said = _dig(doc, ERROR_KEYS)
        words = f" ({self._site.short(str(said))})" if said is not None else ""
        raise InstanceError(
            f"the platform took the start for {_show(challenge_id)}, but neither its answer nor its status names an address{words}; "
            "is [instances] right for this site's plugin (address_key)?",
            maybe_done=True,
        )

    def status(self, challenge_id: str) -> Instance | None:
        """The challenge's running instance, or None when the plugin names none."""
        doc = self._ask("status", challenge_id, refusal_is_none=True)
        if doc is None or not self._names_address(doc):
            return None
        return self._instance(challenge_id, doc)

    def renew(self, challenge_id: str) -> Instance | None:
        """Ask for more time. The instance as the plugin now describes it, or None when its
        answer names no address (the time was extended; ask status() for the rest)."""
        doc = self._ask("renew", challenge_id)
        return self._instance(challenge_id, doc) if self._names_address(doc) else None

    def stop(self, challenge_id: str) -> None:
        """Stop the challenge's instance and free its slot. On a plugin that keeps one
        container per account (config.single) the stop route takes whatever runs, so the
        status is asked first: when this challenge's instance is not the one running, nothing
        is stopped (a teammate's container of another challenge stays up)."""
        if self.config.single and self.status(challenge_id) is None:
            return
        self._ask("stop", challenge_id)

    # ------------------------------------------------------------------ the wire

    def _ask(self, action: str, challenge_id: str, *, refusal_is_none: bool = False) -> dict | None:
        number = self.ids.get(challenge_id)
        if number is None:
            raise InstanceError(f"{_show(challenge_id)} is not a challenge of this board, so flightdeck asks the platform nothing about it")
        method, path = getattr(self.config.routes, action)
        root = self._site.root + (API if self.config.routes.api else "")
        content = None
        if "{id}" in path:  # the path carries the number: no body, so a GET goes out as a GET
            path = path.replace("{id}", str(number))
        elif self.config.routes.body_key is not None:
            content = json.dumps({self.config.routes.body_key: number}).encode()
        what = f"instance {action} for challenge {number}"
        changes = action != "status"
        if changes and self.config.gap > 0 and self._changed_at is not None:
            waited = self._monotonic() - self._changed_at
            if waited < self.config.gap:  # the plugin refuses two changes this close together
                self._sleep(self.config.gap - waited)
        deadline = time.monotonic() + self.timeout

        def exchange():
            try:
                with self._http.stream(method, root + path, content=content) as response:
                    body = _read_sync(response, MAX_API_BYTES, deadline)
                    return (response.status_code, body)
            except httpx.HTTPError as exc:
                return _describe(exc)  # the error itself is dropped: its request holds the token

        outcome = _by(deadline, "ctfd-instance", exchange)
        if changes:
            self._changed_at = self._monotonic()  # counted from the answer: the plugin's own clock started no later
        if outcome is _LATE:
            raise InstanceError(f"no answer from the platform to {what} within {self.timeout:g} s; it may have been done: look at the challenge on the site",
                                maybe_done=changes)
        if not isinstance(outcome, tuple):
            done = "; it may have been done: look at the challenge on the site" if outcome.sent else ""
            raise InstanceError(f"no answer from the platform to {what} ({self._site.short(outcome.what)}){done}", maybe_done=changes and outcome.sent)
        status, body = outcome
        acted = changes and 200 <= status < 300  # an answer that is not the plugin's own (a proxy's page, one cut short): it may have acted
        if not isinstance(body, bytes):
            raise InstanceError(f"{what}: the platform's answer was too long or never ended (HTTP {status})", maybe_done=acted)
        doc = _parse(body)
        said = _dig(doc, ERROR_KEYS) if isinstance(doc, dict) else None
        failed = isinstance(doc, dict) and (doc.get("success") is False or doc.get("error") not in (None, "", False))
        if status >= 400 or failed:
            if refusal_is_none and status in (400, 404):
                return None
            words = self._site.short(str(said)) if said is not None else f"HTTP {status}"
            raise InstanceRefused(f"the platform refused {what}: {words}", full=bool(said is not None and _FULL.search(str(said))))
        if not isinstance(doc, dict):
            raise InstanceError(f"{what}: the platform's answer is not JSON (HTTP {status}); is [instances] right for this site's plugin?",
                                maybe_done=acted)
        return doc

    def _names_address(self, doc: dict | None) -> bool:
        return doc is not None and _dig(doc, self.config.answers.address) is not None

    def _instance(self, challenge_id: str, doc: dict | None) -> Instance:
        assert doc is not None
        answers = self.config.answers
        raw = _dig(doc, answers.address)
        if not isinstance(raw, str) or not raw.strip():
            raise InstanceError(f"the platform's answer for {_show(challenge_id)} names no address; is [instances] right for this site's plugin?")
        scheme, host, port = _address(raw.strip())
        if host is None and answers.loose:
            scheme, host, port = _within(raw)
        if port is None:
            given = _dig(doc, answers.port)
            if isinstance(given, str) and given.isascii() and given.isdigit():
                given = int(given)
            if isinstance(given, int) and not isinstance(given, bool):
                port = given
        if scheme is None and answers.web is not None and _dig(doc, (answers.web[0],)) == answers.web[1]:
            scheme = "http"  # the plugin says it is a web server: its address is one whatever the challenge's category
        if host is None or (port is not None and not 1 <= port <= 65535) or (port is None and scheme is None):
            raise InstanceError(f"the platform's answer for {_show(challenge_id)} names no usable address ({self._site.short(raw)})")
        return Instance(challenge_id, host, port, scheme, _ends(_dig(doc, answers.expires), self._clock()), self._site.short(raw))


def _ends(left: object, now: float) -> float | None:
    """When an instance ends, from what the plugin says of it: seconds left (a small number),
    the moment itself (a large one, or an ISO 8601 / RFC 3339 timestamp; one with no zone is
    read as UTC). None when it says nothing flightdeck can read."""
    if isinstance(left, str):
        text = left.strip()
        if re.fullmatch(r"\d{1,12}(\.\d{1,9})?", text):
            left = float(text)
        else:
            try:  # at most six digits of a second's fraction, which is all datetime keeps
                moment = datetime.fromisoformat(re.sub(r"(\.\d{6})\d+", r"\1", text[:64]))
            except ValueError:
                return None
            if moment.tzinfo is None:
                moment = moment.replace(tzinfo=timezone.utc)
            return moment.timestamp()
    if isinstance(left, bool) or not isinstance(left, (int, float)) or not math.isfinite(left) or left <= 0:
        return None
    return now + float(left) if left < 10**9 else float(left)


def _address(text: str) -> tuple[str | None, str | None, int | None]:
    """(scheme, host, port) read out of what a plugin calls the address: a URL, "host:port",
    "nc host port", or a bare host. A host that does not look like one is None."""
    scheme = None
    found = re.fullmatch(r"(https?)://([^/:\s]+)(?::(\d{1,5}))?(?:/\S*)?", text)
    if found:
        scheme, host, port = found.group(1), found.group(2), found.group(3)
    else:
        found = re.fullmatch(r"(?:nc\s+|ncat\s+|telnet\s+)?([^\s:]+)(?:[:\s]+(\d{1,5}))?", text)
        if not found:
            return None, None, None
        host, port = found.group(1), found.group(2)
    if not _HOST.fullmatch(host):
        return None, None, None
    return scheme, host.lower(), int(port) if port else None


_URL_WITHIN = re.compile(r"(https?)://([^\s/?#\"'<>]*)")  # the scheme, and all that comes before the path
_NC_WITHIN = re.compile(r"(?<![\w.-])(?:nc|ncat|telnet)\s+([^\s:\"'<>]+)[:\s]+(\d{1,5})(?![\w-])")
_PAIR_WITHIN = re.compile(r"(?<![\w.@/-])([A-Za-z0-9][A-Za-z0-9.-]*):(\d{1,5})(?![\w@:-])")
_NAME_WITHIN = re.compile(r"(?:[A-Za-z0-9-]+\.)+[A-Za-z][A-Za-z0-9-]*")  # a dotted name whose last part starts with a letter
_IPV4_WITHIN = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")


def _within(text: str) -> tuple[str | None, str | None, int | None]:
    """(scheme, host, port) of the first address in a line a person wrote for players, such
    as "curl -v http://host:8080", "Connect with: nc host 31337" or a link's HTML: the first
    URL, else the first nc line, else the first host:port. Only the host and the port are
    taken, each checked as _address checks them; the rest of the line is never used.

    It never guesses: a wrong address would brief a lane with, and fence it to, a host the
    organiser did not name. So:
    - a URL's host is what follows the last @ before its path ("http://name:password@host/":
      the name and the password are not taken), and a first URL that does not read (letters
      after its port, say) is no address at all: nothing else in the line is tried;
    - a host:port inside a sentence counts only when the host is a dotted name or an IPv4
      address. "12:30" is a time, "ctf:1234" a name and a password, "1.5:30" a version; a
      host with no dot is read only after nc, or when it is the whole answer (_address)."""
    text = text[:2000]
    found = _URL_WITHIN.search(text)
    if found:
        authority = found.group(2).rstrip(".,;:!?)]}")  # the sentence's own punctuation after a URL that ends there
        if "\\" in authority:  # clients disagree on where such a URL's host is
            return None, None, None
        return _address(f"{found.group(1)}://{authority.rpartition('@')[2]}")
    found = _NC_WITHIN.search(text)
    if found:
        return _address(f"{found.group(1)}:{found.group(2)}")
    for found in _PAIR_WITHIN.finditer(text):
        host = found.group(1)
        if _NAME_WITHIN.fullmatch(host) or (_IPV4_WITHIN.fullmatch(host) and all(int(part) <= 255 for part in host.split("."))):
            return _address(f"{host}:{found.group(2)}")
    return None, None, None


def _dig(doc: object, keys: tuple[str, ...]) -> object:
    """The first of `keys` with a value in `doc` or in its `data`."""
    for scope in (doc, doc.get("data") if isinstance(doc, dict) else None):
        if isinstance(scope, dict):
            for key in keys:
                if scope.get(key) not in (None, ""):
                    return scope[key]
    return None


def _show(value: object) -> str:
    return untrusted(str(value), one_line=True)
