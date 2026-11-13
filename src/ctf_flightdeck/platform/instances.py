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
    # body_key = "chal_id"          # the JSON key that carries the challenge's number (else {id} in the path)
    # api = false                   # true: the paths are under /api/v1; false: under the site's root

Plugins differ in their paths and answers (CTFd-whale, CTFd-owl, docker_per_team and others),
so nothing is assumed: an [instances] table with neither a plugin name nor all four routes is
an error. `docker_per_team` was seen working at an event; `ctfd_docker` is a guess at another
plugin's shape and is marked so.

InstanceClient is the wire: start(), status(), renew(), stop() for one challenge, by the
board's id. What it guarantees:

- Scope. It acts only on a challenge that is on the board (`ids`: board id -> CTFd number).
  Any other id is refused before a request is made, so nothing here can touch another
  team's container, an unreleased challenge, the scoreboard or a hint.
- One request per call, never retried: a second "start" could take a second slot. A call
  takes at most `timeout` seconds in all (the same worker-thread deadline as a flag's submit).
- A refused start is an InstanceRefused with the plugin's own words, made safe to show
  (`full` when they say the team's cap is reached), never a container with no address.
- The token goes only to the event's CTFd, in the Authorization header, and is never in a
  message.

The plugin's answer is untrusted: the host must look like a host name or an address, the
port must be a port, and what is shown of it is one line with control characters made
visible. An answer that names no address is an error, never an instance.

It never touches asyncio (a run calls it from a worker thread), never runs anything the
platform hands back, and spends no points: it calls the plugin's own container routes only.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Mapping
from dataclasses import dataclass, field

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
ERROR_KEYS = ("error", "errors", "message")
_HOST = re.compile(r"[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?")
_FULL = re.compile(r"max(imum)?\b.{0,40}\b(container|instance)|limit reached|too many (container|instance)", re.I)
_PATH = re.compile(r"/[A-Za-z0-9_./{}?=&-]*")


class InstanceError(Exception):
    """An instance could not be started, read, renewed or stopped. One line, safe to show."""


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
    body_key: str | None = None
    api: bool = False  # the paths are under /api/v1 (True) or the site's root (False)


PLUGINS: dict[str, Routes] = {
    # seen working at an event in November 2026
    "docker_per_team": Routes(
        start=("POST", "/containers/api/request"), stop=("POST", "/containers/api/stop"),
        renew=("POST", "/containers/api/renew"), status=("POST", "/containers/api/view_info"),
        body_key="chal_id",
    ),
    # a guess at CTFd-Docker-Plugin's shape, never seen working: check it against the site before an event
    "ctfd_docker": Routes(
        start=("POST", "/plugins/ctfd-docker/container?challenge_id={id}"),
        stop=("DELETE", "/plugins/ctfd-docker/container?challenge_id={id}"),
        renew=("PATCH", "/plugins/ctfd-docker/container?challenge_id={id}"),
        status=("GET", "/plugins/ctfd-docker/container?challenge_id={id}"),
        api=True,
    ),
}


@dataclass(frozen=True)
class InstancesConfig:
    """An event profile's [instances] table, checked."""

    routes: Routes
    types: tuple[str, ...] = ()  # CTFd challenge types whose challenges need an instance started
    max_running: int = DEFAULT_MAX_RUNNING
    plugin: str | None = None  # the named shape it came from, for messages


_KEYS = ("plugin", "types", "max_running", *ACTIONS, "body_key", "api")


def parse_config(table: object) -> InstancesConfig:
    """The [instances] table of an event profile. ValueError naming the key when it is wrong."""
    if not isinstance(table, Mapping):
        raise ValueError("instances must be a table")
    unknown = [key for key in table if key not in _KEYS]
    if unknown:
        raise ValueError(f"instances.{_show(unknown[0])} is not a key flightdeck knows (known: {', '.join(_KEYS)})")
    plugin = table.get("plugin")
    if plugin is not None and plugin not in PLUGINS:
        raise ValueError(f"instances.plugin {_show(plugin)} is not a plugin flightdeck knows (known: {', '.join(PLUGINS)}); "
                         "give the four routes instead (start, stop, renew, status)")
    base = PLUGINS[plugin] if plugin is not None else None
    given = {action: _route(action, table[action]) for action in ACTIONS if action in table}
    if base is None:
        missing = [action for action in ACTIONS if action not in given]
        if missing:
            raise ValueError(f"instances needs plugin (one of {', '.join(PLUGINS)}) or all four routes; missing: {', '.join(missing)}")
    body_key = table.get("body_key", base.body_key if base is not None else None)
    if body_key is not None and not (isinstance(body_key, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", body_key)):
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
    most = table.get("max_running", DEFAULT_MAX_RUNNING)
    if isinstance(most, bool) or not isinstance(most, int) or not 1 <= most <= 64:
        raise ValueError("instances.max_running must be a whole number from 1 to 64")
    return InstancesConfig(routes, tuple(types), most, plugin)


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
    expires_at: float | None = None  # time.time() when the platform stops it; None: it did not say
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
                 transport: httpx.BaseTransport | None = None, clock=time.time) -> None:
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
        """Ask the plugin for the challenge's instance: the running one's address. The plugin
        answers the same for one that already runs (no second slot is taken)."""
        return self._instance(challenge_id, self._ask("start", challenge_id))

    def status(self, challenge_id: str) -> Instance | None:
        """The challenge's running instance, or None when the plugin names none."""
        doc = self._ask("status", challenge_id, refusal_is_none=True)
        if doc is None or _dig(doc, HOST_KEYS) is None:
            return None
        return self._instance(challenge_id, doc)

    def renew(self, challenge_id: str) -> Instance | None:
        """Ask for more time. The instance as the plugin now describes it, or None when its
        answer names no address (the time was extended; ask status() for the rest)."""
        doc = self._ask("renew", challenge_id)
        return self._instance(challenge_id, doc) if _dig(doc, HOST_KEYS) is not None else None

    def stop(self, challenge_id: str) -> None:
        """Stop the challenge's instance and free its slot."""
        self._ask("stop", challenge_id)

    # ------------------------------------------------------------------ the wire

    def _ask(self, action: str, challenge_id: str, *, refusal_is_none: bool = False) -> dict | None:
        number = self.ids.get(challenge_id)
        if number is None:
            raise InstanceError(f"{_show(challenge_id)} is not a challenge of this board, so flightdeck asks the platform nothing about it")
        method, path = getattr(self.config.routes, action)
        path = path.replace("{id}", str(number))
        root = self._site.root + (API if self.config.routes.api else "")
        content = None
        if self.config.routes.body_key is not None:
            content = json.dumps({self.config.routes.body_key: number}).encode()
        what = f"instance {action} for challenge {number}"
        deadline = time.monotonic() + self.timeout

        def exchange():
            try:
                with self._http.stream(method, root + path, content=content) as response:
                    body = _read_sync(response, MAX_API_BYTES, deadline)
                    return (response.status_code, body)
            except httpx.HTTPError as exc:
                return _describe(exc)  # the error itself is dropped: its request holds the token

        outcome = _by(deadline, "ctfd-instance", exchange)
        if outcome is _LATE:
            raise InstanceError(f"no answer from the platform to {what} within {self.timeout:g} s; it may have been done: look at the challenge on the site")
        if not isinstance(outcome, tuple):
            done = "; it may have been done: look at the challenge on the site" if outcome.sent else ""
            raise InstanceError(f"no answer from the platform to {what} ({self._site.short(outcome.what)}){done}")
        status, body = outcome
        if not isinstance(body, bytes):
            raise InstanceError(f"{what}: the platform's answer was too long or never ended (HTTP {status})")
        doc = _parse(body)
        said = _dig(doc, ERROR_KEYS) if isinstance(doc, dict) else None
        failed = isinstance(doc, dict) and (doc.get("success") is False or doc.get("error") not in (None, "", False))
        if status >= 400 or failed:
            if refusal_is_none and status in (400, 404):
                return None
            words = self._site.short(str(said)) if said is not None else f"HTTP {status}"
            raise InstanceRefused(f"the platform refused {what}: {words}", full=bool(said is not None and _FULL.search(str(said))))
        if not isinstance(doc, dict):
            raise InstanceError(f"{what}: the platform's answer is not JSON (HTTP {status}); is [instances] right for this site's plugin?")
        return doc

    def _instance(self, challenge_id: str, doc: dict | None) -> Instance:
        assert doc is not None
        raw = _dig(doc, HOST_KEYS)
        if not isinstance(raw, str) or not raw.strip():
            raise InstanceError(f"the platform's answer for {_show(challenge_id)} names no address; is [instances] right for this site's plugin?")
        scheme, host, port = _address(raw.strip())
        if port is None:
            given = _dig(doc, PORT_KEYS)
            if isinstance(given, str) and given.isascii() and given.isdigit():
                given = int(given)
            if isinstance(given, int) and not isinstance(given, bool):
                port = given
        if host is None or (port is not None and not 1 <= port <= 65535) or (port is None and scheme is None):
            raise InstanceError(f"the platform's answer for {_show(challenge_id)} names no usable address ({self._site.short(raw)})")
        left = _dig(doc, REMAINING_KEYS)
        expires = None
        if isinstance(left, (int, float)) and not isinstance(left, bool) and left > 0:
            # a small number is seconds left; a large one is the moment itself
            expires = self._clock() + float(left) if left < 10**9 else float(left)
        return Instance(challenge_id, host, port, scheme, expires, self._site.short(raw))


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
