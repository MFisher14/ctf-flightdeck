"""A challenge's own container: started, renewed and stopped through the platform's instancer.

Some challenges have no fixed address: the platform starts a container for the team when
asked, a few at a time (a small cap per team), and stops it after a while. A board lists no
`urls` for such a challenge; its challenge.json says `"instance": "on-demand"` instead, and an
event profile's [instances] table says how to ask (BOARDS.md). On CTFd that is a container
plugin; on the http platform (platform/http.py) it is the platform's own instancer, rCTF v2's
among them:

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
    # expires_unit = "ms"           # ... a number of the end counts milliseconds, not seconds
    # endpoints_key = "endpoints"   # the answer's key that holds a list of {kind, host, port}, one per address
    # state_key = "status"          # the answer's key that says what the instance is doing
    # running_states = ["running"]  # ... the words that mean it is up
    # pending_states = ["starting"] # ... the words that mean it is on its way up or down: wait, send nothing
    # failed_states = ["errored"]   # ... the words that mean the platform could not run it: say so, send no start

Plugins differ in their paths and answers, so nothing is assumed: an [instances] table with
neither a plugin name nor all four routes is an error. The named shapes (PLUGINS):

- `docker_per_team`: CTFd-Docker-Plugin and its forks. Seen working at an event.
- `ctfd_owl`: ctfd-owl. One container per account, a start that answers only "done" (the
  address is in the status), refusals as HTTP 200 with `msg`.
- `chall_manager`: ctfd-chall-manager. The number in the query for the status and in a JSON
  body for the rest; the address is a line the organiser wrote, the end a timestamp.
- `ctfd_whale`: ctfd-whale. One container per user account, a start that first removes
  whatever that account runs, a status that refuses for any challenge but the running one,
  and an address in one of five forms (an nc line, a link's HTML, a pwntools snippet, an
  https URL, `[ssl] host port`), two of them TLS endpoints that are no web server (tls://).
- `rctf`: rCTF v2's own instancer (github.com/otter-sec/rctf, its API reference), for
  platform = "http". The challenge's string id in the path; the answer a state and a list of
  endpoints, the end in milliseconds; a start may answer "starting" and the status "running"
  later, and "errored" when it could not run it (InstanceFailed); a `tcp-ssl` endpoint is a
  TLS endpoint (tls://). Built from its documentation
  against a fake of it (tests/fake_http.py); not met.
- `gzctf`: GZCTF's containers (github.com/GZTimeWalker/GZCTF, GameController), for
  platform = "http" with the gzctf preset. The game's number in the path ({game}, the [http]
  table's `game`), the challenge's number after it; the start and the renew answer
  {status, entry, expectStopAt}, the status is the challenge's own detail, whose
  context holds instanceEntry and closeTime; the ends are milliseconds since 1970. Refusals
  are {title, status}, asked for in English. A container GZCTF serves through its own
  WebSocket proxy (its entry is the container's id, not a host and a port) is one at an
  address flightdeck will not use, said so. Built from its source against a fake of it
  (tests/fake_gzctf.py); not met.

A shape names the platform it is for (Shape.platform): a CTFd plugin's on CTFd only, rCTF's and
GZCTF's on the http platform only. Routes a profile gives itself are for either. A route may
hold {game}, filled with the http table's game (Wire.game); on a wire with no game such a
route is refused before anything is sent.

The ctfd_owl, chall_manager and ctfd_whale shapes were built from the plugins' public source
against fakes of it (tests/fake_instance_plugins.py) and have not met a real site.

InstanceClient is the wire: start(), status(), renew(), stop() for one challenge, by the
board's id. What it guarantees:

- Scope. It acts only on a challenge that is on the board (`ids`: board id -> the platform's
  own id: CTFd's number, or a string ref such as rCTF's). A string goes into a path
  percent-encoded whole, so it stays one path segment; "." and ".." are refused.
  Any other id is refused before a request is made, so nothing here can touch another
  team's container, an unreleased challenge, the scoreboard or a hint.
- A request is sent once, never again: a second "start" could take a second slot. Each
  request takes at most `timeout` seconds in all (the same worker-thread deadline as a
  flag's submit). Two calls ask more than once, and only the status, which changes nothing:
  a start whose answer names no address asks the status, up to STATUS_TRIES times
  STATUS_GAP seconds apart, before it gives up; and a stop on a plugin that keeps one
  container per account (whose stop takes whatever runs) asks the status first and stops
  only when it is this challenge's.
- One container, never reset. On a plugin whose start replaces whatever the account runs
  (Shape.replaces: ctfd-whale), a start asks the status first and is sent only when the
  account runs nothing: this challenge's running instance is returned as it is, and another
  challenge's is an InstanceBusy, with no start sent. A second start would otherwise take a
  lane's target away from under it.
- A refused start is an InstanceRefused with the plugin's own words, made safe to show
  (`full` when they say the team's cap or budget is reached), never a container with no
  address.
- The token goes only to the event's address, the way the platform's own adapter sends it:
  CTFd's token, or on the http platform the [http] table's own auth (the session of an rCTF
  sign-in, say: HttpCaller.instance_wire()). It is never in a message.
- A start or a renew the platform guards with a CAPTCHA is refused by name
  (InstanceRefused.human), never answered: the player starts that instance on the site, and
  the status finds it there.

The plugin's answer is untrusted: the host must look like a host name or an address, the
port must be a port, and what is shown of it is one line with control characters made
visible. An answer that names no address is an error, never an instance. Only a host and a
port are ever taken out of it, HTML and commands included: nothing in it is run or followed.
An instance may have several addresses (an `endpoints` list: a web front and a TCP service,
say), each checked so, at most MAX_ENDPOINTS of them. rCTF's tcp-ssl, a TLS service, is a
tls:// address, as ctfd-whale's TLS lines are. One of a kind flightdeck cannot hand a lane
(KINDS) is left out and named; an instance with none left is one at an address flightdeck
will not use.

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
from typing import Protocol

import httpx

from urllib.parse import quote

from ..plugins.call import valid_ref
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
MAX_ENDPOINTS = 8  # addresses taken from one answer's endpoints list
MAX_STATES = 16  # words of running_states or pending_states
UNITS = {"s": 1.0, "ms": 0.001}  # expires_unit: seconds per unit of a number of the end
# an endpoint's kind -> the scheme of its `urls` entry (rCTF's tcp-ssl: a TLS endpoint, tls://). A kind not here is
# left out, by name
KINDS = {"tcp": "tcp", "http": "http", "https": "https", "tcp-ssl": "tls"}
_HOST = re.compile(r"[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?")
# a refusal that means "the team's slots or budget are used", in the plugins' own words: docker_per_team's cap,
# ctfd-owl's one container per account and its site-wide count, ctfd-chall-manager's mana, GZCTF's
# Game_ContainerNumberLimitExceeded ("The number of team containers cannot exceed 3")
_FULL = re.compile(
    r"max(imum)?\b.{0,40}\b(container|instance)|limit reached|too many (container|instance)|you have boot\b|used up all your mana"
    r"|number of (team )?containers cannot exceed",
    re.I,
)
# a refusal that wants a person: rCTF v2's badCaptcha and badRecaptchaCode, and any other platform's CAPTCHA
_HUMAN = re.compile(r"captcha|turnstile", re.I)
_KEY =re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")
_PATH = re.compile(r"/[A-Za-z0-9_./{}?=&-]*")
_PLACEHOLDERS = ("{id}", "{game}")  # what a route's braces may hold
# GZCTF's entry for a container it serves through its own WebSocket proxy (Container.IsProxy): the container's Guid
_GUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


class InstanceError(Exception):
    """An instance could not be started, read, renewed or stopped. One line, safe to show.

    `maybe_done`: the request that changes something went out and the platform may have done
    it all the same: no answer came in time, the line dropped, the answer was not the
    plugin's, a start was taken and its status then gave no address, or a start's own answer
    names an address flightdeck will not use. False when the platform said no and when
    nothing was sent. A run reads it after a start (instancerun.py): an instance of that
    challenge that turns up next is then its own, not a teammate's.

    `up`: the answer names an instance of the challenge, at an address flightdeck will not
    use. It runs all the same, and holds a slot until it is stopped."""

    def __init__(self, message: str, *, maybe_done: bool = False, up: bool = False) -> None:
        super().__init__(message)
        self.maybe_done = maybe_done
        self.up = up


class InstanceRefused(InstanceError):
    """The plugin answered and said no. `full`: because the team's cap on containers is reached.
    `human`: because it wants a person to pass a check (a CAPTCHA), which flightdeck never does."""

    def __init__(self, message: str, *, full: bool = False, human: bool = False) -> None:
        super().__init__(message)
        self.full = full
        self.human = human


class InstancePending(InstanceError):
    """The platform says the challenge's instance is on its way up or down (a state of
    pending_states, such as rCTF's "starting"): it holds a slot, and has no address yet.
    Nothing should be sent for it but the status, a little later. `maybe_done` when a start
    of this client's was taken and the instance has not come up within its looks."""

    def __init__(self, message: str, *, maybe_done: bool = False) -> None:
        super().__init__(message, maybe_done=maybe_done, up=True)


class InstanceFailed(InstanceError):
    """The platform says the challenge's instance failed: its state is one of failed_states
    (rCTF v2's "errored"). That is not "no instance": what a start does to such an instance
    is the platform's own and not known here, so none is sent, and the player sees to it on
    the site. `maybe_done` when a start of this client's was taken and then failed."""


class InstanceBusy(InstanceRefused):
    """The account's one container runs another challenge (Shape.busy): this challenge has
    none, and a start would remove the other. It reads as the cap (`full`): a run waits and
    asks again, and never sends the start."""

    def __init__(self, message: str) -> None:
        super().__init__(message, full=True)


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
    empty_body: bool = False  # a start or a renew whose path carries the id still sends {} (rCTF reads a JSON body there)
    empty: tuple[str, ...] = ()  # actions whose done is a 2xx with no body at all (GZCTF's stop: ASP.NET's Ok())
    language: str | None = None  # sent as Accept-Language, so the refusals read in words _FULL and _HUMAN know (GZCTF's)


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
    endpoints: tuple[str, ...] = ()  # keys of a list of {kind, host, port}: each one of the instance's addresses
    state: tuple[str, ...] = ()  # keys of a word that says what the instance is doing
    running: tuple[str, ...] = ()  # the state's words for "up"; with a state key, any other word is "not running"
    pending: tuple[str, ...] = ()  # the state's words for "on its way up or down": InstancePending
    failed: tuple[str, ...] = ()  # the state's words for "the platform could not run it": InstanceFailed
    expires_unit: float = 1.0  # seconds in one unit of a number of the end (UNITS)
    scopes: tuple[str, ...] = ("data",)  # the answer's objects looked in after the answer itself (GZCTF's detail: context)
    errors: tuple[str, ...] = ERROR_KEYS  # the keys of a refusal's words (GZCTF's RequestResponse: title)
    # (pattern, why): an address that matches it whole is one a lane cannot be handed, for that reason
    unreachable: tuple[re.Pattern[str], str] | None = None


@dataclass(frozen=True)
class Shape:
    """A named plugin: its routes, how its answers read, and what its source says of its limits."""

    routes: Routes
    answers: Answers = Answers()
    single: bool = False  # one container per account, and its stop takes whatever runs: max_running is 1, a stop asks first
    gap: float = 0.0  # seconds the plugin wants between two requests that change something; the client waits them
    replaces: bool = False  # a start first removes whatever the account runs: the client asks the status before it sends one
    busy: re.Pattern[str] | None = None  # a refusal in these words: the account's one container is another challenge's
    platform: str = "ctfd"  # the event.platform it is for


_CONTAINERS = "/containers/api"
_OWL = "/plugins/ctfd-owl/container?challenge_id={id}"
_CHALL_MANAGER = "/plugins/ctfd-chall-manager/instance"
_WHALE = "/plugins/ctfd-whale/container?challenge_id={id}"
_RCTF = "/api/v2/integrations/challs/{id}/instance"
_GZCTF = "/api/game/{game}/container/{id}"

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
    # ctfd-whale (github.com/frankli0324/ctfd-whale at 2cc84a9: api.py, decorators.py, utils/control.py, utils/routers/),
    # read from its source, not met. One container per user account. Its POST removes that container, of any challenge,
    # before it starts one, and answers no address; its GET for another challenge's container is a 403, "Container already
    # started but not from this challenge"; data.user_access is the router's line (an nc line, a link's HTML, a pwntools
    # snippet, an https URL, "[ssl] host port"), data.remaining_time the seconds left. Its changing routes refuse a second
    # request within 60 s (decorators.frequency_limited).
    "ctfd_whale": Shape(
        Routes(start=("POST", _WHALE), stop=("DELETE", _WHALE), renew=("PATCH", _WHALE), status=("GET", _WHALE), api=True),
        Answers(address=("user_access",), port=(), expires=("remaining_time",), loose=True),
        single=True, gap=60.0, replaces=True, busy=re.compile(r"\bnot from this challenge\b", re.I),
    ),
    # rCTF v2's own instancer (github.com/otter-sec/rctf: apps/docs .../api/integrations/instance-*.md and
    # packages/types goodInstanceStatus), read from its documentation and types, not met. One route, four methods;
    # data is {status, timeLeftMilliseconds, endpoints: [{kind, host, port, title?, text?}] or null}. A start may
    # answer "starting", the status "running" later; "errored" is one the platform could not run. Errors are {kind, message, data: {error | message}}.
    "rctf": Shape(
        Routes(start=("PUT", _RCTF), stop=("DELETE", _RCTF), renew=("PATCH", _RCTF), status=("GET", _RCTF), empty_body=True),
        Answers(address=(), port=(), expires=("timeLeftMilliseconds",), endpoints=("endpoints",), state=("status",),
                running=("running",), pending=("starting", "stopping"), failed=("errored",), expires_unit=UNITS["ms"]),
        platform="http",
    ),
    # GZCTF (github.com/GZTimeWalker/GZCTF, branch develop: Controllers/GameController.cs, Models/Request/Game/
    # ContainerInfoModel.cs and ChallengeDetailModel.cs, Models/Data/Container.cs and Instance.cs, ClientApp/src/Api.ts),
    # read from its source, not met. No route reads a container, so the status is the challenge's detail: context.
    # instanceEntry is the container's Entry ("ip:port", or its Guid when the site proxies it), context.closeTime its
    # end; both null with no container, and a challenge the team has no instance of is a 404. The start (a 400 when one
    # runs) and the extend answer ContainerInfoModel {status, startedAt, expectStopAt, entry}; times are Unix
    # milliseconds. A start or a stop within 10 s of the last on that challenge is a 429 (IsContainerOperationTooFrequent);
    # an extend before the site's RenewalWindow (10 minutes by default) is a 400.
    "gzctf": Shape(
        Routes(start=("POST", _GZCTF), stop=("DELETE", _GZCTF), renew=("POST", _GZCTF + "/extend"),
               status=("GET", "/api/game/{game}/challenges/{id}"), empty=("stop",), language="en-US"),
        Answers(address=("entry", "instanceEntry"), port=(), expires=("expectStopAt", "closeTime"), state=("status",),
                pending=("Pending",), expires_unit=UNITS["ms"], scopes=("context",), errors=("title",),
                unreachable=(_GUID, "GZCTF serves this container through its own WebSocket proxy (the site's PlatformProxy "
                                    "port mapping), which flightdeck cannot hand a lane: open it from the challenge on the site")),
        gap=10.0, platform="http",
    ),
}
# names a profile may still carry, and what to write instead
REMOVED = {
    "ctfd_docker": "its routes were a guess that matches no plugin whose source was read. CTFd-Docker-Plugin and its forks "
                   "are docker_per_team",
}


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
    replaces: bool = False  # Shape.replaces
    busy: re.Pattern[str] | None = None  # Shape.busy
    platform: str | None = None  # Shape.platform: the event.platform the named shape is for; None: routes of the profile's own


_ANSWER_KEYS = {"address_key": "address", "port_key": "port", "expires_key": "expires", "endpoints_key": "endpoints",
                "state_key": "state"}
_STATE_WORDS = {"running_states": "running", "pending_states": "pending", "failed_states": "failed"}
_KEYS = ("plugin", "types", "max_running", *ACTIONS, "body_key", "api", *_ANSWER_KEYS, *_STATE_WORDS, "expires_unit")


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
        raise ValueError(f"instances.plugin {_show(plugin)} is not a plugin flightdeck knows (known: {', '.join(PLUGINS)}); "
                         "give the four routes instead (start, stop, renew, status)")
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
    routes = Routes(**{action: given.get(action) or getattr(base, action) for action in ACTIONS}, body_key=body_key, api=api,
                    empty_body=base.empty_body if base is not None else False, empty=base.empty if base is not None else (),
                    language=base.language if base is not None else None)
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
        past = ("a start removes the one that runs" if shape is not None and shape.replaces
                else "a start past it is refused")
        raise ValueError(f"instances.max_running must be 1 with plugin {plugin}: it runs one container per account, and {past}")
    answers = shape.answers if shape is not None else Answers()
    named: dict[str, object] = {part: _keys(key, table[key]) for key, part in _ANSWER_KEYS.items() if key in table}
    if "address" in named and not named["address"]:
        raise ValueError("instances.address_key must name at least one key: an answer with no address is no instance")
    named.update({part: _words(key, table[key]) for key, part in _STATE_WORDS.items() if key in table})
    if "expires_unit" in table:
        unit = table["expires_unit"]
        if not isinstance(unit, str) or unit not in UNITS:
            raise ValueError(f"instances.expires_unit must be one of {', '.join(UNITS)}: what a number of the end counts")
        named["expires_unit"] = UNITS[unit]
    answers = replace(answers, **named)
    if (answers.running or answers.pending or answers.failed) and not answers.state:
        raise ValueError("instances.running_states, pending_states and failed_states need state_key: the answer's key that holds "
                         "those words")
    if set(answers.running) & set(answers.pending) or set(answers.failed) & {*answers.running, *answers.pending}:
        raise ValueError("instances.running_states, pending_states and failed_states must not share a word")
    if not answers.address and not answers.endpoints:
        raise ValueError("instances needs address_key or endpoints_key: an answer with no address is no instance")
    return InstancesConfig(routes, tuple(types), most, plugin, answers, single, shape.gap if shape is not None else 0.0,
                           shape.replaces if shape is not None else False, shape.busy if shape is not None else None,
                           shape.platform if shape is not None else None)


def _words(name: str, value: object) -> tuple[str, ...]:
    """running_states, pending_states or failed_states: a list of the words the state key may hold."""
    if not isinstance(value, list) or len(value) > MAX_STATES or \
            not all(isinstance(word, str) and word.strip() and len(word) <= 64 for word in value) or len(set(value)) != len(value):
        raise ValueError(f'instances.{name} must be a list of up to {MAX_STATES} distinct words, such as ["running"]')
    return tuple(value)


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
    bare = path
    for placeholder in _PLACEHOLDERS:
        bare = bare.replace(placeholder, "")
    if "{" in bare or "}" in bare:
        raise ValueError(f"instances.{action}: a brace in the path must be {{id}} (the challenge's id) or {{game}} (the http "
                         "table's game)")
    return method, path


@dataclass(frozen=True)
class Instance:
    """A running instance: where it is, and when the platform stops it if it said."""

    challenge: str  # the board's id
    host: str
    port: int | None
    scheme: str | None = None  # "http", "https", "tcp" or "tls" (a TLS endpoint) when the plugin said; None: a bare host and port
    expires_at: float | None = None  # time.time() when the platform stops it; None: it did not say, or not so flightdeck can read it
    said: str = field(default="", compare=False)  # the plugin's words, safe to show
    more: tuple[tuple[str | None, str, int | None], ...] = ()  # (scheme, host, port) of its other addresses, in the plugin's order
    left_out: tuple[str, ...] = field(default=(), compare=False)  # addresses it named that no lane gets, each safe to show

    def url(self, web: bool) -> str:
        """The instance as a board's `urls` entry: the plugin's own scheme when it gave one
        (tls://host:port for a TLS endpoint that is no web server, what `ncat --ssl host port`
        reaches), else http for a web challenge and tcp for any other (what `nc host port`
        reaches)."""
        return _url(self.scheme, self.host, self.port, web)

    def urls(self, web: bool) -> tuple[str, ...]:
        """Every address of the instance as `urls` entries, the first one first."""
        return tuple(dict.fromkeys([self.url(web), *(_url(scheme, host, port, web) for scheme, host, port in self.more)]))

    def places(self) -> tuple[tuple[str, int | None], ...]:
        """(host, port) of every address: what a lane's network is fenced to."""
        return ((self.host, self.port), *((host, port) for _, host, port in self.more))


def _url(scheme: str | None, host: str, port: int | None, web: bool) -> str:
    scheme = scheme or ("http" if web else "tcp")
    return f"{scheme}://{host}" if port is None else f"{scheme}://{host}:{port}"


class _Ids(dict):
    """Board id -> the platform's own id for the challenge, each checked as it is put in: a
    CTFd number (1 or more), or a string ref (plugins.call.valid_ref)."""

    def __setitem__(self, key: object, value: object) -> None:
        if not isinstance(key, str) or not (_is_number(value) or valid_ref(value)):
            raise ValueError("ids must map board ids (strings) to the platform's challenge ids: CTFd's whole numbers (1 or more), "
                             "or refs (strings of 1 to 128 printable characters)")
        super().__setitem__(key, value)

    def update(self, *args, **kwargs) -> None:  # type: ignore[override]
        for key, value in dict(*args, **kwargs).items():
            self[key] = value


class Wire(Protocol):
    """How a request reaches the platform with the player's token: the address every route is
    under, the headers that carry the token (asked for each request: a session may be signed
    in for first), and the platform's words made safe to show (no token in them).
    `unauthorized()` is told of a 401, so a session the platform no longer takes is asked
    for again. CTFd's is its _Site; the http platform's is HttpCaller.instance_wire()."""

    root: str
    game: str | None  # the value of {game} in a route: the http table's game; None on CTFd

    def headers(self) -> dict[str, str]: ...

    def short(self, text: str) -> str: ...


class InstanceClient:
    """Asks one platform's instancer for the board's challenges' instances: a CTFd's container
    plugin (base_url and token: CTFd's own), or the http platform's (`wire`)."""

    def __init__(self, base_url: str | None, token: str | None, ids: Mapping[str, int | str], config: InstancesConfig, *,
                 wire: Wire | None = None, timeout: float = 20.0, transport: httpx.BaseTransport | None = None, clock=time.time,
                 sleep: Callable[[float], None] = time.sleep, monotonic: Callable[[], float] = time.monotonic) -> None:
        if wire is None:
            if base_url is None or token is None:
                raise ValueError("an instance client needs the platform's address and token, or a wire that carries them")
            wire = _Site(base_url, token)
        self._site = wire
        if not timeout > 0:
            raise ValueError(f"timeout must be a positive number of seconds, got {timeout}")
        self.ids: _Ids = _Ids()
        self.ids.update(ids)
        self.config = config
        self.timeout = timeout
        self._clock = clock
        self._sleep = sleep  # in the caller's thread: a run calls this client from a worker thread
        self._monotonic = monotonic
        self._changed_at: float | None = None  # when the last request that changes something was answered (config.gap)
        self._http = httpx.Client(
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
        answers the same, one refuses, one replaces it): ask status() first, as a run does.
        On a plugin whose start replaces it (config.replaces) the client asks itself, and
        sends the start only when the account runs nothing: this challenge's instance is
        returned as it runs, and another challenge's is an InstanceBusy, with nothing sent."""
        if self.config.replaces:
            there = self.status(challenge_id)
            if there is not None:
                return there
        doc = self._ask("start", challenge_id)
        assert doc is not None
        pending: InstancePending | None = None
        try:
            reading = self._reading(doc)
            if reading == "up":
                return self._instance(challenge_id, doc)
            if reading == "failed":
                raise self._failed(challenge_id, doc)
            for asked in range(STATUS_TRIES):
                if asked:
                    self._sleep(STATUS_GAP)
                try:
                    found = self.status(challenge_id)
                except InstancePending as exc:  # on its way up: looked at again, as an answer with no address is
                    pending = exc
                    continue
                if found is not None:
                    return found
        except InstanceError as exc:
            exc.maybe_done = True  # the start was taken: whatever its answer or the status said, an instance may run
            raise
        if pending is not None or self._reading(doc) == "pending":
            raise InstancePending(f"the platform took the start for {_show(challenge_id)} and is still starting its instance; "
                                  "flightdeck asks its status again in a while", maybe_done=True)
        said = self._dig(doc, ERROR_KEYS)
        words = f" ({self._site.short(str(said))})" if said is not None else ""
        raise InstanceError(
            f"the platform took the start for {_show(challenge_id)}, but neither its answer nor its status names an address{words}; "
            "is [instances] right for this site's plugin (address_key)?",
            maybe_done=True,
        )

    def status(self, challenge_id: str) -> Instance | None:
        """The challenge's running instance, or None when the plugin names none (or says, by
        its state, that none runs). InstancePending when it says one is on its way up or down,
        InstanceFailed when it says one failed."""
        doc = self._ask("status", challenge_id, refusal_is_none=True)
        reading = self._reading(doc)
        if reading == "failed":
            raise self._failed(challenge_id, doc)
        if reading == "pending":
            word = self._dig(doc, self.config.answers.state)
            raise InstancePending(f"the instance of {_show(challenge_id)} is on its way up or down on the platform "
                                  f"({self._site.short(str(word))}); flightdeck sends nothing for it and asks again in a while")
        if reading is None:
            return None
        return self._instance(challenge_id, doc)

    def _failed(self, challenge_id: str, doc: dict | None) -> InstanceFailed:
        word = _dig(doc, self.config.answers.state)
        return InstanceFailed(f"the platform says the instance of {_show(challenge_id)} failed ({self._site.short(str(word))}): "
                              "flightdeck sends no start for it while the platform says so; stop it or start it again on the site")

    def renew(self, challenge_id: str) -> Instance | None:
        """Ask for more time. The instance as the plugin now describes it, or None when its
        answer names no address (the time was extended; ask status() for the rest)."""
        doc = self._ask("renew", challenge_id)
        return self._instance(challenge_id, doc) if self._reading(doc) == "up" else None

    def stop(self, challenge_id: str) -> None:
        """Stop the challenge's instance and free its slot. On a plugin that keeps one
        container per account (config.single) the stop route takes whatever runs, so the
        status is asked first: when this challenge's instance is not the one running, nothing
        is stopped (a teammate's container of another challenge stays up). One the status
        names at an address flightdeck will not use is this challenge's all the same."""
        if self.config.single:
            try:
                there = self.status(challenge_id) is not None
            except InstanceBusy:
                return  # the account's container is another challenge's: this one has none to stop
            except InstanceError as exc:
                if not exc.up:
                    raise
                there = True
            if not there:
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
        what = f"instance {action} for challenge {_show(number)}"
        changes = action != "status"
        if "{id}" in path:  # the path carries the id: no body, so a GET goes out as a GET
            if number in (".", ".."):  # no encoding keeps it one path segment
                raise InstanceError(f"{what}: the challenge's id would name another route, so flightdeck did not send it")
            path = path.replace("{id}", quote(str(number), safe=""))
            if self.config.routes.empty_body and action in ("start", "renew"):
                content = b"{}"
        elif self.config.routes.body_key is not None:
            content = json.dumps({self.config.routes.body_key: number}).encode()
        if "{game}" in path:  # after the id: an id is percent-encoded whole, so no brace of it is left to fill
            game = getattr(self._site, "game", None)
            if not game:
                raise InstanceError(f"{what}: the route has {{game}} in it, and the platform has no game to put there (the [http] "
                                    "table's game); flightdeck sent nothing")
            if game in (".", ".."):
                raise InstanceError(f"{what}: the game would name another route, so flightdeck did not send it")
            path = path.replace("{game}", quote(str(game), safe=""))
        try:
            headers = self._site.headers()
        except InstanceError as exc:  # the wire's sign-in: nothing of this request was sent
            raise InstanceError(f"{what}: {exc}") from None
        if content is not None:
            headers = {**headers, "Content-Type": "application/json"}
        if self.config.routes.language is not None:
            headers = {**headers, "Accept-Language": self.config.routes.language}
        if changes and self.config.gap > 0 and self._changed_at is not None:
            waited = self._monotonic() - self._changed_at
            if waited < self.config.gap:  # the plugin refuses two changes this close together
                self._sleep(self.config.gap - waited)
        deadline = time.monotonic() + self.timeout

        def exchange():
            try:
                with self._http.stream(method, root + path, content=content, headers=headers) as response:
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
        if acted and action in self.config.routes.empty and not body.strip():
            return {}  # the plugin's own "done", with nothing to read
        doc = _parse(body)
        said = _said(doc, self.config.answers.errors)
        failed = isinstance(doc, dict) and (doc.get("success") is False or doc.get("error") not in (None, "", False))
        if status == 401:
            told = getattr(self._site, "unauthorized", None)
            if told is not None:
                told()  # a session the platform no longer takes: the next request signs in again
        if status >= 400 or failed:
            if self.config.busy is not None and said is not None and self.config.busy.search(str(said)):
                # the plugin's words name the other challenge in HTML: flightdeck says it in its own
                raise InstanceBusy(f"the platform refused {what}: the account's one container runs another challenge, and "
                                   f"{self.config.plugin or 'the plugin'} would remove it to start this one")
            if refusal_is_none and status in (400, 404):
                return None
            words = self._site.short(said) if said is not None else f"HTTP {status}"
            if said is not None and _HUMAN.search(said):
                raise InstanceRefused(f"the platform refused {what}: {words}. It wants a person to pass a check (a CAPTCHA), which "
                                      "flightdeck never does: start the instance on the site yourself, and flightdeck finds it there",
                                      human=True)
            raise InstanceRefused(f"the platform refused {what}: {words}", full=bool(said is not None and _FULL.search(said)))
        if not isinstance(doc, dict):
            raise InstanceError(f"{what}: the platform's answer is not JSON (HTTP {status}); is [instances] right for this site's plugin?",
                                maybe_done=acted)
        return doc

    def _reading(self, doc: dict | None) -> str | None:
        """What an answer says of the instance: "up" (it names an address, or its state is a
        running one), "pending" (its state is one of pending_states), "failed" (one of
        failed_states), or None (no instance)."""
        if doc is None:
            return None
        answers = self.config.answers
        if answers.state:
            word = self._dig(doc, answers.state)
            if isinstance(word, str) and word in answers.pending:
                return "pending"
            if isinstance(word, str) and word in answers.failed:
                return "failed"
            if answers.running:
                return "up" if word in answers.running else None  # "running" with no address is one at no usable address
        if self._dig(doc, answers.address) is not None or self._dig(doc, answers.endpoints) is not None:
            return "up"
        return None

    def _instance(self, challenge_id: str, doc: dict | None) -> Instance:
        assert doc is not None
        answers = self.config.answers
        listed = self._dig(doc, answers.endpoints)
        if listed is not None:
            return self._endpoints(challenge_id, doc, listed)
        raw = self._dig(doc, answers.address)
        if raw is None and answers.running:  # its state says it runs, and it names no address
            raise InstanceError(f"the platform says the instance of {_show(challenge_id)} runs, but names no address for it", up=True)
        if not isinstance(raw, str) or not raw.strip():
            raise InstanceError(f"the platform's answer for {_show(challenge_id)} names no address; is [instances] right for this site's plugin?")
        if answers.unreachable is not None and answers.unreachable[0].fullmatch(raw.strip()):
            raise InstanceError(f"the instance of {_show(challenge_id)} runs, at no address flightdeck can use: {answers.unreachable[1]}",
                                up=True)
        scheme, host, port = _address(raw.strip())
        if host is None and answers.loose:
            scheme, host, port = _within(raw)
        if port is None:
            given = _number(self._dig(doc, answers.port))
            if isinstance(given, int) and not isinstance(given, bool):
                port = given
        if scheme is None and answers.web is not None and self._dig(doc, (answers.web[0],)) == answers.web[1]:
            scheme = "http"  # the plugin says it is a web server: its address is one whatever the challenge's category
        if host is None or (port is not None and not 1 <= port <= 65535) or (port is None and scheme is None):
            raise InstanceError(f"the platform's answer for {_show(challenge_id)} names no usable address ({self._site.short(raw)})", up=True)
        return Instance(challenge_id, host, port, scheme, self._end(doc), self._site.short(raw))

    def _dig(self, doc: object, keys: tuple[str, ...]) -> object:
        """The first of `keys` with a value in the answer or in one of its scopes (Answers.scopes)."""
        return _dig(doc, keys, self.config.answers.scopes)

    def _end(self, doc: dict) -> float | None:
        return _ends(self._dig(doc, self.config.answers.expires), self._clock(), self.config.answers.expires_unit)

    def _endpoints(self, challenge_id: str, doc: dict, listed: object) -> Instance:
        """An instance from a list of endpoints, each {kind, host, port}: rCTF v2's form. Each
        host and port is checked as a single address is; a kind flightdeck cannot hand a lane
        (KINDS) is left out and named. Error, `up`, when none is left."""
        if not isinstance(listed, list):
            raise InstanceError(f"the platform's answer for {_show(challenge_id)} has endpoints that are not a list", up=True)
        usable: list[tuple[str | None, str, int]] = []
        left_out: list[str] = []
        for item in listed[:MAX_ENDPOINTS * 4]:
            if not isinstance(item, dict):
                left_out.append("an endpoint that is not an object")
                continue
            kind, host, port = item.get("kind"), item.get("host"), _number(item.get("port"))
            where = f"{host}:{port}" if isinstance(host, str) else "an endpoint with no host"
            if not isinstance(host, str) or not _HOST.fullmatch(host) or isinstance(port, bool) or not isinstance(port, int) \
                    or not 1 <= port <= 65535:
                left_out.append(self._site.short(f"{where}, which is not a host and a port"))
                continue
            if kind is not None and not isinstance(kind, str):  # a list or an object is no kind, and no key of KINDS
                left_out.append(self._site.short(f"{where} (a kind that is not a word)"))
                continue
            if kind is not None and kind not in KINDS:
                left_out.append(self._site.short(f"{where} ({kind}: a kind flightdeck cannot hand a lane yet)"))
                continue
            entry = (KINDS[kind] if kind is not None else None, host.lower(), port)
            if entry not in usable and len(usable) < MAX_ENDPOINTS:
                usable.append(entry)
        if not usable:
            why = "; ".join(left_out) if left_out else "the list is empty"
            raise InstanceError(f"the platform's answer for {_show(challenge_id)} names no address flightdeck can use ({why})", up=True)
        (scheme, host, port), more = usable[0], tuple(usable[1:])
        said = self._site.short(", ".join(f"{h}:{p}" for _, h, p in usable))
        return Instance(challenge_id, host, port, scheme, self._end(doc), said, more, tuple(left_out))


def _number(value: object) -> object:
    """A port the platform wrote as digits, as a number; anything else as it came. Five
    digits at most: a longer string is no port, and int() refuses one past 4300 digits."""
    if isinstance(value, str) and value.isascii() and value.isdigit() and len(value) <= 5:
        return int(value)
    return value


def _said(doc: object, keys: tuple[str, ...] = ERROR_KEYS) -> str | None:
    """A refusal's words: the answer's own (error, errors, message or msg, or the shape's
    `keys`: GZCTF's title), and its data's when they say more (rCTF: "Instancer
    precondition not met." and then why)."""
    if not isinstance(doc, dict):
        return None
    top = _first(doc, keys)
    data = doc.get("data")
    inner = _first(data, keys) if isinstance(data, dict) else None
    if top is not None and inner is not None and inner != top:
        return f"{top}: {inner}"
    return top if top is not None else inner


def _first(scope: dict, keys: tuple[str, ...]) -> str | None:
    for key in keys:
        if scope.get(key) not in (None, ""):
            return str(scope[key])
    return None


def _ends(left: object, now: float, unit: float = 1.0) -> float | None:
    """When an instance ends, from what the plugin says of it: time left (a small number, of
    `unit` seconds each), the moment itself (a large one, in the same units, or an ISO 8601 /
    RFC 3339 timestamp; one with no zone is read as UTC). None when it says nothing
    flightdeck can read."""
    if isinstance(left, str):
        text = left.strip()
        if re.fullmatch(r"\d{1,15}(\.\d{1,9})?", text):
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
    seconds = float(left) * unit
    return now + seconds if seconds < 10**9 else seconds


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
# pwntools: remote("host", port) or remote("host", port, ssl=True); with any other argument it is not read
_REMOTE_WITHIN = re.compile(r"(?<![\w.])remote\(\s*([\"'])([^\"'\s]{1,253})\1\s*,\s*(\d{1,5})\s*(?:,\s*ssl\s*=\s*(True|False)\s*)?\)")
_SSL_WITHIN = re.compile(r"(?<![\w-])\[ssl\]\s+([^\s:\"'<>]+)\s+(\d{1,5})(?![\w-])", re.I)  # "[ssl] host port"
_PAIR_WITHIN = re.compile(r"(?<![\w.@/-])([A-Za-z0-9][A-Za-z0-9.-]*):(\d{1,5})(?![\w@:-])")
_NAME_WITHIN = re.compile(r"(?:[A-Za-z0-9-]+\.)+[A-Za-z][A-Za-z0-9-]*")  # a dotted name whose last part starts with a letter
_IPV4_WITHIN = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")


def _within(text: str) -> tuple[str | None, str | None, int | None]:
    """(scheme, host, port) of the first address in a line a person wrote for players, such
    as "curl -v http://host:8080", "Connect with: nc host 31337" or a link's HTML: the first
    URL, else the first nc line, else the first pwntools remote("host", port) (a TLS
    endpoint with ssl=True), else the first "[ssl] host port" (a TLS endpoint), else the
    first host:port. Only the host and the port are taken, each checked as _address checks
    them; the rest of the line is never used.

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
    found = _REMOTE_WITHIN.search(text)
    if found:
        _, host, port = _address(f"{found.group(2)}:{found.group(3)}")
        return ("tls" if found.group(4) == "True" and host is not None else None), host, port
    found = _SSL_WITHIN.search(text)
    if found:
        _, host, port = _address(f"{found.group(1)}:{found.group(2)}")
        return ("tls" if host is not None else None), host, port
    for found in _PAIR_WITHIN.finditer(text):
        host = found.group(1)
        if _NAME_WITHIN.fullmatch(host) or (_IPV4_WITHIN.fullmatch(host) and all(int(part) <= 255 for part in host.split("."))):
            return _address(f"{host}:{found.group(2)}")
    return None, None, None


def _dig(doc: object, keys: tuple[str, ...], scopes: tuple[str, ...] = ("data",)) -> object:
    """The first of `keys` with a value in `doc`, or in one of its `scopes` (its `data`, say)."""
    inner = [doc.get(name) for name in scopes] if isinstance(doc, dict) else []
    for scope in (doc, *inner):
        if isinstance(scope, dict):
            for key in keys:
                if scope.get(key) not in (None, ""):
                    return scope[key]
    return None


def _show(value: object) -> str:
    return untrusted(str(value), one_line=True)
