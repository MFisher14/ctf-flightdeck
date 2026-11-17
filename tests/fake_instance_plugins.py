"""Three CTFd container plugins, faked for tests: ctfd-owl, ctfd-chall-manager and ctfd-whale.

Each is shaped from the plugin's public source, read on 2026-11-14, and answers as that code
does where flightdeck depends on it. Neither was run: what a real site does beyond its source
(a proxy in front, a fork, an older release) is not here. tests/fake_ctfd.py's FakeCTFd holds
one of each (`fake.owl`, `fake.chall_manager`) and sends them their routes, after CTFd's own
token check (`fake.whale` too). Every host, address and challenge is invented.

ctfd-owl (github.com/D0g3-Lab/H1ve, CTFd/plugins/ctfd-owl: __init__.py, control_utils.py,
db_utils.py). Site-root routes, the challenge's number in the query:

    GET, POST, PATCH, DELETE /plugins/ctfd-owl/container?challenge_id=N

- One container per account: the team in team mode, whichever member started it.
- GET (status): {"success": true} with nothing running; {} when the account's container is
  another challenge's; else type "redirect" with `ip` and `port`, or type "http" with
  `domain` (and ":port" when the site's http port is not 80), each with `remaining_time` and
  `lan_domain`.
- POST (start) answers {"success": true} and never the address. With a container already
  running, of any challenge: "You have boot NAME before." A launch that throws is answered
  {"success": true, "msg": "Failed when launch instance, ..."}: success, and no container.
- PATCH (renew) puts an hour back, up to a number of times. DELETE (stop) destroys the
  account's container whatever its challenge, and answers success with none.
- Every refusal is HTTP 200 with {"success": false, "msg": ...}, a missing challenge too (the
  404 is caught and its text sent as `msg`), except on PATCH, where it is a real 404.
- POST, PATCH and DELETE refuse a second one within the same second ("Frequency limit, You
  should wait at least 1 min.": the code compares against 1 second). The plugin keeps that
  clock in the session; this fake keeps one for the account, as a client that keeps its
  cookies meets it. `limit = 0` turns it off.
- The launch runs inside the POST, so a start answers only when the container is up: `slow`
  holds that answer back, as a launch that outlasts the client's patience does.

ctfd-chall-manager (github.com/ctfer-io/ctfd-chall-manager: api/instance.py,
utils/decorators.py, utils/helpers.py, utils/instance_manager.py). Under CTFd's API:

    GET /api/v1/plugins/ctfd-chall-manager/instance?challengeId=N
    POST, PATCH, DELETE /api/v1/plugins/ctfd-chall-manager/instance   with {"challengeId": N}

- GET (status): {"success": true, "data": {"connectionInfo", "until", "since"}}; with no
  instance, the manager's 404 passed on with {"success": false, "message": "error while
  getting instance info, contact admins"}. `until` is an RFC 3339 timestamp, absent for a
  challenge with no timeout.
- POST (start) answers the same data. One instance per challenge and account; a second
  start is HTTP 200 {"success": false, "message": "instance already exists"}. A start the
  account's mana cannot pay for is a 403, "You or your team used up all your mana."
- PATCH (renew) answers {"success": true, "data": {"message": "Your instance has been
  renewed !"}}; DELETE (stop) {"success": true, "data": {}}; either with no instance is the
  manager's 404.
- A challenge that is hidden or not there is a 403, "challenge not visible"; a request with
  no challengeId a 400, "missing args".

ctfd-whale (github.com/frankli0324/ctfd-whale at 2cc84a9, read on 2026-11-14: api.py,
decorators.py, utils/control.py, utils/routers/frp.py and trp.py). Under CTFd's API, the
challenge's number in the query:

    GET, POST, PATCH, DELETE /api/v1/plugins/ctfd-whale/container?challenge_id=N

- One container per user account (the user, not the team, even in team mode).
- GET (status): {"success": true, "data": {}} with nothing running; for another challenge's
  container a 403, "Container already started but not from this challenge (<a ...>NAME</a>)";
  else data with `user_access`, `lan_domain` and `remaining_time` (seconds).
- POST (start) first removes the account's container, whatever its challenge, then starts
  one and answers {"success": true, "message": "Container created"}, never the address.
- PATCH (renew) puts the full time back, up to a number of times; for another challenge's
  container a 403. DELETE (stop) removes the account's container whatever its challenge
  (the route does not even check the challenge).
- `user_access` is the router's line. frp: "nc IP PORT" for a direct challenge, a link's HTML
  for an http one. trp: a pwntools snippet with ssl=True for a direct one, an https URL for
  an http one, "[ssl] DOMAIN PORT" for any other.
- Refusals are flask-restx aborts: HTTP 403 with {"message", "success": false}. A challenge
  that is hidden or not there is a 403, "challenge not visible".
- POST, PATCH and DELETE refuse a second one within 60 seconds ("Frequency limit, You should
  wait at least 1 min."). The plugin keeps that clock in the session; this fake keeps one for
  the account. `limit = 0` turns it off.
- They also take a lock of the account's for 10 seconds (Redis, decorators.frequency_limited),
  and give it back only when the route answers well: one they refuse leaves it held, and any
  POST, PATCH or DELETE of the account in those 10 seconds, from any session, is refused
  before the plugin does anything, "Request Too Fast!". A real CTFd 3.7.7 with the plugin at
  2cc84a9 did both on 2026-11-17 (and kept the 60 s per session, as its source says).
"""

from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fake_ctfd import FakeCTFd, Reply

OWL_ROUTE = "/plugins/ctfd-owl/container"
OWL_TYPE = "dynamic_check_docker"
CHALL_MANAGER_ROUTE = "/api/v1/plugins/ctfd-chall-manager/instance"
CHALL_MANAGER_TYPE = "dynamic_iac"
WHALE_ROUTE = "/api/v1/plugins/ctfd-whale/container"
WHALE_TYPE = "dynamic_docker"
_NOT_FOUND = ("404 Not Found: The requested URL was not found on the server. If you entered the URL manually please check "
              "your spelling and try again.")


def _reply(status: int, body: object) -> Reply:
    from fake_ctfd import Reply

    return Reply(status, body)


class FakeOwl:
    """ctfd-owl's container routes. `container` is the account's one container, or None."""

    def __init__(self, site: FakeCTFd, clock=time.time) -> None:
        self.site = site
        self.clock = clock
        self.container: dict | None = None  # {"challenge", "port", "docker_id", "started", "renews"}
        self.http: set[int] = set()  # challenges served through the http proxy: answered with `domain`, not `ip` and `port`
        self.direct_ip = "198.51.100.7"  # frp_direct_ip_address (a documentation address)
        self.domain_suffix = "owl.example.test"  # frp_http_domain_suffix
        self.http_port = 80  # frp_http_port
        self.seconds = 3600  # a container's life, and what a renew puts back
        self.max_renews = 5  # docker_max_renew_count
        self.max_containers: int | None = None  # docker_max_container_count, for the whole site
        self.others = 0  # containers other accounts run, counted against max_containers
        self.launch_fails = False  # the launch throws: answered as success with a msg, and no container
        self.slow: threading.Event | None = None  # set: a start's answer waits for it (the plugin launches inside the POST)
        self.limit = 1  # seconds between two changing requests; 0: no limit
        self._changed: int | None = None
        self._next = 0

    def boot(self, challenge_id: int) -> dict:
        """A container for the account, as a teammate (or an earlier run) would have started it."""
        self._next += 1
        self.container = {"challenge": challenge_id, "port": 28000 + self._next, "docker_id": f"box{self._next:04d}",
                          "started": self.clock(), "renews": 0}
        return self.container

    def answer(self, method: str, query: dict) -> Reply:
        self._clean()
        number = _number(query.get("challenge_id", [None])[0])
        if method == "GET":
            if not self._visible(number):
                return self._no(_NOT_FOUND)
            if self.container is None:
                return _reply(200, {"success": True})
            if self.container["challenge"] != number:
                return _reply(200, {})
            return _reply(200, self._described())
        if method not in ("POST", "PATCH", "DELETE"):
            return _reply(405, "<html>Method Not Allowed</html>")
        if self._limited():
            return self._no("Frequency limit, You should wait at least 1 min.")
        if method == "POST":
            if self.container is not None:
                return self._no(f"You have boot {self.site.challenges[self.container['challenge']].name} before.")
            if not self._visible(number):
                return self._no(_NOT_FOUND)
            if self.max_containers is not None and self.max_containers <= self.others:
                return self._no("Max container count exceed.")
            if self.site.challenges[number].type != OWL_TYPE:
                return self._no(_NOT_FOUND)
            if self.launch_fails:
                return _reply(200, {"success": True, "msg": "Failed when launch instance, please contact with the admin."})
            self.boot(number)
            done = _reply(200, {"success": True})
            done.hold = self.slow  # the container is up; only the answer is late
            return done
        if method == "DELETE":
            self.container = None  # whatever its challenge: the route never looks at challenge_id
            return _reply(200, {"success": True})
        if not self._visible(number):
            return _reply(404, "<html>Not Found</html>")  # PATCH checks the challenge outside any try
        if self.container is None:
            return self._no("Instance not found.")
        if self.container["renews"] >= self.max_renews:
            return self._no("Max renewal times exceed.")
        if self.container["challenge"] == number:  # a renew for another challenge changes nothing, and still says success
            self.container["started"] = min(self.container["started"] + self.seconds, self.clock())
            self.container["renews"] += 1
        return _reply(200, {"success": True})

    def _described(self) -> dict:
        box = self.container
        assert box is not None
        common = {"remaining_time": int(self.seconds - (self.clock() - box["started"])), "lan_domain": f"1-{box['docker_id']}"}
        if box["challenge"] in self.http:
            domain = f"{box['docker_id']}.{self.domain_suffix}" + ("" if self.http_port == 80 else f":{self.http_port}")
            return {"success": True, "type": "http", "domain": domain, **common}
        return {"success": True, "type": "redirect", "ip": self.direct_ip, "port": box["port"], **common}

    def _visible(self, number: int | None) -> bool:
        return number in self.site.challenges and self.site.challenges[number].type != "hidden"

    def _limited(self) -> bool:
        now = int(self.clock())
        if self.limit and self._changed is not None and now - self._changed < self.limit:
            return True
        self._changed = now
        return False

    def _clean(self) -> None:  # the plugin's own job, every 5 s: a container past its life is destroyed
        if self.container is not None and self.clock() - self.container["started"] >= self.seconds:
            self.container = None

    @staticmethod
    def _no(words: str) -> Reply:
        return _reply(200, {"success": False, "msg": words})


class FakeChallManager:
    """ctfd-chall-manager's instance route. `instances`: challenge id -> its instance's data."""

    def __init__(self, site: FakeCTFd, clock=time.time) -> None:
        self.site = site
        self.clock = clock
        self.instances: dict[int, dict] = {}  # {"connectionInfo", "since", "until"}; no "until" without a timeout
        self.seconds: float | None = 600  # the challenge's timeout; None: an instance has no end
        self.connection = "nc {host} {port}"  # what the organiser's scenario writes as connectionInfo
        self.host = "cm.example.test"
        self.mana_total = 0  # 0: the mana feature is off
        self.mana_cost = 0  # what each instance costs when it is on
        self.mana_others = 0  # mana a teammate's instances hold, which this account's list does not show
        self._next = 0

    def boot(self, challenge_id: int) -> dict:
        """An instance for the account (the team), as a teammate or an earlier run would have started it."""
        self._next += 1
        data = {"connectionInfo": self.connection.format(host=self.host, port=30000 + self._next), "since": _stamp(self.clock())}
        if self.seconds is not None:
            data["until"] = _stamp(self.clock() + self.seconds)
        self.instances[challenge_id] = data
        return data

    def answer(self, method: str, query: dict, body: bytes) -> Reply:
        self._clean()
        in_query = query.get("challengeId", [None])[0]
        try:
            doc = json.loads(body) if body else None
        except ValueError:
            return _reply(400, {"message": "The browser (or proxy) sent a request that this server could not understand."})
        in_body = doc.get("challengeId") if isinstance(doc, dict) else None
        seen = in_query or in_body  # the visibility check takes it from either place
        if not seen:
            return self._abort(400, "missing args")
        challenge = self.site.challenges.get(_number(seen))
        if challenge is None or challenge.type == "hidden":
            return self._abort(403, "challenge not visible")
        if method == "GET":  # the status reads the query only, the changing routes the JSON body only
            if not in_query:
                return self._abort(400, "missing argument challenge_id of source_id")
        elif in_body is None:
            return _reply(400, {"message": "missing challenge_id"})
        number = _number(in_query if method == "GET" else in_body)
        if number != challenge.id:
            return _reply(400, {"message": "Input payload validation failed"})
        if challenge.type != CHALL_MANAGER_TYPE:
            return _reply(500, {"message": "Internal Server Error"})  # the plugin's own lookup of the challenge finds none
        running = self.instances.get(number)
        if method == "GET":
            if running is None:
                return _reply(404, {"success": False, "message": "error while getting instance info, contact admins"})
            return _reply(200, {"success": True, "data": dict(running)})
        if method == "POST":
            if self.mana_total > 0 and self.mana_cost > 0:
                used = self.mana_cost * len(self.instances) + self.mana_others
                if used + self.mana_cost > self.mana_total:
                    return self._abort(403, "You or your team used up all your mana.")
            if running is not None:
                return _reply(200, {"success": False, "message": "instance already exists"})
            return _reply(200, {"success": True, "data": dict(self.boot(number))})
        if method == "PATCH":
            if running is None:
                return _reply(404, {"success": False, "message": "error while patching instance, contact admins"})
            if self.seconds is not None:
                running["until"] = _stamp(self.clock() + self.seconds)
            return _reply(200, {"success": True, "data": {"message": "Your instance has been renewed !"}})
        if method == "DELETE":
            if running is None:
                return _reply(404, {"success": False, "message": "error while deleting instance, contact admins"})
            del self.instances[number]
            return _reply(200, {"success": True, "data": {}})
        return _reply(405, {"message": "The method is not allowed for the requested URL."})

    def _clean(self) -> None:  # the manager's janitor: an instance past its `until` is gone
        now = self.clock()
        for number, data in list(self.instances.items()):
            if "until" in data and datetime.fromisoformat(data["until"]).timestamp() <= now:
                del self.instances[number]

    @staticmethod
    def _abort(status: int, words: str) -> Reply:  # flask-restx's abort(code, message, success=False)
        return _reply(status, {"message": words, "success": False})


class FakeWhale:
    """ctfd-whale's container route. `container` is the account's one container, or None."""

    def __init__(self, site: FakeCTFd, clock=time.time) -> None:
        self.site = site
        self.clock = clock
        self.container: dict | None = None  # {"challenge", "port", "uuid", "started", "renews"}
        self.router = "frp"  # "frp" or "trp": which router the site uses, and so how user_access reads
        self.kinds: dict[int, str] = {}  # challenge id -> its redirect_type: "direct" (the default), "http" or another
        self.direct_ip = "198.51.100.9"  # frp_direct_ip_address (a documentation address)
        self.http_suffix = "whale.example.test"  # frp_http_domain_suffix
        self.http_port = "80"  # frp_http_port, a string as the site's config keeps it
        self.trp_suffix = "trp.example.test"  # trp_domain_suffix
        self.trp_port = 1443  # trp_listening_port
        self.seconds = 3600  # docker_timeout
        self.max_renews = 5  # docker_max_renew_count
        self.max_containers = 1000  # docker_max_container_count, for the whole site
        self.others = 0  # containers other accounts run
        self.launch_fails = False  # the launch throws: the record is removed and the start refused
        self.slow: threading.Event | None = None  # set: a start's answer waits for it (the launch is inside the POST)
        self.limit = 60  # seconds between two changing requests; 0: no limit
        self.lock = 10  # seconds the account's lock stays held after a changing request the plugin refused
        self.locked_until: float | None = None  # held until then: a changing request is "Request Too Fast!"
        self.removed: list[int] = []  # the challenges whose containers a start or a stop removed, in order
        self._changed: int | None = None
        self._next = 0

    def boot(self, challenge_id: int) -> dict:
        """A container for the account, as the player on the site (or an earlier run) would have started it."""
        self._next += 1
        self.container = {"challenge": challenge_id, "port": 28000 + self._next, "uuid": f"5eed{self._next:04d}",
                          "started": self.clock(), "renews": 0}
        return self.container

    def answer(self, method: str, query: dict) -> Reply:
        self._clean()
        number = _number(query.get("challenge_id", [None])[0])
        if method != "DELETE" and not self._visible(number):
            return self._abort("challenge not visible")
        if method == "GET":
            if self.container is None:
                return _reply(200, {"success": True, "data": {}})
            if self.container["challenge"] != number:
                theirs = self.site.challenges[self.container["challenge"]]
                link = f'<a target="_blank" href="/challenges#{theirs.category}-{theirs.name}-{theirs.id}">{theirs.name}</a>'
                return self._abort(f"Container already started but not from this challenge ({link})")
            return _reply(200, {"success": True, "data": {
                "lan_domain": f"1-{self.container['uuid']}", "user_access": self.access(self.container),
                "remaining_time": int(self.seconds - (self.clock() - self.container["started"]))}})
        if method not in ("POST", "PATCH", "DELETE"):
            return _reply(405, {"message": "The method is not allowed for the requested URL."})
        if self.locked_until is not None and self.clock() < self.locked_until:
            return self._abort("Request Too Fast!")  # before the route does anything; the lock stays as it is
        self.locked_until = self.clock() + self.lock  # taken: given back only by an answer that is no refusal (_done)
        if self._limited():
            return self._abort("Frequency limit, You should wait at least 1 min.")
        if method == "POST":
            self._remove()  # whatever runs, of any challenge: the plugin's first step
            if self.others > self.max_containers:  # counted after the removal, as the plugin does
                return self._abort("Max container count exceed.")
            if self.launch_fails or self.site.challenges[number].type != WHALE_TYPE:
                return self._abort("Container creation failed")
            self.boot(number)
            done = self._done({"success": True, "message": "Container created"})
            done.hold = self.slow
            return done
        if method == "DELETE":
            if self.container is None:
                return self._abort("No such container")
            self._remove()
            return self._done({"success": True, "message": "Container destroyed"})
        if self.container is None:
            return self._abort("Instance not found.")
        if self.container["challenge"] != number:
            return self._abort(f"Container started but not from this challenge（{self.site.challenges[self.container['challenge']].name}）")
        if self.container["renews"] >= self.max_renews:
            return self._abort("Max renewal count exceed.")
        self.container["started"] = self.clock()
        self.container["renews"] += 1
        return self._done({"success": True, "message": "Container Renewed"})

    def access(self, box: dict) -> str:
        """user_access as the site's router writes it (frp.py's and trp.py's access())."""
        kind = self.kinds.get(box["challenge"], "direct")
        if self.router == "frp":
            if kind == "direct":
                return f"nc {self.direct_ip} {box['port']}"
            if kind == "http":
                host = self.http_suffix + (f":{self.http_port}" if self.http_port != "80" else "")
                return f'<a target="_blank" href="http://{box["uuid"]}.{host}/">Link to the Challenge</a>'
            return ""
        domain = f"{box['uuid']}.{self.trp_suffix}"
        if kind == "direct":
            return f'from pwn import *<br>remote("{domain}", {self.trp_port}, ssl=True).interactive()'
        if kind == "http":
            return f"https://{domain}" + (f":{self.trp_port}" if self.trp_port != 443 else "")
        return f"[ssl] {domain} {self.trp_port}"

    def _done(self, body: dict) -> Reply:
        self.locked_until = None  # the route answered well: the plugin gives its lock back
        return _reply(200, body)

    def _remove(self) -> None:
        if self.container is not None:
            self.removed.append(self.container["challenge"])
            self.container = None

    def _visible(self, number: int | None) -> bool:
        return number in self.site.challenges and self.site.challenges[number].type != "hidden"

    def _limited(self) -> bool:
        now = int(self.clock())
        if self.limit and self._changed is not None and now - self._changed < self.limit:
            return True
        self._changed = now
        return False

    def _clean(self) -> None:  # the plugin's job, every 10 s: a container past its time is removed
        if self.container is not None and self.clock() - self.container["started"] >= self.seconds:
            self.container = None

    @staticmethod
    def _abort(words: str) -> Reply:  # flask-restx's abort(403, message, success=False)
        return _reply(403, {"message": words, "success": False})


def _number(value: object) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return int(value) if isinstance(value, str) and value.isascii() and value.isdigit() else None


def _stamp(moment: float) -> str:
    """A moment as the manager's API writes one: RFC 3339, UTC, with a Z."""
    return datetime.fromtimestamp(moment, timezone.utc).isoformat().replace("+00:00", "Z")
