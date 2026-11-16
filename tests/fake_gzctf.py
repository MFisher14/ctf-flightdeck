"""A stand-in for GZCTF's player API, for the gzctf preset of the http platform (platform/http.py).

It answers real HTTP on 127.0.0.1 in a background thread (FakeSite of tests/fake_http.py). The
game, the challenges, the flags and the cookie are invented; no real platform is contacted.

The shapes are GZCTF's as its public source has them (github.com/GZTimeWalker/GZCTF, branch
develop): ASP.NET's camelCase JSON, enums as their names, an error as RequestResponse
{"title", "status"}.

- every /api/game route wants the cookie GZCTF_Token: else 401 with no body, as ASP.NET's
  cookie scheme answers an API request it cannot sign in;
- GET /api/game/GAME/details: GameDetailModel, {challenges: {Category: [ChallengeInfo]},
  challengeCount, rank: {solvedChallenges: [{id, score, type, time}], ...}, teamToken, ...};
  ChallengeInfo is {id, title, category, score, solved (a count of the teams), deadline, bloods};
- GET /api/game/GAME/challenges/ID: ChallengeDetailModel, {id, title, content, category, hints,
  score, type, context: {closeTime, instanceEntry, url, fileSize}, limit, attempts, deadline};
  url is /assets/HASH/NAME for a file the site keeps, or a whole URL for one kept elsewhere;
- GET /assets/HASH/NAME: the file, with no sign-in asked;
- POST /api/game/GAME/challenges/ID {"flag"}: 200 and the submission's number, a bare JSON
  number; 400 RequestResponse past the challenge's limit, or when the flag is empty after
  the site's decryption (with ApiEncryption on, a flag sent in the clear decrypts to nothing);
  429 with Retry-After while `limited` is above 0;
- GET /api/game/GAME/challenges/ID/status/SUB: a bare JSON string, "FlagSubmitted" for the
  first `pending` looks, then "Accepted" or "WrongAnswer" (a flag sent again for a challenge
  already solved is Accepted, as GZCTF judges it);
- GET /api/config: ClientConfig, {title, slogan, apiPublicKey, ...}; apiPublicKey is null
  unless `encrypted`.

Containers (GameController's CreateContainer, ExtendContainerLifetime and DeleteContainer), for
a task whose `container` is a container type:

- POST /api/game/GAME/container/ID: ContainerInfoModel {status, startedAt, expectStopAt,
  entry}, times as Unix milliseconds; 400 when one runs ("The container of this challenge
  already exists"), at the team's cap ("The number of team containers cannot exceed N"), or
  for a challenge of no container type; entry is "host:port", or the container's Guid when
  `proxy` (the site's PlatformProxy port mapping); `pending_starts` starts answer Pending;
- POST /api/game/GAME/container/ID/extend: ContainerInfoModel, the end `extension` later;
  400 with none ("... hasn't been created") or before the last `window` seconds ("Container's
  lifetime cannot be extended yet");
- DELETE /api/game/GAME/container/ID: 200 with no body at all, as ASP.NET's Ok(); 400 with none;
- the detail's context.instanceEntry and closeTime are the container's entry and end, null
  with none; its type is the task's container type, else StaticAttachment.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections import deque
from dataclasses import dataclass, field

from fake_ctfd import Reply, Request
from fake_http import FakeSite

# Synthetic, and no real cookie: characters of the kind an ASP.NET ticket has (base64url).
COOKIE = "CfDJ8fake-gzctf-ticket_for-tests_0c41"
GAME = "3"
PUBLIC_KEY = "ZmFrZS14MjU1MTkta2V5LWZvci10ZXN0cy0wMDAwMDA="  # 32 invented bytes, base64
FLAG_FORMAT = r"t\{\w+\}"


@dataclass
class GTask:
    """An invented challenge. `files`: name -> content, or name -> a whole URL (a str) where
    the file is kept on another host (GZCTF has one attachment per challenge)."""

    id: int
    title: str
    category: str = "Misc"
    score: int = 100
    content: str = "A synthetic challenge."
    files: dict[str, bytes | str] = field(default_factory=dict)
    flag: str = "t{right}"
    solved: bool = False
    solves: int = 0
    limit: int = 0
    container: str | None = None  # "StaticContainer" or "DynamicContainer": the site starts one for the team when asked
    entry: str = ""  # the container's address as GZCTF's Entry gives it ("host:port"); "" for an invented one


def sample() -> list[GTask]:
    """Three invented challenges: one with a file, one with a limit, one the team has solved."""
    return [
        GTask(11, "Warm Up", score=50, content="Read the note.", files={"note.txt": b"a synthetic handout\n"}, flag="t{warm}"),
        GTask(12, "Web Thing", category="Web", score=250, flag="t{web}", solves=4, limit=3),
        GTask(13, "Done Before", score=150, flag="t{done}", solved=True),
    ]


def body(value: object, status: int = 200, headers: dict[str, str] | None = None) -> Reply:
    """A reply whose body is `value` as JSON, a bare number or string included."""
    return Reply(status, json.dumps(value).encode(), {"Content-Type": "application/json; charset=utf-8", **(headers or {})})


def problem(status: int, title: str) -> Reply:
    return Reply(status, {"title": title, "status": status})


class FakeGZCTF(FakeSite):
    """The fake GZCTF. Tests script replies ahead of its own for one kind of request
    (script("submit", ...); the kinds are "details", "challenge", "asset", "submit",
    "status" and "config")."""

    def __init__(self, tasks: list[GTask] | tuple[GTask, ...] = (), *, cookie: str = COOKIE, game: str = GAME) -> None:
        super().__init__(self._route)
        self.tasks: dict[int, GTask] = {task.id: task for task in tasks}
        self.cookie = cookie
        self.game = game
        self.encrypted = False
        self.limited = 0  # this many submits are answered 429 first
        self.pending = 1  # looks at a submission answered FlagSubmitted before its verdict
        self.submissions: dict[int, tuple[int, str, int]] = {}  # number -> (challenge, flag, looks so far)
        self.containers: dict[int, dict] = {}  # challenge -> its ContainerInfoModel
        self.container_limit = 3  # the game's ContainerCountLimit
        self.proxy = False  # the site serves containers through its own WebSocket proxy: the entry is a Guid
        self.pending_starts = 0  # this many starts answer status Pending (the detail names the entry all the same)
        self.lifetime = 7200.0  # seconds a container lives (DefaultLifetime: 120 minutes)
        self.extension = 7200.0  # seconds an extend adds (ExtensionDuration)
        self.window = 600.0  # an extend is taken only this many seconds before the end (RenewalWindow: 10 minutes)
        self._scripted: dict[str, deque[Reply]] = {}

    def script(self, kind: str, *replies: Reply) -> None:
        with self._lock:
            self._scripted.setdefault(kind, deque()).extend(replies)

    def of(self, kind: str) -> list[Request]:
        with self._lock:
            return [r for r in self.requests if kind_of(r) == kind]

    def submits(self) -> list[tuple[int, str]]:
        """(the challenge, the flag) of each submit, in order."""
        return [(int(r.route.split("/")[5]), r.json["flag"]) for r in self.of("submit")]

    def _route(self, request: Request) -> Reply:
        kind = kind_of(request)
        with self._lock:
            queued = self._scripted.get(kind)
            if queued:
                return queued.popleft()
        if kind == "config":
            return body({"title": "Synthetic GZ", "slogan": "Hack for fun not for profit", "footerInfo": None,
                         "apiPublicKey": PUBLIC_KEY if self.encrypted else None, "portMapping": "Default", "defaultLifetime": 120})
        if kind == "asset":
            for task in self.tasks.values():
                for name, content in task.files.items():
                    if isinstance(content, bytes) and request.route == asset_url(content, name):
                        return Reply(200, content)
            return problem(404, "File not found")
        if kind == "":
            return Reply(404, b"")
        if _cookie(request) != self.cookie:
            return Reply(401, b"")
        parts = request.route.split("/")
        if parts[3] != self.game:
            return problem(404, "Game not found")
        if kind == "details":
            return body(self._details())
        task = self.tasks.get(int(parts[5]))
        if task is None:
            return problem(404, "Challenge not found")
        if kind == "challenge":
            return body(self._detail(task))
        if kind.startswith("container-"):
            return self._container(task, kind)
        if kind == "submit":
            return self._submit(task, request)
        return self._status(task, int(parts[7]))

    def _details(self) -> dict:
        board: dict[str, list] = {}
        for task in self.tasks.values():
            board.setdefault(task.category, []).append({"id": task.id, "title": task.title, "category": task.category, "score": task.score,
                                                        "solved": task.solves, "deadline": None, "bloods": [], "disableBloodBonus": False})
        solved = [{"id": t.id, "score": t.score, "type": "Normal", "userName": "player", "time": 0} for t in self.tasks.values() if t.solved]
        return {"challenges": board, "challengeCount": len(self.tasks), "teamToken": "synthetic-team-signature",
                "rank": {"id": 7, "name": "synthetic team", "score": 0, "rank": 1, "lastSubmissionTime": 0, "solvedChallenges": solved},
                "writeupRequired": False, "writeupDeadline": 0}

    def _detail(self, task: GTask) -> dict:
        url = None
        for name, content in task.files.items():
            url = content if isinstance(content, str) else asset_url(content, name)
        attempts = sum(1 for challenge, _, _ in self.submissions.values() if challenge == task.id)
        running = self.containers.get(task.id)
        return {"id": task.id, "title": task.title, "content": task.content, "category": task.category, "hints": [], "score": task.score,
                "type": task.container or "StaticAttachment",
                "context": {"closeTime": running["expectStopAt"] if running else None,
                            "instanceEntry": running["entry"] if running else None, "url": url, "fileSize": None},
                "limit": task.limit, "attempts": attempts, "deadline": None}

    def _container(self, task: GTask, kind: str) -> Reply:
        if task.container is None:
            return problem(400, "This challenge cannot create a container")
        running = self.containers.get(task.id)
        now = time.time() * 1000
        if kind == "container-start":
            if running is not None:
                return problem(400, "The container of this challenge already exists")
            if len(self.containers) >= self.container_limit:
                return problem(400, f"The number of team containers cannot exceed {self.container_limit}")
            entry = GUID if self.proxy else (task.entry or f"10.13.{task.id}.7:3{task.id:04d}")
            status = "Running"
            if self.pending_starts > 0:
                self.pending_starts -= 1
                status = "Pending"
            self.containers[task.id] = {"status": status, "startedAt": int(now), "expectStopAt": int(now + self.lifetime * 1000),
                                        "entry": entry}
            return body(self.containers[task.id])
        if running is None:
            return problem(400, "The container of this challenge hasn't been created")
        if kind == "container-extend":
            if running["expectStopAt"] - now > self.window * 1000:
                return problem(400, "Container's lifetime cannot be extended yet")
            running["expectStopAt"] = int(running["expectStopAt"] + self.extension * 1000)
            return body(running)
        del self.containers[task.id]
        return Reply(200, b"")

    def _submit(self, task: GTask, request: Request) -> Reply:
        flag = request.json.get("flag") if isinstance(request.json, dict) else None
        if self.encrypted:  # the site decrypts what it is sent: a flag in the clear decrypts to nothing
            flag = None
        if not isinstance(flag, str) or not flag.strip():
            return problem(400, "Flag is required")
        if self.limited > 0:
            self.limited -= 1
            return Reply(429, b"", {"Retry-After": "5"})
        attempts = sum(1 for challenge, _, _ in self.submissions.values() if challenge == task.id)
        if task.limit and attempts >= task.limit:
            return problem(400, "Submission limit exceeded")
        number = 900 + len(self.submissions) + 1
        self.submissions[number] = (task.id, flag, 0)
        return body(number)

    def _status(self, task: GTask, number: int) -> Reply:
        found = self.submissions.get(number)
        if found is None or found[0] != task.id:
            return problem(404, "Submission not found")
        challenge, flag, looks = found
        self.submissions[number] = (challenge, flag, looks + 1)
        if looks < self.pending:
            return body("FlagSubmitted")
        if flag == task.flag:
            task.solved = True
            return body("Accepted")
        return body("WrongAnswer")


GUID = "0f8fad5b-d9cb-469f-a165-70867728950e"  # an invented container id, as a proxied entry shows it


def asset_url(content: bytes, name: str) -> str:
    """Where GZCTF keeps a file it holds: /assets/<sha256 of the file>/<its name>."""
    return f"/assets/{hashlib.sha256(content).hexdigest()}/{name}"


def _cookie(request: Request) -> str | None:
    for part in request.headers.get("cookie", "").split(";"):
        name, _, value = part.strip().partition("=")
        if name == "GZCTF_Token":
            return value
    return None


def kind_of(request: Request) -> str:
    """What a request to the fake asks for: "details", "challenge", "asset", "submit", "status", "config",
    "container-start", "container-extend", "container-stop"; "" else."""
    method, parts = request.method, request.route.split("/")
    if (method, request.route) == ("GET", "/api/config"):
        return "config"
    if method == "GET" and len(parts) == 4 and parts[1] == "assets":
        return "asset"
    if len(parts) < 5 or parts[:3] != ["", "api", "game"] or not parts[3].isdigit():
        return ""
    if (method, len(parts), parts[4]) == ("GET", 5, "details"):
        return "details"
    if len(parts) >= 6 and parts[4] == "container" and parts[5].isdigit():
        if len(parts) == 6:
            return {"POST": "container-start", "DELETE": "container-stop"}.get(method, "")
        if (method, len(parts), parts[6]) == ("POST", 7, "extend"):
            return "container-extend"
        return ""
    if len(parts) >= 6 and parts[4] == "challenges" and parts[5].isdigit():
        if len(parts) == 6:
            return {"GET": "challenge", "POST": "submit"}.get(method, "")
        if method == "GET" and len(parts) == 8 and parts[6] == "status" and parts[7].isdigit():
            return "status"
    return ""
