"""Stand-ins for platforms with a JSON API, for the tests of the http platform (platform/http.py).

Both answer real HTTP on 127.0.0.1 in a background thread (the server of tests/fake_ctfd.py).
The challenges and the tokens are invented, and no real platform is contacted.

FakeSite is a server whose answers the test writes: `handler(request) -> Reply`. It serves
the shapes that are not rCTF's (a bearer token, a detail route, a submission that is judged
later) and the hosts that are not the platform (a file host, the target of a redirect).

FakeRCTF answers in the shape of rCTF's player API, as its public source has it
(github.com/redpwn/rctf, server/api): a body of {"kind", "message", "data"}, with the kind
carrying the verdict whatever the HTTP status.

- POST /api/v1/auth/login {"teamToken"}: 200 goodLogin with data.authToken; 401
  badTokenVerification for another token;
- every other route wants `Authorization: Bearer <authToken>`: else 401 badToken;
- GET /api/v1/challs: 200 goodChallenges, data a list of {id, name, description, category,
  author, files: [{name, url}], points, solves, sortWeight}; 401 badNotStarted before the
  start. A file's url is a path (`/uploads?key=...`, the default upload provider's form)
  unless the task gives a whole URL (the form of a storage bucket);
- GET /uploads?key=KEY: the file, with no sign-in asked;
- POST /api/v1/challs/ID/submit {"flag"}: 200 goodFlag, 400 badFlag, 409
  badAlreadySolvedChallenge, 429 badRateLimit with data.timeLeft in milliseconds (while
  `limited` is above 0), 404 badChallenge, 401 badEnded after the end;
- GET /api/v1/users/me: 200 goodUserData; data.solves lists {id, ...}, and data.teamToken is
  the team's own token, as rCTF returns it there.
"""

from __future__ import annotations

import json
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import parse_qs, quote, urlsplit

from fake_ctfd import STOP_WAIT, TLS, Reply, Request, _Server
from serving import Serving

TEAM_TOKEN = "fake-rctf-team-token-for-tests-51b8"  # synthetic, and not shaped like any real token
AUTH_TOKEN = "fake-rctf-session-for-tests-e07a"  # what the fake's login answers with
FLAG_FORMAT = r"t\{\w+\}"  # the flags of the invented challenges below


class FakeSite:
    """A server on 127.0.0.1 (a free port) that answers what `handler` returns for each
    request, and records every request. With `tls` it speaks https."""

    def __init__(self, handler: Callable[[Request], Reply], *, tls: TLS | None = None) -> None:
        self.handler = handler
        self.requests: list[Request] = []
        self._lock = threading.Lock()
        self._httpd = _Server(self, tls)
        self.url = f"{'https' if tls is not None else 'http'}://127.0.0.1:{self._httpd.server_address[1]}"
        self._serving: Serving | None = None

    def __enter__(self):
        self._serving = Serving(self._httpd, "fake-http")
        return self

    def __exit__(self, *exc: object) -> None:
        if self._serving is not None:
            self._serving.stop()
        self._httpd.close(wait=STOP_WAIT)

    def sent(self, method: str, route: str) -> list[Request]:
        """The requests with that method to that route (the path without its query), in order."""
        with self._lock:
            return [r for r in self.requests if r.method == method and r.route == route]

    def _answer(self, method: str, path: str, headers: dict[str, str], body: bytes) -> Reply:
        request = Request(method, path, headers, body, time.monotonic())
        with self._lock:
            self.requests.append(request)
        try:
            return self.handler(request)
        except Exception as exc:  # a bug in the test's handler: say so instead of hanging the client
            return Reply(500, {"error": "fake_site_bug", "message": f"{type(exc).__name__}: {exc}"})


@dataclass
class RTask:
    """An invented challenge. `files`: name -> content, or name -> a whole URL (a str) where
    the file is kept on another host. `flag`: the right one."""

    id: str
    name: str
    category: str = "misc"
    points: int = 100
    description: str = "A synthetic challenge."
    files: dict[str, bytes | str] = field(default_factory=dict)
    flag: str = "t{right}"
    solved: bool = False
    solves: int = 0


def sample() -> list[RTask]:
    """Three invented challenges: one with a file, one without, one the team has solved. No
    file holds its challenge's flag."""
    return [
        RTask("warm-7f3a", "Warm Up", points=50, description="Read the note.", files={"note.txt": b"a synthetic handout\n"}, flag="t{warm}"),
        RTask("web-19c2", "Web Thing", category="web", points=250, flag="t{web}", solves=4),
        RTask("done-a4d0", "Done Before", points=150, flag="t{done}", solved=True),
    ]


def answer(status: int, kind: str, message: str, data: object = None) -> Reply:
    body: dict = {"kind": kind, "message": message}
    if data is not None:
        body["data"] = data
    return Reply(status, body)


class FakeRCTF(FakeSite):
    """The fake rCTF. Tests script replies ahead of its own for one kind of request
    (script("challs", ...); the kinds are "login", "challs", "file", "submit" and "me")."""

    def __init__(self, tasks: list[RTask] | tuple[RTask, ...] = (), *, team_token: str = TEAM_TOKEN, auth_token: str = AUTH_TOKEN) -> None:
        super().__init__(self._route)
        self.tasks: dict[str, RTask] = {task.id: task for task in tasks}
        self.team_token = team_token
        self.auth_token = auth_token
        self.started = True
        self.ended = False
        self.limited = 0  # this many submits are answered badRateLimit first
        self.time_left = 4000  # their data.timeLeft, in milliseconds
        self._scripted: dict[str, deque[Reply]] = {}

    def add(self, *tasks: RTask) -> None:
        with self._lock:
            for task in tasks:
                self.tasks[task.id] = task

    def script(self, kind: str, *replies: Reply) -> None:
        """The next requests of that kind get these replies first, in order."""
        with self._lock:
            self._scripted.setdefault(kind, deque()).extend(replies)

    def kinds(self) -> list[str]:
        """What each request so far asked for, in order."""
        with self._lock:
            return [kind_of(r) for r in self.requests]

    def of(self, kind: str) -> list[Request]:
        with self._lock:
            return [r for r in self.requests if kind_of(r) == kind]

    def submits(self) -> list[tuple[str, str]]:
        """(the challenge's id as the path carried it, the flag) of each submit, in order."""
        return [(r.route.split("/")[4], r.json["flag"]) for r in self.of("submit")]

    def _route(self, request: Request) -> Reply:
        kind = kind_of(request)
        with self._lock:
            queued = self._scripted.get(kind)
            if queued:
                return queued.popleft()
        if kind == "login":
            token = request.json.get("teamToken") if isinstance(request.json, dict) else None
            if token != self.team_token:
                return answer(401, "badTokenVerification", "The token is not one of ours.")
            return answer(200, "goodLogin", "Signed in.", {"authToken": self.auth_token})
        if kind == "file":
            key = parse_qs(urlsplit(request.path).query).get("key", [""])[0]
            for task in self.tasks.values():
                for name, content in task.files.items():
                    if isinstance(content, bytes) and key == f"{task.id}-{name}":
                        return Reply(200, content)
            return Reply(404, "no such upload")
        if kind == "":
            return answer(404, "badEndpoint", "No such route.")
        scheme, _, value = request.headers.get("authorization", "").partition(" ")
        if scheme != "Bearer" or value != self.auth_token:
            return answer(401, "badToken", "The token is not valid.")
        if kind == "challs":
            if not self.started:
                return answer(401, "badNotStarted", "The event has not started yet.")
            return answer(200, "goodChallenges", "The challenges.", [self._listed(task) for task in self.tasks.values()])
        if kind == "me":
            solves = [{"id": t.id, "name": t.name, "category": t.category, "points": t.points, "solves": t.solves, "createdAt": 0}
                      for t in self.tasks.values() if t.solved]
            return answer(200, "goodUserData", "The team.", {"name": "synthetic team", "score": 0, "solves": solves,
                                                             "teamToken": self.team_token, "id": "team-0001"})
        return self._submit(request)

    def _listed(self, task: RTask) -> dict:
        files = [{"name": name, "url": content if isinstance(content, str) else f"/uploads?key={quote(f'{task.id}-{name}', safe='')}"}
                 for name, content in task.files.items()]
        return {"id": task.id, "name": task.name, "description": task.description, "category": task.category, "author": "nobody",
                "files": files, "points": task.points, "solves": task.solves, "sortWeight": 0}

    def _submit(self, request: Request) -> Reply:
        task = self.tasks.get(request.route.split("/")[4])
        if self.ended:
            return answer(401, "badEnded", "The event is over.")
        if task is None:
            return answer(404, "badChallenge", "No such challenge.")
        try:
            flag = json.loads(request.body)["flag"]
        except (ValueError, KeyError, TypeError):
            return answer(400, "badBody", "The body is not what this route takes.")
        if self.limited > 0:
            self.limited -= 1
            return answer(429, "badRateLimit", "Too many submissions: slow down.", {"timeLeft": self.time_left})
        if task.solved:
            return answer(409, "badAlreadySolvedChallenge", "Your team solved this one already.")
        if flag != task.flag:
            return answer(400, "badFlag", "That is not the flag.")
        task.solved = True
        return answer(200, "goodFlag", "That is the flag.")


def kind_of(request: Request) -> str:
    """What a request to the fake rCTF asks for: "login", "challs", "file", "submit", "me"; "" for anything else."""
    route, method = request.route, request.method
    if (method, route) == ("POST", "/api/v1/auth/login"):
        return "login"
    if (method, route) == ("GET", "/api/v1/challs"):
        return "challs"
    if (method, route) == ("GET", "/api/v1/users/me"):
        return "me"
    if (method, route) == ("GET", "/uploads"):
        return "file"
    parts = route.split("/")
    if method == "POST" and len(parts) == 6 and parts[:4] == ["", "api", "v1", "challs"] and parts[5] == "submit":
        return "submit"
    return ""
