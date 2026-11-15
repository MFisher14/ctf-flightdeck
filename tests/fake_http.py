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
  badTokenVerification for another token, and for the token as the login link writes it
  (percent-encoded: rCTF decodes nothing there);
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

With `v2` it is rCTF v2 (github.com/otter-sec/rctf), as its API reference and response types
have it (read on 2026-11-14; not run):

- GET /api/v2/challs: the v1 list, and per challenge instancerLifetime (milliseconds, or null
  with no instancer), instancerExtendable, instancerStoppable, instancerActions;
- GET, PUT, PATCH, DELETE /api/v2/integrations/challs/ID/instance (status, start, extend,
  stop): 200 goodInstanceStatus with data {status, timeLeftMilliseconds, endpoints}; status
  one of stopped, starting, running, stopping, errored; endpoints null unless running, each
  {kind, host, port, title, text} with kind tcp, tcp-ssl, http or https. A challenge with no
  instancer is 404 badEndpoint. A start of a running one, and an extend of a stopped one,
  are 400 badInstancerState with data.error. With `captcha`, a start and an extend with no
  captchaCode are 403 badCaptcha. A task's `instancer` sets its endpoints and lifetime, and
  how many looks at its status answer "starting" after a start (`slow`).

FakeNoCTF answers in the shape of noCTF's player API, as its public source has it
(github.com/noctf-project/noctf); its own docstring lists the routes.
"""

from __future__ import annotations

import json
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import parse_qs, quote, unquote, urlsplit

from fake_ctfd import STOP_WAIT, TLS, Reply, Request, _Server
from serving import Serving

# Synthetic, and no real token. It has the characters rCTF's tokens have (standard base64: + / =),
# which the team's login link writes percent-encoded (login_link below).
TEAM_TOKEN = "fake+rctf/team+token/for+tests/51b8=="
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
    instancer: Instancer | None = None  # rCTF v2: the challenge has an instance the platform starts for the team


@dataclass
class Instancer:
    """An invented challenge's instancer on the fake rCTF v2. `endpoints`: (kind, host, port)."""

    endpoints: list[tuple[str, str, int]] = field(default_factory=lambda: [("tcp", "pwn-1.chal.example.test", 31337)])
    lifetime: int = 600_000  # milliseconds an instance lives
    slow: int = 0  # looks at the status that answer "starting" after a start
    status: str = "stopped"
    left: int = 0  # looks still "starting"


def sample() -> list[RTask]:
    """Three invented challenges: one with a file, one without, one the team has solved. No
    file holds its challenge's flag."""
    return [
        RTask("warm-7f3a", "Warm Up", points=50, description="Read the note.", files={"note.txt": b"a synthetic handout\n"}, flag="t{warm}"),
        RTask("web-19c2", "Web Thing", category="web", points=250, flag="t{web}", solves=4),
        RTask("done-a4d0", "Done Before", points=150, flag="t{done}", solved=True),
    ]


def login_link(url: str, token: str = TEAM_TOKEN) -> str:
    """The team's login link as rCTF's own page builds it (its client's profile page:
    `${location.origin}/login?token=${encodeURIComponent(teamToken)}`): the token is
    percent-encoded in it, so + / = stand as %2B %2F %3D."""
    return f"{url}/login?token={quote(token, safe='')}"


def answer(status: int, kind: str, message: str, data: object = None) -> Reply:
    body: dict = {"kind": kind, "message": message}
    if data is not None:
        body["data"] = data
    return Reply(status, body)


class FakeRCTF(FakeSite):
    """The fake rCTF. Tests script replies ahead of its own for one kind of request
    (script("challs", ...); the kinds are "login", "challs", "file", "submit" and "me")."""

    def __init__(self, tasks: list[RTask] | tuple[RTask, ...] = (), *, team_token: str = TEAM_TOKEN, auth_token: str = AUTH_TOKEN,
                 v2: bool = False, captcha: bool = False) -> None:
        super().__init__(self._route)
        self.tasks: dict[str, RTask] = {task.id: task for task in tasks}
        self.team_token = team_token
        self.auth_token = auth_token
        self.v2 = v2
        self.captcha = captcha
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
        if kind in ("challs2", "instance") and not self.v2:  # the older rCTF has no /api/v2
            kind = ""
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
        if kind == "challs2":
            return answer(200, "goodChallengesV2", "The challenges.", [self._listed_v2(task) for task in self.tasks.values()])
        if kind == "instance":
            return self._instance(request)
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

    def _listed_v2(self, task: RTask) -> dict:
        return {**self._listed(task), "tags": None,
                "instancerLifetime": task.instancer.lifetime if task.instancer is not None else None,
                "instancerExtendable": task.instancer is not None, "instancerStoppable": task.instancer is not None,
                "instancerActions": [], "hasFlag": True}

    def _instance(self, request: Request) -> Reply:
        task = self.tasks.get(unquote(request.route.split("/")[5]))
        if task is None or task.instancer is None:
            return answer(404, "badEndpoint", "The request endpoint could not be found.")
        box, method = task.instancer, request.method
        if method in ("PUT", "PATCH"):
            body = request.json
            if not isinstance(body, dict):
                return answer(400, "badJson", "The request body is not valid JSON.")
            if self.captcha and not body.get("captchaCode"):
                return answer(403, "badCaptcha", "The captcha verification failed.")
        if method == "PUT":
            if box.status in ("running", "starting"):
                return answer(400, "badInstancerState", "Instancer precondition not met.", {"error": "Instance already running."})
            box.status, box.left = ("starting", box.slow) if box.slow else ("running", 0)
        elif method == "PATCH":
            if box.status != "running":
                return answer(400, "badInstancerState", "Instancer precondition not met.", {"error": "Instance is not running."})
        elif method == "DELETE":
            box.status = "stopped"
        elif box.status == "starting":  # GET: a look at a starting instance
            box.left -= 1
            if box.left < 0:
                box.status = "running"
        running = box.status == "running"
        endpoints = [{"kind": kind, "host": host, "port": port, "title": kind, "text": f"nc {host} {port}"}
                     for kind, host, port in box.endpoints] if running else None
        return answer(200, "goodInstanceStatus", "The instance status was retrieved.",
                      {"status": box.status, "timeLeftMilliseconds": box.lifetime if running else None, "endpoints": endpoints})

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
    if (method, route) == ("GET", "/api/v2/challs"):
        return "challs2"
    if len(parts) == 7 and parts[:5] == ["", "api", "v2", "integrations", "challs"] and parts[6] == "instance":
        return "instance"
    if method == "POST" and len(parts) == 6 and parts[:4] == ["", "api", "v1", "challs"] and parts[5] == "submit":
        return "submit"
    return ""


# ---------------------------------------------------------------------- noCTF

# Synthetic, and no real token: what the fake noCTF takes as the session token its web page keeps.
NOCTF_SESSION = "fake-noctf-session-for-tests-9d21"


@dataclass
class NTask:
    """An invented noCTF challenge. `files`: name -> content (kept by the fake under a signed
    files/local/ path), or name -> a whole URL (a str) where the file is on another host.
    `categories`: the tag noCTF keeps them in, comma-separated, or None for no tag. `value`:
    None while the scoreboard has no value for it. `manual`: a challenge the organisers judge
    by hand, whose flag is queued."""

    id: int
    title: str
    categories: str | None = "misc"
    value: int | None = 100
    description: str = "A synthetic challenge."
    files: dict[str, bytes | str] = field(default_factory=dict)
    flag: str = "t{right}"
    solved: bool = False
    solve_count: int = 0
    manual: bool = False
    queued: bool = False


def noctf_sample() -> list[NTask]:
    """Three invented challenges: one with a file, one in two categories with no value yet, one
    the team has solved. No file holds its challenge's flag."""
    return [
        NTask(11, "Warm Up", value=50, description="Read the note.", files={"note.txt": b"a synthetic handout\n"}, flag="t{warm}"),
        NTask(12, "Two Hats", categories="crypto,rev", value=None, flag="t{hats}", solve_count=3),
        NTask(13, "Done Before", value=150, flag="t{done}", solved=True, solve_count=9),
    ]


def noctf_error(status: int, error: str, message: str, headers: dict[str, str] | None = None) -> Reply:
    """An error as noCTF's error handler sends one: {"error", "message"}, and no data."""
    return Reply(status, {"error": error, "message": message}, headers or {})


class FakeNoCTF(FakeSite):
    """The fake noCTF, in the shape its public source has (github.com/noctf-project/noctf: the
    contracts in core/api/src/contract, the handlers in apps/server/src/routes). Every route is
    at the root of the API's address, and an error is {"error", "message"} with its HTTP status.

    - every route but a file wants `Authorization: Bearer <session>`: else 401 AuthenticationError;
    - GET /challenges: {"data": {"challenges": [{id, slug, title, tags, hidden, can_submit, value,
      solve_count}]}}: no description and no files; the categories are tags.categories;
    - GET /challenges/ID: {"data": {id, slug, title, description, hidden, visible_at, updated_at,
      tags, metadata: {solve, files: [{filename, size, hash, url, is_attachment}], hints}}}; a
      file's url is `files/local/REF?iat=...&sig=...` (no leading slash: the web page puts the
      API's address in front) unless the task gives a whole URL; 404 NotFoundError;
    - GET /files/local/REF?iat=&sig=: the file, with no sign-in asked; 403 without its signature;
    - POST /challenges/ID/solves {"data": flag}: 200 {"data": {"status", "hidden"}} with status
      correct, incorrect or (a manual challenge) queued; 409 ConflictError while the team has a
      solve or a queued flag for it; 429 TooManyRequestsError with Retry-After in seconds (while
      `limited` is above 0); 403 ForbiddenError after the end; 404 for no such challenge;
    - GET /team/scoreboard: {"data": {team_id, score, rank, ..., solves: [{id, user_id,
      challenge_id, hidden, created_at, value}], awards}}.

    Tests script replies ahead of its own for one kind of request (script("solve", ...); the kinds
    are "list", "detail", "file", "solve" and "team")."""

    def __init__(self, tasks: list[NTask] | tuple[NTask, ...] = (), *, session: str = NOCTF_SESSION) -> None:
        super().__init__(self._route)
        self.tasks: dict[int, NTask] = {task.id: task for task in tasks}
        self.session = session
        self.ended = False
        self.limited = 0  # this many submits are answered 429 first
        self.retry_after = 12  # their Retry-After header, in seconds
        self._scripted: dict[str, deque[Reply]] = {}

    def script(self, kind: str, *replies: Reply) -> None:
        with self._lock:
            self._scripted.setdefault(kind, deque()).extend(replies)

    def kinds(self) -> list[str]:
        with self._lock:
            return [noctf_kind(r) for r in self.requests]

    def of(self, kind: str) -> list[Request]:
        with self._lock:
            return [r for r in self.requests if noctf_kind(r) == kind]

    def submits(self) -> list[tuple[str, object]]:
        """(the challenge's id as the path carried it, the body's data) of each submit, in order."""
        return [(r.route.split("/")[2], (r.json or {}).get("data")) for r in self.of("solve")]

    def _route(self, request: Request) -> Reply:
        kind = noctf_kind(request)
        with self._lock:
            queued = self._scripted.get(kind)
            if queued:
                return queued.popleft()
        if kind == "file":
            query = parse_qs(urlsplit(request.path).query)
            if not query.get("sig") or not query.get("iat"):
                return noctf_error(403, "ForbiddenError", "Invalid signature")
            ref = request.route.split("/")[3]
            for task in self.tasks.values():
                for name, content in task.files.items():
                    if isinstance(content, bytes) and ref == f"r{task.id}-{name}":
                        return Reply(200, content)
            return noctf_error(404, "NotFoundError", "File not found")
        if kind == "":
            return noctf_error(404, "NotFoundError", "Route not found")
        if request.headers.get("authorization", "") != f"Bearer {self.session}":
            return noctf_error(401, "AuthenticationError", "no authorization header supplied")
        if kind == "list":
            return Reply(200, {"data": {"challenges": [self._summary(task) for task in self.tasks.values()]}})
        if kind == "team":
            solves = [{"id": 500 + t.id, "user_id": 7, "challenge_id": t.id, "hidden": False, "created_at": "2026-11-14T09:00:00.000Z",
                       "value": t.value or 0} for t in self.tasks.values() if t.solved]
            return Reply(200, {"data": {"team_id": 3, "tag_ids": [], "score": 0, "rank": 1, "last_solve": "1970-01-01T00:00:00.000Z",
                                        "updated_at": "1970-01-01T00:00:00.000Z", "hidden": False, "solves": solves, "awards": [],
                                        "graph": [[], []]}})
        task = self._task(request)
        if task is None:
            return noctf_error(404, "NotFoundError", "Challenge not found")
        if kind == "detail":
            return Reply(200, {"data": self._detail(task)})
        return self._solve(request, task)

    def _task(self, request: Request) -> NTask | None:
        part = request.route.split("/")[2]
        return self.tasks.get(int(part)) if part.isdigit() else None

    def _summary(self, task: NTask) -> dict:
        return {"id": task.id, "slug": task.title.lower().replace(" ", "-"), "title": task.title, "tags": self._tags(task),
                "hidden": False, "can_submit": True, "value": task.value, "solve_count": task.solve_count}

    def _detail(self, task: NTask) -> dict:
        files = [{"filename": name, "size": len(content) if isinstance(content, bytes) else 0, "hash": "sha256:" + "0" * 64,
                  "url": content if isinstance(content, str) else f"files/local/{quote(f'r{task.id}-{name}', safe='')}?iat=1&sig=c2ln",
                  "is_attachment": True} for name, content in task.files.items()]
        return {"id": task.id, "slug": task.title.lower().replace(" ", "-"), "title": task.title, "description": task.description,
                "hidden": False, "visible_at": None, "updated_at": "2026-11-14T08:00:00.000Z", "tags": self._tags(task),
                "metadata": {"solve": {"input_type": "text"}, "files": files, "hints": []}}

    @staticmethod
    def _tags(task: NTask) -> dict:
        return {"difficulty": "easy", **({"categories": task.categories} if task.categories is not None else {})}

    def _solve(self, request: Request, task: NTask) -> Reply:
        body = request.json
        if not isinstance(body, dict) or set(body) != {"data"} or not isinstance(body["data"], str):
            return noctf_error(400, "ValidationError", "data must be string")
        if self.limited > 0:
            self.limited -= 1
            return noctf_error(429, "TooManyRequestsError", "You're trying too hard", {"Retry-After": str(self.retry_after)})
        if self.ended:
            return noctf_error(403, "ForbiddenError", "The CTF has ended. Thanks for playing!")
        if task.solved or task.queued:
            return noctf_error(409, "ConflictError", "A current (queued or solved) submission exists")
        if task.manual:
            task.queued = True
            status = "queued"
        elif body["data"] == task.flag:
            task.solved = True
            status = "correct"
        else:
            status = "incorrect"
        return Reply(200, {"data": {"status": status, "hidden": False}})


def noctf_kind(request: Request) -> str:
    """What a request to the fake noCTF asks for: "list", "detail", "file", "solve", "team"; "" for anything else."""
    route, method = request.route, request.method
    parts = route.split("/")
    if method == "GET" and route == "/challenges":
        return "list"
    if method == "GET" and route == "/team/scoreboard":
        return "team"
    if method == "GET" and len(parts) == 4 and parts[:3] == ["", "files", "local"]:
        return "file"
    if len(parts) == 3 and parts[1] == "challenges" and method == "GET":
        return "detail"
    if len(parts) == 4 and parts[1] == "challenges" and parts[3] == "solves" and method == "POST":
        return "solve"
    return ""
