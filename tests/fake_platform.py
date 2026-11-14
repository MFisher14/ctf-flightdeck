"""A fake platform flightdeck does not know, and a synthetic plugin that talks to it, for tests.

The platform answers real HTTP on 127.0.0.1 in a background thread (the server of
tests/fake_ctfd.py), so a plugin's platform is tested end to end in a run: flightdeck starts
the adapter as a real process, and the adapter asks this fake. The challenges are invented,
the wire is made up for these tests, and nothing here is any real platform's.

- every request must carry `Authorization: Bearer <token>`: else 401 {"error": "unauthorized"};
- GET /api/challenges: {"challenges": [{"id", "name", "category", "points", "text", "files":
  [name, ...], "max_attempts"}]}, in the order they were added;
- GET /api/challenges/<id>/files/<name>: the file;
- GET /api/solved: {"ids": [id, ...]}, the challenges the account has solved;
- POST /api/challenges/<id>/attempt with {"flag": FLAG}: {"result": "solved"} for one that is
  solved already; while `limited` is above 0, {"result": "slow_down"} (with "retry_after" when
  `retry_after` is set), judging nothing; else {"result": "correct"} (it is then solved) or
  {"result": "wrong"}. Each has a "message". An id it does not list is 404.

Tests script replies ahead of these for one kind of request (script("GET", "solved", ...);
the kinds are "challenges", "file", "solved" and "attempt") and read back every request in
`requests`.

make_adapter() writes the plugin: a plugin.toml and an adapter.py of the standard library
only. The adapter maps the fake's words onto the plugin API's (correct, wrong -> incorrect,
solved -> already_solved, slow_down -> rate_limited, anything else -> unjudged), downloads a
pull's files for the refs flightdeck does not know yet, and on an HTTP error exits 1 with
"the platform answered HTTP <status>" on stderr. It uses no proxy, whatever the machine's
settings: its platform is on 127.0.0.1.
"""

from __future__ import annotations

import json
import re
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from fake_ctfd import STOP_WAIT, Reply, Request, _Server

TOKEN = "fake-platform-token-for-tests-9d2c"  # synthetic, and not shaped like any real token
FLAG_FORMAT = r"t\{\w+\}"  # the flags of the invented challenges below

ADAPTER = r'''
import json, os, sys, urllib.error, urllib.request

req = json.load(sys.stdin)
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # the platform is on 127.0.0.1: never a proxy


def api(path, body=None, raw=False):
    request = urllib.request.Request(
        req["url"] + path,
        data=None if body is None else json.dumps(body).encode(),
        headers={"Authorization": "Bearer " + os.environ["FLIGHTDECK_PLUGIN_TOKEN"], "Content-Type": "application/json"},
    )
    try:
        with opener.open(request, timeout=20) as reply:
            data = reply.read()
    except urllib.error.HTTPError as exc:
        sys.exit(f"the platform answered HTTP {exc.code}")
    except OSError as exc:
        sys.exit(f"the platform did not answer ({exc})")
    return data if raw else json.loads(data)


if req["op"] == "pull":
    challenges = []
    for task in api("/api/challenges")["challenges"]:
        ref, files = str(task["id"]), []
        if ref not in req["known"]:
            for name in task["files"]:
                target = os.path.join(req["files"], ref, name)
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with open(target, "wb") as out:
                    out.write(api(f"/api/challenges/{ref}/files/{name}", raw=True))
                files.append(f"{ref}/{name}")
        challenges.append({"ref": ref, "name": task["name"], "category": task["category"], "points": task["points"],
                           "description": task["text"], "files": files, "max_attempts": task["max_attempts"]})
    out = {"challenges": challenges}
elif req["op"] == "submit":
    answer = api(f"/api/challenges/{req['ref']}/attempt", {"flag": req["flag"]})
    words = {"correct": "correct", "wrong": "incorrect", "solved": "already_solved", "slow_down": "rate_limited"}
    out = {"verdict": words.get(answer.get("result"), "unjudged"), "detail": str(answer.get("message", ""))}
    for key in ("tries_left", "retry_after"):
        if key in answer:
            out[key] = answer[key]
elif req["op"] == "solved":
    out = {"solved": [str(number) for number in api("/api/solved")["ids"]]}
else:
    sys.exit("unknown op")
json.dump(out, sys.stdout)
'''

MANIFEST = 'name = "{name}"\napi = 1\ncommand = ["{{python}}", "adapter.py"]\nversion = "0.1.0"\ndescription = "A fake platform, for tests"\n'


def make_adapter(folder: Path, *, name: str = "acme") -> Path:
    """A plugin folder whose adapter talks to a FakePlatform at the event's url."""
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "plugin.toml").write_text(MANIFEST.format(name=name))
    (folder / "adapter.py").write_text(ADAPTER)
    return folder


@dataclass
class FakeTask:
    """An invented challenge. `files`: name -> content. `flag`: the right one."""

    id: int
    name: str
    category: str = "misc"
    points: int = 100
    text: str = "A synthetic challenge."
    files: dict[str, bytes] = field(default_factory=dict)
    flag: str = "t{right}"
    solved: bool = False
    max_attempts: int = 0


def sample() -> list[FakeTask]:
    """Three invented challenges: one with a file, one without, one the account has solved. No
    file holds its challenge's flag: the deck holds a flag a handout spells out for the player."""
    return [
        FakeTask(17, "Warm Up", points=50, text="Read the note.", files={"note.txt": b"a synthetic handout\n"}, flag="t{warm}"),
        FakeTask(23, "Web Thing", category="web", points=250, flag="t{web}"),
        FakeTask(31, "Done Before", points=150, flag="t{done}", solved=True),
    ]


class FakePlatform:
    """The fake platform on 127.0.0.1 (a free port). Entering the context starts serving;
    leaving it hangs up on clients still connected and stops the server."""

    def __init__(self, tasks: list[FakeTask] | tuple[FakeTask, ...] = (), *, token: str = TOKEN) -> None:
        self.tasks: dict[int, FakeTask] = {task.id: task for task in tasks}
        self.token = token
        self.limited = 0  # this many attempts are answered slow_down first
        self.retry_after: float | None = None  # their retry_after
        self.requests: list[Request] = []
        self._scripted: dict[tuple[str, str], deque[Reply]] = {}
        self._lock = threading.Lock()
        self._httpd = _Server(self, None)
        self.url = f"http://127.0.0.1:{self._httpd.server_address[1]}"
        self._thread: threading.Thread | None = None

    def __enter__(self) -> FakePlatform:
        self._thread = threading.Thread(
            target=self._httpd.serve_forever, kwargs={"poll_interval": 0.05}, name="fake-platform", daemon=True
        )
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        if self._thread is not None:
            self._httpd.shutdown()
            self._thread.join()
        self._httpd.close(wait=STOP_WAIT)

    # ------------------------------------------------------------------ for tests

    def add(self, *tasks: FakeTask) -> None:
        with self._lock:
            for task in tasks:
                self.tasks[task.id] = task

    def script(self, method: str, kind: str, *replies: Reply) -> None:
        """The next requests of that kind get these replies first, in order."""
        with self._lock:
            self._scripted.setdefault((method, kind), deque()).extend(replies)

    def sent(self, kind: str) -> list[Request]:
        """The requests of that kind, in order."""
        with self._lock:
            return [r for r in self.requests if _kind(r.method, r.path) == kind]

    def attempts(self) -> list[tuple[int, str]]:
        """(the challenge's id, the flag) of each attempt, in order."""
        return [(int(urlsplit(r.path).path.split("/")[3]), r.json["flag"]) for r in self.sent("attempt")]

    # ------------------------------------------------------------------ answering

    def _answer(self, method: str, path: str, headers: dict[str, str], body: bytes) -> Reply:
        with self._lock:
            self.requests.append(Request(method, path, headers, body, time.monotonic()))
            kind = _kind(method, path)
            queued = self._scripted.get((method, kind))
            if queued:
                return queued.popleft()
            try:
                return self._route(kind, urlsplit(path).path, headers, body)
            except Exception as exc:  # a bug in the fake: say so instead of hanging the client
                return Reply(500, {"error": "fake_platform_bug", "message": f"{type(exc).__name__}: {exc}"})

    def _route(self, kind: str, route: str, headers: dict[str, str], body: bytes) -> Reply:
        scheme, _, value = headers.get("authorization", "").partition(" ")
        if scheme != "Bearer" or value != self.token:
            return Reply(401, {"error": "unauthorized"})
        if kind == "challenges":
            return Reply(200, {"challenges": [
                {"id": t.id, "name": t.name, "category": t.category, "points": t.points, "text": t.text,
                 "files": list(t.files), "max_attempts": t.max_attempts}
                for t in self.tasks.values()
            ]})
        if kind == "solved":
            return Reply(200, {"ids": [t.id for t in self.tasks.values() if t.solved]})
        parts = route.split("/")
        task = self.tasks.get(int(parts[3])) if kind in ("file", "attempt") else None
        if task is None:
            return Reply(404, {"error": "not_found"})
        if kind == "file":
            content = task.files.get(parts[5])
            return Reply(404, {"error": "not_found"}) if content is None else Reply(200, content)
        return self._attempt(task, body)

    def _attempt(self, task: FakeTask, body: bytes) -> Reply:
        try:
            flag = json.loads(body)["flag"]
        except (ValueError, KeyError, TypeError):
            return Reply(400, {"error": "invalid_request"})
        if task.solved:
            return Reply(200, {"result": "solved", "message": "you already solved this"})
        if self.limited > 0:
            self.limited -= 1
            answer: dict = {"result": "slow_down", "message": "too many attempts"}
            if self.retry_after is not None:
                answer["retry_after"] = self.retry_after
            return Reply(200, answer)
        if flag == task.flag:
            task.solved = True
            return Reply(200, {"result": "correct", "message": "well done"})
        return Reply(200, {"result": "wrong", "message": "not the flag"})


_ROUTES = (
    ("GET", re.compile(r"/api/challenges"), "challenges"),
    ("GET", re.compile(r"/api/challenges/\d+/files/[^/]+"), "file"),
    ("GET", re.compile(r"/api/solved"), "solved"),
    ("POST", re.compile(r"/api/challenges/\d+/attempt"), "attempt"),
)


def _kind(method: str, path: str) -> str:
    """What a request asks for: "challenges", "file", "solved" or "attempt"; "" for anything else."""
    route = urlsplit(path).path
    for verb, shape, kind in _ROUTES:
        if method == verb and shape.fullmatch(route):
            return kind
    return ""
