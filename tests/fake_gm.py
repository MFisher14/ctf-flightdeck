"""A fake Game Master, for tests: the one-URL platform flightdeck's Game Master adapter speaks to.

It answers real HTTP on 127.0.0.1 in a background thread (the server of tests/fake_ctfd.py),
so the adapter is tested end to end with nothing mocked. The challenges are invented. Its
wire is the contract in src/ctf_flightdeck/platform/gamemaster.py:

- every request must carry `Authorization: Bearer <token>`: without it, or with another
  token, the answer is 401 {"error": "unauthorized"};
- GET ?op=list&all=true: {"challenges": [{"id", "name", "day", "lane", "mode", "solved"}]};
- GET ?op=status&challenge=<id>: the attempt (its files as one "download" with "sha256" and
  "filename", or as "artifacts" when it has several); 409 {"error": "start_required"} with
  the questions' ids for one that is not started;
- GET ?op=artifact&challenge=<id>&delivery=<n>: file n, named in Content-Disposition;
- POST {"challenge": id}: starts the attempt (recorded in `starts`), answers the attempt;
- POST {"challenge": id, "answers": {answer id: value}}: judged by these rules, in order:
  a body that is not such an object is 400 invalid_request; one over 64 KiB is 413
  payload_too_large; a challenge that is solved is 200 already_solved (whatever the
  answers); one not started is 409 start_required; one expired is 409 attempt_expired;
  answers that are empty, name an answer id the attempt has not, or are not strings are 400
  invalid_answers; any wrong value is 200 incorrect; right values are banked, and the answer
  is 200 accepted with "remaining" while other answers are still wanted, else 200 CORRECT
  with the flag (the challenge is then solved). While `limited` is above 0, a submit is
  429 {"error": "rate_limited"} with Retry-After `retry_after` first, judging nothing.
  An id the Game Master does not list is 404 {"error": "unknown_challenge"}.

Tests script replies ahead of these for one kind of request (script("GET", "status", ...),
script("POST", "submit", ...)) and read back every request in `requests`. `hold_submits`
holds each answer to a submission (judged when it arrives) until the test sets it.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlsplit

from fake_ctfd import HANG_UP, STOP_WAIT, Reply, Request, _Server  # noqa: F401  (HANG_UP: for the tests)

TOKEN = "fake-gm-bearer-token-for-tests-51d0"  # synthetic
MAX_BODY = 64 * 1024


@dataclass
class FakeAttempt:
    """An invented challenge. `answers`: answer id -> the right value. `questions`: answer id ->
    (the question, its answer_format). `files`: (name, content) of each delivery, in order."""

    id: str
    name: str
    lane: str = "misc"
    mode: str = "single_solve"
    day: int = 1
    prompt: str = ""
    guidance: str = ""
    answers: dict[str, str] = field(default_factory=lambda: {"a1": "right"})
    questions: dict[str, tuple[str, dict]] = field(default_factory=dict)
    files: list[tuple[str, bytes]] = field(default_factory=list)
    targets: list[str] = field(default_factory=list)
    deadline: str | None = None
    flag: str = "flag{0123456789abcdef0123456789abcdef}"
    started: bool = False
    solved: bool = False
    expired: bool = False
    banked: set[str] = field(default_factory=set)
    name_in_status: bool = True  # False: the status names no file; only the download's Content-Disposition does
    sha256: dict[int, str] = field(default_factory=dict)  # delivery index -> the sha256 the status states instead of the real one


def sample() -> list[FakeAttempt]:
    """Five invented challenges: a started one with a file, an unstarted one, one with two
    answers and two files, a clocked one, and a solved one."""
    return [
        FakeAttempt("metadata-day-01", "Who Wrote It", lane="metadata", prompt="Inspect evidence.zip. Who is the author?",
                    guidance="Answer with the author's name only.", answers={"d01-author": "Alice Example"},
                    questions={"d01-author": ("Author?", {"kind": "text"})}, files=[("evidence.zip", b"PK\x03\x04evidence")],
                    started=True),
        FakeAttempt("script-day-05", "Obfuscated", lane="script", day=5, prompt="What is the key?",
                    answers={"s5-key": "0xdeadbeef"}),
        FakeAttempt("mobile-day-04", "Two Phones", lane="mobile", day=4, prompt="Two phones, two answers.",
                    answers={"m4-a": "pixel", "m4-b": "nokia 3310"},
                    questions={"m4-a": ("The first phone?", {"kind": "text"}), "m4-b": ("The second?", {"kind": "text"})},
                    files=[("blob.txt", b"first delivery\n"), ("blob.txt", b"second delivery\n")], started=True),
        FakeAttempt("metadata-day-01/time_trial", "Who Wrote It", lane="metadata", mode="time_trial",
                    answers={"d01-author": "Alice Example"}),
        FakeAttempt("binary-day-02", "Packed", lane="binary", day=2, answers={"b2": "upx"}, started=True, solved=True),
    ]


class FakeGM:
    """A fake Game Master on 127.0.0.1 (a free port). Entering the context starts serving;
    leaving it hangs up on clients still connected and stops the server."""

    def __init__(self, challenges: list[FakeAttempt] | tuple[FakeAttempt, ...] = (), *, token: str = TOKEN) -> None:
        self.challenges: dict[str, FakeAttempt] = {c.id: c for c in challenges}
        self.token = token
        self.limited = 0  # this many submits are answered 429 rate_limited first
        self.retry_after: str | None = None  # their Retry-After
        self.hold_submits: threading.Event | None = None  # set: answers to submissions wait for it (a slow Game Master)
        self.starts: list[str] = []  # the ids started through the fake, in order
        self.requests: list[Request] = []
        self._scripted: dict[tuple[str, str], deque[Reply]] = {}
        self._lock = threading.Lock()
        self._httpd = _Server(self, None)
        self.url = f"http://127.0.0.1:{self._httpd.server_address[1]}/"
        self._thread: threading.Thread | None = None

    def __enter__(self) -> FakeGM:
        self._thread = threading.Thread(
            target=self._httpd.serve_forever, kwargs={"poll_interval": 0.05}, name="fake-gm", daemon=True
        )
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        if self._thread is not None:
            self._httpd.shutdown()
            self._thread.join()
        self._httpd.close(wait=STOP_WAIT)

    # ------------------------------------------------------------------ for tests

    def add(self, *challenges: FakeAttempt) -> None:
        with self._lock:
            for challenge in challenges:
                self.challenges[challenge.id] = challenge

    def script(self, method: str, op: str, *replies: Reply) -> None:
        """The next requests of that kind get these replies first, in order. `op`: a GET's op
        (list, status, artifact), or a POST's kind: "start" or "submit"."""
        with self._lock:
            self._scripted.setdefault((method, op), deque()).extend(replies)

    def sent(self, method: str, op: str) -> list[Request]:
        """The requests of that kind, in order."""
        with self._lock:
            return [r for r in self.requests if r.method == method and _op(r.method, r.path, r.body) == op]

    def submissions(self) -> list[object]:
        """The JSON body of each submission, in order."""
        return [r.json for r in self.sent("POST", "submit")]

    # ------------------------------------------------------------------ answering

    def _answer(self, method: str, path: str, headers: dict[str, str], body: bytes) -> Reply:
        with self._lock:
            self.requests.append(Request(method, path, headers, body, time.monotonic()))
            op = _op(method, path, body)
            queued = self._scripted.get((method, op))
            if queued:
                return queued.popleft()
            try:
                return self._route(method, op, parse_qs(urlsplit(path).query), headers, body)
            except Exception as exc:  # a bug in the fake: say so instead of hanging the client
                return Reply(500, {"error": "fake_gm_bug", "message": f"{type(exc).__name__}: {exc}"})

    def _route(self, method: str, op: str, query: dict, headers: dict[str, str], body: bytes) -> Reply:
        scheme, _, value = headers.get("authorization", "").partition(" ")
        if scheme != "Bearer" or value != self.token:
            return Reply(401, {"error": "unauthorized"})
        if method == "POST":
            if op == "start":
                return self._start(body)
            reply = self._submit(body)  # judged now: a hold delays only the answer
            reply.hold = self.hold_submits
            return reply
        if op == "list":
            return Reply(200, {"message": "every released challenge", "challenges": [
                {"id": c.id, "name": c.name, "day": c.day, "lane": c.lane, "mode": c.mode, "solved": c.solved}
                for c in self.challenges.values()
            ]})
        challenge = self.challenges.get((query.get("challenge") or [""])[0])
        if challenge is None:
            return Reply(404, {"error": "unknown_challenge"})
        if op == "status":
            if not challenge.started:
                return Reply(409, {"error": "start_required", "questions": [{"id": aid} for aid in challenge.answers]})
            return Reply(200, self._status(challenge))
        if op == "artifact":
            if not challenge.started:
                return Reply(409, {"error": "start_required"})
            index = (query.get("delivery") or [""])[0]
            if not index.isdigit() or int(index) >= len(challenge.files):
                return Reply(404, {"error": "unknown_delivery"})
            name, content = challenge.files[int(index)]
            return Reply(200, content, {"Content-Disposition": f'attachment; filename="{name}"'})
        return Reply(400, {"error": "invalid_request"})

    def _status(self, c: FakeAttempt) -> dict:
        body: dict = {
            "attempt_id": f"att-{c.id}", "mode": c.mode, "name": c.name, "prompt": c.prompt, "guidance": c.guidance,
            "questions": [
                {"id": aid, **({"question": c.questions[aid][0], "answer_format": c.questions[aid][1]} if aid in c.questions else {})}
                for aid in c.answers
            ],
            "answer_ids": list(c.answers),
            "deadline": c.deadline,
        }
        if c.solved:
            body["result"] = "CORRECT"
        if c.targets:
            body["targets"] = [{"url": url} for url in c.targets]
        files = [
            {"download": f"/?op=download&capability=cap-{c.id}-{i}", "sha256": c.sha256.get(i, hashlib.sha256(content).hexdigest()),
             **({"filename": name} if c.name_in_status else {})}
            for i, (name, content) in enumerate(c.files)
        ]
        if len(files) == 1:
            body.update(files[0])
        elif files:
            body["artifacts"] = files
        return body

    def _start(self, body: bytes) -> Reply:
        doc = _json(body)
        challenge = self.challenges.get(doc.get("challenge")) if isinstance(doc, dict) and isinstance(doc.get("challenge"), str) else None
        if challenge is None:
            return Reply(404, {"error": "unknown_challenge"})
        challenge.started = True
        challenge.expired = False
        self.starts.append(challenge.id)
        return Reply(200, self._status(challenge))

    def _submit(self, body: bytes) -> Reply:
        if self.limited > 0:
            self.limited -= 1
            return Reply(429, {"error": "rate_limited"}, {"Retry-After": self.retry_after} if self.retry_after else {})
        if len(body) > MAX_BODY:
            return Reply(413, {"error": "payload_too_large"})
        doc = _json(body)
        if not isinstance(doc, dict) or not isinstance(doc.get("challenge"), str) or "answers" not in doc:
            return Reply(400, {"error": "invalid_request"})
        challenge = self.challenges.get(doc["challenge"])
        if challenge is None:
            return Reply(404, {"error": "unknown_challenge"})
        if challenge.solved:
            return Reply(200, {"result": "already_solved", "message": "This challenge is already solved.", "name": challenge.name})
        if not challenge.started:
            return Reply(409, {"error": "start_required", "questions": [{"id": aid} for aid in challenge.answers]})
        if challenge.expired:
            return Reply(409, {"error": "attempt_expired"})
        answers = doc["answers"]
        if (not isinstance(answers, dict) or not answers
                or any(aid not in challenge.answers or not isinstance(value, str) for aid, value in answers.items())):
            return Reply(400, {"error": "invalid_answers"})
        if any(challenge.answers[aid] != value for aid, value in answers.items()):
            return Reply(200, {"result": "incorrect", "name": challenge.name})
        challenge.banked |= set(answers)
        remaining = len(set(challenge.answers) - challenge.banked)
        if remaining:
            return Reply(200, {"result": "accepted", "remaining": remaining, "name": challenge.name})
        challenge.solved = True
        return Reply(200, {"result": "CORRECT", "name": challenge.name, "flag": challenge.flag})


def _json(body: bytes) -> object:
    try:
        return json.loads(body)
    except ValueError:
        return None


def _op(method: str, path: str, body: bytes) -> str:
    if method == "POST":
        doc = _json(body)
        return "submit" if isinstance(doc, dict) and "answers" in doc else "start"
    return (parse_qs(urlsplit(path).query).get("op") or [""])[0]
