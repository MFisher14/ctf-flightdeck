"""A fake CTFd on 127.0.0.1 for the wave rehearsal (B-039) and its tests. Never a real platform.

    board = [FakeChallenge(1, "warmup", "Web", files={"a.txt": b"..."}, flag="CSCTF{x}"), ...]
    with FakeCTFd(board, token="rehearsal-...", open_after=2) as fake:
        fake.base_url                     # http://127.0.0.1:<port>
        fake.log                          # [Request] every request it saw, in order

It speaks the CTFd API v1 subset the carried client (ctf/client.py) uses:

    GET  /api/v1/challenges               403 for the first `open_after` polls (the wave is not open),
                                          then the visible list
    GET  /api/v1/challenges/<id>          detail, files as /files/<id>/<name>?token=...
    GET  /files/<id>/<name>               the file bytes
    GET  /api/v1/users/me, /teams/me      a fixed rehearsal account (answered while closed, as CTFd does)
    GET  /api/v1/tokens                   the account's token rows (id, type, expiration) when built
                                          with tokens=[...] (B-190's expiry check); else 404
    GET  /api/v1/teams/me/solves          the team's solves (seeded + accepted in this run)
    GET  /api/v1/challenges/<id>/solves   (B-099) every team's solve of one challenge, earliest first:
                                          the challenge's `board_solves` plus our correct attempts in
                                          this run ({account_id, name, date (ISO, Z)}); the list rows
                                          carry `solves` (the count), as CTFd's do
    GET  /api/v1/scoreboard               (B-099) the standings from those solves (pos, name, score);
                                          both answer 403 with scores_hidden=True
    POST /api/v1/challenges/attempt       judged exactly against the challenge's flag; an attempt
                                          closer than `min_attempt_gap` seconds to the previous one is
                                          answered "ratelimited" (CTFd's own throttle), as live
    POST /containers/api/view_info        the docker_per_team plugin's status route, for challenges
                                          with `instance=True`

Anything else answers 404 and is recorded. Hint endpoints (/api/v1/unlocks, /api/v1/hints/<id>) are
recorded as `hint` so a rehearsal fails loudly when anything tries to spend points. Every request
must carry `Authorization: Token <token>`; one without it answers 403 and is recorded with
kind `unauthenticated` (whatever route it asked for), so `unknown` means only a route the fake lacks.
The server binds loopback only and stops on exit from the `with` block.
"""
from __future__ import annotations

import datetime
import json
import re
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlsplit

LOOPBACK = "127.0.0.1"


def _iso(at: float) -> str:
    """CTFd's solve date: ISO 8601 in UTC with a Z."""
    return datetime.datetime.fromtimestamp(at, datetime.timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass
class FakeChallenge:
    id: int
    name: str
    category: str
    files: dict[str, bytes] = field(default_factory=dict)
    flag: str | None = None               # None: no flag is accepted (the attempt is incorrect)
    description: str = ""
    value: int = 100
    solved: bool = False                  # already solved by the team when the wave opens
    instance: bool = False                # answers the docker_per_team view_info route
    connection_info: str | None = None    # the detail's connection_info (B-155: a replay endpoint)
    # B-099: the board's solves of this challenge, (team name, epoch seconds), any team, any order.
    # A correct attempt in the run adds (the fake's team_name, wall clock).
    board_solves: list[tuple[str, float]] = field(default_factory=list)


@dataclass(frozen=True)
class Request:
    t: float
    method: str
    path: str
    status: int
    authed: bool
    kind: str                             # list | detail | file | me | tokens | solves | challenge_solves |
                                          # scoreboard | attempt | instance | hint | unauthenticated |
                                          # closed | unknown
    body: dict | None = None
    verdict: str | None = None            # attempts only


_DETAIL = re.compile(r"^/api/v1/challenges/(\d+)$")
_SOLVES = re.compile(r"^/api/v1/challenges/(\d+)/solves$")
_FILE = re.compile(r"^/files/(\d+)/([^/]+)$")
_HINT = re.compile(r"^/api/v1/(unlocks|hints/\d+)$")


class FakeCTFd:
    def __init__(self, board: list[FakeChallenge], *, token: str, open_after: int = 0,
                 min_attempt_gap: float = 0.0, clock=time.monotonic, tokens: list[dict] | None = None,
                 team_name: str = "rehearsal", wall=time.time, scores_hidden: bool = False):
        if not token:
            raise ValueError("FakeCTFd needs the token its client will send")
        ids = [c.id for c in board]
        if len(ids) != len(set(ids)):
            raise ValueError(f"duplicate challenge ids on the fake board: {ids}")
        self.board = {c.id: c for c in board}
        self.token = token
        self.open_after = open_after
        self.min_attempt_gap = min_attempt_gap
        self.clock = clock
        self.tokens = tokens              # GET /api/v1/tokens rows (B-190); None: the route is absent
        self.team_name = team_name        # B-099: our team on the fake board
        self.wall = wall                  # B-099: the clock of a board solve's date (epoch seconds)
        self.scores_hidden = scores_hidden   # B-099: /scoreboard and per-challenge solves answer 403
        self.log: list[Request] = []
        self._lock = threading.Lock()
        self._list_polls = 0
        self._last_attempt: float | None = None
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    # ------------------------------------------------------------------------------ lifecycle
    @property
    def base_url(self) -> str:
        if self._server is None:
            raise RuntimeError("FakeCTFd is not running (use it as a context manager)")
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def __enter__(self) -> "FakeCTFd":
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):          # quiet: the log is fake.log
                pass

            def do_GET(self):
                fake._handle(self, "GET")

            def do_POST(self):
                fake._handle(self, "POST")

        self._server = ThreadingHTTPServer((LOOPBACK, 0), Handler)
        self._server.daemon_threads = True
        self._thread = threading.Thread(target=self._server.serve_forever, name="fakectfd", daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

    # ------------------------------------------------------------------------------ queries
    def requests(self, kind: str) -> list[Request]:
        with self._lock:
            return [r for r in self.log if r.kind == kind]

    def solved_ids(self) -> set[int]:
        return {c.id for c in self.board.values() if c.solved}

    # ------------------------------------------------------------------------------ handler
    def _handle(self, h: BaseHTTPRequestHandler, method: str) -> None:
        path = unquote(urlsplit(h.path).path)
        body = None
        n = int(h.headers.get("Content-Length") or 0)
        if n:
            try:
                body = json.loads(h.rfile.read(n).decode("utf-8"))
            except ValueError:
                body = {"_unparsed": True}
        authed = h.headers.get("Authorization") == f"Token {self.token}"
        with self._lock:
            status, kind, payload, verdict = self._route(method, path, body, authed)
            self.log.append(Request(self.clock(), method, path, status, authed, kind,
                                    body if isinstance(body, dict) else None, verdict))
        if isinstance(payload, bytes):
            data, ctype = payload, "application/octet-stream"
        else:
            data, ctype = json.dumps(payload).encode("utf-8"), "application/json"
        h.send_response(status)
        h.send_header("Content-Type", ctype)
        h.send_header("Content-Length", str(len(data)))
        h.end_headers()
        h.wfile.write(data)

    def _route(self, method: str, path: str, body, authed: bool):
        if _HINT.match(path):
            return 403, "hint", {"success": False, "errors": ["rehearsal: hints are never bought"]}, None
        if not authed:
            return 403, "unauthenticated", {"success": False, "errors": ["missing or wrong token"]}, None
        if method == "GET" and path == "/api/v1/challenges":
            self._list_polls += 1
            if self._list_polls <= self.open_after:
                return 403, "list", {"success": False, "message": "not open yet"}, None
            return 200, "list", {"success": True, "data": [self._row(c) for c in self.board.values()]}, None
        if method == "GET" and path in ("/api/v1/users/me", "/api/v1/teams/me"):
            return 200, "me", {"success": True, "data": {"id": 1, "name": "rehearsal", "team_id": 1}}, None
        if method == "GET" and path == "/api/v1/tokens" and self.tokens is not None:
            return 200, "tokens", {"success": True, "data": list(self.tokens)}, None
        if not self._open():
            return 403, "closed", {"success": False, "message": "not open yet"}, None
        m = _DETAIL.match(path)
        if method == "GET" and m:
            c = self.board.get(int(m.group(1)))
            if c is None:
                return 404, "detail", {"success": False, "message": "no such challenge"}, None
            return 200, "detail", {"success": True, "data": self._detail(c)}, None
        m = _FILE.match(path)
        if method == "GET" and m:
            c = self.board.get(int(m.group(1)))
            if c is None or m.group(2) not in c.files:
                return 404, "file", {"success": False}, None
            return 200, "file", c.files[m.group(2)], None
        if method == "GET" and path in ("/api/v1/teams/me/solves", "/api/v1/users/me/solves"):
            rows = [{"challenge_id": cid} for cid in sorted(self.solved_ids())]
            return 200, "solves", {"success": True, "data": rows}, None
        m = _SOLVES.match(path)
        if method == "GET" and m:
            if self.scores_hidden:
                return 403, "challenge_solves", {"success": False, "errors": ["Scores are currently hidden"]}, None
            c = self.board.get(int(m.group(1)))
            if c is None:
                return 404, "challenge_solves", {"success": False, "message": "no such challenge"}, None
            ids = self._account_ids()
            rows = [{"account_id": ids[team], "name": team, "date": _iso(at), "account_url": f"/teams/{ids[team]}"}
                    for team, at in sorted(c.board_solves, key=lambda s: s[1])]
            return 200, "challenge_solves", {"success": True, "data": rows}, None
        if method == "GET" and path == "/api/v1/scoreboard":
            if self.scores_hidden:
                return 403, "scoreboard", {"success": False, "errors": ["Scores are currently hidden"]}, None
            return 200, "scoreboard", {"success": True, "data": self.standings()}, None
        if method == "POST" and path == "/api/v1/challenges/attempt":
            return self._attempt(body)
        if method == "POST" and path == "/containers/api/view_info":
            cid = (body or {}).get("chal_id")
            c = self.board.get(cid) if isinstance(cid, int) else None
            if c is None or not c.instance:
                return 400, "instance", {"error": "no instance for this challenge"}, None
            return 200, "instance", {"success": True, "hostname": LOOPBACK, "port": 40000 + c.id,
                                     "remaining_time": 900}, None
        return 404, "unknown", {"success": False, "message": f"fake CTFd has no route {method} {path}"}, None

    def _open(self) -> bool:
        return self.open_after == 0 or self._list_polls > self.open_after

    def _account_ids(self) -> dict[str, int]:
        """A stable account id per team on the board (first solve first)."""
        every = sorted((at, team) for c in self.board.values() for team, at in c.board_solves)
        ids: dict[str, int] = {}
        for _, team in every:
            ids.setdefault(team, len(ids) + 1)
        return ids

    def standings(self) -> list[dict]:
        """The CTFd /scoreboard rows from the board solves: score = the values of the challenges a team
        solved, ties broken by who reached it first (the earlier last solve)."""
        ids = self._account_ids()
        score: dict[str, int] = {}
        last: dict[str, float] = {}
        for c in self.board.values():
            for team, at in c.board_solves:
                score[team] = score.get(team, 0) + c.value
                last[team] = max(last.get(team, at), at)
        order = sorted(score, key=lambda t: (-score[t], last[t]))
        return [{"pos": i, "account_id": ids[t], "account_type": "team", "name": t, "score": score[t]}
                for i, t in enumerate(order, 1)]

    def _row(self, c: FakeChallenge) -> dict:
        return {"id": c.id, "name": c.name, "category": c.category, "value": c.value,
                "solved_by_me": c.solved, "type": "standard", "tags": [], "solves": len(c.board_solves)}

    def _detail(self, c: FakeChallenge) -> dict:
        return {"id": c.id, "name": c.name, "category": c.category, "value": c.value,
                "description": c.description, "connection_info": c.connection_info, "hints": [], "tags": [],
                "solved_by_me": c.solved,
                "files": [f"/files/{c.id}/{name}?token=rehearsal" for name in sorted(c.files)]}

    def _attempt(self, body):
        cid = (body or {}).get("challenge_id")
        sub = (body or {}).get("submission")
        c = self.board.get(cid) if isinstance(cid, int) else None
        if c is None or not isinstance(sub, str):
            return 404, "attempt", {"success": False, "message": "bad attempt"}, "bad"
        now = self.clock()
        gap_ok = self._last_attempt is None or now - self._last_attempt >= self.min_attempt_gap
        self._last_attempt = now
        if not gap_ok:
            verdict = "ratelimited"
            msg = "You're submitting flags too fast. Slow down."
        elif c.solved:
            verdict, msg = "already_solved", "You already solved this"
        elif c.flag is not None and sub == c.flag:
            c.solved = True
            c.board_solves.append((self.team_name, float(self.wall())))
            verdict, msg = "correct", "Correct"
        else:
            verdict, msg = "incorrect", "Incorrect"
        return 200, "attempt", {"success": True, "data": {"status": verdict, "message": msg}}, verdict
