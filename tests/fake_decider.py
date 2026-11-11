"""A fake Strands Decider server, for tests: POST /v1/systemone and GET /health on 127.0.0.1.

It answers real HTTP, so the decider engine (light.DeciderLight) runs end to end with nothing
in flightdeck mocked: httpx, JSON, status codes and time limits all run for real. The shapes
are the decider repository's own (src/strands_decider/schema.py and server.py):

- request: {"state": ..., "questions": {name: {"type": "choice", "instructions": ...,
  "criteria": {option: description}}}}
- answer: {"model": ..., "answers": {name: {"type": "choice", "choice": option,
  "probabilities": {option: p}, "confidence": c}}, "usage": {"input_tokens": n,
  "output_tokens": n}, "latency_ms": t}, each number rounded to 4 decimals
- error: FastAPI's {"detail": "..."} (or a list of {"msg": ...} for a request it refused)
- GET /health: {"status": "ok", "model", "checkpoint", "base_model", "max_length",
  "temperature", "device", "prefix_cache", "vision"}

Like the real server (FastAPI 0.162, strict about content types by default), it reads a POST's
body as JSON only when its Content-Type says so (application/json, or application/<x>+json);
any other body is refused with HTTP 422 before a scripted reply is used, in FastAPI's words: a
body without that header gets {"detail": [{"type": "model_attributes_type", "loc": ["body"],
...}]}, as the decider's server sent it to a request made without one.

Each POST takes the next scripted reply (a Reply, a body dict, or a function of the request
that returns either), else the responder's, else 500. Every request is recorded with its raw
body and its headers (names in lower case), so a test can check the very bytes sent.
`most_at_once` is the largest number of requests the server was answering at the same time.
"""

from __future__ import annotations

import email.message
import json
import socket
import socketserver
import sys
import threading
import time
from collections import deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

SYSTEMONE = "/v1/systemone"
HEALTH = "/health"
MODEL = "strands-decider-2B-qwen3.5-v1-2610"  # what the server reports for StrandsAgents/<this>
STOP_WAIT = 5.0


@dataclass
class Reply:
    """One answer: a dict body goes out as JSON, a str body as is. `delay` seconds first."""

    status: int = 200
    body: dict | str | None = None
    delay: float = 0.0


class FakeDeciderServer:
    """The fake server, in a background thread; entering the context starts it, leaving it
    hangs up on clients still connected and stops it."""

    def __init__(self, replies: Iterable = (), *, responder: Callable[[dict], Reply | dict] | None = None,
                 health: dict | Reply | None = None) -> None:
        self.requests: list[dict] = []  # {"method", "path", "headers", "raw": bytes, "json": object | None, "at": monotonic}
        self._replies: deque = deque(replies)
        self._responder = responder
        self.health = health_body() if health is None else health
        self.most_at_once = 0
        self._at_once = 0
        self._lock = threading.Lock()
        self._httpd = _Server(self)
        self.base_url = f"http://127.0.0.1:{self._httpd.server_address[1]}"
        self._thread: threading.Thread | None = None

    def add(self, *replies) -> None:
        with self._lock:
            self._replies.extend(replies)

    def __enter__(self) -> FakeDeciderServer:
        self._thread = threading.Thread(target=self._httpd.serve_forever, kwargs={"poll_interval": 0.05},
                                        name="fake-decider", daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        if self._thread is not None:
            self._httpd.shutdown()
            self._thread.join()
        self._httpd.close(wait=STOP_WAIT)

    def asked(self) -> list[dict]:
        """The POSTs to /v1/systemone, in order."""
        with self._lock:
            return [r for r in self.requests if r["method"] == "POST" and urlsplit(r["path"]).path == SYSTEMONE]

    def _answer(self, method: str, path: str, raw: bytes, headers: dict[str, str]) -> Reply:
        parsed, refused = _body(raw, headers.get("content-type"))
        record = {"method": method, "path": path, "headers": headers, "raw": raw, "json": parsed, "at": time.monotonic()}
        route = urlsplit(path).path
        with self._lock:
            self.requests.append(record)
            if method == "GET" and route == HEALTH:
                if self.health is None or isinstance(self.health, Reply):
                    return self.health or Reply(404, {"detail": "Not Found"})
                return Reply(200, self.health)
            if method != "POST" or route != SYSTEMONE:
                return Reply(404, {"detail": "Not Found"})
            if refused is not None:  # the server refuses it before any model sees it: no scripted reply is used
                return refused
            item = self._replies.popleft() if self._replies else self._responder
        if item is None:
            return Reply(500, {"detail": "fake decider: out of scripted replies, and no responder"})
        try:
            made = item(parsed) if callable(item) else item
        except Exception as exc:  # a bug in the test's script: say so instead of hanging
            return Reply(500, {"detail": f"fake decider: the script raised {type(exc).__name__}: {exc}"})
        return made if isinstance(made, Reply) else Reply(200, made)

    def _begin(self) -> None:
        with self._lock:
            self._at_once += 1
            self.most_at_once = max(self.most_at_once, self._at_once)

    def _end(self) -> None:
        with self._lock:
            self._at_once -= 1


def _body(raw: bytes, content_type: str | None) -> tuple[object, Reply | None]:
    """(the POST body as JSON, None), or (None, the 422 the real server sends): it reads a body
    as JSON only when its Content-Type is application/json or application/<x>+json, as FastAPI
    does with strict content types (fastapi/routing.py); anything else stays bytes, which the
    request's schema refuses."""
    if not raw:
        return None, Reply(422, {"detail": [{"type": "missing", "loc": ["body"], "msg": "Field required", "input": None}]})
    message = email.message.Message()
    message["content-type"] = content_type or ""
    subtype = message.get_content_subtype()
    if not content_type or message.get_content_maintype() != "application" or not (
            subtype == "json" or subtype.endswith("+json")):
        return None, Reply(422, {"detail": [{
            "type": "model_attributes_type", "loc": ["body"],
            "msg": "Input should be a valid dictionary or object to extract fields from",
            "input": raw.decode("utf-8", "replace")}]})
    try:
        return json.loads(raw), None
    except ValueError as exc:
        return None, Reply(422, {"detail": [{"type": "json_invalid", "loc": ["body", getattr(exc, "pos", 0)],
                                             "msg": "JSON decode error", "input": {},
                                             "ctx": {"error": getattr(exc, "msg", str(exc))}}]})


# ---------------------------------------------------------------------- answers in the server's shapes


def answer(name: str, choice: str, probabilities: dict, confidence, *, model: str = MODEL,
           input_tokens: int = 120, kind: str = "choice") -> dict:
    """A /v1/systemone answer body, as the server sends it."""
    return {
        "model": model,
        "answers": {name: {"type": kind, "choice": choice, "probabilities": probabilities, "confidence": confidence}},
        "usage": {"input_tokens": input_tokens, "output_tokens": 1},
        "latency_ms": 12.34,
    }


def picks(option: str, confidence: float, *, model: str = MODEL, input_tokens: int = 120,
          delay: float = 0.0) -> Callable[[dict], Reply]:
    """A scripted reply that answers whatever single question it is asked with `option`, the
    probabilities spread so the confidence is `confidence`: the server's own formula,
    (N p_max - 1) / (N - 1), each number rounded to 4 decimals as it rounds them."""

    def reply(request: dict) -> Reply:
        ((name, question),) = request["questions"].items()
        options = list(question["criteria"])
        n = len(options)
        top = (confidence * (n - 1) + 1) / n
        rest = (1 - top) / (n - 1)
        probabilities = {o: round(top if o == option else rest, 4) for o in options}
        return Reply(200, answer(name, option, probabilities, round(confidence, 4), model=model,
                                 input_tokens=input_tokens), delay)

    return reply


def health_body(model: str = MODEL, *, max_length: int = 4096) -> dict:
    return {"status": "ok", "model": model, "checkpoint": f"StrandsAgents/{model}", "base_model": "Qwen/Qwen3.5-2B-Base",
            "max_length": max_length, "temperature": {"noul": 0.91, "choice": 0.77, "score": 0.96}, "device": "mps",
            "prefix_cache": True, "vision": False}


def detail(status: int, text) -> Reply:
    """An error as FastAPI sends one."""
    return Reply(status, {"detail": text})


def the_question(request: dict) -> tuple[str, dict]:
    """(name, question) of a request's one question."""
    ((name, question),) = request["questions"].items()
    return name, question


# ---------------------------------------------------------------------- the HTTP server


class _Server(ThreadingHTTPServer):
    """Tracks its connections and request threads, so stopping can hang up and wait."""

    def __init__(self, fake: FakeDeciderServer) -> None:
        self.fake = fake
        self._open: set[socket.socket] = set()
        self._workers: list[threading.Thread] = []
        self._track = threading.Lock()
        super().__init__(("127.0.0.1", 0), _Handler)

    def server_bind(self) -> None:
        socketserver.TCPServer.server_bind(self)  # no slow host-name lookup
        self.server_name, self.server_port = self.server_address[:2]

    def process_request(self, request, client_address) -> None:
        worker = threading.Thread(target=self.process_request_thread, args=(request, client_address),
                                  name="fake-decider-request", daemon=True)
        with self._track:
            self._open.add(request)
            self._workers = [w for w in self._workers if w.is_alive()]
            self._workers.append(worker)
        worker.start()

    def shutdown_request(self, request) -> None:
        with self._track:
            self._open.discard(request)
        super().shutdown_request(request)

    def close(self, wait: float) -> None:
        with self._track:
            still_open, workers = list(self._open), list(self._workers)
        for sock in still_open:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        deadline = time.monotonic() + wait
        for worker in workers:
            worker.join(max(0.0, deadline - time.monotonic()))
        self.server_close()

    def handle_error(self, request, client_address) -> None:
        if isinstance(sys.exc_info()[1], (ConnectionError, TimeoutError)):
            return  # a client that hung up or gave up: expected in the time-limit tests
        super().handle_error(request, client_address)


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = 30
    server: _Server

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length > 0 else b""
        self._serve("POST", raw)

    def do_GET(self) -> None:
        self._serve("GET", b"")

    def _serve(self, method: str, raw: bytes) -> None:
        fake = self.server.fake
        fake._begin()
        try:
            headers = {name.lower(): value for name, value in self.headers.items()}
            reply = fake._answer(method, self.path, raw, headers)
            if reply.delay:
                time.sleep(reply.delay)
            self._send(reply)
        finally:
            fake._end()

    def _send(self, reply: Reply) -> None:
        if isinstance(reply.body, dict):
            data = json.dumps(reply.body).encode()
        elif isinstance(reply.body, str):
            data = reply.body.encode()
        else:
            data = b""
        try:
            self.send_response(reply.status)
            if data:
                self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except OSError:
            self.close_connection = True

    def log_message(self, format: str, *args: object) -> None:
        pass
