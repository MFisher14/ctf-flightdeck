"""A fake OpenAI-compatible chat completions server, for tests.

It answers real HTTP on 127.0.0.1, so the model client (and the agent driver above it) is
tested end to end with nothing mocked: httpx, headers, JSON, status codes and retries all
run for real. Replies are scripted. Each request takes the next scripted reply; when the
script is empty, the responder (if any) answers; with neither, the server answers 500 with
a JSON error saying it ran out. Every request is recorded, so a test can check what the
client sent.

The server listens on the loopback interface only, in a background thread. The responder
runs on the server's request threads, possibly several at once: keep it quick and
thread-safe, unless a test means it to be slow (to make the client time out).

With `models`, GET /v1/models lists those ids as an OpenAI-compatible server does, or gives
that FakeReply (without, it answers 404, as a server that lists none). With `key`, every
request without `Authorization: Bearer <key>` gets 401, and GET /v1/key answers 200 to one
with it (OpenRouter's key check); `public_models` lets GET /v1/models through without the
key, as OpenRouter does.
"""

from __future__ import annotations

import itertools
import json
import socket
import socketserver
import sys
import threading
import time
from collections import deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

CHAT_PATH = "/v1/chat/completions"
MODELS_PATH = "/v1/models"
KEY_PATH = "/v1/key"  # OpenRouter's: what the key in the request is
STOP_WAIT = 5.0  # seconds leaving the context waits for request threads (a slow responder) in all

_completion_ids = itertools.count(1)


@dataclass
class FakeReply:
    """One answer. A dict body goes out as JSON, a str body as is (to test bad JSON)."""

    status: int = 200
    body: dict | str | None = None
    headers: dict[str, str] = field(default_factory=dict)


class FakeModelServer:
    """POST /v1/chat/completions on 127.0.0.1 (a free port), in a background thread.

    Each request takes the next scripted reply, or asks the responder. The port is taken
    when the server is made, so `base_url` is known before it starts. Entering the
    context starts serving; leaving it hangs up on clients still connected, stops the
    server and joins its threads.
    """

    def __init__(
        self,
        replies: Iterable[dict | FakeReply] = (),
        *,
        responder: Callable[[dict], dict | FakeReply] | None = None,
        models: Iterable[str] | FakeReply | None = None,
        key: str | None = None,
        public_models: bool = False,
    ) -> None:
        self.requests: list[dict] = []  # each {"path": str, "headers": {lower-case name: value}, "json": dict | None}
        self._replies: deque[dict | FakeReply] = deque(replies)
        self._responder = responder
        # what GET /v1/models lists (or answers); None: 404
        self.models = models if models is None or isinstance(models, FakeReply) else list(models)
        self.key = key  # the key every request must carry; None: none needed
        self.public_models = public_models  # GET /v1/models needs no key
        self._lock = threading.Lock()
        self._httpd = _Server(self)
        self.base_url = f"http://127.0.0.1:{self._httpd.server_address[1]}/v1"
        self._thread: threading.Thread | None = None

    def add(self, *replies: dict | FakeReply) -> None:
        """Script more replies, after the ones still waiting."""
        with self._lock:
            self._replies.extend(replies)

    def __enter__(self) -> FakeModelServer:
        self._thread = threading.Thread(
            target=self._httpd.serve_forever, kwargs={"poll_interval": 0.05}, name="fake-model-server", daemon=True
        )
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        if self._thread is not None:
            self._httpd.shutdown()
            self._thread.join()
        self._httpd.close(wait=STOP_WAIT)

    def chats(self) -> list[dict]:
        """The requests made to the chat endpoint (the model calls), in order."""
        with self._lock:
            return [r for r in self.requests if urlsplit(r["path"]).path == CHAT_PATH]

    def _answer(self, method: str, path: str, headers: dict[str, str], body: object) -> FakeReply:
        record = {"path": path, "headers": headers, "json": body}
        with self._lock:
            self.requests.append(record)
            route = urlsplit(path).path
            listing = method == "GET" and route == MODELS_PATH
            if self.key is not None and headers.get("authorization") != f"Bearer {self.key}" and not (listing and self.public_models):
                return FakeReply(401, {"error": {"message": "fake model server: no valid key in the request", "code": 401}})
            if listing and isinstance(self.models, FakeReply):
                return self.models
            if listing and self.models is not None:
                listed = [{"id": model, "object": "model", "created": 0, "owned_by": "fake"} for model in self.models]
                return FakeReply(200, {"object": "list", "data": listed})
            if method == "GET" and route == KEY_PATH and self.key is not None:
                return FakeReply(200, {"data": {"label": "fake key", "usage": 0, "limit": None}})
            if method != "POST" or route != CHAT_PATH:
                return FakeReply(404, _error(f"fake model server: nothing at {method} {path}; chat is POST {CHAT_PATH}"))
            if self._replies:
                return _as_reply(self._replies.popleft())
            responder = self._responder
        if responder is None:
            return FakeReply(500, _error("fake model server: out of scripted replies, and no responder"))
        try:
            return _as_reply(responder(record))
        except Exception as exc:  # a bug in the test's responder: tell the client instead of hanging
            return FakeReply(500, _error(f"fake model server: the responder raised {type(exc).__name__}: {exc}"))


def error_reply(status: int, message: str, *, headers: dict[str, str] | None = None) -> FakeReply:
    """An OpenAI-style error answer: {"error": {"message": ..., "code": status}}."""
    return FakeReply(status, {"error": {"message": message, "code": status}}, dict(headers or {}))


def text_reply(
    content: str,
    *,
    prompt_tokens: int = 100,
    completion_tokens: int = 20,
    cached_tokens: int = 0,
    cost: float | None = None,
    model: str = "fake/model",
) -> dict:
    """A complete chat.completion body whose message is plain text."""
    return _completion(
        {"role": "assistant", "content": content},
        "stop",
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        cached_tokens=cached_tokens,
        cost=cost,
        model=model,
    )


def tool_call_reply(
    name: str,
    arguments: dict | str,
    *,
    call_id: str = "call_1",
    content: str = "",
    prompt_tokens: int = 100,
    completion_tokens: int = 20,
    cached_tokens: int = 0,
    cost: float | None = None,
    model: str = "fake/model",
) -> dict:
    """A chat.completion body with one tool call. A str `arguments` is sent as is (bad JSON too)."""
    return _completion(
        _tool_message([(call_id, name, arguments)], content),
        "tool_calls",
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        cached_tokens=cached_tokens,
        cost=cost,
        model=model,
    )


def tool_calls_reply(
    calls: list[tuple[str, dict | str]],
    *,
    content: str = "",
    prompt_tokens: int = 100,
    completion_tokens: int = 20,
    cached_tokens: int = 0,
    cost: float | None = None,
    model: str = "fake/model",
) -> dict:
    """A chat.completion body with several tool calls in one message, ids call_1, call_2, ..."""
    numbered = [(f"call_{n}", name, arguments) for n, (name, arguments) in enumerate(calls, 1)]
    return _completion(
        _tool_message(numbered, content),
        "tool_calls",
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        cached_tokens=cached_tokens,
        cost=cost,
        model=model,
    )


def _tool_message(calls: list[tuple[str, str, dict | str]], content: str) -> dict:
    return {
        "role": "assistant",
        "content": content or None,  # real APIs send null, not "", beside tool calls
        "tool_calls": [
            {
                "id": call_id,
                "type": "function",
                "function": {
                    "name": name,
                    "arguments": arguments if isinstance(arguments, str) else json.dumps(arguments),
                },
            }
            for call_id, name, arguments in calls
        ],
    }


def _completion(
    message: dict,
    finish_reason: str,
    *,
    prompt_tokens: int,
    completion_tokens: int,
    cached_tokens: int,
    cost: float | None,
    model: str,
) -> dict:
    usage: dict = {
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "total_tokens": prompt_tokens + completion_tokens,
        "prompt_tokens_details": {"cached_tokens": cached_tokens},
    }
    if cost is not None:
        usage["cost"] = cost
    return {
        "id": f"chatcmpl-fake-{next(_completion_ids)}",
        "object": "chat.completion",
        "created": 0,
        "model": model,
        "choices": [{"index": 0, "message": message, "finish_reason": finish_reason}],
        "usage": usage,
    }


def _error(message: str) -> dict:
    return {"error": {"message": message, "type": "fake_model_server"}}


def _as_reply(reply: dict | FakeReply) -> FakeReply:
    return reply if isinstance(reply, FakeReply) else FakeReply(200, reply)


class _Server(ThreadingHTTPServer):
    """The HTTP server. It tracks its connections and request threads, so stopping can
    hang up on clients and wait for the threads, and `requests` is final once it has."""

    def __init__(self, fake: FakeModelServer) -> None:
        self.fake = fake
        self._open: set[socket.socket] = set()
        self._workers: list[threading.Thread] = []
        self._track = threading.Lock()
        super().__init__(("127.0.0.1", 0), _Handler)

    def server_bind(self) -> None:
        # HTTPServer.server_bind looks up the host's full name, which can stall on some networks.
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]

    def process_request(self, request, client_address) -> None:
        # Our own threads, not ThreadingMixIn's: it never joins daemon threads, and these must
        # be daemons so that a responder stuck for good cannot keep the test run alive.
        worker = threading.Thread(
            target=self.process_request_thread, args=(request, client_address), name="fake-model-request", daemon=True
        )
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
        """Hang up on every client still connected, wait up to `wait` seconds in all for
        the request threads to finish, then close the listening socket.

        httpx keeps connections alive between requests; without hanging up, each idle
        connection would hold its thread until it timed out. Call only once serving stopped.
        """
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
            return  # a client that hung up or timed out: expected in the timeout tests
        super().handle_error(request, client_address)


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"  # keep-alive, as real APIs do
    timeout = 30  # seconds an idle connection may stay open (a backstop: leaving hangs up first)
    server: _Server

    def do_POST(self) -> None:
        self._send(self.server.fake._answer("POST", self.path, self._headers(), self._json()))

    def do_GET(self) -> None:
        self._send(self.server.fake._answer("GET", self.path, self._headers(), None))

    def _headers(self) -> dict[str, str]:
        return {name.lower(): value for name, value in self.headers.items()}

    def _json(self) -> object:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length > 0 else b""
        try:
            return json.loads(raw) if raw else None
        except ValueError:
            return None

    def _send(self, reply: FakeReply) -> None:
        if isinstance(reply.body, dict):
            data = json.dumps(reply.body).encode()
        elif isinstance(reply.body, str):
            data = reply.body.encode()
        else:
            data = b""
        headers = {"Content-Type": "application/json"} if data else {}
        headers.update(reply.headers)
        try:
            self.send_response(reply.status)
            for name, value in headers.items():
                self.send_header(name, value)
            if not any(name.lower() == "content-length" for name in headers):
                self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except OSError:  # the client hung up (it timed out, or the server is closing)
            self.close_connection = True

    def log_message(self, format: str, *args: object) -> None:
        pass  # quiet: tests read server.requests instead
