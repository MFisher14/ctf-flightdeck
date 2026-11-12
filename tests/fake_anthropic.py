"""A fake Anthropic Messages API server, for tests.

Like fake_model.py (whose HTTP server it reuses): real HTTP on 127.0.0.1, so the official
SDK runs end to end with nothing mocked: its headers, its JSON, its errors. Each request is
recorded and takes the next scripted reply; when the script is empty, the responder (if
any) answers; with neither, the server answers 500 in the API's error shape.

It also checks each request against the rules the real API enforces and this client must
keep (`contract()`): it answers 400 invalid_request_error, as the API would, when a request
breaks one: no messages, a first message that is not the user's, roles that do not
alternate, an empty turn or text block, a field the API does not know (a private key like
"_anthropic_content" included), a tool_use left without its tool_result in the next turn or
a tool_result for no tool_use, tool results after other content, temperature or top_p or
top_k (removed on these models), a forced tool_choice, an OpenAI-style tool, fallbacks
without their beta header, or `speed: "fast"` on a model without fast mode or, on a
research-preview model, without the fast-mode beta header. A test that means to send such a
request turns it off with check=False.

With `models`, it also answers the Models API: GET /v1/models lists the models that are not
retired, and GET /v1/models/{id} gives one, by its id or an alias in `aliases`, or 404
not_found_error. A model is an id (active), or a dict with its id and lifecycle. With `key`,
a request without that key (in x-api-key, or as the Bearer token the SDK sends) gets 401
authentication_error.

Replies carry usage as the API reports it (message()): the tokens written to the cache,
split by TTL under cache_creation, and, for a call the server-side refusal fallback ran on
more than one model, one usage.iterations entry per attempt (attempt()).

Nothing here is a real key, a real model answer or a real event: replies are scripted.
"""

from __future__ import annotations

import itertools
import threading
from collections import deque
from collections.abc import Callable, Iterable
from urllib.parse import urlsplit

from fake_model import STOP_WAIT, FakeReply, _Server

MESSAGES_PATH = "/v1/messages"
MODELS_PATH = "/v1/models"
FALLBACK_BETA = "server-side-fallback-2026-07-01"
FAST_BETA = "fast-mode-2026-02-01"
FAST_MODELS = {"claude-opus-5-5", "claude-fable-5-2", "claude-mythos-5-2", "claude-opus-5", "claude-opus-4-8"}
FAST_PREVIEW = {"claude-opus-5", "claude-opus-4-8"}  # these need the beta header for any speed
_ids = itertools.count(1)

_MESSAGE_KEYS = {"role", "content"}
_REQUEST_KEYS = {
    "model", "max_tokens", "messages", "system", "tools", "tool_choice", "cache_control", "fallbacks", "metadata",
    "output_config", "thinking", "stop_sequences", "stream", "service_tier", "speed", "context_management",
}


class FakeAnthropicServer:
    """POST /v1/messages on 127.0.0.1 (a free port), in a background thread.

    `base_url` is what the SDK takes (it adds /v1/messages itself). Entering the context
    starts serving; leaving it hangs up on clients still connected and stops the server."""

    def __init__(
        self,
        replies: Iterable[dict | FakeReply] = (),
        *,
        responder: Callable[[dict], dict | FakeReply] | None = None,
        check: bool = True,
        models: Iterable[str | dict] | None = None,
        aliases: dict[str, str] | None = None,
        key: str | None = None,
    ) -> None:
        self.requests: list[dict] = []  # each {"path": str, "headers": {lower-case name: value}, "json": dict | None}
        self._replies: deque[dict | FakeReply] = deque(replies)
        self._responder = responder
        self._check = check
        self.models = None if models is None else [_model(m) for m in models]  # None: no Models API (404)
        self.aliases = dict(aliases or {})  # alias -> model id, as GET /v1/models/{alias} resolves it
        self.key = key  # the x-api-key every request must carry; None: any
        self._lock = threading.Lock()
        self._httpd = _Server(self)
        self.base_url = f"http://127.0.0.1:{self._httpd.server_address[1]}"
        self._thread: threading.Thread | None = None

    def add(self, *replies: dict | FakeReply) -> None:
        with self._lock:
            self._replies.extend(replies)

    def __enter__(self) -> FakeAnthropicServer:
        self._thread = threading.Thread(
            target=self._httpd.serve_forever, kwargs={"poll_interval": 0.05}, name="fake-anthropic-server", daemon=True
        )
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        if self._thread is not None:
            self._httpd.shutdown()
            self._thread.join()
        self._httpd.close(wait=STOP_WAIT)

    def _answer(self, method: str, path: str, headers: dict[str, str], body: object) -> FakeReply:
        record = {"path": path, "headers": headers, "json": body}
        with self._lock:
            self.requests.append(record)
            if self.key is not None and self.key not in (headers.get("x-api-key"), headers.get("authorization", "").removeprefix("Bearer ")):
                return error(401, "authentication_error", "invalid x-api-key")
            route = urlsplit(path).path
            if method == "GET" and self.models is not None and route.startswith(MODELS_PATH):
                return self._models(route)
            if method != "POST" or route != MESSAGES_PATH:
                return error(404, "not_found_error", f"fake Anthropic server: nothing at {method} {path}")
            problem = contract(record) if self._check else None
            if problem is not None:
                return error(400, "invalid_request_error", problem)
            if self._replies:
                return _as_reply(self._replies.popleft())
            responder = self._responder
        if responder is None:
            return error(500, "api_error", "fake Anthropic server: out of scripted replies, and no responder")
        try:
            return _as_reply(responder(record))
        except Exception as exc:  # a bug in the test's responder: tell the client instead of hanging
            return error(500, "api_error", f"fake Anthropic server: the responder raised {type(exc).__name__}: {exc}")

    def _models(self, route: str) -> FakeReply:
        """The Models API: the list (retired models only when asked for), or one model."""
        assert self.models is not None
        if route == MODELS_PATH:
            shown = [m for m in self.models if m["lifecycle"] != "retired"]
            return FakeReply(200, {"data": shown, "has_more": False, "first_id": shown[0]["id"] if shown else None,
                                   "last_id": shown[-1]["id"] if shown else None})
        wanted = route[len(MODELS_PATH) + 1:]
        wanted = self.aliases.get(wanted, wanted)
        for model in self.models:
            if model["id"] == wanted:
                return FakeReply(200, model)
        return error(404, "not_found_error", f"model: {wanted}")


def _model(spec: str | dict) -> dict:
    """A model object as the Models API sends it."""
    fields = {"id": spec} if isinstance(spec, str) else dict(spec)
    return {"type": "model", "display_name": fields["id"], "created_at": "2026-01-01T00:00:00Z", "lifecycle": "active",
            **fields}


# ---------------------------------------------------------------------- the rules a request must keep


def contract(record: dict) -> str | None:
    """What the real API would refuse in this request (as its 400 says it), or None."""
    body = record["json"]
    if not isinstance(body, dict):
        return "the request body is not a JSON object"
    for key in ("model", "max_tokens", "messages"):
        if key not in body:
            return f"{key}: Field required"
    unknown = sorted(set(body) - _REQUEST_KEYS)
    if unknown:
        return f"{unknown[0]}: Extra inputs are not permitted"
    for key in ("temperature", "top_p", "top_k"):
        if key in body:
            return f"{key}: not supported on this API version"
    choice = body.get("tool_choice")
    if isinstance(choice, dict) and choice.get("type") in ("any", "tool"):
        return 'tool_choice: type "tool" and "any" are not supported for this model.'
    betas = {b.strip() for b in record["headers"].get("anthropic-beta", "").split(",") if b.strip()}
    if "fallbacks" in body and FALLBACK_BETA not in betas:
        return "fallbacks: Extra inputs are not permitted (the server-side fallback beta header is missing)"
    if "speed" in body:
        if body["speed"] not in ("standard", "fast"):
            return "speed: Input should be 'standard' or 'fast'"
        if body["speed"] == "fast" and body["model"] not in FAST_MODELS:
            return f"speed: fast mode is not supported for {body['model']}"
        if body["model"] in FAST_PREVIEW and FAST_BETA not in betas:
            return f"speed: {body['model']} needs the {FAST_BETA} beta header for speed"
    for index, tool in enumerate(body.get("tools") or []):
        if not isinstance(tool, dict) or "name" not in tool or "input_schema" not in tool or set(tool) - {"name", "description", "input_schema", "cache_control"}:
            return f"tools.{index}: a custom tool takes name, description and input_schema"
    system = body.get("system")
    if system is not None and not (isinstance(system, str) or all(_is_text(b) for b in system)):
        return "system: must be a string or a list of text blocks"
    messages = body["messages"]
    if not isinstance(messages, list) or not messages:
        return "messages: at least one message is required"
    open_calls: set[str] = set()
    for i, message in enumerate(messages):
        if not isinstance(message, dict):
            return f"messages.{i}: not an object"
        extra = sorted(set(message) - _MESSAGE_KEYS)
        if extra:
            return f"messages.{i}.{extra[0]}: Extra inputs are not permitted"
        role, content = message.get("role"), message.get("content")
        if role not in ("user", "assistant"):
            return f"messages.{i}.role: must be user or assistant"
        if i == 0 and role != "user":
            return "messages.0: the first message must use the user role"
        if i > 0 and role == messages[i - 1].get("role"):
            return f"messages.{i}: roles must alternate between user and assistant"
        blocks = [{"type": "text", "text": content}] if isinstance(content, str) else content
        if not isinstance(blocks, list) or not blocks:
            return f"messages.{i}: all messages must have non-empty content"
        for j, block in enumerate(blocks):
            if not isinstance(block, dict):
                return f"messages.{i}.content.{j}: not an object"
            private = [key for key in block if key.startswith("_")]
            if private:
                return f"messages.{i}.content.{j}.{private[0]}: Extra inputs are not permitted"
            if block.get("type") == "text" and not str(block.get("text", "")).strip():
                return f"messages.{i}.content.{j}: text content blocks must contain non-whitespace text"
        if role == "user":
            results = [b.get("tool_use_id") for b in blocks if b.get("type") == "tool_result"]
            kinds = [b.get("type") for b in blocks]
            if results and kinds[: len(results)] != ["tool_result"] * len(results):
                return f"messages.{i}: tool_result blocks must come first in the user message"
            if open_calls and set(results) != open_calls:
                return f"messages.{i}: tool_use ids were found without tool_result blocks immediately after: {sorted(open_calls - set(results))}"
            if not open_calls and results:
                return f"messages.{i}: unexpected tool_use_id found in tool_result blocks: {results[0]}"
            open_calls = set()
        else:
            open_calls = {b.get("id") for b in blocks if b.get("type") == "tool_use"}
    if open_calls:
        return "messages: the last assistant turn's tool_use blocks have no tool_result after them"
    if messages[-1].get("role") != "user":
        return "messages: the conversation must end with a user turn (these models take no prefill)"
    return None


def _is_text(block: object) -> bool:
    return isinstance(block, dict) and block.get("type") == "text" and isinstance(block.get("text"), str) and set(block) <= {"type", "text", "cache_control"}


# ---------------------------------------------------------------------- replies


def message(
    content: list[dict],
    *,
    stop_reason: str = "end_turn",
    model: str = "claude-haiku-5-5",
    input_tokens: int = 100,
    output_tokens: int = 20,
    cache_read: int = 0,
    cache_write: int = 0,
    cache_write_1h: int = 0,
    stop_details: dict | None = None,
    speed: str | None = None,
    iterations: list[dict] | None = None,
) -> dict:
    """A complete Messages API response body; `speed` goes in usage.speed when given.

    The usage is the API's: cache_creation_input_tokens is every token written to the cache,
    cache_creation splits it by TTL (`cache_write` to the 5-minute cache, `cache_write_1h` to
    the 1-hour one). `iterations` is usage.iterations, one entry per attempt (attempt()), as a
    server-side refusal fallback reports them; the top-level counts are then the last
    attempt's, since the API's "top-level `usage` covers only the attempt that produced the
    returned message"."""
    if iterations:
        last = iterations[-1]
        input_tokens, output_tokens, cache_read = last["input_tokens"], last["output_tokens"], last["cache_read_input_tokens"]
        cache_write = last["cache_creation"]["ephemeral_5m_input_tokens"]
        cache_write_1h = last["cache_creation"]["ephemeral_1h_input_tokens"]
    usage = _counts(input_tokens, output_tokens, cache_read, cache_write, cache_write_1h)
    if iterations is not None:
        usage["iterations"] = iterations
    if speed is not None:
        usage["speed"] = speed
    return {
        "id": f"msg_fake_{next(_ids)}",
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": content,
        "stop_reason": stop_reason,
        "stop_sequence": None,
        "stop_details": stop_details,
        "usage": usage,
    }


def _counts(input_tokens: int, output_tokens: int, cache_read: int, cache_write: int, cache_write_1h: int) -> dict:
    return {
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "cache_read_input_tokens": cache_read,
        "cache_creation_input_tokens": cache_write + cache_write_1h,
        "cache_creation": {"ephemeral_5m_input_tokens": cache_write, "ephemeral_1h_input_tokens": cache_write_1h},
    }


def attempt(
    model: str | None,
    *,
    kind: str = "message",
    input_tokens: int = 0,
    output_tokens: int = 0,
    cache_read: int = 0,
    cache_write: int = 0,
    cache_write_1h: int = 0,
) -> dict:
    """One entry of usage.iterations: an attempt of the call on `model` (None: an entry that
    names none). `kind` "message" is an attempt on the model asked for, or one the classifiers
    declined; "fallback_message" the attempt the fallback answered with."""
    entry: dict = {"type": kind, **_counts(input_tokens, output_tokens, cache_read, cache_write, cache_write_1h)}
    if model is not None:
        entry["model"] = model
    return entry


def thinking(signature: str = "fake-signature-1", text: str = "") -> dict:
    """A thinking block as these models return it (its text is "" under the default display)."""
    return {"type": "thinking", "thinking": text, "signature": signature}


def text_message(text: str, **options) -> dict:
    return message([{"type": "text", "text": text}], **options)


def tool_message(
    name: str,
    arguments: dict,
    *,
    call_id: str = "toolu_fake_1",
    text: str = "",
    signature: str = "fake-signature-1",
    **options,
) -> dict:
    """A thinking block, optional text, and one tool_use block: stop_reason tool_use."""
    content = [thinking(signature)]
    if text:
        content.append({"type": "text", "text": text})
    content.append({"type": "tool_use", "id": call_id, "name": name, "input": arguments})
    return message(content, stop_reason="tool_use", **options)


def refusal(category: str | None = "cyber", explanation: str | None = None, **options) -> dict:
    """A request the classifiers declined: HTTP 200, stop_reason refusal, no content."""
    details = {"type": "refusal", "category": category, "explanation": explanation}
    return message([], stop_reason="refusal", stop_details=details, **options)


def error(status: int, kind: str, text: str, *, headers: dict[str, str] | None = None) -> FakeReply:
    """An API error answer: {"type": "error", "error": {"type": kind, "message": text}}."""
    body = {"type": "error", "error": {"type": kind, "message": text}, "request_id": "req_fake"}
    return FakeReply(status, body, dict(headers or {}))


def _as_reply(reply: dict | FakeReply) -> FakeReply:
    return reply if isinstance(reply, FakeReply) else FakeReply(200, reply)
