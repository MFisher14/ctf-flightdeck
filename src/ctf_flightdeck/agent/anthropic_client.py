"""The Anthropic Messages API client: ModelClient's chat(), for Claude models.

A lane's driver keeps its conversation as OpenAI-style message dicts (agent/client.py). This
client translates both ways and calls the API through the official `anthropic` SDK:

- The leading system message becomes `system`: a text block with a cache breakpoint. Tools
  render before the system prompt and both are the same every turn, so that one breakpoint
  caches tools and system together; top-level automatic caching covers the growing tail.
- An assistant message this client made carries the response's raw content blocks under
  CONTENT_KEY ("_anthropic_content"), and they go back exactly as received: thinking blocks
  must come back unchanged, and so must the tool_use blocks the tool results answer. An
  assistant message without them (an OpenAI-style API made it) becomes a text block and
  tool_use blocks. An assistant message with no blocks at all is left out.
- Consecutive "tool" messages become one user message of tool_result blocks, and a user
  note after them joins that message as a text block: consecutive messages of one role are
  merged, so the request alternates user and assistant.
- Tools: an OpenAI function schema becomes name, description and input_schema.

The reply comes back in ModelClient's terms: the assistant message for the history (its
OpenAI-style content and tool_calls, so an OpenAI-style API can take the context over, and
the raw blocks under CONTENT_KEY), the text, the tool calls with their input as JSON text,
the stop reason, the usage (prompt tokens = input + cache read + cache write, cached tokens
= cache read, cache-write tokens = cache write, no cost: flightdeck prices it from the config)
and the model that answered. A call the server-side refusal fallback ran on more than one
model reports each attempt in usage.iterations: its usage is then told per model that ran
it (agent/client.py Usage), so each attempt is priced as that model (_usage).

What is sent, as Anthropic's documentation says for these models: no `thinking` (left out, they
think adaptively), no `temperature` (they reject it, and SDK 2 has no such argument), no
`tool_choice` (forcing a tool is a 400; auto is the default). A model in
SERVER_FALLBACK_MODELS (Claude Sonnet 5.5 and Opus 5.5 among them) carries the server-side
refusal fallback (beta server-side-fallback-2026-07-01, fallbacks "default"): a request its
classifiers decline runs again, inside the same call, on the model Anthropic recommends for
that category. A final stop_reason "refusal" means the whole chain declined: a ModelError,
declined and never retried, naming the category. Claude Haiku 5.5 has no server-side
fallback, so its requests carry none. A client made with server_fallback=False sends none at
all (the light role: a refusal stays a refusal, and the player sees it).

Fast mode (`fast`, from [api] fast; agent/fastmode.py has the facts). A model listed there is
called with `speed: "fast"`, plus the beta flag fast-mode-2026-02-01 for a research-preview
model. Fast mode has its own rate limit: a 429 on a fast request is not waited out but tried
again at once at standard speed, and that lane session stays at standard speed (switching
speed invalidates the prompt cache, so it does not switch back and forth); the reply carries
a notice saying so. A fast call is priced here, at the fast rate, unless the API says it ran
at standard speed (usage.speed): its Usage.cost is set, so the config's standard price is not
used for it. `effort` (the light role's "low") goes out as output_config.effort.

Retries are this client's own, as in ModelClient: the SDK's are off (max_retries=0), so the
driver's before_retry gate holds a paused lane between tries. A status is retried as the
SDK itself would (408, 409, 429 and every 5xx, 529 "overloaded" included, unless the server
says otherwise in x-should-retry), and so are connection failures and timeouts.

Secrets. The key and the base URL are passed to the SDK explicitly, so it reads no other
credential (ANTHROPIC_AUTH_TOKEN, a profile) and no ANTHROPIC_BASE_URL from the environment.
An SDK exception is described and dropped, never chained onto a ModelError: its request
holds the Authorization header. Server text has the key cut out. A redirect is an answer,
not a new place to send the key. The SDK's OpenTelemetry spans are off, so lane content
cannot leave through an exporter the environment might configure.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable, Iterable, Sequence
from dataclasses import dataclass, replace

import anthropic
import httpx2

from ..pricing import cost
from ..text import untrusted
from .client import (
    _KEY_CHARS,
    CONNECT_TIMEOUT,
    MAX_ERROR_TEXT,
    ModelError,
    Reply,
    ToolCall,
    Usage,
    _count,
    _finite,
    _phrase,
    retry_delay,
)
from .fastmode import FAST_BETA, FAST_MODES, fast_problem
from .refusal import FALLBACK_BETA, SERVER_FALLBACK_MODELS

DEFAULT_BASE_URL = "https://api.anthropic.com"  # the SDK's own default; it adds /v1/messages
DEFAULT_TIMEOUT = 600.0  # seconds per try: the SDK's default request timeout (10 minutes)
DEFAULT_MAX_TOKENS = 16_000  # when the caller gives none: Anthropic's documented default for a request that does not stream
CONTENT_KEY = "_anthropic_content"  # the raw content blocks of a reply, on its history message

EFFORTS = ("low", "medium", "high", "xhigh", "max")
EFFORT_MODELS = frozenset({
    "claude-fable-5", "claude-fable-5-1", "claude-fable-5-2", "claude-mythos-5", "claude-mythos-5-1",
    "claude-mythos-5-2", "claude-opus-5-5", "claude-opus-5", "claude-opus-4-8", "claude-opus-4-7", "claude-opus-4-6",
    "claude-opus-4-5", "claude-sonnet-5-5", "claude-sonnet-5", "claude-sonnet-4-6", "claude-haiku-5-5",
})
"""The models that take output_config.effort (Anthropic's documentation, its thinking table); it is an
error on Claude Haiku 4.5 and Sonnet 4.5, so it goes only to these."""

TRANSIENT = (httpx2.TimeoutException, httpx2.NetworkError, httpx2.RemoteProtocolError, httpx2.ProxyError)
"""Transport errors a retry can fix, as the SDK's APIConnectionError carries them."""


@dataclass(frozen=True)
class _Failure:
    """One failed try, in our words: what happened, the status if the API answered, whether
    a retry may help, and the server's Retry-After."""

    text: str
    status: int | None
    retryable: bool
    retry_after: str | None = None


@dataclass(frozen=True)
class _Malformed:
    """A 2xx reply the client cannot use: `what` in our words, `detail` in the server's."""

    what: str
    detail: str = ""


@dataclass(frozen=True)
class _Declined:
    """stop_reason "refusal": the model (and any server-side fallback) declined."""

    category: str
    explanation: str
    usage: Usage


class AnthropicClient:
    """Claude through the Anthropic Messages API, with ModelClient's chat() and aclose().

    Like ModelClient: shared by the lanes on one event loop, `timeout` bounds each try as a
    whole (connecting gets at most CONNECT_TIMEOUT of it), and a call makes at most
    `max_retries + 1` tries, waiting retry_delay() between them. `max_tokens` ([api]
    max_tokens) goes with every call that gives none; without it, DEFAULT_MAX_TOKENS.
    """

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        api_key: str | None = None,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        max_retries: int = 4,
        backoff: float = 1.0,
        fast: Iterable[str] = (),
        server_fallback: bool = True,
        effort: str | None = None,
        max_tokens: int | None = None,
    ) -> None:
        where = _base_url(base_url)
        if not isinstance(api_key, str) or not _KEY_CHARS.fullmatch(api_key):
            raise ValueError(
                "the Anthropic API needs an API key that an HTTP header can carry (printable ASCII, no "
                "spaces or line breaks); check the variable it came from"
            )
        if not timeout > 0:
            raise ValueError(f"timeout must be a positive number of seconds, got {timeout}")
        if max_retries < 0:
            raise ValueError(f"max_retries must not be negative, got {max_retries}")
        if not backoff >= 0:
            raise ValueError(f"backoff must not be negative, got {backoff}")
        fast = frozenset(fast)
        for model in sorted(fast):
            problem = fast_problem(model)
            if problem is not None:
                raise ValueError(f"fast mode cannot be used: {problem}")
        if effort is not None and effort not in EFFORTS:
            raise ValueError(f"effort must be one of {', '.join(EFFORTS)}, got {effort!r}")
        if max_tokens is not None and (not isinstance(max_tokens, int) or isinstance(max_tokens, bool) or max_tokens < 1):
            raise ValueError(f"max_tokens must be a positive whole number, got {max_tokens!r}")
        self.max_tokens = max_tokens
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff = backoff
        self.fast = fast  # models called in fast mode
        self.server_fallback = server_fallback
        self.effort = effort
        self._standard: set[str] = set()  # lane sessions whose fast mode hit its rate limit: standard speed from then on
        self._key = api_key
        self._where = where
        limit = anthropic.Timeout(timeout, connect=min(timeout, CONNECT_TIMEOUT))
        self._sdk = anthropic.AsyncAnthropic(
            api_key=api_key,  # explicit: the SDK then reads no credential from the environment
            base_url=base_url,  # explicit: ANTHROPIC_BASE_URL is never read
            max_retries=0,  # our retries, so the driver's before_retry gate runs between them
            timeout=limit,
            http_client=anthropic.DefaultAsyncHttpxClient(timeout=limit, follow_redirects=False),
            open_telemetry=False,
        )
        self._closed = False

    def __repr__(self) -> str:
        return f"AnthropicClient({self._where!r}, key={'set' if self._key else 'none'})"

    async def __aenter__(self) -> AnthropicClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        self._closed = True
        await self._sdk.close()

    async def chat(
        self,
        model: str,
        messages: list[dict],
        tools: list[dict],
        *,
        session_id: str,
        max_tokens: int | None = None,
        temperature: float | None = None,
        before_retry: Callable[[], Awaitable[None]] | None = None,
    ) -> Reply:
        """The model's next message. Raises ModelError when the call fails for good.

        session_id is not sent: the Messages API caches by content, not by session; it is what
        keeps a lane at standard speed once its fast mode hit the rate limit. Giving a
        temperature is a ValueError: these models reject it, and flightdeck does not drop a
        setting quietly. before_retry is awaited before each retry, after the backoff, as in
        ModelClient (and before the standard-speed try after a fast-mode 429); whatever it
        raises comes out of chat() as it is."""
        if temperature is not None:
            raise ValueError(
                "the Anthropic client sends no temperature: Claude's current models reject it; "
                "leave temperature unset for this provider"
            )
        if max_tokens is None:
            max_tokens = self.max_tokens
        fast = model in self.fast and session_id not in self._standard
        params = self._params(model, messages, tools, max_tokens, fast=fast)
        if self._closed:
            raise RuntimeError("the model client is closed")
        tries = self.max_retries + 1
        made = 0
        notice = ""
        failure = _Failure("no try was made", None, False)
        while True:
            outcome = await self._try(params)
            if not isinstance(outcome, _Failure):
                return self._reply(outcome, model, fast=model if fast else None, notice=notice)
            failure = outcome
            if fast and failure.status == 429:
                # Fast mode's own rate limit: go on at standard speed now, and stay there for this
                # session, since every switch of speed invalidates the prompt cache.
                fast = False
                self._standard.add(session_id)
                params = self._params(model, messages, tools, max_tokens, fast=False)
                notice = (
                    f"fast mode's own rate limit was reached (HTTP 429): {model} goes on at standard speed for "
                    "this lane's session (switching speed starts the prompt cache again)"
                )
                if before_retry is not None:
                    await before_retry()
                continue
            made += 1
            if not failure.retryable:
                raise self._error(failure.text, status=failure.status)
            if made >= tries:
                break
            await asyncio.sleep(retry_delay(made - 1, self.backoff, failure.retry_after))
            if before_retry is not None:
                await before_retry()
        raise self._error(f"{failure.text}; gave up after {tries} tries", status=failure.status, retryable=True)

    def _params(self, model: str, messages: Sequence[dict], tools: Sequence[dict], max_tokens: int | None, *,
                fast: bool) -> dict:
        effort = self.effort if self.effort is not None and model in EFFORT_MODELS else None
        return request(model, messages, tools, max_tokens, fast=fast, effort=effort, server_fallback=self.server_fallback)

    async def _try(self, params: dict) -> dict | _Failure:
        """One try: the message as a dict, or what went wrong.

        The SDK's exception is described here and dropped: its request holds the key."""
        try:
            async with asyncio.timeout(self.timeout):
                message = await self._sdk.beta.messages.create(**params)
        except TimeoutError:  # our deadline on the whole try passed
            return _Failure(f"no answer from the Anthropic API at {self._where}: timed out after {self.timeout:g} s", None, True)
        except anthropic.APIStatusError as exc:
            return self._answered(exc)
        except anthropic.APIConnectionError as exc:
            cause = exc.__cause__
            transient = cause is None or isinstance(exc, anthropic.APITimeoutError) or isinstance(cause, TRANSIENT)
            what = type(cause).__name__ if cause is not None else type(exc).__name__
            said = str(cause) if cause is not None else ""
            detail = f"{what}: {said}" if said else what
            return _Failure(f"no answer from the Anthropic API at {self._where}: {self._short(detail)}", None, transient)
        except anthropic.AnthropicError as exc:  # the SDK could not use what came back
            return _Failure(f"the Anthropic API sent a reply the SDK could not read ({type(exc).__name__})", None, False)
        except (ValueError, RecursionError) as exc:
            # what the SDK raises for a 2xx body that is not JSON, or nested too deep to parse
            return _Failure(f"the Anthropic API sent a reply that is not a JSON message ({type(exc).__name__})", 200, False)
        if not isinstance(message, anthropic.BaseModel):  # JSON, but not an object: the SDK hands it back as it is
            return _Failure("the Anthropic API sent a reply that is not a JSON message (not an object)", 200, False)
        # warnings off: a block type newer than this SDK is kept as sent, without a warning per turn
        return message.to_dict(mode="python", warnings=False)

    def _answered(self, exc: anthropic.APIStatusError) -> _Failure:
        """'the Anthropic API answered HTTP 529 (overloaded_error): Overloaded'."""
        status = exc.status_code
        kind, said = _error_parts(exc.body)
        kind = self._short(kind)[:60] if kind else ""
        text = f"the Anthropic API answered HTTP {status}" + (f" ({kind})" if kind else _phrase(status))
        if said:
            text += f": {self._short(said)}"
        headers = exc.response.headers
        return _Failure(text, status, _retryable(status, headers.get("x-should-retry")), headers.get("retry-after"))

    def _reply(self, data: dict, asked: str = "", *, fast: str | None = None, notice: str = "") -> Reply:
        """The reply to a call to `asked`, its usage priced at the fast rate when `fast` names
        the model of a fast request, and `notice` in front of its own."""
        outcome = parse(data, asked)
        if isinstance(outcome, Reply):
            reply = outcome if fast is None else replace(outcome, usage=fast_priced(outcome.usage, fast))
            if notice:
                reply = replace(reply, notice="; ".join(n for n in (notice, reply.notice) if n))
            return reply
        if isinstance(outcome, _Declined):
            text = f"the model declined ({self._short(outcome.category) if outcome.category else 'no category given'})"
            if outcome.explanation:
                text += f": {self._short(outcome.explanation)}"
            usage = outcome.usage if fast is None else fast_priced(outcome.usage, fast)
            raise self._error(text, status=200, declined=True, usage=usage)
        text = f"{outcome.what} (HTTP 200)" + (f": {self._short(outcome.detail)}" if outcome.detail else "")
        raise self._error(text, status=200)

    def _redact(self, text: str) -> str:
        return text.replace(self._key, "[key]") if self._key else text

    def _short(self, text: str) -> str:
        """The server's words, safe to show: no key, no control characters, one line, 300 at most."""
        text = untrusted(self._redact(text)[: MAX_ERROR_TEXT * 4], one_line=True).strip()
        return text if len(text) <= MAX_ERROR_TEXT else text[: MAX_ERROR_TEXT - 3] + "..."

    def _error(self, message: str, *, status: int | None = None, retryable: bool = False,
               declined: bool = False, usage: Usage | None = None) -> ModelError:
        return ModelError(untrusted(self._redact(message), one_line=True), status=status, retryable=retryable,
                          declined=declined, usage=usage)


# ---------------------------------------------------------------------- the request


def request(model: str, messages: Sequence[dict], tools: Sequence[dict], max_tokens: int | None, *,
            fast: bool = False, effort: str | None = None, server_fallback: bool = True) -> dict:
    """The keyword arguments for the SDK's beta messages.create(): the same every try.

    fast: `speed: "fast"` (and the fast-mode beta for a research-preview model); the model
    must be one agent/fastmode.py lists. effort: output_config.effort. server_fallback=False
    leaves the server-side refusal fallback out even for a model that has one."""
    if not isinstance(model, str) or not model:
        raise ValueError("model must be a non-empty string")
    if max_tokens is not None and (not isinstance(max_tokens, int) or isinstance(max_tokens, bool) or max_tokens < 1):
        raise ValueError(f"max_tokens must be a positive whole number, got {max_tokens!r}")
    system, rest = _split_system(messages)
    params: dict = {
        "model": model,
        "max_tokens": max_tokens or DEFAULT_MAX_TOKENS,
        "messages": to_anthropic(rest),
        "cache_control": {"type": "ephemeral"},  # automatic caching: the breakpoint follows the conversation's end
    }
    if system:
        blocks = [{"type": "text", "text": text} for text in system]
        blocks[-1]["cache_control"] = {"type": "ephemeral"}  # tools + system: the fixed prefix
        params["system"] = blocks
    if tools:
        params["tools"] = [_tool(tool) for tool in tools]
    betas: list[str] = []
    if server_fallback and model in SERVER_FALLBACK_MODELS:
        betas.append(FALLBACK_BETA)
        params["fallbacks"] = "default"
    if fast:
        problem = fast_problem(model)
        if problem is not None:
            raise ValueError(f"fast mode cannot be used: {problem}")
        params["speed"] = "fast"
        if FAST_MODES[model].beta:
            betas.append(FAST_BETA)
    if effort is not None:
        params["output_config"] = {"effort": effort}
    if betas:
        params["betas"] = betas
    return params


def fast_priced(usage: Usage, model: str) -> Usage:
    """`usage` of a fast request to `model`, its part on `model` priced at the fast rate (the
    tokens read from the cache and those written to it at the fast input rate: the
    documentation gives no other), unless the API says it ran at standard speed. A part
    another model ran (the refusal fallback's) gets no cost here: the config prices it."""
    if usage.speed == "standard":
        return usage
    price = FAST_MODES[model].price

    def priced(part: Usage) -> Usage:
        if part.model:
            return part
        return replace(part, cost=cost(price, part.prompt_tokens, part.completion_tokens, part.cached_tokens,
                                       part.cache_write_tokens))

    return replace(priced(usage), more=tuple(priced(part) for part in usage.more))


def _split_system(messages: Sequence[dict]) -> tuple[list[str], list[dict]]:
    """The leading system messages' texts, and the messages after them."""
    texts: list[str] = []
    for index, message in enumerate(messages):
        if not isinstance(message, dict):
            raise ValueError(f"message {index} is not a dict")
        if message.get("role") != "system":
            return texts, list(messages[index:])
        text = _text_of(message.get("content"), f"message {index}")
        if text:
            texts.append(text)
    return texts, []


def to_anthropic(messages: Sequence[dict]) -> list[dict]:
    """The conversation after the system prompt as Messages API turns (see the module doc)."""
    turns: list[dict] = []
    for index, message in enumerate(messages):
        where = f"message {index}"
        if not isinstance(message, dict):
            raise ValueError(f"{where} is not a dict")
        role = message.get("role")
        if role == "tool":
            call_id = message.get("tool_call_id")
            if not isinstance(call_id, str) or not call_id:
                raise ValueError(f"{where}: a tool result without a tool_call_id")
            result = {"type": "tool_result", "tool_use_id": call_id, "content": _text_of(message.get("content"), where)}
            _add(turns, "user", [result])
        elif role == "user":
            text = _text_of(message.get("content"), where)
            if text:
                _add(turns, "user", [{"type": "text", "text": text}])
        elif role == "assistant":
            raw = message.get(CONTENT_KEY)
            if raw is not None:
                if not isinstance(raw, list):
                    raise ValueError(f"{where}: {CONTENT_KEY} is not a list of content blocks")
                blocks = list(raw)  # the blocks themselves go back exactly as they came
            else:
                blocks = _from_openai(message, where)
            if blocks:
                _add(turns, "assistant", blocks)
        elif role == "system":
            raise ValueError(f"{where}: a system message after the conversation started; flightdeck puts none there")
        else:
            raise ValueError(f"{where}: unknown role {role!r}")
    return turns


def _add(turns: list[dict], role: str, blocks: list[dict]) -> None:
    """Append blocks as a turn of `role`, joining the last turn when it has the same role."""
    if turns and turns[-1]["role"] == role:
        turns[-1]["content"].extend(blocks)
    else:
        turns.append({"role": role, "content": list(blocks)})


def _from_openai(message: dict, where: str) -> list[dict]:
    """An OpenAI-style assistant message as content blocks: its text, then its tool calls."""
    blocks: list[dict] = []
    text = _text_of(message.get("content"), where)
    if text.strip():
        blocks.append({"type": "text", "text": text})
    for call in message.get("tool_calls") or []:
        function = call.get("function") if isinstance(call, dict) else None
        call_id = call.get("id") if isinstance(call, dict) else None
        name = function.get("name") if isinstance(function, dict) else None
        if not isinstance(call_id, str) or not call_id or not isinstance(name, str) or not name:
            raise ValueError(f"{where}: a tool call without an id or a function name")
        try:
            arguments = json.loads(function.get("arguments") or "{}")
        except (TypeError, ValueError, RecursionError):
            arguments = {}  # the call ran with arguments that were not JSON, and its result said so
        blocks.append({"type": "tool_use", "id": call_id, "name": name,
                       "input": arguments if isinstance(arguments, dict) else {}})
    return blocks


def _text_of(content: object, where: str) -> str:
    """A message's text: a string, or the text parts of a list of content parts."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for part in content:
            if isinstance(part, dict) and part.get("type", "text") == "text" and isinstance(part.get("text"), str):
                parts.append(part["text"])
            else:
                raise ValueError(f"{where}: content parts other than text cannot go to the Anthropic API")
        return "".join(parts)
    raise ValueError(f"{where}: content of an unknown kind ({type(content).__name__})")


def _tool(tool: dict) -> dict:
    """An OpenAI function tool as a Messages API tool: name, description, input_schema."""
    function = tool.get("function") if isinstance(tool, dict) and tool.get("type") == "function" else None
    name = function.get("name") if isinstance(function, dict) else None
    if not isinstance(name, str) or not name:
        raise ValueError("a tool that is not an OpenAI function with a name")
    out: dict = {"name": name, "input_schema": function.get("parameters") or {"type": "object", "properties": {}}}
    description = function.get("description")
    if isinstance(description, str) and description:
        out["description"] = description
    return out


# ---------------------------------------------------------------------- the reply


def parse(data: dict, asked: str = "") -> Reply | _Malformed | _Declined:
    """A message (as the SDK's to_dict() gives it) of a call to the model `asked` as a Reply;
    or what is wrong with it."""
    reported = data.get("error")
    if isinstance(reported, dict):  # an error in a 2xx answer
        return _Malformed("the Anthropic API reported an error", _string(reported.get("message")) or "no message given")
    content = data.get("content")
    if not isinstance(content, list) or not all(isinstance(block, dict) for block in content):
        return _Malformed("the Anthropic API sent a message without a list of content blocks")
    usage = _usage(data.get("usage"), asked, _string(data.get("model")))
    stop = _string(data.get("stop_reason"))
    if stop == "refusal":
        details = data.get("stop_details")
        details = details if isinstance(details, dict) else {}
        return _Declined(_string(details.get("category")), _string(details.get("explanation")), usage)
    if not _finite(content):
        # it goes back into the history, and the next request's body could not encode it
        return _Malformed("the Anthropic API sent a message holding a number JSON cannot carry (NaN or infinity)")
    texts: list[str] = []
    calls: list[ToolCall] = []
    entries: list[dict] = []
    notices: list[str] = []
    for block in content:
        kind = block.get("type")
        if kind == "text":
            text = block.get("text")
            if not isinstance(text, str):
                return _Malformed("the Anthropic API sent a text block without text")
            texts.append(text)
        elif kind == "tool_use":
            call_id, name, arguments = block.get("id"), block.get("name"), block.get("input")
            if not isinstance(call_id, str) or not call_id or not isinstance(name, str) or not name:
                return _Malformed("the Anthropic API sent a tool_use block without an id or a name")
            if not isinstance(arguments, dict):
                return _Malformed("the Anthropic API sent a tool_use block whose input is not an object")
            arguments_text = json.dumps(arguments)
            calls.append(ToolCall(call_id, name, arguments_text))
            entries.append({"id": call_id, "type": "function", "function": {"name": name, "arguments": arguments_text}})
        elif kind == "fallback":
            notices.append(_fallback_notice(block))
    text = "".join(texts)
    message: dict = {"role": "assistant", "content": text if text or not entries else None, CONTENT_KEY: content}
    if entries:
        message["tool_calls"] = entries
    return Reply(
        message=message,
        content=text,
        tool_calls=tuple(calls),
        finish_reason=stop,
        usage=usage,
        model=_string(data.get("model")),
        notice="; ".join(notices),
    )


def _usage(raw: object, asked: str = "", served: str = "") -> Usage:
    """What a call to the model `asked` used (Usage says how a call on several models is told):
    prompt tokens = input + cache read + cache write; cached = cache read; cache write = what
    the call wrote to the cache (cache_creation_input_tokens, all of it at the 5-minute rate:
    flightdeck's requests never ask for the 1-hour cache); cost unknown; and the speed the API
    says the request ran at ("fast" or "standard"), "" when it says neither.

    With usage.iterations, the call's attempts are what counts: Anthropic's documentation
    (shared/model-migration.md, the refusal section) says "`usage.iterations` is the per-attempt
    source of truth; top-level `usage` covers only the attempt that produced the returned
    message", and "fallback attempts bill at the fallback model's rates". So the attempts are
    summed per model that ran them, and the top-level counts, the last attempt's, are not added
    again. An attempt that names no model ran on the model asked for, except the fallback's
    (fallback_message), which ran on the model the reply names (`served`). A declined attempt
    counts as it is reported: whether one declined before any output is billed depends on its
    category, so the meter may count one Anthropic does not bill, never leave out one it does."""
    if not isinstance(raw, dict):
        return Usage()
    speed = raw.get("speed")
    speed = speed if speed in ("fast", "standard") else ""
    entries = raw.get("iterations")
    attempts = [entry for entry in entries if isinstance(entry, dict)] if isinstance(entries, list) else []
    if not attempts:
        return replace(_tokens(raw), speed=speed)
    parts: dict[str, Usage] = {}
    last = asked
    for entry in attempts:
        name = entry.get("model")
        if not isinstance(name, str) or not name:
            name = served if entry.get("type") == "fallback_message" and served else asked
        parts[name] = _plus(parts.get(name, Usage()), _tokens(entry))
        last = name

    def named(name: str, part: Usage) -> Usage:
        return replace(part, model="" if name == asked else untrusted(name, one_line=True)[:80])

    top = named(last, parts.pop(last))
    return replace(top, speed=speed, more=tuple(named(name, part) for name, part in parts.items()))


def _tokens(raw: dict) -> Usage:
    """One usage object's (or one attempt's) token counts."""
    read = _count(raw.get("cache_read_input_tokens"))
    written = _count(raw.get("cache_creation_input_tokens"))
    return Usage(prompt_tokens=_count(raw.get("input_tokens")) + read + written,
                 completion_tokens=_count(raw.get("output_tokens")), cached_tokens=read, cache_write_tokens=written)


def _plus(a: Usage, b: Usage) -> Usage:
    return replace(a, prompt_tokens=a.prompt_tokens + b.prompt_tokens, completion_tokens=a.completion_tokens + b.completion_tokens,
                   cached_tokens=a.cached_tokens + b.cached_tokens, cache_write_tokens=a.cache_write_tokens + b.cache_write_tokens)


def _fallback_notice(block: dict) -> str:
    """'Anthropic's refusal fallback: claude-opus-5-5 declined (cyber), claude-opus-4-8 answered'."""

    def model(side: str) -> str:
        info = block.get(side)
        name = info.get("model") if isinstance(info, dict) else None
        return untrusted(name, one_line=True)[:80] if isinstance(name, str) and name else "a model"

    trigger = block.get("trigger")
    category = trigger.get("category") if isinstance(trigger, dict) else None
    why = f" ({untrusted(category, one_line=True)[:40]})" if isinstance(category, str) and category else ""
    return f"Anthropic's refusal fallback: {model('from')} declined{why}, {model('to')} answered"


def _error_parts(body: object) -> tuple[str, str]:
    """(error.type, error.message) of an Anthropic error body, or ("", the body's text)."""
    if isinstance(body, dict):
        error = body.get("error")
        if isinstance(error, dict):
            return _string(error.get("type")), _string(error.get("message"))
        return "", ""
    return ("", body) if isinstance(body, str) else ("", "")


def _retryable(status: int, should_retry: str | None) -> bool:
    """The SDK's own retry policy: the server's x-should-retry wins; else 408, 409, 429, 5xx."""
    if should_retry == "true":
        return True
    if should_retry == "false":
        return False
    return status in (408, 409, 429) or status >= 500


def _base_url(base_url: str) -> str:
    """The base URL as errors show it (no user info, query or fragment); ValueError when it
    is not an http(s) URL with a host."""
    if not isinstance(base_url, str) or not base_url.startswith(("http://", "https://")):
        raise ValueError("base_url must start with http:// or https://")
    try:
        url = httpx2.URL(base_url)
    except httpx2.InvalidURL as exc:
        raise ValueError(f"base_url is not a valid URL: {exc}") from None
    if not url.host:
        raise ValueError("base_url has no host")
    return str(url.copy_with(userinfo=b"", query=None, fragment=None))


def _string(value: object) -> str:
    return value if isinstance(value, str) else ""
