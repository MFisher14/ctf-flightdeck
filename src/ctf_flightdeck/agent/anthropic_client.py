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
= cache read, no cost: flightdeck prices it from the config) and the model that answered.

What is sent, as the claude-api skill says for these models: no `thinking` (left out, they
think adaptively), no `temperature` (they reject it, and SDK 2 has no such argument), no
`tool_choice` (forcing a tool is a 400; auto is the default). A model in
SERVER_FALLBACK_MODELS (Claude Sonnet 5.5 and Opus 5.5 among them) carries the server-side
refusal fallback (beta server-side-fallback-2026-07-01, fallbacks "default"): a request its
classifiers decline runs again, inside the same call, on the model Anthropic recommends for
that category. A final stop_reason "refusal" means the whole chain declined: a ModelError,
declined and never retried, naming the category. Claude Haiku 5.5 has no server-side
fallback, so its requests carry none.

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
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass

import anthropic
import httpx2

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

DEFAULT_BASE_URL = "https://api.anthropic.com"  # the SDK's own default; it adds /v1/messages
DEFAULT_TIMEOUT = 600.0  # seconds per try: the SDK's default request timeout (10 minutes)
DEFAULT_MAX_TOKENS = 16_000  # when the caller gives none: the skill's default for a request that does not stream
CONTENT_KEY = "_anthropic_content"  # the raw content blocks of a reply, on its history message
FALLBACK_BETA = "server-side-fallback-2026-07-01"  # the beta that takes fallbacks="default"
SERVER_FALLBACK_MODELS = frozenset(
    {"claude-sonnet-5-5", "claude-opus-5-5", "claude-opus-5", "claude-fable-5-1", "claude-fable-5-2"}
)
"""The models whose requests carry the server-side refusal fallback by default (claude-api
skill). Claude Haiku 5.5 is not one: it has none, and a fallbacks list is a 400 there."""

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
    `max_retries + 1` tries, waiting retry_delay() between them.
    """

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        api_key: str | None = None,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        max_retries: int = 4,
        backoff: float = 1.0,
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
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff = backoff
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

        session_id is not sent: the Messages API caches by content, not by session. Giving a
        temperature is a ValueError: these models reject it, and flightdeck does not drop a
        setting quietly. before_retry is awaited before each retry, after the backoff, as in
        ModelClient; whatever it raises comes out of chat() as it is."""
        if temperature is not None:
            raise ValueError(
                "the Anthropic client sends no temperature: Claude's current models reject it; "
                "leave temperature unset for this provider"
            )
        params = request(model, messages, tools, max_tokens)
        if self._closed:
            raise RuntimeError("the model client is closed")
        tries = self.max_retries + 1
        failure = _Failure("no try was made", None, False)
        for attempt in range(tries):
            outcome = await self._try(params)
            if not isinstance(outcome, _Failure):
                return self._reply(outcome)
            failure = outcome
            if not failure.retryable:
                raise self._error(failure.text, status=failure.status)
            if attempt + 1 < tries:
                await asyncio.sleep(retry_delay(attempt, self.backoff, failure.retry_after))
                if before_retry is not None:
                    await before_retry()
        raise self._error(f"{failure.text}; gave up after {tries} tries", status=failure.status, retryable=True)

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

    def _reply(self, data: dict) -> Reply:
        outcome = parse(data)
        if isinstance(outcome, Reply):
            return outcome
        if isinstance(outcome, _Declined):
            text = f"the model declined ({self._short(outcome.category) if outcome.category else 'no category given'})"
            if outcome.explanation:
                text += f": {self._short(outcome.explanation)}"
            raise self._error(text, status=200, declined=True, usage=outcome.usage)
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


def request(model: str, messages: Sequence[dict], tools: Sequence[dict], max_tokens: int | None) -> dict:
    """The keyword arguments for the SDK's beta messages.create(): the same every try."""
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
    if model in SERVER_FALLBACK_MODELS:
        params["betas"] = [FALLBACK_BETA]
        params["fallbacks"] = "default"
    return params


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


def parse(data: dict) -> Reply | _Malformed | _Declined:
    """A message (as the SDK's to_dict() gives it) as a Reply; or what is wrong with it."""
    reported = data.get("error")
    if isinstance(reported, dict):  # an error in a 2xx answer
        return _Malformed("the Anthropic API reported an error", _string(reported.get("message")) or "no message given")
    content = data.get("content")
    if not isinstance(content, list) or not all(isinstance(block, dict) for block in content):
        return _Malformed("the Anthropic API sent a message without a list of content blocks")
    usage = _usage(data.get("usage"))
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


def _usage(raw: object) -> Usage:
    """prompt tokens = input + cache read + cache write; cached = cache read; cost unknown."""
    if not isinstance(raw, dict):
        return Usage()
    read = _count(raw.get("cache_read_input_tokens"))
    prompt = _count(raw.get("input_tokens")) + read + _count(raw.get("cache_creation_input_tokens"))
    return Usage(prompt_tokens=prompt, completion_tokens=_count(raw.get("output_tokens")), cached_tokens=read, cost=None)


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
