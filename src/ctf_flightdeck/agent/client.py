"""The model API client: chat completions from an OpenAI-compatible endpoint.

A lane's driver hands the client the conversation so far and gets back the model's next
message. The endpoint is `POST {base_url}/chat/completions`: OpenRouter by default, or any
server that speaks the same dialect (a local one needs no key). The client has three jobs:
build a request that keeps prompt caching working, retry the failures a retry can fix, and
turn the answer into plain data that nothing has to trust.

Caching. Most of a lane's tokens are the same prefix re-read every turn, so cache hits are
most of the bill. OpenRouter routes requests with the same `session_id` to the provider
that served them before, which keeps the prefix in that provider's cache. A
`provider.order` would switch that sticky routing off, so the client never sends a
`provider` object at all (docs/ARCHITECTURE.md).

Secrets. The API key goes in the Authorization header and nowhere else: not in a repr, an
error message or an exception chain. Error text from the server has the key cut out before
it is used, because a server may echo the key back.

Untrusted data. Everything in an answer came from a model or a server. Error text is passed
through `text.untrusted()` and shortened. The reply's message is handed back as data for
the history, with its role pinned to "assistant" so an answer cannot smuggle a system or
tool message into the conversation.
"""

from __future__ import annotations

import asyncio
import json
import math
import re
import uuid
from dataclasses import dataclass
from http import HTTPStatus

import httpx

from ..text import untrusted

RETRY_STATUSES = frozenset({408, 429, 500, 502, 503, 504})
"""Statuses that mean "not now": a timeout, a rate limit, an overloaded or failing upstream."""

TRANSIENT = (httpx.TimeoutException, httpx.NetworkError, httpx.RemoteProtocolError, httpx.ProxyError)
"""Transport errors a retry can fix: timeouts, refused or dropped connections."""

MAX_WAIT = 30.0  # seconds: the longest pause between tries, whatever Retry-After asks for
CONNECT_TIMEOUT = 15.0  # seconds: a connection that takes longer is not coming
MAX_SESSION_ID = 256  # OpenRouter's limit on session_id
MAX_ERROR_TEXT = 300  # characters of the server's own words kept in a ModelError

_KEY_CHARS = re.compile(r"[\x21-\x7e]+")  # what a key may hold: printable ASCII, no spaces
_TITLE_CHARS = re.compile(r"[\x20-\x7e]+")
_SECONDS = re.compile(r"\s*(\d+(?:\.\d+)?)\s*")  # Retry-After in seconds; an HTTP date is ignored
_NOT_JSON = object()


@dataclass(frozen=True)
class ToolCall:
    """One function call the model asked for."""

    id: str
    name: str
    arguments: str  # the JSON text exactly as the model sent it (may be invalid JSON)


@dataclass(frozen=True)
class Usage:
    """The tokens a call used and, when the API says, what it cost."""

    prompt_tokens: int = 0
    completion_tokens: int = 0
    cached_tokens: int = 0  # of the prompt tokens, how many the API served from its cache
    cost: float | None = None  # dollars charged, when the API reports it (OpenRouter does)

    @property
    def total(self) -> int:
        return self.prompt_tokens + self.completion_tokens


@dataclass(frozen=True)
class Reply:
    """The model's next message, parsed. Everything in it is untrusted data."""

    message: dict  # the assistant message as returned (role, content, tool_calls), to append to the history
    content: str  # "" when the message has no text
    tool_calls: tuple[ToolCall, ...]
    finish_reason: str  # "" if absent
    usage: Usage
    model: str  # the model the API says answered ("" if absent)


class ModelError(Exception):
    """A call failed for good. str() never contains the key or any header.

    `status` is the HTTP status of the last answer, None when the last try got none (it
    could not connect, or timed out). `retryable` is True when the failure was of a kind
    that passes (a rate limit, an overload, the network) and the retries ran out, so trying
    again later may work; False when trying again will not help (a bad request, a bad key,
    a reply that makes no sense).
    """

    def __init__(self, message: str, *, status: int | None = None, retryable: bool = False) -> None:
        super().__init__(message)
        self.status = status
        self.retryable = retryable


def retry_delay(attempt: int, backoff: float, retry_after: str | None = None) -> float:
    """Seconds to wait after failed try number `attempt` (0 for the first).

    A numeric Retry-After from the server wins; otherwise the wait doubles from `backoff`.
    Either way it is capped at MAX_WAIT, so no server can park a lane for an hour.
    """
    match = _SECONDS.fullmatch(retry_after) if retry_after is not None else None
    seconds = float(match.group(1)) if match else backoff * 2.0 ** min(attempt, 64)
    return min(MAX_WAIT, max(0.0, seconds))


class ModelClient:
    """Chat completions from one OpenAI-compatible endpoint, shared by the lanes.

    `chat()` may run for several lanes at once on one event loop. httpx pools connections
    per loop, so keep the client on that loop and `aclose()` it when done (or use `async
    with`). `timeout` bounds each try as a whole, in seconds, from connecting to the last
    byte of the answer: an answer that is not complete by then is given up on and tried
    again (a non-streaming answer only starts once the model has finished); connecting gets
    at most CONNECT_TIMEOUT of it. A call makes at most `max_retries + 1` tries. With
    `transport` given, httpx ignores proxy variables.
    """

    def __init__(
        self,
        base_url: str,
        api_key: str | None,
        *,
        timeout: float = 180.0,
        max_retries: int = 4,
        backoff: float = 1.0,
        transport: httpx.AsyncBaseTransport | None = None,
        app_name: str = "ctf-flightdeck",
    ) -> None:
        self._url = _endpoint(base_url)
        if api_key is not None and not _KEY_CHARS.fullmatch(api_key):
            raise ValueError(
                "the API key is empty or holds characters an HTTP header cannot carry "
                "(spaces, line breaks, non-ASCII); check the variable it came from"
            )
        if not _TITLE_CHARS.fullmatch(app_name):
            raise ValueError("app_name must be printable ASCII")
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
        self._where = str(self._url.copy_with(userinfo=b"", query=None, fragment=None))
        headers = {"Content-Type": "application/json", "X-Title": app_name}
        if api_key is not None:
            headers["Authorization"] = f"Bearer {api_key}"
        self._http = httpx.AsyncClient(
            headers=headers,
            timeout=httpx.Timeout(timeout, connect=min(timeout, CONNECT_TIMEOUT)),
            transport=transport,
            follow_redirects=False,  # a redirect is an answer, not a new place to send the key
        )
        self._closed = False

    def __repr__(self) -> str:
        return f"ModelClient({self._where!r}, key={'set' if self._key else 'none'})"

    async def __aenter__(self) -> ModelClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        self._closed = True
        await self._http.aclose()

    async def chat(
        self,
        model: str,
        messages: list[dict],
        tools: list[dict],
        *,
        session_id: str,
        max_tokens: int | None = None,
        temperature: float | None = None,
    ) -> Reply:
        """The model's next message. Raises ModelError when the call fails for good."""
        content = _request_body(model, messages, tools, session_id, max_tokens, temperature)
        if self._closed:
            raise RuntimeError("the model client is closed")
        tries = self.max_retries + 1
        failure, status = "", None
        for attempt in range(tries):
            response, problem, transient = await self._post(content)
            if response is None:
                failure, status = f"no answer from the model API at {self._where}: {self._short(problem)}", None
                if not transient:
                    raise self._error(failure)
                wait = retry_delay(attempt, self.backoff)
            elif response.status_code in RETRY_STATUSES:
                failure, status = self._answered(response), response.status_code
                wait = retry_delay(attempt, self.backoff, response.headers.get("retry-after"))
            elif not response.is_success:
                raise self._error(self._answered(response), status=response.status_code)
            else:
                return self._reply(response)
            if attempt + 1 < tries:
                await asyncio.sleep(wait)
        raise self._error(f"{failure}; gave up after {tries} tries", status=status, retryable=True)

    async def _post(self, content: bytes) -> tuple[httpx.Response | None, str, bool]:
        """One try: the response, or None with what went wrong and whether a retry may help.

        httpx's timeouts bound each wait for bytes, not the whole answer, so a server that
        sends a byte now and then could hold a try for as long as it liked: the deadline
        here bounds the whole try. The httpx error is described here and dropped, never
        chained onto a ModelError: its request holds the Authorization header.
        """
        try:
            async with asyncio.timeout(self.timeout):
                return await self._http.post(self._url, content=content), "", False
        except TimeoutError:  # the deadline passed: no complete answer in time
            return None, f"timed out after {self.timeout:g} s", True
        except httpx.HTTPError as exc:
            what = type(exc).__name__ + (f": {exc}" if str(exc) else "")
            return None, what, isinstance(exc, TRANSIENT)

    def _answered(self, response: httpx.Response) -> str:
        """'the model API answered HTTP 429 (Too Many Requests): <its error message>'."""
        code = response.status_code
        text = f"the model API answered HTTP {code}{_phrase(code)}"
        message = _error_message(_json(response))
        return f"{text}: {self._short(message)}" if message else text

    def _reply(self, response: httpx.Response) -> Reply:
        """A 2xx answer as a Reply, or a ModelError naming what is wrong with it."""
        status = response.status_code
        data = _json(response)
        if data is _NOT_JSON:
            what, detail = "the model API sent a reply that is not JSON", response.text or "(empty)"
        elif not isinstance(data, dict):
            what, detail = "the model API sent a reply that is not a JSON object", ""
        else:
            try:
                return _parse(data)
            except _Malformed as bad:  # the ModelError is raised below, outside this block: it chains nothing
                what, detail = bad.what, bad.detail
        message = f"{what} (HTTP {status})" + (f": {self._short(detail)}" if detail else "")
        raise self._error(message, status=status)

    def _redact(self, text: str) -> str:
        return text.replace(self._key, "[key]") if self._key else text

    def _short(self, text: str) -> str:
        """The server's words, safe to show: no key, no control characters, one line, 300 at most."""
        text = untrusted(self._redact(text)[: MAX_ERROR_TEXT * 4], one_line=True).strip()
        return text if len(text) <= MAX_ERROR_TEXT else text[: MAX_ERROR_TEXT - 3] + "..."

    def _error(self, message: str, *, status: int | None = None, retryable: bool = False) -> ModelError:
        return ModelError(untrusted(self._redact(message), one_line=True), status=status, retryable=retryable)


class _Malformed(Exception):
    """A 2xx reply the client cannot use: `what` in our words, `detail` in the server's."""

    def __init__(self, what: str, detail: str = "") -> None:
        super().__init__(what)
        self.what = what
        self.detail = detail


def _endpoint(base_url: str) -> httpx.URL:
    """{base_url}/chat/completions, whether or not base_url ends with "/"."""
    if not isinstance(base_url, str) or not base_url.startswith(("http://", "https://")):
        raise ValueError("base_url must start with http:// or https://")
    try:
        url = httpx.URL(base_url)
    except httpx.InvalidURL as exc:
        raise ValueError(f"base_url is not a valid URL: {exc}") from None
    if not url.host:
        raise ValueError("base_url has no host")
    return url.copy_with(path=url.path.rstrip("/") + "/chat/completions")


def _request_body(
    model: str,
    messages: list[dict],
    tools: list[dict],
    session_id: str,
    max_tokens: int | None,
    temperature: float | None,
) -> bytes:
    """The JSON body, encoded once so every try sends the same bytes.

    Never a `provider` object: provider.order switches off sticky routing, and with it
    the prompt cache.
    """
    if not isinstance(model, str) or not model:
        raise ValueError("model must be a non-empty string")
    if not isinstance(session_id, str) or not 1 <= len(session_id) <= MAX_SESSION_ID:
        size = len(session_id) if isinstance(session_id, str) else type(session_id).__name__
        raise ValueError(f"session_id must be 1 to {MAX_SESSION_ID} characters (OpenRouter's limit), got {size}")
    body: dict = {"model": model, "messages": messages, "session_id": session_id}
    if tools:
        body["tools"] = tools
        body["tool_choice"] = "auto"
    if max_tokens is not None:
        body["max_tokens"] = max_tokens
    if temperature is not None:
        body["temperature"] = temperature
    return json.dumps(body, separators=(",", ":"), allow_nan=False).encode("ascii")


def _parse(data: dict) -> Reply:
    """A chat.completion body as a Reply; _Malformed when it is an error or makes no sense."""
    if data.get("error"):
        raise _reported(data)
    choices = data.get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        raise _Malformed("the model API sent a reply without choices")
    choice = choices[0]
    if choice.get("error"):
        raise _reported(choice)
    message = choice.get("message")
    if not isinstance(message, dict):
        raise _Malformed("the model API sent a reply without a message")
    calls, entries = _tool_calls(message.get("tool_calls"))
    history = {**message, "role": "assistant"}
    if entries is not None:
        history["tool_calls"] = entries
    return Reply(
        message=history,
        content=_content(message.get("content")),
        tool_calls=calls,
        finish_reason=_text(choice.get("finish_reason")),
        usage=_usage(data.get("usage")),
        model=_text(data.get("model")),
    )


def _reported(holder: dict) -> _Malformed:
    """An error the API put in a 2xx body (OpenRouter does when a provider fails)."""
    error = holder.get("error")
    code = error.get("code") if isinstance(error, dict) else None
    what = "the model API reported an error" + (f", code {code}" if isinstance(code, int) else "")
    return _Malformed(what, _error_message(holder) or "no message given")


def _content(raw: object) -> str:
    """The message's text: a string, or the text parts of a list of content parts."""
    if raw is None:
        return ""
    if isinstance(raw, str):
        return raw
    if isinstance(raw, list):
        return "".join(
            part["text"]
            for part in raw
            if isinstance(part, dict) and part.get("type", "text") == "text" and isinstance(part.get("text"), str)
        )
    raise _Malformed(f"the model API sent message content of an unknown kind ({type(raw).__name__})")


def _tool_calls(raw: object) -> tuple[tuple[ToolCall, ...], list[dict] | None]:
    """The calls, and a completed copy of the message's tool_calls if one needed completing.

    Arguments are kept exactly as sent. A call with no id gets a fresh one, and arguments
    sent as an object become JSON text; the history copy gets the same fix, so the next
    request answers the calls the driver ran, under the same ids.
    """
    if raw is None:
        return (), None
    if not isinstance(raw, list):
        raise _Malformed("the model API sent tool_calls that are not a list")
    calls: list[ToolCall] = []
    entries: list[dict] = []
    completed = False
    for raw_entry in raw:
        function = raw_entry.get("function") if isinstance(raw_entry, dict) else None
        name = function.get("name") if isinstance(function, dict) else None
        if not isinstance(name, str):
            raise _Malformed("the model API sent a tool call without a function name")
        entry = dict(raw_entry)
        call_id = entry.get("id")
        if not isinstance(call_id, str) or not call_id:
            call_id = entry["id"] = f"call_{uuid.uuid4().hex[:24]}"
            completed = True
        arguments = function.get("arguments")
        if not isinstance(arguments, str):
            arguments = "" if arguments is None else json.dumps(arguments)
            entry["function"] = {**function, "arguments": arguments}
            completed = True
        calls.append(ToolCall(call_id, name, arguments))
        entries.append(entry)
    return tuple(calls), entries if completed else None


def _usage(raw: object) -> Usage:
    if not isinstance(raw, dict):
        return Usage()
    details = raw.get("prompt_tokens_details")
    cached = details.get("cached_tokens") if isinstance(details, dict) else None
    return Usage(
        prompt_tokens=_count(raw.get("prompt_tokens")),
        completion_tokens=_count(raw.get("completion_tokens")),
        cached_tokens=_count(cached),
        cost=_dollars(raw.get("cost")),
    )


def _count(value: object) -> int:
    """A token count; 0 when absent or not a whole, non-negative number."""
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return max(0, value)
    if isinstance(value, float) and value.is_integer():
        return max(0, int(value))
    return 0


def _dollars(value: object) -> float | None:
    """A reported cost; None (unknown) when absent or not a finite, non-negative number."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        value = float(value)
    except OverflowError:  # an integer too big for a float: no real bill
        return None
    return value if math.isfinite(value) and value >= 0 else None


def _text(value: object) -> str:
    return value if isinstance(value, str) else ""


def _json(response: httpx.Response) -> object:
    """The parsed body, or _NOT_JSON when it is not strict JSON.

    Python's parser also takes NaN and Infinity, and reads a number such as 1e400 as
    infinity. JSON has neither, and a reply message holding one could never be sent back
    in the history: `_request_body` refuses it. A body nested deeper than the parser can
    follow raises RecursionError, not ValueError, and is refused the same way.
    """
    try:
        return response.json(parse_constant=_refuse_constant, parse_float=_finite_float)
    except (ValueError, RecursionError):  # ValueError covers UnicodeDecodeError too
        return _NOT_JSON


def _refuse_constant(name: str) -> float:
    raise ValueError(f"{name} is not JSON")


def _finite_float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        raise ValueError("a number too big for a float")
    return value


def _error_message(data: object) -> str:
    """The text of an OpenAI-style error ({"error": {"message": ...}}), or ""."""
    if not isinstance(data, dict):
        return ""
    error = data.get("error")
    if isinstance(error, dict):
        message = error.get("message")
        return message if isinstance(message, str) else ""
    return error if isinstance(error, str) else ""


def _phrase(code: int) -> str:
    try:
        return f" ({HTTPStatus(code).phrase})"
    except ValueError:
        return ""
