"""Two model APIs, one in front of the other: the primary first, the fallback when it keeps failing.

FallbackClient has ModelClient's chat() and aclose(). A lane's call goes to the primary. When
the primary fails for good with a retryable error (a rate limit, an overload, a 5xx, or no
answer, after its own retries), the call goes to the fallback API with the lane's model
mapped to the fallback's ladder, and the lane stays there for the rest of its current
context: the two APIs are never mixed inside one context, so a reply with Anthropic thinking
blocks is never followed by one from another API that the next Anthropic request would have
to replay. The first reply from the fallback carries a notice for the lane's transcript
("moved to OpenRouter (anthropic/claude-haiku-5.5) for the rest of this context: ...").

A context is the message list the driver keeps for a lane (agent/driver.py): it appends to
that one list for as long as the context lasts and starts a new list at an escalation (which
also gets a new session id) and at a context refresh. A call with another list, or another
session, is a fresh context, and it tries the primary again.

A failure that is not retryable (a bad request, a bad key, the model declining) does not
move the lane: trying another API would not change the answer, or should not. Nothing falls
back silently either: a lane's model with no fallback model, or a fallback that fails too,
ends the call with an error that says so.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from .client import ChatClient, ModelClient, ModelError, Reply

if TYPE_CHECKING:
    from ..config import Config


@dataclass
class _Moved:
    """A lane session that moved to the fallback: the context it moved in, the model there,
    and the notice its first fallback reply still has to carry ("" once it has)."""

    messages: list[dict]
    model: str
    notice: str


class FallbackClient:
    """The primary API, and the fallback for a lane whose primary keeps failing.

    `models` maps each primary model to its fallback model (position i of [models] ladder to
    position i of [fallback] ladder). `primary_name` and `fallback_name` are how the notices
    and errors name the two APIs ("Anthropic", "OpenRouter")."""

    def __init__(
        self,
        primary: ChatClient,
        fallback: ChatClient,
        models: Mapping[str, str],
        *,
        primary_name: str,
        fallback_name: str,
    ) -> None:
        self.primary = primary
        self.fallback = fallback
        self.models = dict(models)
        self.primary_name = primary_name
        self.fallback_name = fallback_name
        self._moved: dict[str, _Moved] = {}  # session id -> the context that moved

    def __repr__(self) -> str:
        return f"FallbackClient({self.primary!r}, then {self.fallback!r})"

    async def __aenter__(self) -> FallbackClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        self._moved.clear()
        try:
            await self.primary.aclose()
        finally:
            await self.fallback.aclose()

    def moved(self, session_id: str) -> str | None:
        """The fallback model a lane session is on now, or None when it is on the primary."""
        moved = self._moved.get(session_id)
        return moved.model if moved is not None else None

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
        """The model's next message, from the primary or, for a context that moved, the
        fallback. Raises ModelError when the call fails for good on the API it ended on."""
        if not isinstance(session_id, str) or not session_id:
            raise ValueError("session_id must be a non-empty string: it is what keeps a lane on one API")
        moved = self._moved.get(session_id)
        if moved is not None and moved.messages is not messages:
            del self._moved[session_id]  # a fresh context (a refresh): the primary again
            moved = None
        if moved is None:
            failure: ModelError | None = None
            try:
                return await self.primary.chat(
                    model, messages, tools, session_id=session_id, max_tokens=max_tokens,
                    temperature=temperature, before_retry=before_retry,
                )
            except ModelError as exc:
                failure = exc
            # outside the except block: what is raised from here chains nothing
            if not failure.retryable:
                raise failure
            target = self.models.get(model)
            if target is None:
                raise _again(failure, f"{failure}; no fallback: [fallback] ladder has no model for {model}")
            moved = _Moved(
                messages, target,
                f"moved to {self.fallback_name} ({target}) for the rest of this context: "
                f"{self.primary_name} failed: {failure}",
            )
            self._moved[session_id] = moved
            if before_retry is not None:
                await before_retry()  # the move is a retry too: a paused lane waits here
        failed: ModelError | None = None
        try:
            reply = await self.fallback.chat(
                moved.model, messages, tools, session_id=session_id, max_tokens=max_tokens,
                temperature=temperature, before_retry=before_retry,
            )
        except ModelError as exc:
            failed = exc
        if failed is not None:
            raise _again(failed, f"{failed} (on {self.fallback_name}, where this context moved when {self.primary_name} failed)")
        if moved.notice:
            notice = moved.notice + (f"; {reply.notice}" if reply.notice else "")
            moved.notice = ""
            reply = replace(reply, notice=notice)
        return reply


def _again(error: ModelError, message: str) -> ModelError:
    """A new ModelError like `error` with `message`: raised outside any except block, it
    chains nothing (an SDK's exception may hold a request with the key in it)."""
    return ModelError(message, status=error.status, retryable=error.retryable, declined=error.declined, usage=error.usage)


def client_for(provider: str, base_url: str, key: str | None, *, fast: Sequence[str] = ()) -> ChatClient:
    """The client for one API: AnthropicClient for "anthropic" (calling the models in `fast`
    in fast mode), else ModelClient."""
    if provider == "anthropic":
        from .anthropic_client import AnthropicClient

        return AnthropicClient(base_url, key, fast=fast)
    if provider != "openai":
        raise ValueError(f"unknown API provider {provider!r}: openai or anthropic")
    if fast:
        raise ValueError("fast mode is a feature of the Anthropic Messages API, not of an OpenAI-compatible one")
    return ModelClient(base_url, key)


def build_client(config: Config, key: str | None, fallback_key: str | None) -> ChatClient:
    """The lanes' client for `config`: the [api] one, behind a FallbackClient when the config
    has a [fallback]. The keys are read by the caller (config.api_key(), fallback_key())."""
    spare = config.fallback
    # the fallback first: a client that is never used has opened no connection, so the one
    # left behind when the other raises (a key no header can carry) holds nothing open
    fallback = client_for(spare.provider, spare.base_url, fallback_key) if spare is not None else None
    primary = client_for(config.api.provider, config.api.base_url, key, fast=config.api.fast)
    if spare is None or fallback is None:
        return primary
    return FallbackClient(
        primary,
        fallback,
        dict(zip(config.models, spare.ladder)),
        primary_name=api_name(config.api.provider, config.api.base_url),
        fallback_name=api_name(spare.provider, spare.base_url),
    )


def api_name(provider: str, base_url: str) -> str:
    """How notices name an API: "Anthropic", "OpenRouter", "OpenAI", else its host."""
    host = (urlsplit(base_url).hostname or "").lower()
    if host == "api.anthropic.com" or (provider == "anthropic" and not host):
        return "Anthropic"
    if host == "openrouter.ai" or host.endswith(".openrouter.ai"):
        return "OpenRouter"
    if host == "api.openai.com":
        return "OpenAI"
    return host or "the model API"
