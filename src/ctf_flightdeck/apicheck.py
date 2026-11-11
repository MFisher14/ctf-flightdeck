"""Before a run: does the model API take the key, and does it serve the ladder's models?

A model id the API does not serve, a key it refuses, or a server that is not up ends every
lane at its first call, and the deck starts the next challenge, which ends the same way,
until the board is used up. So before the console starts, check() asks each API the run's
lanes use ([api], and [fallback] when the config has one) once, as the lanes will call it:

- an OpenAI-style API (OpenRouter, OpenAI, a server on this machine): GET {base_url}/models
  with the key. OpenRouter lists its models to anyone, so GET {base_url}/key checks the key;
- the Anthropic API: its Models API through the official SDK: the list, then by id each
  model the list does not name (that resolves an alias, and says whether it is retired).

What stops the run (CheckFailed, whose message says what to fix): the key refused (HTTP
401), nothing answering at the address, a ladder model the API's list does not have (with
the closest ids it does list), a model Anthropic has retired. What is a note, the run going
on unchecked: an API that does not list its models (404, 405), any other answer (403, 429,
5xx, something that is not a model list), or no answer in time. Nothing is retried and
nothing is spent: listing models costs nothing.

A name without a tag is the same model as its ":latest" (Ollama lists llama3 as
llama3:latest), and on OpenRouter a variant such as model:nitro is that model's.

Secrets: the key goes in a header and nowhere else, and the server's words have it cut out;
everything from the server is shown only as untrusted text, cut short. An httpx or SDK error
is described and dropped, never chained: its request holds the key.
"""

from __future__ import annotations

import difflib
import json
import re
import time
from collections.abc import Collection, Sequence
from dataclasses import dataclass
from http import HTTPStatus
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from .text import untrusted

LOCAL_HOSTS = ("127.0.0.1", "localhost", "::1")
TIMEOUT = 15.0  # seconds for one request, all of it (a model list is a few MB at most)
CONNECT_TIMEOUT = 5.0
MAX_LIST_BYTES = 32 * 1024 * 1024  # a model list bigger than this is not one
MAX_SHOWN = 160  # characters of the server's own words kept in a message
SHOWN_IDS = 8  # listed ids a message names when none is close
_KEY_CHARS = re.compile(r"[\x21-\x7e]+")  # what a key may hold: printable ASCII, no spaces (as the clients say)
_NOT_JSON = object()


@dataclass(frozen=True)
class Api:
    """One model API a run's lanes call: [api], or [fallback]."""

    table: str  # "api" or "fallback": the config table it comes from
    provider: str  # "openai" | "anthropic"
    base_url: str
    key: str | None  # None: the config names no key variable
    key_env: str  # the variable the key came from ("" for none)
    ladder: tuple[str, ...]  # the model ids its lanes may use


class CheckFailed(Exception):
    """The API cannot serve this run. The message says why and what to fix; never the key."""


def check(api: Api, *, source: Path | None = None, timeout: float = TIMEOUT, key_check: str | None = None) -> list[str]:
    """Ask the API whether it takes the key and serves the ladder. Returns notes for the
    player (the run goes on); raises CheckFailed when the run cannot work. `source` is the
    config file, which the messages name. `key_check` is where an OpenAI-style API says
    whether it takes the key when its model list is public (default: key_url())."""
    if api.key is not None and not _KEY_CHARS.fullmatch(api.key):
        raise CheckFailed(
            f"the key in {api.key_env} is empty or holds characters an HTTP header cannot carry (spaces, line breaks, "
            "non-ASCII): check that variable"
        )
    ask = _Asker(api, source, timeout)
    if api.provider == "anthropic":
        return ask.anthropic()
    return ask.openai(key_check or key_url(api.base_url))


def key_url(base_url: str) -> str | None:
    """Where an OpenAI-style API says whether it takes a key, when its model list does not:
    OpenRouter's GET {base_url}/key (anyone may list its models). None for other APIs, whose
    model list wants the key."""
    host = (urlsplit(base_url).hostname or "").lower()
    if _openrouter(host):
        return base_url.rstrip("/") + "/key"
    return None


def _openrouter(host: str) -> bool:
    return host == "openrouter.ai" or host.endswith(".openrouter.ai")


# ---------------------------------------------------------------------- comparing a ladder with a list


def listed_models(body: object) -> list[str] | None:
    """The model ids in an OpenAI-style model list ({"data": [{"id": ...}, ...]}), or None when
    `body` is not one."""
    data = body.get("data") if isinstance(body, dict) else None
    if not isinstance(data, list):
        return None
    ids = [item.get("id") for item in data if isinstance(item, dict)]
    if len(ids) != len(data) or not all(isinstance(i, str) and i for i in ids):
        return None
    return ids


def missing(ladder: Sequence[str], listed: Collection[str], *, openrouter: bool = False) -> list[str]:
    """The ladder's models the list does not have."""
    have = set(listed)

    def served(model: str) -> bool:
        if model in have or f"{model}:latest" in have:
            return True
        if openrouter:  # a variant (:nitro, :floor, :online, ...) is its model's; a preset is the account's own
            base, sep, _ = model.rpartition(":")
            return model.startswith("@") or bool(sep and base in have)
        return False

    return [model for model in ladder if not served(model)]


def not_listed(models: Sequence[str], listed: Sequence[str]) -> str:
    """'qwen2.5-coder-7b (closest it lists: qwen2.5-coder:7b)', for each model, ';'-joined."""
    parts = []
    for model in models:
        close = difflib.get_close_matches(model, listed, n=3, cutoff=0.5)
        if close:
            hint = "closest it lists: " + ", ".join(_one(name) for name in close)
        elif not listed:
            hint = "it lists no models"
        elif len(listed) <= SHOWN_IDS:
            hint = "it lists " + ", ".join(_one(name) for name in listed)
        else:
            hint = f"none close among the {len(listed)} it lists"
        parts.append(f"{_one(model)} ({hint})")
    return "; ".join(parts)


# ---------------------------------------------------------------------- asking


class _Asker:
    def __init__(self, api: Api, source: Path | None, timeout: float) -> None:
        self.api = api
        self.timeout = timeout
        self.where = _shown(api.base_url)
        self.host = (urlsplit(api.base_url).hostname or "").lower()
        self.local = self.host in LOCAL_HOSTS
        self.who = "the model API" if api.table == "api" else "the [fallback] API"
        self.config = f" in {source}" if source is not None else ""

    # ------------------------------------------------------------------ OpenAI-style

    def openai(self, key_check: str | None) -> list[str]:
        headers = {"Authorization": f"Bearer {self.api.key}"} if self.api.key else {}
        limit = httpx.Timeout(self.timeout, connect=min(self.timeout, CONNECT_TIMEOUT))
        notes: list[str] = []
        with httpx.Client(headers=headers, timeout=limit, follow_redirects=False) as http:
            status, body = self._get(http, self.api.base_url.rstrip("/") + "/models")
            if status is None:
                return [self._no_answer_in_time()]
            if status == 401:
                raise self._refused(status, self._said(body))
            listed = listed_models(_json(body)) if 200 <= status < 300 else None
            if listed is None:
                notes.append(self._unchecked(status, self._said(body)))
            else:
                gone = missing(self.api.ladder, listed, openrouter=_openrouter(self.host))
                if gone:
                    raise self._not_served(gone, listed)
            if key_check is not None and self.api.key:  # anyone may list its models: does it take the key?
                notes += self._key_check(http, key_check)
        return notes

    def _key_check(self, http: httpx.Client, url: str) -> list[str]:
        status, body = self._get(http, url)
        if status == 401:
            raise self._refused(status, self._said(body))
        if status is not None and 200 <= status < 300:
            return []
        how = f"gave no complete answer within {self.timeout:g} s" if status is None else f"answered HTTP {status}{_phrase(status)}"
        return [f"could not check the key in {self.api.key_env} with {self.who} at {self.where}: GET /key {how}"]

    def _get(self, http: httpx.Client, url: str) -> tuple[int | None, bytes]:
        """One GET: (status, body), or (None, b"") when no complete answer came in time.
        CheckFailed when nothing answers at all."""
        deadline = time.monotonic() + self.timeout
        what = ""
        try:
            with http.stream("GET", url) as response:
                chunks, size = [], 0
                for chunk in response.iter_bytes():
                    size += len(chunk)
                    if size > MAX_LIST_BYTES:
                        break
                    chunks.append(chunk)
                    if time.monotonic() > deadline:
                        return None, b""
                return response.status_code, b"".join(chunks)
        except httpx.TimeoutException:
            return None, b""
        except httpx.HTTPError as exc:  # described and dropped: its request holds the key
            what = type(exc).__name__ + (f": {self._short(str(exc))}" if str(exc) else "")
        raise self._nothing_answers(what)

    # ------------------------------------------------------------------ Anthropic

    def anthropic(self) -> list[str]:
        import anthropic

        limit = anthropic.Timeout(self.timeout, connect=min(self.timeout, CONNECT_TIMEOUT))
        client = anthropic.Anthropic(
            api_key=self.api.key,  # explicit: the SDK then reads no credential from the environment
            base_url=self.api.base_url,  # explicit: ANTHROPIC_BASE_URL is never read
            max_retries=0,
            timeout=limit,
            http_client=anthropic.DefaultHttpxClient(timeout=limit, follow_redirects=False),
            open_telemetry=False,
        )
        try:
            return self._anthropic(client)
        finally:
            client.close()

    def _anthropic(self, client) -> list[str]:
        import anthropic

        listed: dict[str, object] = {}
        failure = None
        try:
            for info in client.models.list(limit=1000):
                listed[info.id] = info
        except anthropic.AnthropicError as exc:
            failure = self._sdk_failure(exc)
        if failure is not None:
            if isinstance(failure, CheckFailed):
                raise failure
            return [failure]
        notes: list[str] = []
        gone: list[str] = []
        retired: list[str] = []
        for model in self.api.ladder:
            info = listed.get(model)
            if info is None:  # not in the list: an alias, or a model it does not serve
                failure = None
                try:
                    info = client.models.retrieve(model)
                except anthropic.NotFoundError:
                    gone.append(model)
                    continue
                except anthropic.AnthropicError as exc:
                    failure = self._sdk_failure(exc)
                if failure is not None:
                    if isinstance(failure, CheckFailed):
                        raise failure
                    notes.append(failure)
                    continue
            lifecycle = getattr(info, "lifecycle", None)
            if lifecycle == "retired":
                retired.append(model)
            elif lifecycle == "deprecated":
                when = getattr(info, "retires_at", None)
                notes.append(
                    f"{_one(model)} is deprecated on the Anthropic API"
                    + (f" and retires on {when:%Y-%m-%d}" if when is not None else "")
                    + f": move {self._ladder()} to a newer model before then"
                )
        if gone:
            raise self._not_served(gone, list(listed))
        if retired:
            raise CheckFailed(
                f"{', '.join(_one(m) for m in retired)} {'is' if len(retired) == 1 else 'are'} retired on the Anthropic API, "
                f"so every lane on {'it' if len(retired) == 1 else 'them'} would fail at its first call: change "
                f"{self._ladder()}{self.config}, then start play again"
            )
        return notes

    def _sdk_failure(self, exc: Exception) -> CheckFailed | str:
        """An SDK error as the run's: CheckFailed, or a note (the run goes on)."""
        import anthropic

        if isinstance(exc, anthropic.APIStatusError):
            said = self._message(exc.body)
            if exc.status_code == 401:
                return self._refused(401, said)
            return self._unchecked(exc.status_code, said)
        if isinstance(exc, anthropic.APITimeoutError):
            return self._no_answer_in_time()
        if isinstance(exc, anthropic.APIConnectionError):
            cause = exc.__cause__
            what = type(cause).__name__ if cause is not None else type(exc).__name__
            said = str(cause) if cause is not None else ""
            return self._nothing_answers(what + (f": {self._short(said)}" if said else ""))
        return f"could not check {self.who} at {self.where}: its answer could not be read ({type(exc).__name__})"

    # ------------------------------------------------------------------ what the player is told

    def _refused(self, status: int, said: str) -> CheckFailed:
        """The API refused the key (or wants one): `said` is its own words, or ""."""
        says = f": {said}" if said else ""
        if not self.api.key_env:
            return CheckFailed(
                f"{self.who} at {self.where} wants a key (HTTP {status}{says}): name the variable that holds it in "
                f"{self.api.table}.key_env{self.config}, then start play again"
            )
        from .keys import KeysError, keys_path

        try:
            where = str(keys_path())
        except KeysError:
            where = "your keys file"
        return CheckFailed(
            f"{self.who} at {self.where} refused the key in {self.api.key_env} (HTTP {status}{says}): put the right key "
            f"in {self.api.key_env} ({where}, or export it), then start play again"
        )

    def _not_served(self, models: Sequence[str], listed: Sequence[str]) -> CheckFailed:
        it = "it" if len(models) == 1 else "them"
        return CheckFailed(
            f"{self.who} at {self.where} does not serve {not_listed(models, listed)}, so every lane on {it} would fail at "
            f"its first call: change {self._ladder()}{self.config} to ids it serves"
            + (" (or pull the model into your server)" if self.local else "")
            + ", then start play again"
        )

    def _nothing_answers(self, what: str) -> CheckFailed:
        if self.local:
            return CheckFailed(
                f"nothing answers at {self.where} ({what}): start your local model server (it must speak the OpenAI API "
                f"with tool calling), or fix {self.api.table}.base_url{self.config}, then start play again"
            )
        return CheckFailed(
            f"no answer from {self.who} at {self.where} ({what}): check your network connection and "
            f"{self.api.table}.base_url{self.config}, then start play again"
        )

    def _unchecked(self, status: int, said: str) -> str:
        """A note: the API answered, but not with a model list. `said` is its own words, or ""."""
        if status in (404, 405):
            return (
                f"{self.who} at {self.where} does not list its models (GET /models answered HTTP {status}), so flightdeck "
                f"could not check {self._ladder()} against it: a model it does not serve ends each lane at its first call"
            )
        if 200 <= status < 300:
            return f"could not check {self.who} at {self.where}: GET /models answered with something that is not a model list"
        return (
            f"could not check {self.who} at {self.where}: GET /models answered HTTP {status}{_phrase(status)}"
            + (f" ({said})" if said else "")
            + "; the run goes on, unchecked"
        )

    def _no_answer_in_time(self) -> str:
        return f"could not check {self.who} at {self.where}: no complete answer within {self.timeout:g} s; the run goes on, unchecked"

    def _ladder(self) -> str:
        return "models.ladder" if self.api.table == "api" else "fallback.ladder"

    def _said(self, body: bytes) -> str:
        """The server's message in an error body it sent, safe to show, or ""."""
        return self._message(_json(body))

    def _message(self, doc: object) -> str:
        """The message of an OpenAI- or Anthropic-style error ({"error": {"message": ...}}),
        safe to show, or ""."""
        error = doc.get("error") if isinstance(doc, dict) else None
        message = error.get("message") if isinstance(error, dict) else error
        return self._short(message) if isinstance(message, str) and message.strip() else ""

    def _short(self, text: str) -> str:
        """The server's words, safe to show: no key, one line, cut short."""
        if self.api.key:
            text = text.replace(self.api.key, "[key]")
        text = untrusted(text[: MAX_SHOWN * 4], one_line=True).strip()
        return text if len(text) <= MAX_SHOWN else text[: MAX_SHOWN - 3] + "..."


def _json(body: bytes) -> object:
    try:
        return json.loads(body)
    except (ValueError, RecursionError):
        return _NOT_JSON


def _one(text: str) -> str:
    """A model id, safe to show on one line, cut short."""
    shown = untrusted(text, one_line=True)
    return shown if len(shown) <= 80 else shown[:77] + "..."


def _shown(url: str) -> str:
    """The URL without user info, query or fragment, safe to print."""
    try:
        return untrusted(str(httpx.URL(url).copy_with(userinfo=b"", query=None, fragment=None)), one_line=True)
    except (httpx.InvalidURL, ValueError, TypeError):
        return "(the configured base_url)"


def _phrase(code: int | None) -> str:
    try:
        return f" ({HTTPStatus(code).phrase})" if code is not None else ""
    except ValueError:
        return ""
