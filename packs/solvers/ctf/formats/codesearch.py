"""Public code search for an unknown format's magic strings (B-207), off by default.

The format_fingerprint step (ctf.formats.fingerprint) runs this ONLY when the offline lookup named
nothing and the event's policy opens it. In the style of solvers/toolkits/osint_online.py it is not a
general HTTP client: it accepts only short magic strings, builds requests for a tiny allow-list of
public code-search hosts, validates every redirect, sleeps between requests and stops at hard caps.

Three gates, so it cannot run by accident:
  1. A client is OFF unless constructed with ``enabled=True``.
  2. Every request is validated by ``ctf.scope.check_public_fetch`` against the event profile's
     ``rules.public_fetch_allow``; an event that does not list the host is refused.
  3. Only a short magic string is ever sent -- bounded length, printable, one line, no secret shape and
     no path separators. File content can never leave the host.

Rows are UNSURE leads for a human: a repository that contains the magic string, never a verdict that
the member is that project's format. Tests inject ``transport``, ``clock`` and ``sleep`` and so never
touch the network.
"""
from __future__ import annotations

import dataclasses
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from typing import Any

from .. import scope

__all__ = ["CodeSearchError", "CodeSearchDisabled", "HTTPResult", "Lead", "PublicCodeSearchClient"]

MAX_RESPONSE_BYTES = 1 * 1024 * 1024
MAX_REQUESTS = 6
MIN_INTERVAL_SECONDS = 2.0
TIMEOUT_SECONDS = 12.0
MAGIC_MAX_CHARS = 48
RESULTS_PER_MAGIC = 5
GENERIC_USER_AGENT = "Public-Format-Fingerprint-Client/1.0 (magic-string lookup; contact: none)"

# The only hosts a request may be built for. The event profile must ALSO list the host in
# rules.public_fetch_allow (scope.check_public_fetch); this is the client's own narrower allow-list.
ALLOWED_HOSTS = frozenset({"api.github.com"})

# A magic string is a short, single-line, printable token. These shapes are never a magic string and
# never leave the host even if they reached the fingerprint's string table.
SECRET_RE = re.compile(
    r"(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{20,}|"
    r"(?:api[_-]?key|token|secret|password)\s*[:=]\s*\S+|"
    r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,})",
    re.I,
)


class CodeSearchError(ValueError):
    """A request was declined by a scope, input or rate guard."""


class CodeSearchDisabled(CodeSearchError):
    """The client is off: it was not constructed with enabled=True."""


@dataclasses.dataclass(frozen=True)
class HTTPResult:
    status: int
    headers: Mapping[str, str]
    body: bytes
    final_url: str


@dataclasses.dataclass(frozen=True)
class Lead:
    source: str            # the provider label, e.g. "GitHub code search"
    label: str             # the repository / tool the magic string was found in
    why: str               # how it was found (which magic string, which path)
    score: int
    tool: str | None = None
    ref: str | None = None  # a URL for the human to open


Transport = Callable[[str, Mapping[str, str], float, int], HTTPResult]


def _hostname(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.username or parsed.password or parsed.port not in (None, 443):
        raise CodeSearchError("code-search requests must use plain HTTPS on port 443")
    host = (parsed.hostname or "").rstrip(".").lower()
    if host not in ALLOWED_HOSTS:
        raise CodeSearchError(f"code-search host is not allow-listed: {host or '(none)'}")
    return host


class _GuardedRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        _hostname(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _urllib_transport(url: str, headers: Mapping[str, str], timeout: float,
                      max_bytes: int) -> HTTPResult:
    opener = urllib.request.build_opener(_GuardedRedirect())
    req = urllib.request.Request(url, headers=dict(headers), method="GET")
    try:
        with opener.open(req, timeout=timeout) as response:  # noqa: S310 -- host allow-listed above
            final_url = response.geturl()
            _hostname(final_url)
            advertised = response.headers.get("Content-Length")
            if advertised and int(advertised) > max_bytes:
                raise CodeSearchError("code-search response exceeds the byte cap")
            body = response.read(max_bytes + 1)
            if len(body) > max_bytes:
                raise CodeSearchError("code-search response exceeds the byte cap")
            return HTTPResult(int(response.status), dict(response.headers.items()), body, final_url)
    except urllib.error.HTTPError as exc:
        body = exc.read(max_bytes + 1)
        if len(body) > max_bytes:
            raise CodeSearchError("code-search error response exceeds the byte cap") from exc
        return HTTPResult(int(exc.code), dict(exc.headers.items()), body, exc.geturl())


class PublicCodeSearchClient:
    """Sequential, capped public code search for a member's magic strings. OFF unless enabled=True."""

    def __init__(self, *, enabled: bool = False, transport: Transport | None = None,
                 clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep,
                 min_interval: float = MIN_INTERVAL_SECONDS,
                 request_cap: int = MAX_REQUESTS) -> None:
        if min_interval < 1.0:
            raise ValueError("code-search interval cannot be less than one second")
        if not 1 <= request_cap <= MAX_REQUESTS:
            raise ValueError(f"request cap must be 1..{MAX_REQUESTS}")
        self.enabled = bool(enabled)
        self.transport = transport or _urllib_transport
        self.clock = clock
        self.sleep = sleep
        self.min_interval = float(min_interval)
        self.request_cap = int(request_cap)
        self._requests = 0
        self._last_request: float | None = None
        self.skipped: tuple = ()        # per-string input refusals from the last search(); see search()

    @property
    def request_count(self) -> int:
        return self._requests

    def _validate_magic(self, magic: str) -> str:
        if not isinstance(magic, str):
            raise CodeSearchError("a magic string must be text")
        text = magic.strip()
        if not text:
            raise CodeSearchError("empty magic string")
        if len(text) > MAGIC_MAX_CHARS:
            raise CodeSearchError(
                f"magic string is {len(text)} chars, over the {MAGIC_MAX_CHARS}-char cap: only a short "
                "magic string is ever sent, never file content")
        if "\n" in magic or "\r" in magic:
            raise CodeSearchError("magic string spans more than one line")
        if any(ord(c) < 0x20 or ord(c) == 0x7F for c in text):
            raise CodeSearchError("magic string has a control character; not a single printable token")
        if "/" in text or "\\" in text:
            raise CodeSearchError("magic string looks like a path, not a format signature")
        if SECRET_RE.search(text):
            raise CodeSearchError("secret-shaped value must never be sent to a public provider")
        return text

    def _request(self, url: str, profile) -> HTTPResult:
        if not self.enabled:
            raise CodeSearchDisabled(
                "public code search is off; construct the client with enabled=True and open the host "
                "in the event's rules.public_fetch_allow")
        _hostname(url)
        # Gate on the event policy: an event that does not list the host is refused here.
        scope.check_public_fetch(url, purpose="format fingerprint public code search",
                                 profile=profile, error=CodeSearchError)
        if self._requests >= self.request_cap:
            raise CodeSearchError("code-search request cap reached")
        now = self.clock()
        if self._last_request is not None:
            remaining = self.min_interval - (now - self._last_request)
            if remaining > 0:
                self.sleep(remaining)
                now = self.clock()
        headers = {"User-Agent": GENERIC_USER_AGENT, "Accept": "application/vnd.github+json",
                   "Cache-Control": "no-cache"}
        self._requests += 1
        self._last_request = now
        result = self.transport(url, headers, TIMEOUT_SECONDS, MAX_RESPONSE_BYTES)
        _hostname(result.final_url)
        if len(result.body) > MAX_RESPONSE_BYTES:
            raise CodeSearchError("transport returned an over-cap response")
        if not 200 <= int(result.status) < 300:
            raise CodeSearchError(f"code search returned HTTP status {result.status}")
        return result

    @staticmethod
    def _json(result: HTTPResult) -> Any:
        try:
            return json.loads(result.body.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
            raise CodeSearchError("code search returned malformed JSON") from exc

    def search_magic(self, magic: str, *, profile=None) -> list[Lead]:
        """Search one short magic string on GitHub code search; return ranked repository leads."""
        text = self._validate_magic(magic)
        query = urllib.parse.urlencode({"q": '"' + text + '"', "per_page": RESULTS_PER_MAGIC})
        url = "https://api.github.com/search/code?" + query
        result = self._request(url, profile)
        doc = self._json(result)
        rows: list[Lead] = []
        items = doc.get("items", []) if isinstance(doc, dict) else []
        for index, item in enumerate(items[:RESULTS_PER_MAGIC] if isinstance(items, list) else []):
            if not isinstance(item, dict):
                continue
            repo = item.get("repository", {}) if isinstance(item.get("repository"), dict) else {}
            full = str(repo.get("full_name") or repo.get("name") or "?")
            path = str(item.get("path") or "")
            href = str(item.get("html_url") or "")[:2048]
            rows.append(Lead("GitHub code search", full,
                             f"magic {text!r} occurs in {full}/{path}" if path else
                             f"magic {text!r} occurs in {full}",
                             score=40 - index, ref=href or None))
        return rows

    def search(self, magics, *, profile=None) -> list[Lead]:
        """Search a bounded set of magic strings, stopping at the request cap. Returns deduped, ranked
        leads. A per-string INPUT refusal (too long, secret-shaped, path-like, multi-line) skips just
        that magic -- one bad token never suppresses the leads from the others, and nothing was sent so
        nothing leaked. Each skip is recorded in ``self.skipped`` with its reason. A request-time error
        (scope refusal, non-2xx, malformed JSON) still propagates: it is not a per-string input problem."""
        out: list[Lead] = []
        seen = set()
        skipped: list[tuple] = []
        for magic in magics:
            if self._requests >= self.request_cap:
                break
            try:
                self._validate_magic(magic)                 # precedes any request: no bytes have left yet
            except CodeSearchError as exc:
                skipped.append((magic, str(exc)))
                continue
            for lead in self.search_magic(magic, profile=profile):
                key = (lead.label, lead.ref)
                if key not in seen:
                    seen.add(key)
                    out.append(lead)
        self.skipped = tuple(skipped)
        out.sort(key=lambda r: (-r.score, r.label))
        return out
