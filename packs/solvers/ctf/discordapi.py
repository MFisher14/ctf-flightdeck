"""Discord recon, the online half (B-112): a read-only bot client and the capture that fills a snapshot.

    from ctf import discordapi
    client = discordapi.from_profile(profile)            # DiscordRefused before any request
    res = discordapi.capture(client, guild_id, first=50, recent=0)
    res.guild; res.items; res.notes; res.requests; res.partial

What it is allowed to do, and what refuses it (`DiscordRefused`, raised before any connection):

- The event profile must record the player's clearance: `[discord] capture = "bot"`. The default is
  "forbidden". Whether the event's rules and Discord's terms allow a capture tool is the player's call.
- The API host must be listed in the profile's `rules.public_fetch_allow` (ctf.scope
  .check_public_fetch): the same rule as every other fetch from a public host. The event platform is
  refused even when listed.
- The token is read from the environment variable NAMED by `[discord] token_env` (default
  CTF_DISCORD_TOKEN), through ctf.env. It is sent only as the `Authorization: Bot ...` header of a
  request to the configured API base, and appears nowhere else: not in an error, a repr, the snapshot,
  the ledger or a log. A redirect is refused, so the header never reaches another host; plain http is
  refused except to loopback (the test fakes).
- It runs as a BOT application only. Automating a user account (a "self-bot") is against Discord's
  terms: a token whose `/users/@me` is not a bot is refused, and no user-account endpoint is called.
  This module never reads the local Discord app's data and never harvests a token from anywhere.
- GET only. It joins nothing, clicks nothing, posts nothing: getting the bot into the server and the
  onboarding clicks are human steps.

Pacing: at least `min_interval` between requests, a 429 waits out `Retry-After` (up to `max_wait`, at
most `max_retries` times), and a request budget (`max_requests`) ends the capture with a named note
rather than running on. A place the bot may not read (403/404) is a note in the snapshot, never a
silent gap.

The endpoints are Discord's documented v10 REST routes, plus `/applications/{id}/rpc` for a bot's
public description (its About Me). They are exercised here only against a loopback fake
(tests/discord_fake.py); build work never contacts Discord.
"""
from __future__ import annotations

import ipaddress
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

from . import env, scope
from .discordrecon import Item, message_text
from .event import EventProfile

USER_AGENT = "DiscordBot (recon-client, 1.0)"
MAX_BODY = 8 * 1024 * 1024
PAGE = 100                                  # Discord's per-request message limit
TEXT_CHANNEL_TYPES = (0, 5)                 # text, announcement
THREAD_TYPES = (10, 11, 12)
CATEGORY_TYPE = 4
FORUM_TYPES = (15, 16)
NOT_READABLE = (403, 404)


class DiscordError(RuntimeError):
    """A failed or unusable API exchange. The message never holds the token."""


class DiscordRefused(DiscordError):
    """Refused before any request: no clearance, out of scope, no token, not a bot."""


class HttpError(DiscordError):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


class BudgetSpent(DiscordError):
    """The capture's request budget is used up."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):   # noqa: D401 - urllib hook
        return None                         # urllib then raises the 3xx as an HTTPError


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class Client:
    """A GET-only client for one API base. `sleep` and `clock` are injectable (tests drive time)."""

    def __init__(self, api_base: str, token: str, *, timeout: float = 20.0, max_requests: int = 400,
                 min_interval: float = 0.25, max_retries: int = 3, max_wait: float = 30.0,
                 sleep: Callable[[float], None] = time.sleep,
                 clock: Callable[[], float] = time.monotonic):
        parts = urllib.parse.urlsplit(str(api_base))
        host = (parts.hostname or "").lower()
        if parts.scheme not in ("http", "https") or not host:
            raise DiscordRefused(f"Discord API base {api_base!r} is not an http(s) URL with a host")
        if parts.username or parts.password:
            raise DiscordRefused("the Discord API base must not carry credentials")
        if parts.scheme == "http" and not _is_loopback(host):
            raise DiscordRefused(f"Discord API base {api_base!r} is plain http to a non-loopback host: "
                                 "a token is never sent unencrypted")
        if not isinstance(token, str) or not token.strip():
            raise DiscordRefused("no Discord bot token was given")
        if any(not ("!" <= ch <= "~") for ch in token.strip()):
            # A pasted token with a newline or other stray character would make http.client raise an
            # error that quotes the header (escaped, so the scrub would miss it). Refuse it up front and
            # never repeat it.
            raise DiscordRefused("the Discord bot token holds a character outside printable ASCII (a space, "
                                 "a line break or a control character): set the variable again without it")
        if max_requests < 1 or max_retries < 0 or min_interval < 0 or max_wait < 0:
            raise ValueError("max_requests >= 1, max_retries >= 0, min_interval >= 0, max_wait >= 0")
        self.api_base = str(api_base).rstrip("/")
        self._token = token.strip()
        self.timeout, self.max_requests, self.min_interval = timeout, max_requests, min_interval
        self.max_retries, self.max_wait = max_retries, max_wait
        self._sleep, self._clock = sleep, clock
        self._last: float | None = None
        self.requests = 0
        # No proxy from the environment and no redirects: the Authorization header goes to the
        # configured host and nowhere else.
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())

    def __repr__(self) -> str:
        return f"Client(api_base={self.api_base!r}, requests={self.requests})"

    def _scrub(self, text: str) -> str:
        return str(text).replace(self._token, "<redacted>")

    def _pace(self) -> None:
        if self._last is not None:
            wait = self.min_interval - (self._clock() - self._last)
            if wait > 0:
                self._sleep(wait)

    def get(self, path: str, query: Mapping[str, Any] | None = None) -> Any:
        """The decoded JSON of GET <api_base><path>. HttpError carries the status; a 429 is waited out."""
        if not path.startswith("/") or "://" in path or ".." in path:
            raise DiscordError(f"bad API path {path!r}")
        url = self.api_base + path + ("?" + urllib.parse.urlencode(query) if query else "")
        for attempt in range(self.max_retries + 1):
            if self.requests >= self.max_requests:
                raise BudgetSpent(f"the request budget ({self.max_requests}) is spent")
            self._pace()
            req = urllib.request.Request(url, method="GET", headers={
                "Authorization": "Bot " + self._token, "User-Agent": USER_AGENT,
                "Accept": "application/json"})
            self.requests += 1
            try:
                with self._opener.open(req, timeout=self.timeout) as resp:
                    self._last = self._clock()
                    body = resp.read(MAX_BODY + 1)
                    status = resp.status
                    headers = resp.headers
            except urllib.error.HTTPError as e:
                self._last = self._clock()
                status, headers = e.code, e.headers
                try:
                    body = e.read(MAX_BODY + 1)
                except OSError:
                    body = b""
            except ValueError:
                # http.client's ValueError quotes the request line or a header (the token among them):
                # its text is never passed on.
                self._last = self._clock()
                raise DiscordError(f"GET {path}: the request could not be sent (a malformed URL or header)") \
                    from None
            except (urllib.error.URLError, OSError) as e:
                self._last = self._clock()
                reason = getattr(e, "reason", e)
                raise DiscordError(self._scrub(f"GET {path}: no answer ({reason})")) from None
            if len(body) > MAX_BODY:
                raise DiscordError(f"GET {path}: the answer is over {MAX_BODY} bytes")
            if 300 <= status < 400:
                raise HttpError(status, f"GET {path}: HTTP {status} redirect refused (the Authorization "
                                        "header is never sent to another location)")
            doc = None
            if body:
                try:
                    doc = json.loads(body.decode("utf-8", "replace"))
                except json.JSONDecodeError:
                    doc = None
            if status == 429:
                wait = self._retry_after(headers, doc)
                if attempt >= self.max_retries:
                    raise HttpError(429, f"GET {path}: still rate limited after {self.max_retries} "
                                         "retries")
                if wait > self.max_wait:
                    raise HttpError(429, f"GET {path}: rate limited for {wait:.0f} s, over the "
                                         f"{self.max_wait:.0f} s this client waits")
                self._sleep(wait)
                continue
            if status >= 400:
                msg = doc.get("message") if isinstance(doc, dict) else None
                detail = f": {self._scrub(str(msg))[:200]}" if msg else ""
                if status == 401:
                    detail = ": the bot token was rejected (check the variable the profile names)"
                raise HttpError(status, f"GET {path}: HTTP {status}{detail}")
            if doc is None:
                raise DiscordError(f"GET {path}: HTTP {status} with a body that is not JSON")
            return doc
        raise DiscordError(f"GET {path}: gave up")          # not reached: the loop returns or raises

    @staticmethod
    def _retry_after(headers, doc) -> float:
        raw = headers.get("Retry-After") if headers is not None else None
        if raw is None and isinstance(doc, dict):
            raw = doc.get("retry_after")
        try:
            return max(0.0, float(raw))
        except (TypeError, ValueError):
            return 1.0


def from_profile(profile: EventProfile, *, environ: Mapping[str, str] | None = None, **kw) -> Client:
    """The client the event profile allows, or DiscordRefused naming the reason. Checks, in order:
    the recorded clearance, the public-fetch scope, the token variable. Opens no connection."""
    d = profile.discord
    if d.capture != "bot":
        raise DiscordRefused(
            f"event {profile.slug!r}: [discord] capture = {d.capture!r}, so the API client is off. Paste or "
            "export what you can read (`python -m ctf discord checklist`). Set capture = \"bot\" in "
            f"events/{profile.slug}/event.toml only after checking that the event's rules and Discord's "
            "terms allow your bot and an organizer has admitted it to the server")
    try:
        scope.check_public_fetch(d.api_base, purpose="Discord recon capture", profile=profile)
    except scope.OutOfScope as e:
        raise DiscordRefused(str(e)) from None
    token = env.get(d.token_env, environ=environ)
    if token is None:
        raise DiscordRefused(f"${d.token_env} is not set: export the bot token in that variable (the "
                             "profile names the variable, never the token)")
    return Client(d.api_base, token, **kw)


# ------------------------------------------------------------------------------------------ capture

@dataclass
class CaptureResult:
    guild: dict = field(default_factory=dict)
    items: list[Item] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    requests: int = 0
    partial: bool = False            # a step failed or the request budget ran out


def _int(v) -> int:
    """An integer field of an API answer; anything else counts as 0 (the data is not ours)."""
    try:
        return int(v or 0)
    except (TypeError, ValueError):
        return 0


def _s(v) -> str:
    return v.strip() if isinstance(v, str) else ""


def _sid(v) -> str | None:
    """A Discord id as it may go into a request path: digits only (an id is data from the server)."""
    v = str(v) if isinstance(v, (str, int)) and not isinstance(v, bool) else ""
    return v if v.isdigit() else None


def _by_id(objs) -> list[dict]:
    def key(o):
        try:
            return int(o.get("id", 0))
        except (TypeError, ValueError):
            return 0
    return sorted((o for o in objs if isinstance(o, dict)), key=key)


def _author(msg: dict) -> str:
    a = msg.get("author") if isinstance(msg.get("author"), dict) else {}
    return _s(a.get("global_name")) or _s(a.get("username"))


def capture(client: Client, guild_id: str, *, first: int = 50, recent: int = 0, bots: int = 25,
            max_channels: int = 200) -> CaptureResult:
    """Read one server, GET only: its description, roles, expressions, channels (hidden ones included:
    the channel list is not filtered by what the bot can open) with topics and forum tags, active
    threads, scheduled events, soundboard, onboarding and welcome screen, the bots and their public
    descriptions, and per readable text channel its pins, its first `first` messages (the channel
    start) and its newest `recent`. The identity, the server and the channel list must succeed
    (DiscordError otherwise); every other step that fails is a note and `partial`."""
    gid = str(guild_id or "").strip()
    if not gid.isdigit():
        raise DiscordError(f"the guild id {guild_id!r} is not numeric: give the server's id (profile "
                           "[discord] guild_id, or --guild)")
    if first < 0 or recent < 0 or bots < 0 or max_channels < 0:
        raise ValueError("first, recent, bots and max_channels are >= 0")
    res = CaptureResult()
    out = res.items
    spent = False

    def step(label: str, path: str, query=None):
        """An optional read: the JSON, or None with a note."""
        nonlocal spent
        if spent:
            return None
        try:
            return client.get(path, query)
        except BudgetSpent as e:
            spent = res.partial = True
            res.notes.append(f"stopped at {label}: {e}; what follows was not read")
        except HttpError as e:
            if e.status in NOT_READABLE:
                res.notes.append(f"{label}: not readable by the bot (HTTP {e.status})")
            else:
                res.partial = True
                res.notes.append(f"{label}: failed ({e})")
        except DiscordError as e:
            res.partial = True
            res.notes.append(f"{label}: failed ({e})")
        return None

    try:
        me = client.get("/users/@me")
        if not (isinstance(me, dict) and me.get("bot") is True):
            raise DiscordRefused("the token is not a bot application's: automating a user account is "
                                 "against Discord's terms and this client does not do it")
        try:
            guild = client.get(f"/guilds/{gid}")
        except HttpError as e:
            if e.status in NOT_READABLE:
                raise DiscordError(f"the bot cannot read server {gid} (HTTP {e.status}): it is not a member. "
                                   "Getting it admitted is a human step") from None
            raise
        channels = client.get(f"/guilds/{gid}/channels")
    finally:
        res.requests = client.requests
    if not isinstance(guild, dict) or not isinstance(channels, list):
        raise DiscordError("the server or its channel list did not come back in the documented shape")

    res.guild = {"id": gid, **({"name": _s(guild.get("name"))} if _s(guild.get("name")) else {})}
    if _s(guild.get("name")):
        out.append(Item("guild-name", "server", _s(guild["name"]), source="api"))
    if _s(guild.get("description")):
        out.append(Item("guild-description", "server", _s(guild["description"]), source="api"))
    _welcome(out, guild.get("welcome_screen"))
    for n, r in enumerate(sorted((r for r in guild.get("roles") or [] if isinstance(r, dict)),
                                 key=lambda r: -_int(r.get("position"))), 1):
        if _s(r.get("name")) and _s(r.get("name")) != "@everyone":
            out.append(Item("role", "roles", _s(r["name"]), seq=n, source="api"))
    for n, e in enumerate(_by_id(guild.get("emojis") or []), 1):
        if _s(e.get("name")):
            out.append(Item("emoji", "emoji", _s(e["name"]), seq=n, source="api"))
    for n, s in enumerate(_by_id(guild.get("stickers") or []), 1):
        if _s(s.get("name")):
            out.append(Item("sticker", "stickers", _s(s["name"]), seq=n, source="api"))
        extra = " ".join(x for x in (_s(s.get("description")), _s(s.get("tags"))) if x)
        if extra:
            out.append(Item("other", f"sticker {_s(s.get('name')) or s.get('id')}", extra, source="api"))

    rules_id = str(guild.get("rules_channel_id") or "")
    chans = sorted((c for c in channels if isinstance(c, dict)),
                   key=lambda c: (_int(c.get("position")), str(c.get("id"))))
    names = {str(c.get("id")): _s(c.get("name")) for c in chans}
    readable: list[tuple[str, str]] = []                       # (channel id, where)
    for n, c in enumerate(chans, 1):
        name, ctype = _s(c.get("name")), c.get("type")
        if not name:
            continue
        if ctype == CATEGORY_TYPE:
            out.append(Item("category-name", "category " + name, name, seq=n, source="api"))
            continue
        where = "#" + name
        out.append(Item("channel-name", where, name, seq=n, source="api"))
        if _s(c.get("topic")):
            out.append(Item("channel-topic", where, _s(c["topic"]), source="api"))
        if ctype in FORUM_TYPES:
            for k, t in enumerate((t for t in c.get("available_tags") or [] if isinstance(t, dict)), 1):
                if _s(t.get("name")):
                    out.append(Item("forum-tag", where, _s(t["name"]), seq=k, source="api"))
        if ctype in TEXT_CHANNEL_TYPES and _sid(c.get("id")):
            readable.append((_sid(c.get("id")), where))

    doc = step("active threads", f"/guilds/{gid}/threads/active")
    for n, t in enumerate(_by_id((doc or {}).get("threads") or []) if isinstance(doc, dict) else [], 1):
        if not _s(t.get("name")):
            continue
        parent = names.get(str(t.get("parent_id")), "")
        where = f"thread {_s(t['name'])}" + (f" (in #{parent})" if parent else "")
        out.append(Item("thread-name", where, _s(t["name"]), seq=n, source="api"))
        if t.get("type") in THREAD_TYPES and _sid(t.get("id")):
            readable.append((_sid(t.get("id")), where))

    doc = step("scheduled events", f"/guilds/{gid}/scheduled-events")
    for e in _by_id(doc if isinstance(doc, list) else []):
        meta = e.get("entity_metadata") if isinstance(e.get("entity_metadata"), dict) else {}
        text = "\n".join(x for x in (_s(e.get("name")), _s(e.get("description")), _s(meta.get("location"))) if x)
        if text:
            out.append(Item("event", f"event {_s(e.get('name')) or e.get('id')}", text, source="api"))

    doc = step("soundboard", f"/guilds/{gid}/soundboard-sounds")
    sounds = doc.get("items") if isinstance(doc, dict) else doc
    for n, s in enumerate(_by_id(sounds if isinstance(sounds, list) else []), 1):
        if _s(s.get("name")):
            out.append(Item("soundboard", "soundboard", _s(s["name"]), seq=n, source="api"))

    doc = step("onboarding", f"/guilds/{gid}/onboarding")
    for p in (doc.get("prompts") or []) if isinstance(doc, dict) else []:
        if not isinstance(p, dict):
            continue
        lines = [_s(p.get("title"))]
        for o in p.get("options") or []:
            if isinstance(o, dict):
                lines.append(" ".join(x for x in (_s(o.get("title")), _s(o.get("description"))) if x))
        text = "\n".join(x for x in lines if x)
        if text:
            out.append(Item("onboarding", "onboarding", text, source="api"))

    if not isinstance(guild.get("welcome_screen"), dict):
        _welcome(out, step("welcome screen", f"/guilds/{gid}/welcome-screen"))

    if bots:
        doc = step("member list (needs the server-members intent)", f"/guilds/{gid}/members", {"limit": 1000})
        seen_bots = 0
        for m in doc if isinstance(doc, list) else []:
            u = m.get("user") if isinstance(m, dict) and isinstance(m.get("user"), dict) else None
            if not u or u.get("bot") is not True or seen_bots >= bots:
                continue                        # people are not listed: only the server's bots
            seen_bots += 1
            name = _s(m.get("nick")) or _s(u.get("global_name")) or _s(u.get("username")) or str(u.get("id"))
            where = "bot " + name
            out.append(Item("bot-name", where, name, seq=seen_bots, source="api"))
            app = (step(f"{where}: public description", f"/applications/{_sid(u.get('id'))}/rpc")
                   if _sid(u.get("id")) else None)
            if isinstance(app, dict):
                about = "\n".join(x for x in (_s(app.get("description")), _s(app.get("summary"))) if x)
                if about:
                    out.append(Item("bot-about", where, about, source="api"))
    res.notes.append("member profiles (About Me, custom status, banner) cannot be read by a bot: "
                     "paste the challenge author's and the organizers' by hand")

    if len(readable) > max_channels:
        res.partial = True
        res.notes.append(f"{len(readable) - max_channels} channel(s) past the first {max_channels} were "
                         "not read for messages")
    for cid, where in readable[:max_channels]:
        kind = "rules" if cid == rules_id else "message"
        pins = step(f"{where}: pins", f"/channels/{cid}/pins")
        for n, m in enumerate(_by_id(pins if isinstance(pins, list) else []), 1):
            text = message_text(m)
            if text:
                out.append(Item("pin", where, text, author=_author(m), seq=n, source="api"))
        seen: set[str] = set()
        if first:
            msgs = step(f"{where}: first messages", f"/channels/{cid}/messages",
                        {"after": 0, "limit": min(first, PAGE)})
            for n, m in enumerate(_by_id(msgs if isinstance(msgs, list) else []), 1):
                seen.add(str(m.get("id")))
                text = message_text(m)
                if text:
                    out.append(Item(kind, where, text, author=_author(m), seq=n, source="api"))
        if recent:
            msgs = step(f"{where}: recent messages", f"/channels/{cid}/messages", {"limit": min(recent, PAGE)})
            for n, m in enumerate(_by_id(msgs if isinstance(msgs, list) else []), 1):
                text = message_text(m)
                if text and str(m.get("id")) not in seen:
                    out.append(Item(kind, where, text, author=_author(m), seq=1_000_000 + n, source="api"))
    res.requests = client.requests
    return res


def _welcome(out: list, ws) -> None:
    if not isinstance(ws, dict):
        return
    lines = [_s(ws.get("description"))]
    for c in ws.get("welcome_channels") or []:
        if isinstance(c, dict):
            lines.append(_s(c.get("description")))
    text = "\n".join(x for x in lines if x)
    if text:
        out.append(Item("welcome", "welcome screen", text, source="api"))
