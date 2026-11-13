#!/usr/bin/env python3
"""Social-media post helper: post-ID decode, oEmbed and public-embed lookups, and a bounded news-article
scrape for post IDs, with an early human-only flag that stops the loop (B-206).

PINK+ "Absolute Craziness" needed one look at an Instagram post the agent had already named, and spooky
"Visiobibliophobia" was never solved: the platforms were blocked by the network and anti-bot controls,
and the player would not hand his browser to an agent. This module does the parts a script can do
without crossing any of those lines, and stops early, writing a handoff, for the rest.

Offline (no network at all):

    parse_post_ref(url)     -> PostRef: platform, post id, canonical URL, and the post time when the id
                               carries one (X/Twitter, Mastodon and LinkedIn snowflakes, TikTok ids,
                               Bluesky TIDs; Instagram shortcodes as an approximate estimate)
    scan_article(html)      -> ArticleScan: title, published time, canonical URL and every social post
                               the page links or embeds (a/iframe/blockquote/AMP tags, JSON-LD, bare URLs)
    plan(url)               -> FetchPlan: which public endpoint a fetch would use, or why the platform is
                               human-only (no credential-free endpoint: Facebook, Threads, LinkedIn,
                               Instagram stories)

Online (SocialFetchClient, off unless the caller builds one; tests inject the transport):

    fetch_post(url)         one oEmbed (YouTube, Vimeo, X, TikTok, Reddit, Bluesky, mastodon.social) or
                            public embed page (Instagram) request for a recognised post
    scrape_article(url)     one news-article fetch, scanned for post IDs

Guards, in the order a request meets them: a client already stopped by a human-only flag refuses; the
B-115 OSINT box (``ctf.osint_playbook.guard``: token cap, time box, no-progress timer, an existing stop
or handoff) refuses and hands off; a method already settled in the hypothesis ledger is not re-run; the
URL must be plain HTTPS with no credentials or credential-shaped parameters and must not carry a
protected identity; an oEmbed/embed host must be in the closed ENDPOINT_HOSTS table and an article host
must not be a social platform, an IP literal or a local name; every host must pass
``ctf.scope.check_public_fetch`` (the event's ``rules.public_fetch_allow``); then the global and per-host
request caps and the pacing interval. Requests carry a fixed generic User-Agent and never a cookie or an
Authorization header. Redirects are not followed by the transport: a same-host, non-login redirect is
followed once by the client; a redirect to a login, consent or other host is a block.

A block -- HTTP 401/403/407/429/451/999, a login or consent redirect, a captcha or bot-challenge page, an
HTML wall where oEmbed JSON was expected, an empty Instagram embed -- is never worked around: no retry,
no other user agent, no other endpoint, no login, no browser. The client stops, records the attempt as
negative in the hypothesis ledger, writes the B-115 handoff (``reason = "social_human_only"``, which also
records a stop so the dispatcher leaves the challenge to the human) and raises :class:`HumanOnlyStop`.

Every observation is a lead for a human: ``requires_human_pin`` is always true and nothing here submits.
Page and oEmbed content is untrusted data, never instructions.
"""
from __future__ import annotations

import dataclasses
import datetime as _dt
import html.parser
import ipaddress
import json
import math
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

try:  # package import (tests, ctf.cli), script-local import at the CLI
    from . import osint_online as online
except ImportError:  # pragma: no cover - flat import path
    import osint_online as online  # type: ignore

from ctf import env as _env
from ctf import hypothesis as _hyp
from ctf import ledger as _ledger
from ctf import osint_playbook as _pb
from ctf import scope as _scope

__all__ = [
    "ArticleScan", "FetchPlan", "HumanOnlyStop", "PostRef", "SocialBox", "SocialFetchClient",
    "SocialFetchError", "SocialOutOfScope", "ENDPOINT_HOSTS", "REASON_SOCIAL_HUMAN_ONLY",
    "classify_block", "flag_human_only", "parse_post_ref", "plan", "scan_article",
]

MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_REQUESTS = 6
MAX_PER_HOST = 3
MIN_INTERVAL_SECONDS = 1.5
TIMEOUT_SECONDS = 12.0
MAX_URL_CHARS = 2048
MAX_REFS = 64
MAX_REDIRECT_HOPS = 1
GENERIC_USER_AGENT = online.GENERIC_USER_AGENT

REASON_SOCIAL_HUMAN_ONLY = "social_human_only"
HUMAN_ONLY_EVENT = "osint.social_human_only"

# -------------------------------------------------------------------------------- platforms and hosts

_HOST_PLATFORM = {
    "instagram.com": "instagram", "www.instagram.com": "instagram", "instagr.am": "instagram",
    "twitter.com": "x", "www.twitter.com": "x", "mobile.twitter.com": "x", "x.com": "x",
    "www.x.com": "x",
    "tiktok.com": "tiktok", "www.tiktok.com": "tiktok", "m.tiktok.com": "tiktok",
    "youtube.com": "youtube", "www.youtube.com": "youtube", "m.youtube.com": "youtube",
    "youtu.be": "youtube", "www.youtube-nocookie.com": "youtube",
    "reddit.com": "reddit", "www.reddit.com": "reddit", "old.reddit.com": "reddit",
    "new.reddit.com": "reddit", "redd.it": "reddit",
    "facebook.com": "facebook", "www.facebook.com": "facebook", "m.facebook.com": "facebook",
    "web.facebook.com": "facebook",
    "bsky.app": "bluesky",
    "threads.net": "threads", "www.threads.net": "threads", "threads.com": "threads",
    "www.threads.com": "threads",
    "vimeo.com": "vimeo", "player.vimeo.com": "vimeo",
    "linkedin.com": "linkedin", "www.linkedin.com": "linkedin",
}
SOCIAL_HOSTS = frozenset(_HOST_PLATFORM)

# The closed endpoint table: the only hosts an oEmbed/embed request is ever built for. The event profile
# must ALSO list each host in rules.public_fetch_allow (ctf.scope.check_public_fetch).
OEMBED = {
    "youtube": "https://www.youtube.com/oembed?format=json&url=",
    "vimeo": "https://vimeo.com/api/oembed.json?url=",
    "x": "https://publish.twitter.com/oembed?omit_script=1&dnt=true&url=",
    "tiktok": "https://www.tiktok.com/oembed?url=",
    "reddit": "https://www.reddit.com/oembed?url=",
    "bluesky": "https://embed.bsky.app/oembed?format=json&url=",
}
MASTODON_INSTANCES = frozenset({"mastodon.social"})   # instances whose /api/oembed is in the table
INSTAGRAM_EMBED_HOST = "www.instagram.com"
ENDPOINT_HOSTS = frozenset(
    {urllib.parse.urlsplit(u).hostname for u in OEMBED.values()} | MASTODON_INSTANCES | {INSTAGRAM_EMBED_HOST})

# Registrable social domains (plus their short-link domains): a host equal to one of these, or any
# subdomain of one (mbasic.facebook.com, l.facebook.com, vm.tiktok.com), is social and never goes
# through the article scrape.
SOCIAL_DOMAINS = frozenset({
    "instagram.com", "instagr.am", "twitter.com", "x.com", "t.co", "tiktok.com", "youtube.com", "youtu.be",
    "youtube-nocookie.com", "reddit.com", "redd.it", "facebook.com", "fb.com", "fb.watch", "bsky.app",
    "threads.net", "threads.com", "vimeo.com", "linkedin.com", "lnkd.in",
}) | MASTODON_INSTANCES


def _is_social_host(host: str) -> bool:
    host = host.rstrip(".").lower()
    return any(host == d or host.endswith("." + d) for d in SOCIAL_DOMAINS)

# Platforms with no credential-free public endpoint: oEmbed needs an app token (Meta: Facebook, Threads,
# Instagram oEmbed proper) or the content needs a login. "Sanctioned API access" is a human step.
HUMAN_ONLY_PLATFORMS = {
    "facebook": "Facebook oEmbed needs a Meta app access token and posts need a login",
    "threads": "Threads oEmbed needs a Meta app access token",
    "linkedin": "LinkedIn posts need a login (authwall); there is no public oEmbed",
}

_LOCAL_SUFFIXES = (".local", ".localhost", ".internal", ".lan", ".home.arpa", ".intranet", ".corp")
_CRED_KEYS = frozenset({"token", "key", "api_key", "apikey", "secret", "password", "auth", "access_token",
                        "session", "sessionid", "sig", "signature"})


class SocialFetchError(online.OSINTGuardError):
    """A social fetch was declined by an input, scope, cap or response guard."""


class SocialOutOfScope(_scope.OutOfScope, SocialFetchError):
    """The event profile's rules.public_fetch_allow does not list the host."""


class AlreadyTried(SocialFetchError):
    """The hypothesis ledger already settles this exact fetch: it is not re-run."""


class HumanOnlyStop(SocialFetchError):
    """A block, a login wall or a platform with no public endpoint: a human takes over from here.

    `handoff` is the B-115 handoff file when the client ran inside an OSINT box, else None."""

    def __init__(self, reason: str, *, url: str | None = None, platform: str | None = None,
                 handoff: Path | None = None) -> None:
        self.reason = reason
        self.url = url
        self.platform = platform
        self.handoff = handoff
        where = f" ({platform})" if platform else ""
        tail = (f"; handoff written: {handoff}" if handoff is not None else
                "; no OSINT box was attached, so no handoff file was written: run "
                "`python -m ctf osint handoff <id> --reason social_human_only`")
        super().__init__(f"human-only{where}: {reason}; automation stops here, a human takes the "
                         f"browser{tail}")


# ------------------------------------------------------------------------------------------ post refs

@dataclasses.dataclass(frozen=True)
class PostRef:
    platform: str
    post_id: str
    kind: str                      # post | reel | video | short | story | status | comment
    canonical_url: str
    handle: str | None = None
    id_time: str | None = None     # ISO-8601 UTC decoded from the id, when the id carries a time
    id_time_basis: str | None = None
    numeric_id: int | None = None  # Instagram media id (decoded from the shortcode)

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


_IG_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
_IG_EPOCH_MS = 1314220021721            # Instagram id epoch (ms); media id >> 23 = ms since it
_X_EPOCH_MS = 1288834974657             # Twitter snowflake epoch (ms); id >> 22 = ms since it
_X_FIRST_SNOWFLAKE = 29_700_859_247     # ids below this are pre-snowflake: no time in them
_TID_ALPHABET = "234567abcdefghijklmnopqrstuvwxyz"
_MIN_TS = _dt.datetime(2004, 1, 1, tzinfo=_dt.timezone.utc).timestamp()
_MAX_TS = _dt.datetime(2100, 1, 1, tzinfo=_dt.timezone.utc).timestamp()


def _iso(seconds: float) -> str | None:
    if not math.isfinite(seconds) or not _MIN_TS <= seconds <= _MAX_TS:
        return None
    return _dt.datetime.fromtimestamp(seconds, tz=_dt.timezone.utc).isoformat(timespec="milliseconds")


def x_snowflake_time(post_id: int) -> str | None:
    """Post time of an X/Twitter status id (snowflake: id >> 22 is ms since 2010-11-04)."""
    if post_id < _X_FIRST_SNOWFLAKE:
        return None
    return _iso(((post_id >> 22) + _X_EPOCH_MS) / 1000.0)


def tiktok_id_time(post_id: int) -> str | None:
    """Post time of a TikTok video id (the top 32 bits are unix seconds)."""
    return _iso(float(post_id >> 32))


def mastodon_id_time(post_id: int) -> str | None:
    """Post time of a Mastodon status id (id >> 16 is unix ms)."""
    return _iso((post_id >> 16) / 1000.0)


def linkedin_id_time(post_id: int) -> str | None:
    """Post time of a LinkedIn activity id (id >> 22 is unix ms)."""
    return _iso((post_id >> 22) / 1000.0)


def bluesky_tid_time(rkey: str) -> str | None:
    """Post time of a Bluesky record key (TID: 13 base32-sortable chars, value >> 10 is unix µs)."""
    if len(rkey) != 13 or any(c not in _TID_ALPHABET for c in rkey):
        return None
    value = 0
    for c in rkey:
        value = value * 32 + _TID_ALPHABET.index(c)
    if value >> 63:
        return None
    return _iso((value >> 10) / 1_000_000.0)


def instagram_media_id(shortcode: str) -> int | None:
    """The numeric media id of an Instagram shortcode (base64url digits). None for an extended
    (longer than 11 characters) or malformed code."""
    if not 1 <= len(shortcode) <= 11 or any(c not in _IG_ALPHABET for c in shortcode):
        return None
    value = 0
    for c in shortcode:
        value = value * 64 + _IG_ALPHABET.index(c)
    return value


def instagram_id_time(media_id: int) -> str | None:
    """Approximate post time of an Instagram media id (the bits above 23 are ms since the id epoch)."""
    return _iso(((media_id >> 23) + _IG_EPOCH_MS) / 1000.0)


_RX = {
    "ig": re.compile(r"/(?:[A-Za-z0-9_.]{1,30}/)?(p|reel|reels|tv)/([A-Za-z0-9_-]{5,64})/?\Z"),
    "ig_story": re.compile(r"/stories/([A-Za-z0-9_.]{1,30})/(\d{5,25})/?\Z"),
    "x": re.compile(r"\A/([A-Za-z0-9_]{1,15})/status(?:es)?/(\d{1,20})(?:/.*)?\Z"),
    "x_i": re.compile(r"\A/i/(?:web/)?status/(\d{1,20})/?\Z"),
    "tt": re.compile(r"/@([A-Za-z0-9_.-]{1,32})/(video|photo)/(\d{8,20})/?\Z"),
    "tt_embed": re.compile(r"/embed(?:/v2)?/(\d{8,20})/?\Z"),
    "yt_path": re.compile(r"/(shorts|embed|live|v)/([A-Za-z0-9_-]{11})/?\Z"),
    "yt_id": re.compile(r"[A-Za-z0-9_-]{11}\Z"),
    "rd": re.compile(r"/r/([A-Za-z0-9_]{2,21})/comments/([a-z0-9]{1,13})(?:/[^/]*)?(?:/([a-z0-9]{1,13}))?/?\Z"),
    "rd_bare": re.compile(r"/comments/([a-z0-9]{1,13})(?:/.*)?\Z"),
    "redd_it": re.compile(r"/([a-z0-9]{1,13})/?\Z"),
    "bsky": re.compile(r"/profile/([A-Za-z0-9.:_-]{3,253})/post/([a-z2-7]{13})/?\Z"),
    "threads": re.compile(r"/@([A-Za-z0-9_.]{1,30})/post/([A-Za-z0-9_-]{5,64})/?\Z"),
    "vimeo": re.compile(r"/(?:video/)?(\d{5,12})/?\Z"),
    "li_activity": re.compile(r"urn:li:(?:activity|share|ugcPost):(\d{15,21})"),
    "li_posts": re.compile(r"/posts/[^/]*?activity-(\d{15,21})"),
    "mastodon": re.compile(r"/@([A-Za-z0-9_.]{1,30})(?:@[A-Za-z0-9.-]{1,253})?/(\d{6,20})/?\Z"),
    "fb": re.compile(r"/(?:[^/]+/(?:posts|videos|photos)/(?:[^/]+/)?|reel/|watch/?|photo/?|"
                     r"permalink\.php|story\.php|photo\.php)"),
}


def _split(url: str) -> urllib.parse.SplitResult | None:
    raw = str(url).strip()
    if not raw or len(raw) > MAX_URL_CHARS or any(ord(c) < 0x20 for c in raw):
        return None
    if raw.startswith("//"):
        raw = "https:" + raw
    elif "://" not in raw:
        raw = "https://" + raw
    try:
        parts = urllib.parse.urlsplit(raw)
        parts.port  # noqa: B018 - raises on a malformed port
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
        return None
    return parts


def parse_post_ref(url: str) -> PostRef | None:
    """The social post a URL names, or None when it names none. Offline: never contacts anything."""
    parts = _split(url)
    if parts is None:
        return None
    host = (parts.hostname or "").rstrip(".").lower()
    path = re.sub(r"/{2,}", "/", parts.path or "/")
    query = urllib.parse.parse_qs(parts.query)
    platform = _HOST_PLATFORM.get(host)
    if platform is None:
        m = _RX["mastodon"].search(path)
        if m and not any(host.endswith(s) for s in _LOCAL_SUFFIXES):
            pid = int(m.group(2))
            return PostRef("mastodon", m.group(2), "status", f"https://{host}/@{m.group(1)}/{m.group(2)}",
                           m.group(1), mastodon_id_time(pid), "mastodon snowflake (id >> 16 = unix ms)")
        return None

    if platform == "instagram":
        m = _RX["ig_story"].search(path)
        if m:
            return PostRef("instagram", m.group(2), "story",
                           f"https://www.instagram.com/stories/{m.group(1)}/{m.group(2)}/", m.group(1))
        m = _RX["ig"].search(path)
        if not m:
            return None
        kind = {"p": "post", "reel": "reel", "reels": "reel", "tv": "video"}[m.group(1)]
        code = m.group(2)
        media = instagram_media_id(code)
        seg = "reel" if kind == "reel" else ("tv" if kind == "video" else "p")
        return PostRef("instagram", code, kind, f"https://www.instagram.com/{seg}/{code}/", None,
                       None if media is None else instagram_id_time(media),
                       None if media is None else
                       "approximate: Instagram media id (from the shortcode) >> 23 + id epoch; verify on the post",
                       media)

    if platform == "x":
        m_i = _RX["x_i"].search(path)
        m = None if m_i else _RX["x"].search(path)
        if m_i:
            pid, handle = m_i.group(1), None
        elif m:
            pid, handle = m.group(2), m.group(1)
        else:
            return None
        who = handle or "i"
        n = int(pid)
        t = x_snowflake_time(n)
        return PostRef("x", pid, "status", f"https://twitter.com/{who}/status/{pid}", handle, t,
                       "X snowflake (id >> 22 + 2010-11-04 epoch, ms)" if t else None)

    if platform == "tiktok":
        m = _RX["tt"].search(path)
        if m:
            handle, kind, pid = m.group(1), m.group(2), m.group(3)
        else:
            m = _RX["tt_embed"].search(path)
            if not m:
                return None
            handle, kind, pid = None, "video", m.group(1)
        canonical = (f"https://www.tiktok.com/@{handle}/{kind}/{pid}" if handle else
                     f"https://www.tiktok.com/embed/v2/{pid}")
        t = tiktok_id_time(int(pid))
        return PostRef("tiktok", pid, kind, canonical, handle, t,
                       "TikTok id (top 32 bits = unix seconds)" if t else None)

    if platform == "youtube":
        vid, kind = None, "video"
        if host == "youtu.be":
            seg = path.strip("/").split("/")[0]
            vid = seg if _RX["yt_id"].fullmatch(seg) else None
        else:
            m = _RX["yt_path"].search(path)
            if m:
                vid, kind = m.group(2), ("short" if m.group(1) == "shorts" else "video")
            elif path.rstrip("/") == "/watch":
                v = (query.get("v") or [""])[0]
                vid = v if _RX["yt_id"].fullmatch(v) else None
        if vid is None:
            return None
        return PostRef("youtube", vid, kind, f"https://www.youtube.com/watch?v={vid}")

    if platform == "reddit":
        if host == "redd.it":
            m = _RX["redd_it"].search(path)
            return None if not m else PostRef("reddit", m.group(1), "post",
                                              f"https://www.reddit.com/comments/{m.group(1)}/")
        m = _RX["rd"].search(path)
        if m:
            sub, pid, comment = m.group(1), m.group(2), m.group(3)
            if comment:
                return PostRef("reddit", comment, "comment",
                               f"https://www.reddit.com/r/{sub}/comments/{pid}/_/{comment}/", sub)
            return PostRef("reddit", pid, "post", f"https://www.reddit.com/r/{sub}/comments/{pid}/", sub)
        m = _RX["rd_bare"].search(path)
        return None if not m else PostRef("reddit", m.group(1), "post",
                                          f"https://www.reddit.com/comments/{m.group(1)}/")

    if platform == "bluesky":
        m = _RX["bsky"].search(path)
        if not m:
            return None
        t = bluesky_tid_time(m.group(2))
        return PostRef("bluesky", m.group(2), "post",
                       f"https://bsky.app/profile/{m.group(1)}/post/{m.group(2)}", m.group(1), t,
                       "Bluesky TID (value >> 10 = unix microseconds)" if t else None)

    if platform == "threads":
        m = _RX["threads"].search(path)
        return None if not m else PostRef("threads", m.group(2), "post",
                                          f"https://www.threads.net/@{m.group(1)}/post/{m.group(2)}",
                                          m.group(1))

    if platform == "vimeo":
        m = _RX["vimeo"].search(path)
        return None if not m else PostRef("vimeo", m.group(1), "video", f"https://vimeo.com/{m.group(1)}")

    if platform == "linkedin":
        m = _RX["li_activity"].search(urllib.parse.unquote(path)) or _RX["li_posts"].search(path)
        if not m:
            return None
        pid = m.group(1)
        t = linkedin_id_time(int(pid))
        return PostRef("linkedin", pid, "post",
                       f"https://www.linkedin.com/feed/update/urn:li:activity:{pid}/", None, t,
                       "LinkedIn activity id (id >> 22 = unix ms)" if t else None)

    # facebook
    if not _RX["fb"].search(path):
        return None
    pid = None
    for key in ("story_fbid", "fbid", "v"):
        if query.get(key) and re.fullmatch(r"[A-Za-z0-9_]{1,40}", query[key][0]):
            pid = query[key][0]
            break
    if pid is None:
        tail = [seg for seg in path.split("/") if seg]
        pid = tail[-1] if tail else ""
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", pid or ""):
        return None
    keep = {k: v[0] for k, v in query.items() if k in ("story_fbid", "fbid", "id", "v")}
    canonical = urllib.parse.urlunsplit(("https", "www.facebook.com", path, urllib.parse.urlencode(keep), ""))
    return PostRef("facebook", pid, "post", canonical)


# ------------------------------------------------------------------------------------------ the plan

@dataclasses.dataclass(frozen=True)
class FetchPlan:
    ref: PostRef
    mode: str                     # oembed | embed | human_only
    endpoint: str | None          # the exact URL a fetch would request (None when human-only)
    host: str | None
    reason: str

    def to_dict(self) -> dict[str, Any]:
        d = dataclasses.asdict(self)
        d["ref"] = self.ref.to_dict()
        return d


def plan(target: str | PostRef) -> FetchPlan:
    """Which public endpoint a fetch of this post would use, or why it is human-only. Offline.
    Raises SocialFetchError for a URL that names no recognised post (never guesses one)."""
    ref = target if isinstance(target, PostRef) else parse_post_ref(target)
    if ref is None:
        raise SocialFetchError("not a recognised social-media post URL (see parse_post_ref)")
    if ref.platform in HUMAN_ONLY_PLATFORMS:
        return FetchPlan(ref, "human_only", None, None, HUMAN_ONLY_PLATFORMS[ref.platform])
    if ref.platform == "instagram":
        if ref.kind == "story":
            return FetchPlan(ref, "human_only", None, None,
                             "Instagram stories need a login and have no public embed")
        seg = "reel" if ref.kind == "reel" else ("tv" if ref.kind == "video" else "p")
        url = f"https://{INSTAGRAM_EMBED_HOST}/{seg}/{ref.post_id}/embed/captioned/"
        return FetchPlan(ref, "embed", url, INSTAGRAM_EMBED_HOST,
                         "Instagram oEmbed needs a Meta app token; the public embed page does not")
    if ref.platform == "mastodon":
        host = urllib.parse.urlsplit(ref.canonical_url).hostname or ""
        if host not in MASTODON_INSTANCES:
            return FetchPlan(ref, "human_only", None, None,
                             f"Mastodon instance {host} is not in the closed endpoint table "
                             f"({', '.join(sorted(MASTODON_INSTANCES))}); open the post by hand")
        url = f"https://{host}/api/oembed?url=" + urllib.parse.quote(ref.canonical_url, safe="")
        return FetchPlan(ref, "oembed", url, host, "public Mastodon oEmbed")
    if ref.platform == "tiktok" and ref.handle is None:
        return FetchPlan(ref, "human_only", None, None,
                         "TikTok oEmbed needs the author handle in the URL; this link carries only the id")
    base = OEMBED[ref.platform]
    url = base + urllib.parse.quote(ref.canonical_url, safe="")
    return FetchPlan(ref, "oembed", url, urllib.parse.urlsplit(url).hostname, f"public {ref.platform} oEmbed")


# ------------------------------------------------------------------------------- the article scanner

@dataclasses.dataclass(frozen=True)
class FoundRef:
    ref: PostRef
    where: str                    # how the page carried it: a@href, iframe@src, amp-instagram, text, ...

    def to_dict(self) -> dict[str, Any]:
        return {**self.ref.to_dict(), "where": self.where}


@dataclasses.dataclass(frozen=True)
class ArticleScan:
    title: str | None
    published: str | None
    canonical: str | None
    refs: list[FoundRef]
    truncated: bool

    def to_dict(self) -> dict[str, Any]:
        return {"title": self.title, "published": self.published, "canonical": self.canonical,
                "refs": [r.to_dict() for r in self.refs], "truncated": self.truncated}


_BARE_URL_RE = re.compile(
    r"(?:https?:)?//(?:[a-z0-9-]+\.)*(?:instagram\.com|instagr\.am|twitter\.com|x\.com|tiktok\.com|"
    r"youtube\.com|youtu\.be|youtube-nocookie\.com|reddit\.com|redd\.it|facebook\.com|bsky\.app|"
    r"threads\.net|threads\.com|vimeo\.com|linkedin\.com)/[A-Za-z0-9\-._~:/?#@!$&*+,;=%]{1,512}", re.I)
_MASTODON_URL_RE = re.compile(r"https://[a-z0-9.-]{3,253}/@[A-Za-z0-9_.]{1,30}/\d{6,20}", re.I)
_DATE_META = ("article:published_time", "og:published_time", "datepublished", "date", "pubdate",
              "publishdate", "dc.date", "dc.date.issued", "sailthru.date", "parsely-pub-date")


class _ArticleParser(html.parser.HTMLParser):
    def __init__(self, base_url: str | None) -> None:
        super().__init__(convert_charrefs=True)
        self.base = base_url
        self.title_meta: str | None = None
        self.title_tag: list[str] = []
        self.published: str | None = None
        self.canonical: str | None = None
        self.found: list[FoundRef] = []
        self._seen: set[tuple[str, str]] = set()
        self._in_title = False
        self._script: str | None = None       # "ld" | "other" while inside a <script>
        self._script_buf: list[str] = []
        self.overflow = False

    def _add(self, raw: str | None, where: str) -> None:
        if not raw:
            return
        url = raw.strip().replace("\\/", "/")
        if self.base and not url.startswith(("http://", "https://", "//")):
            url = urllib.parse.urljoin(self.base, url)
        ref = parse_post_ref(url)
        if ref is None:
            return
        key = (ref.platform, ref.post_id)
        if key in self._seen:
            return
        if len(self.found) >= MAX_REFS:
            self.overflow = True
            return
        self._seen.add(key)
        self.found.append(FoundRef(ref, where))

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "title":
            self._in_title = True
        elif tag == "meta":
            key = (a.get("property") or a.get("name") or a.get("itemprop") or "").lower()
            content = a.get("content", "").strip()
            if key == "og:title" and content and self.title_meta is None:
                self.title_meta = content[:300]
            elif key in _DATE_META and content and self.published is None:
                self.published = content[:64]
            elif key in ("og:url", "twitter:url") and content and self.canonical is None:
                self.canonical = content[:MAX_URL_CHARS]
            elif key in ("twitter:player", "og:video", "og:video:url", "og:video:secure_url"):
                self._add(content, f"meta@{key}")
        elif tag == "link" and "canonical" in a.get("rel", "").lower().split():
            if a.get("href"):
                self.canonical = a["href"][:MAX_URL_CHARS]
        elif tag == "time" and a.get("datetime") and self.published is None and a.get("pubdate") is not None:
            self.published = a["datetime"][:64]
        elif tag == "script":
            self._script = "ld" if "ld+json" in a.get("type", "").lower() else "other"
            self._script_buf = []
        if tag == "amp-instagram" and a.get("data-shortcode"):
            self._add(f"https://www.instagram.com/p/{a['data-shortcode']}/", "amp-instagram")
        elif tag == "amp-twitter" and a.get("data-tweetid"):
            self._add(f"https://twitter.com/i/status/{a['data-tweetid']}", "amp-twitter")
        elif tag == "amp-youtube" and a.get("data-videoid"):
            self._add(f"https://www.youtube.com/watch?v={a['data-videoid']}", "amp-youtube")
        elif tag == "amp-tiktok" and a.get("data-src"):
            self._add(a["data-src"], "amp-tiktok")
        for attr in ("href", "src", "data-src", "data-href", "data-instgrm-permalink", "cite", "data-url"):
            if a.get(attr) and tag not in ("link", "meta"):
                self._add(a[attr], f"{tag}@{attr}")

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False
        elif tag == "script" and self._script is not None:
            text = "".join(self._script_buf)[:256 * 1024]
            if self._script == "ld":
                self._json_ld(text)
            self._bare(text, "script")
            self._script, self._script_buf = None, []

    def handle_data(self, data: str) -> None:
        if self._script is not None:
            self._script_buf.append(data)
            return
        if self._in_title:
            self.title_tag.append(data)
        self._bare(data, "text")

    def _bare(self, text: str, where: str) -> None:
        text = text.replace("\\/", "/")
        for m in _BARE_URL_RE.finditer(text):
            self._add(m.group(0), where)
        for m in _MASTODON_URL_RE.finditer(text):
            self._add(m.group(0), where)

    def _json_ld(self, text: str) -> None:
        try:
            doc = json.loads(text)
        except (ValueError, RecursionError):
            return
        stack, budget = [doc], 5000
        while stack and budget > 0:
            budget -= 1
            node = stack.pop()
            if isinstance(node, Mapping):
                if self.published is None and isinstance(node.get("datePublished"), str):
                    self.published = node["datePublished"][:64]
                if self.title_meta is None and isinstance(node.get("headline"), str):
                    self.title_meta = node["headline"][:300]
                for key in ("url", "embedUrl", "sameAs", "contentUrl"):
                    if isinstance(node.get(key), str):
                        self._add(node[key], f"json-ld@{key}")
                stack.extend(v for v in node.values() if isinstance(v, (Mapping, list)))
            elif isinstance(node, list):
                stack.extend(node[:256])


def scan_article(page: bytes | str, *, base_url: str | None = None) -> ArticleScan:
    """Title, published time, canonical URL and every social post a news page carries. Offline and
    bounded (MAX_RESPONSE_BYTES of input, MAX_REFS refs); the page is data, never instructions."""
    if isinstance(page, bytes):
        truncated = len(page) > MAX_RESPONSE_BYTES
        text = page[:MAX_RESPONSE_BYTES].decode("utf-8", "replace")
    else:
        truncated = len(page) > MAX_RESPONSE_BYTES
        text = page[:MAX_RESPONSE_BYTES]
    p = _ArticleParser(base_url)
    try:
        p.feed(text)
        p.close()
    except (AssertionError, ValueError):  # a malformed page: keep what was parsed so far
        truncated = True
    title = p.title_meta or (re.sub(r"\s+", " ", "".join(p.title_tag)).strip()[:300] or None)
    return ArticleScan(title, p.published, p.canonical, list(p.found), truncated or p.overflow)


# --------------------------------------------------------------------------------- block detection

_LOGIN_PATH_RE = re.compile(
    r"/(?:accounts/login|login|log-in|signin|sign-in|i/flow/login|checkpoint|challenge|consent|"
    r"authwall|uas/login|auth/|sorry/)", re.I)
_BLOCK_STATUS = {401: "login required (HTTP 401)", 403: "forbidden (HTTP 403)",
                 407: "proxy authentication required (HTTP 407)", 429: "rate limited (HTTP 429)",
                 451: "unavailable for legal reasons (HTTP 451)", 999: "bot block (HTTP 999)"}
# Strong markers only: an article page that merely mentions a captcha is not a wall.
_WALL_MARKERS = (
    (re.compile(rb"cf-chl|challenge-platform|cf_chl_opt|__cf_chl", re.I), "bot challenge page (Cloudflare)"),
    (re.compile(rb"captcha-delivery\.com|geo\.captcha|px-captcha|_px\.js|perimeterx", re.I), "bot challenge page"),
    (re.compile(rb"<title>\s*(?:just a moment|attention required|access denied|are you a robot)", re.I),
     "bot interstitial page"),
    (re.compile(rb"unusual traffic from your computer", re.I), "bot block page"),
)
# On a social endpoint (an oEmbed or embed request), a login form or captcha widget is also a wall.
_SOCIAL_WALL_MARKERS = (
    (re.compile(rb"<input[^>]+type=[\"']?password", re.I), "login wall"),
    (re.compile(rb"g-recaptcha|h-captcha|hcaptcha\.com|recaptcha/api\.js", re.I), "captcha wall"),
    (re.compile(rb"<title>\s*(?:log ?in|sign ?in|login)\b", re.I), "login wall"),
)


def _header(headers: Mapping[str, str], name: str) -> str:
    low = name.lower()
    for k, v in headers.items():
        if str(k).lower() == low:
            return str(v)
    return ""


def classify_block(status: int, headers: Mapping[str, str], body: bytes, url: str, *,
                   social: bool) -> str | None:
    """Why a response is a block or login wall, or None when it is not. `social` adds the login-form and
    captcha-widget markers that would be false positives on an ordinary news page."""
    if status in _BLOCK_STATUS:
        return _BLOCK_STATUS[status]
    if 300 <= status < 400:
        loc = _header(headers, "Location")
        if not loc:
            return f"redirect (HTTP {status}) with no Location"
        target = urllib.parse.urljoin(url, loc)
        t_host = (urllib.parse.urlsplit(target).hostname or "").lower()
        o_host = (urllib.parse.urlsplit(url).hostname or "").lower()
        if _LOGIN_PATH_RE.search(urllib.parse.urlsplit(target).path or "") or t_host.startswith(
                ("consent.", "login.", "accounts.", "auth.")):
            return f"redirect to a login or consent page ({t_host})"
        if t_host != o_host:
            return f"redirect to another host ({t_host})"
        return None
    head = body[:256 * 1024]
    for rx, why in _WALL_MARKERS + (_SOCIAL_WALL_MARKERS if social else ()):
        if rx.search(head):
            return why
    return None


# --------------------------------------------------------------------------- the human-only flag

@dataclasses.dataclass(frozen=True)
class SocialBox:
    """The B-115 OSINT box a client runs inside: the meter (token cap, time box, no-progress timer)
    and the challenge. With a box, every request is guarded and a block writes the handoff."""
    meter: Any                    # ctf.budget.LedgerMeter (osint_playbook.meter)
    challenge_id: str
    agent: str = "social-fetch"

    @property
    def workdir(self) -> Path:
        return self.meter.workdir


def flag_human_only(box: SocialBox, *, reason: str, url: str | None = None, platform: str | None = None,
                    notes: str = "") -> Path:
    """The early human-only flag: write the B-115 handoff for the challenge (which records a stop, so the
    dispatcher and escalator leave it to the human) and a ``osint.social_human_only`` ledger record.
    Idempotent on the handoff: a challenge already handed off keeps its one handoff file and the same
    path comes back (each call still appends its own flag record). Returns the handoff path."""
    cid = str(box.challenge_id).strip()
    if not cid:
        raise SocialFetchError("flag_human_only needs a challenge id")
    host = (urllib.parse.urlsplit(url).hostname or "") if url else ""
    _ledger.append(HUMAN_ONLY_EVENT, workdir=box.workdir, challenge_id=cid, platform=platform or "",
                   host=host, reason=str(reason)[:300])
    prior = _pb.existing_handoff(cid, box.workdir)
    if prior is not None and prior.get("path"):
        return Path(str(prior["path"]))
    sources = [url] if url else []
    note = (f"{platform or 'social'}: {reason}. Automation stopped without retrying, switching endpoint, "
            f"logging in or driving a browser. The human opens the post in their own browser."
            + (f" {notes}" if notes else ""))
    h = _pb.build_handoff(box.meter, cid, reason=REASON_SOCIAL_HUMAN_ONLY, sources=sources, notes=note)
    return h.path


# ------------------------------------------------------------------------------------- the transport

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow: the 3xx comes back to the client, which classifies it."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def _urllib_transport(url: str, headers: Mapping[str, str], timeout: float,
                      max_bytes: int) -> online.HTTPResult:
    opener = urllib.request.build_opener(_NoRedirect())      # no cookie processor: no cookies, ever
    req = urllib.request.Request(url, headers=dict(headers), method="GET")
    try:
        with opener.open(req, timeout=timeout) as response:  # noqa: S310 - host checked by the client
            advertised = response.headers.get("Content-Length")
            if advertised and advertised.isdigit() and int(advertised) > max_bytes:
                raise SocialFetchError("response exceeds the byte cap")
            body = response.read(max_bytes + 1)
            return online.HTTPResult(int(response.status), dict(response.headers.items()), body,
                                     response.geturl())
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read(max_bytes + 1) if exc.fp is not None else b""
            return online.HTTPResult(int(exc.code), dict(exc.headers.items()) if exc.headers else {}, body,
                                     url)
        finally:
            exc.close()


# ------------------------------------------------------------------------------------------ helpers

def _https_host(url: str) -> str:
    try:
        parts = urllib.parse.urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise SocialFetchError("malformed URL") from exc
    if parts.scheme != "https" or parts.username or parts.password or port not in (None, 443):
        raise SocialFetchError("social fetches use plain HTTPS on port 443 with no credentials in the URL")
    host = (parts.hostname or "").rstrip(".").lower()
    if not host:
        raise SocialFetchError("URL has no host")
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        pass
    else:
        raise SocialFetchError("literal-IP URLs are refused")
    if host in ("localhost", "localhost.localdomain") or host.endswith(_LOCAL_SUFFIXES) or "." not in host:
        raise SocialFetchError(f"local or internal host {host} is refused")
    for key, _value in urllib.parse.parse_qsl(parts.query, keep_blank_values=True):
        if key.casefold() in _CRED_KEYS:
            raise SocialFetchError(f"credential-shaped URL parameter {key!r} is refused")
    return host


def _bounded(value: Any, budget: list[int] | None = None, depth: int = 0) -> Any:
    budget = [20_000] if budget is None else budget
    if budget[0] <= 0 or depth > 10:
        raise SocialFetchError("oEmbed JSON exceeds structural bounds")
    budget[0] -= 1
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, str):
        return value[:4096]
    if isinstance(value, Mapping):
        return {str(k)[:128]: _bounded(v, budget, depth + 1) for k, v in list(value.items())[:256]}
    if isinstance(value, list):
        return [_bounded(v, budget, depth + 1) for v in value[:256]]
    return str(value)[:4096]


class _TextAndLinks(html.parser.HTMLParser):
    """Visible text and hrefs of a small HTML fragment (an oEmbed `html` field or an embed page)."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.text: list[str] = []
        self.links: list[str] = []
        self.classed: dict[str, list[str]] = {}
        self.times: list[str] = []
        self.img_alt: list[str] = []
        self._stack: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):  # noqa: ANN001
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag in ("script", "style"):
            self._skip += 1
        if tag == "a" and a.get("href") and len(self.links) < 32:
            self.links.append(a["href"][:MAX_URL_CHARS])
        if tag == "time" and a.get("datetime"):
            self.times.append(a["datetime"][:64])
        if tag == "img" and a.get("alt") and len(self.img_alt) < 8:
            self.img_alt.append(a["alt"][:500])
        if tag not in ("br", "img", "meta", "link", "input", "hr", "source"):
            self._stack.append(a.get("class", ""))

    def handle_endtag(self, tag):  # noqa: ANN001
        if tag in ("script", "style"):
            self._skip = max(0, self._skip - 1)
        if tag not in ("br", "img", "meta", "link", "input", "hr", "source") and self._stack:
            self._stack.pop()

    def handle_data(self, data):  # noqa: ANN001
        if self._skip:
            return
        self.text.append(data)
        recent = [cls.lower() for cls in self._stack[-3:]]
        for name in ("Username", "Caption"):
            if any(name.lower() in cls for cls in recent):
                self.classed.setdefault(name, []).append(data)


def _parse_fragment(fragment: str) -> _TextAndLinks:
    p = _TextAndLinks()
    try:
        p.feed(fragment[:512 * 1024])
        p.close()
    except (AssertionError, ValueError):
        pass
    return p


def _squash(parts: list[str], limit: int = 2000) -> str:
    return re.sub(r"\s+", " ", " ".join(parts)).strip()[:limit]


_OEMBED_KEYS = ("type", "version", "title", "author_name", "author_url", "author_unique_id",
                "provider_name", "provider_url", "thumbnail_url", "upload_date", "description",
                "duration", "video_id", "embed_product_id", "url", "width", "height")


# ------------------------------------------------------------------------------------------ the client

class SocialFetchClient:
    """Capped, paced, scope-checked oEmbed / public-embed / news-article fetches. Off unless built."""

    def __init__(self, *, transport: Callable[..., online.HTTPResult] | None = None,
                 clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep,
                 min_interval: float = MIN_INTERVAL_SECONDS,
                 request_cap: int = MAX_REQUESTS,
                 per_host_cap: int = MAX_PER_HOST,
                 profile=None,
                 box: SocialBox | None = None,
                 protected_identifiers: tuple[str, ...] = ()) -> None:
        if isinstance(min_interval, bool) or not isinstance(min_interval, (int, float)) \
                or not math.isfinite(min_interval) or min_interval < 1.0:
            raise ValueError("min_interval must be a finite number of at least one second")
        for name, value, top in (("request_cap", request_cap, MAX_REQUESTS),
                                 ("per_host_cap", per_host_cap, MAX_PER_HOST)):
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= top:
                raise ValueError(f"{name} must be an int in 1..{top}")
        if box is not None and not isinstance(box, SocialBox):
            raise TypeError("box must be a SocialBox")
        self.transport = transport or _urllib_transport
        self.clock, self.sleep = clock, sleep
        self.min_interval = float(min_interval)
        self.request_cap, self.per_host_cap = request_cap, per_host_cap
        self.profile = profile
        self.box = box
        env_ids = tuple(x.strip() for x in (_env.get("CTF_OSINT_PRIVATE_IDENTIFIERS") or "").split(",")
                        if x.strip())
        self.protected = frozenset(x.casefold() for x in tuple(protected_identifiers) + env_ids if x)
        self._requests = 0
        self._per_host: dict[str, int] = {}
        self._last: float | None = None
        self._stopped: HumanOnlyStop | None = None

    @property
    def request_count(self) -> int:
        return self._requests

    @property
    def stopped(self) -> HumanOnlyStop | None:
        return self._stopped

    # ------------------------------------------------------------------ guards around one request
    def _guard_box(self) -> None:
        if self.box is None:
            return
        h = _pb.guard(self.box.meter, self.box.challenge_id)
        if h is not None:
            exc = HumanOnlyStop(f"the OSINT box is closed ({h.reason})", handoff=h.path)
            self._stopped = exc
            raise exc

    def _guard_settled(self, method: str) -> None:
        if self.box is None:
            return
        s = _hyp.should_skip(self.box.challenge_id, method, self.box.workdir)
        if s.skip:
            raise AlreadyTried(f"{method}: {s.reason}")

    def _record(self, method: str, result: str, evidence: str, hypothesis: str) -> None:
        if self.box is None:
            return
        _hyp.record(self.box.challenge_id, hypothesis=hypothesis, method=method, result=result,
                    agent=self.box.agent, evidence=evidence[:500], workdir=self.box.workdir)

    def _stop(self, reason: str, *, url: str | None, platform: str | None, method: str | None,
              hypothesis: str) -> None:
        handoff = None
        if self.box is not None:
            if method is not None:
                self._record(method, _hyp.NEGATIVE, f"human-only: {reason}", hypothesis)
            handoff = flag_human_only(self.box, reason=reason, url=url, platform=platform)
        exc = HumanOnlyStop(reason, url=url, platform=platform, handoff=handoff)
        self._stopped = exc
        raise exc

    def _check_value(self, url: str) -> None:
        if len(url) > MAX_URL_CHARS:
            raise SocialFetchError("URL is overlong")
        if online.SECRET_RE.search(urllib.parse.unquote(url)):
            raise SocialFetchError("secret-shaped values must never be sent to a public host")
        folded = urllib.parse.unquote(url).casefold()
        if any(p in folded for p in self.protected):
            raise SocialFetchError("a protected/player identity must never be sent to a third party")

    def _pace(self) -> None:
        now = float(self.clock())
        if not math.isfinite(now):
            raise SocialFetchError("pacing clock returned a non-finite value")
        if self._last is not None:
            remaining = self.min_interval - (now - self._last)
            if remaining > 0:
                self.sleep(remaining)
                now = float(self.clock())
        self._last = now

    def _refuse_if_stopped(self) -> None:
        if self._stopped is not None:
            raise HumanOnlyStop(f"this client already stopped: {self._stopped.reason}",
                                url=self._stopped.url, platform=self._stopped.platform,
                                handoff=self._stopped.handoff)

    def _get(self, url: str, *, purpose: str, accept: str, social: bool, platform: str | None,
             method: str, hypothesis: str, hops: int = 0) -> online.HTTPResult:
        self._refuse_if_stopped()
        self._guard_box()
        host = _https_host(url)
        self._check_value(url)
        if social and host not in ENDPOINT_HOSTS:
            raise SocialFetchError(f"{host} is not in the closed social endpoint table")
        if not social and _is_social_host(host):    # covers SOCIAL_HOSTS, ENDPOINT_HOSTS and subdomains
            raise SocialFetchError(f"{host} is a social platform: use fetch_post, not the article scrape")
        _scope.check_public_fetch(url, purpose=purpose, profile=self.profile, error=SocialOutOfScope)
        if self._requests >= self.request_cap:
            raise SocialFetchError(f"request cap of {self.request_cap} reached for this client")
        used = self._per_host.get(host, 0)
        if used >= self.per_host_cap:
            raise SocialFetchError(f"per-host cap of {self.per_host_cap} reached for {host}")
        self._pace()
        headers = {"User-Agent": GENERIC_USER_AGENT, "Accept": accept, "Cache-Control": "no-cache"}
        self._requests += 1                      # counted before the transport: a failure still counts
        self._per_host[host] = used + 1
        res = self.transport(url, headers, TIMEOUT_SECONDS, MAX_RESPONSE_BYTES)
        if not isinstance(res, online.HTTPResult) or not isinstance(res.body, bytes):
            raise SocialFetchError("transport returned an invalid response object")
        if isinstance(res.status, bool) or not isinstance(res.status, int):
            raise SocialFetchError("transport returned an invalid HTTP status")
        if len(res.body) > MAX_RESPONSE_BYTES:
            raise SocialFetchError("response exceeds the byte cap")
        final_host = (urllib.parse.urlsplit(str(res.final_url)).hostname or "").lower()
        if final_host != host:
            raise SocialFetchError(f"transport ended on another host ({final_host}); cross-host redirects "
                                   f"are refused")
        block = classify_block(res.status, res.headers, res.body, url, social=social)
        if block is not None:
            self._stop(block, url=url, platform=platform, method=method, hypothesis=hypothesis)
        if 300 <= res.status < 400:
            if hops >= MAX_REDIRECT_HOPS:
                raise SocialFetchError(f"{host} redirected more than {MAX_REDIRECT_HOPS} time(s)")
            target = urllib.parse.urljoin(url, _header(res.headers, "Location"))
            return self._get(target, purpose=purpose, accept=accept, social=social, platform=platform,
                             method=method, hypothesis=hypothesis, hops=hops + 1)
        if not 200 <= res.status < 300:
            self._record(method, _hyp.NEGATIVE, f"HTTP {res.status} from {host}", hypothesis)
            raise SocialFetchError(f"{host} returned HTTP {res.status}"
                                   + (" (post removed, private or never existed)" if res.status in (404, 410)
                                      else ""))
        return res

    # ------------------------------------------------------------------------------- the lookups
    def fetch_post(self, url: str) -> dict[str, Any]:
        """One oEmbed or public-embed request for the post `url` names. A platform with no public
        endpoint raises the human-only flag before any request (and writes the handoff in a box)."""
        self._refuse_if_stopped()
        p = plan(url)
        ref = p.ref
        hypothesis = f"public {ref.platform} {ref.kind} {ref.post_id} metadata"
        method = f"social {p.mode} {ref.platform} {ref.post_id}"
        if p.mode == "human_only":
            self._guard_box()
            self._stop(p.reason, url=ref.canonical_url, platform=ref.platform, method=method,
                       hypothesis=hypothesis)
        self._guard_settled(method)
        res = self._get(p.endpoint, purpose=f"B-206 social {p.mode} lookup for a {ref.platform} post",
                        accept="application/json" if p.mode == "oembed" else "text/html", social=True,
                        platform=ref.platform, method=method, hypothesis=hypothesis)
        if p.mode == "oembed":
            fields, links = self._oembed_fields(res, ref, p, method, hypothesis)
        else:
            fields, links = self._embed_fields(res, ref, p, method, hypothesis)
        found = []
        for link in links:
            r = parse_post_ref(link)
            if r is not None and (r.platform, r.post_id) != (ref.platform, ref.post_id):
                found.append(r.to_dict())
        summary = ", ".join(f"{k}={str(v)[:60]}" for k, v in fields.items()
                            if k in ("author_name", "title", "username", "text") and v)
        self._record(method, _hyp.INCONCLUSIVE, f"{p.endpoint}: {summary}", hypothesis)
        return {"kind": "social_post", "platform": ref.platform, "post_id": ref.post_id, "mode": p.mode,
                "endpoint": p.endpoint, "ref": ref.to_dict(), "fields": fields, "linked_posts": found[:16],
                "requests": self.request_count, "automatic_answer": None, "requires_human_pin": True,
                "note": "public embed metadata is a lead: a human confirms it on the post before using it"}

    def _oembed_fields(self, res, ref, p, method, hypothesis):  # noqa: ANN001
        ctype = _header(res.headers, "Content-Type").lower()
        body = res.body.lstrip()
        if "json" not in ctype and not body.startswith((b"{", b"[")):
            if body[:1] == b"<":
                self._stop("an HTML page came back where oEmbed JSON was expected (a login or consent wall)",
                           url=p.endpoint, platform=ref.platform, method=method, hypothesis=hypothesis)
            raise SocialFetchError("oEmbed response is not JSON")
        try:
            raw = json.loads(res.body.decode("utf-8"))
        except (UnicodeError, ValueError, RecursionError) as exc:
            raise SocialFetchError("oEmbed returned malformed JSON") from exc
        doc = _bounded(raw)      # outside the try: its "structural bounds" error is a ValueError too
        if not isinstance(doc, Mapping):
            raise SocialFetchError("oEmbed JSON is not an object")
        fields = {k: doc[k] for k in _OEMBED_KEYS if doc.get(k) not in (None, "")}
        links: list[str] = []
        if isinstance(doc.get("html"), str):
            frag = _parse_fragment(doc["html"])
            text = _squash(frag.text)
            if text:
                fields["text"] = text
            links = frag.links + [m.group(0) for m in _BARE_URL_RE.finditer(text)][:16]
            if frag.times:
                fields["embed_time"] = frag.times[0]
        return fields, links

    def _embed_fields(self, res, ref, p, method, hypothesis):  # noqa: ANN001
        page = res.body.decode("utf-8", "replace")
        frag = _parse_fragment(page)
        username = next((u.strip()[:64] for u in frag.classed.get("Username", []) if u.strip()), None)
        caption = _squash(frag.classed.get("Caption", []), 2200) or None
        if username and caption and caption.startswith(username):
            caption = caption[len(username):].strip() or None
        if not username and not caption:
            self._stop("the public embed came back empty (private, removed or withheld from embeds)",
                       url=p.endpoint, platform=ref.platform, method=method, hypothesis=hypothesis)
        fields: dict[str, Any] = {"username": username, "caption": caption}
        if frag.times:
            fields["embed_time"] = frag.times[0]
        if frag.img_alt:
            fields["image_alt"] = frag.img_alt[0]
        return {k: v for k, v in fields.items() if v}, frag.links

    def scrape_article(self, url: str) -> dict[str, Any]:
        """One bounded fetch of a news article, scanned for the social posts it links or embeds."""
        self._refuse_if_stopped()
        url = str(url).strip()
        parts = _split(url)
        if parts is None:
            raise SocialFetchError("not a URL")
        url = urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path or "/", parts.query, ""))
        host = _https_host(url)
        method = f"social article {host}{parts.path or '/'}"
        hypothesis = "the article links or embeds the social post"
        self._guard_settled(method)
        res = self._get(url, purpose="B-206 news-article scrape for social post IDs",
                        accept="text/html,application/xhtml+xml", social=False, platform=None,
                        method=method, hypothesis=hypothesis)
        ctype = _header(res.headers, "Content-Type").lower()
        if "html" not in ctype and not res.body.lstrip()[:1] == b"<":
            raise SocialFetchError(f"{host} did not return an HTML page")
        scan = scan_article(res.body, base_url=url)
        self._record(method, _hyp.INCONCLUSIVE,
                     f"{len(scan.refs)} post ref(s): " + ", ".join(f"{r.ref.platform}:{r.ref.post_id}"
                                                                   for r in scan.refs[:8]), hypothesis)
        return {"kind": "news_article", "url": url, **scan.to_dict(), "requests": self.request_count,
                "automatic_answer": None, "requires_human_pin": True,
                "note": "post refs are leads; fetch one with fetch_post or open it by hand"}


def endpoint_host_status(profile=None) -> list[dict[str, Any]]:
    """Each closed endpoint host and whether the event's rules.public_fetch_allow lists it (offline)."""
    out = []
    for host in sorted(ENDPOINT_HOSTS):
        try:
            _scope.check_public_fetch(host, purpose="B-206 social endpoint", profile=profile)
            out.append({"host": host, "allowed": True, "reason": ""})
        except _scope.OutOfScope as exc:
            out.append({"host": host, "allowed": False, "reason": str(exc)})
    return out
