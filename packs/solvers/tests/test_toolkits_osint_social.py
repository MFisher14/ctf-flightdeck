"""B-206: the social-media post helper -- post-ID decode, the endpoint plan, the news-article scanner,
block detection, the capped/scope-checked fetch client, and the early human-only flag that writes the
B-115 handoff and stops the loop.

No network: every client gets an injected transport that records each call and serves synthetic oEmbed
JSON or HTML. The one test of the default transport uses a toy HTTP server on 127.0.0.1 started by the
test. Time is an injected step clock (rule 16).
"""
from __future__ import annotations

import argparse
import datetime as dt
import http.server
import json
import threading
import urllib.parse

import pytest

import osint_social as S  # solvers/toolkits (root conftest puts it on sys.path)
from ctf import budget, event, hypothesis, ledger, osint_playbook as pb, scope
from ctf.event import Budget

ARTICLE_HOST = "news.example.org"


def _profile(public=tuple(sorted(S.ENDPOINT_HOSTS)) + (ARTICLE_HOST,)):
    return event.parse({
        "slug": "b206-test", "name": "b206 test",
        "dates": {"start": dt.date(2026, 1, 1), "end": dt.date(2026, 12, 31)},
        "platform": {"kind": "ctfd", "base_url": "https://board.b206-platform.test"},
        "flag": {"prefixes": []},
        "rules": {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed",
                  "live_service_scope": ["*.test"], "public_fetch_allow": list(public)},
    }, src="<test>")


@pytest.fixture
def pinned():
    before = scope.pinned()
    prof = _profile()
    scope.pin(prof)
    yield prof
    if before is None:
        scope.unpin()
    else:
        scope.pin(before)


class StepClock:
    def __init__(self):
        self.now = 1000.0
        self.sleeps = []

    def __call__(self):
        return self.now

    def sleep(self, s):
        self.sleeps.append(s)
        self.now += s


class Transport:
    """Records every call; answers from a {substring: (status, headers, body[, final_url])} table."""

    def __init__(self, routes=None):
        self.calls = []
        self.routes = routes or {}

    def __call__(self, url, headers, timeout, max_bytes):
        self.calls.append((url, dict(headers)))
        for key, spec in self.routes.items():
            if key in url:
                status, hdrs, body = spec[:3]
                final = spec[3] if len(spec) > 3 else url
                return S.online.HTTPResult(status, hdrs, body if isinstance(body, bytes) else body.encode(),
                                           final)
        raise AssertionError(f"unexpected URL {url}")


JSON = {"Content-Type": "application/json"}
HTML = {"Content-Type": "text/html; charset=utf-8"}


def _client(transport, *, prof=None, box=None, clock=None, **kw):
    clock = clock or StepClock()
    return S.SocialFetchClient(transport=transport, clock=clock, sleep=clock.sleep,
                               profile=prof or _profile(), box=box, **kw)


def _box(tmp_path, cid="absolute", **osint):
    prof = pb.OsintProfile(**{"time_box_seconds": 100_000, "token_cap": 10_000, **osint})
    m = pb.meter(Budget(), workdir=tmp_path, osint=prof)
    pb.open_box(m, cid)
    return S.SocialBox(m, cid)


# --------------------------------------------------------------------------- ids and their times

def _iso(ms):
    return dt.datetime.fromtimestamp(ms / 1000, tz=dt.timezone.utc).isoformat(timespec="milliseconds")


def test_x_status_id_decodes_to_its_post_time_and_strips_tracking():
    ms = 1_700_000_000_000
    pid = ((ms - 1288834974657) << 22) | 12345
    r = S.parse_post_ref(f"https://x.com/someone/status/{pid}?s=20&t=abc")
    assert (r.platform, r.post_id, r.handle, r.kind) == ("x", str(pid), "someone", "status")
    assert r.id_time == "2023-11-14T22:13:20.000+00:00"
    assert r.canonical_url == f"https://twitter.com/someone/status/{pid}"
    # a pre-snowflake id carries no time
    assert S.parse_post_ref("https://twitter.com/jack/status/20").id_time is None
    assert S.parse_post_ref(f"https://twitter.com/i/web/status/{pid}").handle is None


def test_tiktok_mastodon_linkedin_and_bluesky_ids_decode():
    tt = (1_600_000_000 << 32) | 99
    r = S.parse_post_ref(f"https://www.tiktok.com/@some.user/video/{tt}?lang=en")
    assert r.platform == "tiktok" and r.handle == "some.user" and r.id_time == "2020-09-13T12:26:40.000+00:00"

    md = (1_700_000_000_123 << 16) | 7
    r = S.parse_post_ref(f"https://fosstodon.example/@alice/{md}")
    assert r.platform == "mastodon" and r.handle == "alice" and r.id_time == _iso(1_700_000_000_123)

    li = (1_700_000_000_000 << 22) | 1
    r = S.parse_post_ref(f"https://www.linkedin.com/feed/update/urn:li:activity:{li}/")
    assert r.platform == "linkedin" and r.id_time == _iso(1_700_000_000_000)
    r = S.parse_post_ref(f"https://www.linkedin.com/posts/someone_title-activity-{li}-AbCd")
    assert r.post_id == str(li)

    us = 1_700_000_000_000_000
    value, alphabet = (us << 10) | 5, "234567abcdefghijklmnopqrstuvwxyz"
    rkey = "".join(alphabet[(value >> (5 * i)) & 31] for i in reversed(range(13)))
    r = S.parse_post_ref(f"https://bsky.app/profile/someone.bsky.social/post/{rkey}")
    assert r.platform == "bluesky" and r.post_id == rkey and r.id_time == "2023-11-14T22:13:20.000+00:00"


def _ig_shortcode(media_id):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    out = ""
    while media_id:
        media_id, d = divmod(media_id, 64)
        out = alphabet[d] + out
    return out


def test_instagram_shortcode_decodes_to_media_id_and_approximate_time():
    ms = 1_725_000_000_000
    media = ((ms - 1314220021721) << 23) | 42
    code = _ig_shortcode(media)
    assert len(code) == 11
    r = S.parse_post_ref(f"https://www.instagram.com/someuser/p/{code}/?igsh=xyz")
    assert (r.platform, r.post_id, r.kind, r.numeric_id) == ("instagram", code, "post", media)
    assert r.id_time == _iso(ms) and "approximate" in r.id_time_basis
    assert r.canonical_url == f"https://www.instagram.com/p/{code}/"
    assert S.parse_post_ref(f"https://instagram.com/reel/{code}").kind == "reel"
    assert S.parse_post_ref(f"https://www.instagram.com/tv/{code}/").kind == "video"
    long = S.parse_post_ref("https://www.instagram.com/p/" + "A" * 30 + "/")
    assert long is not None and long.numeric_id is None and long.id_time is None
    story = S.parse_post_ref("https://www.instagram.com/stories/someuser/3412345678901234567/")
    assert story.kind == "story"


def test_youtube_reddit_vimeo_facebook_threads_forms():
    vid = "dQw4w9WgXcQ"
    for u in (f"https://youtu.be/{vid}?t=4", f"https://www.youtube.com/watch?v={vid}&list=x",
              f"https://m.youtube.com/shorts/{vid}", f"https://www.youtube-nocookie.com/embed/{vid}"):
        r = S.parse_post_ref(u)
        assert r.platform == "youtube" and r.post_id == vid and r.canonical_url.endswith(f"?v={vid}"), u
    assert S.parse_post_ref("https://www.youtube.com/watch?v=short") is None
    assert S.parse_post_ref(f"https://m.youtube.com/shorts/{vid}").kind == "short"

    r = S.parse_post_ref("https://old.reddit.com/r/ctf/comments/abc123/a_title/def456/")
    assert (r.post_id, r.kind, r.handle) == ("def456", "comment", "ctf")
    assert S.parse_post_ref("https://redd.it/abc123").canonical_url == "https://www.reddit.com/comments/abc123/"

    assert S.parse_post_ref("https://player.vimeo.com/video/76979871").post_id == "76979871"
    fb = S.parse_post_ref("https://m.facebook.com/permalink.php?story_fbid=pfbid0abc&id=1234&utm=1")
    assert fb.platform == "facebook" and fb.post_id == "pfbid0abc" and "utm" not in fb.canonical_url
    th = S.parse_post_ref("https://www.threads.net/@someone/post/C1abcdefgh")
    assert th.platform == "threads" and th.post_id == "C1abcdefgh"


def test_non_posts_and_malformed_urls_are_not_refs():
    for u in ("https://example.com/news/1", "https://www.instagram.com/someuser/", "javascript:alert(1)",
              "https://x.com/home", "https://www.facebook.com/somepage", "", "https://[::1/x",
              "https://netflix.com/u/status/12345678901", "https://youtu.be/" + "a" * 3000):
        assert S.parse_post_ref(u) is None, u[:80]
    # "x.com" inside another domain is not X, in text or in a link
    assert S.scan_article('<p>https://netflix.com/u/status/12345678901</p><a href="https://box.com/a/status/9">'
                          '</a>').refs == []
    # an id whose time bits land outside 2004..2100 decodes to no time rather than a bogus one
    assert S.parse_post_ref("https://www.tiktok.com/@a/video/12345678").id_time is None


# ------------------------------------------------------------------------------------------ the plan

def test_plan_names_the_endpoint_or_the_human_only_reason():
    pid = ((1_700_000_000_000 - 1288834974657) << 22)
    p = S.plan(f"https://x.com/someone/status/{pid}?s=20")
    assert p.mode == "oembed" and p.host == "publish.twitter.com"
    q = urllib.parse.parse_qs(urllib.parse.urlsplit(p.endpoint).query)
    assert q["url"] == [f"https://twitter.com/someone/status/{pid}"]       # the canonical URL, no ?s=20

    ig = S.plan("https://www.instagram.com/p/CxYz123AbCd/")
    assert ig.mode == "embed" and ig.endpoint == "https://www.instagram.com/p/CxYz123AbCd/embed/captioned/"

    human = {
        "https://www.facebook.com/page/posts/1234567890": "app access token",
        "https://www.threads.net/@a/post/C1abcdefgh": "app access token",
        "https://www.linkedin.com/feed/update/urn:li:activity:7130000000000000000/": "login",
        "https://www.instagram.com/stories/a/3412345678901234567/": "login",
        "https://www.tiktok.com/embed/v2/6718335390845095173": "handle",
        "https://fosstodon.example/@a/109300000000000000": "closed endpoint table",
    }
    for u, why in human.items():
        p = S.plan(u)
        assert p.mode == "human_only" and p.endpoint is None and why in p.reason, u
    assert S.plan("https://mastodon.social/@a/109300000000000000").mode == "oembed"
    with pytest.raises(S.SocialFetchError, match="not a recognised"):
        S.plan("https://example.com/")


def test_every_planned_endpoint_host_is_in_the_closed_table():
    urls = ["https://youtu.be/dQw4w9WgXcQ", "https://vimeo.com/76979871", "https://x.com/a/status/1",
            "https://www.tiktok.com/@a/video/6718335390845095173", "https://redd.it/abc",
            "https://bsky.app/profile/a.b/post/3l6oveex3ii2l", "https://mastodon.social/@a/109300000000000000",
            "https://www.instagram.com/p/CxYz123AbCd/"]
    hosts = {S.plan(u).host for u in urls}
    assert hosts == S.ENDPOINT_HOSTS


# ----------------------------------------------------------------------------- the article scanner

ARTICLE = """<!doctype html><html><head>
<title>Fallback title</title>
<meta property="og:title" content="Club night turns into a festival">
<meta property="article:published_time" content="2026-08-14T09:00:00Z">
<link rel="canonical" href="https://news.example.org/2026/08/club-night">
<script type="application/ld+json">{"@type":"NewsArticle","headline":"ld headline",
 "video":{"embedUrl":"https://www.tiktok.com/@dj.one/video/6718335390845095173"}}</script>
<script>window.__DATA__={"embed":"https:\\/\\/www.youtube.com\\/shorts\\/AbCdEfGhIjK"}</script>
</head><body>
<a href="/2026/08/other-story">related</a>
<a href="https://example.com/not-social">elsewhere</a>
<blockquote class="instagram-media" data-instgrm-permalink="https://www.instagram.com/p/CxYz123AbCd/?utm_source=ig_embed"></blockquote>
<p>Earlier post: https://www.instagram.com/p/CxYz123AbCd/ (same post, said twice)</p>
<blockquote class="twitter-tweet"><p>hello</p>&mdash; DJ (@djone)
<a href="https://twitter.com/djone/status/1585341984679469056?ref_src=twsrc%5Etfw">Oct 26, 2022</a></blockquote>
<iframe src="https://www.youtube-nocookie.com/embed/dQw4w9WgXcQ"></iframe>
<amp-instagram data-shortcode="C9abcDEFghi" width="1" height="1"></amp-instagram>
<p>Also on Bluesky: https://bsky.app/profile/dj.example/post/3l6oveex3ii2l</p>
</body></html>"""


def test_scan_article_finds_every_embedded_post_once_with_metadata():
    scan = S.scan_article(ARTICLE.encode(), base_url="https://news.example.org/2026/08/club-night")
    assert scan.title == "Club night turns into a festival"
    assert scan.published == "2026-08-14T09:00:00Z"
    assert scan.canonical == "https://news.example.org/2026/08/club-night"
    got = {(r.ref.platform, r.ref.post_id): r.where for r in scan.refs}
    assert got == {
        ("tiktok", "6718335390845095173"): "json-ld@embedUrl",
        ("youtube", "AbCdEfGhIjK"): "script",
        ("instagram", "CxYz123AbCd"): "blockquote@data-instgrm-permalink",
        ("x", "1585341984679469056"): "a@href",
        ("youtube", "dQw4w9WgXcQ"): "iframe@src",
        ("instagram", "C9abcDEFghi"): "amp-instagram",
        ("bluesky", "3l6oveex3ii2l"): "text",
    }
    assert not scan.truncated


def test_scan_article_takes_json_ld_date_and_caps_refs():
    page = ('<script type="application/ld+json">[{"datePublished":"2025-01-02"}]</script>'
            + "".join(f'<a href="https://x.com/u/status/{10**15 + i}">x</a>' for i in range(S.MAX_REFS + 20)))
    scan = S.scan_article(page)
    assert scan.published == "2025-01-02"
    assert len(scan.refs) == S.MAX_REFS and scan.truncated


# ---------------------------------------------------------------------------- block detection

def test_classify_block_statuses_redirects_and_walls():
    u = "https://www.instagram.com/p/X/embed/captioned/"
    for status in (401, 403, 407, 429, 451, 999):
        assert S.classify_block(status, {}, b"", u, social=True) is not None
    assert S.classify_block(200, {}, b"{}", u, social=True) is None
    assert S.classify_block(404, {}, b"", u, social=True) is None
    assert "login" in S.classify_block(302, {"location": "/accounts/login/?next=x"}, b"", u, social=True)
    assert "consent" in S.classify_block(302, {"Location": "https://consent.youtube.com/m?x"}, b"", u,
                                         social=True)
    assert "another host" in S.classify_block(301, {"Location": "https://cdn.example.net/x"}, b"", u,
                                              social=True)
    # a login/consent host is a wall by its name alone, even on an innocuous path
    for host in ("login.example.net", "accounts.example.net", "auth.example.net", "consent.example.net"):
        assert S.classify_block(302, {"Location": f"https://{host}/x"}, b"", u, social=True) == \
            f"redirect to a login or consent page ({host})"
    assert S.classify_block(301, {"Location": "/p/X/embed/"}, b"", u, social=True) is None
    challenge = b"<html><script src='/cdn-cgi/challenge-platform/h/b'></script></html>"
    assert S.classify_block(200, {}, challenge, u, social=False) is not None
    login_form = b"<html><header><form><input type='password' name='pw'></form></header><p>story</p></html>"
    assert S.classify_block(200, {}, login_form, "https://news.example.org/a", social=False) is None
    assert S.classify_block(200, {}, login_form, u, social=True) == "login wall"


# ----------------------------------------------------------------------------- the fetch client

X_PID = 1585341984679469056
X_URL = f"https://x.com/djone/status/{X_PID}"
X_OEMBED = json.dumps({
    "url": f"https://twitter.com/djone/status/{X_PID}", "author_name": "DJ One",
    "author_url": "https://twitter.com/djone", "provider_name": "Twitter", "type": "rich",
    "html": ('<blockquote class="twitter-tweet"><p lang="en">Tonight at the club '
             '<a href="https://t.co/abc">pic.twitter.com/abc</a> see https://www.instagram.com/p/CxYz123AbCd/</p>'
             f'&mdash; DJ One (@djone) <a href="https://twitter.com/djone/status/{X_PID}?ref_src=x">'
             'October 26, 2022</a></blockquote><script>ignored()</script>'),
})


def test_fetch_post_oembed_returns_bounded_fields_and_records_the_attempt(tmp_path):
    t = Transport({"publish.twitter.com": (200, JSON, X_OEMBED)})
    box = _box(tmp_path)
    c = _client(t, box=box)
    out = c.fetch_post(X_URL)
    assert len(t.calls) == 1
    url, headers = t.calls[0]
    assert url == S.plan(X_URL).endpoint
    assert headers["User-Agent"] == S.GENERIC_USER_AGENT
    assert not {k.lower() for k in headers} & {"cookie", "authorization"}
    f = out["fields"]
    assert f["author_name"] == "DJ One" and "Tonight at the club" in f["text"] and "ignored" not in f["text"]
    assert "html" not in f
    assert [p["post_id"] for p in out["linked_posts"]] == ["CxYz123AbCd"]     # the post itself is excluded
    assert out["requires_human_pin"] is True and out["automatic_answer"] is None
    assert out["ref"]["id_time"] == "2022-10-26T18:45:58.034+00:00"
    recs = hypothesis.entries("absolute", tmp_path)
    assert [(r["method"], r["result"]) for r in recs] == [(f"social oembed x {X_PID}", "inconclusive")]
    assert budget.is_stopped("absolute", workdir=tmp_path) is None


def test_scope_refuses_a_host_the_event_does_not_list_before_any_request():
    t = Transport({"publish.twitter.com": (200, JSON, X_OEMBED)})
    c = _client(t, prof=_profile(public=("www.youtube.com",)))
    with pytest.raises(S.SocialOutOfScope) as ei:
        c.fetch_post(X_URL)
    assert "publish.twitter.com" in str(ei.value) and "rules.public_fetch_allow" in str(ei.value)
    assert isinstance(ei.value, scope.OutOfScope)
    assert t.calls == [] and c.request_count == 0


def test_request_cap_per_host_cap_and_pacing():
    yt = json.dumps({"title": "a video", "author_name": "chan"})
    t = Transport({"www.youtube.com/oembed": (200, JSON, yt), "vimeo.com/api": (200, JSON, yt)})
    clock = StepClock()
    c = _client(t, clock=clock, request_cap=3, per_host_cap=2, min_interval=2.0)
    c.fetch_post("https://youtu.be/aaaaaaaaaaa")
    clock.now += 0.5
    c.fetch_post("https://youtu.be/bbbbbbbbbbb")
    assert clock.sleeps == [1.5]                      # 2.0 interval minus the 0.5 already elapsed
    with pytest.raises(S.SocialFetchError, match="per-host cap of 2"):
        c.fetch_post("https://youtu.be/ccccccccccc")
    c.fetch_post("https://vimeo.com/76979871")
    with pytest.raises(S.SocialFetchError, match="request cap of 3"):
        c.fetch_post("https://vimeo.com/76979872")
    assert len(t.calls) == 3
    with pytest.raises(ValueError):
        _client(t, min_interval=0.5)
    with pytest.raises(ValueError):
        _client(t, request_cap=S.MAX_REQUESTS + 1)


def test_a_transport_failure_still_counts_against_the_caps():
    import urllib.error

    class Failing:
        def __init__(self):
            self.calls = 0

        def __call__(self, url, headers, timeout, max_bytes):
            self.calls += 1
            raise urllib.error.URLError("synthetic connection reset")

    t = Failing()
    c = _client(t, request_cap=1)
    with pytest.raises(urllib.error.URLError):
        c.fetch_post("https://youtu.be/aaaaaaaaaaa")
    assert t.calls == 1 and c.request_count == 1
    with pytest.raises(S.SocialFetchError, match="request cap of 1"):
        c.fetch_post("https://vimeo.com/76979871")
    assert t.calls == 1                                # refused before the transport ran
    t2 = Failing()
    c2 = _client(t2, per_host_cap=1)
    with pytest.raises(urllib.error.URLError):
        c2.fetch_post("https://youtu.be/aaaaaaaaaaa")
    with pytest.raises(S.SocialFetchError, match="per-host cap of 1"):
        c2.fetch_post("https://youtu.be/bbbbbbbbbbb")
    assert t2.calls == 1 and c2.request_count == 1


def test_a_block_raises_the_human_only_flag_writes_the_handoff_and_stops_the_loop(tmp_path):
    t = Transport({"publish.twitter.com": (429, JSON, "{}")})
    box = _box(tmp_path)
    c = _client(t, box=box)
    with pytest.raises(S.HumanOnlyStop) as ei:
        c.fetch_post(X_URL)
    e = ei.value
    assert "rate limited" in e.reason and e.platform == "x"
    assert e.handoff is not None and e.handoff.is_file()
    doc = json.loads(e.handoff.read_text())
    assert doc["reason"] == S.REASON_SOCIAL_HUMAN_ONLY
    assert [q["method"] for q in doc["queries_tried"]] == [f"social oembed x {X_PID}"]
    assert doc["queries_tried"][0]["result"] == "negative"
    assert budget.is_stopped("absolute", workdir=tmp_path) == "manual"
    flags = [r for r in ledger.read(tmp_path) if r["event"] == S.HUMAN_ONLY_EVENT]
    assert len(flags) == 1 and flags[0]["host"] == "publish.twitter.com"
    # no retry: the same client refuses, and so does a fresh client in the same box
    with pytest.raises(S.HumanOnlyStop, match="already stopped"):
        c.fetch_post("https://youtu.be/dQw4w9WgXcQ")
    t2 = Transport({"www.youtube.com": (200, JSON, "{}")})
    with pytest.raises(S.HumanOnlyStop) as ei2:
        _client(t2, box=box).fetch_post("https://youtu.be/dQw4w9WgXcQ")
    assert ei2.value.handoff == e.handoff
    assert len(t.calls) == 1 and t2.calls == []
    assert len(list((tmp_path / "osint-handoff").glob("*.json"))) == 1


def test_human_only_platform_flags_before_any_request(tmp_path):
    t = Transport()
    box = _box(tmp_path, cid="viz")
    with pytest.raises(S.HumanOnlyStop) as ei:
        _client(t, box=box).fetch_post("https://www.facebook.com/page/posts/1234567890")
    assert t.calls == [] and ei.value.handoff.is_file() and "app access token" in ei.value.reason
    assert budget.is_stopped("viz", workdir=tmp_path) == "manual"


def test_without_a_box_the_flag_still_stops_and_says_how_to_hand_off():
    c = _client(Transport({"publish.twitter.com": (403, HTML, "<html>no</html>")}))
    with pytest.raises(S.HumanOnlyStop) as ei:
        c.fetch_post(X_URL)
    assert ei.value.handoff is None and "ctf osint handoff" in str(ei.value)
    assert c.stopped is ei.value


def test_html_where_oembed_json_was_expected_is_a_wall(tmp_path):
    t = Transport({"www.tiktok.com": (200, HTML, "<html><body>Please wait</body></html>")})
    with pytest.raises(S.HumanOnlyStop, match="oEmbed JSON was expected"):
        _client(t, box=_box(tmp_path)).fetch_post("https://www.tiktok.com/@a/video/6718335390845095173")


IG_EMBED = """<html><body><div class="Embed"><div class="Header"><a class="Username" href="#">
<span class="UsernameText">clubbad.fcn</span></a></div>
<img class="EmbeddedMediaImage" alt="Crowd at the lake stage" src="x.jpg">
<div class="Caption"><a class="CaptionUsername">clubbad.fcn</a> Summer night at the lake, Aug 2026</div>
<time datetime="2026-08-09T20:00:00.000Z"></time></div></body></html>"""


def test_instagram_public_embed_is_parsed_and_an_empty_embed_is_a_wall(tmp_path):
    t = Transport({"www.instagram.com/p/CxYz123AbCd/embed": (200, HTML, IG_EMBED)})
    out = _client(t).fetch_post("https://www.instagram.com/p/CxYz123AbCd/")
    assert out["mode"] == "embed"
    assert out["fields"] == {"username": "clubbad.fcn", "caption": "Summer night at the lake, Aug 2026",
                             "embed_time": "2026-08-09T20:00:00.000Z", "image_alt": "Crowd at the lake stage"}
    assert t.calls[0][1]["Accept"] == "text/html"
    empty = Transport({"www.instagram.com": (200, HTML, "<html><body><div class='Embed'></div></body></html>")})
    with pytest.raises(S.HumanOnlyStop, match="came back empty"):
        _client(empty, box=_box(tmp_path)).fetch_post("https://www.instagram.com/p/CxYz123AbCd/")


def test_redirects_same_host_followed_once_login_is_a_wall_cross_host_refused(tmp_path):
    first = S.plan("https://youtu.be/dQw4w9WgXcQ").endpoint
    t = Transport({"/oembed?format=json": (301, {"Location": "/oembed2"}, ""),
                   "/oembed2": (200, JSON, json.dumps({"title": "t"}))})
    out = _client(t).fetch_post("https://youtu.be/dQw4w9WgXcQ")
    assert [u for u, _ in t.calls] == [first, "https://www.youtube.com/oembed2"]
    assert out["fields"]["title"] == "t"

    loop = Transport({"/oembed": (302, {"Location": "/oembed?again=1"}, "")})
    with pytest.raises(S.SocialFetchError, match="redirected more than"):
        _client(loop).fetch_post("https://youtu.be/dQw4w9WgXcQ")
    assert len(loop.calls) == 1 + S.MAX_REDIRECT_HOPS == 2      # the first request and one hop, no more

    login = Transport({"vimeo.com": (302, {"Location": "https://vimeo.com/log_in/../login"}, "")})
    with pytest.raises(S.HumanOnlyStop, match="login"):
        _client(login).fetch_post("https://vimeo.com/76979871")

    moved = Transport({"vimeo.com": (200, JSON, "{}", "https://evil.example.net/x")})
    with pytest.raises(S.SocialFetchError, match="another host"):
        _client(moved).fetch_post("https://vimeo.com/76979871")


def test_a_closed_osint_box_refuses_before_any_request(tmp_path):
    box = _box(tmp_path, token_cap=100)
    box.meter.add_spend("absolute", 0.5, 150)
    t = Transport({"publish.twitter.com": (200, JSON, X_OEMBED)})
    with pytest.raises(S.HumanOnlyStop) as ei:
        _client(t, box=box).fetch_post(X_URL)
    assert t.calls == [] and budget.OSINT_TOKEN_CAP in ei.value.reason and ei.value.handoff.is_file()


def test_a_settled_fetch_is_not_rerun(tmp_path):
    box = _box(tmp_path)
    t = Transport({"www.reddit.com": (404, JSON, "{}")})
    with pytest.raises(S.SocialFetchError, match="404.*removed"):
        _client(t, box=box).fetch_post("https://redd.it/abc123")
    with pytest.raises(S.AlreadyTried, match="already tried"):
        _client(t, box=box).fetch_post("https://www.reddit.com/comments/abc123/")
    assert len(t.calls) == 1


def test_secret_and_protected_identity_never_leave(monkeypatch):
    t = Transport({"www.youtube.com": (200, JSON, "{}")})
    c = _client(t, protected_identifiers=("dQw4w9WgXcQ",))
    with pytest.raises(S.SocialFetchError, match="protected"):
        c.fetch_post("https://youtu.be/dQw4w9WgXcQ")
    monkeypatch.setenv("CTF_OSINT_PRIVATE_IDENTIFIERS", "abcdefghijk")
    with pytest.raises(S.SocialFetchError, match="protected"):
        _client(t).fetch_post("https://youtu.be/abcdefghijk")
    with pytest.raises(S.SocialFetchError, match="secret-shaped"):
        _client(t).scrape_article(f"https://{ARTICLE_HOST}/a?x=" + "AK" + "IA" + "Q" * 16)  # key-shaped
    assert t.calls == []


# --------------------------------------------------------------------------- the article scrape

def test_scrape_article_returns_post_refs_and_refuses_bad_targets(tmp_path):
    t = Transport({ARTICLE_HOST: (200, HTML, ARTICLE)})
    box = _box(tmp_path)
    out = _client(t, box=box).scrape_article(f"https://{ARTICLE_HOST}/2026/08/club-night#comments")
    assert t.calls[0][0] == f"https://{ARTICLE_HOST}/2026/08/club-night"         # no fragment sent
    assert {(r["platform"], r["post_id"]) for r in out["refs"]} >= {("instagram", "CxYz123AbCd"),
                                                                     ("x", str(X_PID))}
    assert out["title"] == "Club night turns into a festival" and out["requires_human_pin"] is True
    rec = hypothesis.entries("absolute", tmp_path)[-1]
    assert rec["result"] == "inconclusive" and "instagram:CxYz123AbCd" in rec["evidence"]

    bad = {
        "http://news.example.org/a": "plain HTTPS",
        "https://www.instagram.com/p/CxYz123AbCd/": "social platform",
        "https://publish.twitter.com/x": "social platform",
        "https://203.0.113.5/a": "literal-IP",
        "https://intranet.corp/a": "local or internal",
        "https://localhost/a": "local or internal",
        f"https://{ARTICLE_HOST}/a?access_token=1": "credential-shaped",
        f"https://user:pw@{ARTICLE_HOST}/a": "no credentials",
        f"https://{ARTICLE_HOST}:8443/a": "port 443",
        "https://other-news.example.com/a": "public_fetch_allow",
        # a subdomain of a social platform is social too, listed in the event or not
        "https://mbasic.facebook.com/story.php?story_fbid=1&id=2": "social platform",
        "https://l.facebook.com/l.php?u=x": "social platform",
        "https://vm.tiktok.com/ZMabcdef/": "social platform",
        "https://embed.bsky.app/x": "social platform",
    }
    t2 = Transport()
    sub_prof = _profile(public=(ARTICLE_HOST, "mbasic.facebook.com", "l.facebook.com", "vm.tiktok.com",
                                "embed.bsky.app"))
    for url, why in bad.items():
        with pytest.raises(S.SocialFetchError, match=why):
            _client(t2, prof=sub_prof).scrape_article(url)
    assert t2.calls == []


def test_social_host_rule_covers_every_table_host_and_only_social_domains():
    for host in S.SOCIAL_HOSTS | S.ENDPOINT_HOSTS:
        assert S._is_social_host(host), host
    for host in ("netflix.com", "box.com", "notx.com", "facebook.com.example.org", ARTICLE_HOST):
        assert not S._is_social_host(host), host
    assert S._is_social_host("WWW.Facebook.COM.")


# --------------------------------------------------------------------------------- size limits

def test_a_body_over_the_byte_cap_is_refused_and_one_at_the_cap_is_read():
    over = b"<html>" + b" " * (S.MAX_RESPONSE_BYTES - 5)
    t = Transport({ARTICLE_HOST: (200, HTML, over)})
    with pytest.raises(S.SocialFetchError, match="byte cap"):
        _client(t).scrape_article(f"https://{ARTICLE_HOST}/a")
    assert len(t.calls) == 1
    at = b"<html><a href='https://youtu.be/dQw4w9WgXcQ'>v</a>"
    at += b" " * (S.MAX_RESPONSE_BYTES - len(at))
    out = _client(Transport({ARTICLE_HOST: (200, HTML, at)})).scrape_article(f"https://{ARTICLE_HOST}/a")
    assert [r["post_id"] for r in out["refs"]] == ["dQw4w9WgXcQ"] and out["truncated"] is False


def test_scan_article_input_cap_sets_truncated_for_bytes_and_text():
    head = '<a href="https://youtu.be/dQw4w9WgXcQ">v</a>'
    tail = '<a href="https://youtu.be/aaaaaaaaaaa">late</a>'
    pad = S.MAX_RESPONSE_BYTES - len(head)
    for page in (head + " " * pad + tail, (head + " " * pad + tail).encode()):
        scan = S.scan_article(page)
        assert scan.truncated is True
        assert [r.ref.post_id for r in scan.refs] == ["dQw4w9WgXcQ"]     # nothing past the cap is read
    for page in (head + " " * pad, (head + " " * pad).encode()):              # exactly at the cap
        assert S.scan_article(page).truncated is False


def _nested(depth):
    v = "leaf"
    for _ in range(depth):
        v = [v]
    return v


def test_oembed_json_beyond_structural_bounds_is_refused():
    url = "https://youtu.be/dQw4w9WgXcQ"
    deep = json.dumps({"title": "t", "x": _nested(12)})
    with pytest.raises(S.SocialFetchError, match="structural bounds"):
        _client(Transport({"www.youtube.com": (200, JSON, deep)})).fetch_post(url)
    wide = json.dumps({"title": "t", "x": [[0] * 256] * 100})          # 25,600 nodes, all shallow
    with pytest.raises(S.SocialFetchError, match="structural bounds"):
        _client(Transport({"www.youtube.com": (200, JSON, wide)})).fetch_post(url)
    ok = json.dumps({"title": "t", "x": _nested(8)})
    assert _client(Transport({"www.youtube.com": (200, JSON, ok)})).fetch_post(url)["fields"]["title"] == "t"


def test_oembed_json_depth_limit_is_exact():
    # the top-level object is depth 0, "x" is depth 1, so _nested(n) puts its leaf at depth n + 1:
    # depth 10 is the deepest allowed node, depth 11 is refused
    url = "https://youtu.be/dQw4w9WgXcQ"
    deepest_ok = json.dumps({"title": "t", "x": _nested(9)})
    got = _client(Transport({"www.youtube.com": (200, JSON, deepest_ok)})).fetch_post(url)
    assert got["fields"]["title"] == "t"
    one_deeper = json.dumps({"title": "t", "x": _nested(10)})
    with pytest.raises(S.SocialFetchError, match="structural bounds"):
        _client(Transport({"www.youtube.com": (200, JSON, one_deeper)})).fetch_post(url)


def test_an_endpoint_outside_the_closed_table_is_refused_before_any_request(monkeypatch):
    # defense in depth: even if the plan table were edited to point elsewhere, the client refuses
    monkeypatch.setitem(S.OEMBED, "youtube", f"https://{ARTICLE_HOST}/oembed?url=")
    t = Transport({ARTICLE_HOST: (200, JSON, "{}")})
    with pytest.raises(S.SocialFetchError, match="closed social endpoint table"):
        _client(t).fetch_post("https://youtu.be/dQw4w9WgXcQ")
    assert t.calls == []


# ------------------------------------------------------------------------ the human-only flag, again

def test_flag_human_only_writes_one_handoff_however_often_it_is_called(tmp_path):
    box = _box(tmp_path)
    first = S.flag_human_only(box, reason="login wall", url=X_URL, platform="x")
    second = S.flag_human_only(box, reason="login wall again", url=X_URL, platform="x")
    assert first == second and first.is_file()
    assert len(list((tmp_path / "osint-handoff").glob("*.json"))) == 1
    assert json.loads(first.read_text())["reason"] == S.REASON_SOCIAL_HUMAN_ONLY
    assert len([r for r in ledger.read(tmp_path) if r["event"] == S.HUMAN_ONLY_EVENT]) == 2


def test_a_closed_box_wins_over_a_human_only_platform(tmp_path):
    box = _box(tmp_path, token_cap=100)
    box.meter.add_spend("absolute", 0.5, 150)
    t = Transport()
    with pytest.raises(S.HumanOnlyStop) as ei:
        _client(t, box=box).fetch_post("https://www.facebook.com/page/posts/1234567890")
    assert "the OSINT box is closed" in ei.value.reason and budget.OSINT_TOKEN_CAP in ei.value.reason
    assert t.calls == [] and hypothesis.entries("absolute", tmp_path) == []
    assert [r for r in ledger.read(tmp_path) if r["event"] == S.HUMAN_ONLY_EVENT] == []
    assert len(list((tmp_path / "osint-handoff").glob("*.json"))) == 1


def test_article_login_form_is_not_a_wall_but_a_403_is(tmp_path):
    page = "<html><form><input type=password></form><a href='https://youtu.be/dQw4w9WgXcQ'>v</a></html>"
    out = _client(Transport({ARTICLE_HOST: (200, HTML, page)})).scrape_article(f"https://{ARTICLE_HOST}/a")
    assert [r["post_id"] for r in out["refs"]] == ["dQw4w9WgXcQ"]
    with pytest.raises(S.HumanOnlyStop, match="403"):
        _client(Transport({ARTICLE_HOST: (403, HTML, "no")}), box=_box(tmp_path)).scrape_article(
            f"https://{ARTICLE_HOST}/a")
    with pytest.raises(S.SocialFetchError, match="did not return an HTML page"):
        _client(Transport({ARTICLE_HOST: (200, JSON, '{"a":1}')})).scrape_article(f"https://{ARTICLE_HOST}/b")


# ------------------------------------------------------------------------ the default transport

class _Toy(http.server.BaseHTTPRequestHandler):
    seen = []

    def do_GET(self):  # noqa: N802
        _Toy.seen.append((self.path, self.headers.get("Cookie")))
        if self.path == "/start":
            self.send_response(302)
            self.send_header("Set-Cookie", "sid=abc")
            self.send_header("Location", "/accounts/login/")
            self.end_headers()
        elif self.path == "/big":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", "64")
            self.end_headers()
            self.wfile.write(b"y" * 64)
        else:
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"x" * 64)

    def log_message(self, *a):
        pass


def test_default_transport_follows_no_redirect_and_sends_no_cookie():
    srv = http.server.HTTPServer(("127.0.0.1", 0), _Toy)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        base = f"http://127.0.0.1:{srv.server_port}"
        _Toy.seen.clear()
        res = S._urllib_transport(base + "/start", {"User-Agent": "t"}, 30.0, 1024)
        assert res.status == 302 and res.headers.get("Location") == "/accounts/login/"
        assert [p for p, _ in _Toy.seen] == ["/start"]                         # the redirect not followed
        res2 = S._urllib_transport(base + "/next", {"User-Agent": "t"}, 30.0, 32)
        assert len(res2.body) == 33                                            # read stops at cap + 1
        assert _Toy.seen[-1][1] is None                                       # no cookie jar
        # an advertised Content-Length over the cap is refused before the body is read
        with pytest.raises(S.SocialFetchError, match="byte cap"):
            S._urllib_transport(base + "/big", {"User-Agent": "t"}, 30.0, 63)
        assert S._urllib_transport(base + "/big", {"User-Agent": "t"}, 30.0, 64).body == b"y" * 64
    finally:
        srv.shutdown()
        srv.server_close()


# -------------------------------------------------------------------------------------------- CLI

def _cli(monkeypatch, tmp_path, *argv):
    from ctf.cli import social as cli_social
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    p = argparse.ArgumentParser()
    cli_social.add_arguments(p)
    return cli_social.run(p.parse_args(list(argv)))


def test_cli_offline_parse_plan_scan(monkeypatch, tmp_path, capsys):
    assert _cli(monkeypatch, tmp_path, "parse", X_URL, "--json") == 0
    rows = json.loads(capsys.readouterr().out)
    assert rows[0]["ref"]["id_time"] == "2022-10-26T18:45:58.034+00:00"
    assert _cli(monkeypatch, tmp_path, "parse", "https://example.com/") == 2
    capsys.readouterr()
    assert _cli(monkeypatch, tmp_path, "plan", "https://www.facebook.com/p/posts/123456") == 4
    assert "human_only" in capsys.readouterr().out
    f = tmp_path / "saved.html"
    f.write_text(ARTICLE)
    assert _cli(monkeypatch, tmp_path, "scan", str(f), "--json") == 0
    assert len(json.loads(capsys.readouterr().out)["refs"]) == 7


def test_cli_hosts_reports_what_the_event_lists(monkeypatch, tmp_path, capsys):
    before = scope.pinned()
    scope.pin(_profile(public=("www.youtube.com",)))
    try:
        assert _cli(monkeypatch, tmp_path, "hosts") == 0
    finally:
        scope.pin(before) if before else scope.unpin()
    out = capsys.readouterr().out
    assert "ALLOWED  www.youtube.com" in out and "not listed  publish.twitter.com" in out
    assert "events/b206-test/event.toml" in out


def test_cli_fetch_needs_online_then_writes_handoff_on_a_wall(monkeypatch, tmp_path, capsys, pinned):
    t = Transport({"publish.twitter.com": (200, HTML, "<html><title>Log in</title></html>")})
    monkeypatch.setattr(S, "_urllib_transport", t)
    assert _cli(monkeypatch, tmp_path, "fetch", X_URL, "--challenge", "abs") == 2
    assert "--online" in capsys.readouterr().err and t.calls == []
    assert _cli(monkeypatch, tmp_path, "fetch", X_URL, "--online", "--challenge", "abs") == 4
    err = capsys.readouterr().err
    assert "human-only (x)" in err and "handoff written" in err
    assert budget.is_stopped("abs", workdir=tmp_path) == "manual"
    assert len(t.calls) == 1


def test_cli_fetch_and_article_succeed(monkeypatch, tmp_path, capsys, pinned):
    t = Transport({"publish.twitter.com": (200, JSON, X_OEMBED), ARTICLE_HOST: (200, HTML, ARTICLE)})
    monkeypatch.setattr(S, "_urllib_transport", t)
    assert _cli(monkeypatch, tmp_path, "fetch", X_URL, "--online", "--challenge", "abs") == 0
    assert json.loads(capsys.readouterr().out)["fields"]["author_name"] == "DJ One"
    assert _cli(monkeypatch, tmp_path, "article", f"https://{ARTICLE_HOST}/a", "--online",
                "--challenge", "abs") == 0
    assert len(json.loads(capsys.readouterr().out)["refs"]) == 7
    assert [r["event"] for r in ledger.read(tmp_path)][0] == "budget_challenge"   # the box was opened
