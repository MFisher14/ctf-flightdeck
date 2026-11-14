"""B-117: the comment and route crawler (solvers/web/route_crawl.py).

The site is synthetic: a chain of pages in the shape of the 2026 Spooky camera challenge (a
comment names the next directory, a GIF frame names the page in it, the last GIF holds the flag in
a frame), served from a dict or from a fake HTTP server this test starts on 127.0.0.1. Every route,
identifier and sentence in it is invented here; only the shape is the challenge's. The OCR is a
stand-in that tells the bar frames apart (tests/b117_fixtures.py). No real host is contacted: the
out-of-scope URLs below are refused by a scope guard before any name is resolved."""
from __future__ import annotations

import itertools
import json
import random
import re
import socket
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

import b117_fixtures as fx
import image_carve
import route_crawl as rc
from ctf import flagfmt

pytestmark = pytest.mark.needs_tool("py:PIL")

# The live tests need a profile whose own scope lists loopback: solve() checks the profile it is
# handed, and the client then checks the suite's pinned event. CLOSED has an empty scope.
PROFILE = fx.profile(scope=("127.0.0.1",))
CLOSED = fx.profile(slug="b117-closed")
# Every engine call below gets an explicit budget: the production defaults are wall-clock seconds,
# and this suite runs on a machine loaded far past its cores.
BUDGET = 3600.0
FF = flagfmt.for_profile(PROFILE)
FLAG = "CSCTF{read_off_the_last_frame}"
HTML = "text/html; charset=utf-8"


def gif(first_bar):
    """A two-frame GIF whose frames carry bars first_bar + 1 and first_bar + 2 pixels wide."""
    return fx.gif_bytes([fx.bar_frame(first_bar), fx.bar_frame(first_bar + 1)], durations=[500, 10])


# what the stand-in OCR reads in the frame with a bar of key + 1 pixels
PAINTED = {1: "panel dark  KX-58", 3: "next BAY 63", 5: f"sign: {FLAG}"}


def ocr(texts=PAINTED):
    def read(png, deadline=None):
        first, count = fx.bar_of(png)
        return texts.get(count - 1, "") if first == 0 else ""
    return read


def no_codes(data, **kw):
    return []


def site(**extra):
    pages = {
        "/": (HTML, b"<html><!-- BAY-41 is still listed. Older decks: /decks/aft/ -->"
                    b"<body><h1>Decks</h1><a href='/about'>about</a><script src=\"static/site.js\"></script>"
                    b"<a href='https://elsewhere.test/x'>partner</a><a href='/logout'>log out</a>"
                    b"<a href='mailto:ops@site.test'>mail</a><a href='#top'>top</a></body></html>"),
        "/about": (HTML, b"<html><body>Nothing here.</body></html>"),
        "/static/site.js": ("application/javascript", b"// player\nconst status = '/api/status';\n"),
        "/api/status": ("application/json", b'{"ok": true}'),
        "/decks/aft/bay-41": (HTML, b"<html><!-- the rest moved to /decks/hold/ -->"
                                       b"<img src='/clips/bay-41.gif' data-reveal-after='4200'></html>"),
        "/clips/bay-41.gif": ("image/gif", gif(0)),
        "/decks/hold/kx-58": (HTML, b"<html><!-- copy kept at /decks/keel/ --><img src='/clips/kx-58.gif'></html>"),
        "/clips/kx-58.gif": ("image/gif", gif(2)),
        "/decks/keel/bay-63": (HTML, b"<html><img src='/clips/final.gif'></html>"),
        "/clips/final.gif": ("image/gif", gif(4)),
    }
    pages.update(extra)
    return pages


def dict_fetch(pages, log):
    def fetch(route):
        log.append(route)
        if route in pages:
            return 200, pages[route][0], pages[route][1]
        return 404, "text/plain", b"not found"
    return fetch


def run(pages=None, log=None, **kw):
    log = [] if log is None else log
    kw.setdefault("read", ocr())
    kw.setdefault("codes", no_codes)
    kw.setdefault("sleep", lambda s: None)
    return rc.crawl(dict_fetch(site() if pages is None else pages, log), FF, **kw), log


# ---- harvesting ------------------------------------------------------------------------------------

def test_comments_paths_and_script_routes():
    script = ("/* block one\n spans */ var a = 'http://x.test/p'; // tail note\n"
              "//whole line\nvar u = \"//cdn.test/lib.js\"; /// triple\n/* two */")
    assert rc.comments_of(script, "script") == ["block one\n spans", "two", "tail note", "whole line", "/ triple"]
    assert rc.comments_of("a { } /* only blocks */ // not a comment in css", "style") == ["only blocks"]
    text = ("see /decks/aft/ and /decks/aft/bay-41, or /a_b/c%20d.txt. Not 12/05/2026, not 3/4, not and/or, "
            "not TCP/IP, not http://host.test/skip, but (/x/y) yes and /decks/aft/ again; / alone is nothing")
    assert rc.path_tokens(text) == ["/decks/aft/", "/decks/aft/bay-41", "/a_b/c%20d.txt", "/x/y"]
    assert rc.path_tokens("/" + "a" * 600) == [] and rc.path_tokens("") == [] and rc.path_tokens(None) == []
    js = """fetch('/api/decks'); load("./clips/a.gif"); x = `../up.json`; y = 'plain word'; z = "img/cam.png";
            w = 'a b.gif'; v = "/api/decks";"""
    assert rc.script_routes(js) == ["/api/decks", "./clips/a.gif", "../up.json", "img/cam.png"]


def test_sniff():
    assert rc.sniff("/x", b"GIF89a....") == "gif" and rc.sniff("/x", b"\x89PNG\r\n") == "image"
    assert rc.sniff("/x", b"\xff\xd8\xff\xe0") == "image" and rc.sniff("/x.html", b"ab\x00cd") == "other"
    assert rc.sniff("/x", b"  <!DOCTYPE html><p>") == "html" and rc.sniff("/x", b"<p>hi", "text/html") == "html"
    assert rc.sniff("/page.php?id=1", b"hello") == "html" and rc.sniff("/x", b"<!-- note -->") == "html"
    assert rc.sniff("/a.js", b"var a") == "script" and rc.sniff("/a", b"var a", "application/javascript") == "script"
    assert rc.sniff("/a.css", b"a{}") == "style" and rc.sniff("/a", b"a{}", "text/css") == "style"
    assert rc.sniff("/robots.txt", b"Disallow: /x") == "text" and rc.sniff("/api", b"{}", "application/json") == "text"


def test_harvest_html():
    body = (b"<html><head><!-- first: BAY-41 lives under /decks/aft/ --><style>/* style note /css/hidden/ */</style>"
            b"<script>// script note\nvar next = '/api/next';</script></head><body>"
            b"<p>Unit TRN-26 is at /visible/path today.</p><img src='cam.gif' alt='feed KX 58' data-reveal-after>"
            b"<img data-gif='/clips/b.gif' srcset='a.png 1x, /b.png 2x'><a href='/about#team'>x</a>"
            b"<input type='hidden' value='CSCTF{in_the_page}'><div data-delay='4200' title='plain title'></div>"
            b"<a href=''>empty</a><form action='/search'></form><p data-note='just words here'></p>"
            b"<!-- --></body></html>")
    page = rc.harvest("/decks/index.html", body, HTML, FF)
    assert page.kind == "html" and page.flags == ["CSCTF{in_the_page}"]
    assert page.comments == ["first: BAY-41 lives under /decks/aft/", "script note", "style note /css/hidden/"]
    assert page.links == ["cam.gif", "/clips/b.gif", "a.png", "/b.png", "/about#team", "/search", "/api/next"]
    assert page.named == ["/decks/aft/", "/css/hidden/", "/visible/path"]
    assert page.identifiers == ["BAY-41", "TRN-26", "KX 58"]
    assert page.reveal == ["<img data-reveal-after>", "<div data-delay='4200'>"]
    assert rc.harvest("/x", body, HTML).flags == []                  # no flag format: none looked for


def test_harvest_other_kinds(monkeypatch):
    js = rc.harvest("/static/site.js", b"/* go to /decks/bilge/ */ const u = '/api/x'; // unit BAY-41\n", "", FF)
    assert (js.kind, js.comments, js.links, js.named, js.identifiers) == (
        "script", ["go to /decks/bilge/", "unit BAY-41"], ["/api/x"], ["/decks/bilge/"], ["BAY-41"])
    robots = rc.harvest("/robots.txt", b"User-agent: *\nDisallow: /backup/old/\n# CSCTF{in_robots}\n", "text/plain", FF)
    assert (robots.kind, robots.named, robots.flags, robots.comments) == ("text", ["/backup/old/"], ["CSCTF{in_robots}"], [])
    css = rc.harvest("/a.css", b"a { background: url('/img/x.png') } /* KX-58 */", "", FF)
    assert (css.kind, css.comments, css.links, css.identifiers) == ("style", ["KX-58"], [], ["KX-58"])
    picture = rc.harvest("/a.gif", gif(0), "image/gif", FF)
    assert (picture.kind, picture.comments, picture.links) == ("gif", [], [])
    assert rc.harvest("/blob", b"\x00\x01CSCTF{in_a_blob}", "", FF).flags == ["CSCTF{in_a_blob}"]
    monkeypatch.setattr(rc, "MAX_TEXT", 30)
    cut = rc.harvest("/x.html", b"<html><!-- kept --><p>" + b"a" * 100 + b"<!-- lost -->", HTML, FF)
    assert cut.comments == ["kept"] and cut.notes == ["only the first 30 characters were parsed"]


# ---- routes ----------------------------------------------------------------------------------------

@pytest.mark.parametrize("base,ref,want", [
    ("/decks/aft/bay-41", "kx-58", "/decks/aft/kx-58"), ("/decks/aft/", "kx-58", "/decks/aft/kx-58"),
    ("/a/b", "/x/y/", "/x/y/"), ("/a/b/c", "../d", "/a/d"), ("/a/b/c", "../../../../d", "/d"),
    ("/a/b", "./", "/a/"), ("/a/b", ".", "/a/"), ("/a/b/", "..", "/a/"), ("/x", "y", "/y"), ("/", "y/", "/y/"),
    ("/a/b?old=1", "?page=2", "/a/b?page=2"), ("/a/b", "c?d=e&f=g#frag", "/a/c?d=e&f=g"),
    ("/a", "/b#frag", "/b"), ("/a", "&amp;x", "/&x"), ("/a", "//", None), ("/a", "/b//c/../d", "/b/d"),
    ("/a", "", None), ("/a", "   ", None), ("/a", "#top", None), ("/a", "mailto:x@y.test", None),
    ("/a", "javascript:void(0)", None), ("/a", "data:text/plain,x", None), ("/a", "two words", None),
    ("/a", "back\\slash", None), ("/a", "new\nline", None), ("/a", "http://[bad", None),
    ("/a", "https://other.test/x", None), ("/a", "//other.test/x", None), ("/a", "/" + "x" * 600, None),
])
def test_resolve(base, ref, want):
    assert rc.resolve(base, ref) == want


def test_resolve_takes_absolute_urls_of_its_own_origin_only():
    origin = "http://127.0.0.1:8080"
    assert rc.resolve("/a", "http://127.0.0.1:8080/decks/x?y=1", origin) == "/decks/x?y=1"
    assert rc.resolve("/a", "HTTP://127.0.0.1:8080", origin + "/") == "/"
    assert rc.resolve("/a", "//127.0.0.1:8080/x", origin) == "/x"    # scheme-relative, the same host
    for other in ("http://127.0.0.1:8081/x", "https://127.0.0.1:8080/x", "http://localhost:8080/x",
                  "//127.0.0.1:8081/x", "//", "ftp://127.0.0.1:8080/x"):
        assert rc.resolve("/a", other, origin) is None, other
    assert rc.resolve("/a", "http://127.0.0.1:8080/x") is None       # no origin given: every host is another


def test_slugs_directories_and_pairs():
    assert rc.slugs("BAY-41") == ["bay-41", "bay41", "bay_41"] and rc.slugs("KX 58") == ["kx-58", "kx58", "kx_58"]
    assert rc.slugs(" TRN_26 ") == ["trn-26", "trn26", "trn_26"] and rc.slugs("BAY41") == ["bay-41", "bay41", "bay_41"]
    assert rc.slugs("bay-41") == [] and rc.slugs("BAY-41 x") == [] and rc.slugs("") == []
    assert rc.directories_of("/decks/aft/bay-41") == ["/decks/aft/", "/decks/"]
    assert rc.directories_of("/decks/aft/?x=/y/z") == ["/decks/aft/", "/decks/"]
    assert rc.directories_of("/about") == [] and rc.directories_of("/") == []
    # the dash spelling only (the others are tried when such a route misses), made as they are asked for
    pairs = rc.paired_routes(["/a/", "/b/c/"], ["BAY-41", "nope", "KX 5"])
    assert not isinstance(pairs, (list, tuple))
    assert list(pairs) == [("/a/bay-41", "/a/", "BAY-41"), ("/a/kx-5", "/a/", "KX 5"),
                           ("/b/c/bay-41", "/b/c/", "BAY-41"), ("/b/c/kx-5", "/b/c/", "KX 5")]
    endless = rc.paired_routes((f"/d{n}/" for n in itertools.count()), ["BAY-41", "KX 5"])
    assert [next(endless)[0] for _ in range(3)] == ["/d0/bay-41", "/d0/kx-5", "/d1/bay-41"]      # nothing is built ahead


# ---- the crawl over a dict -------------------------------------------------------------------------

def test_chain_is_walked_from_comments_and_frames(tmp_path):
    rep, log = run(out_dir=tmp_path)
    reached = {page.route: page for page in rep.pages}
    assert set(reached) == set(site())                               # every page of the chain, nothing else answered
    assert reached["/decks/aft/bay-41"].why == "directory /decks/aft/ with identifier BAY-41 (both from /)"
    assert reached["/decks/hold/kx-58"].why == \
        "directory /decks/hold/ with identifier KX-58 (both from /decks/aft/bay-41)"
    assert reached["/decks/keel/bay-63"].why == \
        "directory /decks/keel/ with identifier BAY 63 (both from /decks/hold/kx-58)"
    assert reached["/clips/final.gif"].why == "offered on /decks/keel/bay-63"
    assert reached["/static/site.js"].why == "offered on /" and reached["/api/status"].why == "offered on /static/site.js"
    assert reached["/clips/final.gif"].ocr_flags == [FLAG] and reached["/clips/final.gif"].flags == []
    assert reached["/clips/bay-41.gif"].identifiers == ["KX-58"]
    assert reached["/decks/aft/bay-41"].reveal == ["<img data-reveal-after='4200'>"]
    assert log[0] == "/" and len(log) == len(set(log)) == rep.requests
    # what a page offers is fetched before any route made of a directory and an identifier
    assert log.index("/about") < log.index("/decks/aft/bay-41") < log.index("/decks/hold/kx-58")
    # the pair one page named together is tried before pairs put together from two pages
    assert log.index("/decks/hold/kx-58") < log.index("/decks/aft/kx-58")
    assert ("/decks/aft/kx-58", 404, "directory /decks/aft/ with identifier KX-58") in rep.misses
    # folders that only assets were loaded from are not guessed in, and no guess is respelt
    # unless the page itself named the pair: ten pages cost nine misses
    guesses = [route for route, _status, why in rep.misses if why.startswith("directory ")]
    assert not any(route.startswith(("/static/", "/clips/", "/api/")) for route in guesses)
    assert all(route.rsplit("/", 1)[1] in ("bay-41", "kx-58", "bay-63") for route in guesses)
    assert sorted(route for route, _status, _why in rep.misses) == sorted(
        ["/decks/aft/"] + [f"/decks/{folder}{name}" for folder in ("", "aft/", "hold/", "keel/")
                              for name in ("bay-41", "kx-58", "bay-63")
                              if f"/decks/{folder}{name}" not in site()] + ["/decks/hold/", "/decks/keel/"])
    assert rep.requests == len(site()) + len(rep.misses) == 22 and not rep.skipped
    # the frames of every GIF were written for a model read
    assert len(rep.written) == 3 * 5 and (tmp_path / "clips_final.gif.frame1.png").is_file()
    res = rc.result_of(rep, root=tmp_path)
    assert res.status == "candidate" and res.flags == (FLAG,)        # read by OCR: never more than a candidate
    assert [e.detail for e in res.evidence if e.kind == "ocr"] == [
        "OCR of a frame of /clips/final.gif (offered on /decks/keel/bay-63)"]
    assert res.notes.startswith(f"live crawl: {rep.requests} GET(s), 10 answered, {len(rep.misses)} did not")
    assert "/decks/aft/bay-41 [html, directory /decks/aft/ with identifier BAY-41 (both from /)]: " \
           "1 comment(s): the rest moved to /decks/hold/" in res.notes
    assert "timed-reveal attributes <img data-reveal-after='4200'>" in res.notes


def test_what_is_never_requested():
    rep, log = run()
    refused = dict(rep.refused)
    assert refused["/logout"] == "it names a state-changing action; never requested"
    assert refused["https://elsewhere.test/x"] == "another origin (offered on /); never requested"
    assert "/logout" not in log and not any("elsewhere" in route or "mailto" in route for route in log)
    pages = site(**{"/": (HTML, b"<a href='/admin/delete?id=1'>x</a><a href='/reset-password'>y</a>"
                                b"<a href='/notes/7'>z</a><!-- /api/user/remove -->")})
    rep, log = run(pages)
    assert log == ["/", "/notes/7"]
    assert sorted(route for route, _why in rep.refused) == ["/admin/delete?id=1", "/api/user/remove", "/reset-password"]
    # an injected guard replaces the default one
    rep, log = run(pages, destructive=lambda route: route.startswith("/notes"))
    assert "/notes/7" not in log and "/admin/delete?id=1" in log


def test_other_spellings_only_after_a_same_page_pair_misses():
    pages = {"/": (HTML, b"<!-- unit BAY-41, see /decks/aft/ and /decks/other/ --><a href='/list'>l</a>"),
             "/list": (HTML, b"<!-- unit KX-58 -->"),
             "/decks/aft/bay41": (HTML, b"<p>found by its run-together spelling</p>")}
    rep, log = run(pages)
    assert [p.route for p in rep.pages] == ["/", "/list", "/decks/aft/bay41"]
    assert rep.pages[2].why == "directory /decks/aft/ with identifier BAY-41 (both from /), spelt bay41"
    # the dash spellings come first, then the respellings of the pairs the page itself named,
    # then pairs put together from two pages
    assert log.index("/decks/other/bay-41") < log.index("/decks/aft/bay41") < log.index("/decks/aft/kx-58")
    # KX-58 was named on another page than the directories, so its misses are not respelt
    assert not any(route.endswith(("kx58", "kx_58")) for route in log)
    assert "/decks/other/bay41" in log and "/decks/other/bay_41" in log    # that pair missed in every spelling
    assert "/decks/aft/bay_41" not in log                         # ... and this one had answered already
    assert "/decks/bay41" not in log                                 # a parent folder is a place to look, once
    assert "/bay-41" not in log                                      # the root is not a directory to guess in


def test_budgets_are_kept_and_named():
    rep, log = run(max_requests=4)
    assert len(log) == 4 and rep.requests == 4
    assert rep.skipped[0].startswith("stopped at 4 requests; ") and "the next being /" in rep.skipped[0]
    rep, log = run(max_depth=1)
    assert set(log) == {"/", "/about", "/static/site.js", "/decks/aft/", "/decks/aft/bay-41", "/decks/bay-41"}
    rep, log = run(max_depth=0)
    assert log == ["/"]
    rep, log = run(deadline=time.monotonic() - 1)
    assert log == [] and rep.skipped == ["out of time; 1 route(s) were not tried, the next being / (start)"]
    naps = []
    rep, log = run(sleep=naps.append, gap=0.25)
    assert naps == [0.25] * (len(log) - 1)                           # paced between requests, not before the first
    rep, log = run(sleep=naps.append)
    assert naps[-1] == rc.GAP


def test_fetch_refusals_and_blocks():
    def picky(route):
        if route == "/about":
            raise ValueError("refusing ambiguous HTTP response framing")
        return dict_fetch(site(), [])(route)

    rep = rc.crawl(picky, FF, read=ocr(), codes=no_codes, sleep=lambda s: None)
    assert ("/about", "refusing ambiguous HTTP response framing") in rep.refused
    assert any(page.route == "/decks/keel/bay-63" for page in rep.pages)      # the crawl went on

    def down(route):
        raise rc.CrawlBlocked("the target does not answer")

    with pytest.raises(rc.CrawlBlocked):
        rc.crawl(down, FF, sleep=lambda s: None)

    def absent(png, deadline=None):
        raise image_carve.ToolMissing("tesseract is not on PATH")

    rep, _log = run(read=absent)
    assert rep.ocr.startswith("not run: tesseract is not on PATH")
    assert [p.route for p in rep.pages if p.route.startswith("/decks/")] == ["/decks/aft/bay-41"]
    res = rc.result_of(rep)
    assert res.status == "unsure" and "OCR not run: tesseract is not on PATH" in res.notes
    with pytest.raises(rc.CrawlBlocked, match="ocr=on"):
        run(read=absent, ocr="on")
    rep, _log = run(ocr="off")
    assert rep.ocr == "off" and "OCR off" in rc.result_of(rep).notes
    # the report keeps the worst OCR state it met: a still GIF read after the animated one (which
    # needs no OCR at all) does not hide that the animated one went unread
    still = fx.gif_bytes([fx.bar_frame(0)])
    pages = {"/": (HTML, b"<img src='/a.gif'><img src='/b.gif'>"), "/a.gif": ("image/gif", gif(0)),
             "/b.gif": ("image/gif", still)}
    rep, log = run(pages, read=absent)
    assert log == ["/", "/a.gif", "/b.gif"] and rep.ocr.startswith("not run: tesseract is not on PATH")
    rep, _log = run(pages)
    assert rep.ocr == "run"


def test_flag_in_page_bytes_is_proven():
    pages = {"/": (HTML, b"<a href='/deep'>d</a>"), "/deep": (HTML, b"<!-- CSCTF{in_a_comment} -->")}
    rep, _log = run(pages)
    res = rc.result_of(rep)
    assert res.status == "solved" and res.flags == ("CSCTF{in_a_comment}",)
    assert (res.evidence[0].kind, res.evidence[0].detail, res.evidence[0].path) == (
        "wire", "flag in the bytes of /deep (offered on /)", "/deep")
    pages["/"] = (HTML, b"<a href='/deep'>d</a><!-- CSCTF{decoy_on_the_front} -->")
    assert rc.result_of(run(pages)[0]).status == "candidate"
    plain, _log = run({"/": (HTML, b"<p>hello</p>")})
    assert rc.result_of(plain).status == "none"
    start, log = run({"/app/": (HTML, b"<a href='x'>x</a>"), "/app/x": (HTML, b"ok")}, start="/app/")
    assert log == ["/app/", "/app/x"]


def test_code_in_a_gif_frame_is_proven_through_the_crawl():
    pages = {"/": (HTML, b"<img src='/cam.gif'>"), "/cam.gif": ("image/gif", gif(0))}

    def codes(data, **kw):
        return [{"format": "qr_code", "text": "CSCTF{code_in_a_frame}", "bytes": b"", "how": "frame 1"}]

    rep, _log = run(pages, codes=codes, read=ocr({}))
    assert rep.pages[1].flags == ["CSCTF{code_in_a_frame}"] and rep.pages[1].ocr_flags == []
    res = rc.result_of(rep)
    assert res.status == "solved" and res.flags == ("CSCTF{code_in_a_frame}",)
    assert res.evidence[0].detail == "flag in the bytes of /cam.gif (offered on /)"


# ---- live, through the scope-locked client, against a loopback fake --------------------------------

class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        pass

    def _answer(self):
        """A page is (content type, body), or (status, location) for a redirect. A server with
        `ranges` answers `Range: bytes=a-b` with 206 and Content-Range; one without sends the
        whole body with 200, as many static hosts do."""
        self.server.seen.append((self.command, self.path))
        asked = self.headers.get("Range")
        if asked:
            self.server.ranges_seen.append((self.path, asked))
        ctype, body = self.server.pages.get(self.path, ("text/plain", None))
        headers = {}
        if isinstance(ctype, int):
            status, headers["Location"], ctype, body = ctype, body, "text/html", b"<a href='/trap'>moved</a>"
        else:
            status = 200 if body is not None else 404
            body = body if body is not None else b"not found"
        span = re.fullmatch(r"bytes=(\d+)-(\d+)", asked or "")
        if span and status == 200 and self.server.ranges:
            first, last = int(span.group(1)), min(int(span.group(2)), len(body) - 1)
            total = "*" if self.server.ranges == "no total" else len(body)
            status, headers["Content-Range"] = 206, f"bytes {first}-{last}/{total}"
            body = body[first:last + 1]
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        for name, value in headers.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = do_HEAD = do_PUT = do_DELETE = _answer


@contextmanager
def serve(pages, ranges=True, handler=_Handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.pages, server.seen, server.ranges, server.ranges_seen = pages, [], ranges, []
    server.handle_error = lambda *_args: None          # the client hangs up at its body cap: not an error here
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)


def test_live_crawl_is_get_only_same_origin_and_walks_the_chain(tmp_path, monkeypatch):
    monkeypatch.setattr(image_carve, "ocr_text", ocr())
    with serve({"/x": (HTML, b"<p>the partner site</p>")}) as (other, other_url):
        pages = site()
        pages["/"] = (HTML, pages["/"][1].replace(b"https://elsewhere.test/x", other_url.encode() + b"/x"))
        with serve(pages) as (server, url):
            res = rc.solve(tmp_path, PROFILE, seconds=BUDGET, url=url + "/", gap=0, max_requests=40)
            seen = list(server.seen)
        assert other.seen == []                                      # the other origin was never contacted
    assert res.status == "candidate" and res.flags == (FLAG,) and res.engine == "web.route_crawl"
    assert {method for method, _path in seen} == {"GET"}
    paths = [path for _method, path in seen]
    assert paths[0] == "/" and "/decks/keel/bay-63" in paths and "/clips/final.gif" in paths
    assert "/logout" not in paths and len(paths) == len(set(paths)) <= 40
    assert f"not requested: {other_url}/x: another origin (offered on /); never requested" in res.notes
    assert "not requested: /logout: it names a state-changing action; never requested" in res.notes
    written = [e.path for e in res.evidence if e.detail == "written"]
    assert len(written) == 15 and all(p.startswith("recon/route_crawl/clips_") for p in written)


def test_live_crawl_is_blocked_out_of_scope_and_when_nothing_answers(tmp_path):
    refused = rc.solve(tmp_path, PROFILE, seconds=BUDGET, url="http://not-in-scope.example/")
    assert refused.status == "blocked" and "the live target is refused" in refused.notes
    assert "live_service_scope" in refused.notes and "'b117-test'" in refused.notes
    unusable = rc.solve(tmp_path, PROFILE, seconds=BUDGET, url="not a url")
    assert unusable.status == "blocked" and "has no host" in unusable.notes
    with pytest.raises(rc.CrawlBlocked):
        rc.live_fetch("not a url")
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    down = rc.solve(tmp_path, PROFILE, seconds=BUDGET, url=f"http://127.0.0.1:{port}/")
    assert down.status == "blocked" and "the target does not answer" in down.notes
    with pytest.raises(ValueError):
        rc.solve(tmp_path, PROFILE, seconds=BUDGET, ocr="sometimes")


def test_the_profile_handed_to_solve_decides_the_scope_before_the_client(tmp_path, monkeypatch):
    """The suite's pinned event allows loopback, so the client alone would let this crawl run.
    The profile solve() was handed has an empty scope: nothing may be contacted, and nothing is."""
    from ctf import scope
    with serve({"/": (HTML, b"<!-- CSCTF{must_not_be_read} -->")}) as (server, url):
        assert scope.check_url(url + "/") == "127.0.0.1"             # the pinned event would allow it
        closed = rc.solve(tmp_path, CLOSED, seconds=BUDGET, url=url + "/")
        assert server.seen == []
        assert closed.status == "blocked" and closed.flags == ()
        assert "event 'b117-closed' has an empty rules.live_service_scope" in closed.notes
        # the same crawl under a profile that lists loopback runs
        assert rc.solve(tmp_path, PROFILE, seconds=BUDGET, url=url + "/").flags == ("CSCTF{must_not_be_read}",)
    # both guards hold: a host this profile allows and the current event does not is refused by
    # the client, before any name is resolved
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: pytest.fail("a name was resolved"))
    wide = fx.profile(scope=("*.example",), slug="b117-wide")
    other = rc.solve(tmp_path, wide, seconds=BUDGET, url="http://only-in-the-profile.example/")
    assert other.status == "blocked" and "the live target is refused" in other.notes and "b117-wide" not in other.notes


def test_live_fetch_refuses_what_the_client_refuses(monkeypatch):
    import web
    built = []
    real_init = web.WebClient.__init__

    def spy(self, *args, **kw):
        real_init(self, *args, **kw)
        built.append(self)

    monkeypatch.setattr(web.WebClient, "__init__", spy)
    with serve({"/": (HTML, b"ok")}) as (server, url):
        fetch, origin, start = rc.live_fetch(url + "/app/?tab=1")
        assert origin == url and start == "/app/?tab=1"
        assert fetch("/") == (200, HTML, b"ok", {"requests": 1})
        assert fetch("/missing")[0] == 404
        with pytest.raises(ValueError, match="scope-locked client"):
            fetch("http://127.0.0.1:1/elsewhere")
        # the one client the crawl uses is the GET-only one: a POST through it is refused unsent
        assert len(built) == 1 and built[0].get_only is True
        with pytest.raises(web.OutOfScope, match="get_only client refuses a POST"):
            built[0].post("/", data="x=1")
        assert server.seen == [("GET", "/"), ("GET", "/missing")]


# ---- saved pages -----------------------------------------------------------------------------------

def _saved():
    pages = site()
    return {"index.html": pages["/"][1], "static/site.js": pages["/static/site.js"][1],
            "decks/aft/bay-41.html": pages["/decks/aft/bay-41"][1], "clips/bay-41.gif": pages["/clips/bay-41.gif"][1],
            "logo.png": b"\x89PNG\r\n\x1a\n" + bytes(20), "data.bin": bytes(64)}


def test_saved_pages_list_what_to_fetch_and_make_no_request(tmp_path, monkeypatch):
    monkeypatch.setattr(rc, "live_fetch", lambda *a, **k: pytest.fail("the saved run made a client"))
    rep = rc.examine_saved(_saved(), FF, read=ocr(), codes=no_codes, out_dir=tmp_path)
    assert rep.mode == "saved" and rep.requests == 0
    assert [p.route for p in rep.pages] == ["/clips/bay-41.gif", "/decks/aft/bay-41.html", "/index.html", "/static/site.js"]
    unsaved = dict(rep.unsaved)
    assert unsaved["/about"] == "offered on /index.html" and unsaved["/api/status"] == "offered on /static/site.js"
    assert unsaved["/decks/hold/"] == "named on /decks/aft/bay-41.html"
    assert unsaved["/decks/hold/kx-58"] == "directory /decks/hold/ with identifier KX-58"
    assert unsaved["/decks/aft/bay-41"] == "directory /decks/aft/ with identifier BAY-41"
    assert "/static/site.js" not in unsaved and "/clips/bay-41.gif" not in unsaved      # they are saved
    assert not any(route.endswith(("bay41", "bay_41")) for route in unsaved)           # dash spelling only
    assert len(rep.written) == 5 and len(list(tmp_path.iterdir())) == 5
    # with the OCR off the frames are neither composited nor written here (gif_reveal's job at
    # intake); what the GIF's bytes say is still read
    flagged = dict(_saved(), **{"clips/bay-41.gif": fx.gif_bytes([fx.bar_frame(0), fx.bar_frame(1)],
                                                                 comment=b"CSCTF{in_a_saved_gif_comment}")})
    quiet = rc.examine_saved(flagged, FF, ocr="off", read=lambda *a, **k: pytest.fail("the OCR ran"), codes=no_codes,
                             out_dir=tmp_path / "unused")
    assert quiet.written == [] and not (tmp_path / "unused").exists()
    assert (quiet.animations[0].total, quiet.animations[0].read) == (2, 0)
    assert rc.result_of(quiet).flags == ("CSCTF{in_a_saved_gif_comment}",)
    assert quiet.pages[0].route == "/clips/bay-41.gif" and "2 frames" in quiet.pages[0].notes
    res = rc.result_of(rep, root=tmp_path)
    assert res.status == "unsure" and res.flags == ()
    assert "routes the saved pages point at that are not saved (GET them, in scope): " in res.notes
    assert "/decks/hold/kx-58 (directory /decks/hold/ with identifier KX-58)" in res.notes
    assert not res.notes.startswith("live crawl")


def test_saved_run_needs_a_page_and_keeps_its_caps(monkeypatch):
    files = _saved()
    without_html = {name: data for name, data in files.items() if not name.endswith(".html")}
    rep = rc.examine_saved(without_html, FF, read=ocr(), codes=no_codes)
    assert rep.pages == [] and rep.unsaved == [] and rc.result_of(rep).status == "none"
    flagged = rc.result_of(rc.examine_saved({"index.html": b"<!-- CSCTF{saved_comment} -->"}, FF, codes=no_codes))
    assert flagged.status == "solved" and flagged.evidence[0].kind == "carve"
    many = {"index.html": "".join(f"<a href='/p{n}'>x</a>" for n in range(50)).encode()}
    notes = rc.result_of(rc.examine_saved(many, FF)).notes
    assert "/p39 (offered on /index.html) and 10 more" in notes and "/p40" not in notes
    served = {"site/index.html": b"<a href='/site/'>home</a><a href='/site/index.html'>same</a>"}
    assert rc.examine_saved(served, FF).unsaved == []               # a folder is saved by its index.html
    monkeypatch.setattr(rc, "MAX_FILE", 10)
    rep = rc.examine_saved({"index.html": b"<!-- /a/long/enough/page -->"}, FF)
    assert rep.pages == [] and rep.skipped == ["index.html: over the 10 byte cap, not read"]


def test_solve_reads_the_challenge_files_by_default(tmp_path, monkeypatch):
    for name, data in _saved().items():
        path = tmp_path / "files" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    # the saved run leaves the frames of a saved GIF to gif_reveal: the OCR is not called at all,
    # and the frames are not written a second time
    monkeypatch.setattr(image_carve, "ocr_text", lambda *a, **k: pytest.fail("the saved run started the OCR"))
    whole = []
    real_read = Path.read_bytes
    monkeypatch.setattr(Path, "read_bytes", lambda self: (whole.append(self.name), real_read(self))[1])
    res = rc.solve(tmp_path, CLOSED, seconds=BUDGET)                 # no scope is needed: nothing is contacted
    assert res.status == "unsure" and "kx-58" not in res.notes
    assert "/decks/hold/ (named on /decks/aft/bay-41.html)" in res.notes
    assert "OCR left to toolkits.gif_reveal for the saved GIFs (ocr=auto reads their frames here too)" in res.notes
    assert [e for e in res.evidence if e.detail == "written"] == [] and not (tmp_path / "recon").exists()
    # only the text pages and the GIF were read whole: the picture and the binary were told from
    # their first bytes and left alone
    assert sorted(whole) == ["bay-41.gif", "bay-41.gif", "bay-41.html", "index.html", "site.js"]     # the GIF: told, then read
    quiet = rc.solve(tmp_path, PROFILE, seconds=BUDGET, ocr="off", out=str(tmp_path / "elsewhere"))
    assert "kx-58" not in quiet.notes and "OCR off" in quiet.notes and not (tmp_path / "elsewhere").exists()
    # asked for, the frames are read and written here and the identifier in them becomes a route to fetch
    monkeypatch.setattr(image_carve, "ocr_text", ocr())
    asked = rc.solve(tmp_path, PROFILE, seconds=BUDGET, ocr="auto")
    assert asked.status == "unsure" and "/decks/hold/kx-58 (directory /decks/hold/ with identifier KX-58)" in asked.notes
    assert "OCR left to" not in asked.notes
    written = [e.path for e in asked.evidence if e.detail == "written"]
    assert len(written) == 5 and all(p.startswith("recon/route_crawl/clips_bay-41.gif.") for p in written)
    # with no saved page there is nothing to report, and no file is read whole to find that out
    for name in ("index.html", "decks/aft/bay-41.html"):
        (tmp_path / "files" / name).unlink()
    del whole[:]
    assert rc.solve(tmp_path, CLOSED, seconds=BUDGET).status == "none" and whole == []
    files, _skipped = rc.saved_files(tmp_path)
    assert len(files) == 0 and list(files) == []
    with pytest.raises(FileNotFoundError):
        rc.solve(tmp_path / "missing", PROFILE, seconds=BUDGET)


def test_default_budgets_fit_the_manifest_and_the_intake_budget(tmp_path, monkeypatch):
    """The production defaults, read where solve() hands them on (no wall clock is measured)."""
    from ctf.engines import manifest
    from ctf.intake import DEFAULT_ENGINE_BUDGET
    seen = {}

    def saved(files, ff, **kw):
        seen["saved"] = kw
        return rc.Report(mode="saved")

    def live(fetch, ff, **kw):
        seen["live"] = kw
        return rc.Report(mode="live")

    monkeypatch.setattr(rc, "examine_saved", saved)
    monkeypatch.setattr(rc, "crawl", live)
    monkeypatch.setattr(rc, "live_fetch", lambda url, **kw: (seen.setdefault("fetch", kw) and None, "http://127.0.0.1:9", "/"))
    monkeypatch.setattr(rc.time, "monotonic", lambda: 1000.0)
    rc.solve(tmp_path, PROFILE)
    rc.solve(tmp_path, PROFILE, url="http://127.0.0.1:9/")
    assert seen["saved"]["deadline"] == 1000.0 + rc.SAVED_SECONDS and seen["saved"]["ocr"] == "off"
    assert seen["live"]["deadline"] == 1000.0 + rc.DEFAULT_SECONDS and seen["live"]["ocr"] == "auto"
    assert seen["fetch"]["deadline"] == seen["live"]["deadline"]      # the ranged GETs stop with the crawl
    intake = {m.id: m for m in manifest.discover()}["web.route_crawl"].intake
    assert intake.spawns is False                                     # the saved run starts no program
    assert 2 * rc.SAVED_SECONDS <= intake.timeout <= DEFAULT_ENGINE_BUDGET / 2
    assert rc.DEFAULT_SECONDS < 60


def test_cli(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("CTF_EVENT", "csctf")
    monkeypatch.setattr(image_carve, "ocr_text", ocr())
    (tmp_path / "index.html").write_bytes(b"<!-- CSCTF{cli_saved} -->")
    assert rc.main([str(tmp_path), "--seconds", "3600"]) == 0
    result = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert result["status"] == "solved" and result["flags"] == ["CSCTF{cli_saved}"]
    with serve({"/": (HTML, b"<!-- CSCTF{cli_live} -->")}) as (server, url):
        argv = [str(tmp_path), "--url", url + "/", "--max-requests", "3", "--ocr", "off", "--seconds", "3600"]
        # the event the CLI runs under decides: csctf's scope does not list loopback
        assert rc.main(argv) == 0
        refused = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
        assert refused["status"] == "blocked" and "'csctf' rules.live_service_scope" in refused["notes"]
        assert server.seen == []
        from ctf import event
        monkeypatch.setattr(event, "current", lambda: PROFILE)
        assert rc.main(argv) == 0
        live = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
        assert live["flags"] == ["CSCTF{cli_live}"] and [m for m, _p in server.seen] == ["GET"]
    assert rc.main([str(tmp_path / "absent")]) == 2 and "no such challenge folder" in capsys.readouterr().err


# ---- redirects -------------------------------------------------------------------------------------

def test_a_3xx_is_a_miss_and_its_body_is_not_harvested():
    """Only a 2xx is a page. A redirect's body (and a 304's) is not read for links, comments or
    flags: what it points at is fetched as its own route, or not at all."""
    def fetch(route):
        if route == "/":
            return 200, HTML, b"<a href='/moved'>a</a><a href='/cached'>b</a>"
        if route == "/moved":
            return 302, HTML, b"<a href='/in-the-redirect-body'>x</a><!-- CSCTF{in_a_redirect_body} -->"
        if route == "/cached":
            return 304, HTML, b"<a href='/in-the-304-body'>x</a>"
        return 404, "text/plain", b""

    log = []

    def logged(route):
        log.append(route)
        return fetch(route)

    rep = rc.crawl(logged, FF, sleep=lambda s: None)
    assert log == ["/", "/moved", "/cached"]
    assert [page.route for page in rep.pages] == ["/"]
    assert rep.misses == [("/moved", 302, "offered on /"), ("/cached", 304, "offered on /")]
    assert rc.result_of(rep).flags == ()


def test_a_redirect_is_followed_as_an_offered_link_under_every_guard():
    pages = {"/": (HTML, b"<a href='/go'>a</a><a href='/next'>b</a><a href='/out'>c</a><a href='/loop-a'>d</a>"),
             "/landing": (HTML, b"<!-- CSCTF{behind_a_redirect} -->")}
    moved = {"/go": "/account/delete", "/next": "landing", "/out": "https://elsewhere.test/x",
             "/loop-a": "/loop-b", "/loop-b": "/loop-a"}
    log = []

    def fetch(route):
        log.append(route)
        if route in moved:
            return 302, HTML, b"", {"location": moved[route]}
        return dict_fetch(pages, [])(route)

    rep = rc.crawl(fetch, FF, sleep=lambda s: None)
    assert log == ["/", "/go", "/next", "/out", "/loop-a", "/landing", "/loop-b"]     # each route once: the loop ends
    assert "/account/delete" not in log
    assert dict(rep.refused) == {"/account/delete": "it names a state-changing action; never requested",
                                 "https://elsewhere.test/x": "another origin (redirect from /out); never requested"}
    landing = rep.pages[-1]
    assert (landing.route, landing.why, landing.flags) == ("/landing", "redirect from /next", ["CSCTF{behind_a_redirect}"])
    assert ("/go", 302, "offered on /") in rep.misses and rep.requests == len(log)
    # a redirect is one link deeper: at the depth limit it is not followed
    log.clear()
    rc.crawl(fetch, FF, sleep=lambda s: None, max_depth=1)
    assert log == ["/", "/go", "/next", "/out", "/loop-a"]


def test_a_paired_route_that_redirects_is_respelt_only_if_its_target_misses():
    front = (HTML, b"<!-- unit BAY-41 under /decks/aft/ -->")
    log = []

    def site_with(target_answers):
        def fetch(route):
            log.append(route)
            if route == "/":
                return 200, front[0], front[1]
            if route == "/decks/aft/bay-41":
                return 301, HTML, b"", {"location": "/decks/aft/bay-41/"}
            if route == "/decks/aft/bay-41/" and target_answers:
                return 200, HTML, b"<p>the page, behind a trailing slash</p>"
            return 404, "text/plain", b""
        return fetch

    rep = rc.crawl(site_with(True), FF, sleep=lambda s: None)
    assert rep.pages[-1].route == "/decks/aft/bay-41/" and rep.pages[-1].why == "redirect from /decks/aft/bay-41"
    assert not any(route.endswith(("bay41", "bay_41")) for route in log)     # the pair answered: no other spelling
    log.clear()
    rc.crawl(site_with(False), FF, sleep=lambda s: None)
    assert "/decks/aft/bay41" in log and "/decks/aft/bay_41" in log          # its target missed: the pair is respelt


def test_live_redirect_to_a_destructive_route_never_reaches_the_server(tmp_path):
    with serve({"/x": (HTML, b"elsewhere")}) as (other, other_url):
        pages = {"/": (HTML, b"<a href='/go'>a</a><a href='/next'>b</a><a href='/out'>c</a>"),
                 "/go": (302, "/account/delete"), "/account/delete": (HTML, b"<p>deleted</p>"),
                 "/next": (301, "/landing"), "/landing": (HTML, b"<!-- CSCTF{live_behind_a_redirect} -->"),
                 "/out": (307, other_url + "/x")}
        with serve(pages) as (server, url):
            res = rc.solve(tmp_path, PROFILE, seconds=BUDGET, url=url + "/", gap=0)
            seen = [path for _method, path in server.seen]
        assert other.seen == []                                      # the redirect out of the origin was not followed
    assert seen == ["/", "/go", "/next", "/out", "/landing"]         # ... and /account/delete was never requested
    assert res.status == "solved" and res.flags == ("CSCTF{live_behind_a_redirect}",)
    assert "not requested: /account/delete: it names a state-changing action; never requested" in res.notes
    assert f"not requested: {other_url}/x: another origin (redirect from /out); never requested" in res.notes
    assert "/landing [html, redirect from /next]" in res.notes
    assert "/trap" not in seen                                       # the link in a redirect's body is not a lead


# ---- bodies over the client's cap ------------------------------------------------------------------

def _noise_gif(frames=8, side=400, seed=7):
    """An animated GIF of noise frames (noise does not compress, so it is well over 1 MiB)."""
    from PIL import Image
    rng = random.Random(seed)
    return fx.gif_bytes([Image.frombytes("L", (side, side), rng.randbytes(side * side)) for _ in range(frames)])


def test_live_gif_over_the_clients_cap_is_read_whole_by_ranged_gets(tmp_path):
    import web
    flag = "CSCTF{after_the_last_frame}"
    big = _noise_gif() + b" " + flag.encode()
    assert len(big) > web.MAX_BODY + 100_000                         # the flag and the last frames are past the cap
    with serve({"/": (HTML, b"<img src='/cam.gif'>"), "/cam.gif": ("image/gif", big)}) as (server, url):
        res = rc.solve(tmp_path, PROFILE, seconds=BUDGET, url=url + "/", gap=0, ocr="off")
        assert server.ranges_seen == [("/cam.gif", f"bytes={web.MAX_BODY}-{2 * web.MAX_BODY - 1}")]
        assert [path for _method, path in server.seen] == ["/", "/cam.gif", "/cam.gif"]
    assert res.status == "solved" and res.flags == (flag,)
    assert "live crawl: 3 GET(s), 2 answered" in res.notes           # the ranged GET is counted
    assert "/cam.gif [gif, offered on /]: 8 frames" in res.notes
    assert "cut the body" not in res.notes and "ends before its trailer" not in res.notes

    # a server that ignores Range: the body stays cut, and the result says whose cut it is
    with serve({"/": (HTML, b"<img src='/cam.gif'>"), "/cam.gif": ("image/gif", big)}, ranges=False) as (server, url):
        res = rc.solve(tmp_path, PROFILE, seconds=BUDGET, url=url + "/", gap=0, ocr="off")
    assert res.status == "unsure" and res.flags == ()
    assert (f"/cam.gif: the client cut the body at {web.MAX_BODY} bytes and the server does not answer ranged GETs "
            f"(status 200); the first {web.MAX_BODY} bytes were read") in res.notes


def test_live_page_over_the_cap_is_whole_with_ranges_and_unsure_without(tmp_path, monkeypatch):
    import web
    monkeypatch.setattr(web, "MAX_BODY", 4096)                       # the client's cap, small so the bodies are
    flag = "CSCTF{at_the_end_of_a_long_page}"
    page = b"<html><p>" + b"filler " * 1500 + b"</p><!-- " + flag.encode() + b" --></html>"
    assert 2 * 4096 < len(page) < 3 * 4096
    for ranges in (True, "no total"):
        with serve({"/": (HTML, page)}, ranges=ranges) as (server, url):
            res = rc.solve(tmp_path, PROFILE, seconds=BUDGET, url=url + "/", gap=0)
            assert [asked for _path, asked in server.ranges_seen] == ["bytes=4096-8191", "bytes=8192-12287"]
        assert res.status == "solved" and res.flags == (flag,) and "live crawl: 3 GET(s), 1 answered" in res.notes
    with serve({"/": (HTML, page)}, ranges=False) as (server, url):
        res = rc.solve(tmp_path, PROFILE, seconds=BUDGET, url=url + "/", gap=0)
    # nothing was found in the part that was read, and that is not `none`: the rest was never seen
    assert res.status == "unsure" and res.flags == ()
    assert "/ [html, start]: the client cut the body at 4096 bytes and the server does not answer ranged GETs" in res.notes

    # the ranged GETs are requests like any other: they stop at the request budget, the deadline
    # and the cap on one asset, and each stop is named
    with serve({"/": (HTML, page)}) as (server, url):
        res = rc.solve(tmp_path, PROFILE, seconds=BUDGET, url=url + "/", gap=0, max_requests=2)
        assert len(server.seen) == 2
        assert "and the request budget ended; the first 8192 bytes were read" in res.notes and res.status == "unsure"
        monkeypatch.setattr(rc, "MAX_ASSET", 6000)
        res = rc.solve(tmp_path, PROFILE, seconds=BUDGET, url=url + "/", gap=0)
        assert "over the 6000 byte cap for one asset; the first 6000 bytes were read" in res.notes
        monkeypatch.setattr(rc, "MAX_ASSET", 8 << 20)
        fetch, _origin, _start = rc.live_fetch(url + "/", deadline=time.monotonic() - 1)
        status, _ctype, body, info = fetch("/")
        assert (status, len(body), info["requests"]) == (200, 4096, 1) and "the time ran out" in info["cut"]
        naps = []
        fetch, _origin, _start = rc.live_fetch(url + "/", gap=0.25, sleep=naps.append)
        assert fetch("/")[2] == page and naps == [0.25, 0.25]        # paced like the crawl's own GETs


def test_a_ranged_answer_that_is_not_the_asked_range_is_not_stitched_on(tmp_path, monkeypatch):
    """Content-Range must start where the body so far ends; anything else would splice bytes
    from the wrong place into a page that is then read as evidence."""
    import web
    monkeypatch.setattr(web, "MAX_BODY", 4096)
    page = b"<p>" + b"x" * 9000 + b"</p>"

    class Shifted(_Handler):
        def _answer(self):
            if self.headers.get("Range"):
                self.send_response(206)
                self.send_header("Content-Range", f"bytes 0-99/{len(page)}")
                self.send_header("Content-Length", "100")
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(page[:100])
                return
            _Handler._answer(self)

        do_GET = _answer

    with serve({"/": (HTML, page)}, ranges=False, handler=Shifted) as (_server, url):
        fetch, _origin, _start = rc.live_fetch(url + "/")
        status, _ctype, body, info = fetch("/")
    assert status == 200 and body == page[:4096] and info["requests"] == 2
    assert "does not answer ranged GETs (status 206)" in info["cut"]


# ---- caps on what one page can cost ----------------------------------------------------------------

def test_queue_cap_is_kept_and_named(monkeypatch):
    monkeypatch.setattr(rc, "MAX_QUEUE", 3)
    pages = {"/": (HTML, "".join(f"<a href='/p{n}'>x</a>" for n in range(6)).encode())}
    pages.update({f"/p{n}": (HTML, b"ok") for n in range(6)})
    rep, log = run(pages)
    assert log == ["/", "/p0", "/p1", "/p2"]
    assert rep.skipped == ["3 route(s) were never queued: 3 were waiting already; the first was /p3"]
    monkeypatch.setattr(rc, "MAX_QUEUE", 2000)
    rep, log = run(pages)
    assert len(log) == 7 and rep.skipped == []


def test_unclosed_block_comments_cost_their_length_not_its_square():
    """A page of unclosed comment openers. Measured in CPU time (this machine's wall clock says
    nothing): the regex this replaced took 6 s for half as many and four times that for these."""
    hostile = "/*" + " /*" * 40_000
    started = time.process_time()
    assert rc.comments_of(hostile, "script") == []
    assert rc.comments_of(hostile + " closed */ var a; /* two */ // tail", "script")[1:] == ["two", "tail"]
    page = rc.harvest("/x.html", ("<script>" + hostile + "</script><!-- kept -->").encode(), HTML, FF)
    assert page.comments == ["kept"]
    assert time.process_time() - started < 5.0
    assert rc.split_blocks("a /* b */ c /* d") == ([" b "], "a   c /* d")
    assert rc.split_blocks("/*/ x") == ([], "/*/ x") and rc.split_blocks("/**/") == ([""], " ")


def test_missing_code_reader_is_named_once(monkeypatch):
    import sys
    monkeypatch.setitem(sys.modules, "zxingcpp", None)               # neither camera decoder imports
    monkeypatch.setitem(sys.modules, "pyzbar", None)
    pages = {"/": (HTML, b"<img src='/a.gif'><img src='/b.gif'>"), "/a.gif": ("image/gif", gif(0)),
             "/b.gif": ("image/gif", gif(2))}
    rep = rc.crawl(dict_fetch(pages, []), FF, read=ocr({}), sleep=lambda s: None)
    note = "codes not read: neither py:zxingcpp nor py:pyzbar is importable"
    assert rep.skipped == [note] and note in rc.result_of(rep).notes


# ---- round 2 of verification -----------------------------------------------------------------------

def test_saved_run_caps_what_it_lists_and_pairs_and_names_each_cap(monkeypatch):
    """A page that names hundreds of folders and of identifiers. Counted, not timed: the pairs are
    made one at a time (one slugs() call each) and stop when the list is full, so the work is the
    cap, not the product of what the page names."""
    made = []
    real_slugs = rc.slugs
    monkeypatch.setattr(rc, "slugs", lambda identifier: (made.append(identifier), real_slugs(identifier))[1])
    names = " ".join(f"/d{k}/" for k in range(400)) + " " + " ".join(f"ID-{k}" for k in range(400))
    rep = rc.examine_saved({"index.html": f"<html><!-- {names} --></html>".encode()}, FF)
    # 400 named folders, then pairs of the first 100 folders and identifiers until 2,000 are listed
    assert len(rep.unsaved) == rc.MAX_LISTED == 2000 and len(made) == 1600        # not 400 x 400
    assert rep.unsaved[399] == ("/d399/", "named on /index.html")
    assert rep.unsaved[400] == ("/d0/id-0", "directory /d0/ with identifier ID-0")
    assert rep.unsaved[-1] == ("/d15/id-99", "directory /d15/ with identifier ID-99")
    assert rep.skipped == [
        "the saved pages name 400 directories and 400 identifiers; only the first 100 of each were paired into routes",
        "8400 directory-and-identifier route(s) are not listed: the list stops at 2000"]
    notes = rc.result_of(rep).notes
    assert rep.skipped[0] in notes and rep.skipped[1] in notes and " and 1960 more" in notes

    monkeypatch.setattr(rc, "MAX_LISTED", 5)
    monkeypatch.setattr(rc, "MAX_PAIR_SIDE", 2)
    page = (b"<a href='/p0'>0</a><a href='/p1'>1</a><a href='/p2'>2</a>"
            b"<!-- /da/ /db/ /dc/ and units AB-1 CD-2 EF-3 -->")
    del made[:]
    rep = rc.examine_saved({"index.html": page}, FF)
    assert [route for route, _why in rep.unsaved] == ["/p0", "/p1", "/p2", "/da/", "/db/"] and made == []
    assert rep.skipped == [
        "1 more route(s) the saved pages offer or name are not listed: the list stops at 5",
        "the saved pages name 3 directories and 3 identifiers; only the first 2 of each were paired into routes",
        "4 directory-and-identifier route(s) are not listed: the list stops at 5"]
    # at the caps exactly nothing is said, and the pairs are the first named of each side
    monkeypatch.setattr(rc, "MAX_LISTED", 12)
    monkeypatch.setattr(rc, "MAX_PAIR_SIDE", 3)
    assert rc.examine_saved({"index.html": page.replace(b"<a href='/p0'>0</a><a href='/p1'>1</a><a href='/p2'>2</a>", b"")},
                            FF).skipped == []
    monkeypatch.setattr(rc, "MAX_PAIR_SIDE", 2)
    rep = rc.examine_saved({"index.html": page}, FF)
    assert [route for route, _why in rep.unsaved][6:] == ["/da/ab-1", "/da/cd-2", "/db/ab-1", "/db/cd-2"]
    assert rep.skipped == ["the saved pages name 3 directories and 3 identifiers; only the first 2 of each were "
                           "paired into routes"]


def test_saved_run_stops_reading_files_at_its_deadline_and_holds_one_at_a_time():
    files = {"a.html": b"<!-- /first/ -->", "b.html": b"<!-- /second/ -->", "c.js": b"// /third/"}
    rep = rc.examine_saved(files, FF, deadline=time.monotonic() - 1)
    assert rep.pages == [] and rep.skipped == ["out of time; 3 saved file(s) were not read, the next being a.html"]
    assert rc.result_of(rep).status == "none"

    class Counting(dict):                                            # how often each file's bytes are asked for
        asked = []

        def __getitem__(self, name):
            self.asked.append(name)
            return dict.__getitem__(self, name)

    files = Counting(files, **{"cam.gif": gif(0)})
    rep = rc.examine_saved(files, FF, ocr="off", codes=no_codes)
    assert len(rep.pages) == 4
    # each file is asked for once, and a GIF once more when it is read: no body is kept in between
    assert sorted(Counting.asked) == ["a.html", "b.html", "c.js", "cam.gif", "cam.gif"]


def test_live_pairs_are_taken_one_at_a_time_and_stop_at_the_queue_cap(monkeypatch):
    made = []
    real_slugs = rc.slugs
    monkeypatch.setattr(rc, "slugs", lambda identifier: (made.append(identifier), real_slugs(identifier))[1])
    monkeypatch.setattr(rc, "MAX_QUEUE", 50)
    names = " ".join(f"/d{k}/" for k in range(300)) + " " + " ".join(f"ID-{k}" for k in range(300))
    rep, log = run({"/": (HTML, f"<html><!-- {names} --></html>".encode())}, max_requests=3)
    # 300 folders named: 50 queued, 250 not; then the first pair finds the queue full, and the
    # other 89,999 are counted, not made
    assert len(made) == 1
    assert "90250 route(s) were never queued: 50 were waiting already; the first was /d50/" in rep.skipped
    assert log == ["/", "/d0/", "/d1/"]

    # a crawl keeps a bounded number of folders and identifiers for pairing, and says so
    monkeypatch.setattr(rc, "MAX_QUEUE", 2000)
    monkeypatch.setattr(rc, "MAX_KNOWN", 2)
    del made[:]
    rep, log = run({"/": (HTML, b"<!-- /da/ /db/ /dc/ /dd/ units AB-1 CD-2 EF-3 GH-4 -->")})
    assert [route for route in log if "-" in route] == ["/da/ab-1", "/da/cd-2", "/db/ab-1", "/db/cd-2"]
    assert rep.skipped == ["directories named after the first 2 were not paired into routes (2 mention(s))",
                           "identifiers named after the first 2 were not paired into routes (2 mention(s))"]
    monkeypatch.setattr(rc, "MAX_KNOWN", 4)
    rep, log = run({"/": (HTML, b"<!-- /da/ /db/ /dc/ /dd/ units AB-1 CD-2 EF-3 GH-4 -->")})
    assert rep.skipped == [] and len([route for route in log if "-" in route and route.count("/") == 2]) == 16


def test_a_route_that_does_not_answer_is_a_miss_once_the_target_has_answered():
    front = (b"<!-- CSCTF{read_before_the_hang} --><a href='/a'>a</a><a href='/stream'>s</a><a href='/b'>b</a>")
    pages = {"/": (HTML, front), "/a": (HTML, b"<p>a</p>"), "/b": (HTML, b"<!-- /deeper/ -->")}
    log = []

    def fetch(route):
        if route.startswith("/s"):
            log.append(route)
            raise rc.CrawlBlocked("no answer, though the target had answered before: timed out")
        return dict_fetch(pages, log)(route)

    rep = rc.crawl(fetch, FF, sleep=lambda s: None)
    assert [page.route for page in rep.pages] == ["/", "/a", "/b"]   # the crawl went on past /stream
    assert log == ["/", "/a", "/stream", "/b", "/deeper/"]
    assert ("/stream", None, "offered on /") in rep.misses and rep.requests == 5
    assert rep.skipped == ["/stream did not answer (offered on /): no answer, though the target had answered "
                           "before: timed out"]
    res = rc.result_of(rep)
    assert res.status == "solved" and res.flags == ("CSCTF{read_before_the_hang}",)
    assert "live crawl: 5 GET(s), 3 answered, 2 did not" in res.notes and rep.skipped[0] in res.notes

    # three in a row end the crawl, with what was read; an answer in between starts the count again
    pages["/"] = (HTML, front + b"<a href='/s1'>1</a><a href='/s2'>2</a><a href='/c'>c</a><a href='/d'>d</a>")
    del log[:]
    rep = rc.crawl(fetch, FF, sleep=lambda s: None)
    assert log == ["/", "/a", "/stream", "/b", "/s1", "/s2", "/c", "/d", "/deeper/"] and len(rep.skipped) == 3
    pages["/"] = (HTML, front.replace(b"<a href='/b'>b</a>", b"") + b"<a href='/s1'>1</a><a href='/s2'>2</a>"
                  b"<a href='/c'>c</a><a href='/d'>d</a>")
    del log[:]
    rep = rc.crawl(fetch, FF, sleep=lambda s: None)
    assert log == ["/", "/a", "/stream", "/s1", "/s2"]
    assert rep.skipped[-1] == "stopped: 3 routes in a row did not answer; 2 route(s) were not tried"
    assert rc.result_of(rep).flags == ("CSCTF{read_before_the_hang}",)

    # a target that never answered is still a block: a refusal is not an answer
    def never(route):
        if route == "/":
            raise ValueError("refused")
        raise rc.CrawlBlocked("the target does not answer")

    with pytest.raises(rc.CrawlBlocked):
        rc.crawl(never, FF, start="/x", sleep=lambda s: None)


class _HangsUp(_Handler):
    """Closes the connection without a word on /stream, and on any ranged GET."""

    def _answer(self):
        if self.path == "/stream" or self.headers.get("Range"):
            self.server.seen.append((self.command, self.path))
            self.close_connection = True
            self.connection.close()
            return
        _Handler._answer(self)

    do_GET = _answer


def test_live_crawl_keeps_what_it_read_when_a_route_hangs_up(tmp_path, monkeypatch):
    flag = "CSCTF{on_the_front_page}"
    pages = {"/": (HTML, f"<!-- {flag} --><a href='/a'>a</a><a href='/stream'>s</a><a href='/b'>b</a>".encode()),
             "/a": (HTML, b"<p>a</p>"), "/b": (HTML, b"<p>b</p>")}
    with serve(pages, handler=_HangsUp) as (server, url):
        res = rc.solve(tmp_path, PROFILE, seconds=BUDGET, url=url + "/", gap=0)
        seen = [path for _method, path in server.seen]
    assert seen == ["/", "/a", "/stream", "/b"]
    assert res.status == "solved" and res.flags == (flag,)           # not `blocked`: three pages had answered
    assert "live crawl: 4 GET(s), 3 answered, 1 did not" in res.notes
    assert "/stream did not answer (offered on /): no answer, though the target had answered before: " in res.notes
    assert "tools/vpn.py" not in res.notes                           # that advice is for a target that never answered

    # a body over the client's cap whose ranged GET hangs up: the first part is kept and named as a part
    import web
    monkeypatch.setattr(web, "MAX_BODY", 4096)
    long = f"<html><!-- {flag} --><p>".encode() + b"filler " * 1500 + b"</p></html>"
    with serve({"/": (HTML, long)}, handler=_HangsUp) as (server, url):
        res = rc.solve(tmp_path, PROFILE, seconds=BUDGET, url=url + "/", gap=0)
        assert [path for _method, path in server.seen] == ["/", "/"]
    assert res.flags == (flag,) and res.status == "solved"
    assert ("/ [html, start]: 1 comment(s): " + flag) in res.notes
    assert ("the client cut the body at 4096 bytes and the ranged GET for the rest did not answer; "
            "the first 4096 bytes were read") in res.notes


def test_a_location_is_followed_only_from_a_3xx_and_counts_as_a_link_deep():
    """Two mutations of the redirect code survived round 1: following a Location on a miss that
    is not a 3xx, and queueing a redirect's target at the redirecting route's own depth."""
    log = []

    def fetch(route):
        log.append(route)
        if route == "/":
            return 200, HTML, b"<a href='/gone'>a</a><a href='/broken'>b</a>"
        if route == "/gone":
            return 404, HTML, b"", {"location": "/not-a-redirect"}
        if route == "/broken":
            return 500, HTML, b"", {"location": "/nor-this"}
        return 200, HTML, b"<p>reached</p>"

    rep = rc.crawl(fetch, FF, sleep=lambda s: None)
    assert log == ["/", "/gone", "/broken"]                          # a Location on a 404 or a 500 is not a lead
    assert rep.misses == [("/gone", 404, "offered on /"), ("/broken", 500, "offered on /")]

    chain = {"/r1": "/r2", "/r2": "/r3", "/r3": "/r4", "/r4": "/r5"}

    def hops(route):
        log.append(route)
        if route == "/":
            return 200, HTML, b"<a href='/r1'>in</a>"
        if route in chain:
            return 302, HTML, b"", {"location": chain[route]}
        return 200, HTML, b"<!-- CSCTF{at_the_end_of_the_chain} -->"

    for limit, want in ((1, ["/", "/r1"]), (2, ["/", "/r1", "/r2"]), (3, ["/", "/r1", "/r2", "/r3"]),
                        (5, ["/", "/r1", "/r2", "/r3", "/r4", "/r5"])):
        del log[:]
        rep = rc.crawl(hops, FF, sleep=lambda s: None, max_depth=limit)
        assert log == want, limit                                    # each hop of a chain is one link deeper
    assert rep.pages[-1].why == "redirect from /r4" and rep.pages[-1].flags == ["CSCTF{at_the_end_of_the_chain}"]
