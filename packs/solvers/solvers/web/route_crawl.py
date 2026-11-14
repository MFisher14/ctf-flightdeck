#!/usr/bin/env python3
"""Web engine `route_crawl` (B-117): comments, routes and identifiers of a site, followed together.

At the 2026 Spooky event one web challenge was a chain no single page gave away: a comment on
each page named the next directory, an identifier painted into that page's camera GIF named the
page inside it, and the last page's script held one GIF frame back. Each step is mechanical once
the comments, the routes and the text in the frames are read together, so this does that:

  harvest   every page gives up its comments (HTML, script and style), the routes it offers
            (attributes, script strings), the path-like tokens in its comments and plain text,
            the identifiers in its text and comments (BAY-41, KX 58), any attribute that names a
            timed reveal, and every flag in its bytes.
  frames    a GIF goes to gif_reveal: every frame whatever its delay, OCR for the identifiers and
            flags painted in it, codes, comment blocks. The frames are written for a model read.
  routes    what a page offers is followed first, then the paths its comments and text name, then
            routes made of a directory and an identifier (lower case, a dash: /decks/hold/ and
            KX 58 give /decks/hold/kx-58). A pair that one page named together comes first, and
            only such a pair is tried in its other spellings (kx58, kx_58) when it misses; a pair
            put together from two pages, or with a folder a page was merely found in, costs one
            request. A folder only assets were loaded from, and the site root, are not guessed in.

Two ways to run, one logic:

  saved     over the challenge's saved pages (no network; what intake runs). Every saved text
            page and GIF is harvested (a file is told from its first bytes: a binary, a picture
            or an archive is never read whole); the routes they name that are not saved, and the
            directory-and-identifier routes, are listed for the agent to fetch, up to MAX_LISTED.
            A saved GIF gives its comment blocks and codes here; its frames are left to
            toolkits.gif_reveal, which intake runs on every GIF (two engines compositing, writing
            and reading the same frames spent the challenge's intake budget twice). `ocr=auto`
            or `ocr=on` reads and writes them here as well.
  live      `url=<start>`: a breadth-first GET crawl of that one origin through the scope-locked
            client (solvers/toolkits/web.py WebClient, get_only=True, the client the web lane
            uses). The scope is checked twice: the profile handed to solve() must allow the host
            (ctf.scope.check_url with that profile, before any client is built), and the client
            checks the current event as well. Nothing but GET is sent and nothing leaves the
            origin. A route that does not answer after the target has is a miss, and the
            crawl goes on (it stops after MAX_SILENT in a row); what was read is reported. No
            redirect is followed by the client: a 3xx is a miss, and its Location is
            queued like a link the page offered, so every guard below applies to it. A route with
            a state-changing word (proof_hunt.is_destructive: logout, delete, reset, ...) is never
            requested, whether a page offered it or a redirect pointed at it. The crawl is capped
            (requests, depth, seconds) and paced. The client keeps the first 1 MiB of a body; the
            rest of a larger one (a camera GIF) is read by ranged GETs, each counted as a request,
            up to MAX_ASSET. A body that could not be read whole is named, with why, and a result
            that rests on a cut body is never `none`.

  solve(challenge_dir, profile, **opts) -> SolverResult      the engine contract (python -m ctf run)
  crawl(fetch, ff, ...) -> Report                             the live logic over any fetch(route)
  examine_saved(files, ff, ...) -> Report                     the saved-pages run over {name: bytes}
  saved_files(challenge_dir) -> ({name: bytes}, notes)        the text pages and GIFs of a challenge
  harvest(route, body, content_type="") -> Page
  comments_of(text, kind);  path_tokens(text);  resolve(base, ref, origin=None);  slugs(identifier)

  .venv/bin/python -m ctf run web.route_crawl <challenge_dir> [--opt url=http://host:port/] [--opt ocr=off]

Status: a flag in a page's bytes, a GIF comment block or a decoded code is `solved` when it is the
only one; a flag read by OCR is never more than `candidate`. Pages with comments, routes or
identifiers and no flag are `unsure`, the chain named. A scope refusal or an unreachable target is
`blocked`, saying which. An identifier that is painted too roughly for OCR, or a directory a page
only describes in words, is not guessed: the frames are written and the notes say what was tried.
"""
from __future__ import annotations

import argparse
import heapq
import itertools
import html
import posixpath
import re
import sys
import time
import urllib.parse
from collections.abc import Mapping
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path

try:
    from ctf import flagfmt
except ModuleNotFoundError:
    sys.path.append(str(Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

HERE = Path(__file__).resolve().parent
_TK = HERE.parent / "toolkits"
if str(_TK) not in sys.path:
    sys.path.append(str(_TK))

import _visual_stego as vs      # noqa: E402
import gif_reveal               # noqa: E402

ENGINE = "web.route_crawl"
MAX_FILE = 8 << 20                    # bytes of one saved page
MAX_TEXT = 2 << 20                    # characters of one page that are parsed
MAX_REQUESTS = 60                     # GETs one live crawl sends
MAX_DEPTH = 10                        # links deep a live crawl goes
MAX_QUEUE = 2000                      # routes waiting at once
MAX_LISTED = 2000                     # routes one saved run lists as not saved (its notes print the first 40)
MAX_PAIR_SIDE = 100                   # directories, and identifiers, one saved run pairs with each other
MAX_KNOWN = 500                       # directories, and identifiers, one live crawl keeps for pairing
MAX_SILENT = 3                        # routes in a row with no answer at which a live crawl stops
HEAD = 4096                           # first bytes of a saved file that tell what it is (all that sniff() looks at)
MAX_ROUTE = 512                       # characters of one route
MAX_ASSET = 8 << 20                   # bytes of one live body, read by ranged GETs past the client's cap
GAP = 0.1                             # seconds between two GETs
DEFAULT_SECONDS = 45.0                # a live crawl; under the 60 s the manifest gives the engine
SAVED_SECONDS = 10.0                  # the saved run: no OCR by default, so parsing and codes only
LINK_ATTRS = {"href", "src", "action", "poster", "data", "formaction", "background", "cite", "longdesc"}
REVEAL_WORDS = ("reveal", "delay", "hidden", "secret", "timed")
OFFERED, NAMED, PAIRED, RESPELT, CROSSED = 0, 1, 2, 3, 4      # queue priorities, best first

_PATH = re.compile(r"(?<![A-Za-z0-9_.:/~%-])/(?:[A-Za-z0-9._~%-]+/)*[A-Za-z0-9._~%-]*")
_SCRIPT_STRING = re.compile(r"""(["'`])((?:/|\.{1,2}/)[^"'`\s<>\\]{1,300}|[A-Za-z0-9._~%/-]{1,200}\.(?:gif|png|jpe?g|webp|js|json|html?|php|txt|xml|css))\1""")
_LINE_COMMENT = re.compile(r"(?m)(?<![:\"'\\/])//([^\n]*)")
_IMAGE_MAGIC = (b"\x89PNG", b"\xff\xd8\xff", b"RIFF", b"BM", b"\x00\x00\x01\x00")


class CrawlBlocked(RuntimeError):
    """The live crawl could not run or go on: out of scope, unreachable, or the client is missing.
    From a fetch it means the route did not answer: that ends the crawl only while nothing has
    answered yet."""


# ---- harvesting one page ---------------------------------------------------------------------------

@dataclass
class Page:
    route: str
    status: int | None = 200
    kind: str = "other"               # html | script | style | text | gif | image | other
    why: str = "start"                # how the crawl came to this route
    comments: list = field(default_factory=list)
    links: list = field(default_factory=list)          # references the page offers, as written
    named: list = field(default_factory=list)          # path-like tokens in its comments and plain text
    identifiers: list = field(default_factory=list)
    reveal: list = field(default_factory=list)         # attributes that name a timed reveal
    flags: list = field(default_factory=list)          # proven: in the page's bytes
    ocr_flags: list = field(default_factory=list)      # candidates: read by OCR out of a GIF
    notes: list = field(default_factory=list)
    cut: str = ""                     # why the body is not whole (the client's cap, no ranged GETs), or ""


class _Html(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.comments, self.links, self.reveal, self.text, self.scripts, self.styles = [], [], [], [], [], []
        self._inside = None

    def handle_comment(self, data):
        self.comments.append(data.strip())

    def handle_starttag(self, tag, attrs):
        self._inside = tag if tag in ("script", "style") else None
        for name, value in attrs:
            name = (name or "").lower()
            if any(word in name for word in REVEAL_WORDS):
                self.reveal.append(f"<{tag} {name}={value!r}>" if value is not None else f"<{tag} {name}>")
            if not value:
                continue
            if name in LINK_ATTRS or (name.startswith("data-") and _looks_like_reference(value)):
                self.links.append(value)
            elif name == "srcset":
                self.links += [part.split()[0] for part in value.split(",") if part.split()]
            elif name in ("alt", "title", "content", "value", "placeholder"):
                self.text.append(value)

    def handle_endtag(self, tag):
        self._inside = None

    def handle_data(self, data):
        if self._inside == "script":
            self.scripts.append(data)
        elif self._inside == "style":
            self.styles.append(data)
        else:
            self.text.append(data)


def _looks_like_reference(value: str) -> bool:
    value = value.strip()
    return bool(value) and " " not in value and (value.startswith(("/", "./", "../", "http://", "https://"))
                                                 or bool(re.search(r"\.[A-Za-z0-9]{2,5}(?:\?|$)", value)))


def split_blocks(text: str) -> tuple:
    """([block comment bodies], the text with each block replaced by a blank). One pass with
    str.find: an opener with no closer ends the scan (nothing after it can close one either), so a
    page of unclosed openers costs its length, not its length squared."""
    blocks, rest, pos = [], [], 0
    while True:
        start = text.find("/*", pos)
        end = text.find("*/", start + 2) if start >= 0 else -1
        if end < 0:
            break
        blocks.append(text[start + 2:end])
        rest.append(text[pos:start])
        pos = end + 2
    rest.append(text[pos:])
    return blocks, " ".join(rest)


def comments_of(text: str, kind: str) -> list:
    """The comments of a script or style source: /* blocks */ and, in a script, // lines (a //
    inside a URL or a string that starts one is left alone)."""
    blocks, rest = split_blocks(text)
    out = [block.strip() for block in blocks]
    if kind == "script":
        out += [m.group(1).strip() for m in _LINE_COMMENT.finditer(rest)]
    return [c for c in out if c]


def path_tokens(text: str) -> list:
    """The path-like tokens of a text: a slash, then segments of letters, digits and . _ ~ % -,
    at least one letter among them (so a date or a fraction is not a path), deduplicated."""
    out = []
    for m in _PATH.finditer(text or ""):
        token = m.group(0).rstrip(".")
        if len(token) > 1 and re.search(r"[A-Za-z]", token) and len(token) <= MAX_ROUTE:
            out.append(token)
    return list(dict.fromkeys(out))


def script_routes(text: str) -> list:
    """The string literals of a script that are routes: a rooted or dot-relative path, or a
    relative name with a web file extension."""
    return list(dict.fromkeys(m.group(2) for m in _SCRIPT_STRING.finditer(text or "")))


def sniff(route: str, body: bytes, content_type: str = "") -> str:
    """What a fetched body is: gif, image, html, script, style, text or other."""
    if body[:6] in (b"GIF87a", b"GIF89a"):
        return "gif"
    if body.startswith(_IMAGE_MAGIC):
        return "image"
    if b"\x00" in body[:4096]:
        return "other"
    ctype, path = content_type.lower(), route.split("?")[0].lower()
    head = body[:2048].lstrip().lower()
    if "html" in ctype or head.startswith((b"<!doctype", b"<html", b"<!--", b"<head", b"<body")) \
            or path.endswith((".html", ".htm", ".xhtml", ".php")):
        return "html"
    if "javascript" in ctype or "ecmascript" in ctype or path.endswith((".js", ".mjs", ".cjs")):
        return "script"
    if "css" in ctype or path.endswith(".css"):
        return "style"
    return "text"


def harvest(route: str, body: bytes, content_type: str = "", ff=None) -> Page:
    """One fetched or saved body as a Page: its kind, comments, offered links, named paths,
    identifiers, timed-reveal attributes and (with a flag format) the flags in its bytes. A GIF or
    image is only classified here; gif_reveal reads GIFs."""
    page = Page(route, kind=sniff(route, body, content_type))
    if ff is not None:
        page.flags = list(ff.find_flags(body))
    if page.kind in ("gif", "image", "other"):
        return page
    text = body.decode("utf-8", "replace")
    if len(text) > MAX_TEXT:
        page.notes.append(f"only the first {MAX_TEXT} characters were parsed")
        text = text[:MAX_TEXT]
    if page.kind == "html":
        parser = _Html()
        try:
            parser.feed(text)
            parser.close()
        except Exception as exc:                        # html.parser is lenient; a failure is named
            page.notes.append(f"HTML parse stopped: {type(exc).__name__}: {exc}")
        scripts, styles = "\n".join(parser.scripts), "\n".join(parser.styles)
        page.comments = [c for c in parser.comments if c] + comments_of(scripts, "script") + comments_of(styles, "style")
        page.links = parser.links + script_routes(scripts)
        page.reveal = parser.reveal
        visible = "\n".join(parser.text)
    else:
        page.comments = comments_of(text, page.kind) if page.kind in ("script", "style") else []
        page.links = script_routes(text) if page.kind == "script" else []
        visible = text if page.kind == "text" else ""
    spoken = "\n".join(page.comments)
    page.named = list(dict.fromkeys(path_tokens(spoken) + path_tokens(visible)))
    page.links = list(dict.fromkeys(page.links))
    page.identifiers = gif_reveal.identifiers(spoken + "\n" + visible)
    return page


# ---- routes ----------------------------------------------------------------------------------------

def resolve(base: str, ref: str, origin: str | None = None) -> str | None:
    """A reference as written on the page at `base`, as an origin-rooted route (path and query,
    dot segments resolved, no fragment), or None when it is not a route of this origin: another
    scheme (mailto:, javascript:, data:), another host (`origin` is scheme://host[:port]; with no
    origin every absolute URL is another host), a fragment only, control characters, or over
    MAX_ROUTE characters."""
    ref = html.unescape(ref or "").strip()
    if not ref or ref.startswith("#") or any(ord(ch) < 0x21 or ord(ch) == 0x7F for ch in ref) or "\\" in ref:
        return None
    if ref.startswith("//"):                            # scheme-relative: the origin's scheme, a host of its own
        if origin is None:
            return None
        ref = origin.split(":", 1)[0] + ":" + ref
    try:
        parts = urllib.parse.urlsplit(ref)
    except ValueError:
        return None
    if parts.scheme or parts.netloc:
        if parts.scheme.lower() not in ("http", "https") or origin is None \
                or f"{parts.scheme}://{parts.netloc}".lower() != origin.lower().rstrip("/"):
            return None
        path = parts.path or "/"
    else:
        folder = base.split("?")[0]
        folder = folder if folder.endswith("/") else posixpath.dirname(folder) + "/"
        path = parts.path if parts.path.startswith("/") else folder.rstrip("/") + "/" + parts.path
        if not parts.path and parts.query:
            path = base.split("?")[0]
    trailing = path.endswith("/") or path.endswith(("/.", "/.."))
    path = posixpath.normpath(path) if path else "/"
    path = "/" + path.lstrip("/")
    if trailing and not path.endswith("/"):
        path += "/"
    route = path + ("?" + parts.query if parts.query else "")
    return route if len(route) <= MAX_ROUTE else None


def slugs(identifier: str) -> list:
    """The spellings of an identifier a route could use, likeliest first: lower case with a dash
    (bay-41), run together (bay41), with an underscore (bay_41)."""
    m = gif_reveal.IDENTIFIER.fullmatch(identifier.strip())
    if not m:
        return []
    word, number = m.group(1).lower(), m.group(2)
    return [f"{word}-{number}", f"{word}{number}", f"{word}_{number}"]


def directories_of(route: str) -> list:
    """The directories a route lies in or is, deepest first: /a/b/c -> /a/b/, /a/; /a/b/ -> /a/b/, /a/.
    The root is not listed (pairing every identifier with it is a guess, not a lead)."""
    path = route.split("?")[0]
    parts = [p for p in path.split("/") if p]
    if not path.endswith("/"):
        parts = parts[:-1]
    return ["/" + "/".join(parts[:n]) + "/" for n in range(len(parts), 0, -1)]


def paired_routes(directories, identifiers):
    """Yields (route, directory, identifier): every directory joined with every identifier in its
    dash spelling (slugs()[0]; the other spellings are tried only when such a route misses). A
    generator: a page that names thousands of each costs what is taken from it, not their
    product."""
    for directory in directories:
        for identifier in identifiers:
            spelt = slugs(identifier)
            if spelt:
                yield directory + spelt[0], directory, identifier


# ---- one delivery ----------------------------------------------------------------------------------

@dataclass
class Report:
    mode: str = "saved"               # saved | live
    pages: list = field(default_factory=list)           # [Page] that answered (or were saved)
    misses: list = field(default_factory=list)          # [(route, status, why)] that did not
    refused: list = field(default_factory=list)         # [(route, reason)] never requested
    unsaved: list = field(default_factory=list)         # saved mode: [(route, why)] named but not saved
    animations: list = field(default_factory=list)      # gif_reveal Animations
    written: list = field(default_factory=list)
    skipped: list = field(default_factory=list)
    requests: int = 0
    ocr: str = "not needed"


def _ocr_rank(state: str) -> int:
    """Order of the OCR states a report can be in, so that it names the worst one a run met."""
    return 3 if state.startswith("not run") else {"run": 2, "off": 1}.get(state, 0)


def _read_gif(route: str, body: bytes, page: Page, rep: Report, ff, *, ocr, out_dir, deadline, prefixes, read, codes):
    """Read one GIF with gif_reveal into `page` (identifiers, flags) and the report."""
    try:
        got = gif_reveal.examine({route.strip("/") or "root.gif": body}, ff, ocr=ocr, out_dir=out_dir,
                                 deadline=deadline, prefixes=prefixes, read=read, codes=codes)
    except gif_reveal.ToolMissing as exc:
        raise CrawlBlocked(f"the GIF {route} could not be read as asked (ocr={ocr}): {exc}") from exc
    rep.written += got.written
    rep.skipped += [note for note in got.skipped if note not in rep.skipped]
    rep.ocr = max(rep.ocr, got.ocr, key=_ocr_rank)
    for anim in got.animations:
        rep.animations.append(anim)
        page.identifiers = list(dict.fromkeys(page.identifiers + anim.identifiers))
        page.flags = list(dict.fromkeys(page.flags + [flag for flag, _kind, _where in anim.proven]))
        page.ocr_flags = list(dict.fromkeys(page.ocr_flags + anim.ocr_flags))
        for k, why in anim.suspects:
            page.notes.append(f"frame {k} is {why}")
        if anim.total > 1:
            page.notes.append(f"{anim.total} frames")


def crawl(fetch, ff, *, start: str = "/", origin: str | None = None, max_requests: int | None = None,
          max_depth: int | None = None, deadline=None, gap: float | None = None, ocr: str = "auto",
          out_dir: Path | None = None, prefixes=(), destructive=None, read=None, codes=None,
          sleep=time.sleep) -> Report:
    """A breadth-first GET crawl of one origin. `fetch(route) -> (status, content_type, body)` makes
    the request. A refusal it raises as ValueError is recorded for that route. CrawlBlocked from
    it means the route did not answer: while nothing has answered yet that is the target being
    unreachable, and it propagates; once any route has answered it is a miss (status None) and
    the crawl goes on with what it has, stopping after MAX_SILENT such routes in a row. It may
    return a fourth item, a dict: `location` (the
    Location of a 3xx it did not follow), `cut` (why the body is not whole) and `requests` (how
    many GETs the answer cost, when more than one). A 3xx is a miss; its Location is queued as a
    link the route offered, so the origin check, the destructive guard, the depth and the request
    budget apply to where it points. Routes are taken best first: offered by a page, named
    on one, a directory and an identifier one page named together (dash spelling), such a pair
    from two pages. Only when a same-page pair misses are its other spellings tried, so a guess
    costs one request unless the page itself made it likely. `destructive(route)` (default
    proof_hunt.is_destructive) vetoes a route before any request. Stops at `max_requests` (default
    MAX_REQUESTS), `max_depth` links from the start, or `deadline` (time.monotonic()), and says
    which."""
    max_requests = MAX_REQUESTS if max_requests is None else max_requests
    max_depth = MAX_DEPTH if max_depth is None else max_depth
    gap = GAP if gap is None else gap
    destructive = destructive or _is_destructive()
    rep = Report(mode="live")
    queue, order, seen = [], 0, set()
    directories, known_ids = {}, {}                     # directory -> {pages that named it in words}; identifier -> {pages}
    dropped, first_dropped = 0, None                    # routes never queued: counted, the first one named
    unpaired = {"directories": 0, "identifiers": 0}     # named past MAX_KNOWN: not kept for pairing
    answered_any, silent = False, 0                     # has any route answered; routes in a row that did not

    def push(priority, route, why, depth, parent=None, pair=None) -> bool:
        """False when the queue is full (the route is counted as never queued)."""
        nonlocal order, dropped, first_dropped
        if not route or route in seen:
            return True
        if len(queue) >= MAX_QUEUE:                     # a page of thousands of links: the cap is named below
            dropped += 1
            first_dropped = first_dropped or route
            return False
        order += 1
        heapq.heappush(queue, (priority, order, route, why, depth, parent, pair))
        return True

    first = resolve("/", start, origin) or "/"
    push(OFFERED, first, "start", 0)
    answered = set()                                    # (directory, identifier) pairs some spelling of which answered
    while queue:
        _priority, _order, route, why, depth, parent, pair = heapq.heappop(queue)
        if route in seen or (pair is not None and pair[:2] in answered):
            continue
        if rep.requests >= max_requests:
            rep.skipped.append(f"stopped at {max_requests} requests; {len(queue) + 1} route(s) were not tried, "
                               f"the next being {route} ({why})")
            break
        if deadline is not None and time.monotonic() > deadline:
            rep.skipped.append(f"out of time; {len(queue) + 1} route(s) were not tried, the next being {route} ({why})")
            break
        seen.add(route)
        if destructive(route):
            rep.refused.append((route, "it names a state-changing action; never requested"))
            continue
        if rep.requests:
            sleep(gap)
        rep.requests += 1
        try:
            answer = tuple(fetch(route))
        except ValueError as exc:
            rep.refused.append((route, str(exc)))
            continue
        except CrawlBlocked as exc:
            if not answered_any:                        # the target itself is not there: nothing to report
                raise
            silent += 1
            rep.misses.append((route, None, why))
            rep.skipped.append(f"{route} did not answer ({why}): {' '.join(str(exc).split())[:200]}")
            if silent >= MAX_SILENT:
                rep.skipped.append(f"stopped: {MAX_SILENT} routes in a row did not answer; {len(queue)} route(s) "
                                   "were not tried")
                break
            continue
        answered_any, silent = True, 0
        status, content_type, body = answer[:3]
        info = answer[3] if len(answer) > 3 else {}
        rep.requests += max(0, int(info.get("requests", 1)) - 1)
        if status is None or not 200 <= status < 300:
            rep.misses.append((route, status, why))
            location = str(info.get("location") or "").strip()
            if location and status is not None and 300 <= status < 400:
                target = resolve(route, location, origin)
                if target is None:
                    if re.match(r"(?i)https?://|//", location):
                        rep.refused.append((location[:MAX_ROUTE], f"another origin (redirect from {route}); never requested"))
                elif depth < max_depth:                 # where it points is vetted like any offered link
                    push(OFFERED, target, f"redirect from {route}", depth + 1, parent, pair)
            elif pair is not None and not pair[2]:      # a same-page pair missed: its other spellings
                directory, identifier, _respelt = pair
                for slug in slugs(identifier)[1:]:
                    push(RESPELT, directory + slug, f"{why}, spelt {slug}", depth, pair=(directory, identifier, True))
            continue
        if pair is not None:
            answered.add(pair[:2])
        page = harvest(route, body, content_type, ff)
        page.status, page.why = status, why
        if info.get("cut"):
            page.cut = str(info["cut"])
            page.notes.append(page.cut)
            rep.skipped.append(f"{route}: {page.cut}")
        rep.pages.append(page)
        if page.kind == "gif":
            _read_gif(route, body, page, rep, ff, ocr=ocr, out_dir=out_dir, deadline=deadline, prefixes=prefixes,
                      read=read, codes=codes)
        # what a GIF's frames say belongs to the page that showed it: that page's directories pair
        # with the identifiers in its frames first
        owner = parent if page.kind == "gif" and parent else route
        if depth < max_depth:
            for ref in page.links:
                target = resolve(route, ref, origin)
                if target is None:
                    if re.match(r"(?i)https?://|//", ref.strip()):
                        rep.refused.append((ref.strip()[:MAX_ROUTE], f"another origin (offered on {route}); never requested"))
                    continue
                push(OFFERED, target, f"offered on {route}", depth + 1, route)
            for token in page.named:
                push(NAMED, resolve(route, token, origin), f"named on {route}", depth + 1, route)
        fresh_dirs = []

        def learn(directory, named_by=None):
            fresh = directory not in directories
            if fresh and len(directories) >= MAX_KNOWN:
                unpaired["directories"] += 1
                return
            owners = directories.setdefault(directory, set())
            if named_by is not None and named_by not in owners:
                owners.add(named_by)
                fresh = True
            if fresh and directory not in fresh_dirs:
                fresh_dirs.append(directory)

        # a directory a page names in words is a lead of that page; its parents, and the folders
        # pages were found in, are places to look. A folder only assets were loaded from is neither.
        for token in page.named:
            target = resolve(route, token, origin)
            for k, directory in enumerate(directories_of(target) if target else []):
                learn(directory, owner if k == 0 else None)
        if page.kind == "html":
            for directory in directories_of(route):
                learn(directory)
        fresh_ids = []
        for identifier in page.identifiers:
            if identifier not in known_ids and len(known_ids) >= MAX_KNOWN:
                unpaired["identifiers"] += 1
                continue
            if owner not in known_ids.setdefault(identifier, set()):
                known_ids[identifier].add(owner)
                fresh_ids.append(identifier)
        if depth < max_depth:
            # taken one at a time, and no further once the queue is full: what is left is counted
            # by its size, not walked (a page can name thousands of folders and of identifiers)
            old_ids = [identifier for identifier in known_ids if identifier not in fresh_ids]
            total, taken = len(directories) * len(fresh_ids) + len(fresh_dirs) * len(old_ids), 0
            for target, directory, identifier in itertools.chain(paired_routes(list(directories), fresh_ids),
                                                                 paired_routes(fresh_dirs, old_ids)):
                taken += 1
                together = directories[directory] & known_ids[identifier]
                if not push(PAIRED if together else CROSSED, target, f"directory {directory} with identifier {identifier}"
                            + (f" (both from {sorted(together)[0]})" if together else ""), depth + 1,
                            pair=(directory, identifier, False) if together else None):
                    dropped += total - taken
                    break
    if dropped:
        rep.skipped.append(f"{dropped} route(s) were never queued: {MAX_QUEUE} were waiting already; "
                           f"the first was {first_dropped}")
    for what, count in unpaired.items():
        if count:
            rep.skipped.append(f"{what} named after the first {MAX_KNOWN} were not paired into routes "
                               f"({count} mention(s))")
    return rep


def _is_destructive():
    """proof_hunt.is_destructive, loaded the way the web lane loads the proof reader."""
    from ctf import web_lane
    try:
        return web_lane.load_proof_hunt().is_destructive
    except (web_lane.WebLaneError, AttributeError) as exc:
        raise CrawlBlocked(f"the destructive-route guard (solvers/web/proof_hunt.py is_destructive) is missing: {exc}") from exc


def live_fetch(url: str, timeout: float = 10.0, *, max_requests: int | None = None, gap: float | None = None,
               deadline=None, sleep=time.sleep):
    """(fetch, origin, start route) for a live crawl of `url` through the scope-locked, GET-only
    WebClient. CrawlBlocked when the client's scope guard refuses the host or the URL is unusable,
    and from fetch() when a route does not answer (crawl() decides what that means).

    The client follows no redirect here (allow_redirects=False): a 3xx comes back as it is, with
    its Location for the crawl to vet. The client keeps at most its MAX_BODY (1 MiB) of a body and
    says so (`truncated`); the rest is read by ranged GETs of that size, each paced by `gap` and
    counted against `max_requests` (all GETs this fetch sends, the crawl's own included) and
    `deadline`. A body that is still not whole (no ranged GETs on the server, the budget or the
    time ran out, over MAX_ASSET) comes back with why in `cut`."""
    import web
    try:
        client = web.WebClient(url, timeout=timeout, get_only=True)
    except web.OutOfScope as exc:
        raise CrawlBlocked(f"the live target is refused: {exc}") from exc
    parts = urllib.parse.urlsplit(client.base)
    max_requests = MAX_REQUESTS if max_requests is None else max_requests
    gap = GAP if gap is None else gap
    cap = web.MAX_BODY
    sent, got = [0], [0]                                # GETs sent; GETs that came back with a response

    def get(route, **kw):
        sent[0] += 1
        try:
            answer = client.get(route, allow_redirects=False, **kw)
        except web.OutOfScope as exc:
            raise ValueError(f"refused by the scope-locked client: {exc}") from exc
        except web.VPNRequired as exc:
            if not got[0]:                              # nothing ever answered: the client's advice (the VPN) applies
                raise CrawlBlocked(f"the target does not answer: {exc}") from exc
            raise CrawlBlocked(f"no answer, though the target had answered before: {exc.__cause__ or exc}") from exc
        got[0] += 1
        headers = {str(k).lower(): str(v) for k, v in (answer.get("response_headers") or {}).items()}
        return answer, headers

    def rest(route, body):
        """(body, why it is still not whole or "") after ranged GETs for what the client cut."""
        cut = f"the client cut the body at {cap} bytes"
        while len(body) < MAX_ASSET:
            if sent[0] >= max_requests:
                return body, f"{cut} and the request budget ended; the first {len(body)} bytes were read"
            if deadline is not None and time.monotonic() > deadline:
                return body, f"{cut} and the time ran out; the first {len(body)} bytes were read"
            sleep(gap)
            try:
                answer, headers = get(route, headers={"Range": f"bytes={len(body)}-{len(body) + cap - 1}"})
            except ValueError as exc:
                return body, f"{cut} and the ranged GET for the rest was refused ({exc}); the first {len(body)} bytes were read"
            except CrawlBlocked:                        # the first part answered: it is kept, and named as a part
                return body, f"{cut} and the ranged GET for the rest did not answer; the first {len(body)} bytes were read"
            span = re.fullmatch(r"bytes (\d+)-(\d+)/(\d+|\*)", headers.get("content-range", "").strip())
            chunk = answer.get("body") or b""
            if answer.get("status") != 206 or not span or int(span.group(1)) != len(body) or not chunk:
                return body, (f"{cut} and the server does not answer ranged GETs (status {answer.get('status')}); "
                              f"the first {len(body)} bytes were read")
            body += chunk
            if (span.group(3) != "*" and len(body) >= int(span.group(3))) or (span.group(3) == "*" and len(chunk) < cap):
                return body, ""
        return body[:MAX_ASSET], (f"{cut} and the body is over the {MAX_ASSET} byte cap for one asset; "
                                  f"the first {MAX_ASSET} bytes were read")

    def fetch(route):
        before = sent[0]
        answer, headers = get(route)
        status, body, info = answer.get("status"), answer.get("body") or b"", {}
        if status is not None and 300 <= status < 400 and headers.get("location"):
            info["location"] = headers["location"]
        if answer.get("truncated"):
            body, why = rest(route, body)
            if why:
                info["cut"] = why
        info["requests"] = sent[0] - before
        return status, headers.get("content-type", ""), body, info

    return fetch, client.origin, (parts.path or "/") + ("?" + parts.query if parts.query else "")


def examine_saved(files: dict, ff, *, ocr: str = "auto", out_dir: Path | None = None, deadline=None, prefixes=(),
                  read=None, codes=None) -> Report:
    """The saved-pages run over {relative name: bytes}: no request is made. Every text page and
    GIF is harvested (a file named a/b.html is the route /a/b.html); `unsaved` lists the routes the
    pages offer or name that are not among the files, then the directory-and-identifier routes
    (dash spelling) that are not, each with why, for the agent to fetch. Files that are neither
    text nor GIF are left to their own engines. Nothing is reported unless a saved file is HTML.

    What one run costs is capped and each cap is named in `skipped`: files not reached before
    `deadline`; MAX_LISTED routes listed; MAX_PAIR_SIDE directories and as many identifiers
    paired (the first named, in file order), the pairs made one at a time until the list is
    full. With `ocr="off"` a GIF's frames are neither composited nor written here (out_dir is
    not used): its comment blocks, trailing bytes and codes are read."""
    rep = Report(mode="saved")
    routes = {"/" + name.lstrip("/"): name for name in files}
    pages = {}
    todo = sorted(routes)
    for k, route in enumerate(todo):
        if deadline is not None and time.monotonic() > deadline:
            rep.skipped.append(f"out of time; {len(todo) - k} saved file(s) were not read, the next being {routes[route]}")
            break
        body = files[routes[route]]
        if len(body) > MAX_FILE:
            rep.skipped.append(f"{routes[route]}: over the {MAX_FILE} byte cap, not read")
            continue
        page = harvest(route, body, "", ff)
        page.why = "saved"
        if page.kind in ("image", "other"):
            continue
        pages[route] = page                             # the page, not its bytes: one body is held at a time
    if not any(page.kind == "html" for page in pages.values()):
        return rep
    for route, page in pages.items():
        if page.kind == "gif":
            _read_gif(route, files[routes[route]], page, rep, ff, ocr=ocr, out_dir=out_dir if ocr != "off" else None,
                      deadline=deadline, prefixes=prefixes, read=read, codes=codes)
        rep.pages.append(page)
    saved = set(routes) | {r[:-len("index.html")] for r in routes if r.endswith("/index.html")}
    listed, more = {}, 0                                # route -> why; routes past MAX_LISTED (counted, not kept)
    directories, identifiers = {}, {}                   # insertion-ordered sets: the first named are the ones paired

    def note(target, why):
        nonlocal more
        if target in listed:
            return
        if len(listed) >= MAX_LISTED:
            more += 1
            return
        listed[target] = why

    for page in rep.pages:
        for ref, why in [(r, "offered on") for r in page.links] + [(r, "named on") for r in page.named]:
            target = resolve(page.route, ref)
            if target is None:
                continue
            if why == "named on":
                directories.update(dict.fromkeys(directories_of(target)))
            if target not in saved and target.split("?")[0] not in saved:
                note(target, f"{why} {page.route}")
        if page.kind == "html":
            directories.update(dict.fromkeys(directories_of(page.route)))
        identifiers.update(dict.fromkeys(page.identifiers))
    if more:
        rep.skipped.append(f"{more} more route(s) the saved pages offer or name are not listed: the list stops at {MAX_LISTED}")
    if len(directories) > MAX_PAIR_SIDE or len(identifiers) > MAX_PAIR_SIDE:
        rep.skipped.append(f"the saved pages name {len(directories)} directories and {len(identifiers)} identifiers; "
                           f"only the first {MAX_PAIR_SIDE} of each were paired into routes")
    some_dirs, some_ids = list(directories)[:MAX_PAIR_SIDE], list(identifiers)[:MAX_PAIR_SIDE]
    pairs, total, taken = paired_routes(some_dirs, some_ids), len(some_dirs) * len(some_ids), 0
    while taken < total and len(listed) < MAX_LISTED:   # a pair is made only while there is room to list it
        made = next(pairs, None)
        if made is None:
            taken = total
            break
        taken += 1
        target, directory, identifier = made
        if target not in saved:
            listed.setdefault(target, f"directory {directory} with identifier {identifier}")
    if taken < total:                                   # the rest are counted by size, not made
        rep.skipped.append(f"{total - taken} directory-and-identifier route(s) are not listed: the list stops at "
                           f"{MAX_LISTED}")
    rep.unsaved = list(listed.items())
    return rep


class _Saved(Mapping):
    """{name: bytes} over files on disk: each is read when it is asked for and not kept, so the
    saved run holds one file at a time however many the challenge has."""

    def __init__(self, paths):
        self._paths = dict(paths)

    def __getitem__(self, name):
        return self._paths[name].read_bytes()

    def __iter__(self):
        return iter(self._paths)

    def __len__(self):
        return len(self._paths)


def saved_files(challenge_dir: Path) -> tuple:
    """({route name: bytes}, [notes]) of the challenge's saved text pages and GIFs, as a mapping
    that reads a file when it is asked for. What a file is is told from its first HEAD bytes (all
    sniff() looks at), so a binary, a picture or an archive is opened and never read whole; and
    when no file is an HTML page the mapping is empty (the saved run reports nothing then). Names
    are relative to the folder the files are in."""
    paths, skipped = vs.challenge_paths(challenge_dir, MAX_FILE)
    folder = next((d for d in ("unpacked", "files") if (challenge_dir / d).is_dir()), None)
    kept, has_page = [], False
    for rel, path in paths:
        name = rel[len(folder) + 1:] if folder else rel
        with path.open("rb") as handle:
            kind = sniff("/" + name, handle.read(HEAD))
        if kind in ("image", "other"):
            continue
        has_page = has_page or kind == "html"
        kept.append((name, path))
    return _Saved(kept if has_page else ()), skipped


def result_of(rep: Report, *, challenge_id=None, seconds: float = 0.0, root: Path | None = None):
    """The SolverResult of a Report (status rules in the module docstring)."""
    from ctf.result import Cost, Evidence, SolverResult

    def rel(p):
        try:
            return str(Path(p).relative_to(root)) if root else str(p)
        except ValueError:
            return str(p)

    proven, candidates, evidence, notes = [], [], [], []
    for page in rep.pages:
        for flag in page.flags:
            if flag not in proven:
                proven.append(flag)
                evidence.append(Evidence("wire" if rep.mode == "live" else "carve",
                                         f"flag in the bytes of {page.route} ({page.why})", path=page.route))
        for flag in page.ocr_flags:
            if flag not in proven and flag not in candidates:
                candidates.append(flag)
                evidence.append(Evidence("ocr", f"OCR of a frame of {page.route} ({page.why})", path=page.route))
        parts = []
        if page.comments:
            parts.append(f"{len(page.comments)} comment(s): " + " | ".join(" ".join(c.split())[:160] for c in page.comments[:4]))
        if page.identifiers:
            parts.append("identifiers " + ", ".join(page.identifiers[:12]))
        if page.reveal:
            parts.append("timed-reveal attributes " + ", ".join(page.reveal[:4]))
        parts += page.notes
        if parts or rep.mode == "live":
            notes.append(f"{page.route} [{page.kind}, {page.why}]" + (": " + "; ".join(parts) if parts else ""))
    if rep.mode == "live":
        notes.insert(0, f"live crawl: {rep.requests} GET(s), {len(rep.pages)} answered, {len(rep.misses)} did not")
    if rep.unsaved:
        notes.append("routes the saved pages point at that are not saved (GET them, in scope): "
                     + ", ".join(f"{route} ({why})" for route, why in rep.unsaved[:40])
                     + (f" and {len(rep.unsaved) - 40} more" if len(rep.unsaved) > 40 else ""))
    for route, reason in rep.refused[:20]:
        notes.append(f"not requested: {route}: {reason}")
    for p in rep.written:
        evidence.append(Evidence("carve", "written", path=rel(p)))
    if rep.ocr not in ("not needed", "run"):
        notes.append(f"OCR {rep.ocr}")
    notes += rep.skipped
    # a body that was not read whole is never `none`: what was cut may hold what was looked for
    material = any(p.comments or p.named or p.identifiers or p.reveal or p.kind == "gif" or p.cut for p in rep.pages) \
        or bool(rep.unsaved)
    status = vs.status_of(proven, candidates, material)
    return SolverResult(status=status, flags=proven + candidates, evidence=evidence,
                        cost=Cost(seconds=round(seconds, 3)), engine=ENGINE, challenge_id=challenge_id,
                        notes="; ".join(notes))


# ---- the engine contract ---------------------------------------------------------------------------

def solve(challenge_dir: Path, profile, **opts):
    """Engine contract. With no `url`: the saved-pages run over the challenge's files. opts: url
    (start of a live crawl; `profile`'s live_service_scope must allow the host, and so must the
    current event's, which the client checks), ocr (auto|on|off; default auto for a live crawl and
    off for the saved run, whose GIF frames toolkits.gif_reveal reads and writes), out (folder for
    GIF frames; default <challenge>/recon/route_crawl), seconds (budget, default 45 live and 10 saved),
    max_requests (default 60), max_depth (default 10), gap (seconds between GETs, default 0.1)."""
    from ctf.result import SolverResult
    t0 = time.monotonic()
    challenge_dir = Path(challenge_dir)
    out_dir = Path(opts["out"]) if opts.get("out") else challenge_dir / "recon" / "route_crawl"
    ff = flagfmt.for_profile(profile)
    live = bool(opts.get("url"))
    common = {"ocr": str(opts.get("ocr", "auto" if live else "off")), "out_dir": out_dir,
              "prefixes": tuple(profile.flag.prefixes),
              "deadline": t0 + float(opts.get("seconds", DEFAULT_SECONDS if live else SAVED_SECONDS))}
    if common["ocr"] not in ("auto", "on", "off"):
        raise ValueError("ocr must be auto, on or off")
    try:
        if live:
            url = str(opts["url"])
            from ctf import scope
            try:                                        # the profile this run was given decides first
                scope.check_url(url, what=f"live crawl target {url!r}", profile=profile)
            except scope.OutOfScope as exc:
                raise CrawlBlocked(f"the live target is refused: {exc}") from exc
            max_requests = int(opts["max_requests"]) if "max_requests" in opts else None
            gap = float(opts["gap"]) if "gap" in opts else None
            fetch, origin, start = live_fetch(url, max_requests=max_requests, gap=gap, deadline=common["deadline"])
            rep = crawl(fetch, ff, start=start, origin=origin, max_requests=max_requests,
                        max_depth=int(opts["max_depth"]) if "max_depth" in opts else None, gap=gap, **common)
        else:
            files, skipped = saved_files(challenge_dir)
            rep = examine_saved(files, ff, **common)
            rep.skipped += skipped
            if "ocr" not in opts and any(anim.total > 1 for anim in rep.animations):
                rep.ocr = "left to toolkits.gif_reveal for the saved GIFs (ocr=auto reads their frames here too)"
    except CrawlBlocked as exc:
        return SolverResult(status="blocked", engine=ENGINE, notes=str(exc))
    return result_of(rep, seconds=time.monotonic() - t0, root=challenge_dir)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="route_crawl.py", description=__doc__.split("\n\n")[0])
    ap.add_argument("challenge_dir", type=Path, help="the challenge folder (its saved pages are read; GIF frames go under recon/)")
    ap.add_argument("--url", help="crawl this origin live (GET only, scope-locked) instead of the saved pages")
    ap.add_argument("--event", help="event slug (default: the current event)")
    ap.add_argument("--ocr", choices=("auto", "on", "off"),
                    help="read GIF frames by OCR (default: auto for a live crawl, off for saved pages)")
    ap.add_argument("--seconds", type=float, help=f"budget (default {DEFAULT_SECONDS:g} live, {SAVED_SECONDS:g} saved)")
    ap.add_argument("--max-requests", type=int, default=MAX_REQUESTS)
    a = ap.parse_args(argv)
    from ctf import event
    profile = event.load(a.event) if a.event else event.current()
    if not a.challenge_dir.is_dir():
        print(f"route_crawl.py: no such challenge folder: {a.challenge_dir}", file=sys.stderr)
        return 2
    opts = {"max_requests": a.max_requests}
    for key, value in (("ocr", a.ocr), ("seconds", a.seconds), ("url", a.url)):
        if value is not None:
            opts[key] = value
    print(solve(a.challenge_dir, profile, **opts).to_json())
    return 0


if __name__ == "__main__":
    sys.exit(main())
