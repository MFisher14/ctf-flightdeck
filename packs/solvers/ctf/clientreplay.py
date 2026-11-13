"""Shipped-client constants and User-Agent replay (B-131).

A challenge that ships its own client (a browser inside a bootable disk image, a script, an app) can
gate content on that client's hard-coded User-Agent. At PINK+ "PINK OS" the second half of the flag
was served by an organizer page only to the shipped browser's User-Agent, one link away from the
client's home page; two passes replayed the User-Agent against the home page alone and stopped one
hop short, and the gap was filled with eight wrong guesses. This module does the deterministic half:

    from ctf import clientreplay
    h = clientreplay.harvest([challenge_dir])           # offline: User-Agent and URL constants
    h.custom_user_agents(); h.client_urls()             # harvest_blobs({name: bytes}) for bytes in memory
    rep = clientreplay.replay(urls, user_agents, profile=profile, hops=1)   # network, scope-guarded
    rep.diffs; rep.flags; rep.fragments; rep.refused; rep.operator_steps()
    clientreplay.join_fragments(head, tail, profile)    # literal head + literal tail, or None
    clientreplay.guess_stop(profile, challenge_id)      # the submit gate's stop, read for a report

Harvest (no network). Every regular file under the given paths is read as bytes in windows, never
executed and never imported: a raw disk image is scanned as it lies (a file stored uncompressed on
FAT, ext or NTFS shows its text), a zip's members are read through the zip, ASCII and UTF-16LE both.
Paths with a `.ctf` or `.git` part are never opened. A User-Agent is taken where the name is followed
by a quoted value (`"User-Agent": "X"`, `USER_AGENT = 'X'`, `setRequestHeader("User-Agent", "X")`), a
header line (`User-Agent: X`) or an assignment whose value is shaped like `product/1.0`; `how` is
"nearby" for a quoted `product/1.0` string that only sits near the name (a constant passed by
variable). Format templates (`%s`, `{}`) are dropped. A stock library or browser User-Agent
(`curl/8.5`, `Mozilla/5.0 ...`) is marked `stock`. A URL is `near_ua` when it lies within NEAR bytes
of a custom User-Agent in the same file: those are the client's own URLs. The byte budget is
explicit; a file cut short by it is named in `truncated`, never silently skipped.

Replay (network). Every URL, every redirect target and every first-level link goes through
`ctf.scope.check_url` under the event profile before a connection is opened: only hosts in
`rules.live_service_scope` (or a player-pointed service) are contacted, and the event platform never
is. A refused URL is listed in `refused` with the guard's reason and becomes an operator step (the
player decides about an organizer host; nothing here widens the scope). For each allowed URL one
normal request is sent (`baseline_ua`) and one per shipped User-Agent; the replies are compared
(status, final URL, content type, body). A page whose body differs between two normal requests is
marked `unstable`, so a timestamp is not read as User-Agent gating. Then each first-level link of
those replies (hop 1) gets the same treatment; `hops` bounds the depth. GET only, no cookies, no
state change; `max_requests` caps the run and `interval` paces it (a cap that was hit is reported as
`capped` with the URLs left out).

Flags and fragments. A value in the event's flag format that only a shipped User-Agent received is
`ua_only`. In a reply that differs from the normal one, a line that is not in the normal reply is
searched for a flag fragment: a `tail` (text closed by `}` with no `{`) or a `head` (a flag prefix
and `{` never closed). Fragments are reported, never completed: `join_fragments` returns the literal
concatenation only when it is one flag in the event's format, and inserts, trims and re-cases nothing.

Guess stop. `guess_stop` reads what the submit gate enforces (ctf/platform/rules.py:
rules.wrong_answer_stop and rules.approved_extras, rules.guess_budget, resolved through
ctf.eventpolicy.summary) so an engine can say, beside a fragment, how many wrong answers and guesses
the challenge has used. It enforces nothing itself: the gate does.
"""
from __future__ import annotations

import hashlib
import http.client
import re
import ssl
import time
import urllib.parse
import zipfile
from dataclasses import asdict, dataclass, field
from html import unescape as _html_unescape
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator

from . import event as _event
from . import flagfmt, scope
from .event import EventProfile

WINDOW = 8 * 1024 * 1024            # bytes of a file scanned at a time
OVERLAP = 16384                     # bytes two windows share, so a constant on a boundary is whole
HOLD = 8192                         # a constant this close to a window's end is read with the next one
MAX_UA = 256                        # characters of a User-Agent value
MAX_URL = 2048
NEAR = 64 * 1024                    # a URL this close to a custom User-Agent is one of the client's
DEFAULT_MAX_BYTES = 4 * 1024 ** 3   # bytes harvest() reads in all unless told otherwise
MAX_ZIP_MEMBERS = 2000
MAX_CONSTANTS = 5000                # distinct URLs kept (a disk image holds thousands)
SKIP_PARTS = frozenset({".ctf", ".git"})
OWN_OUTPUT = ("recon/client", "recon/boot")     # this item's own reports: never re-read as evidence

DEFAULT_BASELINE_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
                       "Chrome/126.0.0.0 Safari/537.36")
DEFAULT_TIMEOUT = 10.0
DEFAULT_MAX_REQUESTS = 60
DEFAULT_MAX_LINKS = 20
DEFAULT_INTERVAL = 0.5              # seconds between two requests (organizer hosts are not flooded)
MAX_BODY = 512 * 1024
MAX_REDIRECTS = 3
EXCERPT = 400

_UA_NAMES = (b"user-agent", b"user_agent", b"useragent", b"user agent")
_SEP = re.compile(rb"(?![A-Za-z0-9_])([\s\"'`:=,()\[\]]{1,12})")
_QUOTES = b"\"'`"
_PRODUCT = re.compile(r"/\d")
_TEMPLATE = re.compile(r"%[-0-9.]*[sdvxq]|\{[\w.:!]*\}|\$\{|\$\(|<[A-Za-z_ -]+>")
_NEARBY = re.compile(rb"[\"'`]([A-Za-z][A-Za-z0-9._ +-]{1,40}/\d[A-Za-z0-9._+-]{0,24}(?: [\x20-\x7e]{0,120})?)[\"'`]")
_URL = re.compile(rb"https?://[A-Za-z0-9\-._~:/?#\[\]@!$&()*+,;=%]{3,2048}")     # at most MAX_URL
_HOST = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,62})?\.)+[a-z][a-z0-9-]{1,62}$|^localhost$")
_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_STOCK = re.compile(
    r"^(?:Mozilla/\d|Opera/\d|curl/|Wget/|python-requests/|Python-urllib/|Python/\d|Go-http-client/|"
    r"okhttp/|libwww-perl/|Java/|aiohttp/|node-fetch|node/|axios/|Dalvik/|Apache-HttpClient/|"
    r"PostmanRuntime/|Lynx/|Links |w3m/|libcurl|git/|urlgrabber/|APT-HTTP/|Debian APT|pip/|"
    r"Microsoft-CryptoAPI/|WinHttp|PowerShell/|aria2/|HTTPie/|Ruby|GuzzleHttp/|undici|ELinks/)", re.I)
_ASSET_EXT = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".bmp", ".css", ".js", ".mjs",
              ".map", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp3", ".mp4", ".webm", ".ogg", ".wav",
              ".pdf", ".zip", ".gz", ".tar", ".7z", ".iso", ".img", ".exe", ".dmg", ".apk")
_LINK_ATTR = re.compile(r"""(?:href|src|action)\s*=\s*(?:"([^"<>]{1,2048})"|'([^'<>]{1,2048})'|([^\s"'<>]{1,2048}))""",
                        re.I)
_TEXT_URL = re.compile(r"https?://[A-Za-z0-9\-._~:/?#\[\]@!$&()*+,;=%]{3,2048}")
_TAIL = re.compile(r"(?:^|(?<=[\s\"'>:=(,]))([^\s{}\"'<>]{3,200}\})(?=$|[\s\"'<,.;)])")


class ReplayError(ValueError):
    """A harvest or replay input is unusable; the message names it."""


# ------------------------------------------------------------------------------------------ harvest

@dataclass
class Constant:
    kind: str                    # "user-agent" | "url"
    value: str
    path: str                    # the file, relative to the path given; "a.zip -> member" inside a zip
    offset: int                  # byte offset of the value's name (user-agent) or of the URL in `path`
    encoding: str = "ascii"      # ascii | utf-16le
    how: str = "direct"          # user-agent: direct | nearby (a product/1.0 string near the name)
    stock: bool = False          # user-agent: a stock library or browser value
    near_ua: bool = False        # url: within NEAR bytes of a custom User-Agent in the same file
    count: int = 1               # times the value was seen over the whole harvest


@dataclass
class Harvest:
    user_agents: list[Constant] = field(default_factory=list)
    urls: list[Constant] = field(default_factory=list)
    files: int = 0
    scanned_bytes: int = 0
    truncated: list[str] = field(default_factory=list)   # "<file>: <why>": read in part or not at all
    skipped: list[str] = field(default_factory=list)     # "<file>: <why>": not readable as data

    def custom_user_agents(self) -> list[Constant]:
        """The User-Agent values that are not a stock library or browser one, direct ones first."""
        return sorted((c for c in self.user_agents if not c.stock), key=lambda c: c.how != "direct")

    def client_urls(self) -> list[Constant]:
        """The URLs that sit beside a custom User-Agent: the shipped client's own."""
        return [c for c in self.urls if c.near_ua]

    def to_dict(self) -> dict[str, Any]:
        return {"user_agents": [asdict(c) for c in self.user_agents], "urls": [asdict(c) for c in self.urls],
                "files": self.files, "scanned_bytes": self.scanned_bytes, "truncated": list(self.truncated),
                "skipped": list(self.skipped)}


def is_stock_user_agent(value: str) -> bool:
    return _STOCK.match(value) is not None


def _clean_ua(raw: bytes, *, quoted: bool) -> str | None:
    """The User-Agent in `raw` (the bytes after the name's separators), or None when it is not one."""
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        return None
    if not quoted:
        text = re.split(r"[\"'`]", text, maxsplit=1)[0]      # a header line inside a string literal ends there
        text = text.rstrip(";,)}] ")
    text = re.sub(r"(?:\\r|\\n|\\0)+$", "", text).strip()
    if not 3 <= len(text) <= MAX_UA or not re.search(r"[A-Za-z]", text):
        return None
    if _TEMPLATE.search(text) or any(n.decode() in text.lower() for n in _UA_NAMES):
        return None
    if not quoted and not _PRODUCT.search(text):
        return None          # `'User-Agent': self.ua,` and prose: only product/1.0 counts unquoted
    return text


def _ua_after(tail: bytes) -> str | None:
    """The value that follows a User-Agent name, from the bytes right after the name."""
    m = _SEP.match(tail)
    if not m:
        return None
    sep = m.group(1)
    rest = tail[m.end():]
    quote = next((bytes([c]) for c in reversed(sep) if bytes([c]) in _QUOTES), None)
    if quote is not None and sep.rstrip().endswith(quote):
        end = rest.find(quote)
        line = re.match(rb"[\x20-\x7e]*", rest).group(0)
        if end < 0 or end > len(line):
            return None                  # the quote never closes on this line: not a constant
        return _clean_ua(rest[:end], quoted=True)
    if b":" not in sep and b"=" not in sep:
        return None                      # prose ("the user agent of ..."): no header line, no assignment
    return _clean_ua(re.match(rb"[\x20-\x7e]{0,%d}" % (MAX_UA + 8), rest).group(0), quoted=False)


def _clean_url(raw: str) -> str | None:
    url = raw.rstrip(".,;:!?")
    while url.endswith(")") and url.count(")") > url.count("("):
        url = url[:-1]
    while url.endswith("]") and url.count("]") > url.count("["):
        url = url[:-1]
    url = url.rstrip(".,;:!?")
    if _TEMPLATE.search(url) or "%s" in url:
        return None
    try:
        parts = urllib.parse.urlsplit(url)
        host = (parts.hostname or "").lower()
        _ = parts.port                   # a port that is not a number is not a URL to fetch
    except ValueError:
        return None
    if not host or not (_HOST.match(host) or _IPV4.match(host) or ":" in host):
        return None
    return url


def _find_all(hay: bytes, needle: bytes) -> Iterator[int]:
    at = hay.find(needle)
    while at >= 0:
        yield at
        at = hay.find(needle, at + 1)


def scan_bytes(data: bytes, name: str = "", base: int = 0) -> list[Constant]:
    """The User-Agent and URL constants in one block of bytes (ASCII and UTF-16LE), in offset order.
    `base` is the block's offset in its file. No de-duplication and no near_ua mark: harvest() does both."""
    out: list[Constant] = []
    low = data.lower()
    for nm in _UA_NAMES:
        for at in _find_all(low, nm):
            tail = data[at + len(nm): at + len(nm) + MAX_UA + 32]
            value = _ua_after(tail)
            if value is not None:
                out.append(Constant("user-agent", value, name, base + at, stock=is_stock_user_agent(value)))
                continue
            lo = max(0, at - 2048)
            for m in _NEARBY.finditer(data, lo, min(len(data), at + 2048)):
                v = _clean_ua(m.group(1), quoted=True)
                if v is not None and not is_stock_user_agent(v):
                    out.append(Constant("user-agent", v, name, base + m.start(1), how="nearby"))
        wide = nm.decode().encode("utf-16le")
        for at in _find_all(low, wide):
            chunk = data[at + len(wide): at + len(wide) + 2 * (MAX_UA + 32)]
            tail = chunk[: len(chunk) & ~1].decode("utf-16le", "replace").encode("ascii", "replace")
            value = _ua_after(tail.replace(b"?", b"\x00"))
            if value is not None:
                out.append(Constant("user-agent", value, name, base + at, encoding="utf-16le",
                                    stock=is_stock_user_agent(value)))
    for m in _URL.finditer(data):
        url = _clean_url(m.group(0).decode("ascii"))
        if url is not None:
            out.append(Constant("url", url, name, base + m.start()))
    for at in _find_all(data, "http".encode("utf-16le")):
        chunk = data[at: at + 2 * MAX_URL]
        text = chunk[: len(chunk) & ~1].decode("utf-16le", "replace").encode("ascii", "replace")
        m = _URL.match(text)
        if m:
            url = _clean_url(m.group(0).decode("ascii"))
            if url is not None:
                out.append(Constant("url", url, name, base + at, encoding="utf-16le"))
    once: dict[tuple, Constant] = {}
    for c in out:
        once.setdefault((c.kind, c.value, c.offset, c.encoding), c)      # two names can point at one nearby value
    return sorted(once.values(), key=lambda c: c.offset)


class _Budget:
    def __init__(self, total: int):
        self.left = int(total)


def _scan_stream(read: Callable[[int], bytes], name: str, budget: _Budget, h: Harvest) -> list[Constant]:
    """Scan one stream in overlapping windows within the byte budget. Constants found in the overlap
    twice are kept once (same kind, value and offset)."""
    found: dict[tuple, Constant] = {}
    carry = b""
    pos = 0                               # bytes of the stream read so far
    while True:
        if budget.left <= 0:
            if read(1):
                h.truncated.append(f"{name}: the byte budget ran out after {pos} bytes")
            break
        block = read(min(WINDOW, budget.left))
        if not block:
            break
        budget.left -= len(block)
        h.scanned_bytes += len(block)
        data = carry + block
        base = pos - len(carry)
        limit = base + len(data) - HOLD   # a value that starts past this may be cut: the next window has it whole
        for c in scan_bytes(data, name, base):
            if c.offset < limit:
                found.setdefault((c.kind, c.value, c.offset, c.encoding), c)
        pos += len(block)
        carry = data[-OVERLAP:]
    for c in scan_bytes(carry, name, pos - len(carry)):       # the stream's last bytes, held back above
        found.setdefault((c.kind, c.value, c.offset, c.encoding), c)
    return sorted(found.values(), key=lambda c: c.offset)


def _own_output(rel: str) -> bool:
    r = rel.replace("\\", "/")
    return any(r == o or r.startswith(o + "/") for o in OWN_OUTPUT)


def _sources(paths: Iterable[str | Path], h: Harvest) -> Iterator[tuple[str, Path]]:
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            for f in sorted(p.rglob("*")):
                rel = f.relative_to(p)
                if SKIP_PARTS & set(rel.parts) or _own_output(rel.as_posix()):
                    continue
                if f.is_symlink():
                    h.skipped.append(f"{rel.as_posix()}: a symbolic link is not followed")
                    continue
                if f.is_file():
                    yield rel.as_posix(), f
        elif p.is_file() and not p.is_symlink():
            if SKIP_PARTS & set(p.parts):
                raise ReplayError(f"{p}: a path under .ctf or .git is never read")
            yield p.name, p
        else:
            raise ReplayError(f"{p}: not a file or folder to harvest")


def _scan_file(rel: str, path: Path, budget: _Budget, h: Harvest) -> list[list[Constant]]:
    """The constants of one file, one list per byte stream (the file itself, or each zip member)."""
    groups: list[list[Constant]] = []
    is_zip = False
    try:
        is_zip = zipfile.is_zipfile(path)
    except OSError as e:
        h.skipped.append(f"{rel}: {type(e).__name__}: {e}")
        return groups
    if is_zip:
        try:
            with zipfile.ZipFile(path) as zf:
                infos = [i for i in zf.infolist() if not i.is_dir()]
                if len(infos) > MAX_ZIP_MEMBERS:
                    h.truncated.append(f"{rel}: {len(infos)} zip members, only the first {MAX_ZIP_MEMBERS} read")
                for info in infos[:MAX_ZIP_MEMBERS]:
                    member = f"{rel} -> {info.filename}"
                    if info.flag_bits & 0x1:
                        h.skipped.append(f"{member}: encrypted zip member")
                        continue
                    try:
                        with zf.open(info) as fh:
                            groups.append(_scan_stream(fh.read, member, budget, h))
                    except (RuntimeError, NotImplementedError, zipfile.BadZipFile, OSError, EOFError,
                            ValueError) as e:
                        h.skipped.append(f"{member}: {type(e).__name__}: {e}")
                    if info.filename.lower().endswith((".zip", ".jar", ".apk")):
                        h.skipped.append(f"{member}: a nested archive is not opened (run the intake sweep first)")
            return groups
        except (zipfile.BadZipFile, OSError) as e:
            h.skipped.append(f"{rel}: not readable as a zip ({type(e).__name__}: {e}); scanned as raw bytes")
    try:
        with open(path, "rb") as fh:
            groups.append(_scan_stream(fh.read, rel, budget, h))
    except OSError as e:
        h.skipped.append(f"{rel}: {type(e).__name__}: {e}")
    return groups


def harvest(paths: Iterable[str | Path], *, max_bytes: int = DEFAULT_MAX_BYTES) -> Harvest:
    """The User-Agent and URL constants of every file under `paths` (files or folders), read as data.
    Each distinct value is kept once, at its first place, with its count. ReplayError for a path that
    is neither a file nor a folder, or a budget below 1."""
    if isinstance(paths, (str, Path)):
        paths = [paths]
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 1:
        raise ReplayError(f"max_bytes must be an integer >= 1, got {max_bytes!r}")
    h = Harvest()
    budget = _Budget(max_bytes)
    merge = _Merge()
    for rel, path in _sources(paths, h):
        h.files += 1
        for group in _scan_file(rel, path, budget, h):
            merge.add(group)
    return merge.into(h)


def harvest_blobs(files) -> Harvest:
    """harvest() over bytes already in memory: `files` maps a name to its bytes (the {name: bytes}
    form the toolkits pass around). Each blob is scanned whole."""
    h = Harvest()
    merge = _Merge()
    for name, data in files.items():
        data = bytes(data)
        h.files += 1
        h.scanned_bytes += len(data)
        merge.add(scan_bytes(data, str(name)))
    return merge.into(h)


class _Merge:
    """Folds the constants of each byte stream into one de-duplicated harvest."""

    def __init__(self):
        self.uas: dict[str, Constant] = {}
        self.urls: dict[str, Constant] = {}
        self.dropped = 0

    def add(self, group: list[Constant]) -> None:
        marks = [c.offset for c in group if c.kind == "user-agent" and not c.stock]
        for c in group:
            if c.kind == "user-agent":
                seen = self.uas.get(c.value)
                if seen is None:
                    self.uas[c.value] = c
                else:
                    seen.count += 1
                    if seen.how == "nearby" and c.how == "direct":
                        c.count = seen.count
                        self.uas[c.value] = c
                continue
            near = any(abs(c.offset - m) <= NEAR for m in marks)
            seen = self.urls.get(c.value)
            if seen is not None:
                seen.count += 1
                seen.near_ua = seen.near_ua or near
            elif len(self.urls) < MAX_CONSTANTS or near:
                c.near_ua = near
                self.urls[c.value] = c
            else:
                self.dropped += 1

    def into(self, h: Harvest) -> Harvest:
        if self.dropped:
            h.truncated.append(f"{self.dropped} more URL occurrence(s) beyond the first {MAX_CONSTANTS} distinct "
                               "URLs were not kept (none of them beside a custom User-Agent)")
        h.user_agents = list(self.uas.values())
        h.urls = list(self.urls.values())
        return h


# ------------------------------------------------------------------------------------------- replay

@dataclass
class Response:
    url: str                          # the URL asked for
    ua: str | None                    # the shipped User-Agent sent, or None for the normal request
    status: int | None = None
    final_url: str = ""               # after the redirects that were followed
    content_type: str = ""
    length: int = 0                   # bytes of body read (at most MAX_BODY)
    sha256: str = ""
    body: bytes = b""
    error: str | None = None          # the request could not be made or failed; names why
    truncated: bool = False

    def summary(self) -> dict[str, Any]:
        d = asdict(self)
        d.pop("body")
        return d


@dataclass
class Diff:
    url: str
    ua: str
    hop: int
    parent: str | None
    what: list[str]                   # each difference from the normal reply, in words
    unstable: bool = False            # two normal requests differed too: not evidence of UA gating
    excerpt: str = ""                 # the start of the reply the shipped User-Agent received


@dataclass
class Refusal:
    url: str
    reason: str
    hop: int
    parent: str | None
    via: str = "seed"                 # seed | link | redirect


@dataclass
class FlagHit:
    value: str
    url: str
    ua: str | None
    ua_only: bool                     # a shipped User-Agent received it and the normal request did not


@dataclass
class Fragment:
    kind: str                         # head | tail
    value: str
    url: str
    ua: str


@dataclass
class ReplayReport:
    user_agents: list[str] = field(default_factory=list)
    baseline_ua: str = DEFAULT_BASELINE_UA
    hops: int = 1
    requests: int = 0
    responses: list[Response] = field(default_factory=list)
    diffs: list[Diff] = field(default_factory=list)
    refused: list[Refusal] = field(default_factory=list)
    flags: list[FlagHit] = field(default_factory=list)
    fragments: list[Fragment] = field(default_factory=list)
    capped: bool = False
    not_fetched: list[str] = field(default_factory=list)   # URLs left out by max_requests / max_links
    skipped_assets: int = 0

    def gated(self) -> list[Diff]:
        """The differences that hold: a shipped User-Agent got another reply and the page is stable."""
        return [d for d in self.diffs if not d.unstable]

    def operator_steps(self) -> list[str]:
        """One line per refused URL: what the player would have to decide (nothing here does it)."""
        out = []
        for r in self.refused:
            where = f"linked from {r.parent}" if r.parent else "a shipped-client URL"
            if r.via == "redirect":
                where = f"redirect target of {r.parent}"
            out.append(f"not contacted: {r.url} ({where}): {r.reason}. The player decides whether to open it "
                       f"with the shipped User-Agent ({', '.join(self.user_agents) or 'none found'}).")
        return out

    def to_dict(self) -> dict[str, Any]:
        return {"user_agents": list(self.user_agents), "baseline_ua": self.baseline_ua, "hops": self.hops,
                "requests": self.requests, "responses": [r.summary() for r in self.responses],
                "diffs": [asdict(d) for d in self.diffs], "refused": [asdict(r) for r in self.refused],
                "flags": [asdict(f) for f in self.flags], "fragments": [asdict(f) for f in self.fragments],
                "capped": self.capped, "not_fetched": list(self.not_fetched),
                "skipped_assets": self.skipped_assets}


def _connect(scheme: str, host: str, port: int, timeout: float) -> http.client.HTTPConnection:
    if scheme == "https":
        return http.client.HTTPSConnection(host, port, timeout=timeout, context=ssl.create_default_context())
    return http.client.HTTPConnection(host, port, timeout=timeout)


def _normal_url(url: str) -> str:
    try:
        parts = urllib.parse.urlsplit(url.strip())
        _ = parts.port
    except ValueError as e:
        raise ReplayError(f"{url!r} is not a usable URL: {e}") from None
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
        raise ReplayError(f"{url!r} is not an absolute http(s) URL")
    return urllib.parse.urlunsplit((parts.scheme.lower(), parts.netloc, parts.path or "/", parts.query, ""))


def get(url: str, ua: str, *, profile: EventProfile | None = None, timeout: float = DEFAULT_TIMEOUT,
        max_bytes: int = MAX_BODY, connect: Callable[..., Any] | None = None) -> tuple[int | None, dict, bytes, bool]:
    """One GET of `url` with User-Agent `ua`: (status, lower-cased headers, body up to max_bytes,
    truncated). The scope guard runs first, here, on every call: `scope.OutOfScope` before any
    connection for a URL the event profile does not allow. No redirect is followed, no cookie is
    sent or kept. OSError / http.client.HTTPException pass through for the caller to record."""
    scope.check_url(url, what=f"shipped-client replay GET {url!r}", profile=profile)
    parts = urllib.parse.urlsplit(url)
    scheme = parts.scheme.lower()
    port = parts.port or scope.DEFAULT_PORTS[scheme]
    conn = (connect or _connect)(scheme, parts.hostname, port, timeout)
    try:
        target = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        conn.request("GET", target, headers={"User-Agent": ua, "Accept": "*/*", "Connection": "close"})
        resp = conn.getresponse()
        body = resp.read(max_bytes + 1)
        headers = {k.lower(): v for k, v in resp.getheaders()}
        return resp.status, headers, body[:max_bytes], len(body) > max_bytes
    finally:
        conn.close()


def links_of(body: bytes, base_url: str, content_type: str = "") -> list[str]:
    """The absolute http(s) URLs a reply links to (href, src, action attributes and bare URLs in the
    text), resolved against `base_url`, in order, each once, fragments dropped."""
    if content_type.split("/")[0].strip().lower() in ("image", "audio", "video", "font"):
        return []
    text = body.decode("utf-8", "replace")
    raw: list[str] = []
    for m in _LINK_ATTR.finditer(text):
        raw.append(_html_unescape(next(g for g in m.groups() if g is not None)).strip())
    for m in _TEXT_URL.finditer(text):
        bare = _clean_url(m.group(0))                # a URL in running text: drop the sentence's punctuation
        if bare is not None:
            raw.append(bare)
    out: list[str] = []
    for r in raw:
        if not r or r.startswith(("#", "javascript:", "mailto:", "data:", "tel:")):
            continue
        try:
            absolute = _normal_url(urllib.parse.urljoin(base_url, r))
        except (ReplayError, ValueError):
            continue
        if _clean_url(absolute) is None:
            continue
        if absolute not in out:
            out.append(absolute)
    return out


def is_asset(url: str) -> bool:
    return urllib.parse.urlsplit(url).path.lower().endswith(_ASSET_EXT)


def compare(base: Response, other: Response) -> list[str]:
    """How the shipped User-Agent's reply differs from the normal one, in words (empty = the same)."""
    if base.error or other.error:
        if base.error and other.error:
            return []
        if other.error:
            return [f"the normal request answered {base.status}, the shipped User-Agent's failed: {other.error}"]
        return [f"the normal request failed ({base.error}), the shipped User-Agent's answered {other.status}"]
    what = []
    if base.status != other.status:
        what.append(f"status {other.status} instead of {base.status}")
    if base.final_url != other.final_url:
        what.append(f"ends at {other.final_url} instead of {base.final_url}")
    if base.content_type.split(";")[0].strip().lower() != other.content_type.split(";")[0].strip().lower():
        what.append(f"content type {other.content_type or 'none'} instead of {base.content_type or 'none'}")
    if base.sha256 != other.sha256:
        what.append(f"body differs ({other.length} bytes instead of {base.length})")
    return what


_PLACEHOLDERS = frozenset({"...", "flag", "your_flag", "example", "example_flag", "insert_flag_here",
                           "replace_me", "redacted", "placeholder"})


def _real_flags(ff: flagfmt.FlagFormat, body: bytes) -> list[str]:
    """The flag-format values in a reply, minus the placeholders a page uses to show the format."""
    out = []
    for value in ff.find_flags(body):
        inner = value[value.find("{") + 1:-1].strip().casefold() if "{" in value else value.casefold()
        if inner in _PLACEHOLDERS or not inner.strip(".*?_-x "):
            continue
        if value not in out:
            out.append(value)
    return out


def _excerpt(body: bytes) -> str:
    text = body[:EXCERPT * 4].decode("utf-8", "replace")
    text = "".join(ch if ch.isprintable() or ch in "\n\t" else "?" for ch in text)
    return text[:EXCERPT]


def find_fragments(base_body: bytes, ua_body: bytes, profile: EventProfile) -> list[tuple[str, str]]:
    """(kind, value) for each flag fragment in the lines only the shipped User-Agent received: a
    `tail` (closed by `}` with no `{`) or a `head` (a flag prefix and `{`, never closed). A line that
    holds a whole flag is not a fragment."""
    ff = flagfmt.for_profile(profile)
    base_lines = set(base_body.decode("utf-8", "replace").splitlines())
    out: list[tuple[str, str]] = []
    for line in ua_body.decode("utf-8", "replace").splitlines():
        if line in base_lines or len(line) > 4096:
            continue
        rest = line
        for flag in ff.find_flags(line):
            rest = rest.replace(flag, " ")
        for m in _TAIL.finditer(rest):
            if ("tail", m.group(1)) not in out:
                out.append(("tail", m.group(1)))
        for prefix in profile.flag.prefixes:
            hm = re.search(re.escape(prefix) + r"\{[^\s{}]*$", rest.rstrip())
            if hm and ("head", hm.group(0)) not in out:
                out.append(("head", hm.group(0)))
    return out


def join_fragments(head: str, tail: str, profile: EventProfile) -> str | None:
    """`head + tail`, exactly as given, when that is one flag in the event's format; else None.
    Nothing is inserted, trimmed or re-cased: a join that needs any of those is a guess."""
    if not isinstance(head, str) or not isinstance(tail, str) or not head or not tail:
        return None
    value = head + tail
    return value if flagfmt.for_profile(profile).is_flag(value) and value == value.strip() else None


def _resolve_profile(profile: EventProfile | None) -> EventProfile:
    if profile is not None:
        return profile
    pinned = scope.pinned()
    if pinned is not None:
        return pinned
    try:
        return _event.current()
    except _event.EventError as e:
        raise ReplayError(f"no event profile: {e}; a replay needs the event's rules.live_service_scope "
                          "(set CTF_EVENT or pass the profile)") from e


def replay(urls: Iterable[str], user_agents: Iterable[str], *, profile: EventProfile | None = None,
           hops: int = 1, max_requests: int = DEFAULT_MAX_REQUESTS, max_links: int = DEFAULT_MAX_LINKS,
           timeout: float = DEFAULT_TIMEOUT, max_bytes: int = MAX_BODY, baseline_ua: str = DEFAULT_BASELINE_UA,
           interval: float = DEFAULT_INTERVAL, sleep: Callable[[float], None] = time.sleep,
           connect: Callable[..., Any] | None = None) -> ReplayReport:
    """Fetch each in-scope URL, and its links down to `hops`, once normally and once per shipped
    User-Agent, and report the differences (module docstring). ReplayError for an unusable argument
    or no event profile; a URL the scope guard refuses is reported, never fetched."""
    prof = _resolve_profile(profile)
    uas = []
    for ua in user_agents:
        ua = str(ua).strip()
        if not ua or any(ch in ua for ch in "\r\n\x00"):
            raise ReplayError(f"unusable User-Agent {ua!r} (empty, or it holds a line break)")
        if ua not in uas:
            uas.append(ua)
    if not uas:
        raise ReplayError("no shipped User-Agent to replay: harvest one first, or pass it")
    for name, v, lo in (("hops", hops, 0), ("max_requests", max_requests, 1), ("max_links", max_links, 0)):
        if isinstance(v, bool) or not isinstance(v, int) or v < lo:
            raise ReplayError(f"{name} must be an integer >= {lo}, got {v!r}")
    if any(ch in baseline_ua for ch in "\r\n\x00") or not baseline_ua.strip():
        raise ReplayError("unusable baseline User-Agent")
    ff = flagfmt.for_profile(prof)
    rep = ReplayReport(user_agents=uas, baseline_ua=baseline_ua, hops=hops)
    sent = [0]

    def room(n: int = 1) -> bool:
        return rep.requests + n <= max_requests

    def fetch(url: str, ua: str | None, hop: int, parent: str | None) -> Response:
        """One request and the redirects it leads through (each scope-checked, each counted)."""
        r = Response(url=url, ua=ua, final_url=url)
        at = url
        for step in range(MAX_REDIRECTS + 1):
            if not room():
                rep.capped = True
                r.error = f"not sent: max_requests ({max_requests}) reached"
                break
            if sent[0] and interval > 0:
                sleep(interval)
            sent[0] += 1
            rep.requests += 1
            try:
                status, headers, body, cut = get(at, ua or baseline_ua, profile=prof, timeout=timeout,
                                                 max_bytes=max_bytes, connect=connect)
            except scope.OutOfScope as e:
                rep.requests -= 1
                sent[0] -= 1
                r.error = f"refused by the scope guard: {e}"
                break
            except (OSError, http.client.HTTPException) as e:
                r.error = f"{type(e).__name__}: {e}"
                break
            r.status, r.final_url, r.body, r.truncated = status, at, body, cut
            r.content_type = headers.get("content-type", "")
            loc = headers.get("location")
            if status in (301, 302, 303, 307, 308) and loc:
                try:
                    nxt = _normal_url(urllib.parse.urljoin(at, loc))
                except (ReplayError, ValueError):
                    break
                try:
                    scope.check_url(nxt, what=f"redirect target {nxt!r}", profile=prof)
                except scope.OutOfScope as e:
                    if not any(x.url == nxt and x.via == "redirect" for x in rep.refused):
                        rep.refused.append(Refusal(nxt, str(e), hop, url, via="redirect"))
                    break
                if step == MAX_REDIRECTS:
                    break
                at = nxt
                continue
            break
        r.length = len(r.body)
        r.sha256 = hashlib.sha256(r.body).hexdigest() if r.status is not None else ""
        rep.responses.append(r)
        return r

    seen: set[str] = set()
    queue: list[tuple[str, int, str | None]] = []
    for raw in urls:
        u = _normal_url(str(raw))
        if u not in seen:
            seen.add(u)
            queue.append((u, 0, None))

    while queue:
        url, hop, parent = queue.pop(0)
        try:
            scope.check_url(url, what=f"shipped-client URL {url!r}", profile=prof)
        except scope.OutOfScope as e:
            rep.refused.append(Refusal(url, str(e), hop, parent, via="seed" if hop == 0 else "link"))
            continue
        if not room(1 + len(uas)):
            rep.capped = True
            rep.not_fetched.append(url)
            continue
        base = fetch(url, None, hop, parent)
        base_flags = _real_flags(ff, base.body) if base.body else []
        for value in base_flags:
            if not any(f.value == value for f in rep.flags):
                rep.flags.append(FlagHit(value, url, None, False))
        replies = [base]
        for ua in uas:
            r = fetch(url, ua, hop, parent)
            replies.append(r)
            what = compare(base, r)
            if not what:
                continue
            d = Diff(url, ua, hop, parent, what, excerpt=_excerpt(r.body))
            if what == [f"body differs ({r.length} bytes instead of {base.length})"] and room():
                again = fetch(url, None, hop, parent)
                if not again.error and again.sha256 != base.sha256:
                    d.unstable = True
                    d.what.append("two normal requests differed as well: the page changes by itself")
            rep.diffs.append(d)
            for value in _real_flags(ff, r.body):
                hit = next((f for f in rep.flags if f.value == value), None)
                if hit is None:
                    rep.flags.append(FlagHit(value, url, ua, value not in base_flags and not d.unstable))
            if not d.unstable:
                for kind, value in find_fragments(base.body, r.body, prof):
                    if not any(f.kind == kind and f.value == value for f in rep.fragments):
                        rep.fragments.append(Fragment(kind, value, url, ua))
        if hop >= hops:
            continue
        found: list[str] = []
        for r in replies:
            if r.error or not r.body:
                continue
            for link in links_of(r.body, r.final_url or url, r.content_type):
                if link not in seen and link not in found:
                    found.append(link)
        pages = [u for u in found if not is_asset(u)]
        rep.skipped_assets += len(found) - len(pages)
        for link in pages[:max_links]:
            seen.add(link)
            queue.append((link, hop + 1, url))
        for link in pages[max_links:]:
            seen.add(link)
            rep.capped = True
            rep.not_fetched.append(link)
    return rep


# --------------------------------------------------------------------------------------- guess stop

@dataclass(frozen=True)
class GuessStop:
    challenge_id: str
    wrong: int
    wrong_answer_stop: int
    approved_extras: bool
    guesses_used: int
    guess_budget: int

    @property
    def stopped(self) -> bool:
        """The wrong-answer stop is reached: the gate refuses the next send until the player decides."""
        return self.wrong >= self.wrong_answer_stop

    @property
    def guesses_left(self) -> int:
        return max(0, self.guess_budget - self.guesses_used)

    def line(self) -> str:
        head = (f"challenge {self.challenge_id}: {self.wrong} wrong answer(s) of {self.wrong_answer_stop}, "
                f"{self.guesses_used} guess(es) used of a budget of {self.guess_budget}")
        if self.stopped:
            who = ("only the player can approve another send" if self.approved_extras
                   else "the stop is final on this event")
            return f"STOP: {head}; the wrong-answer stop is reached and {who}"
        if self.guesses_left == 0:
            return f"{head}; no guess may be sent: a value goes out only when every part of it is literal"
        return f"{head}; {self.guesses_left} guess(es) left"


def guess_stop(profile: EventProfile, challenge_id: str, workdir: Path | None = None) -> GuessStop:
    """What the submit gate holds against `challenge_id` now: its wrong answers against
    rules.wrong_answer_stop and its judged guesses against rules.guess_budget. A read of the event
    ledger through the gate's own counters; the gate (ctf/platform/rules.py) does the refusing."""
    from . import eventpolicy
    from .platform.rules import EventRules, challenge_key
    if not str(challenge_id).strip():
        raise ReplayError("guess_stop needs the challenge id")
    pol = eventpolicy.summary(profile)
    rules = EventRules(profile, workdir)
    return GuessStop(challenge_id=challenge_key(str(challenge_id)), wrong=rules.wrong_count(challenge_id),
                     wrong_answer_stop=pol.wrong_answer_stop, approved_extras=pol.approved_extras,
                     guesses_used=rules.guesses_used(challenge_id), guess_budget=pol.guess_budget)


__all__ = ["Constant", "Diff", "FlagHit", "Fragment", "GuessStop", "Harvest", "Refusal", "ReplayError",
           "ReplayReport", "Response", "compare", "find_fragments", "get", "guess_stop", "harvest",
           "harvest_blobs", "is_asset", "is_stock_user_agent", "join_fragments", "links_of", "replay", "scan_bytes"]
