#!/usr/bin/env python3
"""Web engine `client_gate` (B-127): the client-side-check opener and client-JS custom-encoding recognizer.

Two 2026 Spooky web challenges were decided in the page's own code. In one, an HTML comment named a text
file and the flag's shape (`<prefix>{band}`), and the page's script lowercased the input and compared a
53-bit string hash with a constant: the answer was the candidate whose hash matched. In the other, the
script listed URL path tokens that were base64 of a text written in two letters (one for a 0 bit, one for
a 1 bit) of 16-bit character codes; the listed keys were jokes, and the same encoding of the unlisted key
`flag` was the path that answered with the flag. Both are mechanical once the page is read whole, so:

  mirror     saved: the challenge's saved pages, scripts and text files (no network; what intake runs).
             live (`url=`): the page, its scripts and the files its comments and scripts name, GET only,
             through the scope-locked client route_crawl uses (solvers/toolkits/web.py WebClient,
             get_only=True). The profile handed to solve() must allow the host (ctf.scope.check_url);
             an event whose rules.live_service_scope does not list it (a manual event such as Spooky)
             is refused with `blocked`, naming the key, never quietly downgraded to the saved run.
  harvest    HTML, script and style comments, script sources (inline and external), the path, endpoint
             and parameter tables of every script (js_recon), the routes the comments name, and every
             string literal of every script (a JavaScript tokenizer, _jsmini, not a regex).
  decode     every string token (and path segment) of the scripts goes through the shared codec graph
             (ctf.codec, B-163) with this engine's codecs added: two-symbol text as bits (both
             polarities), 16- and 7-bit packing, and any custom base64 alphabet the script carries. A
             token that reads as a key or a flag is kept with its chain. Numeric arrays go through the
             B-094 numeric-ASCII reader (solvers/warmups/numsym.py).
  invert     a chain that two or more tokens share is a recognized encoding. It is inverted step by step
             (each step's variant, padding and case chosen so that every observed token re-encodes to
             itself exactly), and the likely hidden keys (flag, admin, secret, ... and `keys=`) are
             encoded with it into routes, placed where the script places its tokens. Live: those routes
             are fetched (GET) and a flag in an answer is `solved`. Saved: they are listed to fetch.
  gate       every equality comparison in the scripts with a constant on one side is a gate. The other
             side's input slot (a name the program does not define: `input.value`, a parameter) is found,
             and candidates are run through it in process by _jsmini, a bounded evaluator of a JavaScript
             subset with no host objects (the fetched script is never executed: no node, no browser, no
             DOM). A known 53-bit hash is computed natively and cross-checked against the evaluator once.
             A match is proof only when the gate tells the candidate from near-misses of it (a length or
             prefix check is reported, never trusted). A plain equality gate gives its constant.

Candidates for a gate: `candidates=` (comma separated) and `candidates_file=`, the flag-shaped strings
of the pages and decodes, the templates they show (`<prefix>{band}` takes every candidate word in the
slot), and the words and short phrases of the comments, text files and visible text. The leap a page
leaves to knowledge (a song title to the band that made it) is the model's or the player's: the engine
then reports the gate, the template and the command that confirms a guess.

  solve(challenge_dir, profile, **opts) -> SolverResult      the engine contract (python -m ctf run)
  analyze(sources, ff, profile, ...) -> Report                the whole analysis over [Source]
  saved_sources(folder) -> ([Source], notes);  mirror_live(url, profile, ...) -> ([Source], fetch, notes)
  find_gates(scripts) -> [Gate];  check_gate(gate, candidates) -> [Match]
  decode_tokens(strings, ff, ...) -> [Decoded];  encodings(decoded, strings) -> [Encoding]

  .venv/bin/python -m ctf run web.client_gate <challenge_dir> [--opt url=http://host/] [--opt candidates=a,b]

opts: url, saved (folder of saved pages; default the challenge folder), candidates, candidates_file,
keys (more hidden keys), max_requests (live, default 30), gap (seconds between GETs, default 0.1),
gate_steps (evaluator steps for all gates, default 2,000,000), token_nodes (codec-graph nodes per token,
default 400).

Status: a gate-confirmed candidate in the event format, a flag in the answer to an encoded hidden route,
or the constant of a plain equality gate in the event format is `solved`. A flag-shaped string in the pages
or a decode that no gate confirms is `candidate`. A gate, an encoding or hidden routes with no flag is
`unsure`, with what to do next. A refused or unreachable live target, or no saved page to read, is
`blocked`.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import itertools
import json
import re
import sys
import time
import urllib.parse
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path

try:
    from ctf import flagfmt
except ModuleNotFoundError:
    sys.path.append(str(Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

HERE = Path(__file__).resolve().parent
for _d in (HERE, HERE.parent / "toolkits", HERE.parent / "warmups"):
    if str(_d) not in sys.path:
        sys.path.append(str(_d))

import _jsmini as J            # noqa: E402
import _visual_stego as vs     # noqa: E402
import js_recon                # noqa: E402
import route_crawl as rc       # noqa: E402

from ctf.codec import AnyOf, FlagOracle, Graph, Recognizer   # noqa: E402
from ctf.codec import codecs as C                              # noqa: E402

ENGINE = "web.client_gate"
MAX_FILE = 4 << 20                     # bytes of one saved file read
MAX_REQUESTS = 30                      # GETs one live run sends (mirror and hidden routes together)
MAX_DEPTH = 2                          # references followed from the start page
GAP = 0.1                              # seconds between two GETs
MAX_TOKENS = 800                       # string tokens one run decodes
TOKEN_NODES = 400                      # codec-graph nodes per token
MIN_TOKEN = 8                          # characters of a string token worth decoding
MAX_TOKEN = 4096
GATE_STEPS = 2_000_000                 # evaluator steps for every gate and candidate of one run
CANDIDATE_STEPS = 400_000              # evaluator steps for one candidate
MAX_CANDIDATES = 20_000
MAX_NUMARRAY = 512                     # values of one numeric array read by the numeric-ASCII reader
PARSE_BUDGET = 3_000_000               # tokens the gate finder may parse over all scripts of one run
MAX_HIDDEN_ROUTES = 24                 # encoded hidden routes one live run fetches
DEFAULT_KEYS = ("flag", "admin", "secret", "key", "hidden", "debug", "root", "password", "flag.txt",
                "getflag", "get_flag", "the_flag", "secret_flag", "hidden_flag", "admin_panel")
FOLLOW_EXT = (".js", ".mjs", ".txt", ".json", ".md", ".xml", ".csv", ".log", ".bak", ".html", ".htm",
              ".php", ".map")
_BARE_FILE = re.compile(r"(?<![\w/.-])([A-Za-z0-9_-][A-Za-z0-9_.-]{0,80}\.(?:txt|js|json|md|xml|csv|log|bak|html?|php))\b")
_SOURCEMAP = re.compile(r"[#@]\s*sourceMappingURL\s*=\s*(\S+)")
_WORD = re.compile(r"[A-Za-z0-9][A-Za-z0-9_'-]{1,39}")
_KEY_TEXT = re.compile(r"[A-Za-z0-9 _.:/-]+")
_TOKEN_SHAPE = re.compile(r"[A-Za-z0-9+/=_.:%-]+")
_STOP = frozenset("the and for you are with this that from have not but was his her its our they them "
                  "into out who what when where which why how all any can will just than then there "
                  "here some your about would could should".split())


class GateBlocked(RuntimeError):
    """The run could not read anything: out of scope, unreachable, or nothing saved."""


# ---- sources ---------------------------------------------------------------------------------------

@dataclass
class Source:
    route: str                         # origin-rooted route (live) or /<saved name>
    kind: str                          # html | script | text | style
    text: str
    origin: str = ""                   # "saved" or the live origin
    inline_of: str = ""                # for an inline script: the page it is in


class _Page(HTMLParser):
    """Inline scripts, script srcs and visible text of one HTML page (comments come from route_crawl)."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.scripts, self.srcs, self.text = [], [], []
        self._in = None

    def handle_starttag(self, tag, attrs):
        self._in = tag if tag in ("script", "style") else None
        if tag == "script":
            for k, v in attrs:
                if (k or "").lower() == "src" and v:
                    self.srcs.append(v)

    def handle_endtag(self, tag):
        self._in = None

    def handle_data(self, data):
        if self._in == "script":
            self.scripts.append(data)
        elif self._in is None:
            self.text.append(data)


def _decode(body: bytes) -> str:
    return body.decode("utf-8", "replace")


def saved_sources(folder: Path) -> tuple:
    """([Source], [notes]) of the saved pages, scripts and text files of a challenge folder (its
    `unpacked/` or `files/` when present). Pictures, archives and binaries are left out unread, and so
    is everything under a dot-folder or named with a leading dot (`.ctf/`, `.env`, `.git/`): those hold
    tokens and bookkeeping, never a saved page."""
    paths, skipped = vs.challenge_paths(folder, MAX_FILE)
    sub = next((d for d in ("unpacked", "files") if (Path(folder) / d).is_dir()), None)
    out, hidden = [], 0
    for rel, path in paths:
        name = rel[len(sub) + 1:] if sub else rel
        if any(part.startswith(".") for part in Path(name).parts):
            hidden += 1                                 # never opened: the name alone decides
            continue
        with path.open("rb") as fh:
            head = fh.read(rc.HEAD)
        kind = rc.sniff("/" + name, head)
        if kind not in ("html", "script", "text", "style"):
            continue
        out.append(Source("/" + name.replace("\\", "/"), kind, _decode(path.read_bytes()), "saved"))
    if hidden:
        skipped.append(f"{hidden} file(s) under a dot-folder or with a dot-name (.ctf/, .env, ...) not read")
    return out, skipped


def _is_destructive():
    from ctf import web_lane
    try:
        return web_lane.load_proof_hunt().is_destructive
    except (web_lane.WebLaneError, AttributeError) as exc:
        raise GateBlocked(f"the destructive-route guard (solvers/web/proof_hunt.py is_destructive) is missing: {exc}") from exc


def references(src: Source) -> list:
    """The routes a source points at that are worth mirroring: script srcs, linked text and script
    files, the paths its comments and text name, and bare file names (`nightmare.txt`) in its comments."""
    body = src.text.encode("utf-8", "replace")
    page = rc.harvest(src.route, body, "")
    refs = list(page.links) + list(page.named)
    for c in page.comments:
        refs += _BARE_FILE.findall(c)
        refs += [m for m in _SOURCEMAP.findall(c) if not m.startswith("data:")]
    if src.kind == "script":
        refs += [p for p in js_recon.scan_text(src.route, src.text)["paths"]]
    out = []
    for ref in refs:
        low = ref.split("?")[0].split("#")[0].lower()
        if low.endswith(FOLLOW_EXT) or ref in page.named:
            out.append(ref)
    return list(dict.fromkeys(out))


def mirror_live(url: str, profile, *, max_requests: int = MAX_REQUESTS, gap: float = GAP, sleep=time.sleep):
    """([Source], fetch, origin, start route, notes, budget) of a live mirror: the start page, then the
    references it and they name, breadth first, up to MAX_DEPTH links deep, GET only, one origin.
    GateBlocked when the profile or the client refuses the host or nothing answers. `budget` is a
    one-item list of the GETs left for the hidden routes."""
    from ctf import scope
    try:
        scope.check_url(url, what=f"client-gate target {url!r}", profile=profile)
    except scope.OutOfScope as exc:
        raise GateBlocked(f"the live target is refused: {exc}. Save the page, its scripts and the files its "
                          f"comments name into the challenge folder and run without url=") from exc
    try:
        fetch, origin, start = rc.live_fetch(url, max_requests=max_requests, gap=gap)
    except rc.CrawlBlocked as exc:
        raise GateBlocked(str(exc)) from exc
    destructive = _is_destructive()
    sources, notes, seen = [], [], {start}
    queue, sent = [(start, 0)], [0]
    while queue and sent[0] < max_requests:
        route, depth = queue.pop(0)
        if sent[0]:
            sleep(gap)
        try:
            status, ctype, body, info = fetch(route)
        except rc.CrawlBlocked as exc:
            if not sources:
                raise GateBlocked(str(exc)) from exc
            notes.append(f"{route}: no answer ({exc}); the mirror stopped")
            break
        except ValueError as exc:
            notes.append(f"{route}: refused ({exc})")
            continue
        sent[0] += info.get("requests", 1)
        if status != 200:
            notes.append(f"{route}: HTTP {status}")
            continue
        kind = rc.sniff(route, body, ctype)
        if kind not in ("html", "script", "text", "style"):
            continue
        src = Source(route, kind, _decode(body), origin)
        sources.append(src)
        if depth >= MAX_DEPTH:
            continue
        for ref in references(src):
            nxt = rc.resolve(route, ref, origin)
            if nxt is None or nxt in seen:
                continue
            seen.add(nxt)
            if destructive(nxt):
                notes.append(f"{nxt}: not requested (names a state-changing action)")
                continue
            queue.append((nxt, depth + 1))
    if queue:
        notes.append(f"{len(queue)} referenced route(s) not mirrored: the request budget ({max_requests}) ran out")
    return sources, fetch, origin, start, notes, [max(0, max_requests - sent[0])]


def expand(sources: list) -> tuple:
    """(scripts, comments, texts): every script (external and inline, as Sources), every comment
    [(route, text)], and the readable text [(route, text)] of pages and text files."""
    scripts, comments, texts = [], [], []
    for s in sources:
        page = rc.harvest(s.route, s.text.encode("utf-8", "replace"), "")
        comments += [(s.route, c) for c in page.comments]
        if s.kind == "script":
            scripts.append(s)
        elif s.kind == "html":
            p = _Page()
            try:
                p.feed(s.text)
                p.close()
            except Exception:                           # html.parser is lenient; a failure only loses text
                pass
            for k, body in enumerate(p.scripts):
                if body.strip():
                    scripts.append(Source(f"{s.route}#script{k + 1}", "script", body, s.origin, s.route))
            texts.append((s.route, " ".join(p.text)))
        elif s.kind == "text" and s.route.split("?")[0].lower().endswith(".map"):
            scripts += sourcemap_scripts(s)
        elif s.kind == "text":
            texts.append((s.route, s.text))
    return scripts, comments, texts


def sourcemap_scripts(src: Source) -> list:
    """The original scripts a source map carries in its sourcesContent, as script Sources named
    `<map route>!<source name>` (solvers/web/sourcemap.py reconstruct; a map without contents gives
    none)."""
    import sourcemap                                       # reconstruct never raises: a non-map gives none
    rec = sourcemap.reconstruct(src.text.encode("utf-8", "replace"), src.route)
    return [Source(f"{src.route}!{ent['name']}", "script", ent["content"], src.origin, src.route)
            for ent in rec["sources"] if isinstance(ent.get("content"), str) and ent["content"].strip()]


# ---- JS string tables ------------------------------------------------------------------------------

@dataclass
class Script:
    source: Source
    toks: list
    strings: list                      # [str] literal strings, in order
    prefixes: list                     # path prefixes the script concatenates a value onto
    numarrays: list                    # [[int]] numeric array literals
    recon: dict
    error: str = ""


def read_script(src: Source) -> Script:
    try:
        toks = J.tokenize(src.text)
        err = ""
    except J.JsError as exc:
        toks, err = [J.Tok("eof", None, 0, False, 0)], f"{src.route}: not tokenized ({exc})"
    strings, prefixes, arrays = [], [], []
    for i, tk in enumerate(toks):
        nxt = toks[i + 1] if i + 1 < len(toks) else None
        if tk.kind == "str":
            strings.append(tk.value)
            if nxt is not None and nxt.kind == "punct" and nxt.value == "+" and _prefix_like(tk.value):
                prefixes.append(tk.value)
        elif tk.kind == "tmpl":
            strs, exprs = tk.value
            strings += [s for s in strs if s]
            if exprs and _prefix_like(strs[0]):
                prefixes.append(strs[0])
        elif tk.kind == "punct" and tk.value == "[":
            vals, j = [], i + 1
            while toks[j].kind == "num" and len(vals) < MAX_NUMARRAY:
                vals.append(toks[j].value)
                j += 1
                if toks[j].kind == "punct" and toks[j].value == ",":
                    j += 1
                    continue
                break
            if len(vals) >= 4 and toks[j].kind == "punct" and toks[j].value == "]" \
                    and all(v == int(v) and 0 <= v < 0x110000 for v in vals):
                arrays.append([int(v) for v in vals])
    return Script(src, toks, strings, list(dict.fromkeys(prefixes)), arrays,
                  js_recon.scan_text(src.route, src.text), err)


def _prefix_like(s: str) -> bool:
    return bool(s) and len(s) <= 300 and " " not in s and (s.endswith(("/", "=", "?")) or
                                                           (s.startswith("/") and s.endswith(("-", "_"))))


# ---- codecs this engine adds to the shared graph ---------------------------------------------------

def _sym2(low_is_zero: bool):
    def decode(b: bytes):
        s = b.strip()
        kinds = sorted(set(s))
        if len(kinds) != 2 or len(s) < 7 or any(k in b" \t\r\n" for k in kinds) or set(kinds) <= set(b"01"):
            return None
        if len(s) % 7 and len(s) % 8:
            return None
        lo, hi = kinds
        zero, one = (lo, hi) if low_is_zero else (hi, lo)
        return s.translate(bytes.maketrans(bytes((zero, one)), b"01"))
    decode.__doc__ = ("two-symbol text as bits, the lower symbol 0" if low_is_zero
                      else "two-symbol text as bits, the higher symbol 0")
    return decode


def _bits(width: int):
    def decode(b: bytes):
        s = b.strip()
        if len(s) < width or len(s) % width or set(s) - set(b"01"):
            return None
        chars = [int(s[i:i + width], 2) for i in range(0, len(s), width)]
        try:
            return "".join(chr(c) for c in chars).encode("utf-8")
        except (ValueError, UnicodeEncodeError):
            return None
    decode.__doc__ = f"bits packed {width} to a character"
    return decode


_STD64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def _alpha64(alphabet: str):
    table = str.maketrans(alphabet[:64], _STD64)

    def decode(b: bytes):
        try:
            s = b.strip().decode("ascii")
        except UnicodeDecodeError:
            return None
        body = s.rstrip(alphabet[64] if len(alphabet) > 64 else "=")
        if len(body) < 4 or len(body) % 4 == 1 or set(body) - set(alphabet[:64]):
            return None
        std = body.translate(table)
        try:
            return base64.b64decode(std + "=" * (-len(std) % 4), validate=True) or None
        except (binascii.Error, ValueError):
            return None
    decode.__doc__ = "base64 over the script's own alphabet"
    return decode


def custom_alphabets(strings) -> list:
    """The 64/65-character strings of a script that are a base64 alphabet other than the standard one."""
    out = []
    for s in strings:
        if len(s) in (64, 65) and len(set(s)) == len(s) and all(32 < ord(c) < 127 for c in s) \
                and s[:64] != _STD64 and s[:64] != _STD64[:62] + "-_" and s not in out:
            out.append(s)
    return out[:4]


def engine_codecs(alphabets=()) -> tuple:
    out = [C.Codec("sym2lo", C.SYMBOL, _sym2(True), "two-symbol text as bits, lower symbol 0", True),
           C.Codec("sym2hi", C.SYMBOL, _sym2(False), "two-symbol text as bits, higher symbol 0", True),
           C.Codec("bin16", C.STRICT, _bits(16), "bits packed 16 to a character", True),
           C.Codec("bin7", C.STRICT, _bits(7), "bits packed 7 to a character", True)]
    for k, a in enumerate(alphabets):
        out.append(C.Codec(f"b64alpha{k}", C.STRICT, _alpha64(a), "base64 over the script's alphabet", True))
    return tuple(out)


# ---- encoders: the inverse of each step a recognized encoding may use ---------------------------------

def _enc_variants(name: str, before: bytes, alphabets) -> list:
    """[(variant label, encode(bytes) -> bytes)] for one codec step; `before` is a sample of the
    state the step decoded (the two symbols of a sym2 step are read from it). [] = not invertible."""
    if name == "b64":
        return [("pad", base64.b64encode), ("nopad", lambda b: base64.b64encode(b).rstrip(b"="))]
    if name == "b64url":
        return [("pad", base64.urlsafe_b64encode), ("nopad", lambda b: base64.urlsafe_b64encode(b).rstrip(b"="))]
    if name == "b32":
        return [("pad", base64.b32encode), ("nopad", lambda b: base64.b32encode(b).rstrip(b"="))]
    if name == "hex":
        return [("lower", lambda b: b.hex().encode()), ("upper", lambda b: b.hex().upper().encode())]
    if name == "binary":
        return [("8", lambda b: "".join(f"{c:08b}" for c in b).encode()),
                ("8 spaced", lambda b: " ".join(f"{c:08b}" for c in b).encode())]
    if name in ("bin16", "bin7"):
        width = 16 if name == "bin16" else 7

        def enc(b, width=width):
            t = b.decode("utf-8")
            if any(ord(c) >= (1 << width) for c in t):
                raise ValueError("character too wide")
            return "".join(format(ord(c), f"0{width}b") for c in t).encode()
        return [(str(width), enc)]
    if name in ("sym2lo", "sym2hi"):
        kinds = sorted(set(before.strip()))
        if len(kinds) != 2:
            return []
        lo, hi = kinds
        zero, one = (lo, hi) if name == "sym2lo" else (hi, lo)
        table = bytes.maketrans(b"01", bytes((zero, one)))
        return [("pair", lambda b: b.translate(table))]
    if name.startswith("b64alpha"):
        alphabet = alphabets[int(name[len("b64alpha"):])]
        table = str.maketrans(_STD64, alphabet[:64])
        pad = alphabet[64] if len(alphabet) > 64 else "="
        return [("pad", lambda b: base64.b64encode(b).decode().rstrip("=").translate(table).encode()
                 + pad.encode() * (-len(base64.b64encode(b).decode().rstrip("=")) % 4)),
                ("nopad", lambda b: base64.b64encode(b).decode().rstrip("=").translate(table).encode())]
    if name == "reverse":
        return [("", lambda b: b[::-1])]
    if name == "rot13":
        return [("", lambda b: C._rot_letters(b, 13))]
    if name == "url":
        return [("", lambda b: urllib.parse.quote_from_bytes(b, safe="").encode())]
    if name == "decimal":
        return [("space", lambda b: " ".join(str(c) for c in b).encode()),
                ("comma", lambda b: ",".join(str(c) for c in b).encode())]
    return []


def _states(token: bytes, chain, codecs) -> list:
    """The state before each step of `chain` applied to `token`: [state0 (the token), state1, ...]."""
    out, cur = [token], token
    for name in chain:
        cur = C.by_name(name, codecs).decode(cur)
        if cur is None:
            return []
        out.append(cur)
    return out


def invert(chain, samples, codecs, alphabets):
    """(encode(str) -> str, how) that re-encodes every sample's key to its token exactly, or (None, why).
    samples: [(token, key)]."""
    states = _states(samples[0][0].encode("latin-1"), chain, codecs)
    if not states:
        return None, "the chain does not replay on its own token"
    per_step = []
    for k, name in enumerate(chain):
        variants = _enc_variants(name, states[k], alphabets)
        if not variants:
            return None, f"step {name} has no inverse here"
        per_step.append(variants)
    for combo in itertools.product(*per_step):
        def encode(key: str, combo=combo) -> str:
            cur = key.encode("utf-8")
            for _, fn in reversed(combo):
                cur = fn(cur)
            return cur.decode("latin-1")
        try:
            if all(encode(key) == token for token, key in samples):
                how = "+".join(f"{n}" + (f"({lab})" if lab else "") for n, (lab, _) in zip(chain, combo))
                return encode, how
        except (ValueError, UnicodeError):
            continue
    return None, "no variant of the inverse re-encodes every observed token exactly"


# ---- decoding the string tables --------------------------------------------------------------------

def keylike(data: bytes):
    """The text of a decoded state when it reads as a key or a short name (a joke key, `admin`), else
    False: printable, 2..40 characters, mostly letters, at least three different ones, few case switches
    (a base64 or hex intermediate has many), and a vowel in any word of four letters or more."""
    try:
        s = data.decode("ascii")
    except UnicodeDecodeError:
        return False
    if not 2 <= len(s) <= 40 or not _KEY_TEXT.fullmatch(s) or s != s.strip():
        return False
    letters = [c for c in s if c.isalpha()]
    if len(letters) < max(2, 0.6 * len(s)):
        return False
    if len(s) >= 4 and len(set(s)) < 3:
        return False
    # camelCase (`secretKey`) rises once per word; a base64 or hex intermediate switches case at random
    rises = sum(1 for a, b in zip(s, s[1:]) if a.isalpha() and b.isalpha() and a.islower() and b.isupper())
    switches = sum(1 for a, b in zip(s, s[1:]) if a.isalpha() and b.isalpha() and a.islower() != b.islower())
    allowed = max(1, len(s) // 6)
    if rises > allowed or switches > 2 * allowed:
        return False
    # a text that is one short unit repeated (`RUVFRUVF`) is an encoding of repeated bits, not a key
    if len(s) >= 6 and any(len(s) % n == 0 and s == s[:n] * (len(s) // n) for n in range(1, len(s) // 2 + 1)):
        return False
    if len(letters) >= 4 and not any(c in "aeiouyAEIOUY" for c in letters):
        return False
    return s


@dataclass
class Decoded:
    token: str
    answer: str
    chain: tuple
    oracle: str                       # "flag" or "key"
    source: str


def token_candidates(strings) -> list:
    """The string tokens worth decoding: whole literals in a token alphabet, and the long segments of
    path-like literals."""
    out = []
    for s in strings:
        parts = [s]
        if "/" in s:
            parts += [p for p in s.split("/") if p]
        for p in parts:
            if MIN_TOKEN <= len(p) <= MAX_TOKEN and _TOKEN_SHAPE.fullmatch(p):
                out.append(p)
    return list(dict.fromkeys(out))


def decode_tokens(script_strings, profile, *, alphabets=(), token_nodes: int = TOKEN_NODES,
                  max_tokens: int = MAX_TOKENS) -> tuple:
    """([Decoded], notes): every token of [(source route, [strings])] that the codec graph reads as a key
    or a flag in the event format, by at least one representation step. Bounded by node counts only."""
    codecs = tuple(c for c in C.core() if c.kind in C.REPRESENTATION) + engine_codecs(alphabets) + \
        tuple(c for c in C.core() if c.name in ("reverse", "rot13"))
    graph = Graph(codecs, max_depth=5, max_nodes=token_nodes, max_loose=1, xor=False, keyed=False)
    flag_oracle = FlagOracle(profile)
    out, notes, done = [], [], 0
    seen = set()
    for route, strings in script_strings:
        for tok in token_candidates(strings):
            if tok in seen:
                continue
            if done >= max_tokens:
                notes.append(f"only the first {max_tokens} string tokens were decoded")
                return out, notes
            seen.add(tok)
            done += 1
            raw = tok.encode("latin-1", "replace")
            oracle = AnyOf(flag_oracle, Recognizer(lambda d, raw=raw: d != raw and keylike(d), "key"))
            res = graph.search(raw, oracle)
            for hit in res.hits:
                if not hit.chain or not C.representation_steps(hit.chain, codecs):
                    continue
                kind = "flag" if hit.answer in flag_oracle.check(hit.data) else "key"
                out.append(Decoded(tok, hit.answer, tuple(hit.chain), kind, route))
    return out, notes


@dataclass
class Encoding:
    chain: tuple
    how: str
    samples: list                     # [(token, key)]
    verified: bool
    why: str = ""
    hidden: list = field(default_factory=list)       # [(key, token, [routes])]
    encode: object = None


def _case_style(keys) -> str:
    letters = "".join(c for k in keys for c in k if c.isalpha())
    if letters and letters == letters.lower():
        return "lower"
    if letters and letters == letters.upper():
        return "upper"
    return "as-is"


def route_templates(token: str, scripts) -> list:
    """Where a script puts a token: a literal that holds it inside a path, a prefix the script
    concatenates a value onto, else the site root. Templates hold \\0 for the token."""
    tpls = []
    for sc in scripts:
        for s in sc.strings:
            if token in s and s != token and len(s) <= MAX_TOKEN:
                tpls.append(s.replace(token, "\0", 1))
        tpls += [p + "\0" for p in sc.prefixes]
    tpls.append("/\0")
    return list(dict.fromkeys(tpls))[:6]


def encodings(decoded, scripts, *, keys=(), codecs=None, alphabets=()) -> list:
    """[Encoding]: chains two or more different key tokens share, inverted and checked on every token,
    with the likely hidden keys the observed ones lack encoded into routes."""
    codecs = codecs or (tuple(C.core()) + engine_codecs(alphabets))
    groups = {}
    for d in decoded:
        if d.oracle == "key":
            groups.setdefault(d.chain, {})[d.token] = d.answer
    out = []
    for chain, pairs in groups.items():
        if len(pairs) < 2:
            continue
        samples = sorted(pairs.items())
        enc, how = invert(chain, samples, codecs, alphabets)
        e = Encoding(chain, how if enc else "", samples, enc is not None, "" if enc else how, encode=enc)
        if enc is not None:
            style = _case_style(k for _, k in samples)
            known = {k.lower() for _, k in samples}
            wanted = list(dict.fromkeys(list(keys) + list(DEFAULT_KEYS)))
            for key in wanted:
                key = key.lower() if style == "lower" else key.upper() if style == "upper" else key
                if key.lower() in known:
                    continue
                try:
                    tok = enc(key)
                except (ValueError, UnicodeError):
                    continue
                tpls = route_templates(samples[0][0], scripts)
                e.hidden.append((key, tok, [t.replace("\0", urllib.parse.quote(tok, safe="=+/-_.~")) for t in tpls]))
        out.append(e)
    return out


# ---- gates -----------------------------------------------------------------------------------------

_EQ = frozenset({"===", "==", "!==", "!="})


def _walk(node):
    stack = [node]
    while stack:
        n = stack.pop()
        if isinstance(n, tuple):
            yield n
            stack.extend(x for x in n if isinstance(x, (tuple, list)))
        elif isinstance(n, list):
            stack.extend(x for x in n if isinstance(x, (tuple, list)))


def show(e, depth=0) -> str:
    """A short JavaScript rendering of an expression node, for evidence lines."""
    if depth > 12 or not isinstance(e, tuple) or not e:
        return "…"
    k = e[0]
    if k == "num":
        return J.to_str(e[1])
    if k == "str":
        return json.dumps(e[1])[:80]
    if k == "name":
        return e[1]
    if k == "input":
        return "<input>"
    if k == "member":
        if e[2][0] == "str" and re.fullmatch(r"[A-Za-z_$][\w$]*", e[2][1]):
            return f"{show(e[1], depth + 1)}.{e[2][1]}"
        return f"{show(e[1], depth + 1)}[{show(e[2], depth + 1)}]"
    if k == "call":
        return f"{show(e[1], depth + 1)}({', '.join(show(a, depth + 1) for a in e[2])})"
    if k in ("bin", "logic"):
        return f"{show(e[2], depth + 1)} {e[1]} {show(e[3], depth + 1)}"
    if k == "unary":
        return f"{e[1]}{' ' if e[1].isalpha() else ''}{show(e[2], depth + 1)}"
    if k == "fn":
        return f"function {e[1] or ''}(…)"
    return "…"


@dataclass
class Gate:
    source: str
    op: str
    target: object                     # the constant side's value (number or string)
    probe: tuple                       # the other side with ('input',) at the input slot
    kind: str                          # equality | transform
    expr: str                          # rendering of the comparison
    fast: str = ""                     # a natively computed hash recognized in the probe ("cyrb53")
    fast_args: tuple = ()
    norm: tuple = ()                   # normalizations applied to the input first (input_normalizer)


@dataclass
class Match:
    gate: Gate
    value: str
    proof: bool                        # the gate refused every near-miss of the value
    how: str


class Program:
    """Functions, constants and equality comparisons of a set of scripts (anywhere in them: nested
    callbacks included), read by parsing from every token that can start one."""

    def __init__(self, scripts, budget: int = PARSE_BUDGET):
        self.funcs, self.consts, self.comparisons, self.notes = {}, {}, [], []
        self.parsed = 0
        seen = set()
        for sc in scripts:
            toks = sc.toks
            for i, tk in enumerate(toks):
                if self.parsed > budget:
                    self.notes.append(f"the gate finder's parse budget ({budget} tokens) ran out in {sc.source.route}")
                    return
                if tk.kind != "name" and not (tk.kind == "punct" and tk.value == "="):
                    continue
                nxt = toks[i + 1] if i + 1 < len(toks) else None
                if nxt is None:
                    continue
                try:
                    found = self._parse_at(toks, i, tk, nxt)
                except (J.JsError, RecursionError, IndexError):
                    continue
                for node in found:
                    for n in _walk(node):
                        if n[0] == "bin" and n[1] in _EQ:
                            key = repr(n)
                            if key not in seen:
                                seen.add(key)
                                self.comparisons.append((sc.source.route, n))

    def _parse_at(self, toks, i, tk, nxt):
        v = tk.value
        if tk.kind == "name" and v == "function" and nxt.kind == "name":
            p = J.Parser(toks, i)
            decl = p.function_declaration()
            self.parsed += p.i - i
            self.funcs.setdefault(decl[1], decl[2])
            return [decl[2]]
        if tk.kind == "name" and v in ("const", "let", "var") and (nxt.kind == "name" or nxt.value in ("[", "{")):
            p = J.Parser(toks, i)
            st = p.var_statement()
            self.parsed += p.i - i
            for target, init in st[2]:
                if target[0] == "name" and init is not None:
                    if init[0] == "fn":
                        self.funcs.setdefault(target[1], init)
                    else:
                        self.consts.setdefault(target[1], []).append(init)
            return [init for _, init in st[2] if init is not None]
        if tk.kind == "name" and v in ("if", "while") and nxt.value == "(":
            p = J.Parser(toks, i + 1)
            e = p.paren_expression()
            self.parsed += p.i - i
            return [e]
        if tk.kind == "name" and v == "return":
            p = J.Parser(toks, i + 1)
            e = p.expression()
            self.parsed += p.i - i
            return [e]
        if tk.kind == "punct" and v == "=" and i > 0 and toks[i - 1].kind == "name":
            p = J.Parser(toks, i + 1)
            e = p.assignment()
            self.parsed += p.i - i
            name = toks[i - 1].value
            if e[0] == "fn":
                self.funcs.setdefault(name, e)
            return [e]
        return []

    def interp(self, max_steps=CANDIDATE_STEPS) -> J.Interp:
        it = J.Interp(max_steps)
        for name, fn in self.funcs.items():
            it.define(name, fn)
        for name, inits in self.consts.items():
            if name not in self.funcs and len(inits) == 1:
                it.define_lazy(name, inits[0])
        return it


_MISSING = object()


def _const(it: J.Interp, expr):
    it.reset(CANDIDATE_STEPS)
    try:
        v = it.eval(expr)
    except J.Unresolved:
        return _MISSING
    except (J.JsError, RecursionError):
        return _MISSING
    if isinstance(v, bool) or v is None or v is J.UNDEF or isinstance(v, (J.Closure, J.Builtin, J.JSObject,
                                                                         J.JSArray)):
        return _MISSING
    return v


def _root(e):
    while e[0] in ("member", "call"):
        e = e[1]
    return e


def _free(it: J.Interp, e) -> bool:
    """True when the chain's root is a name the program does not define (the input slot), or `this`."""
    r = _root(e)
    if r[0] == "this":
        return True
    if r[0] != "name":
        return False
    it.reset(CANDIDATE_STEPS)
    try:
        it.eval(r)
        return False
    except J.Unresolved:
        return True
    except (J.JsError, RecursionError):
        return False


# String operations the code applies to the value it read: a chain rooted at an undefined name keeps
# these outer steps (`input.value.trim().toLowerCase().length`), and what is left is the input slot.
STRING_OPS = frozenset({"length", "charCodeAt", "codePointAt", "charAt", "at", "toLowerCase", "toUpperCase",
                        "toLocaleLowerCase", "toLocaleUpperCase", "trim", "trimStart", "trimEnd", "trimLeft",
                        "trimRight", "normalize", "split", "slice", "substring", "substr", "indexOf",
                        "lastIndexOf", "includes", "startsWith", "endsWith", "repeat", "padStart", "padEnd",
                        "replace", "replaceAll", "concat", "toString", "valueOf", "match", "search",
                        # array steps after a split('')
                        "reverse", "join", "map", "filter", "reduce", "every", "some", "sort", "find",
                        "findIndex"})


def _string_op(e) -> bool:
    """A member or method-call step on a string: `.length`, `[3]`, `.toLowerCase()`, `.split('')`."""
    if e[0] == "member":
        return (e[2][0] == "str" and e[2][1] in STRING_OPS) or e[2][0] == "num"
    return e[0] == "call" and e[1][0] == "member" and e[1][2][0] == "str" and e[1][2][1] in STRING_OPS


def holify(it: J.Interp, e):
    """`e` with every chain rooted at an undefined name replaced by ('input',) at the point where the
    code reads its value, keeping the string operations (trim, toLowerCase, length, split, ...) the
    code applies to that value. Function bodies are left alone."""
    if not isinstance(e, tuple) or not e or e[0] in ("fn", "num", "str", "bool", "null"):
        return e
    if e[0] == "member" and _string_op(e) and _free(it, e[1]):
        return ("member", holify(it, e[1]), e[2], e[3])
    if e[0] == "call" and _string_op(e) and _free(it, e[1][1]):
        return ("call", ("member", holify(it, e[1][1]), e[1][2], e[1][3]),
                [holify(it, a) for a in e[2]], e[3])
    if e[0] in ("name", "member", "call", "this") and _free(it, e):
        return ("input",)
    return tuple(holify(it, x) if isinstance(x, tuple) else
                 [holify(it, y) for y in x] if isinstance(x, list) else x for x in e)


def _norm_chain(e):
    """The string normalizations wrapped around ('input',), outermost first, or None when `e` is not
    only a normalized input."""
    out = []
    while e[0] == "call" and e[1][0] == "member" and e[1][2][0] == "str" and e[1][2][1] in J.STRING_METHODS_INPUT \
            and not e[2]:
        out.append(e[1][2][1])
        e = e[1][1]
    return out if e == ("input",) else None


def input_normalizer(probe) -> tuple:
    """The normalizations (outermost first) the gate applies to its input before anything else: the
    page accepts every input with the same normalized form, so a match is reported normalized. () when
    the input is used raw or in more than one differently normalized way."""
    chains = [c for c in (_norm_chain(n) for n in _walk(probe)) if c is not None]
    if not chains:
        return ()
    longest = max(chains, key=len)
    if any(c != longest[len(longest) - len(c):] for c in chains):
        return ()
    return tuple(longest)


def normalized(norm, value: str) -> str:
    for m in reversed(norm):
        value = J._string_method(None, value, m, [])
    return value


def _has_input(e) -> bool:
    return any(n[0] == "input" for n in _walk(e))


def _only_normalized_input(e) -> bool:
    return _norm_chain(e) is not None


_CYRB53 = {0xDEADBEEF, 0x41C6CE57, 2654435761, 1597334677, 2246822507, 3266489909}


def fingerprint(fn) -> str:
    nums = {int(n[1]) for n in _walk(fn) if n[0] == "num" and n[1] == int(n[1])}
    if _CYRB53 <= nums:
        return "cyrb53"
    return ""


def cyrb53(s: str, seed: int = 0) -> int:
    """The 53-bit string hash pages call cyrb53 (UTF-16 code units, as charCodeAt reads them)."""
    def imul(a, b):
        return (a * b) & 0xFFFFFFFF
    h1, h2 = (0xDEADBEEF ^ seed) & 0xFFFFFFFF, (0x41C6CE57 ^ seed) & 0xFFFFFFFF
    units = s.encode("utf-16-le")
    for k in range(0, len(units), 2):
        ch = units[k] | units[k + 1] << 8
        h1 = imul(h1 ^ ch, 2654435761)
        h2 = imul(h2 ^ ch, 1597334677)
    h1 = imul(h1 ^ (h1 >> 16), 2246822507)
    h1 ^= imul(h2 ^ (h2 >> 13), 3266489909)
    h2 = imul(h2 ^ (h2 >> 16), 2246822507)
    h2 ^= imul(h1 ^ (h1 >> 13), 3266489909)
    return 4294967296 * (2097151 & h2) + (h1 & 0xFFFFFFFF)


def _substitute(prog: Program, it, e, depth=0):
    """A probe whose names were assigned elsewhere (`const v = input.value.toLowerCase()`, then
    `cyrb53(v) === H`, or `const h = cyrb53(v)`, then `h === H`) gets what was assigned in their place,
    when that is not a constant, up to three hops deep, so the normalizations around the input slot
    are kept. Function bodies are left alone."""
    if depth >= 3 or not isinstance(e, tuple) or not e or e[0] in ("fn", "num", "str", "bool", "null"):
        return e
    if e[0] == "name":
        if e[1] in prog.consts and e[1] not in prog.funcs and _const(it, e) is _MISSING:
            inits = [x for x in prog.consts[e[1]] if x[0] != "fn"]
            if inits:
                return _substitute(prog, it, inits[-1], depth + 1)
        return e
    return tuple(_substitute(prog, it, x, depth) if isinstance(x, tuple) else
                 [_substitute(prog, it, y, depth) for y in x] if isinstance(x, list) else x for x in e)


def find_gates(prog: Program) -> list:
    """[Gate]: every equality comparison with a constant number or string on one side and the input
    slot somewhere in the other."""
    it = prog.interp()
    gates, seen = [], set()
    for route, (_, op, left, right) in prog.comparisons:
        lv, rv = _const(it, left), _const(it, right)
        if (lv is _MISSING) == (rv is _MISSING):
            continue
        target, probe = (lv, right) if rv is _MISSING else (rv, left)
        if isinstance(target, float) and target == int(target):
            target = int(target)
        probe = holify(it, _substitute(prog, it, probe))
        if not _has_input(probe):
            continue
        key = (repr(target), repr(probe))
        if key in seen:
            continue
        seen.add(key)
        kind = "equality" if _only_normalized_input(probe) else "transform"
        g = Gate(route, op, target, probe, kind, f"{show(probe)} {op} {show(('num', float(target)) if isinstance(target, int) else ('str', target))}",
                 norm=input_normalizer(probe))
        if probe[0] == "call" and probe[1][0] == "name" and probe[1][1] in prog.funcs and probe[2] \
                and _only_normalized_input(probe[2][0]) and fingerprint(prog.funcs[probe[1][1]]) == "cyrb53":
            fn = prog.funcs[probe[1][1]]
            seed = 0
            if len(probe[2]) > 1:
                sv = _const(it, probe[2][1])
                seed = int(sv) if isinstance(sv, float) else None
            elif len(fn[2]) > 1 and fn[2][1][1] is not None:
                sv = _const(it, fn[2][1][1])
                seed = int(sv) if isinstance(sv, float) else None
            if seed is not None:
                g.fast, g.fast_args = "cyrb53", (seed,)
        gates.append(g)
    return gates


def _normalize(probe_arg, value: str) -> str:
    """Apply the string methods wrapped around the input slot `probe_arg`, innermost first."""
    return normalized(_norm_chain(probe_arg) or (), value)


def flag_input_gates(gates, ff, matches=()) -> list:
    """The gates whose input is plausibly the flag itself: a hash or transform gate, unless a value it
    was proven to accept is not flag-shaped (then it checks a password); an equality gate only when its
    constant is flag-shaped. A gate on a password (`pw === 'letmein'`) says nothing about the flag the
    page reveals after it, so it refutes nothing."""
    password = {id(m.gate) for m in matches if m.proof and not ff.is_flag(m.value)}
    return [g for g in gates if (g.kind != "equality" and id(g) not in password)
            or (g.kind == "equality" and isinstance(g.target, str) and ff.is_flag(g.target))]


def refutable_values(comments, scripts, ff) -> list:
    """The flag-shaped strings a gate may refute: those of comments (HTML and script comments, which a
    page never shows) that no script string also holds. A flag in script code, a decoded script token
    or a numeric array is what a page reveals once its check passes, so a gate never refutes it."""
    in_code = {f for sc in scripts for x in sc.strings for f in ff.find_flags(x)}
    return [f for _, c in comments for f in ff.find_flags(c) if f not in in_code]


def refuted(runner, gates, values) -> list:
    """The values (from refutable_values) every gate (from flag_input_gates) rejects: a placeholder
    such as `<prefix>{band}` in a comment that the page's hash gate refuses is a template, not the flag.
    Empty when the page has no gate a value can fail."""
    checkable = [g for g in gates if g.kind != "equality" or isinstance(g.target, str)]
    if not checkable:
        return []
    out = []
    for v in dict.fromkeys(values):
        if all(not (runner.matches(g, v) if g.kind != "equality" else
                    _normalize_equality(g, v) == g.target) for g in checkable):
            out.append(v)
    return out


def _normalize_equality(gate, value):
    return normalized(gate.norm, value)


class GateRunner:
    """Runs candidates through gates with one shared step budget (deterministic, no clock)."""

    def __init__(self, prog: Program, steps: int = GATE_STEPS):
        self.prog, self.left, self.notes = prog, int(steps), []
        self.it = prog.interp()
        self._fast_ok = {}

    def evaluate(self, gate: Gate, value: str):
        """The probe's value for one input, or _MISSING when the evaluator cannot say."""
        if gate.fast and self._fast_ok.get(id(gate), True):
            v = cyrb53(_normalize(gate.probe[2][0], value), gate.fast_args[0])
            if id(gate) not in self._fast_ok:          # cross-check the native hash once against the evaluator
                slow = self._interp(gate, value)
                ok = slow is not _MISSING and isinstance(slow, float) and int(slow) == v
                self._fast_ok[id(gate)] = ok
                if not ok:
                    self.notes.append(f"{gate.source}: the native cyrb53 disagreed with the evaluator; the evaluator is used")
                    return slow
            return float(v)
        return self._interp(gate, value)

    def _interp(self, gate, value):
        if self.left <= 0:
            return _MISSING
        budget = min(CANDIDATE_STEPS, self.left)
        self.it.reset(budget)
        try:
            v = self.it.eval(gate.probe, {"\0input": value})
        except (J.JsError, RecursionError):         # the evaluator cannot say: no match, steps spent
            self.left -= self.it.steps
            return _MISSING
        self.left -= self.it.steps
        return v

    def matches(self, gate: Gate, value: str) -> bool:
        v = self.evaluate(gate, value)
        if v is _MISSING:
            return False
        if isinstance(v, float) and v == int(v) and isinstance(gate.target, int):
            return int(v) == gate.target
        return J.strict_equal(v, float(gate.target) if isinstance(gate.target, int) else gate.target) or \
            (gate.op in ("==", "!=") and J.loose_equal(v, gate.target))

    def discriminates(self, gate: Gate, value: str) -> bool:
        """True when every near-miss of `value` (one character changed, one more, one fewer) fails the
        gate. The replacement characters are digits, so a case-folding gate cannot fold them back; a
        near-miss with the same normalized form as `value` is no near-miss and is left out."""
        near = [value + "7", value[:-1] if len(value) > 1 else value + "8"]
        if value:
            mid = len(value) // 2
            near.append(value[:mid] + ("7" if value[mid] != "7" else "8") + value[mid + 1:])
            near.append(("9" if value[0] != "9" else "8") + value[1:])
        same = normalized(gate.norm, value)
        return not any(normalized(gate.norm, n) != same and self.matches(gate, n) for n in near)


def check_gate(runner: GateRunner, gate: Gate, candidates, limit: int = 3) -> list:
    out = []
    for value in candidates:
        if runner.left <= 0 and not gate.fast:
            break
        if runner.matches(gate, value):
            value = normalized(gate.norm, value)       # the page reads every input in this form
            if any(m.value == value for m in out):
                continue
            out.append(Match(gate, value, runner.discriminates(gate, value),
                             f"{gate.expr} holds for {value!r}"))
            if len(out) >= limit:
                break
    return out


# ---- candidates ------------------------------------------------------------------------------------

def _templates(ff, profile, texts) -> list:
    """Flag templates ('pre{', '}') from flag-shaped strings the pages show, then the event prefixes."""
    out = []
    for t in texts:
        for f in ff.find_flags(t):
            pre = f[:f.index("{") + 1]
            if (pre, "}") not in out:
                out.append((pre, "}"))
    for p in getattr(profile.flag, "prefixes", ()) or ():
        if (p + "{", "}") not in out:
            out.append((p + "{", "}"))
    return out


def _words(texts) -> list:
    words, phrases = [], []
    for t in texts:
        toks = _WORD.findall(t)
        for w in toks:
            if w.lower() not in _STOP:
                words.append(w)
        for n in (2, 3):
            for k in range(len(toks) - n + 1):
                group = toks[k:k + n]
                if any(len(w) < 2 for w in group):
                    continue
                phrases.append("_".join(group))
                phrases.append("".join(group))
    return list(dict.fromkeys(words + phrases))


def candidates(explicit, ff, profile, texts, decoded_answers=(), limit=MAX_CANDIDATES) -> list:
    """Candidate inputs, likeliest first: the explicit ones (bare and in each template, lower case
    first), the flag-shaped strings found, decoded answers, then the harvested words and phrases."""
    tpls = _templates(ff, profile, list(texts) + list(decoded_answers))
    found = [f for t in list(texts) + list(decoded_answers) for f in ff.find_flags(t)]
    out = []

    def add(v):
        if v and len(out) < limit:
            out.append(v)

    def wrapped(w):
        for pre, post in tpls:
            add(pre + w.lower() + post)
            add(pre + w + post)

    for w in explicit:
        wrapped(w)
        add(w.lower())
        add(w)
    for f in found:
        add(f)
    for a in decoded_answers:
        add(a)
    for w in _words(texts):
        wrapped(w)
        add(w.lower())
        add(w)
    return list(dict.fromkeys(out))[:limit]


# ---- the whole analysis ----------------------------------------------------------------------------

@dataclass
class Report:
    sources: list = field(default_factory=list)          # [(route, kind, chars)]
    comments: list = field(default_factory=list)         # [(route, text)]
    unsaved: list = field(default_factory=list)          # routes named but not read
    recon: dict = field(default_factory=dict)            # js_recon tables, merged
    decoded: list = field(default_factory=list)          # [Decoded]
    encodings: list = field(default_factory=list)        # [Encoding]
    gates: list = field(default_factory=list)            # [Gate]
    matches: list = field(default_factory=list)          # [Match]
    numeric: list = field(default_factory=list)          # [(route, step, text)] numsym decodes
    page_flags: list = field(default_factory=list)       # [(route, flag)] flag-shaped strings in the bytes
    hidden_hits: list = field(default_factory=list)      # [(route, key, flag)] live answers
    hidden_misses: list = field(default_factory=list)    # [(route, status)]
    candidates_tried: int = 0
    refuted: list = field(default_factory=list)          # flag-shaped strings every gate of the page rejects
    notes: list = field(default_factory=list)


def _numsym():
    try:
        import numsym
    except ImportError as exc:                         # B-094's pack; named, never skipped quietly
        raise GateBlocked(f"the numeric-ASCII reader (solvers/warmups/numsym.py, B-094) does not import: {exc}") from exc
    return numsym


def analyze(sources, ff, profile, *, explicit=(), keys=(), steps: int = GATE_STEPS,
            token_nodes: int = TOKEN_NODES) -> Report:
    rep = Report()
    rep.sources = [(s.route, s.kind, len(s.text)) for s in sources]
    script_srcs, rep.comments, texts = expand(sources)
    scripts = [read_script(s) for s in script_srcs]
    rep.notes += [sc.error for sc in scripts if sc.error]
    rep.recon = js_recon.scan({sc.source.route: sc.source.text for sc in scripts})
    for s in sources:
        for f in ff.find_flags(s.text):
            if (s.route, f) not in rep.page_flags:
                rep.page_flags.append((s.route, f))
    # routes named but not read
    have = {s.route for s in sources}
    for s in sources:
        for ref in references(s):
            r = rc.resolve(s.route, ref, None)
            if r and r not in have and r not in rep.unsaved:
                rep.unsaved.append(r)
    # numeric arrays through B-094
    ns = _numsym()
    for sc in scripts:
        for vals in sc.numarrays:   # read_script keeps at most MAX_NUMARRAY values of one array
            for step, text in ns.numascii_search(vals):
                for f in ff.find_flags(text):
                    rep.numeric.append((sc.source.route, step, f))
    # string tokens through the codec graph
    alphabets = custom_alphabets([x for sc in scripts for x in sc.strings])
    rep.decoded, notes = decode_tokens([(sc.source.route, sc.strings) for sc in scripts], profile,
                                       alphabets=alphabets, token_nodes=token_nodes)
    rep.notes += notes
    rep.encodings = encodings(rep.decoded, scripts, keys=keys, alphabets=alphabets)
    # gates
    prog = Program(scripts)
    rep.gates = find_gates(prog)
    if rep.gates:
        decoded_answers = [d.answer for d in rep.decoded] + [f for _, _, f in rep.numeric]
        all_texts = [c for _, c in rep.comments] + [t for _, t in texts] + \
            [x for sc in scripts for x in sc.strings if len(x) <= 200]
        cands = candidates(list(explicit), ff, profile, all_texts, decoded_answers)
        rep.candidates_tried = len(cands)
        runner = GateRunner(prog, steps)
        for g in rep.gates:
            if g.kind == "equality":
                continue
            rep.matches += check_gate(runner, g, cands)
        rep.notes += runner.notes
        rep.refuted = refuted(runner, flag_input_gates(rep.gates, ff, rep.matches),
                              refutable_values(rep.comments, scripts, ff))
        rep.notes += prog.notes
        if runner.left <= 0:
            rep.notes.append(f"the gate evaluator's step budget ({steps}) ran out; pass gate_steps= for more")
    return rep


def probe_hidden(rep: Report, fetch, origin: str, page_route: str, ff, budget: int, *, gap=GAP, sleep=time.sleep):
    """GET each encoded hidden route of every verified encoding (up to MAX_HIDDEN_ROUTES and `budget`,
    the GETs the mirror left); a flag in an answer is recorded in rep.hidden_hits. A route that names a
    state-changing action (logout, delete, ...) is never requested and is named in the notes."""
    destructive = _is_destructive()
    sent, held, limit = 0, [], min(budget, MAX_HIDDEN_ROUTES)
    routes_left = [(key, rc.resolve(page_route, raw, origin)) for enc in rep.encodings if enc.verified
                   for key, tok, routes in enc.hidden for raw in routes]
    done = set()                                       # keys whose route already answered a flag
    for key, route in routes_left:
        if key in done or route is None:
            continue
        if destructive(route):
            held.append(route)
            continue
        if sent >= limit:
            rep.notes.append("the hidden-route budget ran out before every encoded key was requested")
            break
        sleep(gap)
        sent += 1
        try:
            status, ctype, body, info = fetch(route)
        except (rc.CrawlBlocked, ValueError) as exc:
            rep.hidden_misses.append((route, f"no answer: {exc}"))
            continue
        flags = ff.find_flags(body) if status == 200 else []
        if flags:
            rep.hidden_hits += [(route, key, f) for f in flags]
            done.add(key)
            continue
        rep.hidden_misses.append((route, status))
    if held:
        rep.notes.append(f"{len(held)} hidden route(s) not requested (they name a state-changing action): "
                         + ", ".join(held[:4]))


def result_of(rep: Report, ff, *, seconds: float = 0.0, challenge_id=None):
    from ctf.result import Cost, Evidence, SolverResult
    solved, cands, ev, lines = [], [], [], []

    def add(lst, f):
        if f not in lst:
            lst.append(f)

    for route, key, flag in rep.hidden_hits:
        enc = next((e for e in rep.encodings if any(h[0] == key for h in e.hidden)), None)
        add(solved, flag)
        ev.append(Evidence("wire", f"GET {route} (the hidden key {key!r} through {enc.how if enc else '?'}) "
                                   f"answered {flag}"))
    for m in rep.matches:
        if m.proof and ff.is_flag(m.value):
            add(solved, m.value)
            ev.append(Evidence("oracle", f"{m.how}; near-misses fail it (gate in {m.gate.source})"))
        else:
            add(cands, m.value)
            why = "not in the event flag format" if m.proof else "the gate also accepts near-misses of it"
            lines.append(f"gate match {m.value!r} is a candidate only: {why} ({m.how})")
    for g in rep.gates:
        if g.kind == "equality" and isinstance(g.target, str):
            if ff.is_flag(g.target):
                add(solved, g.target)
                ev.append(Evidence("match", f"the page compares its input to this constant: {g.expr} ({g.source})"))
            else:
                add(cands, g.target)
                lines.append(f"equality gate in {g.source}: the expected input is {g.target!r}")
    for f in rep.refuted:
        lines.append(f"{f!r} is flag-shaped but every gate of the page rejects it: a template or a decoy, not the flag")
    for route, f in rep.page_flags:
        if f not in solved and f not in rep.refuted:
            add(cands, f)
    for d in rep.decoded:
        if d.oracle == "flag" and d.answer not in solved and d.answer not in rep.refuted:
            add(cands, d.answer)
            lines.append(f"{d.source}: {d.token[:40]!r} decodes ({'+'.join(d.chain)}) to {d.answer!r}")
    for route, step, f in rep.numeric:
        if f not in solved and f not in rep.refuted:
            add(cands, f)
            lines.append(f"{route}: a numeric array reads ({step}) as {f!r}")
    cands = [c for c in cands if c not in solved]

    # what was read and what to do next
    lines.insert(0, f"read {len(rep.sources)} source(s): " + ", ".join(f"{r} ({k})" for r, k, _ in rep.sources[:12]))
    for route, c in rep.comments[:12]:
        lines.append(f"comment {route}: {c[:160]!r}")
    if rep.unsaved:
        lines.append("named but not read (fetch these next): " + ", ".join(rep.unsaved[:20]))
    for e in rep.encodings:
        if e.verified:
            lines.append(f"recognized encoding {e.how}: {len(e.samples)} token(s) decode to keys "
                         + ", ".join(repr(k) for _, k in e.samples[:8]))
            for key, tok, routes in e.hidden[:6]:
                lines.append(f"  hidden key {key!r} -> {tok[:90]} -> try {routes[0][:120]}")
        else:
            lines.append(f"chain {'+'.join(e.chain)} decodes {len(e.samples)} tokens but does not invert: {e.why}")
    for d in rep.decoded:
        if d.oracle == "key" and not any(d.chain == e.chain for e in rep.encodings):
            lines.append(f"{d.source}: {d.token[:40]!r} decodes ({'+'.join(d.chain)}) to {d.answer!r}")
    for g in rep.gates:
        if g.kind != "equality":
            lines.append(f"gate in {g.source}: {g.expr}" + (f" [{g.fast}]" if g.fast else ""))
    if any(g.kind != "equality" for g in rep.gates) and not solved:
        lines.append(f"{rep.candidates_tried} candidate(s) tried, none confirmed; pass the answer you expect with "
                     f"--opt candidates=<word>[,<word>...] (each is also tried inside every flag template)")
    for route, status in rep.hidden_misses[:6]:
        lines.append(f"hidden route {route}: {status}")
    lines += rep.notes
    notes = "\n".join(lines)
    cost = Cost(seconds=round(seconds, 3))
    if solved:
        return SolverResult(status="solved", flags=solved, evidence=ev, cost=cost, engine=ENGINE,
                            challenge_id=challenge_id, notes=notes)
    if cands:
        return SolverResult(status="candidate", flags=cands, cost=cost, engine=ENGINE, challenge_id=challenge_id,
                            notes=notes)
    if rep.gates or rep.encodings or rep.decoded or rep.comments or rep.unsaved:
        return SolverResult(status="unsure", cost=cost, engine=ENGINE, challenge_id=challenge_id, notes=notes)
    return SolverResult(status="none", cost=cost, engine=ENGINE, challenge_id=challenge_id, notes=notes)


def _list_opt(value) -> list:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value if str(v)]
    return [v.strip() for v in str(value).split(",") if v.strip()]


def solve(challenge_dir: Path, profile, **opts):
    """Engine contract. With no `url`: the saved pages of `saved` (default: the challenge folder).
    With `url`: a live GET mirror, when the profile's live_service_scope allows the host."""
    from ctf.result import SolverResult
    t0 = time.process_time()
    challenge_dir = Path(challenge_dir)
    ff = flagfmt.for_profile(profile)
    explicit = _list_opt(opts.get("candidates"))
    if opts.get("candidates_file"):
        cf = Path(opts["candidates_file"])
        if not cf.is_file():
            return SolverResult(status="blocked", engine=ENGINE, notes=f"candidates_file {cf} does not exist")
        explicit += [ln.strip() for ln in cf.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip()]
    keys = _list_opt(opts.get("keys"))
    steps = int(opts.get("gate_steps", GATE_STEPS))
    nodes = int(opts.get("token_nodes", TOKEN_NODES))
    gap = float(opts.get("gap", GAP))
    try:
        if opts.get("url"):
            max_requests = int(opts.get("max_requests", MAX_REQUESTS))
            sources, fetch, origin, start, notes, budget = mirror_live(str(opts["url"]), profile,
                                                                       max_requests=max_requests, gap=gap)
            rep = analyze(sources, ff, profile, explicit=explicit, keys=keys, steps=steps, token_nodes=nodes)
            rep.notes[:0] = notes
            probe_hidden(rep, fetch, origin, start, ff, budget[0], gap=gap)
        else:
            folder = Path(opts["saved"]) if opts.get("saved") else challenge_dir
            if not folder.is_dir():
                raise GateBlocked(f"no saved-pages folder at {folder}")
            sources, skipped = saved_sources(folder)
            if not sources:
                raise GateBlocked(f"no saved page, script or text file under {folder}: save the page (HTML), its "
                                  f"scripts and the files its comments name there, or pass url= for an event "
                                  f"whose rules.live_service_scope allows the host")
            rep = analyze(sources, ff, profile, explicit=explicit, keys=keys, steps=steps, token_nodes=nodes)
            rep.notes += skipped
    except GateBlocked as exc:
        return SolverResult(status="blocked", engine=ENGINE, notes=str(exc))
    return result_of(rep, ff, seconds=time.process_time() - t0)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="client_gate.py", description=__doc__.split("\n\n")[0])
    ap.add_argument("challenge_dir", type=Path)
    ap.add_argument("--url", help="mirror this page live (GET only, scope-locked) instead of the saved pages")
    ap.add_argument("--saved", help="folder of saved pages (default: the challenge folder)")
    ap.add_argument("--candidates", help="comma-separated candidate answers for a client-side gate")
    ap.add_argument("--candidates-file")
    ap.add_argument("--keys", help="comma-separated extra hidden keys to encode")
    ap.add_argument("--event", help="event slug (default: the current event)")
    a = ap.parse_args(argv)
    from ctf import event
    profile = event.load(a.event) if a.event else event.current()
    opts = {k: v for k, v in (("url", a.url), ("saved", a.saved), ("candidates", a.candidates),
                              ("candidates_file", a.candidates_file), ("keys", a.keys)) if v}
    print(solve(a.challenge_dir, profile, **opts).to_json())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
