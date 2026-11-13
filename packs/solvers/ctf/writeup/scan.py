"""Redaction and the leak scan: the gate between private staging and anything public.

    sc = Scanner(profile, known=["PINK{...}", ...], allow=[...])
    text, n = sc.redact(text)          # only when the policy redacts (Policy.redact)
    findings = sc.scan(text)           # [Finding(kind, line, preview, blocking)]

What redaction removes (when the event redacts; an event that forbids sharing always does):
  * the body of every "Flag" section (a markdown heading named Flag), harvesting the values in it;
  * every known value (confirmed flags, rejected candidates, ledger flags, the harvested values),
    case-insensitively, wherever it appears;
  * every flag in the event format, with the prefix matched in ANY case (an accepted flag may start
    with a capital where the profile says lower case: SpookyCTF 2026) and a broad body;
  * the inner body of every known flag (>= 6 chars) where it appears outside its wrapper;
  * every token whose sha256 is a recorded `flag_sha256` (an event that forbids sharing keeps only the
    hash in the ledger): the token becomes a known value, so it is redacted wherever it appears.
A redacted flag reads PREFIX{<redacted>}; a fragment or bare value reads <redacted>.

What the scan reports (never echoing a value: previews are masked, an external URL loses its
credentials, query, fragment and any token-like path segment):
  blocking always   secret (JWT, bearer; an authorization or cookie header in raw, dict or JSON form;
                    a cookies= dict, cookies.set(...) or cookies[...] = ...; a session/token key with
                    a literal value in a dict; curl -b/--cookie name=value; an X-*-Token, X-Api-Key
                    or Api-Key header in raw, dict or JSON form; a token/session/cookie name assigned
                    a quoted literal; a shell `NAME_TOKEN=value` or `export ...`; a basic-auth
                    tuple with a literal password; URL credentials; private key; cloud/API token),
                    instance-url (a URL on the platform or a live-service host), instance-host (a bare
                    hostname on one: `nc chal.inst.example 31337`, `ssh ctf@inst.example`), ipv4 (not loopback),
                    uuid, longhex (32+ hex: session ids, keys), unfinished (<!-- TODO), open-check
                    (<!-- CHECK:), unclosed-private (<!-- private --> without its close)
  blocking when redacting   flag, known-value, flag-fragment, flag-shaped (any-prefix X{...})
  note              flag / flag-shaped when the event keeps flags; external-url (review it)
`allow` (the staging folder's publish-allow.txt) accepts, for the kinds flag-shaped, uuid, longhex and
external-url only, an exact token per line, or a rule `@<kind> <path glob>` (e.g. `@longhex */solve/*`)
that accepts every finding of that kind in matching files. It can never allow an event flag, a known
value, a fragment or a secret. Lines starting with # are comments.

Private blocks `<!-- private --> ... <!-- /private -->` are dropped by strip_private() before a file
leaves staging: drafts keep the raw solve log there.
"""
from __future__ import annotations

import fnmatch
import hashlib
import re
from dataclasses import dataclass
from typing import Iterable
from urllib.parse import urlsplit

from .. import event as _event
from .. import flagfmt as _flagfmt
from . import common, policy as _policy

REDACTED = "<redacted>"
FRAGMENT_MIN = 6           # shorter flag bodies are not redacted as bare fragments (too many false hits)
KNOWN_MIN = 6              # shorter bare (unwrapped) known values are reported, not redacted

_PREFIX_WORD = re.compile(_flagfmt.UNKNOWN_PREFIX)
_BROAD_BODY = r"[^{}\n]{1,256}"
_SHAPE_BODY = r"[^{}\s]{1,256}"
_PLACEHOLDER = re.compile(r"(?:\.\.\.|…|<[^<>{}\n]*>|redacted|REDACTED|Redacted|\s*)")

PRIVATE_RX = re.compile(r"<!--\s*private\s*-->.*?<!--\s*/private\s*-->\n?", re.S | re.I)
PRIVATE_OPEN_RX = re.compile(r"<!--\s*private\s*-->", re.I)
TODO_RX = re.compile(r"<!--\s*TODO\b", re.I)
CHECK_RX = re.compile(r"<!--\s*CHECK:", re.I)
HEADING_RX = re.compile(r"^(#{1,6})[ \t]+(.+?)[ \t]*#*[ \t]*$", re.M)
FLAG_HEADING_RX = re.compile(r"^flags?\b", re.I)
BACKTICK_RX = re.compile(r"`([^`\n]{1,300})`")
_BARE_TOKEN = re.compile(r"[^\s/.`]+")

_Q = r"[\"']"                    # a quote around a header name or value (the dict and JSON forms)
_LIT = r"(?![<{$])[^\"'\s]"        # a literal value character; `<token>`, `{tok}`, `$TOK` are placeholders
SECRET_RX = {
    "jwt": re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]*)?"),
    # `Authorization: x`, `"Authorization": "x"`, `'authorization': 'x'`, `authorization="x"`
    "auth-header": re.compile(rf"(?i)\b(?:proxy-)?authorization(?:{_Q}?\s*:\s*{_Q}?|\s*=\s*{_Q})[^\s\"']+"),
    "bearer": re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    # `Cookie: a=b`, `"Cookie": "a=b"`, `Set-Cookie: a=b`
    "cookie-header": re.compile(rf"(?i)\b(?:set-)?cookie{_Q}?\s*:\s*{_Q}?[^\s;=\"']+=[^\s\"']+"),
    # `cookies={"session": "x"}`, `cookies = {'sid': 'x'}`, `"cookies": {"a": "x"}`, `cookies=dict(a="x")`
    "cookie-dict": re.compile(rf"(?i)\bcookies?{_Q}?\s*[=:]\s*(?:dict\(|\{{)\s*{_Q}?[^\s\"'=:]+{_Q}?\s*[=:]\s*"
                              rf"{_Q}{_LIT}{{4,}}"),
    # `s.cookies.set("session", "x")`, `s.cookies["session"] = "x"`
    "cookie-set": re.compile(rf"(?i)\bcookies(?:\.set\(\s*{_Q}[^\"'\n]+{_Q}\s*,\s*|\[\s*{_Q}[^\"'\n]+{_Q}\s*\]\s*=\s*)"
                             rf"{_Q}{_LIT}{{4,}}"),
    # a session or token key with a literal value in a dict or JSON object: `{"session": "x"}`
    "session-key": re.compile(rf"(?i){_Q}(?:session(?:[_-]?id)?|sessid|phpsessid|connect\.sid|sid|token|"
                              rf"access[_-]?token|auth[_-]?token|refresh[_-]?token|api[_-]?key|csrf[_-]?token|jwt)"
                              rf"{_Q}\s*:\s*{_Q}{_LIT}{{8,}}{_Q}"),
    # `curl -b 'session=x'`, `curl --cookie "a=x"`, `--cookie=a=x` (a cookie file `-b jar.txt` has no `=`)
    "curl-cookie": re.compile(rf"(?<!\S)(?:-b|--cookie)(?:\s+|=){_Q}?[^\s;=\"']+={_LIT}{{4,}}"),
    # a token header in raw, dict or JSON form: `-H 'X-Api-Key: x'`, `{"X-Auth-Token": "x"}`, `Api-Key: x`
    "token-header": re.compile(rf"(?i)(?:x-[a-z0-9-]*(?:token|api-?key|auth|session|secret|csrf)"
                               rf"[a-z0-9-]*|api-?key|auth-token){_Q}?\s*:\s*{_Q}?{_LIT}{{8,}}"),
    # a token, session or cookie name assigned a quoted literal: `token = "x"`, `SESSION = "x"`,
    # `cookie = "session=x"`, `CTFD_TOKEN="x"` (a call such as `requests.Session()` is not a literal)
    "secret-assign": re.compile(rf"(?i)(?<!\w)(?:[a-z0-9]+_)*(?:token|session(?:_?id)?|sessid|sid|cookies?|"
                                rf"api_?key|jwt|auth)(?:_[a-z0-9]+)*\s*=\s*{_Q}{_LIT}{{8,}}{_Q}"),
    # a shell environment value: `export CTFD_TOKEN=x`, `CTFD_TOKEN=x python solve.py`
    "env-secret": re.compile(r"[A-Z0-9_]*(?:TOKEN|SESSION|COOKIE|API_?KEY|SECRET|JWT|"
                             r"PASSWORD|AUTH)[A-Z0-9_]*=[A-Za-z0-9._~+/=:-]{8,}(?![\w.(])"),
    # requests' basic auth with a literal password: `auth=("admin", "x")`, `HTTPBasicAuth("u", "x")`
    "basic-auth": re.compile(rf"(?:\bauth\s*=\s*\(|\bHTTP(?:Basic|Digest)Auth\()\s*{_Q}[^\"'\n]*{_Q}\s*,\s*"
                             rf"{_Q}{_LIT}{{4,}}{_Q}"),
    "url-credentials": re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^\s/:@]+:[^\s/@]+@"),
    "private-key": re.compile(r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----"),
    "aws-key": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "github-token": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})\b"),
    "slack-token": re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    "api-key": re.compile(r"\b(?:sk-(?:ant-)?[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{30,})\b"),
}
IPV4_RX = re.compile(r"(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d.])")
UUID_RX = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)
LONGHEX_RX = re.compile(r"\b[0-9a-f]{32,}\b", re.I)
URL_RX = re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s)<>\]\"'`]+", re.I)
# A bare hostname (two or more labels, the last starting with a letter). It is checked against the
# event's infrastructure hosts only, so `solve.py` or `docs.python.org` is never a finding.
HOST_RX = re.compile(r"(?<![\w-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}(?![\w-])", re.I)
SHA256_RX = re.compile(r"[0-9a-f]{64}")
_HASH_SPLIT = re.compile(r"[\"'`()\[\]<>,;=:]+")
_HASH_EDGE = ".,:;!?\"'`()[]<>"

ALLOWABLE = frozenset({"flag-shaped", "uuid", "longhex", "external-url"})


@dataclass(frozen=True)
class Finding:
    kind: str
    line: int
    preview: str
    blocking: bool
    path: str = ""

    def __str__(self) -> str:
        where = f"{self.path}:" if self.path else ""
        return f"{'BLOCK' if self.blocking else 'NOTE '} {self.kind} {where}L{self.line}: {self.preview}"

    def to_dict(self) -> dict:
        return {"kind": self.kind, "path": self.path, "line": self.line, "preview": self.preview,
                "blocking": self.blocking}


def split_flag(tok: str) -> tuple[str, str] | None:
    """(prefix, body) of a PREFIX{body} token, else None. String operations only: every flag pattern
    comes from ctf.flagfmt."""
    i = tok.find("{")
    if i < 1 or not tok.endswith("}") or not _PREFIX_WORD.fullmatch(tok[:i]):
        return None
    return tok[:i], tok[i + 1:-1]


def mask(hit: str) -> str:
    """A preview that never carries the value: a flag keeps its prefix, anything else 4 chars."""
    parts = split_flag(hit)
    if parts:
        return f"{parts[0]}{{…{len(parts[1])} chars}}"
    if len(hit) <= 4:
        return "…" + f"({len(hit)} chars)"
    return f"{hit[:4]}…({len(hit)} chars)"


_TOKENISH_LONG = 20        # a path segment this long is masked whatever it holds
_TOKENISH_MIXED = 10       # ... and one this long that mixes letters and digits


def _mask_segment(seg: str) -> str:
    """A URL path segment, or `…(N)` when it looks like a token (long, or long-ish with letters and
    digits mixed): a token in the path (`/api/<token>/x`) must not reach a preview."""
    if len(seg) >= _TOKENISH_LONG or (len(seg) >= _TOKENISH_MIXED and re.search(r"\d", seg)
                                       and re.search(r"[A-Za-z]", seg)):
        return f"…({len(seg)})"
    return seg


def url_preview(url: str) -> str:
    """An external URL without the parts that can carry a token: credentials, query and fragment are
    masked, a path segment that looks like a token is masked, and a long path is cut."""
    try:
        u = urlsplit(url)
        host = u.hostname or ""
        port = f":{u.port}" if u.port else ""
    except ValueError:
        return mask(url)
    path = "/".join(_mask_segment(s) for s in u.path.split("/"))
    path = path if len(path) <= 48 else path[:48] + "…"
    return (f"{u.scheme}://{'…@' if '@' in u.netloc else ''}{host}{port}{path}"
            f"{'?…' if u.query else ''}{'#…' if u.fragment else ''}")


def strip_private(text: str) -> tuple[str, bool]:
    """(text without private blocks, unclosed). An unclosed opener drops everything after it."""
    out = PRIVATE_RX.sub("", text)
    m = PRIVATE_OPEN_RX.search(out)
    if m:
        return out[:m.start()], True
    return out, False


def _is_placeholder(token: str) -> bool:
    body = token[token.index("{") + 1:-1]
    return _PLACEHOLDER.fullmatch(body) is not None


def flag_sections(text: str) -> list[tuple[int, int]]:
    """(start, end) character spans of the bodies of headings named Flag/Flags."""
    heads = list(HEADING_RX.finditer(text))
    spans = []
    for i, h in enumerate(heads):
        if not FLAG_HEADING_RX.match(h.group(2)):
            continue
        level = len(h.group(1))
        end = len(text)
        for nxt in heads[i + 1:]:
            if len(nxt.group(1)) <= level:
                end = nxt.start()
                break
        spans.append((h.end(), end))
    return spans


class Scanner:
    def __init__(self, profile: _event.EventProfile, known: Iterable[str] = (), allow: Iterable[str] = (),
                 known_hashes: Iterable[str] = ()):
        self.profile = profile
        self.policy = _policy.for_profile(profile)
        # The event's prefixes in any case with a broad body: redaction and the scan must over-match,
        # never under-match. Both patterns are built by ctf.flagfmt (the single flag-pattern source).
        self.event_rx = _flagfmt.FlagFormat(_event.FlagSpec(
            prefixes=tuple(profile.flag.prefixes), body=_BROAD_BODY, case="insensitive")).regex
        self.shape_rx = _flagfmt.FlagFormat(_event.FlagSpec(prefixes=(), body=_SHAPE_BODY, case="exact")).regex
        tokens, rules = set(), []
        for a in allow:
            a = (a or "").strip()
            if not a:
                continue
            if a.startswith("@"):
                kind, _, glob = a[1:].partition(" ")
                if kind not in ALLOWABLE or not glob.strip():
                    raise common.WriteupError(f"allow rule {a!r}: write '@<kind> <path glob>' with kind one of "
                                     f"{', '.join(sorted(ALLOWABLE))}")
                rules.append((kind, glob.strip()))
            else:
                tokens.add(a)
        self.allow = frozenset(tokens)
        self.allow_rules = tuple(rules)
        self.known: set[str] = set()
        self.short_known: set[str] = set()
        hashes = set()
        for h in known_hashes:
            h = str(h or "").strip().lower()
            if not SHA256_RX.fullmatch(h):
                raise common.WriteupError(f"known flag hash {h[:12]!r}... is not a sha256 hex digest")
            hashes.add(h)
        self.known_hashes = frozenset(hashes)
        self.add_known(known)

    # ------------------------------------------------------------------------------------- known values
    def add_known(self, values: Iterable[str]) -> None:
        for v in values:
            v = (v or "").strip()
            if not v or self._placeholder_value(v):
                continue
            if len(v) >= KNOWN_MIN or self.shape_rx.fullmatch(v) or self.event_rx.fullmatch(v):
                self.known.add(v)
            else:
                self.short_known.add(v)

    def _placeholder_value(self, v: str) -> bool:
        return bool(self.shape_rx.fullmatch(v) or self.event_rx.fullmatch(v)) and _is_placeholder(v)

    def resolve_hashes(self, text: str) -> list[str]:
        """Tokens of `text` whose sha256 is a recorded flag hash; each becomes a known value. A token is
        a whitespace-separated chunk, that chunk without edge punctuation, and each piece of it split
        at quotes, brackets, `=`, `:`, `,` and `;` (so `flag="x"` and `{"flag": "x"}` resolve x). A
        value with whitespace in it is not resolved this way (the event format still catches it)."""
        if not self.known_hashes:
            return []
        found = set()
        for m in re.finditer(r"\S+", text):
            chunk = m.group(0)
            cands = {chunk, chunk.strip(_HASH_EDGE)}
            cands.update(piece.strip(_HASH_EDGE) for piece in _HASH_SPLIT.split(chunk))
            for c in cands:
                if c and hashlib.sha256(c.encode("utf-8")).hexdigest() in self.known_hashes:
                    found.add(c)
        self.add_known(found)
        return sorted(found)

    def fragments(self) -> list[str]:
        out = set()
        for v in self.known:
            parts = split_flag(v)
            if parts and len(parts[1].strip()) >= FRAGMENT_MIN:
                out.add(parts[1].strip())
        return sorted(out, key=len, reverse=True)

    def harvest_flag_sections(self, text: str) -> list[str]:
        """Values written in Flag sections: flag-shaped tokens, and backtick spans that are one bare
        token (no whitespace, no '/' or '.', so `flag.txt` or a path is not taken for a value)."""
        vals = []
        for a, b in flag_sections(text):
            body = text[a:b]
            vals += [m.group(1) for m in BACKTICK_RX.finditer(body) if _BARE_TOKEN.fullmatch(m.group(1))
                     or self.shape_rx.fullmatch(m.group(1))]
            vals += [m.group(0) for m in self.shape_rx.finditer(body)]
            vals += [m.group(0) for m in self.event_rx.finditer(body)]
        return [v for v in vals if v.strip()]

    # ---------------------------------------------------------------------------------------- redact
    def _flag_note(self) -> str:
        if self.policy.sharing_forbidden:
            return "Flag redacted: this event's rules forbid sharing flags.\n\n"
        return "Flag redacted.\n\n"

    def redact(self, text: str) -> tuple[str, int]:
        """Redact flags and known values. Returns (text, number of replacements)."""
        self.add_known(self.harvest_flag_sections(text))
        self.resolve_hashes(text)
        n = 0
        # 1. Flag sections: the whole body goes.
        for a, b in reversed(flag_sections(text)):
            text = text[:a] + "\n\n" + self._flag_note() + text[b:]
            n += 1
        # 2. Known values, longest first, any case.
        for v in sorted(self.known, key=len, reverse=True):
            parts = split_flag(v)
            rep = f"{parts[0]}{{{REDACTED}}}" if parts else REDACTED
            text, k = re.subn(re.escape(v), lambda _m, r=rep: r, text, flags=re.I)
            n += k
        # 3. Anything in the event format.
        hits = [0]

        def ev(m: re.Match) -> str:
            tok = m.group(0)
            if _is_placeholder(tok):
                return tok
            hits[0] += 1
            return tok[:tok.index("{")] + "{" + REDACTED + "}"
        text = self.event_rx.sub(ev, text)
        n += hits[0]
        # 4. Bare fragments of known flags.
        for frag in self.fragments():
            text, k = re.subn(re.escape(frag), REDACTED, text, flags=re.I)
            n += k
        return text, n

    # ------------------------------------------------------------------------------------------- scan
    def scan(self, text: str, path: str = "") -> list[Finding]:
        red = self.policy.redact
        out: list[Finding] = []
        self.resolve_hashes(text)

        def add(kind, i, hit, blocking, preview=None):
            if kind in ALLOWABLE and (hit in self.allow or any(
                    k == kind and fnmatch.fnmatchcase(path, g) for k, g in self.allow_rules)):
                return
            out.append(Finding(kind, i, preview if preview is not None else mask(hit), blocking, path))

        if PRIVATE_OPEN_RX.search(text):
            line = text[:PRIVATE_OPEN_RX.search(text).start()].count("\n") + 1
            add("unclosed-private", line, "<!-- private -->", True, "<!-- private --> left in the file")
        known_lower = [(v, v.lower()) for v in self.known]
        frags = [f.lower() for f in self.fragments()]
        for i, line in enumerate(text.splitlines(), 1):
            low = line.lower()
            ev_hits = [m.group(0) for m in self.event_rx.finditer(line) if not _is_placeholder(m.group(0))]
            for hit in ev_hits:
                add("flag", i, hit, red)
            for m in self.shape_rx.finditer(line):
                tok = m.group(0)
                if _is_placeholder(tok) or tok in ev_hits or self.event_rx.fullmatch(tok):
                    continue
                add("flag-shaped", i, tok, red)
            rest = low
            for v, vl in known_lower:
                if vl in low:
                    add("known-value", i, v, red)
                    rest = rest.replace(vl, " ")
            for hit in ev_hits:
                rest = rest.replace(hit.lower(), " ")
            for fl in frags:                  # a body outside its wrapper (the full value is reported above)
                if fl in rest:
                    add("flag-fragment", i, fl, red)
            for kind, rx in SECRET_RX.items():
                for m in rx.finditer(line):
                    add("secret", i, m.group(0), True, f"{kind}: {mask(m.group(0))}")
            url_spans = []
            for m in URL_RX.finditer(line):
                url = m.group(0)
                url_spans.append(m.span())
                try:
                    host = urlsplit(url).hostname or ""
                except ValueError:
                    host = ""
                if host and self.policy.is_infra_host(host):
                    add("instance-url", i, url, True, f"host {host}")
                elif not IPV4_RX.fullmatch(host or "") and host not in ("localhost",):
                    add("external-url", i, url, False, url_preview(url))
            for m in HOST_RX.finditer(line):
                if any(a <= m.start() < b for a, b in url_spans):
                    continue                      # inside a URL: reported above
                if self.policy.is_infra_host(m.group(0)):
                    add("instance-host", i, m.group(0), True, f"host {m.group(0).lower()}")
            for m in IPV4_RX.finditer(line):
                ip = m.group(0)
                if ip.startswith("127.") or ip == "0.0.0.0":
                    continue
                add("ipv4", i, ip, True, "an IPv4 address")
            for m in UUID_RX.finditer(line):
                add("uuid", i, m.group(0), True)
            for m in LONGHEX_RX.finditer(line):
                add("longhex", i, m.group(0), True)
            if TODO_RX.search(line):
                add("unfinished", i, "<!-- TODO", True, "<!-- TODO --> left in the file")
            if CHECK_RX.search(line):
                add("open-check", i, "<!-- CHECK", True, "<!-- CHECK: --> left in the file")
        return out
