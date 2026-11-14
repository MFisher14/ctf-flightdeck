"""Brief-URL fetch + labeled-field extractor (B-088): read a named field off the site a brief names.

    from ctf import brieffield
    q = brieffield.field_question(description)       # Field(phrase, tokens, key, head) or None
    brieffield.brief_urls(description)               # http(s) URLs in the brief, in order, deduplicated
    text = brieffield.html_to_text(body)             # visible text, one block per line, title + meta
    brieffield.label_values(text, q)                 # [Hit(value, label, score, where)] for that field
    r = brieffield.try_brief_url(detail, profile=None, fetch=None, online=True)   # fastlane result

The shape it closes: a brief names a site ("the fund is at https://...") and asks for one field on it
("Find the company registration number shown on the site"). The page shows it as a
label and a value ("Reg. No. AB-1234-5678", next to a distinct "Licence XY-0000"). One GET of
the page, then a match of the page's label/value pairs against the noun the task names, gives the
value without a model turn.

Rules it keeps:

* Scope first. Every URL passes `ctf.scope.check_url` (the profile's `rules.live_service_scope`, or a
  player-pointed service: `python -m ctf policy point <id> <host[:port]>`) before any request, an
  injected fetch included. An out-of-scope URL is not fetched; the result names it and the reason.
  The event platform is never fetched here (scope refuses it).
* One bounded GET per URL: at most `MAX_URLS` in-scope URLs, each fetched once, `MAX_FETCH_BYTES`
  read, `FETCH_TIMEOUT_S` timeout, no retry, no proxy, at most `MAX_REDIRECTS` redirects and each
  redirect target scope-checked before it is followed (http/https only).
* A candidate, never a flag: the result has `flag=None`, a `candidate` and an `instruction` (verify
  the value as displayed; the brief's wrapper, when it states one, is shown as `wrapped`). Several
  distinct values for the field give no single candidate unless one label matches the noun strictly
  better; every value is listed in `candidates`, and the first `MAX_LISTED` of them in `how` and
  `instruction` (with a count of the rest), so a page of many matching labels makes no huge note.
* The page is untrusted data: parsed as text, never executed, and nothing in it is followed.
"""
from __future__ import annotations

import html
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Callable, Optional

from . import scope as _scope

KLASS = "osint:brief-url"
MAX_FETCH_BYTES = 512 * 1024      # same cap as ctf.fastlane: never pull an unbounded page
FETCH_TIMEOUT_S = 10.0
MAX_URLS = 3                      # in-scope brief URLs fetched (each once) before giving up
MAX_REDIRECTS = 2
USER_AGENT = "ctf-tools-brieffield/1"
MAX_VALUE_CHARS = 96
MAX_LISTED = 10                   # values named in how/instruction (all of them stay in `candidates`)


class BriefFetchError(RuntimeError):
    """The one GET of a brief URL failed; the message names why."""


# ------------------------------------------------------------------------------------------------
# vocabulary: canonical label tokens
# ------------------------------------------------------------------------------------------------
# A label word is lower-cased, its trailing "." and possessive "'s" dropped, then mapped here, so
# "Reg. No.", "Registration Number" and "registered no" all read (registration, number).
ALIASES = {
    "reg": "registration", "regd": "registration", "registered": "registration", "registry": "registration",
    "regn": "registration", "regist": "registration",
    "no": "number", "nr": "number", "num": "number", "nbr": "number", "#": "number", "№": "number",
    "nº": "number", "n°": "number", "numbers": "number",
    "license": "licence", "lic": "licence", "licensed": "licence", "licenced": "licence",
    "tel": "phone", "telephone": "phone", "ph": "phone", "mobile": "phone",
    "e-mail": "email", "mail": "email",
    "addr": "address",
    "ref": "reference",
    "acct": "account", "acc": "account",
    "identifier": "id", "ident": "id",
    "co": "company", "corp": "company", "corporate": "company", "firm": "company",
    "s/n": "serial", "sn": "serial",
    "dob": "date",
    "user": "username", "login": "username",
}
# Field heads: the noun a task asks for ends in one of these. A label carrying a DIFFERENT head is a
# different field ("Registration date" is not the registration number).
HEADS = frozenset({"number", "id", "code", "name", "address", "email", "phone", "date", "licence",
                   "reference", "serial", "iban", "username", "handle", "domain", "vat", "year"})
# Heads whose value is an identifier (digits, maybe letters and dashes): parsed token by token.
ID_HEADS = frozenset({"number", "id", "code", "reference", "serial", "licence", "iban", "vat"})
_FILLER = frozenset({"of", "the", "a", "an", "and"})
# Words that name a field: a label carrying one the task did not ask for is another field. "company"
# qualifies without naming one ("Company Registration Number" is still the registration number).
_GENERIC = frozenset({"company"})
_FIELD_WORDS = (HEADS | frozenset(ALIASES.values())) - _GENERIC
# A head that names no field on its own: "the number" needs a key word ("registration number").
_VAGUE = frozenset({"number", "id", "code", "name", "date", "year", "reference", "serial", "address"})
# Whole label phrases that mean another phrase (UK-style "Company No." is the registration number).
_PHRASES = (
    (re.compile(r"\bcompany\s+(?:no\.?|number|nr\.?)(?=\W|$)", re.I), "company registration number"),
    (re.compile(r"\bcrn\b", re.I), "registration number"),
    (re.compile(r"\bn°", re.I), "no"),
)


def canon(word: str) -> str:
    w = word.strip().lower().replace("’", "'")
    w = w.rstrip(".:")
    if w.endswith("'s"):
        w = w[:-2]
    return ALIASES.get(w, w)


@dataclass(frozen=True)
class Field:
    """The field a brief asks for: `phrase` as written, canonical `tokens`, the discriminating `key`
    word (the one right before the head) and the `head` (None when the noun has no head word)."""
    phrase: str
    tokens: tuple[str, ...]
    key: str
    head: Optional[str]
    mentions: int = 1

    @property
    def kind(self) -> str:
        """How a value is read: 'id' (identifier tokens), 'email', 'phone', or 'text'."""
        h = self.head or self.key
        if h in ID_HEADS:
            return "id"
        if h in ("email", "phone"):
            return h
        return "text"


@dataclass(frozen=True)
class Hit:
    value: str
    label: str
    score: float
    where: str
    url: Optional[str] = None

    def to_dict(self) -> dict:
        return {"value": self.value, "label": self.label, "score": self.score, "where": self.where,
                "url": self.url}


# ------------------------------------------------------------------------------------------------
# the brief: the field it asks for, and the URLs it names
# ------------------------------------------------------------------------------------------------
_HEAD_ALT = (r"number|nr|id|identifier|code|name|address|e-?mail|phone|telephone|date|licen[cs]e|"
             r"reference|serial|iban|username|handle|domain|vat|year")
_VERB = (r"find|what(?:'s|’s|\s+is|\s+was|\s+are)|identify|recover|report|give|submit|provide|read|locate|"
         r"retrieve|determine|enter|answer\s*(?:is|:)?")
_QUESTION_RE = re.compile(
    rf"\b(?:{_VERB})\s*:?\s+(?:me\s+|us\s+)?(?:the|its|their|his|her|this|that)\s+"
    rf"((?:(?!(?:and|or|of|the|in|on|at|by|for|from|to|with|as)\b)[a-z][a-z'’\-]*\s+){{0,4}}"
    rf"(?:{_HEAD_ALT}))(?![a-z])", re.I)
_TAG_RE = re.compile(r"<[^>]{0,400}>")
_MD_RE = re.compile(r"[*_`~]+")
_URL_RE = re.compile(r"https?://[^\s'\"<>()\[\]`*]+", re.I)
_WRAP_RE = re.compile(r"([A-Za-z][A-Za-z0-9_]{0,31})\{\s*<\s*answer\s*>\s*\}", re.I)


def _plain(text: str) -> str:
    """A brief with HTML tags, markdown emphasis and entities removed, for question matching."""
    t = html.unescape(_TAG_RE.sub(" ", text or ""))
    return _MD_RE.sub("", t)


def field_question(text: str) -> Optional[Field]:
    """The field the brief asks for, or None. Every "find / what is / submit / answer: the X <head>"
    phrase is read; phrases with the same (key, head) are one field, the longest phrase kept. The
    field asked most often wins (a tie: the first asked)."""
    groups: dict[tuple[str, Optional[str]], list] = {}
    for m in _QUESTION_RE.finditer(_plain(text)):
        phrase = " ".join(m.group(1).split())
        toks = tuple(t for t in (canon(w) for w in phrase.split()) if t and t not in _FILLER)
        if not toks:
            continue
        head = toks[-1] if toks[-1] in HEADS else None
        if head is not None and len(toks) >= 2:
            key = toks[-2]
        elif head in _VAGUE:
            continue                      # "the number", "the name": too vague to match a label by
        else:
            key, head = toks[-1], None    # "the licence", "the IBAN": the word is its own key
        g = groups.setdefault((key, head), [m.start(), 0, phrase, toks])
        g[1] += 1
        if len(toks) > len(g[3]):
            g[2], g[3] = phrase, toks
    if not groups:
        return None
    (key, head), (_, n, phrase, toks) = min(groups.items(), key=lambda kv: (-kv[1][1], kv[1][0]))
    return Field(phrase=phrase, tokens=toks, key=key, head=head, mentions=n)


def brief_urls(text: str) -> list[str]:
    """http(s) URLs named in the brief, in order, deduplicated, trailing punctuation dropped."""
    out: list[str] = []
    for m in _URL_RE.finditer(html.unescape(text or "")):
        u = m.group(0).rstrip(".,;:!?'\"")
        if u not in out:
            out.append(u)
    return out


def wrapped(text: str, value: str) -> Optional[str]:
    """`PREFIX{value}` when the brief states its answer wrapper as `PREFIX{<answer>}`, else None."""
    m = _WRAP_RE.search(html.unescape(text or ""))
    return f"{m.group(1)}{{{value}}}" if m else None


# ------------------------------------------------------------------------------------------------
# the page: HTML to text lines
# ------------------------------------------------------------------------------------------------
_BLOCK = frozenset({"p", "div", "br", "li", "ul", "ol", "tr", "td", "th", "dt", "dd", "dl", "table",
                    "h1", "h2", "h3", "h4", "h5", "h6", "header", "footer", "section", "article", "nav",
                    "aside", "main", "form", "label", "button", "blockquote", "pre", "hr", "title",
                    "figcaption", "address", "option", "summary", "details", "caption"})
_SKIP = frozenset({"script", "style", "noscript", "template", "svg"})
_META_NAMES = frozenset({"description", "og:description", "og:title", "twitter:description",
                         "twitter:title", "keywords"})


class _Text(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.lines: list[tuple[str, str]] = []      # (where, text)
        self.buf: list[str] = []
        self.skip = 0
        self.in_title = False

    def _flush(self, where: str = "body") -> None:
        t = " ".join("".join(self.buf).split())
        self.buf = []
        if t:
            self.lines.append((where, t))

    def handle_starttag(self, tag, attrs):
        if tag in _SKIP:
            self.skip += 1
            return
        if tag == "meta":
            a = {k.lower(): (v or "") for k, v in attrs}
            name = (a.get("name") or a.get("property") or "").lower()
            if name in _META_NAMES and a.get("content", "").strip():
                self.lines.append((f"meta {name}", " ".join(a["content"].split())))
            return
        if tag in _BLOCK:
            self._flush("title" if self.in_title else "body")
        if tag == "title":
            self.in_title = True

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        if tag in _SKIP:
            self.skip = max(0, self.skip - 1)
            return
        if tag == "title":
            self._flush("title")
            self.in_title = False
        elif tag in _BLOCK:
            self._flush()

    def handle_data(self, data):
        if not self.skip:
            self.buf.append(data)

    def close(self):
        super().close()
        self._flush("title" if self.in_title else "body")


def page_lines(body: str) -> list[tuple[str, str]]:
    """(where, text) per visible block of an HTML page: the title, meta descriptions, then body blocks.
    A body that is not HTML is split on its own lines."""
    if not re.search(r"<\s*(html|body|div|p|title|meta|span|table|h\d|br)\b", body or "", re.I):
        return [("body", " ".join(ln.split())) for ln in (body or "").splitlines() if ln.strip()]
    p = _Text()
    try:
        p.feed(body)
        p.close()
    except Exception:                 # malformed markup: keep what parsed
        p._flush()
    return p.lines


def html_to_text(body: str) -> str:
    return "\n".join(t for _, t in page_lines(body))


# ------------------------------------------------------------------------------------------------
# label / value matching
# ------------------------------------------------------------------------------------------------
_SEG_SPLIT = re.compile(r"\s*(?:\||·|•|¦|•|;)\s*")
_WORD = re.compile(r"№|#|[^\W\d_][\w'’/\-]*\.?", re.U)
_SEP = re.compile(r"[\s:=#\-–—>]*(?:is\s+|are\s+)?[\s:=]*")
_ID_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9\-/._]*")
_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}")
_PHONE = re.compile(r"\+?\d[\d\s().\-]{5,}\d")
_TEXT_STOP = re.compile(r"\s{3,}|\s[-–—]\s|[|·•;]")


def _label_score(field: Field, label: tuple[str, ...]) -> Optional[float]:
    """How well a page label matches the field, or None when it is another field."""
    L = {t for t in label if t not in _FILLER}
    if field.key not in L:
        return None
    allowed = {field.key} | ({field.head} if field.head else set(ID_HEADS))
    N = set(field.tokens)
    if (L - N - allowed - _GENERIC) & _FIELD_WORDS:
        return None                   # "Registration date" / "Licensed Reg. No." is another field
    return len(L & N) - 0.5 * len(L - N)


def _id_value(rest: str) -> Optional[str]:
    """An identifier at the start of `rest`: up to 4 tokens joined by single spaces ("HRB 12345"),
    each holding a digit or short all-caps; it must hold a digit. Stops at punctuation that ends a
    token (",", ")") or a wider gap."""
    toks: list[str] = []
    for m in re.finditer(r"(\S+)(\s*)", rest):
        raw, gap = m.group(1), m.group(2)
        tok = raw.rstrip(".,;:)]}")
        tok = tok.rstrip("._/-")
        if not tok or not _ID_TOKEN.fullmatch(tok) or canon(tok) in HEADS or canon(tok) in ALIASES:
            break                     # "VAT", "No." and the like start the next label
        if not (any(c.isdigit() for c in tok) or (tok.isupper() and len(tok) <= 6)):
            break
        toks.append(tok)
        if len(toks) >= 4 or raw != tok or gap != " ":
            break
    while toks and not any(c.isdigit() for c in toks[-1]):
        toks.pop()                    # a trailing all-caps word is the next label, not the value
    value = " ".join(toks)
    return value if any(c.isdigit() for c in value) else None


def _value(field: Field, rest: str) -> Optional[str]:
    rest = rest.strip()
    if not rest:
        return None
    if field.kind == "id":
        return _id_value(rest)
    if field.kind == "email":
        m = _EMAIL.match(rest)
        return m.group(0) if m else None
    if field.kind == "phone":
        m = _PHONE.match(rest)
        return m.group(0).strip() if m else None
    v = _TEXT_STOP.split(rest, 1)[0].strip().rstrip(".,")
    if not v or len(v) > MAX_VALUE_CHARS or len(v.split()) > 8:
        return None
    if field.head in ("date", "year") and not any(c.isdigit() for c in v):
        return None
    return v


def _rephrase(seg: str) -> str:
    for rx, rep in _PHRASES:
        seg = rx.sub(rep, seg)
    return seg


def label_values(lines, field: Field, *, url: Optional[str] = None) -> list[Hit]:
    """Every (value, label) on the page whose label matches `field`. `lines` is page_lines() output or
    plain text. A label with nothing after it on its line takes the next line as its value (a table
    cell or a <dt>/<dd> pair)."""
    if isinstance(lines, str):
        lines = [("body", ln) for ln in lines.splitlines()]
    vocab = set(field.tokens) | HEADS | set(ALIASES.values()) | _FILLER
    hits: list[Hit] = []
    flat = [(where, seg) for where, text in lines for seg in _SEG_SPLIT.split(_rephrase(text)) if seg.strip()]
    for idx, (where, seg) in enumerate(flat):
        words = list(_WORD.finditer(seg))
        i = 0
        while i < len(words):
            if canon(words[i].group(0)) not in vocab or canon(words[i].group(0)) in _FILLER:
                i += 1
                continue
            j = i + 1
            while (j < len(words) and j - i < 6 and canon(words[j].group(0)) in vocab
                   and not seg[words[j - 1].end():words[j].start()].strip()):
                j += 1
            # The best label inside the run of label words: "Licensed. Reg. No." holds "Reg. No.".
            # It must end the run (the value follows it); the longest best-scoring start wins.
            score, k = None, i
            for start in range(i, j):
                s = _label_score(field, tuple(canon(w.group(0)) for w in words[start:j]))
                if s is not None and (score is None or s > score):
                    score, k = s, start
            if score is not None:
                rest = seg[words[j - 1].end():]
                sep = _SEP.match(rest)
                rest = rest[sep.end():] if sep else rest
                value = _value(field, rest)
                if value is None and not rest.strip() and idx + 1 < len(flat):
                    value = _value(field, flat[idx + 1][1])
                if value is not None:
                    text_label = seg[words[k].start():words[j - 1].end()]
                    hits.append(Hit(value=value, label=text_label, score=score, where=where, url=url))
            i = j
    return hits


def rank(hits: list[Hit]) -> tuple[Optional[Hit], list[dict]]:
    """(the candidate or None, every distinct value with its best label and all places seen). One
    distinct value is the candidate; among several, the one whose best label scores strictly
    highest, else none."""
    by: dict[str, dict] = {}
    for h in hits:
        d = by.setdefault(h.value, {"value": h.value, "label": h.label, "score": h.score, "seen": [],
                                    "url": h.url})
        d["seen"].append(h.where)
        if h.score > d["score"]:
            d["label"], d["score"] = h.label, h.score
    vals = sorted(by.values(), key=lambda d: (-d["score"], -len(d["seen"])))
    if not vals:
        return None, []
    best = vals[0]
    if len(vals) > 1 and vals[1]["score"] >= best["score"]:
        return None, vals
    return Hit(best["value"], best["label"], best["score"], ", ".join(best["seen"]), best["url"]), vals


# ------------------------------------------------------------------------------------------------
# the one GET
# ------------------------------------------------------------------------------------------------
class _ScopedRedirect(urllib.request.HTTPRedirectHandler):
    max_redirections = MAX_REDIRECTS

    def __init__(self, profile):
        super().__init__()
        self.profile = profile
        self.hops: list[str] = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        scheme = urllib.parse.urlsplit(newurl).scheme.lower()
        if scheme not in ("http", "https"):
            raise BriefFetchError(f"redirect to a non-http URL refused: {newurl}")
        if len(self.hops) >= MAX_REDIRECTS:
            raise BriefFetchError(f"more than {MAX_REDIRECTS} redirects (last {newurl})")
        _scope.check_url(newurl, what=f"redirect target {newurl!r}", profile=self.profile)
        self.hops.append(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def scoped_get(url: str, *, profile=None, timeout: float = FETCH_TIMEOUT_S,
               max_bytes: int = MAX_FETCH_BYTES) -> str:
    """One GET of an in-scope URL: the body text (cut at `max_bytes`). Raises scope.OutOfScope before
    any connection when the URL (or a redirect target) is out of scope, BriefFetchError on any other
    failure (named). No proxy, no retry, no cookies."""
    if urllib.parse.urlsplit(url).scheme.lower() not in ("http", "https"):
        raise BriefFetchError(f"{url!r} is not an http(s) URL")
    _scope.check_url(url, what=f"brief URL {url!r}", profile=profile)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _ScopedRedirect(profile))
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "text/html,*/*;q=0.5"})
    try:
        with opener.open(req, timeout=timeout) as r:  # noqa: S310 (scope-checked challenge URL)
            raw = r.read(max_bytes)
            charset = r.headers.get_content_charset() or "utf-8"
    except _scope.OutOfScope:
        raise
    except BriefFetchError:
        raise
    except urllib.error.HTTPError as e:
        raise BriefFetchError(f"GET {url} answered HTTP {e.code}") from None
    except urllib.error.URLError as e:
        reason = e.reason
        if isinstance(reason, (_scope.OutOfScope, BriefFetchError)):
            raise reason from None
        raise BriefFetchError(f"GET {url} failed: {reason}") from None
    except (OSError, ValueError) as e:
        raise BriefFetchError(f"GET {url} failed: {type(e).__name__}: {e}") from None
    try:
        return raw.decode(charset, "replace")
    except LookupError:
        return raw.decode("utf-8", "replace")


# ------------------------------------------------------------------------------------------------
# the fastlane branch
# ------------------------------------------------------------------------------------------------
def _result(*, candidate=None, how="", confidence="low", source=None, instruction=None, **extra) -> dict:
    out = {"klass": KLASS, "flag": None, "candidate": candidate, "how": how, "confidence": confidence,
           "source": source, "instruction": instruction}
    out.update(extra)
    return out


def _listing(values: list[dict], sep: str) -> str:
    """The first MAX_LISTED values with their labels, then how many more there are. The page is
    untrusted: hundreds of matching labels must not make a note line of hundreds of values."""
    out = sep.join(f"{v['value']} ({v['label']!r})" for v in values[:MAX_LISTED])
    more = len(values) - MAX_LISTED
    return out + (f"{sep}and {more} more (all in candidates)" if more > 0 else "")


def try_brief_url(detail: dict, *, profile=None, fetch: Optional[Callable[[str], Optional[str]]] = None,
                  online: bool = True) -> Optional[dict]:
    """The brief-URL branch: None unless the brief both names an http(s) URL and asks for a named
    field. Otherwise a fastlane-shaped result (flag always None) with `field`, `candidates` (every
    distinct value seen), `fetched` and `refused` ([{url, reason}]) and `wrapped`.

    `fetch(url) -> body | None` is injectable (tests); the scope check runs before it either way."""
    desc = detail.get("description") or ""
    field = field_question(desc)
    urls = brief_urls(desc)
    if field is None or not urls:
        return None
    base = {"field": field.phrase, "candidates": [], "fetched": [], "refused": [], "wrapped": None}
    look = f"read the '{field.phrase}' label on the page and submit the value exactly as displayed"
    if not online:
        return _result(how=f"brief names {urls[0]} and asks for the {field.phrase} (offline: not fetched)",
                       source=urls[0], instruction=f"open {urls[0]}; {look}", **base)
    get = fetch if fetch is not None else (lambda u: scoped_get(u, profile=profile))
    in_scope = 0
    errors: list[str] = []
    for url in urls:
        try:
            _scope.check_url(url, what=f"brief URL {url!r}", profile=profile)
        except _scope.OutOfScope as e:
            base["refused"].append({"url": url, "reason": str(e)})
            continue
        if in_scope >= MAX_URLS:
            break
        in_scope += 1
        try:
            body = get(url)
        except _scope.OutOfScope as e:
            base["refused"].append({"url": url, "reason": str(e)})
            continue
        except BriefFetchError as e:
            errors.append(str(e))
            continue
        base["fetched"].append(url)
        if not body:
            errors.append(f"GET {url} returned no body")
            continue
        best, values = rank(label_values(page_lines(body), field, url=url))
        if not values:
            errors.append(f"no '{field.phrase}' label with a value on {url}")
            continue
        base["candidates"] = values
        if best is None:
            listing = _listing(values, "; ")
            return _result(how=f"{len(values)} distinct values for the {field.phrase} on {url}: {listing}",
                           source=url, instruction=f"pick the one the brief means from: {listing}", **base)
        base["wrapped"] = wrapped(desc, best.value)
        how = (f"'{best.label}' on {url} reads {best.value} ({best.where})"
               + (f"; other values for related labels: "
                  + _listing(values[1:], ", ") if len(values) > 1 else ""))
        sub = f" (brief's wrapper: {base['wrapped']})" if base["wrapped"] else ""
        return _result(candidate=best.value, how=how,
                       confidence="medium" if len(values) == 1 and best.score >= 2 else "low",
                       source=url,
                       instruction=f"verify '{best.label}' = {best.value} on {url} is the {field.phrase} "
                                   f"the brief asks for, then submit it as displayed{sub}", **base)
    if base["refused"] and not base["fetched"] and not errors:
        r0 = base["refused"][0]
        return _result(how=f"brief URL {r0['url']} not fetched: out of scope",
                       source=r0["url"],
                       instruction=(f"{r0['reason']}. If the brief puts it in scope, add the host to "
                                    "rules.live_service_scope or point it (python -m ctf policy point "
                                    f"<id> <host>) and re-run; else open it by hand and {look}"), **base)
    why = "; ".join(errors) or "no in-scope brief URL"
    return _result(how=f"brief-URL lookup for the {field.phrase} found no value: {why}",
                   source=(base["fetched"] or urls)[0],
                   instruction=f"open {(base['fetched'] or urls)[0]} by hand; {look}", **base)
