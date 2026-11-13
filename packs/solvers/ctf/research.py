"""Shared research cache (B-199): one look-up per question per event, shared by every agent.

Standards and protocol research was repeated per lane (each agent fetched the same RFC, the same
format spec), and the parallel fetches tripped a 429 burst. This is a local store, in the event
workdir, of answers agents already found, keyed by the normalized query or document URL, plus a short
claim so a second agent asking the same thing while the first is fetching waits instead of fetching
again.

Nothing here fetches anything. An agent looks up with `get`; on a miss it claims the key, does the
look-up with its own tools, and stores the answer with `put` (which releases the claim).

Keys. A URL (http/https, or a bare `www.` host) is normalized: scheme folded (http and https are the
same document), host lower-cased without `www.` and a default port, the fragment and tracking
parameters (utm_*, fbclid, gclid, ...) dropped, the remaining query sorted, a trailing slash dropped.
Anything else is a query: Unicode-normalized, case-folded, split into words (punctuation other than
`+ # . - _ /` inside a word is a separator), stop words dropped, word order kept, so "The RFC 4648
base32 alphabet" and "rfc 4648: base32 alphabet?" are one key while "convert hex to base64" and
"convert base64 to hex" (a different question) are not.

A URL carrying credentials (user:pass@) or a secret-looking query parameter (token, key, auth,
session, password, sig, ...) is refused (ResearchError): the cache is shared and must hold no secret.

Store: `<workdir>/research/<sha256(key)[:32]>.json` (schema 1), written atomically; a claim is
`<same>.claim`, written whole to a temp file and renamed into place so no reader sees half of one.
Every change to a claim file (claim, take-over, refresh, release, and `put` dropping it) happens under
an exclusive `fcntl.flock` on `<same>.lock`, so the read-decide-write is one step: exactly one agent
wins a fresh claim, and exactly one wins the take-over of a stale one (stale after CLAIM_TTL seconds).
The kernel drops the lock when its holder dies, so a lock never goes stale. Local filesystems only
(flock is not reliable over NFS); the workdir is local.

    from ctf import research
    c = research.Cache(research.default_root())
    c.get("rfc 4648 base32") -> Entry | None
    c.claim("rfc 4648 base32", agent="a1") -> Claim     # ClaimHeld when another agent holds it
    c.put("rfc 4648 base32", answer, sources=[url], agent="a1")
    c.lookup(q, agent=..., claim=True) -> Lookup(status="hit"|"claimed"|"held"|"miss", entry, claim)
"""
from __future__ import annotations

import contextlib
import datetime as _dt
import fcntl
import hashlib
import json
import os
import re
import tempfile
import time
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from . import paths

__all__ = ["SCHEMA", "DIR_NAME", "CLAIM_TTL", "MAX_ANSWER_BYTES", "ResearchError", "ClaimHeld", "Entry",
           "Claim", "Lookup", "normalize", "normalize_url", "normalize_query", "is_url", "key_digest",
           "Cache", "default_root"]

SCHEMA = 1
DIR_NAME = "research"
CLAIM_TTL = 15 * 60                 # a claim older than this is stale: its agent died or gave up
MAX_ANSWER_BYTES = 64 * 1024        # store a summary with its sources, not a whole page

_TRACKING = re.compile(r"^(utm_.*|fbclid|gclid|dclid|msclkid|mc_cid|mc_eid|_ga|ref_src|yclid)$", re.I)
# a query parameter is secret-looking when a part of its name (split on _ - .) is one of these, or the
# name contains token / secret / passw anywhere ("author" and "keyword" are not secrets)
_SECRET_PARTS = frozenset("key apikey pwd passwd password session sessionid sessid sid cookie sig signature "
                          "credential credentials jwt bearer auth authorization oauth otp".split())
_SECRET_ANYWHERE = re.compile(r"token|secret|passw", re.I)
_STOP = frozenset("a an and are as at be by for from how i in is it of on or the to what when where which "
                  "who why with does do can".split())
_WORD = re.compile(r"[0-9a-zÀ-￿][0-9a-zÀ-￿+#._/-]*")


class ResearchError(ValueError):
    """A key the cache refuses (empty, or carrying a secret), an oversized answer, or a store that
    cannot be read or written. The message names which."""


class ClaimHeld(RuntimeError):
    """Another agent holds a fresh claim on the key: wait for its answer instead of fetching again."""

    def __init__(self, claim: "Claim"):
        super().__init__(f"{claim.agent} is looking this up (claimed {claim.age():.0f} s ago)")
        self.claim = claim


# ---------------------------------------------------------------------------------------- keys

def _secret_param(name: str) -> bool:
    low = name.lower()
    return bool(_SECRET_ANYWHERE.search(low)) or any(p in _SECRET_PARTS for p in re.split(r"[_.\-]+", low))


def is_url(text: str) -> bool:
    t = text.strip().lower()
    return t.startswith(("http://", "https://", "www."))


def normalize_url(url: str) -> str:
    """The cache key of a document URL (see the module docstring). ResearchError on credentials or a
    secret-looking parameter, or a URL with no host."""
    raw = url.strip()
    if raw.lower().startswith("www."):
        raw = "https://" + raw
    parts = urlsplit(raw)
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
        raise ResearchError(f"not an http(s) URL with a host: {url!r}")
    if parts.username is not None or parts.password is not None:
        raise ResearchError("refused: the URL carries credentials (user:pass@host); the research cache "
                            "is shared, store the URL without them")
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    bad = sorted({k for k, _ in pairs if _secret_param(k)})
    if bad:
        raise ResearchError(f"refused: the URL has secret-looking query parameter(s) {', '.join(bad)}; "
                            f"the research cache is shared, store the URL without them")
    host = parts.hostname.lower()
    if host.startswith("www."):
        host = host[4:]
    port = parts.port
    if port and port not in (80, 443):
        host = f"{host}:{port}"
    path = re.sub(r"/{2,}", "/", parts.path or "/")
    if len(path) > 1:
        path = path.rstrip("/")
    query = urlencode(sorted((k, v) for k, v in pairs if not _TRACKING.match(k)))
    return "url:" + urlunsplit(("", host, path, query, "")).lstrip("/")


def normalize_query(query: str) -> str:
    """The cache key of a free-text query (see the module docstring). ResearchError when no word is
    left."""
    text = unicodedata.normalize("NFKC", query).casefold()
    words = []
    for w in _WORD.findall(text):
        w = w.strip("._/-")
        if w and w not in _STOP:
            words.append(w)
    if not words:
        raise ResearchError(f"empty research query: {query!r}")
    return "q:" + " ".join(words)              # order kept: "hex to base64" is not "base64 to hex"


def normalize(text: str) -> str:
    """The key for a query or a URL."""
    if not text or not text.strip():
        raise ResearchError("empty research key")
    return normalize_url(text) if is_url(text) else normalize_query(text)


def key_digest(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]


# ---------------------------------------------------------------------------------------- records

def _iso(t: float) -> str:
    return _dt.datetime.fromtimestamp(t, _dt.timezone.utc).replace(microsecond=0).isoformat()


@dataclass
class Entry:
    key: str
    asked: str               # the text the storing agent asked with (first spelling)
    answer: str
    sources: list = field(default_factory=list)
    agent: str = ""
    at: float = 0.0          # epoch seconds stored

    def to_dict(self) -> dict:
        return {"schema": SCHEMA, "key": self.key, "asked": self.asked, "answer": self.answer,
                "sources": list(self.sources), "agent": self.agent, "at": self.at, "at_iso": _iso(self.at)}


@dataclass
class Claim:
    key: str
    agent: str
    at: float
    now: float = 0.0

    def age(self) -> float:
        return max(0.0, (self.now or time.time()) - self.at)


@dataclass
class Lookup:
    status: str              # "hit" | "claimed" (you now hold the claim) | "held" (another agent) | "miss"
    key: str
    entry: Entry | None = None
    claim: Claim | None = None


# ---------------------------------------------------------------------------------------- the store

def default_root() -> Path:
    """`<workdir>/research` of the current event ($CTF_WORKDIR, else ~/ctf-work/<slug>; ctf.paths.workdir
    fails loudly when no event is selected)."""
    return paths.workdir() / DIR_NAME


class Cache:
    """The research store under `root` (created on first write). `clock` returns epoch seconds; tests
    inject one so claim expiry needs no sleeping."""

    def __init__(self, root: Path, *, clock=time.time):
        self.root = Path(root)
        self.clock = clock

    def _paths(self, key: str) -> tuple[Path, Path]:
        d = key_digest(key)
        return self.root / f"{d}.json", self.root / f"{d}.claim"

    @contextlib.contextmanager
    def _claim_lock(self, key: str):
        """Hold the exclusive per-key lock that serializes every change to the key's claim file."""
        self.root.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(self.root / f"{key_digest(key)}.lock"), os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)                       # closing the descriptor drops the flock

    # -- entries ----------------------------------------------------------------------------------

    def _load(self, p: Path, key: str) -> Entry | None:
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None
        except (OSError, ValueError) as e:
            raise ResearchError(f"research entry {p} is unreadable ({type(e).__name__}: {e}); "
                                f"remove it to re-research") from e
        if not isinstance(d, dict) or d.get("schema") != SCHEMA or d.get("key") != key:
            raise ResearchError(f"research entry {p} has another schema or key; remove it to re-research")
        return Entry(key=d["key"], asked=d.get("asked", ""), answer=d.get("answer", ""),
                     sources=list(d.get("sources", [])), agent=d.get("agent", ""), at=float(d.get("at", 0)))

    def get(self, text: str) -> Entry | None:
        key = normalize(text)
        return self._load(self._paths(key)[0], key)

    def put(self, text: str, answer: str, *, sources=(), agent: str, replace: bool = False) -> Entry:
        """Store an answer; releases this agent's claim on the key. ResearchError when an answer is
        already stored (unless `replace`), the answer is empty or over MAX_ANSWER_BYTES, or a source
        URL is refused (each is normalized like a key, so a credential never lands in the store)."""
        key = normalize(text)
        if not answer or not answer.strip():
            raise ResearchError("refused: an empty answer (store what you found, or release the claim)")
        size = len(answer.encode("utf-8"))
        if size > MAX_ANSWER_BYTES:
            raise ResearchError(f"refused: the answer is {size} bytes (over {MAX_ANSWER_BYTES}); store a "
                                f"summary and the source URLs, not the whole document")
        for s in sources:
            if is_url(s):
                normalize_url(s)       # raises on credentials / secret parameters
        entry_p, claim_p = self._paths(key)
        old = self._load(entry_p, key)
        if old is not None and not replace:
            raise ResearchError(f"already answered by {old.agent} at {_iso(old.at)}; read it with "
                                f"`ctf research get`, or pass --replace to overwrite it")
        e = Entry(key=key, asked=text.strip(), answer=answer, sources=list(sources), agent=agent,
                  at=self.clock())
        self.root.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=entry_p.name + ".", suffix=".tmp", dir=str(self.root))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(e.to_dict(), f, indent=1, sort_keys=True)
            os.replace(tmp, entry_p)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        with self._claim_lock(key):
            claim_p.unlink(missing_ok=True)
        return e

    def entries(self) -> list[Entry]:
        """Every stored answer, newest first. ResearchError on an unreadable entry (named)."""
        if not self.root.is_dir():
            return []
        out = []
        for p in sorted(self.root.glob("*.json")):
            try:
                key = json.loads(p.read_text(encoding="utf-8")).get("key", "")
            except (OSError, ValueError, AttributeError) as e:
                raise ResearchError(f"research entry {p} is unreadable ({type(e).__name__}); remove it") from e
            got = self._load(p, key)
            if got is not None:
                out.append(got)
        return sorted(out, key=lambda e: -e.at)

    # -- claims -----------------------------------------------------------------------------------

    def _read_claim(self, p: Path, key: str) -> Claim | None:
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
            return Claim(key=key, agent=str(d["agent"]), at=float(d["at"]), now=self.clock())
        except FileNotFoundError:
            return None
        except (OSError, ValueError, KeyError, TypeError):
            # a half-written or corrupt claim (the writer died mid-write): treat it as made now by an
            # unknown agent, so it expires after CLAIM_TTL like any other instead of blocking forever
            try:
                at = p.stat().st_mtime
            except FileNotFoundError:
                return None
            return Claim(key=key, agent="(unreadable claim)", at=at, now=self.clock())

    def holder(self, text: str) -> Claim | None:
        """The fresh claim on the key, or None (no claim, or a stale one)."""
        key = normalize(text)
        c = self._read_claim(self._paths(key)[1], key)
        return c if c is not None and c.age() < CLAIM_TTL else None

    def claim(self, text: str, *, agent: str) -> Claim:
        """Claim the key for `agent`. Re-claiming your own claim refreshes it. ClaimHeld when another
        agent holds a fresh claim. A stale claim is taken over, by exactly one agent: the read of the
        current claim and the write of the new one happen under the per-key lock."""
        key = normalize(text)
        _, claim_p = self._paths(key)
        with self._claim_lock(key):
            cur = self._read_claim(claim_p, key)
            if cur is not None and cur.agent != agent and cur.age() < CLAIM_TTL:
                raise ClaimHeld(cur)
            # none, ours (refresh) or stale (take over): write it whole, then rename it into place
            now = self.clock()
            body = json.dumps({"key": key, "agent": agent, "at": now}).encode()
            fd, tmp = tempfile.mkstemp(prefix=claim_p.name + ".", suffix=".tmp", dir=str(self.root))
            try:
                with os.fdopen(fd, "wb") as f:
                    f.write(body)
                os.replace(tmp, claim_p)
            except BaseException:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
                raise
            return Claim(key=key, agent=agent, at=now, now=now)

    def release(self, text: str, *, agent: str) -> bool:
        """Drop `agent`'s claim on the key; False when it holds none (another agent's claim is kept)."""
        key = normalize(text)
        _, claim_p = self._paths(key)
        if not claim_p.exists():
            return False
        with self._claim_lock(key):
            cur = self._read_claim(claim_p, key)
            if cur is None or cur.agent != agent:
                return False
            claim_p.unlink(missing_ok=True)
            return True

    # -- the one call agents make -----------------------------------------------------------------

    def lookup(self, text: str, *, agent: str, claim: bool = False) -> Lookup:
        """hit (an answer is stored), held (another agent is looking it up now), claimed (it was a miss
        and `claim` made you the one to look it up) or miss."""
        key = normalize(text)
        entry = self.get(text)
        if entry is not None:
            return Lookup("hit", key, entry=entry)
        held = self.holder(text)
        if held is not None and held.agent != agent:
            return Lookup("held", key, claim=held)
        if not claim:
            return Lookup("miss", key)
        try:
            return Lookup("claimed", key, claim=self.claim(text, agent=agent))
        except ClaimHeld as e:                     # lost a race to another agent
            return Lookup("held", key, claim=e.claim)
