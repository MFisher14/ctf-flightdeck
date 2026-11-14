"""Route a challenge to engines from their manifests' [[routes]] tables.

    from ctf.engines import router
    hits = router.route("crypto", "an RSA modulus with a small e", files_dir)   # [Hit], best first
    router.engine_paths("web", "jinja template injection")                      # repo-relative module paths

A route matches when every condition it states holds: the canonical category is one of `category`
(no category = any), the lower-cased description contains one of `keywords` (lower-case substrings,
so " hci" keeps its leading space; a keyword padded with a space on *both* ends such as " ais " is a
whole-word match on the trimmed token, boundary-safe at the start, end or punctuation edge of the
text), and a downloaded file matches one of `files` (`magic:<text>`
prefix of the first bytes, `magic:0x<hex>` for binary magic; `ext:.x` suffix; `name:<glob>`). An
engine's score is its best matching route's priority (default 50); ties sort by id. Retired engines
are never routed.

ctf/triage.py ranks the same way from the generated route table (routetable.py), so `rank()` is the
one matching loop for both.
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from .. import paths
from . import manifest as _manifest

_HEAD_BYTES = 4096


@dataclass(frozen=True)
class Hit:
    manifest: _manifest.Manifest
    priority: int
    reason: str


def canonical_category(cat: str) -> str:
    from .. import triage  # lazy: triage imports this module
    return triage.canonical_category(cat)


def _file_heads(files_dir: Path | None) -> list[tuple[Path, bytes]]:
    if not files_dir or not Path(files_dir).is_dir():
        return []
    out = []
    for f in sorted(Path(files_dir).rglob("*")):
        if f.is_file():
            with open(f, "rb") as fh:
                out.append((f, fh.read(_HEAD_BYTES)))
    return out


_HEX_RE = re.compile(r"^0x(?:[0-9a-fA-F]{2})+$")


def magic_bytes(val: str) -> bytes:
    """The bytes a `magic:` matcher names: `0x<hex>` (what the generator writes for non-printable
    magic, e.g. `magic:0x89504e47`) is hex; anything else is the text itself (`magic:%PDF-`)."""
    if _HEX_RE.match(val):
        return bytes.fromhex(val[2:])
    return val.encode("latin-1")


def _file_match(matcher: str, heads: list[tuple[Path, bytes]]) -> str | None:
    kind, _, val = matcher.partition(":")
    magic = magic_bytes(val) if kind == "magic" else b""
    for f, head in heads:
        if kind == "magic" and head.startswith(magic):
            return f"{f.name} starts with {val!r}"
        if kind == "ext" and f.name.lower().endswith(val.lower()):
            return f"{f.name} has {val}"
        if kind == "name" and fnmatch.fnmatch(f.name, val):
            return f"{f.name} matches {val}"
    return None


@lru_cache(maxsize=512)
def _word_re(token: str) -> "re.Pattern[str]":
    return re.compile(r"\b" + re.escape(token) + r"\b")


def _keyword_hit(kw: str, text: str) -> bool:
    """True when manifest keyword `kw` matches lower-cased `text`.

    A keyword padded with a space on *both* ends (the whole-word convention, e.g. `" ais "`) matches
    the trimmed token on word boundaries, so it hits "AIS", "the AIS feed" and "the AIS." alike while
    still rejecting "mayonnaise", "aisle" and "praise" -- the leading/trailing space was only ever a
    stand-in for a boundary and failed at the start, end or punctuation edge of the text. Every other
    keyword (including the one-sided `" hci"`) keeps the plain lower-cased substring match."""
    token = kw.strip()
    if token and kw[:1] == " " and kw[-1:] == " ":
        return _word_re(token).search(text) is not None
    return kw in text


def route_matches(r: _manifest.Route, cat: str, text: str, heads) -> str | None:
    """Why `r` matches (a short reason), or None."""
    if r.matches_everything:
        return None                       # lint rejects these; never let one route everything
    why = []
    if r.category:
        if cat not in r.category:
            return None
        why.append(f"category {cat}")
    if r.keywords:
        kw = next((k for k in r.keywords if _keyword_hit(k, text)), None)
        if kw is None:
            return None
        why.append(f"keyword {kw.strip()!r}")
    if r.files:
        fw = next((w for w in (_file_match(m, heads) for m in r.files) if w), None)
        if fw is None:
            return None
        why.append(fw)
    return ", ".join(why)


def rank(entries, category: str, description: str = "", files_dir: Path | None = None, *,
         heads: list[tuple[Path, bytes]] | None = None) -> list[tuple]:
    """[(key, priority, reason)] best first, for `entries` = [(key, routes)] where key sorts ties.

    An entry's score is its best matching route's priority. `heads` ([(file, first bytes)]) replaces
    the walk of files_dir, for a caller that chooses the files itself (intake leaves the sweep's own
    files out)."""
    entries = list(entries)
    cat = canonical_category(category)
    text = (description or "").lower()
    if heads is None:
        heads = _file_heads(files_dir) if any(r.files for _, rs in entries for r in rs) else []
    out = []
    for key, routes in entries:
        best = None
        for r in routes:
            why = route_matches(r, cat, text, heads)
            if why is not None and (best is None or r.effective_priority > best[0]):
                best = (r.effective_priority, why)
        if best:
            out.append((key, best[0], best[1]))
    out.sort(key=lambda t: (-t[1], t[0]))
    return out


def route(category: str, description: str = "", files_dir: Path | None = None, *,
          manifests: list[_manifest.Manifest] | None = None, root: Path | None = None) -> list[Hit]:
    ms = _manifest.discover(root) if manifests is None else manifests
    by_id = {m.id: m for m in ms if m.status != "retired"}
    ranked = rank(((m.id, m.routes) for m in by_id.values()), category, description, files_dir)
    return [Hit(by_id[i], p, why) for i, p, why in ranked]


def route_heads(manifests: list[_manifest.Manifest], category: str, description: str,
                heads: list[tuple[Path, bytes]]) -> list[Hit]:
    """route() over given (file, first bytes) pairs instead of a walk of a folder (rank's `heads`)."""
    by_id = {m.id: m for m in manifests if m.status != "retired"}
    ranked = rank(((m.id, m.routes) for m in by_id.values()), category or "", description, heads=list(heads))
    return [Hit(by_id[i], p, why) for i, p, why in ranked]


def engine_paths(category: str, description: str = "", files_dir: Path | None = None, *,
                 root: Path | None = None) -> list[str]:
    root = paths.repo_root() if root is None else Path(root)
    return [h.manifest.rel_module(root) for h in route(category, description, files_dir, root=root)]
