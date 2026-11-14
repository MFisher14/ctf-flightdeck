"""File routes inferred from the input formats an engine's code tests for (R-10).

    python -m ctf engines generate --file-routes      append one to each unrouted engine that qualifies
    python -m ctf engines generate --file-routes --dry-run

An engine whose code compares a file's extension (`.suffix ==`, `.endswith(...)`) or its first bytes
(`.startswith(b"...")`) against a distinctive format makes its input obvious: a challenge that ships
such a file should suggest it. This module turns those comparisons (generate.analyze) into one
`[[routes]] files = [...]` table, with no category or keyword condition, so the route fires in any
category when a downloaded file matches.

Only distinctive matchers count. Dropped: generic text and data extensions (.txt .json .xml .yaml
.csv .log .py .js .html .bin ...), generic containers (.zip .gz .tar .xz .7z, RIFF, FORM and their
magic), keys, certificates and .env files (.pem .key .env .p12 ...), byte order marks and text openers
(`<?xml`, `<html`, `#!`, `rem `), and magic shorter than three
bytes (`MZ`, `PK`, `\\xff\\xd8`), which too many unrelated files share. An engine with no
distinctive matcher, or with more than MAX_MATCHERS (a multi-format dispatcher, better routed by
keyword by hand), gets none.

Priorities sit below the carried category lists (BASE_PRIORITY and down): a file match adds the
engine to the list without pushing the engines the category and description chose. Engines that
claim the same matcher get distinct priorities (more specific engines, fewer matchers, first), so
route lint never sees two equal claims.

Existing manifests are only appended to, never rewritten, and only when they have no route at all.
"""
from __future__ import annotations

import tomllib
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from .. import paths
from . import manifest as _manifest
from .router import magic_bytes

BASE_PRIORITY = 30
MAX_MATCHERS = 8
MIN_MAGIC_BYTES = 3
COMMENT = ("inferred by `python -m ctf engines generate --file-routes` from the formats the code tests "
           "for (R-10); correct by hand")

GENERIC_EXTS = frozenset("""
.txt .text .json .jsonl .xml .yaml .yml .toml .ini .cfg .conf .csv .tsv .log .md .rst .py .pyw .js .cjs
.mjs .ts .html .htm .css .bin .dat .data .raw .out .tmp .bak .zip .gz .gzip .tgz .tar .bz2 .xz .7z .zst
.lz .lzma .rar .invalid .in .hex .0 .n .c .h .cpp .sh .bat
.pem .key .env .p12 .pfx .crt .cer .der .pub
""".split())
# The last row (R-10 round 1): keys, certificates and .env files ship with challenges of every category,
# and an engine that tests for them usually scans archive members for secrets, not its own input.
GENERIC_MAGIC = frozenset({
    b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08", b"\x1f\x8b\x08", b"BZh", b"\xfd7zXZ", b"\xfd7zXZ\x00",
    b"7z\xbc\xaf\x27\x1c", b"\x28\xb5\x2f\xfd", b"Rar!\x1a\x07", b"\xef\xbb\xbf", b"\xff\xfe\x00\x00",
    b"\x00\x00\xfe\xff", b"<?xml", b"<html", b"<head", b"<!doctype html", b"<!DOCTYPE html", b"<script",
    b"-----", b"RIFF", b"FORM", b"rem ",
})


def distinctive(exts, magics) -> list[str]:
    """The matchers (`ext:.x`, `magic:...`) among an engine's inferred inputs that name a specific format."""
    out = {f"ext:{e.lower()}" for e in exts if e.lower() not in GENERIC_EXTS}
    for m in magics:
        val = m.split(":", 1)[1]
        b = magic_bytes(val)
        if len(b) >= MIN_MAGIC_BYTES and b not in GENERIC_MAGIC and b.strip():
            out.add(m)
    return sorted(out)


def taken_priorities(manifests) -> dict[str, set[int]]:
    """matcher -> priorities already claimed by existing routes that carry that file matcher."""
    taken: dict[str, set[int]] = defaultdict(set)
    for m in manifests:
        if m.status == "retired":
            continue
        for r in m.routes:
            for f in r.files:
                taken[f].add(r.effective_priority)
    return taken


def assign(candidates: list[tuple[str, list[str]]], taken: dict[str, set[int]] | None = None,
           base: int = BASE_PRIORITY) -> tuple[dict[str, int], list[str]]:
    """({key: priority}, [skip reasons]) for `candidates` = [(key, matchers)].

    More specific candidates (fewer matchers) choose first; each takes the highest priority <= base
    that no existing route and no earlier candidate holds for any matcher it shares."""
    taken = defaultdict(set, {k: set(v) for k, v in (taken or {}).items()})
    out, skipped = {}, []
    for key, files in sorted(candidates, key=lambda kv: (len(kv[1]), kv[0])):
        used = set().union(*(taken[f] for f in files)) if files else set()
        p = next((x for x in range(base, 0, -1) if x not in used), None)
        if p is None:
            skipped.append(f"{key}: no free priority at or below {base} for {', '.join(files)}")
            continue
        out[key] = p
        for f in files:
            taken[f].add(p)
    return out, skipped


def block(files: list[str], priority: int) -> str:
    from .generate import _toml_list
    return f"\n[[routes]]  # {COMMENT}\nfiles = {_toml_list(files)}\npriority = {priority}\n"


@dataclass
class Planned:
    manifest: _manifest.Manifest
    files: list[str]
    priority: int

    @property
    def text(self) -> str:
        return block(self.files, self.priority)


def plan(root: Path | None = None, manifests: list[_manifest.Manifest] | None = None
         ) -> tuple[list[Planned], list[str]]:
    """(routes to append, reasons engines were left unrouted) for every unrouted, non-retired engine."""
    from .generate import analyze
    root = paths.repo_root() if root is None else Path(root)
    ms = _manifest.discover(root) if manifests is None else manifests
    cands, by_id, skipped = [], {}, []
    for m in ms:
        if m.routes or m.status == "retired" or not m.module_path.is_file():
            continue
        facts = analyze(m.module_path)
        found = distinctive(facts.exts, facts.magics)
        if not found:
            continue
        if len(found) > MAX_MATCHERS:
            skipped.append(f"{m.id}: tests for {len(found)} formats (a dispatcher); route it by keyword by hand")
            continue
        cands.append((m.id, found))
        by_id[m.id] = m
    prio, why = assign(cands, taken_priorities(ms))
    skipped += why
    planned = [Planned(by_id[k], files, prio[k]) for k, files in sorted(cands) if k in prio]
    return planned, skipped


def apply(planned: list[Planned]) -> int:
    """Append each planned route to its sidecar. Refuses (before writing anything) a sidecar that is not
    the manifest the plan read or that has gained a route since."""
    for p in planned:
        current = _manifest.load(p.manifest.path)
        if current.routes:
            raise RuntimeError(f"{p.manifest.path} has a route now; not appending an inferred one")
    for p in planned:
        text = p.manifest.path.read_text(encoding="utf-8")
        new = text + ("" if text.endswith("\n") else "\n") + p.text
        _manifest.parse(tomllib.loads(new), p.manifest.path)          # never write an invalid file
        p.manifest.path.write_text(new, encoding="utf-8")
    return len(planned)
