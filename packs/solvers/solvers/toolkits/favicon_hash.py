#!/usr/bin/env python3
"""Favicon multi-hash opener (B-089): fingerprint every handout icon at intake, no model, no network.

    python -m ctf run toolkits.favicon_hash <icon-file> [--out DIR] [--event SLUG]

Intake (`python -m ctf intake`, B-002) runs it on every icon-like handout file (its manifest's
`[intake]` table: `.ico`, a `favicon.*`, or a file whose bytes begin with the ICO magic). It reads one
file and records the hashes that scan engines index a favicon under -- the Shodan MurmurHash3 (over
MIME-base64, signed), the plain MD5 (Censys / ZoomEye) and SHA-256 -- plus the ready-made `icon_hash`
lookups for each engine, using `ctf.favicon`. No bytes are fetched: the offline half of B-089. The
online half (fetch a declared `<link rel=icon>` over the network, `.onion` through B-091) is
`python -m ctf favicon`, which runs outside intake's network-denied engine guard.

A favicon challenge asks for one of these hashes wrapped in the event flag format, but which form (the
signed mmh3, the MD5, ...) is a reasoning step for the agent, so every hash wrapped in the format is
reported as a *candidate*, never a proven flag. The file is untrusted data: it is hashed, never run.

Result (one SolverResult JSON line, the last on stdout):

  candidate  the file is an icon and at least one hash, wrapped in the event flag format, is a
             well-formed flag (several forms are plausible, so never `solved`)
  unsure     an icon, but the event flag format is not known (no prefixes), so nothing can be wrapped;
             the hashes are in the report for a human/model read
  none       the file is not an icon
  blocked    no event profile loads

The hashes, queries and wrapped candidates go to `<out>/favicon_hash-<file>.md` (intake's
`recon/engines/toolkits.favicon_hash/`), or to stdout without `--out`. Under `--out` stdout carries
only a summary line and the result, so intake's scan of it for the event format finds nothing the
result leaves out.
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

try:
    from ctf import event as _event
    from ctf import favicon as _favicon
    from ctf import flagfmt as _flagfmt
    from ctf.result import Cost, Evidence, SolverResult
except ModuleNotFoundError:            # run as a plain script: the checkout root on sys.path
    sys.path.append(str(Path(__file__).resolve().parents[2]))
    from ctf import event as _event
    from ctf import favicon as _favicon
    from ctf import flagfmt as _flagfmt
    from ctf.result import Cost, Evidence, SolverResult

ENGINE = "toolkits.favicon_hash"


def _wrapped_candidates(fh: _favicon.FaviconHashes, ff) -> list[tuple[str, str]]:
    """(label, flag) for each hash value that, wrapped in a known crib, is a well-formed event flag.
    The crib list is the event's own (`ff.cribs()`); the first crib that holds a value is used."""
    out: list[tuple[str, str]] = []
    values = [("mmh3 (Shodan/FOFA, signed)", str(fh.mmh3)),
              ("mmh3 (unsigned)", str(fh.mmh3_unsigned)),
              ("md5 (Censys/ZoomEye)", fh.md5),
              ("sha256", fh.sha256)]
    try:
        cribs = ff.cribs()
    except LookupError:
        return out
    for label, value in values:
        for crib in cribs:
            cand = f"{crib}{value}}}"
            if ff.is_flag(cand):
                out.append((label, cand))
                break
    return out


def _report_md(path: Path, fh: _favicon.FaviconHashes, candidates: list[tuple[str, str]]) -> str:
    q = _favicon.icon_hash_queries(fh)
    lines = [f"# favicon hashes: {path.name}", "",
             f"- size: {fh.size} bytes", "",
             "## hashes", "",
             f"- Shodan mmh3 (signed): `{fh.mmh3}`",
             f"- mmh3 (unsigned): `{fh.mmh3_unsigned}`",
             f"- MD5 (Censys/ZoomEye): `{fh.md5}`",
             f"- SHA-256: `{fh.sha256}`", "",
             "## ready-made icon_hash queries", ""]
    for engine, query in q.items():
        lines.append(f"- {engine}: `{query}`")
    lines.append("")
    if candidates:
        lines.append("## candidate flags (one hash form is the answer; pick by the brief)")
        lines.append("")
        for label, flag in candidates:
            lines.append(f"- {label}: `{flag}`")
        lines.append("")
    return "\n".join(lines)


def analyze(path: Path, profile) -> tuple[SolverResult, str]:
    """Return (result, report markdown) for one file. Pure of I/O beyond reading `path`."""
    t0 = time.process_time()
    data = path.read_bytes()
    if not _favicon.looks_like_icon(path):
        return (SolverResult(status="none", engine=ENGINE,
                             notes=f"{path.name} is not an icon file",
                             cost=Cost(seconds=time.process_time() - t0)), "")
    fh = _favicon.fingerprint(data)
    ff = _flagfmt.for_profile(profile)
    candidates = _wrapped_candidates(fh, ff)
    report = _report_md(path, fh, candidates)
    evidence = [
        Evidence(kind="hash", detail=f"Shodan mmh3 (signed) = {fh.mmh3}", path=str(path)),
        Evidence(kind="hash", detail=f"MD5 = {fh.md5}", path=str(path)),
        Evidence(kind="hash", detail=f"SHA-256 = {fh.sha256}", path=str(path)),
    ]
    for engine, query in _favicon.icon_hash_queries(fh).items():
        evidence.append(Evidence(kind="query", detail=f"{engine}: {query}"))
    cost = Cost(seconds=time.process_time() - t0)
    if candidates:
        flags = tuple(dict.fromkeys(flag for _, flag in candidates))  # distinct, first-seen order
        return (SolverResult(status="candidate", engine=ENGINE,
                             flags=flags,
                             evidence=tuple(evidence), cost=cost,
                             notes="favicon hashes wrapped in the event flag format; the answer is one "
                                   "form (mmh3/md5/sha256) -- read the brief"), report)
    return (SolverResult(status="unsure", engine=ENGINE, evidence=tuple(evidence), cost=cost,
                         notes="favicon hashed; the event flag format is not known, so no form could "
                               "be wrapped -- see the report for the hashes and queries"), report)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="favicon multi-hash opener (B-089)")
    ap.add_argument("file", help="the icon file to hash")
    ap.add_argument("--out", metavar="DIR", default=None,
                    help="write the report to DIR/favicon_hash-<file>.md instead of stdout")
    ap.add_argument("--event", metavar="SLUG", default=None, help="event profile to use")
    args = ap.parse_args(argv)

    try:
        profile = _event.load(args.event) if args.event else _event.current()
    except _event.EventError as e:
        res = SolverResult(status="blocked", engine=ENGINE, notes=f"no event profile: {e}")
        print(res.to_json())
        return 0

    path = Path(args.file)
    if not path.is_file():
        res = SolverResult(status="blocked", engine=ENGINE, notes=f"no such file: {path}")
        print(res.to_json())
        return 0

    result, report = analyze(path, profile)
    if args.out and report:
        out_dir = Path(args.out)
        out_dir.mkdir(parents=True, exist_ok=True)
        out_file = out_dir / f"favicon_hash-{path.name}.md"
        out_file.write_text(report)
        print(f"favicon_hash: {result.status} -> {out_file}")
    elif report:
        print(report)
    print(result.to_json())
    return 0


if __name__ == "__main__":
    sys.exit(main())
