#!/usr/bin/env python3
"""Toolkit `series_chain` (B-090): a follow-up task answered from the evidence a sibling task saved.

"Onion Deanon 1: Fingerprint the Certificate" says only "Continuation of the same lab ... Get the
certificate's SHA-256 fingerprint". The first task of the lab ("Onion Deanon 1: Read the
Certificate") already saved the leaf certificate in its workspace, so the answer is a computed
field of a saved file. This engine runs ctf.series.chain on the challenge folder: it finds the
series siblings in the workdir (the challenge folder's parent), hashes the certificates and favicons
they saved, maps the task wording to the field and the answer form, and wraps each answer in the
flag format.

  solve(challenge_dir, profile, **opts) -> SolverResult    the engine contract (python -m ctf run,
                                                           intake run = "challenge")

Status: `candidate` when a field was computed and wrapped (never `solved`: nothing is proven until
the platform says so, and nothing is submitted here); `unsure` when the brief says it continues a
lab but no sibling or no saved evidence is there yet (the reason names what is missing), or the
answers have no flag format; `none` when the task is not part of a series. Every reused value is
recorded in the hypothesis ledger (ctf.series.record_reuse). Sibling files are data: read and
hashed, never run.

  .venv/bin/python solvers/toolkits/series_chain.py CHALLENGE_DIR [--root WORKDIR] [--event SLUG] [--no-ledger]
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

try:
    from ctf import series as _series
    from ctf.result import Cost, Evidence, SolverResult
except ModuleNotFoundError:            # run as a plain script: the checkout root on sys.path
    sys.path.append(str(Path(__file__).resolve().parents[2]))
    from ctf import series as _series
    from ctf.result import Cost, Evidence, SolverResult

ENGINE = "toolkits.series_chain"


def result_of(rep, seconds: float) -> SolverResult:
    ev = [Evidence("match", f"{c.kind} {c.field} ({c.form}) of {c.source} saved by sibling {c.sibling}",
                   path=c.source) for c in rep.candidates[:16]]
    cost = Cost(seconds=round(seconds, 3))
    cid = rep.challenge_id
    if rep.status == "candidate":
        return SolverResult(status="candidate", flags=tuple(rep.flags), evidence=tuple(ev), cost=cost,
                            engine=ENGINE, challenge_id=cid,
                            notes=rep.reason + " (report: recon/series.md)")
    if rep.status == "unlinked":
        return SolverResult(status="none", cost=cost, engine=ENGINE, challenge_id=cid, notes=rep.reason)
    answers = "; ".join(f"{c.kind} {c.field} {c.form}: {c.answer}" for c in rep.candidates[:8])
    return SolverResult(status="unsure", evidence=tuple(ev), cost=cost, engine=ENGINE, challenge_id=cid,
                        notes=f"{rep.status}: {rep.reason}" + (f"; answers: {answers}" if answers else ""))


def solve(challenge_dir: Path, profile, **opts):
    """Engine contract. opts: root (the workdir holding the siblings; default the challenge folder's
    parent), ledger (default true: record what was reused in the hypothesis ledger)."""
    t0 = time.monotonic()
    challenge_dir = Path(challenge_dir)
    root = Path(opts["root"]) if opts.get("root") else None
    try:
        rep = _series.chain(challenge_dir, root=root, profile=profile)
    except _series.SeriesError as e:
        return SolverResult(status="blocked", engine=ENGINE, notes=f"series chain could not run: {e}")
    _series.write_report(rep)
    if str(opts.get("ledger", "true")).lower() not in ("0", "false", "no", "off"):
        _series.record_reuse(rep, profile=profile)
    return result_of(rep, time.monotonic() - t0)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="series_chain.py", description=__doc__.split("\n\n")[0])
    ap.add_argument("challenge_dir", type=Path)
    ap.add_argument("--root", type=Path, help="the workdir holding the sibling folders (default: the parent)")
    ap.add_argument("--event", help="event slug (default: the current event)")
    ap.add_argument("--no-ledger", action="store_true", help="do not record the reuse in the hypothesis ledger")
    a = ap.parse_args(argv)
    from ctf import event
    profile = event.load(a.event) if a.event else event.current()
    res = solve(a.challenge_dir, profile, root=a.root, ledger=not a.no_ledger)
    print(res.to_json())
    return 0


if __name__ == "__main__":
    sys.exit(main())
