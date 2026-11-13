"""ctf intake <id>... | --all: parallel no-model intake, one worker process per challenge (B-002).

Each worker downloads the challenge through the event's platform adapter, sweeps it (recursive unpack,
sha256 manifest, flag search: ctf/sweep.py), runs the engines that have an [intake] input adapter
with the network denied, and writes recon/index.md, triage.md, recon/flags.txt and recon/intake.json
in <workdir>/<id>-<slug>/. Nothing is submitted unless --submit is given: then, after every worker
has finished, the parent auto-submits each `solved` challenge's one unambiguous flag through the
SubmitGate, at most --submit-cap judged sends per challenge across runs (B-012,
ctf/intake/autosubmit.py; manual-mode events refuse). See ctf/intake/__init__.py.

    python -m ctf intake --all                       # every unsolved challenge not taken in yet
    python -m ctf intake 9076 9080 --jobs 8
    python -m ctf wait && python -m ctf intake --all # at a wave open
    python -m ctf intake --all --submit              # and auto-submit unambiguous flags (cap 1 each)

Exit 0 when every worker ran (whatever it found) and no auto-submit failed, 1 when one was blocked or
crashed or an auto-submit failed, 2 when intake could not start (a bad option, no profile, no board).
"""
from __future__ import annotations

import argparse
import statistics
import sys

HELP = "download, unpack, sweep and run input-adapted engines on challenges in parallel, no model"


def add_arguments(p: argparse.ArgumentParser) -> None:
    from ..intake import DEFAULT_ENGINE_BUDGET, guard
    p.add_argument("ids", nargs="*", help="challenge ids (or use --all)")
    p.add_argument("--all", action="store_true", help="every challenge on the board not solved and not taken in yet")
    p.add_argument("--event", help="event slug (default: $CTF_EVENT / the only profile)")
    p.add_argument("--jobs", type=int, help="workers at once (default: one per challenge up to 2 x CPUs)")
    p.add_argument("--force", action="store_true", help="--all: redo challenges already taken in")
    p.add_argument("--include-solved", action="store_true", help="--all: take team-solved challenges too")
    p.add_argument("--no-engines", action="store_true", help="download and sweep only")
    p.add_argument("--max-cost", default="cheap", choices=("cheap", "medium", "heavy"),
                   help="highest engine cost_class to run (default cheap)")
    p.add_argument("--engine-budget", type=float, default=DEFAULT_ENGINE_BUDGET,
                   help=f"seconds of engine time per challenge (default {DEFAULT_ENGINE_BUDGET:g})")
    p.add_argument("--net-guard", default="auto", choices=guard.MODES,
                   help="auto: OS sandbox when it works, else the Python guard; os: require the OS sandbox")
    p.add_argument("--no-ledger", action="store_true", help="no intake / engine.run ledger records")
    p.add_argument("--no-brief-fetch", action="store_true",
                   help="do not GET a URL the brief names to read the field it asks for (B-088); "
                        "the read is then an instruction")
    from ..intake import autosubmit
    p.add_argument("--submit", action="store_true",
                   help="auto-submit one unambiguous flag per solved challenge through the submit gate "
                        "(B-012); manual-mode events refuse")
    p.add_argument("--submit-cap", type=int, default=autosubmit.DEFAULT_CAP,
                   help=f"max judged auto-submit sends per challenge, across runs (>= 0, default "
                        f"{autosubmit.DEFAULT_CAP}); rate-limited, paused and refused sends do not count")


def _pct(xs, q):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round(q * (len(xs) - 1))))] if xs else 0.0


def run(args: argparse.Namespace) -> int:
    from .. import event as _event
    from .. import intake
    from ..platform import PlatformError
    if bool(args.ids) == bool(args.all):
        print("ctf intake: give challenge ids or --all (not both)", file=sys.stderr)
        return 2
    if args.submit_cap < 0:
        print(f"ctf intake: --submit-cap must be >= 0, got {args.submit_cap}", file=sys.stderr)
        return 2
    try:
        profile = _event.load(args.event) if args.event else _event.current()
        opts = intake.Options(engines=not args.no_engines, max_cost=args.max_cost,
                              engine_budget=args.engine_budget, net_guard=args.net_guard,
                              record=not args.no_ledger, brief_fetch=not args.no_brief_fetch)
        if args.net_guard == "os" and not args.no_engines:
            intake.guard.resolve("os")             # fail here, once, not in every worker
        if args.all:
            ids, skipped = intake.board(profile, include_solved=args.include_solved, force=args.force)
            for cid, why in skipped:
                print(f"skip {cid}: {why}")
        else:
            ids = list(dict.fromkeys(args.ids))
        if not ids:
            print("ctf intake: nothing to take in")
            return 0
        print(f"intake: {len(ids)} challenge(s), {intake.default_jobs(len(ids)) if args.jobs is None else args.jobs} "
              "at once", flush=True)

        def done(o):
            line = (o.summary or {}).get("line") or (o.summary or {}).get("error") or f"see {o.log}"
            print(f"[{o.started:5.1f}s +{o.seconds:5.1f}s] {'ok  ' if o.ok else 'FAIL'} {line}", flush=True)

        outs = intake.intake_many(ids, profile, jobs=args.jobs, options=opts, on_done=done)
    except (intake.IntakeError, intake.guard.GuardError, _event.EventError, PlatformError) as e:
        print(f"ctf intake: {type(e).__name__}: {e}", file=sys.stderr)
        return 2
    secs = [o.seconds for o in outs]
    print(f"intake: {sum(o.ok for o in outs)}/{len(outs)} ran; all started within "
          f"{max(o.started for o in outs):.1f}s; p50 {statistics.median(secs):.1f}s, "
          f"p90 {_pct(secs, 0.9):.1f}s, max {max(secs):.1f}s", flush=True)
    failed = _auto_submit(outs, profile, args.submit_cap) if args.submit else 0
    return 0 if all(o.ok for o in outs) and not failed else 1


def _auto_submit(outs, profile, cap: int, *, gate=None, workdir=None) -> int:
    """B-012: after intake, auto-submit each solved challenge's one unambiguous flag through the gate,
    capped per challenge. Every send goes through ctf.platform.get_adapter (the SubmitGate); a
    manual-mode event is refused there. This runs in the parent, never in a network-guarded worker.

    One challenge's failure never stops the rest: it is printed, and counted in the return value (the
    number of challenges whose auto-submit failed, or 1 when the gate could not be built)."""
    from .. import paths as _paths
    from ..intake import autosubmit
    from ..platform import PlatformError, get_adapter
    try:
        gate = get_adapter(profile) if gate is None else gate
    except PlatformError as e:
        print(f"autosubmit: NOT RUN, the submit gate could not be built: {type(e).__name__}: {e}")
        return 1
    workdir = _paths.workdir(profile.slug) if workdir is None else workdir
    sent = accepted = failed = 0
    for o in outs:
        s = o.summary or {}
        cid = s.get("challenge_id")
        if cid is None:
            print(f"autosubmit: no summary for a run (see {o.log}); skipped")
            continue
        where = s.get("dir")
        prov = f"intake auto-submit; evidence in {where}/recon/intake.json" if where else f"intake {cid}"
        try:
            a = autosubmit.auto_submit(cid, s.get("status"), s.get("flags") or [], gate, profile=profile,
                                       provenance=prov, cap=cap, workdir=workdir)
        except Exception as e:            # e.g. the ledger cannot be read or written: name it, carry on
            failed += 1
            print(f"autosubmit {cid}: FAILED ({type(e).__name__}: {e})")
            continue
        print(a.line())
        failed += int(a.error is not None)
        sent += int(a.submitted)
        accepted += int(a.accepted)
    print(f"autosubmit: {accepted} accepted, {sent} sent, {failed} failed (cap {cap}/challenge)")
    return failed
