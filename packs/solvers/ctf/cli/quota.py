"""ctf quota scan | status | set | plan | gate | wait | daily | check -- harness quota meter (B-171).

    python -m ctf quota scan [--root DIR ...] [--harness claude|codex|all] [--log PATH ...] [--tz ZONE] [--json]
        read new session-log lines for quota readings (Codex rate_limits, limit-hit messages, served
        responses) into <workdir>/usage/quota-state.json
    python -m ctf quota status [--json]        each harness and window: used, margin, reset, state, reserve
    python -m ctf quota set HARNESS --window W (--used PCT | --exhausted) [--resets WHEN] --by WHO [--note T]
        record a reading taken off the harness's own usage screen (a quota.reading ledger event)
    python -m ctf quota plan --jobs FILE [--json]
        schedule jobs (JSON list of {id, kind, harnesses?, prefer?, est_pct?}): writeups first, each on the
        harness that can take it, the rest held in batches by the time their limit resets
    python -m ctf quota gate --kind KIND [--harness H ...] [--prefer H] [--est PCT] [--json]
        may one job of KIND start now? prints the harness (exit 0) or why not and when (exit 3)
    python -m ctf quota wait --jobs FILE [--max-wait S] [--scan]
        sleep (no model) until the first held batch opens, re-plan, print what is released
    python -m ctf quota daily [--json]         spend per day (usage ledger by harness, ledger spend by
                                               category) against the profile's allowance.daily_usd
    python -m ctf quota check                  the doctor's allowance check alone

Common: --event SLUG, --workdir DIR, --now WHEN (epoch or ISO-8601: plan as of another time).

Exit codes: 0 ok; 1 the check failed, or nothing held has a known release time (wait); 2 a named error
(no event or workdir, a bad job file, a corrupt state, a missing session source); 3 held: a job could
not be placed now (plan, gate), or wait gave up after --max-wait.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

HELP = "harness quota meter, release reserve and quota-aware job scheduling (B-171)"
HELD_EXIT = 3


class QuotaCLIError(RuntimeError):
    pass


def _sleep(seconds: float) -> None:          # replaced in tests
    time.sleep(seconds)


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("--event", help="event slug (default: the current event)")
    p.add_argument("--workdir", help="the event workdir (default: the event's)")
    p.add_argument("--now", help="plan as of this time (epoch seconds or ISO-8601; default now)")
    sp = p.add_subparsers(dest="action", required=True)
    sc = sp.add_parser("scan", help="read session logs for quota readings")
    sc.add_argument("--root", action="append", default=[],
                    help="another folder whose sessions count (repeatable; the workdir always does)")
    sc.add_argument("--harness", choices=("claude", "codex", "all"), default="all")
    sc.add_argument("--log", action="append", default=[],
                    help="read this log instead of discovering (repeatable; needs --harness claude|codex)")
    sc.add_argument("--claude-home", help="Claude Code config folder (default $CLAUDE_CONFIG_DIR, else ~/.claude)")
    sc.add_argument("--codex-home", help="Codex config folder (default $CODEX_HOME, else ~/.codex)")
    sc.add_argument("--tz", help="zone the harnesses print reset times in (default this machine's)")
    sc.add_argument("--json", action="store_true")
    st = sp.add_parser("status", help="each harness and window: used, margin, reset, state")
    st.add_argument("--json", action="store_true")
    se = sp.add_parser("set", help="record a reading taken off the harness's usage screen")
    se.add_argument("harness", choices=("claude", "codex"))
    se.add_argument("--window", required=True, help="session | weekly | spend | ...")
    g = se.add_mutually_exclusive_group(required=True)
    g.add_argument("--used", type=float, help="percent of the window used")
    g.add_argument("--exhausted", action="store_true", help="the limit is hit")
    se.add_argument("--resets", help="when the window resets (epoch, ISO-8601, or +2h / +30m / +3d)")
    se.add_argument("--by", required=True, help="who read it")
    se.add_argument("--note")
    pl = sp.add_parser("plan", help="schedule jobs across the harnesses")
    pl.add_argument("--jobs", required=True, help="JSON file: [{id, kind, harnesses?, prefer?, est_pct?}]")
    pl.add_argument("--json", action="store_true")
    ga = sp.add_parser("gate", help="may one job of a kind start now?")
    ga.add_argument("--kind", required=True, choices=("writeup", "retro", "release", "solve", "build"))
    ga.add_argument("--harness", action="append", choices=("claude", "codex"),
                    help="harness the job may run on (repeatable; default both)")
    ga.add_argument("--prefer", choices=("claude", "codex"))
    ga.add_argument("--est", type=float, help="percent of a window the job is expected to use")
    ga.add_argument("--json", action="store_true")
    wa = sp.add_parser("wait", help="sleep until the first held batch opens, then re-plan")
    wa.add_argument("--jobs", required=True)
    wa.add_argument("--max-wait", type=float, default=None, help="give up after this many seconds (exit 3)")
    wa.add_argument("--grace", type=float, default=60.0, help="seconds after the reset before re-planning")
    wa.add_argument("--scan", action="store_true", help="scan the session logs before re-planning")
    da = sp.add_parser("daily", help="spend per day against allowance.daily_usd")
    da.add_argument("--pricing", help="pricing table (default tools/ledger/pricing.json)")
    da.add_argument("--json", action="store_true")
    sp.add_parser("check", help="the doctor's allowance check alone")


def _profile(args):
    from .. import event
    return event.load(args.event) if args.event else event.current()


def _workdir(args, prof) -> Path:
    from .. import paths
    if args.workdir:
        return Path(args.workdir).expanduser().resolve()
    return paths.workdir(prof.slug)


def _when(raw: str, now: float) -> float:
    from ..budget import _parse_when
    raw = raw.strip()
    if raw.startswith("+") and raw[-1:] in "smhd" and raw[1:-1].replace(".", "", 1).isdigit():
        return now + float(raw[1:-1]) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[raw[-1]]
    return _parse_when(raw)


def _tools():
    """tools.ledger owns the session-log readers; a lazy import like ctf/cli/usage.py (CONTRACTS section 11)."""
    try:
        from tools.ledger import pricing, quota as qscan, sources, usage
    except ImportError as e:
        raise QuotaCLIError(f"needs tools.ledger (the session-log readers) and cannot import it ({e}); "
                            "run from the repo root") from e
    return pricing, qscan, sources, usage


def _scan(args, wd: Path) -> int:
    import zoneinfo
    _pricing, qscan, _sources, usage = _tools()
    roots = [wd] + [Path(r).expanduser() for r in args.root]
    harnesses = usage.HARNESSES if args.harness == "all" else (args.harness,)
    refs = None
    if args.log:
        if args.harness == "all":
            raise QuotaCLIError("--log needs --harness claude or --harness codex")
        refs = [usage.ref_for(p, args.harness) for p in args.log]
    try:
        tz = zoneinfo.ZoneInfo(args.tz) if args.tz else None
    except (zoneinfo.ZoneInfoNotFoundError, ValueError):
        raise QuotaCLIError(f"--tz {args.tz!r} is not an IANA time zone") from None
    res = qscan.scan(wd, roots, harnesses=harnesses, refs=refs, tz=tz,
                     claude_home=Path(args.claude_home).expanduser() if args.claude_home else None,
                     codex_home=Path(args.codex_home).expanduser() if args.codex_home else None)
    from .. import quota
    if args.json:
        print(json.dumps(dict(res.to_dict(), state=str(quota.state_path(wd)))))
    else:
        print(f"quota scan: {res.logs} log(s), {res.lines} new line(s); {res.hits} limit hit(s), "
              f"{res.served} served response(s), {res.readings} newer reading(s); state {quota.state_path(wd)}")
        if res.untimed:
            print(f"  {res.untimed} reading(s) had no timestamp and are timed by their log's modification time")
    for n in res.notes:
        print(f"note: {n}", file=sys.stderr)
    return 0


def _print_status(snap, quota) -> None:
    rel = quota.fmt_time(snap.next_release) if snap.next_release is not None else "none ahead"
    print(f"quota as of {quota.fmt_time(snap.now)}; next release {rel}")
    for h, s in snap.harnesses.items():
        last = f"; last served response {quota.fmt_time(s.last_ok)}" if s.last_ok else ""
        print(f"{h}: {s.status.upper()}{last}")
        if not s.windows:
            print("  no reading (python -m ctf quota scan, or quota set)")
        for w in s.windows:
            eff = f"{w.effective_pct:g}%" if w.effective_pct is not None else "?"
            res = " reserve held" if w.reserved else ""
            print(f"  {w.window:<10} {w.status:<9} {eff:>5}  resets {quota.fmt_time(w.resets_at)}{res}  "
                  f"[{w.source}] {w.note}")


def _print_plan(plan, quota) -> None:
    for a in plan.assigned:
        room = f", {a.headroom_pct:g}% headroom left" if a.headroom_pct is not None else ""
        print(f"RUN   {a.job} ({a.kind}) on {a.harness} [{a.mode}] est {a.est_pct:g}%{room}")
    for hd in plan.held:
        why = "; ".join(f"{h}: {r}" for h, r in hd.reasons.items())
        print(f"HOLD  {hd.job} ({hd.kind}) until {quota.fmt_time(hd.release_at)}: {why}")
    for t, ids in plan.batches:
        print(f"batch at {quota.fmt_time(t)}: {', '.join(ids)}")
    for w in plan.warnings:
        print(f"warning: {w}", file=sys.stderr)


def _read_jobs(path: str, quota):
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise QuotaCLIError(f"job file not found: {path}") from None
    except json.JSONDecodeError as e:
        raise QuotaCLIError(f"{path}: not JSON ({e})") from None
    return quota.load_jobs(data)


def _daily(args, prof, wd: Path, quota) -> int:
    from .. import ledger
    pricing, _q, _s, usage = _tools()
    prices = pricing.load_prices(args.pricing)
    days, undated = quota.daily(usage.load(wd).values(), ledger.read(wd), price=lambda r: pricing.cost(r, prices),
                                tz=prof.allowance.tz, allowance_usd=prof.allowance.daily_usd)
    if args.json:
        print(json.dumps({"days": [d.to_dict() for d in days], "undated": undated, "tz": prof.allowance.tz,
                          "allowance_usd": prof.allowance.daily_usd}))
    else:
        cap = f"${prof.allowance.daily_usd:,.2f}" if prof.allowance.daily_usd else "none set"
        print(f"per-day spend ({prof.allowance.tz}); daily allowance {cap}")
        for d in days:
            use = ", ".join(f"{h} ${v:,.2f}" for h, v in sorted(d.usage_usd.items())) or "-"
            sp = ", ".join(f"{c} ${v:,.2f}" for c, v in sorted(d.spend_usd.items())) or "-"
            flag = "  OVER" if d.over else ""
            unp = f"  ({d.unpriced} unpriced)" if d.unpriced else ""
            print(f"{d.date}  ${d.total:>10,.2f}{flag}  usage: {use}  ledger spend: {sp}{unp}")
        if undated:
            print(f"note: {undated} usage row(s) carry no timestamp and are in no day")
    return 1 if any(d.over for d in days) else 0


def run(args: argparse.Namespace) -> int:
    from .. import quota
    from ..event import EventError
    named = (QuotaCLIError, EventError, FileNotFoundError, ValueError, OSError)
    try:
        extra = ()
        if args.action in ("scan", "daily"):
            _p, _q, sources, usage = _tools()
            extra = (usage.UsageError, sources.SourceError)
    except QuotaCLIError as e:
        print(f"ctf quota: {e}", file=sys.stderr)
        return 2
    try:
        prof = _profile(args)
        wd = _workdir(args, prof)
        now = _when(args.now, time.time()) if args.now else time.time()
        if args.action == "scan":
            return _scan(args, wd)
        if args.action == "set":
            resets = _when(args.resets, time.time()) if args.resets else None
            quota.record(wd, args.harness, args.window, used_pct=args.used, resets_at=resets,
                         exhausted=args.exhausted, by=args.by, note=args.note)
            print(f"recorded {args.harness} {args.window}: "
                  + ("exhausted" if args.exhausted else f"{args.used:g}% used")
                  + (f", resets {quota.fmt_time(resets)}" if resets else ""))
            return 0
        if args.action == "daily":
            return _daily(args, prof, wd, quota)
        if args.action == "check":
            c = quota.check(prof, workdir=wd, now=now)
            print(c.line())
            return 1 if c.blocking else 0
        snap = quota.snapshot(prof, workdir=wd, now=now)
        if args.action == "status":
            if args.json:
                print(json.dumps(snap.to_dict()))
            else:
                _print_status(snap, quota)
            return 0
        if args.action == "gate":
            job = quota.Job("gate", args.kind, tuple(args.harness or quota.HARNESSES), args.prefer, args.est)
            plan = quota.schedule(snap, [job])
            if args.json:
                print(json.dumps(plan.to_dict()))
            elif plan.assigned:
                a = plan.assigned[0]
                print(a.harness)
                for w in plan.warnings:
                    print(f"warning: {w}", file=sys.stderr)
            else:
                hd = plan.held[0]
                print(f"held until {quota.fmt_time(hd.release_at)}: "
                      + "; ".join(f"{h}: {r}" for h, r in hd.reasons.items()), file=sys.stderr)
            return 0 if plan.assigned else HELD_EXIT
        jobs = _read_jobs(args.jobs, quota)
        plan = quota.schedule(snap, jobs)
        if args.action == "plan":
            if args.json:
                print(json.dumps(plan.to_dict()))
            else:
                _print_plan(plan, quota)
            return HELD_EXIT if plan.held else 0
        # wait
        if not plan.held:
            _print_plan(plan, quota)
            return 0
        t = quota.next_wait(plan)
        if t is None:
            _print_plan(plan, quota)
            print("ctf quota wait: no held job has a known release time; record a reading "
                  "(python -m ctf quota set ...) or scan the logs", file=sys.stderr)
            return 1
        delay = max(0.0, t + args.grace - now)
        if args.max_wait is not None and delay > args.max_wait:
            _sleep(args.max_wait)
            print(f"ctf quota wait: the first batch opens at {quota.fmt_time(t)}, past --max-wait "
                  f"{args.max_wait:g}s", file=sys.stderr)
            return HELD_EXIT
        before = {hd.job for hd in plan.held}
        print(f"waiting {delay:.0f}s for the batch at {quota.fmt_time(t)}", file=sys.stderr)
        _sleep(delay)
        if args.scan:
            ns = argparse.Namespace(root=[], harness="all", log=[], claude_home=None, codex_home=None,
                                    tz=None, json=False)
            _scan(ns, wd)
        later = now + delay if args.now else time.time()
        plan = quota.schedule(quota.snapshot(prof, workdir=wd, now=later), jobs)
        released = [a for a in plan.assigned if a.job in before]
        for a in released:
            print(f"RELEASED {a.job} ({a.kind}) on {a.harness} [{a.mode}]")
        _print_plan(plan, quota)
        return 0 if released else HELD_EXIT
    except named + extra + (quota.QuotaError,) as e:
        print(f"ctf quota: {e}", file=sys.stderr)
        return 2
