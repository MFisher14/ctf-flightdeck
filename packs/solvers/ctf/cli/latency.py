"""ctf latency open | start | pending | phases | floors | lane-done -- the release latency path (B-185).

    python -m ctf latency open CID [--at WHEN] [--lead S] [--connections N] [--no-start] [--dest DIR]
                               [--timeout S] [--alert-after S] [--json]
        warm N connections at WHEN - lead, then at WHEN list || start (list || detail with
        --no-start), wait for provisioning by status reads, download into DIR; prints the phases
    python -m ctf latency start CID [--no-wait] [--timeout S] [--alert-after S] [--max-posts N] [--json]
        one guarded start: a POST only when no start of the attempt is pending, then status reads
        until ready (the provisioning alert at --alert-after, default 45 s); never a re-POST while
        the attempt prepares
    python -m ctf latency pending [--clear CID] [--json] [--workdir DIR]     the start records
    python -m ctf latency phases [--challenge CID] [--since WHEN] [--json] [--workdir DIR]
    python -m ctf latency floors [--record MODE=S ...] [--bank MODE=N ...] [--since WHEN] [--write]
                                 [--json] [--workdir DIR]
        the wire-floor table per mode (from the wire journal and the phases log); for a Game Master
        event a timed mode also gets its bank-submit floor (the cumulative base bank the ladder waits
        behind, at the measured submit round trip), which --bank MODE=N overrides
    python -m ctf latency lane-done LANE [--undo] [--workdir DIR]
        mark a lane done, so the last working lane is exempt from the minute hold (the wire's
        sole-lane rule; the team cap still holds)

open and start contact the platform through get_adapter (journaled and budgeted by the wire); a
Game Master Time Trial or Mastery id is refused before any request (only the opener starts a clock).
The other actions read and write <workdir>/wire/ only. WHEN is epoch seconds or ISO-8601 with a UTC
offset.

Exit codes: 0 ok; 1 the attempt is not ready (still preparing at the timeout, absent) or a step of
the opening failed; 2 a named error (no profile, unusable workdir, bad argument, a platform error);
4 refused before a request (a timed id, a re-POST past --max-posts).
"""
from __future__ import annotations

import argparse
import dataclasses
import datetime as _dt
import json
import sys
from pathlib import Path

HELP = "the release latency path: warm + parallel open, guarded starts, phase timing, wire floors"


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("--event", help="event slug (default: the current event)")
    sp = p.add_subparsers(dest="action", required=True)
    op = sp.add_parser("open", help="warm, then list || start at the release, provisioning wait, download")
    op.add_argument("challenge")
    op.add_argument("--at", help="the release (epoch or ISO-8601 with offset); default: now")
    op.add_argument("--lead", type=float, default=None, help="warm this many seconds before --at (default 2)")
    op.add_argument("--connections", type=int, default=None, help="connections to warm (default 2)")
    op.add_argument("--no-start", action="store_true", help="read only: list || detail, no start POST")
    op.add_argument("--dest", help="download every delivery into this folder")
    op.add_argument("--timeout", type=float, default=None, help="provisioning wait limit, s (default 600)")
    op.add_argument("--alert-after", type=float, default=None, help="provisioning alert, s (default 45)")
    op.add_argument("--json", action="store_true")
    st = sp.add_parser("start", help="one guarded start, then status reads until ready")
    st.add_argument("challenge")
    st.add_argument("--no-wait", action="store_true", help="the start (or status read) only")
    st.add_argument("--timeout", type=float, default=None)
    st.add_argument("--alert-after", type=float, default=None)
    st.add_argument("--max-posts", type=int, default=None, help="unanswered start POSTs allowed (default 2)")
    st.add_argument("--json", action="store_true")
    pe = sp.add_parser("pending", help="the persisted start records; --clear CID forgets one")
    pe.add_argument("--clear", metavar="CID")
    pe.add_argument("--json", action="store_true")
    pe.add_argument("--workdir")
    ph = sp.add_parser("phases", help="per run: each phase's time after the release and its duration")
    ph.add_argument("--challenge")
    ph.add_argument("--since")
    ph.add_argument("--json", action="store_true")
    ph.add_argument("--workdir")
    fl = sp.add_parser("floors", help="the wire-floor table per mode")
    fl.add_argument("--record", action="append", default=[], metavar="MODE=S",
                    help="a known best time for a mode (first blood, record) to compare (repeatable)")
    fl.add_argument("--bank", action="append", default=[], metavar="MODE=N",
                    help="override the cumulative base-bank size for a timed mode's bank floor "
                         "(repeatable); without it, a Game Master event's benchmark bank is used")
    fl.add_argument("--since")
    fl.add_argument("--write", action="store_true", help="also write <workdir>/wire/floors.json")
    fl.add_argument("--json", action="store_true")
    fl.add_argument("--workdir")
    ld = sp.add_parser("lane-done", help="mark a lane done (the sole-lane exemption reads it)")
    ld.add_argument("lane")
    ld.add_argument("--undo", action="store_true", help="the lane is working again")
    ld.add_argument("--workdir")


def _profile(args):
    from .. import event
    return event.load(args.event) if args.event else event.current()


def _workdir(args, prof) -> Path:
    from .. import paths
    if getattr(args, "workdir", None):
        return Path(args.workdir).expanduser().resolve()
    return paths.workdir(prof.slug)


def _when(text: str) -> float:
    from .ledger import parse_when
    return parse_when(text)


def _utc(ts) -> str:
    if ts is None:
        return "-"
    return _dt.datetime.fromtimestamp(float(ts), tz=_dt.timezone.utc).isoformat(
        timespec="milliseconds").replace("+00:00", "Z")


def _kw(args, **names) -> dict:
    """Keyword arguments for the options the caller gave (the library keeps its own defaults)."""
    return {k: getattr(args, a) for k, a in names.items() if getattr(args, a, None) is not None}


def run(args: argparse.Namespace) -> int:
    from ..event import EventError
    from ..platform import NotAllowed, PlatformError
    from ..platform import latency
    try:
        prof = _profile(args)
        if args.action == "open":
            return _open(args, prof)
        if args.action == "start":
            return _start(args, prof)
        wd = _workdir(args, prof)
        if args.action == "pending":
            return _pending(args, wd)
        if args.action == "phases":
            return _phases(args, wd)
        if args.action == "floors":
            return _floors(args, prof, wd)
        if args.action == "lane-done":
            from ..platform import wire
            marks = wire.mark_lane_done(wd, args.lane, done=not args.undo)
            print(f"lane {args.lane} {'working again' if args.undo else 'done'}; lanes done: "
                  + (", ".join(f"{k} ({_utc(v)})" for k, v in sorted(marks.items())) or "none"))
            return 0
    except (NotAllowed, latency.StartRefused) as e:
        print(f"ctf latency {args.action}: refused: {e}", file=sys.stderr)
        return 4
    except (EventError, ValueError, PlatformError) as e:
        print(f"ctf latency {args.action}: {e}", file=sys.stderr)
        return 2
    raise AssertionError(f"unhandled action {args.action!r}")


def _gate(prof):
    from ..platform import get_adapter
    return get_adapter(prof)


def _outcome_dict(o) -> dict:
    d = dataclasses.asdict(o)
    d["info"] = dataclasses.asdict(o.info) if o.info is not None else None
    return d


def _open(args, prof) -> int:
    from ..platform import latency
    gate = _gate(prof)
    res = latency.open_release(
        gate, args.challenge, anchor=_when(args.at) if args.at else None, start=not args.no_start,
        dest=Path(args.dest).expanduser().resolve() if args.dest else None,
        **_kw(args, lead_s="lead", connections="connections", timeout_s="timeout",
              alert_after_s="alert_after"))
    if args.json:
        print(json.dumps({"challenge": res.challenge, "run": res.run, "listed": res.listed, "ok": res.ok,
                          "start": _outcome_dict(res.start) if res.start else None,
                          "files": [str(p) for p in res.files], "errors": res.errors,
                          "phases": res.phases}, indent=1, default=str))
    else:
        print(f"open {res.challenge} (run {res.run})")
        for r in res.phases:
            rel = f"+{r['rel_s']:.3f}s" if r.get("rel_s") is not None else _utc(r["t0"])
            print(f"  {r['phase']:<16} {rel:>12}  {r['dur_s'] * 1000:8.1f} ms  {'ok' if r['ok'] else r['error']}")
        if res.listed is False:
            print(f"  {res.challenge} is not on the list")
        if res.start is not None:
            print(f"  attempt: {res.start.state} after {res.start.posts} POST(s), {res.start.polls} status read(s)"
                  + (f"; {res.start.note}" if res.start.note else ""))
        for name, e in res.errors.items():
            print(f"  ERROR {name}: {e}")
        for p in res.files:
            print(f"  file {p}")
    return 0 if res.ok else 1


def _start(args, prof) -> int:
    from ..platform import latency
    gate = _gate(prof)
    guard = latency.StartGuard(gate, **_kw(args, alert_after_s="alert_after", max_posts="max_posts"))
    if args.no_wait:
        out = guard.start(args.challenge)
    else:
        out = guard.ensure_ready(args.challenge, **_kw(args, timeout_s="timeout"))
    if args.json:
        print(json.dumps(_outcome_dict(out), indent=1, default=str))
    else:
        conn = out.info.connection_info if out.info is not None else ""
        print(f"{out.challenge}: {out.state} ({'POST sent' if out.posted else 'no POST'}; {out.posts} POST(s), "
              f"{out.polls} status read(s){', alerted' if out.alerted else ''})"
              + (f"; {out.note}" if out.note else ""))
        if conn:
            print(conn)
    return 0 if out.state == "ready" or (args.no_wait and out.state in ("preparing", "unknown")) else 1


def _pending(args, wd: Path) -> int:
    from ..platform import latency
    if args.clear:
        had = latency.clear_start(wd, args.clear)
        print(f"start record of {args.clear} {'cleared' if had else 'not found'}")
        return 0
    recs = latency.pending_starts(wd)
    if args.json:
        print(json.dumps(recs, indent=1, sort_keys=True))
        return 0
    if not recs:
        print(f"no start records in {latency.phases_path(wd).parent}")
    for cid, r in sorted(recs.items()):
        print(f"{cid}: {r.get('state')}  posts {r.get('posts', 0)} (unanswered {r.get('open_posts', 0)})  "
              f"polls {r.get('polls', 0)}  first POST {_utc(r.get('first_post'))}  last POST "
              f"{_utc(r.get('last_post'))}" + (f"  ALERTED {_utc(r['alerted'])}" if r.get("alerted") else ""))
    return 0


def _phases(args, wd: Path) -> int:
    from ..platform import latency, wire
    since = _when(args.since) if args.since else None
    rows, bad = latency.read_phases(wd, since=since)
    jrows, jbad = wire.read_journal(wd, since=since - 1 if since is not None else None)
    rep = latency.run_report(rows, jrows, challenge=args.challenge)
    if bad or jbad:
        print(f"ctf latency phases: {bad} unreadable phases line(s), {jbad} unreadable journal line(s) "
              "skipped", file=sys.stderr)
    if args.json:
        print(json.dumps(rep, indent=1))
        return 0
    if not rep:
        print(f"no phases in {latency.phases_path(wd)}")
    for r in rep:
        first = f"+{r['first_request_rel_s']:.3f}s" if r["first_request_rel_s"] is not None else "-"
        print(f"{r['challenge']} [{r['mode']}] run {r['run']}: anchor {_utc(r['anchor'])}, first request {first}, "
              f"open {r['open_s'] if r['open_s'] is not None else '-'} s, {r['requests']} request(s) held "
              f"{r['held_s']:g} s, {r['bytes']} bytes")
        for name, p in r["phases"].items():
            rel = f"+{p['rel_s']:.3f}s" if p.get("rel_s") is not None else "-"
            print(f"  {name:<16} {rel:>12}  {(p.get('dur_s') or 0) * 1000:8.1f} ms"
                  + ("" if p.get("ok") else f"  FAILED {p.get('error')}"))
        if r["missing"]:
            print(f"  not measured: {', '.join(r['missing'])}")
    return 0


def _fmt(v) -> str:
    return "-" if v is None else f"{v:.3f}"


def _bank_counts(prof, overrides, modes) -> dict:
    from ..platform import gmtiming
    counts = gmtiming.bank_counts(prof.slug, modes) if prof.platform.kind == "gamemaster" else {}
    for mode, s in latency_parse_banks(overrides).items():
        counts[mode] = s
    return counts


def latency_parse_banks(items) -> dict:
    out = {}
    for it in items:
        mode, sep, n = str(it).partition("=")
        if not sep or not mode.strip() or not n.strip().isdigit():
            raise ValueError(f"--bank {it!r} is not MODE=N (e.g. web/time_trial=1300)")
        out[mode.strip()] = int(n)
    return out


def _floors(args, prof, wd: Path) -> int:
    from ..platform import latency, wire
    since = _when(args.since) if args.since else None
    records = latency.parse_records(args.record)
    rows, bad = latency.read_phases(wd, since=since)
    jrows, jbad = wire.read_journal(wd, since=since)
    base = latency.floor_table(rows, jrows, kind=prof.platform.kind, records=records)
    banks = _bank_counts(prof, args.bank, [r["mode"] for r in base])
    table = (latency.floor_table(rows, jrows, kind=prof.platform.kind, records=records, bank_counts=banks)
             if banks else base)
    if bad or jbad:
        print(f"ctf latency floors: {bad} unreadable phases line(s), {jbad} unreadable journal line(s) "
              "skipped", file=sys.stderr)
    if args.write:
        p = latency.write_floors(wd, table)
        print(f"floors written to {p}", file=sys.stderr)
    if args.json:
        print(json.dumps(table, indent=1))
        return 0
    if not table:
        print(f"no timings in {wire.wire_dir(wd)}: run a practice or base opening first")
        return 0
    print(f"{'mode':<22} {'runs':>4} {'open floor':>10} {'submit':>8} {'floor':>8}  ops (min/p50 s)")
    for r in table:
        ops = ", ".join(f"{op} {_fmt(s['min'])}/{_fmt(s['p50'])} n{s['n']}" for op, s in r["ops"].items())
        print(f"{r['mode']:<22} {r['runs']:>4} {_fmt(r['open_floor_s']):>10} {_fmt(r['submit_floor_s']):>8} "
              f"{_fmt(r['floor_s']):>8}  {ops or '-'}")
        if "bank" in r:
            b = r["bank"]
            print(f"  bank-submit floor: {b['count']} ids x {_fmt(b['submit_rtt'].get('min'))} s = "
                  f"{_fmt(b['bank_floor_min_s'])} s (p50 {_fmt(b['bank_floor_p50_s'])} s)")
        if "record_s" in r:
            print(f"  record {r['record_s']:g} s: {r['verdict']}")
    return 0
