"""`python -m ctf show <sub>` — the operator read kit (B-210): one command, stable compact output, in place of
the throwaway readers, replay and compare scripts agents kept rewriting (replay_all.py, cmp.py, timing.py,
prof.py, dbg.py and thousands of inline `python -c` JSON readers).

It is one command with B-257's `ctf state`: every `ctf state` subcommand works here unchanged (attempt,
result, start, key, answers, ladder, proofs, conventions, routes, qdiff, status, journal, lint; library
`ctf.lanestate`), and `ctf show` adds:

    question [CID] [--root R|--dir D|--file BODY] [--day N] [--id QID]...   the questions, one line each
    keys     [CID] [--root R|--dir D] [--day N]       key.json beside the submitted answers (= ! -)
    verdicts [CID] [--status S] [--since T] [--kind EV]... [--limit N] [--root R|--dir D]
                                                     the verdict ledger (platform.submit, submit.done,
                                                     hof.result); with a folder also its verdicts.jsonl
    timeline [CID] [--lane L] [--since T] [--limit N]  a challenge's (or a lane's) ledger records in order
    hcfg     SAMPLE... [--plain-only] [--json]        every HCFG container: carrier, section, offset,
                                                     encoding layer, key, CRC, member names
    members  DELIVERY [--prefix dNN] [--json]         a delivery's members in archive order: size, sha256, day
    replay   --tree A [--tree B ...] (--lane L | --engine ID --input F...) [--repeat K] [--case NAME]...
             [--lines REGEX] [--cprofile [--profile-dir D]] [--out FILE.json] [--cap S] [--guard M]
                                                     fresh-process replay per attempt, per-attempt wall and
                                                     CPU, answer diff across trees (exit 1 on a difference)
    lane-profile --lane L [--tree T] [--case NAME]... [--top N]
                                                     the lane's cases under cProfile: CPU per case, top functions

Ledger subcommands read <workdir>/ledger.jsonl (--workdir, else the event's; --event picks the event).
No network, no model; replay runs engines (never a challenge binary) under the intake network guard. Exit
codes: 0 ok, 1 a replay difference (or lint findings), 2 a missing or unreadable input or bad argument.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .. import lanestate as _ls
from .. import opkit as _ok
from . import state as _state

HELP = ("operator read kit: every `ctf state` read plus question, keys, verdict ledger, timeline, hcfg and "
        "member dumps, tree replay/compare with per-attempt CPU and cProfile, lane profile")

_OWN = ("question", "keys", "verdicts", "timeline", "hcfg", "members", "replay", "lane-profile")


def _locator(sp: argparse.ArgumentParser) -> None:
    sp.add_argument("cid", nargs="?", help="challenge id (located under --root/$CTF_REAL_CHALLENGES)")
    sp.add_argument("--root", type=Path, help="challenges root (default: $CTF_REAL_CHALLENGES)")
    sp.add_argument("--dir", type=Path, help="the challenge folder directly (skips id lookup)")
    sp.add_argument("--day", type=int, help="look only under <root>/day-NN")


def _ledger_opts(sp: argparse.ArgumentParser) -> None:
    sp.add_argument("--event", help="event slug (default: the current event)")
    sp.add_argument("--workdir", type=Path, help="event workdir holding ledger.jsonl (default: the event's)")
    sp.add_argument("--since", help="epoch seconds, ISO-8601 with offset, or <N>s/m/h ago")
    sp.add_argument("--limit", type=int, default=_ok.DEFAULT_LIMIT, help="show at most the last N (0: all)")
    sp.add_argument("--json", action="store_true", help="one JSON record per line")


def add_arguments(p: argparse.ArgumentParser) -> None:
    sub = _state.add_arguments(p, skip=("verdicts",))

    q = sub.add_parser("question", help="the challenge's questions: id, kind, syntax, literal none, accepted")
    _locator(q)
    q.add_argument("--file", type=Path, help="read the questions from this body (start/attempt/status JSON)")
    q.add_argument("--id", dest="ids", action="append", default=[], help="only this question id (repeatable)")

    k = sub.add_parser("keys", help="key.json beside the submitted answers, per answer id")
    _locator(k)

    v = sub.add_parser("verdicts", help="the verdict ledger: platform.submit, submit.done, hof.result")
    _locator(v)
    _ledger_opts(v)
    v.add_argument("--status", help="only records with this status (correct, incorrect, ...)")
    v.add_argument("--kind", action="append", default=[], choices=_ok.VERDICT_EVENTS,
                   help="only this record kind (repeatable)")

    t = sub.add_parser("timeline", help="a challenge's (or lane's) ledger records, oldest first")
    t.add_argument("cid", nargs="?", help="challenge id (`9` also matches `9#a`)")
    t.add_argument("--lane", help="only records of this lane (`lane` field or engine id prefix)")
    t.add_argument("--kind", action="append", default=[], help="only this ledger event type (repeatable)")
    _ledger_opts(t)

    h = sub.add_parser("hcfg", help="dump every HCFG container of a sample set")
    h.add_argument("samples", nargs="+", type=Path, help="sample files, folders, or delivery zips")
    h.add_argument("--plain-only", action="store_true", help="only the lane's single-byte XOR layout")
    h.add_argument("--json", action="store_true")

    m = sub.add_parser("members", help="a delivery's members in archive order")
    m.add_argument("delivery", type=Path, help="a delivery zip or an unpacked folder")
    m.add_argument("--prefix", help="only this day's members (e.g. d03), by the lane's own rule")
    m.add_argument("--json", action="store_true")

    r = sub.add_parser("replay", help="replay a lane (or inputs) on one or more trees and compare")
    r.add_argument("--tree", action="append", default=[], required=True,
                   help="a checkout (repeatable; labels A, B, ... or LABEL=PATH)")
    _replay_opts(r)
    r.add_argument("--repeat", type=int, default=1, help="attempts per case per tree (fresh process each)")
    r.add_argument("--engine", help="replay this engine on --input files instead of a lane's set")
    r.add_argument("--input", action="append", default=[], type=Path, help="an input file (with --engine)")
    r.add_argument("--lines", help="compare only stdout lines matching this regex")
    r.add_argument("--cprofile", action="store_true", help="run each attempt under cProfile")
    r.add_argument("--profile-dir", type=Path, help="keep the .prof files here (with --cprofile)")
    r.add_argument("--out", type=Path, help="write answers and times (attempts + diff) to this JSON file")
    r.add_argument("--json", action="store_true", help="print the report as JSON")

    lp = sub.add_parser("lane-profile", help="profile a lane's cases: CPU per case and top functions")
    lp.add_argument("--tree", action="append", default=[], help="the checkout (default: this one)")
    _replay_opts(lp)
    lp.add_argument("--top", type=int, default=15, help="functions to list")
    lp.add_argument("--profile-dir", type=Path, help="keep the .prof files here")


def _replay_opts(sp: argparse.ArgumentParser) -> None:
    sp.add_argument("--lane", help="the lane whose regression set to replay")
    sp.add_argument("--case", dest="cases", action="append", default=[], help="only this case (repeatable)")
    sp.add_argument("--workdir", type=Path, help="event workdir: event cases and run folders (default: the event's)")
    sp.add_argument("--cap", type=float, default=60.0, help="seconds per attempt at idle load (load-scaled)")
    sp.add_argument("--guard", default="auto", choices=("auto", "os", "hook"), help="intake network guard")


def _emit(lines) -> int:
    for ln in lines:
        print(ln)
    return 0


def _dir(args) -> Path:
    if args.day is None or args.dir is not None:
        return _ls.resolve_challenge_dir(args.cid, root=args.root, direct=args.dir)
    from .. import paths as _paths
    base = args.root if args.root is not None else _paths.saved_challenges_root()
    if base is None:
        raise _ls.LaneStateError("--day needs a challenges root: pass --root DIR or set $CTF_REAL_CHALLENGES")
    day = Path(base).expanduser() / f"day-{args.day:02d}"
    if not day.is_dir():
        raise _ls.LaneStateError(f"--day {args.day}: no folder {day}")
    if not args.cid:
        raise _ls.LaneStateError("--day needs a challenge id")
    hits = sorted(c for c in day.iterdir() if c.is_dir() and (c.name == args.cid or c.name.endswith("-" + args.cid)))
    if len(hits) != 1:
        what = "no challenge folder" if not hits else "ambiguous: " + ", ".join(h.name for h in hits) + ";"
        raise _ls.LaneStateError(f"id {args.cid!r} under {day}: {what} pass --dir")
    return hits[0]


def _records(args) -> list[dict]:
    from .. import ledger, paths
    wd = Path(args.workdir).expanduser() if args.workdir else paths.workdir(args.event)
    p = ledger.path(wd)
    if not p.exists():
        raise FileNotFoundError(f"no ledger at {p}")
    return list(ledger.read(wd))


def run(args: argparse.Namespace) -> int:
    if args.sub not in _OWN:
        return _state.run(args)
    from ..event import EventError
    from ..treereplay import ReplayError
    try:
        return _RUN[args.sub](args)
    except (_ls.LaneStateError, _ok.OpKitError, ReplayError, EventError, FileNotFoundError, ValueError) as e:
        print(f"ctf show {args.sub}: {e}", file=sys.stderr)
        return 2


def _question(args) -> int:
    if args.file is not None:
        src, body = _ok.question_body(file=args.file)
    else:
        src, body = _ok.question_body(_dir(args))
    return _emit(_ok.question_lines(body, args.ids, source=src.name))


def _keys(args) -> int:
    return _emit(_ok.keys_lines(_dir(args)))


def _verdicts(args) -> int:
    folder = args.dir is not None or args.root is not None or args.day is not None
    if folder and args.json:
        raise _ok.OpKitError("--json prints the ledger only; read the folder's verdicts.jsonl without --json")
    since = _ok.parse_since(args.since)
    rows = _ok.verdict_rows(_records(args), cid=args.cid, status=args.status, since=since,
                            slug=args.event, events=tuple(args.kind) or _ok.VERDICT_EVENTS)
    if args.json:
        for r in rows:
            print(json.dumps(_redact(r), sort_keys=True))
    else:
        _emit(_ok.verdict_lines(rows, limit=args.limit))
    if folder:
        # the archived Game Master's per-challenge verdicts.jsonl, when the folder holds one (B-257 reader)
        _emit(_ls.read_verdicts(_dir(args)))
    return 0


def _redact(r: dict) -> dict:
    out = {k: v for k, v in r.items() if k not in ("flag", "flag_sha256")}
    ref = _ok.flag_ref(r)
    if ref:
        out["flag_ref"] = ref
    return out


def _timeline(args) -> int:
    since = _ok.parse_since(args.since)
    rows = _ok.timeline_rows(_records(args), cid=args.cid, lane=args.lane, since=since,
                             events=tuple(args.kind) or None)
    if args.json:
        for r in rows:
            print(json.dumps(_redact(r), sort_keys=True))
        return 0
    label = args.cid if args.cid else f"lane {args.lane}"
    return _emit(_ok.timeline_lines(rows, label=label, limit=args.limit))


def _hcfg(args) -> int:
    rows = _ok.hcfg_rows(args.samples, others=not args.plain_only)
    if args.json:
        print(json.dumps(rows, indent=1, sort_keys=True))
        return 0
    return _emit(_ok.hcfg_lines(rows))


def _members(args) -> int:
    rows = _ok.member_rows(args.delivery, prefix=args.prefix)
    if args.json:
        print(json.dumps(rows, indent=1, sort_keys=True))
        return 0
    return _emit(_ok.member_lines(rows, label=args.delivery.name, prefix=args.prefix))


def _replay(args) -> int:
    from .. import treereplay as _tr
    rep = _tr.replay(args.tree, lane=args.lane, engine=args.engine, inputs=args.input, repeat=args.repeat,
                     workdir=args.workdir, cap=args.cap, guard=args.guard, lines=args.lines, cases=args.cases,
                     cprofile=args.cprofile, profile_dir=args.profile_dir)
    d = _tr.diff(rep)
    if args.out is not None:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps({**rep.to_dict(), "diff": [c.to_dict() for c in d]}, indent=1) + "\n",
                            encoding="utf-8")
    if args.json:
        print(json.dumps({**rep.to_dict(), "diff": [c.to_dict() for c in d]}, indent=1))
    else:
        _emit(_tr.render(rep, d))
        if args.cprofile:
            _emit(_tr.lane_profile(rep))
        if args.out is not None:
            print(f"wrote {args.out}")
    return 1 if _tr.has_difference(d) else 0


def _lane_profile(args) -> int:
    from .. import paths as _paths
    from .. import treereplay as _tr
    if not args.lane:
        raise _tr.ReplayError("lane-profile needs --lane L")
    trees = args.tree or [str(_paths.repo_root())]
    if len(trees) != 1:
        raise _tr.ReplayError("lane-profile profiles one tree; compare trees with `ctf show replay`")
    rep = _tr.replay(trees, lane=args.lane, repeat=1, workdir=args.workdir, cap=args.cap, guard=args.guard,
                     cases=args.cases, cprofile=True, profile_dir=args.profile_dir)
    _emit(_tr.lane_profile(rep, top=args.top))
    bad = [a for a in rep.attempts if a.status not in (_tr.OK, _tr.NOT_RUN)]
    for a in bad:
        print(f"  note: {a.case}: {a.status} {a.reason}")
    return 0


_RUN = {"question": _question, "keys": _keys, "verdicts": _verdicts, "timeline": _timeline, "hcfg": _hcfg,
        "members": _members, "replay": _replay, "lane-profile": _lane_profile}
