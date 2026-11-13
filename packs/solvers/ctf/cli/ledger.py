"""ctf ledger replay | waves | summary | mark | spend -- the event ledger as a wave replay (B-101).

    python -m ctf ledger replay [--wave W] [--t0 WHEN] [--json]   second-by-second ledger of one wave
    python -m ctf ledger waves                                     the waves in the ledger
    python -m ctf ledger summary [--wave W] [--json]               spend by category, dollars/solve,
                                                                   hard-tail share, layer-1 close rate
    python -m ctf ledger mark STAGE --challenge ID [--by WHO] [--layer L] [--note TEXT]
    python -m ctf ledger mark wave_open --wave W [--announced WHEN]
    python -m ctf ledger spend --usd N --tok N --category C [--source S] [--note TEXT]

The ledger is <workdir>/ledger.jsonl of the event (--workdir, else $CTF_WORKDIR, else the event's;
--event picks the event). `summary` needs the event profile: the hard tail is the budget meter's
high-value-tail rule. See ctf/replay.py for how records become stages and waves.

Exit codes: 0 ok, 2 an error (no ledger, unknown wave, bad stage, no event profile).
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import sys
from pathlib import Path

HELP = "the event ledger as a second-by-second wave replay, live spend summary, and stage marks"


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("--event", help="event slug (default: the current event)")
    p.add_argument("--workdir", help="the event workdir holding ledger.jsonl (default: the event's)")
    sp = p.add_subparsers(dest="action", required=True)
    rp = sp.add_parser("replay", help="the second-by-second ledger of one wave")
    rp.add_argument("--wave", help="wave label (default: the latest)")
    rp.add_argument("--t0", help="time the wave from this instant (epoch seconds or ISO-8601 with offset)")
    rp.add_argument("--json", action="store_true")
    sp.add_parser("waves", help="list the waves in the ledger")
    su = sp.add_parser("summary", help="spend by category, dollars/solve, hard-tail share, layer-1 close rate")
    su.add_argument("--wave", help="only this wave's challenges")
    su.add_argument("--json", action="store_true")
    mk = sp.add_parser("mark", help="record a stage event now")
    from ..stages import SPEND_CATEGORIES, STAGES
    mk.add_argument("stage", choices=STAGES)
    mk.add_argument("--challenge", help="challenge id (every stage but wave_open)")
    mk.add_argument("--wave", help="wave label (wave_open; optional on detect)")
    mk.add_argument("--announced", help="wave_open: the published start (epoch seconds or ISO-8601 with offset)")
    mk.add_argument("--by", help="who or what reached the stage (dispatcher, agent:codex, engine:<id>, ...)")
    mk.add_argument("--layer", choices=("layer1", "agent", "human"), help="accepted: who closed it")
    mk.add_argument("--note")
    sd = sp.add_parser("spend", help="record spend that belongs to no challenge (build, verify, doc, ...)")
    sd.add_argument("--usd", type=float, required=True)
    sd.add_argument("--tok", type=int, required=True, help="token count")
    sd.add_argument("--category", required=True, choices=SPEND_CATEGORIES)
    sd.add_argument("--source", help="where the figure came from (e.g. tools.ledger price)")
    sd.add_argument("--note")


def parse_when(text: str) -> float:
    """Epoch seconds, or ISO-8601 with a UTC offset (a naive time is refused: no silent zone guess)."""
    t = text.strip()
    try:
        return float(t)
    except ValueError:
        pass
    try:
        when = _dt.datetime.fromisoformat(t.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError(f"{text!r}: not epoch seconds or ISO-8601") from None
    if when.tzinfo is None:
        raise ValueError(f"{text!r} has no UTC offset; write e.g. 2026-11-07T08:00-05:00")
    return when.timestamp()


def _workdir(args) -> Path:
    from .. import paths
    if args.workdir:
        return Path(args.workdir).expanduser().resolve()
    return paths.workdir(args.event)


def _records(wd: Path) -> list[dict]:
    from .. import ledger
    p = ledger.path(wd)
    if not p.exists():
        raise FileNotFoundError(f"no ledger at {p}")
    return list(ledger.read(wd))


def run(args: argparse.Namespace) -> int:
    from .. import replay, stages
    from ..event import EventError
    try:
        wd = _workdir(args)
        if args.action == "mark":
            return _mark(args, wd)
        if args.action == "spend":
            rec = stages.record_spend(args.usd, args.tok, args.category, source=args.source, note=args.note,
                                      workdir=wd)
            print(f"recorded {rec['category']} spend ${rec['usd']:.2f} in {wd / 'ledger.jsonl'}")
            return 0
        recs = _records(wd)
        if args.action == "waves":
            wl = replay.waves(recs)
            if not wl:
                print("no wave_open records in the ledger (replay times one wave from the first stage)")
                return 0
            member = replay.assign(replay.stage_events(recs), wl)
            for w in wl:
                n = sum(1 for lab in member.values() if lab == w.label)
                print(f"{w.label:<8} T0 {replay._utc(w.t0)}{' (announced)' if w.announced is not None else ''}"
                      f"  listed {w.count if w.count is not None else '-'}  challenges {n}")
            return 0
        if args.action == "replay":
            t0 = parse_when(args.t0) if args.t0 else None
            r = replay.wave_replay(recs, args.wave, t0=t0)
            print(json.dumps(r.to_dict(), indent=1) if args.json else replay.render(r))
            return 0
        if args.action == "summary":
            from .. import budget, event
            prof = event.load(args.event) if args.event else event.current()
            meter = budget.LedgerMeter(prof, workdir=wd, on_cap=lambda st, p: None)
            s = replay.summarize(recs, tail_of=lambda c: meter.status(c).timer_applies, wave=args.wave)
            print(json.dumps(s.to_dict(), indent=1) if args.json else replay.render_summary(s))
            return 0
    except (EventError, FileNotFoundError, KeyError, ValueError) as e:
        msg = e.args[0] if isinstance(e, KeyError) and e.args else e
        print(f"ctf ledger {args.action}: {msg}", file=sys.stderr)
        return 2
    raise AssertionError(f"unhandled action {args.action!r}")


def _mark(args, wd: Path) -> int:
    from .. import stages
    fields: dict = {}
    for k in ("by", "layer", "note"):
        if getattr(args, k):
            fields[k] = getattr(args, k)
    if args.stage == "wave_open":
        if args.challenge:
            raise ValueError("wave_open is for the whole board; drop --challenge")
        if args.layer:
            raise ValueError("--layer goes with an accepted mark")
        ann = parse_when(args.announced) if args.announced else None
        label = args.wave
        if label is None:
            label = f"W{len(stages.wave_labels(wd)) + 1}"
        elif label in stages.wave_labels(wd):
            raise ValueError(f"wave {label!r} is already in the ledger")
        fields["wave"], fields["count"] = label, None
        if ann is not None:
            fields["announced"] = ann
        fields = {k: v for k, v in fields.items() if v is not None}
        rec = stages.mark("wave_open", workdir=wd, **fields)
    else:
        if args.announced:
            raise ValueError("--announced goes with wave_open")
        if args.layer and args.stage != "accepted":
            raise ValueError("--layer goes with an accepted mark")
        if args.wave:
            fields["wave"] = args.wave
        rec = stages.mark(args.stage, args.challenge, workdir=wd, **fields)
    print(f"{rec['event']} recorded at {rec['ts']:.3f}" + (f" for {rec['challenge_id']}" if rec.get("challenge_id") else ""))
    return 0
