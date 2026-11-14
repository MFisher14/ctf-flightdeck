"""ctf spend -- build and review spend governors (B-202, ctf/spendgov.py).

    python -m ctf spend status [--json]
        each phase's cap and spend, each mode's budget and spend, every investigation
    python -m ctf spend cap PHASE --usd N [--period day|event] --reason R      (interactive)
        the player's cap on one phase (solve build verify doc orchestrate guardian other)
    python -m ctf spend decide MODE --usd N [--challenge GLOB ...] [--minutes N] [--value TEXT] --reason R
        (interactive) the player's budget for a mode (speedrun is built in), decided before its spend;
        --minutes is an optional time box from the mode's first spend
    python -m ctf spend gate [--phase P] [--mode M] [--challenge ID] [--json]
        may this work start now? exit 0 yes, 3 held (no cap / budget decided yet, or spent)
    python -m ctf spend tier PATH ... [--root DIR]
        each file's review tier and the scope's (its riskiest file's); an absolute path is taken
        relative to --root (default: this repo's root)
    python -m ctf spend review-plan --tasks FILE [--root DIR] [--max-agents N] [--json]
        the review dispatcher's dry run: tier and stopping-rule step per task, duplicates folded,
        spawns capped; prints the agent count before anything starts
    python -m ctf spend next SCOPE PATTERN ... [--root DIR]
        the stopping rule for one scope: review | stop | fix | escalate
    python -m ctf spend record SCOPE PATTERN ... (--findings SEV=N[,SEV=N] | --findings-file JSON)
            [--root DIR] [--by WHO]
        one finished review round (a review.round ledger record and the reviewed snapshot); with
        --findings-file the severities are counted from the reviewer's JSON output
    python -m ctf spend diff SCOPE [PATTERN ...] [--root DIR] [--json]
        the standing diff audit: what changed since the scope's last review round
    python -m ctf spend investigate open ID --question Q --metric M --threshold T --minutes N --usd N --by WHO
    python -m ctf spend investigate close ID --answer X --by WHO [--note T]
    python -m ctf spend investigate status [ID] [--json]

Common: --event SLUG, --workdir DIR, --now WHEN (epoch or ISO-8601). `cap` and `decide` are the
player's decisions: they refuse without an interactive terminal and ask for the phase or mode to be
typed back, so no agent sets its own cap.

Exit codes: 0 ok / allowed / clean; 1 diff found changes; 2 a named error; 3 held (gate), a person is
needed (review-plan, next: escalate or over the spawn cap), or an investigation hit its time box or
dollar cap.
"""
from __future__ import annotations

import argparse
import getpass
import json
import sys
import time
from pathlib import Path

HELP = "build and review spend governors: phase caps, mode budgets, review stopping rule, investigations (B-202)"
HELD_EXIT = 3


class SpendCLIError(RuntimeError):
    pass


def add_arguments(p: argparse.ArgumentParser) -> None:
    from ..spendgov import PERIODS, PHASES
    p.add_argument("--event", help="event slug (default: the current event)")
    p.add_argument("--workdir", help="the event workdir (default: the event's)")
    p.add_argument("--now", help="as of this time (epoch seconds or ISO-8601; default now)")
    sp = p.add_subparsers(dest="action", required=True)
    st = sp.add_parser("status", help="caps, mode budgets and investigations with their spend")
    st.add_argument("--json", action="store_true")
    ca = sp.add_parser("cap", help="the player's cap on one phase (interactive)")
    ca.add_argument("phase", choices=PHASES)
    ca.add_argument("--usd", type=float, required=True)
    ca.add_argument("--period", choices=PERIODS, default="day")
    ca.add_argument("--reason", required=True)
    de = sp.add_parser("decide", help="the player's budget for a mode, before its spend (interactive)")
    de.add_argument("mode")
    de.add_argument("--usd", type=float, required=True)
    de.add_argument("--challenge", action="append", default=[], help="challenge id glob (custom modes; repeatable)")
    de.add_argument("--value", help="what the player decided a board place (or the mode) is worth")
    de.add_argument("--minutes", type=float, help="optional time box: wall-clock minutes from the mode's first spend")
    de.add_argument("--reason", required=True)
    ga = sp.add_parser("gate", help="may this work start now? (exit 3 when held)")
    ga.add_argument("--phase")
    ga.add_argument("--mode")
    ga.add_argument("--challenge")
    ga.add_argument("--json", action="store_true")
    ti = sp.add_parser("tier", help="review tier of each file and of the scope")
    ti.add_argument("paths", nargs="+")
    ti.add_argument("--root", help="root an absolute path is made relative to (default: this repo's root)")
    rp = sp.add_parser("review-plan", help="dry-run a review wave: dedupe, stopping rule, spawn cap")
    rp.add_argument("--tasks", required=True, help="JSON list of {name, scope: [path or glob, ...]}")
    rp.add_argument("--root", default=".", help="repo root the scopes are relative to (default .)")
    rp.add_argument("--max-agents", type=int, default=None, help="review agents the wave may start")
    rp.add_argument("--json", action="store_true")
    nx = sp.add_parser("next", help="the stopping rule for one scope")
    nx.add_argument("scope")
    nx.add_argument("patterns", nargs="+")
    nx.add_argument("--root", default=".")
    nx.add_argument("--json", action="store_true")
    rc = sp.add_parser("record", help="record a finished review round")
    rc.add_argument("scope")
    rc.add_argument("patterns", nargs="+")
    fg = rc.add_mutually_exclusive_group(required=True)
    fg.add_argument("--findings", help="SEV=N[,SEV=N] (info low medium high critical); 'none' for none")
    fg.add_argument("--findings-file", help="the reviewer's JSON output (a findings list, or an object with "
                                            "one); each finding's severity is counted")
    rc.add_argument("--root", default=".")
    rc.add_argument("--by")
    di = sp.add_parser("diff", help="what changed since the scope's last review round")
    di.add_argument("scope")
    di.add_argument("patterns", nargs="*", help="the scope now (default: the files that round reviewed)")
    di.add_argument("--root", default=".")
    di.add_argument("--json", action="store_true")
    iv = sp.add_parser("investigate", help="time-boxed investigations with a numeric question")
    ivs = iv.add_subparsers(dest="inv_action", required=True)
    io = ivs.add_parser("open")
    io.add_argument("id")
    io.add_argument("--question", required=True)
    io.add_argument("--metric", required=True, help="what is measured, with its unit")
    io.add_argument("--threshold", type=float, required=True, help="the value that decides the question")
    io.add_argument("--minutes", type=float, required=True, help="the time box")
    io.add_argument("--usd", type=float, required=True, help="the dollar cap (spend source investigation:<id>)")
    io.add_argument("--by", required=True)
    ic = ivs.add_parser("close")
    ic.add_argument("id")
    ic.add_argument("--answer", type=float, required=True, help="the measured value")
    ic.add_argument("--by", required=True)
    ic.add_argument("--note")
    ist = ivs.add_parser("status")
    ist.add_argument("id", nargs="?")
    ist.add_argument("--json", action="store_true")


def _profile(args):
    from .. import event
    return event.load(args.event) if args.event else event.current()


def _workdir(args, prof) -> Path:
    from .. import paths
    if args.workdir:
        return Path(args.workdir).expanduser().resolve()
    return paths.workdir(prof.slug)


def _recs(wd: Path) -> list[dict]:
    from .. import ledger
    return list(ledger.read(wd))


def _require_human(what: str, name: str) -> str:
    """The player's decision: an interactive terminal and the name typed back."""
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        raise PermissionError(f"`ctf spend {what}` is the player's decision: run it yourself in an interactive "
                              "terminal (no flag bypasses this)")
    typed = input(f"Type {name!r} to confirm the {what}: ").strip()
    if typed != name:
        raise PermissionError(f"confirmation did not match {name!r}; nothing changed")
    return getpass.getuser() or "player"


def parse_findings(text: str) -> dict[str, int]:
    from ..spendgov import SpendGovError, check_findings
    text = text.strip()
    if text.lower() == "none":
        return {}
    out: dict[str, int] = {}
    for part in text.split(","):
        sev, sep, n = part.partition("=")
        if not sep or not n.strip().isdigit():
            raise SpendGovError(f"--findings: {part!r} is not SEV=N (e.g. high=1,low=2, or none)")
        out[sev.strip()] = out.get(sev.strip(), 0) + int(n)
    return check_findings(out)


def read_findings_file(path: Path) -> dict[str, int]:
    """Severity counts from a reviewer's JSON output file (spendgov.count_findings)."""
    from ..spendgov import SpendGovError, count_findings
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise SpendGovError(f"--findings-file {path}: not JSON ({e})") from None
    try:
        return count_findings(data)
    except SpendGovError as e:
        raise SpendGovError(f"--findings-file {path}: {e}") from None


def _money(v: float | None) -> str:
    return "-" if v is None else f"${v:.2f}"


def _print_status(s) -> None:
    from .. import quota
    print(f"phases (day = midnight to midnight {s.tz}):")
    for p in s.phases:
        cap = "NO CAP (held)" if p.cap is None else f"cap {_money(p.cap.usd)}/{p.cap.period} by {p.cap.by}"
        print(f"  {p.phase:<12} spent {_money(p.spent)}  {cap}  left {_money(p.left)}  {p.state}")
    if s.uncategorized_usd:
        print(f"  uncategorized spend (no phase, counts toward no cap): {_money(s.uncategorized_usd)}")
    print("modes:")
    for m in s.modes:
        b = "NOT DECIDED (held)" if m.budget is None else (
            f"budget {_money(m.budget.usd)} by {m.budget.by}"
            + (f", {m.budget.minutes:g} min box" if m.budget.minutes is not None else "")
            + (f", worth: {m.budget.value}" if m.budget.value else ""))
        print(f"  {m.mode:<12} spent {_money(m.spent)}  {b}  {m.state}")
    if s.investigations:
        print("investigations:")
    for i in s.investigations:
        line = (f"  {i.inv_id:<12} {i.state:<11} {i.elapsed_min:.0f}/{i.minutes:g} min  {_money(i.spent)}/"
                f"{_money(i.usd)}  {i.metric} vs {i.threshold:g}: {i.question}")
        if i.answer is not None:
            line += f"  answer {i.answer:g} ({'at or above' if i.crossed else 'below'} the threshold)"
        print(line)
    print(f"as of {quota.fmt_time(s.now)}")


def run(args: argparse.Namespace) -> int:
    from .. import spendgov as sg
    from ..event import EventError
    from .quota import _when
    try:
        prof = _profile(args)
        wd = _workdir(args, prof)
        now = _when(args.now, time.time()) if args.now else time.time()
        tz = prof.allowance.tz
        a = args.action
        if a == "status":
            s = sg.status(workdir=wd, now=now, tz=tz)
            print(json.dumps(s.to_dict())) if args.json else _print_status(s)
            return 0
        if a == "cap":
            by = _require_human("cap", args.phase)
            sg.set_cap(args.phase, args.usd, period=args.period, by=by, reason=args.reason, workdir=wd)
            print(f"{args.phase}: cap ${args.usd:.2f} per {args.period}, set by {by}")
            return 0
        if a == "decide":
            by = _require_human("decide", args.mode)
            sg.decide_mode(args.mode, args.usd, by=by, reason=args.reason, challenges=args.challenge,
                           value=args.value, minutes=args.minutes, workdir=wd)
            print(f"{args.mode}: budget ${args.usd:.2f}, decided by {by}")
            return 0
        if a == "gate":
            v = sg.gate(phase=args.phase, mode=args.mode, challenge_id=args.challenge, workdir=wd, now=now, tz=tz)
            if args.json:
                print(json.dumps(v.to_dict()))
            else:
                print(("allowed: " if v.allowed else "HELD: ") + "; ".join(v.checked))
                for r in v.reasons:
                    print(f"  - {r}")
            return 0 if v.allowed else HELD_EXIT
        if a == "tier":
            troot = Path(args.root) if args.root else None
            for p in args.paths:
                print(f"{sg.tier_of(p, root=troot):<9} {p}")
            print(f"scope tier: {sg.scope_tier(args.paths, root=troot)}")
            return 0
        if a == "review-plan":
            try:
                data = json.loads(Path(args.tasks).read_text(encoding="utf-8"))
            except json.JSONDecodeError as e:
                raise sg.SpendGovError(f"{args.tasks}: not JSON ({e})") from None
            kw = {} if args.max_agents is None else {"max_agents": args.max_agents}
            plan = sg.plan_reviews(sg.load_tasks(data), Path(args.root), records=_recs(wd), **kw)
            if args.json:
                print(json.dumps(plan.to_dict()))
            else:
                for e in plan.entries:
                    extra = f" (in {e.covered_by})" if e.covered_by else ""
                    print(f"{e.action:<9} {e.name:<24} tier {e.tier:<8} agents {e.agents}  files {e.files}{extra}: "
                          f"{e.reason}")
                print(f"dry run: this wave would start {plan.agents} review agent(s) (cap {plan.max_agents})")
                if plan.needs_person:
                    print("a person decides the escalate / over_cap entries before more review starts")
            return HELD_EXIT if plan.needs_person else 0
        if a in ("next", "record"):
            root = Path(args.root)
            files = sg.resolve_scope(root, args.patterns)
            if a == "record":
                fnd = (parse_findings(args.findings) if args.findings is not None
                       else read_findings_file(Path(args.findings_file)))
                rec = sg.record_round(args.scope, root, files, fnd, by=args.by, workdir=wd)
                print(f"recorded round for {args.scope}: tier {rec['tier']}, {rec['files']} file(s), "
                      f"tree {rec['tree'][:12]}, findings {rec['findings'] or 'none'}")
                return 0
            tree = sg.tree_hash(sg.file_hashes(root, files))
            step = sg.next_step(sg.rounds(args.scope, _recs(wd)), sg.scope_tier(files), tree)
            print(json.dumps(step.__dict__) if args.json else f"{step.action}: {step.reason}")
            return HELD_EXIT if step.action == "escalate" else 0
        if a == "diff":
            root = Path(args.root)
            files = sg.resolve_scope(root, args.patterns) if args.patterns else None
            d = sg.diff_since_review(args.scope, root, files, workdir=wd)
            if args.json:
                print(json.dumps(d.to_dict()))
            else:
                print(f"{args.scope}: {'no change' if d.clean else 'changed'} since the last review round "
                      f"({d.unchanged} unchanged)")
                for label, fs in (("added", d.added), ("changed", d.changed), ("removed", d.removed)):
                    for f in fs:
                        print(f"  {label:<8} {f}")
            return 0 if d.clean else 1
        if a == "investigate":
            if args.inv_action == "open":
                sg.open_investigation(args.id, args.question, metric=args.metric, threshold=args.threshold,
                                      minutes=args.minutes, usd=args.usd, by=args.by, workdir=wd)
                print(f"opened {args.id}: {args.minutes:g} min, ${args.usd:.2f}; charge its spend with "
                      f"source {sg.INVESTIGATION_SOURCE}{args.id}")
                return 0
            if args.inv_action == "close":
                sg.close_investigation(args.id, args.answer, by=args.by, note=args.note, workdir=wd)
                st = sg.investigation(args.id, _recs(wd), now=now)
                print(f"closed {args.id}: {st.metric} = {args.answer:g} "
                      f"({'at or above' if st.crossed else 'below'} {st.threshold:g})")
                return 0
            recs = _recs(wd)
            sts = [sg.investigation(args.id, recs, now=now)] if args.id else sg.investigations(recs, now=now)
            for s in sts:
                print(json.dumps(s.to_dict()) if args.json else
                      f"{s.inv_id}: {s.state}  {s.elapsed_min:.0f}/{s.minutes:g} min  ${s.spent:.2f}/${s.usd:.2f}")
            return HELD_EXIT if any(s.state in ("over_time", "over_budget") for s in sts) else 0
        raise SpendCLIError(f"unknown action {a!r}")
    except PermissionError as e:
        print(f"ctf spend: refused: {e}", file=sys.stderr)
        return 2
    except (sg.SpendGovError, SpendCLIError, EventError, ValueError, OSError) as e:
        print(f"ctf spend: {e}", file=sys.stderr)
        return 2
