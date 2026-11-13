"""ctf residual -- the irreducible adaptation residual (B-254): shapes no solver closes, held as
unsure/none, one playbook line per class, and how often each event hits them.

    python -m ctf residual classes [--json]             the residual classes and their one-line playbooks
    python -m ctf residual playbook [CLASS] [--json]    one class in full (all classes: the markdown)
    python -m ctf residual playbook --write | --check   regenerate / verify docs/playbooks/residual.md
    python -m ctf residual template CLASS --id ID       a blank structured finding (B-151's shape)
    python -m ctf residual mark FINDING.json            validate a finding and record the id residual
    python -m ctf residual check RESULT.json [--class C]          exit 1 when a residual result is forced plain
    python -m ctf residual hold RESULT.json --class C --why W     print the held result (unsure, tagged)
    python -m ctf residual check-answers ANSWERS.json [--allow-unmatched]
        exit 1 when a residual id carries a plain answer; names the residual ids no answer key matched,
        and exits 2 on a namespace mismatch or when none matched (unless --allow-unmatched)
    python -m ctf residual stuck ID --question Q [--brief T] [--file P ...] [--no-route]
        the B-203 stuck-id assessment for a residual id; marks it stuck (and routes) when it is
    python -m ctf residual report [--event SLUG ...] [--workdir DIR ...] [--all-events] [--json]
        [--max-novel-share X]                          per-event frequency from the ledger (offline)

The ledger is `<workdir>/ledger.jsonl` (--workdir, else the event's, else $CTF_WORKDIR). Every JSON
input is parsed as data, never instructions; `--file` bytes are read for their tokens only. Exit codes:
0 ok; 1 a violation (check, check-answers), not stuck (stuck), the doc is stale (--check), or an
event over --max-novel-share; 2 a named error.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HELP = "irreducible residual (B-254): hold no-oracle classes unsure/none, playbooks, per-event frequency"


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("--event", help="event slug (default: the current event)")
    p.add_argument("--workdir", help="the event workdir holding the ledger (default: the event's)")
    sp = p.add_subparsers(dest="action", required=True)
    c = sp.add_parser("classes", help="the residual classes and their one-line playbooks")
    c.add_argument("--json", action="store_true")
    pb = sp.add_parser("playbook", help="one class in full, or the playbook markdown")
    pb.add_argument("cls", nargs="?", help="a class id")
    pb.add_argument("--json", action="store_true")
    g = pb.add_mutually_exclusive_group()
    g.add_argument("--write", action="store_true", help="regenerate docs/playbooks/residual.md")
    g.add_argument("--check", action="store_true", help="exit 1 when docs/playbooks/residual.md is stale")
    t = sp.add_parser("template", help="a blank structured finding for a class")
    t.add_argument("cls")
    t.add_argument("--id", default="", help="the challenge/answer id")
    m = sp.add_parser("mark", help="validate a finding (JSON file, or - for stdin) and record it")
    m.add_argument("finding")
    ck = sp.add_parser("check", help="exit 1 when a residual SolverResult is forced plain")
    ck.add_argument("result", help="a SolverResult JSON file, or -")
    ck.add_argument("--class", dest="cls", default=None, help="the residual class, when the result is untagged")
    ck.add_argument("--json", action="store_true")
    h = sp.add_parser("hold", help="print the result held for a residual class")
    h.add_argument("result", help="a SolverResult JSON file, or -")
    h.add_argument("--class", dest="cls", required=True)
    h.add_argument("--why", required=True, help="why the id is in the class (one line)")
    ca = sp.add_parser("check-answers", help="exit 1 when a residual id carries a plain answer")
    ca.add_argument("answers", help="a JSON object {answer id: value}, or -")
    ca.add_argument("--json", action="store_true")
    ca.add_argument("--allow-unmatched", action="store_true",
                    help="pass when no residual id covers any answer key (an answer set with no residual id)")
    s = sp.add_parser("stuck", help="the B-203 stuck assessment for a residual id")
    s.add_argument("id")
    s.add_argument("--question", required=True, help="the asked id/field")
    s.add_argument("--brief", default=None, help="the brief text")
    s.add_argument("--file", action="append", default=[], metavar="PATH", help="a delivered file (data)")
    s.add_argument("--rejections", type=int, default=None, help="override the judged-wrong send count")
    s.add_argument("--no-route", action="store_true", help="do not open a player card")
    s.add_argument("--json", action="store_true")
    r = sp.add_parser("report", help="per-event residual frequency from the ledger (offline)")
    r.add_argument("--event", dest="events", action="append", default=[], metavar="SLUG",
                   help="an event (repeatable); its workdir is ~/ctf-work/<slug> unless $CTF_WORKDIR is set")
    r.add_argument("--workdir", dest="workdirs", action="append", default=[], metavar="DIR",
                   help="an event workdir (repeatable)")
    r.add_argument("--all-events", action="store_true", help="every events/<slug>/event.toml")
    r.add_argument("--max-novel-share", type=float, default=None,
                   help="exit 1 when an event's novel share (agent/human/teammate closes) is above this")
    r.add_argument("--json", action="store_true")


class _Fail(Exception):
    pass


def _workdir(args) -> Path:
    from .. import paths
    if args.workdir:
        return Path(args.workdir).expanduser().resolve()
    return paths.workdir(args.event)


def _read_json(src: str, what: str):
    try:
        text = sys.stdin.read() if src == "-" else Path(src).expanduser().read_text(encoding="utf-8")
    except OSError as e:
        raise _Fail(f"cannot read the {what} {src}: {e.strerror or e}") from None
    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        raise _Fail(f"the {what} {src} is not JSON: {e}") from None


def _result(src: str):
    from ..result import ResultError, SolverResult
    try:
        return SolverResult.from_dict(_read_json(src, "result"))
    except ResultError as e:
        raise _Fail(f"the result {src} is not a SolverResult: {e}") from None


def _profile(args):
    from .. import event
    try:
        return event.load(args.event) if args.event else event.current()
    except event.EventError:
        return None


def _report_targets(args) -> list[tuple[str, Path, bool]]:
    """(label, workdir, listed): `listed` targets came from --all-events, where an event with no
    ledger yet is reported by name instead of failing the whole report."""
    from .. import event, paths
    named = list(args.events)
    listed = sorted(d.name for d in paths.events_root().iterdir() if (d / "event.toml").is_file()) \
        if args.all_events else []
    slugs = named + [s for s in listed if s not in named]
    out = []
    for s in slugs:
        try:
            event.load(s)
        except event.EventError as e:
            raise _Fail(f"unknown event {s!r}: {e}") from None
        out.append((s, paths.workdir(s), s not in named))
    seen: dict[Path, str] = {}
    for s, wd, _ in out:
        if wd in seen:        # a CTF_WORKDIR override sends every event to one ledger
            raise _Fail(f"events {seen[wd]!r} and {s!r} both resolve to the workdir {wd} (is CTF_WORKDIR "
                        "set?), so they would read the same ledger; name each event's --workdir instead")
        seen[wd] = s
    out += [(Path(d).name, Path(d).expanduser().resolve(), False) for d in args.workdirs]
    if not out:
        out.append((args.event or Path(_workdir(args)).name, _workdir(args), False))
    return out


def run(args: argparse.Namespace) -> int:
    from .. import residual as R
    try:
        return _run(args, R)
    except (_Fail, R.ResidualError) as e:
        print(f"ctf residual: {e}", file=sys.stderr)
        return 2


def _run(args, R) -> int:
    a = args.action
    if a == "classes":
        cs = R.classes()
        if args.json:
            print(json.dumps([c.to_dict() for c in cs], indent=2))
        else:
            for c in cs:
                print(f"{c.id}: {c.playbook}")
        return 0
    if a == "playbook":
        from .. import paths
        doc = paths.repo_root() / R.PLAYBOOK_DOC
        if args.write:
            doc.write_text(R.playbook_md(), encoding="utf-8")
            print(f"wrote {R.PLAYBOOK_DOC}")
            return 0
        if args.check:
            have = doc.read_text(encoding="utf-8") if doc.is_file() else None
            if have != R.playbook_md():
                print(f"{R.PLAYBOOK_DOC} is {'missing' if have is None else 'stale'}: "
                      "run python -m ctf residual playbook --write", file=sys.stderr)
                return 1
            print(f"{R.PLAYBOOK_DOC} is current")
            return 0
        if args.cls:
            c = R.get(args.cls)
            if args.json:
                print(json.dumps(c.to_dict(), indent=2))
            else:
                print(f"{c.id}: {c.title}\n  playbook: {c.playbook}\n  shapes: {'; '.join(c.shapes)}\n"
                      f"  no oracle: {c.no_oracle}\n  cold stops at: {c.cold_stops_at}\n"
                      f"  controls: {'; '.join(c.controls)}\n  bounded next probe: {c.bounded_next_probe}\n"
                      f"  never: {c.never}")
            return 0
        print(R.playbook_md(), end="")
        return 0
    if a == "template":
        print(json.dumps(R.handoff_template(args.cls, challenge_id=args.id), indent=2))
        return 0
    if a == "mark":
        f = R.validate_finding(_read_json(args.finding, "finding"))
        R.mark(f, workdir=_workdir(args))
        print(f"marked {f.challenge_id} residual ({f.residual_class}); hold its answer unsure/none")
        return 0
    if a == "check":
        v = R.check(_result(args.result), args.cls)
        if args.json:
            print(json.dumps([x.to_dict() for x in v], indent=2))
        else:
            for x in v:
                print(f"{x.code}: {x.message}")
            if not v:
                print("ok: held (or not a residual result)")
        return 1 if v else 0
    if a == "hold":
        print(R.hold(_result(args.result), args.cls, args.why).to_json(indent=2))
        return 0
    if a == "check-answers":
        answers = _read_json(args.answers, "answers")
        ids = R.marked(_workdir(args))
        v = R.check_answers(answers, ids, require_match=not args.allow_unmatched)
        left = R.unmatched(answers, ids) if isinstance(answers, dict) else []
        if left:
            print(f"note: {len(left)} residual id(s) cover no answer key here (not checked): "
                  + ", ".join(left[:20]), file=sys.stderr)
        if args.json:
            print(json.dumps([x.to_dict() for x in v], indent=2))
        else:
            for x in v:
                print(f"{x.code}: {x.message}")
            if not v:
                print("ok: no residual id carries a plain answer")
        return 1 if v else 0
    if a == "stuck":
        files = {}
        for p in args.file:
            try:
                files[Path(p).name] = Path(p).expanduser().read_bytes()
            except OSError as e:
                raise _Fail(f"cannot read the file {p}: {e.strerror or e}") from None
        kw = {} if args.rejections is None else {"rejections": args.rejections}
        res = R.route_stuck(args.id, question=args.question, brief_text=args.brief, files=files or None,
                            workdir=_workdir(args), profile=_profile(args), route=not args.no_route, **kw)
        if args.json:
            print(json.dumps(res.to_dict(), indent=2))
        else:
            print(f"{res.challenge_id}: {res.status} ({res.reason})")
        return 0 if res.is_stuck else 1
    if a == "report":
        over = []
        out = []
        missing = []
        for label, wd, listed in _report_targets(args):
            try:
                rep = R.report_for(wd, label=label)
            except R.ResidualError as e:
                if not listed:
                    raise
                missing.append(f"{label}: {e}")
                continue
            out.append(rep)
            if args.max_novel_share is not None and rep.novel_share is not None \
                    and rep.novel_share > args.max_novel_share:
                over.append(label)
        if not out:
            raise _Fail("no event has a ledger to measure: " + "; ".join(missing))
        if args.json:
            print(json.dumps([r.to_dict() for r in out], indent=2))
        else:
            print("\n\n".join(R.render_report(r) for r in out))
        for line in missing:
            print(f"ctf residual report: not measured: {line}", file=sys.stderr)
        if over:
            print(f"novel share above {args.max_novel_share:g}: {', '.join(over)}", file=sys.stderr)
            return 1
        return 0
    raise _Fail(f"unknown action {a!r}")
