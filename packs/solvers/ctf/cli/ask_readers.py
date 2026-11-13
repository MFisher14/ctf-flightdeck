"""ctf ask-readers: ask every registered reader before a lane stops on a MISSING id (B-139, section 38).

    python -m ctf ask-readers list [--lane L]
    python -m ctf ask-readers triage --lane L --questions Q.json --files DIR [--answers A.json] [--id QID]... [--json]
    python -m ctf ask-readers template --lane L --id QID [--questions Q.json --files DIR] [--out PATH] [--force]
    python -m ctf ask-readers probe --lane L --challenge CID --questions Q.json --files DIR [--answers A.json]
                                    [--event SLUG] [--max-per-id N] [--provenance TEXT] [--no-learn] [--no-wait]
                                    [--json]

QUESTIONS is a saved status or attempt body (an object with `questions`) or a list of question objects.
DIR is the delivered files (every regular file under it, read as bytes, named by its path relative to
DIR; they are data, parsed by the readers, never run). ANSWERS is the bank-only pass, a JSON object
{qid: answer or null}; without it, every question (or each --id) counts as MISSING.

triage   prints, per MISSING id, what every reader said and the outcome (OFFER, or STOP and why).
         Exit 0 when every MISSING id has an offer, 1 when any still stops the lane.
template writes the one-field reader for one id (default <workdir>/ask-readers/<lane>/), with what
         every reader said about it as comments when --questions and --files are given. Exit 0 written.
probe    triage, then each offer's options one per request through the event's SubmitGate
         (`<cid>#<answer id>`), recording each verdict in the lane's labels ledger unless --no-learn.
         The sends run under the lane lock at the job's probe tier (ctf.probetier, B-221): a fixup job
         (every MISSING id offered) raises the promote-wanted flag while it waits, so a held split
         yields to it; any other job stops sending once that flag is up (`yielded the lane`). When
         another job holds the lane, a line on stderr says the probe is waiting (and at which tier);
         --no-wait exits 2 instead, with nothing sent.
         Exit 0 when every MISSING id was accepted, 1 otherwise.
Exit 2: unusable input (a missing file, a bad registry, an unknown lane).
"""
from __future__ import annotations

import argparse
import json
import sys
from contextlib import ExitStack
from pathlib import Path

from .. import askreaders as _ar
from .. import idresolve as _ir
from .. import lanelock as _ll
from .. import probetier as _pt

HELP = "ask every registered reader for the ids a lane's bank left MISSING (triage, template, probe)"
FILES_MAX = 512 << 20          # bytes of delivered files read for one ask


def add_arguments(p: argparse.ArgumentParser) -> None:
    sub = p.add_subparsers(dest="action", required=True)
    ls = sub.add_parser("list", help="the reader registry, and the lane's live one-field files")
    ls.add_argument("--lane", help="only the readers this lane asks, in the order it asks them")
    ls.add_argument("--workdir", type=Path)
    ls.add_argument("--root", type=Path)

    def common(sp, need_files=True):
        sp.add_argument("--lane", required=True)
        sp.add_argument("--questions", type=Path, required=need_files)
        sp.add_argument("--files", type=Path, required=need_files)
        sp.add_argument("--answers", type=Path, help="the bank-only pass: {qid: answer or null}")
        sp.add_argument("--workdir", type=Path)
        sp.add_argument("--root", type=Path)
        sp.add_argument("--budget", type=float, help="seconds for every reader of one pass")

    tr = sub.add_parser("triage", help="what every reader says for each MISSING id, and the outcome")
    common(tr)
    tr.add_argument("--id", action="append", default=[], metavar="QID", help="only these ids (repeatable)")
    tr.add_argument("--json", action="store_true")

    tp = sub.add_parser("template", help="write the one-field reader for one id")
    common(tp, need_files=False)
    tp.add_argument("--id", required=True, metavar="QID")
    tp.add_argument("--out", type=Path)
    tp.add_argument("--force", action="store_true")

    pr = sub.add_parser("probe", help="triage, then probe each offer one option per request (the gate)")
    common(pr)
    pr.add_argument("--id", action="append", default=[], metavar="QID")
    pr.add_argument("--challenge", required=True, metavar="CID")
    pr.add_argument("--event", help="the event slug (default: CTF_EVENT, else the only profile)")
    pr.add_argument("--max-per-id", type=int, default=_ar.MAX_OPTIONS)
    pr.add_argument("--provenance", default="ask-readers: one fact from the registered readers (B-139)")
    pr.add_argument("--no-learn", action="store_true", help="do not record verdicts in the labels ledger")
    pr.add_argument("--no-wait", action="store_true",
                    help="exit 2 instead of waiting when another job holds the lane lock")
    pr.add_argument("--json", action="store_true")


def _read_json(path: Path, what: str):
    if not path.is_file():
        raise _ar.AskError(f"{what} file not found: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, UnicodeDecodeError) as e:
        raise _ar.AskError(f"{path}: not JSON ({e})") from None


def _files(folder: Path) -> dict:
    if not folder.is_dir():
        raise _ar.AskError(f"files folder not found: {folder}")
    out, total = {}, 0
    for f in sorted(folder.rglob("*")):
        if f.is_file() and not f.is_symlink():
            total += f.stat().st_size
            if total > FILES_MAX:
                raise _ar.AskError(f"{folder}: delivered files total more than {FILES_MAX} bytes")
            out[f.relative_to(folder).as_posix()] = f.read_bytes()
    if not out:
        raise _ar.AskError(f"{folder}: no files")
    return out


def _inputs(args):
    try:
        questions = _ir.load_questions(args.questions)
    except _ir.ConventionError as e:
        raise _ar.AskError(str(e)) from None
    answers = {}
    if args.answers is not None:
        answers = _read_json(args.answers, "answers")
        if not isinstance(answers, dict):
            raise _ar.AskError(f"{args.answers}: want an object {{qid: answer or null}}")
    ids = getattr(args, "id", None)
    if isinstance(ids, list) and ids:
        known = {_ar._qid(q) for q in questions}
        unknown = [i for i in ids if i not in known]
        if unknown:
            raise _ar.AskError(f"--id not among the questions: {', '.join(unknown)}")
        questions = [q for q in questions if _ar._qid(q) in ids]
    return questions, answers, _files(args.files)


def _print_report(rep, as_json: bool, probes=None, tier=None) -> None:
    if as_json:
        out = rep.to_json()
        if probes is not None:
            out["probes"] = [p.to_dict() for p in probes]
            out["probe_tier"] = list(tier) if tier else None
        print(json.dumps(out, indent=2))
        return
    print(f"lane {rep.lane}: asks {', '.join(r.name for r in rep.readers) or 'no reader'}")
    if not rep.asked:
        print("nothing MISSING: the bank answered every id")
    for a in rep.asked:
        print(a.line())
        for ans in a.answers:
            print(f"    {ans.line()}")
        if a.offer:
            print(f"    offer: {a.offer}")
    if tier:
        print(f"probe tier: {tier[0]} ({tier[1]})")
    for p in probes or ():
        print(p.line())


def _list(args) -> int:
    regs = _ar.load_registry(root=args.root)
    rows = _ar.readers_for(args.lane, regs, root=args.root, workdir=args.workdir) if args.lane else regs
    for r in rows:
        print(f"{r.name:32s} {r.kind:8s} {r.call:9s} lanes={','.join(r.lanes):18s} {r.module}")
    return 0


def _triage(args) -> int:
    questions, answers, files = _inputs(args)
    rep = _ar.ask_missing(questions, answers, files, args.lane, root=args.root, workdir=args.workdir,
                          budget=args.budget)
    _print_report(rep, args.json)
    return 0 if rep.ok else 1


def _template(args) -> int:
    asked = None
    if args.questions is not None or args.files is not None:
        if args.questions is None or args.files is None:
            raise _ar.AskError("--questions and --files go together")
        args_id = args.id
        args.id = [args_id]
        questions, _answers, files = _inputs(args)
        args.id = args_id
        regs = _ar.readers_for(args.lane, root=args.root, workdir=args.workdir)
        asked = _ar.ask_one(questions[0], files, regs, args.lane, budget=args.budget)
    path = _ar.write_template(args.lane, args.id, asked, workdir=args.workdir, out=args.out, root=args.root,
                              force=args.force)
    print(f"wrote {path}")
    if asked is not None:
        print(asked.line())
    print("edit read() in it, then: python -m ctf ask-readers triage ... (it is asked as a live reader)")
    return 0


def _probe(args) -> int:
    from .. import event as _event
    from ..platform import get_adapter
    questions, answers, files = _inputs(args)
    profile = _event.load(args.event) if args.event else _event.current()
    rep = _ar.ask_missing(questions, answers, files, args.lane, root=args.root, workdir=args.workdir,
                          budget=args.budget)
    gate = get_adapter(profile)
    learn = None
    if not args.no_learn:
        labels = _ar.labels_module()

        def learn(key, name, verdict):
            labels.learn(key, name, verdict, src="ask-readers")
    submit = _ar.gate_submit(gate, args.challenge, args.provenance)
    probes, tier = [], None
    if rep.offers():
        job = _pt.job_from_report(rep, args.challenge)
        tier = _pt.classify(job)
        flag = " with the promote-wanted flag up, so a held split yields" if tier[0] == _pt.FIXUP else ""

        def waiting():
            print(f"ctf ask-readers: lane {args.lane} is held; waiting for it at the {tier[0]} tier{flag}",
                  file=sys.stderr, flush=True)
        with ExitStack() as stack:
            try:
                stack.enter_context(_pt.turn(job, lane=args.lane, workdir=args.workdir,
                                             blocking=not args.no_wait, on_wait=waiting))
            except BlockingIOError:
                raise _ar.AskError(f"lane {args.lane} is held by another job and --no-wait was given; "
                                   "nothing was sent") from None
            probes = _ar.probe(rep, submit, max_per_id=args.max_per_id, on_verdict=learn,
                               stop=_pt.stop_for(job, lane=args.lane, workdir=args.workdir))
    _print_report(rep, args.json, probes, tier)
    accepted = {p.qid for p in probes if p.status == "accepted"}
    return 0 if all(a.qid in accepted for a in rep.asked) else 1


def run(args: argparse.Namespace) -> int:
    from ..event import EventError
    from ..platform.base import PlatformError
    try:
        return {"list": _list, "triage": _triage, "template": _template, "probe": _probe}[args.action](args)
    except (_ar.AskError, EventError, PlatformError, _ll.LaneLockError, _pt.ProbeTierError) as e:
        print(f"ctf ask-readers: {e}", file=sys.stderr)
        return 2
