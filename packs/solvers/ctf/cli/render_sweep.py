"""ctf render-sweep checklist | rejected -- the fixed checklist of the render-and-read stego sweep
(B-126, engine toolkits.render_ocr_sweep) and its hand-off to the hypothesis ledger (B-181).

    python -m ctf render-sweep checklist DIR [--record] [--cid ID] [--fresh] [--seconds S]
            [--ocr auto|on|off] [--key K]... [--agent A] [--json]
        Print what the sweep ruled out on the challenge folder DIR: per file, the full-band
        spectrogram OCR, the exact 5x7 glyph read and the bit-plane OCR; then the keyless decode and
        the cross-file keys. --record also writes each line to the challenge's hypothesis ledger.
    python -m ctf render-sweep rejected DIR --flag FLAG [--cid ID] [--fresh] [...]
        After the platform rejected FLAG: the same checklist with the reading that gave FLAG marked
        rejected, written to the hypothesis ledger (always): ruled-out probes as negatives, the
        rejected reading as a positive followed by its false-positive correction, so
        `ctf hypothesis check CID --method '<method>'` then says skip instead of the same value
        being derived again.

The sweep's saved report (DIR/recon/render_ocr_sweep/report.json) is reused only when it answers this
run: the files have not changed, it was made with the same options (--key, --ocr off or not, the
event's flag format), its OCR could start (a report saved without tesseract is not reused), and it
did not run out of time on a smaller budget than this run has (--seconds, else the engine's). Anything
else is a fresh sweep, and so is --fresh; the first line printed says which, and why a saved report
was not used. The challenge id is --cid, else the id in DIR/challenge.json; recording
without one is an error. The ledger is <workdir>/hypotheses/ (--workdir, else $CTF_WORKDIR, else the
event's). Nothing here contacts a platform: the rejection is what the operator says it was.

Exit codes: 0 ok, 2 on a named error (no such folder, no challenge id, unknown event, OCR asked for
with --ocr on but tesseract missing).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HELP = "the render-and-read stego sweep's fixed checklist; after a rejected flag, file it as negatives (B-126)"


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("--event", help="event slug (default: the current event)")
    p.add_argument("--workdir", help="the event workdir holding hypotheses/ (default: the event's)")
    sp = p.add_subparsers(dest="action", required=True)
    c = sp.add_parser("checklist", help="print what the sweep ruled out; --record writes it to the hypothesis ledger")
    r = sp.add_parser("rejected", help="a flag was rejected: file the checklist, the rejected reading as a false positive")
    for q in (c, r):
        q.add_argument("challenge_dir", help="the challenge folder (files/ or unpacked/ inside it are read)")
        q.add_argument("--cid", help="challenge id (default: the id in challenge.json)")
        q.add_argument("--fresh", action="store_true", help="run the sweep again even when a saved report matches")
        q.add_argument("--seconds", type=float, help="budget of a fresh sweep (default: the engine's)")
        q.add_argument("--ocr", choices=("auto", "on", "off"), default="auto")
        q.add_argument("--key", action="append", default=[], help="a shift (1..25) or key word to try on the texts")
        q.add_argument("--agent", help="who is recording (default: the engine id)")
        q.add_argument("--json", action="store_true")
    c.add_argument("--record", action="store_true", help="write the checklist to the hypothesis ledger")
    r.add_argument("--flag", required=True, help="the flag the platform rejected")


def _engine():
    """solvers/toolkits/render_ocr_sweep.py, on the engine sys.path."""
    from ..engines import layout
    for p in layout.sys_path():
        if p not in sys.path:
            sys.path.insert(0, p)
    import render_ocr_sweep
    return render_ocr_sweep


def _report(ros, args, profile):
    from .. import flagfmt
    d = Path(args.challenge_dir)
    if not d.is_dir():
        raise FileNotFoundError(f"no such challenge folder: {d}")
    source = "fresh sweep"
    if not args.fresh:
        # the options sweep() gives examine() for this command line: a saved report made with others
        # (a run without the --key asked for now, an OCR-off run) is not the answer to this one
        want = ros.run_options(flagfmt.for_profile(profile), ocr=args.ocr, keys=args.key,
                               prefixes=tuple(profile.flag.prefixes))
        rep = ros.load_report(ros.default_out(d), ros.ic.challenge_files(d))
        why = ros.stale(rep, want, args.seconds) if rep is not None else None
        if rep is not None and why is None:
            return rep, "saved report"
        if why:
            source = f"fresh sweep: {why}"
    opts = {"ocr": args.ocr, "keys": args.key}
    if args.seconds is not None:
        opts["seconds"] = args.seconds
    return ros.sweep(d, profile, **opts), source


def run(args: argparse.Namespace) -> int:
    from .. import event, paths
    from ..hypothesis import HypothesisError
    try:
        profile = event.load(args.event) if args.event else event.current()
        ros = _engine()
        rep, source = _report(ros, args, profile)
        rejected = args.flag if args.action == "rejected" else None
        items = ros.checklist(rep, rejected=rejected)
        record = args.action == "rejected" or args.record
        written = []
        if record:
            cid = args.cid or ros.challenge_id_of(Path(args.challenge_dir))
            if not cid:
                raise ValueError("no challenge id: pass --cid, or run on a folder with a challenge.json")
            wd = Path(args.workdir).expanduser().resolve() if args.workdir else paths.workdir(args.event)
            written = ros.file_checklist(cid, items, workdir=wd, profile=profile, agent=args.agent or ros.ENGINE)
    except (event.EventError, HypothesisError, FileNotFoundError, ValueError) as e:
        print(f"ctf render-sweep: {e}", file=sys.stderr)
        return 2
    except Exception as e:
        if type(e).__name__ != "ToolMissing":
            raise
        print(f"ctf render-sweep: --ocr on, but {e}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps({"source": source, "rejected": rejected, "items": items, "recorded": len(written),
                          "not_covered": list(ros.NOT_COVERED)}))
        return 0
    print(f"({source})")
    print(ros.checklist_text(items, rejected))
    if rejected is not None and not any(i["result"] == "false_positive" for i in items):
        print(f"note: no reading of this sweep gave {rejected}; nothing was marked rejected")
    if record:
        print(f"recorded {len(written)} hypothesis-ledger lines")
    return 0
