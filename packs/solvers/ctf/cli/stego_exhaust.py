"""ctf stego-exhaust -- run the whole stego catalog over a challenge folder and give one deterministic
verdict (B-182, engine toolkits.stego_exhaust).

    python -m ctf stego-exhaust DIR [--rejected FLAG]... [--seconds S] [--ocr auto|on|off] [--no-sandbox]
            [--cid ID] [--no-ledger] [--no-record] [--agent A] [--json]

Every step of the catalog (trailing data, carve, PNG chunk CRCs, metadata fields alone and concatenated,
bit planes 0-7 of every channel set in both bit orders, the deep LSB orders, a flag grep of every plane,
steganalysis, the WAV LSB and B-130's named WAV tools, stegseek --seed, exiftool, B-126's render-and-read
sweep and a keyless decode of every recovered text) runs on every image and recording, each one recorded
in the challenge's hypothesis ledger, and a step the ledger already settles is not run again. The first
line is the verdict: FLAG, OPEN (what the catalog cannot read further, and what it needs), or NOTHING
FURTHER, complete or with every step that did not run (a tool missing, the sandbox down, the clock)
listed as NOT RUN, never as negative. stegseek and exiftool are used only in a stego sandbox container
that is already up: this command never starts, builds or pulls one.

--rejected names a flag the platform rejected (repeatable): a step that reaches it again is REJECTED,
not FLAG. The ledger is <workdir>/hypotheses/ (--workdir, else $CTF_WORKDIR, else the event's); it is used
when a challenge id resolves (--cid, else DIR/challenge.json), and --no-ledger turns it off. The verdict is
also written to DIR/recon/stego_exhaust/verdict.{json,txt}. Nothing here contacts a platform.

Exit codes: 0 ok (whatever the verdict), 2 on a named error (no such folder, unknown event, a bad option,
a corrupt hypothesis ledger). --ocr on with tesseract missing is no error: the render sweep is NOT RUN
and the verdict says so.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HELP = "run the whole stego catalog over a challenge and give one verdict: flag, open or nothing further (B-182)"


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("challenge_dir", help="the challenge folder (files/ or unpacked/ inside it are read)")
    p.add_argument("--event", help="event slug (default: the current event)")
    p.add_argument("--workdir", help="the event workdir holding hypotheses/ (default: the event's)")
    p.add_argument("--rejected", action="append", default=[], help="a flag the platform rejected (repeatable)")
    p.add_argument("--seconds", type=float, help="budget of the whole run (default: the engine's)")
    p.add_argument("--ocr", choices=("auto", "on", "off"), default="auto", help="the render sweep's OCR")
    p.add_argument("--no-sandbox", action="store_true", help="stegseek --seed and exiftool are NOT RUN")
    p.add_argument("--cid", help="challenge id (default: the id in challenge.json)")
    p.add_argument("--no-ledger", action="store_true", help="neither read nor write the hypothesis ledger")
    p.add_argument("--no-record", action="store_true", help="read the ledger (skip settled steps) but write nothing")
    p.add_argument("--agent", help="who is recording (default: the engine id)")
    p.add_argument("--json", action="store_true", help="the verdict as JSON")


def _engine():
    """solvers/toolkits/stego_exhaust.py, on the engine sys.path."""
    from ..engines import layout
    for p in layout.sys_path():
        if p not in sys.path:
            sys.path.insert(0, p)
    import stego_exhaust
    return stego_exhaust


def run(args: argparse.Namespace) -> int:
    from .. import event
    from ..hypothesis import HypothesisError
    try:
        profile = event.load(args.event) if args.event else event.current()
        se = _engine()
        d = Path(args.challenge_dir)
        if not d.is_dir():
            raise FileNotFoundError(f"no such challenge folder: {d}")
        opts = {"rejected": list(args.rejected), "ocr": args.ocr, "sandbox": "off" if args.no_sandbox else "on",
                "ledger": "off" if args.no_ledger else "auto", "record": "0" if args.no_record else "1"}
        if args.seconds is not None:
            opts["seconds"] = args.seconds
        if args.cid:
            opts["challenge_id"] = args.cid
        if args.workdir:
            opts["workdir"] = str(Path(args.workdir).expanduser().resolve())
        if args.agent:
            opts["agent"] = args.agent
        rep = se.run_dir(d, profile, **opts)
        if rep.files:
            se.save(rep, se.default_out(d))
    except (event.EventError, HypothesisError, FileNotFoundError, ValueError) as e:
        print(f"ctf stego-exhaust: {e}", file=sys.stderr)
        return 2
    print(json.dumps(rep.verdict(), indent=1) if args.json else se.verdict_text(rep))
    return 0
