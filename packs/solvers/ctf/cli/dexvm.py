"""ctf dexvm: trace the mobile dex-chain VM on a delivery, and replay earlier builds through the reader (B-229).

    python -m ctf dexvm show APK [APK ...] [--json] [--guard auto|os|hook] [--timeout S]
    python -m ctf dexvm replay [DIR] [--record] [--json] [--guard auto|os|hook] [--timeout S]

Every delivery is parsed in an engine process run by ctf.openers.run_engine (the runner `ctf arm` and `ctf adapt
gate` use): under the intake network guard, in its own process group, with the secrets-scrubbed engine environment
and a fresh workdir, inside a temporary folder of the event workdir. See ctf/dexvm.py.

`show` prints, for each delivery, the VM's verdict, every method that references an ANS literal with its outcome and,
for a decline, the call or opcode the VM has no model of (where an agent starts when a new loader or reflection path
appears), and the armed reader's answer. Unsure options are listed as unsure, never as the answer.

`replay` runs every *.apk / *.apks / *.xapk / *.aab under DIR (default: the saved past-event challenges,
$CTF_REAL_CHALLENGES) through the lane's reader. A build recorded as a mobile-android `adapt` event case must print
that case's accepted answer; any other build must answer plain. Run it before a release so a reused older build (Day
31 dealt the Day 20 build into Mastery) is known to read with no model. `--record` records every plain build not
recorded yet as an event case, so `ctf adapt prewarm` / `ctf adapt gate mobile-android` replay it from then on (record
once the answers were accepted).

The run folders live in the event workdir, so the event must resolve (CTF_EVENT, or CTF_WORKDIR). Exit 0 every
delivery answered plain (show) / no failure (replay), 1 otherwise, 2 an error (a missing file or folder, no build,
no event, a guard that cannot hold, an engine that does not resolve).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .. import dexvm as _dexvm
from .. import event as _event
from .. import paths
from ..adapt import AdaptError
from ..intake import guard as _guard

HELP = "trace the mobile dex-chain VM on an APK, or replay earlier builds through the reader before a release"


def add_arguments(p: argparse.ArgumentParser) -> None:
    sub = p.add_subparsers(dest="action", required=True)
    s = sub.add_parser("show", help="trace each delivery: the VM's entries, declines and the armed answer")
    s.add_argument("apk", nargs="+", type=Path)
    r = sub.add_parser("replay", help="run every earlier build under DIR through the current reader")
    r.add_argument("dir", nargs="?", type=Path, help="default: $CTF_REAL_CHALLENGES (the saved challenges)")
    r.add_argument("--record", action="store_true",
                   help="record each plain build as a mobile-android adapt event case (after it was accepted)")
    for q in (s, r):
        q.add_argument("--json", action="store_true")
        q.add_argument("--guard", choices=_guard.MODES, default="auto", help="the intake network guard (default auto)")
        q.add_argument("--timeout", type=float, default=_dexvm.DEFAULT_TIMEOUT, help="seconds per engine run")


def _render(t: dict) -> list[str]:
    lines = [f"{t.get('name') or t.get('path')}: verdict {t.get('verdict')}  codec {t.get('codec')}"
             + (f" (under {t['layer']})" if t.get("layer") else "")]
    if t.get("answer"):
        lines.append(f"  answer: {t['answer']}  [plain] {t.get('route')}")
    elif t.get("unsure"):
        opts = ", ".join(f"{n}={v}" for n, v in t["unsure"].get("options", []))
        lines.append(f"  answer: none plain; unsure under {t['unsure'].get('key')}: {opts}  (probe on the base only)")
    else:
        lines.append(f"  answer: none  {t.get('route')}")
    if t.get("codes"):
        lines.append(f"  vm codes: {', '.join(t['codes'])}  declines: {t.get('declines')}")
    for e in t.get("entries") or []:
        tail = e.get("code") if e.get("outcome") == "code" else e.get("reason")
        lines.append(f"  dex#{e.get('dex', 0)} {e.get('entry')}: {e.get('outcome')}  {tail}  ({e.get('steps')} steps"
                     + (", in-memory dex loaded)" if e.get("loaded_inmemory") else ")"))
    if t.get("verdict") in ("error", "unreadable"):
        lines.extend(f"  {r}" for r in t.get("reasons") or [])
    if t.get("verdict") == "not-analysis":
        lines.append("  (the document's codec is not analysis: the dex-chain VM is not this delivery's reader)")
    return lines


def _need_event() -> str | None:
    try:
        paths.workdir()
    except _event.EventError as e:
        return f"the run folders live in the event's workdir: {e}"
    return None


def run(args: argparse.Namespace) -> int:
    why = _need_event()
    if why:
        print(f"ctf dexvm: {why}", file=sys.stderr)
        return 2
    try:
        if args.action == "show":
            traces = _dexvm.show(args.apk, guard=args.guard, timeout=args.timeout)
            if args.json:
                print(json.dumps(traces, indent=2, default=str))
            else:
                for t in traces:
                    print("\n".join(_render(t)))
            return 0 if all(t.get("answer") for t in traces) else 1
        root = args.dir
        if root is None:
            root = paths.saved_challenges_root()          # FileNotFoundError names the variable
            if root is None:
                print("ctf dexvm: replay needs a DIR (or CTF_REAL_CHALLENGES set to the saved challenges)",
                      file=sys.stderr)
                return 2
        report = _dexvm.replay(root, guard=args.guard, timeout=args.timeout, record=args.record)
    except (_dexvm.DexvmError, AdaptError, _guard.GuardError, FileNotFoundError) as e:
        print(f"ctf dexvm: {e}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, indent=2, default=str))
        return 0 if report["ok"] else 1
    bad = {f["path"] for f in report["failures"]}
    for b in report["builds"]:
        got = b.get("answer") or b.get("shown") or b.get("verdict") or "nothing"
        held = f"  held to {b['held']}" if b.get("held") else ""
        print(f"{'FAIL' if b['path'] in bad else 'ok  '} {b['path']}: {got}{held}")
    for f in report["failures"]:
        print(f"FAILED {f['path']}: {f['why']}")
        for r in f["reasons"][:5]:
            print(f"    {r}")
    if report["recorded"]:
        print(f"recorded {len(report['recorded'])} event case(s) for mobile-android: {', '.join(report['recorded'])} "
              "(ctf adapt gate mobile-android replays them)")
    print(f"{len(report['builds'])} build(s), {len(report['failures'])} failure(s), "
          f"{report['held']} recorded case(s) held")
    return 0 if report["ok"] else 1
