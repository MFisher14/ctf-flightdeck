"""ctf machine: a spec-driven register machine, its worked-example gate and its service client (B-057).

    python -m ctf machine init [PATH]                    # write a starter spec (never overwrites)
    python -m ctf machine check SPEC [--json]            # run every worked example of the spec
    python -m ctf machine run SPEC PROGRAM [--input "1 2 3"] [--fuel N] [--trace]
    python -m ctf machine play SPEC HOST PORT [--timeout S] [--max-rounds N] [--log FILE] [--fuel N]

For "implement the machine from its specification and answer N programs" challenges. An agent writes
the spec file (`*.machine.toml`) from the prose; the engine solvers/toolkits/spec_machine.py interprets
it (docs/toolkits/spec_machine.md is the reference). No model is called and no spec text is executed
as Python.

`check` prints one line per failing example (expected and got, or the error) and the count. `run`
prints one program's output (PROGRAM is a file, or `-` for stdin); `--trace` writes each executed line
with the registers and flags to stderr. `play` first runs the gate: unless every worked example
reproduces (and there is at least one) it exits 4 without opening a connection. The target must be in
the event's live-service scope (docs/CONTRACTS.md section 13). The flag is printed, never submitted.

Exit 0: written / every example passes / the program ran / the flag was read. 1: an example fails /
the program trapped or ran out of fuel / the service sent no flag. 2: an error (a spec that does not
load, a missing file, an existing PATH for init, a target out of scope, a round that could not be
answered). 4: `play` refused by the gate.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .. import packs, paths, scope

HELP = "spec-driven register machine: check a spec against its worked examples, run a program, play a service"
_ENGINE = Path("solvers") / "toolkits" / "spec_machine.py"


def add_arguments(p: argparse.ArgumentParser) -> None:
    sub = p.add_subparsers(dest="action", required=True)
    i = sub.add_parser("init", help="write a starter spec file")
    i.add_argument("path", nargs="?", default=".", help="a file name or a folder (default: the current folder)")
    c = sub.add_parser("check", help="run every worked example of a spec")
    c.add_argument("spec")
    c.add_argument("--json", action="store_true")
    r = sub.add_parser("run", help="run one program under a spec")
    r.add_argument("spec")
    r.add_argument("program", help="a program file, or - for stdin")
    r.add_argument("--input", default="", help="the input words, separated by blanks or commas")
    r.add_argument("--trace", action="store_true", help="write every executed line with the state to stderr")
    pl = sub.add_parser("play", help="gate on the worked examples, then answer a service round by round")
    pl.add_argument("spec")
    pl.add_argument("host")
    pl.add_argument("port", type=int)
    pl.add_argument("--timeout", type=float, default=10.0, help="seconds to wait for the service (default 10)")
    pl.add_argument("--max-rounds", type=int, default=400, help="reads before giving up (default 400)")
    pl.add_argument("--log", help="append every round and answer to this file")
    for q in (c, r, pl):
        q.add_argument("--fuel", type=int, default=None, help="instructions one run may execute (default: the spec's)")


def _engine():
    """The engine module, shared with a flat `import spec_machine` when the engine path is set up."""
    return packs.load_module("spec_machine", paths.repo_root() / _ENGINE, pack="toolkits.spec_machine")


def _failure_line(r) -> str:
    return f"FAIL #{r.index} {r.name}: " + (r.error or f"expected {r.expected!r}, got {r.got!r}")


def _check(sm, args) -> int:
    report = sm.conformance(sm.load_spec(args.spec), fuel=args.fuel)
    if args.json:
        print(json.dumps({"ok": report.ok, "total": report.total, "passed": report.passed,
                          "failures": [{"index": r.index, "name": r.name, "expected": r.expected,
                                        "got": r.got, "error": r.error} for r in report.failures]}, indent=2))
    else:
        for r in report.failures:
            print(_failure_line(r))
        print(("ok    " if report.ok else "FAIL  ") + report.summary()
              + ("" if report.total else " (a spec with no examples cannot be played)"))
    return 0 if report.ok else 1


def _run(sm, args) -> int:
    spec = sm.load_spec(args.spec)
    source = sys.stdin.read() if args.program == "-" else Path(args.program).read_text(encoding="utf-8")

    def trace(line, text, registers, flags):
        state = " ".join(f"{k}={v}" for k, v in {**registers, **flags}.items() if v)
        print(f"{line:5d}  {text:<28s} {state}", file=sys.stderr)

    try:
        result = sm.run(spec, source, sm.parse_inputs(args.input), fuel=args.fuel,
                        trace=trace if args.trace else None)
    except sm.MachineTrap as e:
        print(f"ctf machine: {type(e).__name__}: {e}", file=sys.stderr)
        return 1
    print(result.text)
    return 0


def _play(sm, args) -> int:
    spec = sm.load_spec(args.spec)
    try:
        played = sm.play(spec, args.host, args.port, timeout=args.timeout, max_rounds=args.max_rounds,
                         transcript=args.log, fuel=args.fuel)
    except sm.GateRefused as e:
        for r in e.report.failures:
            print(_failure_line(r), file=sys.stderr)
        print(f"ctf machine: refused: {e}", file=sys.stderr)
        return 4
    print(f"gate: {played.report.summary()}; answered {played.rounds} round(s)", file=sys.stderr)
    if played.flag:
        print(f"[+] FLAG  {played.flag}")
        return 0
    print(f"[-] no flag; the service's last words: {' '.join(played.last_text.split())[-300:]!r}")
    return 1


def run(args: argparse.Namespace) -> int:
    try:
        sm = _engine()
    except packs.PackError as e:
        print(f"ctf machine: {e}", file=sys.stderr)
        return 2
    try:
        if args.action == "init":
            print(sm.write_template(args.path))
            return 0
        return {"check": _check, "run": _run, "play": _play}[args.action](sm, args)
    except (sm.MachineError, scope.OutOfScope, OSError) as e:
        print(f"ctf machine: {type(e).__name__}: {e}", file=sys.stderr)
        return 2
