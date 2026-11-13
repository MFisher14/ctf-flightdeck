"""ctf toolbox — install and verify the binary toolbox (B-142, tools/toolbox.toml).

    python -m ctf toolbox [--manifest TOML] verify  [--only NAME ...] [--json]
    python -m ctf toolbox [--manifest TOML] install [--only NAME ...] [--apply [--system]] [--json]
    python -m ctf toolbox brewfile [--write | --check]

verify   each tool present, answering its version probe, at or above its minimum, with what it needs
         at runtime. Exit 0 when every core tool is ok, 1 otherwise (optional tools never fail).
install  the steps for what verify found missing, old, broken or drifted. A DRY RUN unless --apply:
         it prints the brew/git commands and the manual steps and runs nothing. With --apply it runs
         the brew/git steps (never a manual one; a `system = true` tool such as macFUSE or VeraCrypt
         only with --system), then verifies again. A step whose program (brew, git) is absent is
         skipped and named; the others still run. Exit 0 when nothing is left to do (after --apply:
         when the re-verify passes), 1 otherwise, 2 when brew/git was absent for a step or a run was
         refused (under CTF_TESTING only test stubs run).
brewfile print the Brewfile rendered from the manifest; --write writes it at the repo root; --check
         exits 1 when the committed one is stale.

Exit 2 on an unreadable manifest or an unknown --only name.
"""
from __future__ import annotations

import argparse
import json
import sys

from .. import toolbox as _tb

HELP = "binary toolbox (B-142): verify host tools, plan or run their installs, render the Brewfile"


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("--manifest", metavar="TOML",
                   help="the toolbox manifest (default tools/toolbox.toml; brewfile --write/--check use the default)")
    sub = p.add_subparsers(dest="toolbox_cmd", required=True)
    v = sub.add_parser("verify", help="check every toolbox tool (exit 1 on a core problem)")
    v.add_argument("--only", nargs="+", metavar="NAME", help="these tools (and what they need)")
    v.add_argument("--json", action="store_true")
    i = sub.add_parser("install", help="plan the installs (a dry run); --apply runs them")
    i.add_argument("--only", nargs="+", metavar="NAME", help="these tools (and what they need)")
    i.add_argument("--apply", action="store_true", help="run the brew/git steps (never the manual ones)")
    i.add_argument("--system", action="store_true",
                   help="with --apply, also run the system steps (macFUSE, VeraCrypt: admin password, "
                        "system extension, reboot)")
    i.add_argument("--json", action="store_true")
    b = sub.add_parser("brewfile", help="render the Brewfile from tools/toolbox.toml")
    g = b.add_mutually_exclusive_group()
    g.add_argument("--write", action="store_true", help="write it at the repo root")
    g.add_argument("--check", action="store_true", help="exit 1 when the committed Brewfile is stale")


def _print_report(report) -> None:
    for s in report:
        print("  " + s.line().replace("\n", "\n  "))


def _verify(args, tools) -> int:
    report = _tb.verify(tools, only=args.only)
    core = _tb.problems(report, core_only=True)
    if args.json:
        print(json.dumps({"passed": not core, "tools": [s.to_dict() for s in report]}, indent=1))
    else:
        print("binary toolbox (tools/toolbox.toml):")
        _print_report(report)
        print("TOOLBOX " + ("OK" if not core else f"PROBLEMS: {', '.join(s.name for s in core)}"
                            + " (`python -m ctf toolbox install` lists the fixes)"))
    return 1 if core else 0


def _install(args, tools) -> int:
    if args.system and not args.apply:
        print("ctf toolbox install: --system only means something with --apply", file=sys.stderr)
        return 2
    report = _tb.verify(tools, only=args.only)
    steps = _tb.plan_install(tools, report)
    results = None
    if args.apply and steps:
        try:
            results = _tb.apply(steps, allow_system=args.system)
        except _tb.ToolboxError as e:
            print(f"ctf toolbox install: {e}", file=sys.stderr)
            return 2
        after = _tb.verify(tools, only=args.only)
    else:
        after = report
    left = _tb.problems(after, core_only=True)
    absent = sorted({r.step.argv[0] for r in results or () if r.reason == "absent"})
    gated = [r.step.tool for r in results or () if r.reason == "system"]
    rc = 2 if absent else (1 if left else 0)
    if absent:
        print(f"ctf toolbox install: {', '.join(absent)} not found on PATH; the steps that need it were "
              "skipped (named below), the rest ran", file=sys.stderr)
    if gated:
        print(f"ctf toolbox install: system step(s) not run: {', '.join(dict.fromkeys(gated))}; re-run with "
              "--apply --system when you can approve an admin password, a system extension and a reboot",
              file=sys.stderr)
    if args.json:
        doc = {"applied": bool(args.apply), "steps": [{"tool": s.tool, "argv": list(s.argv) if s.argv else None,
                                                        "note": s.note, "system": s.system} for s in steps],
               "results": None if results is None else
               [{"tool": r.step.tool, "returncode": r.returncode, "skipped": r.skipped, "reason": r.reason,
                 "output": r.output[-400:]} for r in results],
               "after": [s.to_dict() for s in after], "passed": not left}
        print(json.dumps(doc, indent=1))
        return rc
    if not steps:
        print("nothing to install: every toolbox tool is ok" if not _tb.problems(report)
              else "nothing installable: see the problems below")
    elif results is None:
        print("install plan (DRY RUN: nothing ran; add --apply to run the brew/git steps):")
        for s in steps:
            print("  " + s.line())
    else:
        print("install (--apply):")
        for r in results:
            tag = "SKIP" if r.skipped else ("OK  " if r.returncode == 0 else f"FAIL rc={r.returncode}")
            print(f"  {tag} {r.step.line()}" + (f"\n       {r.output.strip()[-300:]}" if r.output.strip()
                                                and (r.skipped or r.returncode) else ""))
        print("after:")
        _print_report(after)
    if left:
        print("STILL TO DO: " + ", ".join(f"{s.name} ({s.state})" for s in left))
    return rc


def _brewfile(args, tools) -> int:
    text = _tb.render_brewfile(tools)
    p = _tb.brewfile_path()
    if (args.write or args.check) and args.manifest:
        print("ctf toolbox brewfile: --write/--check compare the repo Brewfile with tools/toolbox.toml; "
              "drop --manifest", file=sys.stderr)
        return 2
    if args.write:
        p.write_text(text, encoding="utf-8")
        print(f"wrote {p}")
        return 0
    if args.check:
        have = p.read_text(encoding="utf-8") if p.is_file() else None
        if have != text:
            print(f"{p} is {'missing' if have is None else 'stale'}: run `python -m ctf toolbox brewfile --write`",
                  file=sys.stderr)
            return 1
        print(f"{p} is current")
        return 0
    sys.stdout.write(text)
    return 0


def run(args: argparse.Namespace) -> int:
    try:
        tools = _tb.load(args.manifest)
        if args.toolbox_cmd == "verify":
            return _verify(args, tools)
        if args.toolbox_cmd == "install":
            return _install(args, tools)
        return _brewfile(args, tools)
    except _tb.ToolboxError as e:
        print(f"ctf toolbox: {e}", file=sys.stderr)
        return 2
