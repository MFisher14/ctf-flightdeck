"""ctf preflight — the doctor checks for one event (also run at the end of `ctf doctor`).

    python -m ctf preflight [--event SLUG] [--no-codex] [--codex-mode fast|deep|cyber]
                           [--instance-plugin NAME --instance-challenge ID] [--no-toolbox] [--no-token]
                           [--brief FILE|DIR ...] [--all-briefs] [--settings FILE]
                           [--permission-mode MODE] [--interactive] [--harness claude|codex|both]
                           [--strict] [--json]

Checks (ctf/doctor.py): profile, categories (announced vs routed), router, compaction (B-032),
codex-model, codex-smoke (ONE real Codex call through tools/codex_handoff.sh --preflight),
submit-dry-run (nothing sent), instances (the plugin's status route for one challenge; a read),
toolbox (the binary toolbox, B-142), allowance (B-171), and B-190's token (one live /users/me plus the
token list: validity and expiry), brief-rules (each brief's commands and writes simulated against the
rules the agent runs under; nothing is run), usage, power and capabilities (the sandbox self-test; a
fail the sandbox could cause is labelled sandbox-only).

The report is split: BLOCKING (the wave does not start), ADVISORY (never blocks), NOT RUN, OK.
Exit 0 when nothing blocking failed (with --strict: every check ok), 1 otherwise, 2 when the event
profile or a --settings file does not load.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .. import doctor as _doctor
from .. import event as _event
from .. import paths as _paths
from .. import rulesim as _rulesim

HELP = ("preflight doctor: profile, routes, Codex smoke call, submit dry run, instances, token expiry, "
        "brief rules simulation, usage, sandbox self-test; blocking vs advisory")


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("--event", help="event slug (default: the current event)")
    p.add_argument("--no-codex", action="store_true", help="skip the Codex model check and smoke call")
    p.add_argument("--codex-mode", choices=_doctor.CODEX_MODES, default="fast",
                   help="the handoff mode whose model and flags are smoke-tested (default fast)")
    p.add_argument("--instance-plugin", metavar="NAME",
                   help="probe this instance plugin shape (e.g. docker_per_team) until B-003 puts it in "
                        "the profile")
    p.add_argument("--instance-challenge", type=int, metavar="ID",
                   help="the released challenge whose instance status route is probed")
    p.add_argument("--no-toolbox", action="store_true",
                   help="skip the binary toolbox, asset and image checks (B-142, B-188; `ctf toolbox "
                        "verify` and `ctf toolchain assets` / `status` run them alone)")
    p.add_argument("--no-token", action="store_true",
                   help="skip the token check (it makes one /users/me and one /tokens request)")
    p.add_argument("--brief", action="append", default=[], metavar="FILE|DIR",
                   help="a brief to simulate, or a folder of *brief*.md (repeatable)")
    p.add_argument("--all-briefs", action="store_true",
                   help="simulate the briefs the launchers wrote under the event workdir "
                        f"({_rulesim.LAUNCHER_BRIEF_GLOB}; challenge downloads are not searched)")
    p.add_argument("--settings", metavar="FILE",
                   help="simulate this Claude settings JSON instead of the fence's current settings")
    p.add_argument("--permission-mode", choices=_rulesim.CLAUDE_MODES, default=_rulesim.LAUNCH_PERMISSION_MODE,
                   help="the Claude permission mode the agent is launched with (default: "
                        f"{_rulesim.LAUNCH_PERMISSION_MODE}, the launchers' mode; in auto a would-be prompt "
                        "is left to the classifier and only warns)")
    p.add_argument("--interactive", action="store_true",
                   help="the agent is interactive: a permission prompt is advisory (default: background, "
                        "where a prompt fails the agent silently and blocks)")
    p.add_argument("--harness", choices=("claude", "codex", "both"), default="both",
                   help="which harness's rules to simulate the briefs against")
    p.add_argument("--strict", action="store_true",
                   help="warnings, advisory, sandbox-only and skipped checks fail too")
    p.add_argument("--json", action="store_true", help="print the checks as JSON")


def run(args: argparse.Namespace) -> int:
    try:
        prof = _event.load(args.event) if args.event else _event.current()
    except _event.EventError as e:
        print(f"ctf preflight: {e}", file=sys.stderr)
        return 2
    settings = None
    if args.settings:
        try:
            settings = json.loads(Path(args.settings).read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            print(f"ctf preflight: --settings {args.settings}: {type(e).__name__}: {e}", file=sys.stderr)
            return 2
    briefs = list(args.brief)
    brief_workdir = _paths.workdir(prof.slug) if args.all_briefs else None
    inst = ({"endpoints": {"plugin": args.instance_plugin}, "cap": None}
            if args.instance_plugin else None)
    harnesses = ("claude", "codex") if args.harness == "both" else (args.harness,)
    checks = _doctor.run_checks(prof, codex=not args.no_codex, codex_mode=args.codex_mode,
                                instances_cfg=inst, instance_challenge=args.instance_challenge,
                                toolbox=not args.no_toolbox,
                                token=not args.no_token, briefs=briefs, claude_settings=settings,
                                settings_source=args.settings, harnesses=harnesses,
                                permission_mode=args.permission_mode, background=not args.interactive,
                                brief_workdir=brief_workdir)
    bad = _doctor.failed(checks, strict=args.strict)
    if args.json:
        s = _doctor.split(checks)
        print(json.dumps({"event": prof.slug, "strict": args.strict, "passed": not bad,
                          "blocking": [c.name for c in s.blocking],
                          "advisory": [c.name for c in s.advisory],
                          "not_run": [c.name for c in s.not_run],
                          "sandbox_only": [c.name for c in s.sandbox_only],
                          "checks": [c.to_dict() for c in checks]}, indent=1))
    else:
        print(f"preflight for {prof.slug}:")
        for ln in _doctor.render(checks, strict=args.strict):
            print(ln)
    return 1 if bad else 0
