"""ctf writeup draft | retro | assist | review | check | publish -- the writeup/retro pipeline (B-098,
B-097 for assist and review).

    python -m ctf writeup draft   [--challenge ID ...] [--force]
        one README.md per challenge from the saved evidence into the staging folder (+ STATUS.md)
    python -m ctf writeup retro   [--day YYYY-MM-DD | --since T --until T] [--stdout] [--force]
        a retro of the window from the ledger and the workspace, into <staging>/retro/<label>.md
    python -m ctf writeup check   [PATH ...]  [--pattern-only]
        the leak scan on files as publish would emit them (default PATH: the staging folder)
    python -m ctf writeup publish [--out DIR] [--plan FILE] [--pattern-only]
        DRY RUN: build the redacted public tree and the publish plan; never pushes
    python -m ctf writeup assist  [--dry-run] [--only REL ...]
        draft the TODO prose on the docs model (B-097; ctf/cli/_writeup_assist.py)
    python -m ctf writeup review  [--dry-run] [--only REL ...]
        the one review pass on the primary model; publish refuses drafted text without it

Common options: --event SLUG (default the current event), --workdir DIR (default ctf.paths.workdir()),
--staging DIR (default <workdir>/writeups). The public tree defaults to <workdir>/writeups-public and
its plan to <workdir>/writeups-public.publish-plan.json.

check and publish read the known flag values (confirmed, rejected, ledger) from the workdir; when there
is no workdir, --pattern-only says so explicitly (redaction then rests on the event format and the
Flag sections alone). Exit codes: 0 clean / ready, 1 blocking findings or a closed gate, 2 a
configuration error (named).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .. import event as _event
from .. import paths as _paths
from ..writeup import common, draft as _draft, evidence, policy as _policy, publish as _publish, retro as _retro
from . import _writeup_assist

HELP = "writeup/retro pipeline: draft, retro, assist, review, check, publish (publish is a dry run)"


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("--event", help="event slug (default: the current event)")
    p.add_argument("--workdir", type=Path, help="the event workdir (default: ctf.paths.workdir())")
    p.add_argument("--staging", type=Path, help="private staging folder (default: <workdir>/writeups)")
    sp = p.add_subparsers(dest="action", required=True)
    d = sp.add_parser("draft", help="draft writeups from the saved evidence")
    d.add_argument("--challenge", action="append", metavar="ID", help="only this challenge (repeatable)")
    d.add_argument("--force", action="store_true", help="overwrite drafts edited by hand")
    r = sp.add_parser("retro", help="a retro of the event or one day from the ledger")
    g = r.add_mutually_exclusive_group()
    g.add_argument("--day", help="UTC day YYYY-MM-DD")
    g.add_argument("--since", help="window start (ISO-8601 with offset, or epoch)")
    r.add_argument("--until", help="window end (ISO-8601 with offset, or epoch)")
    r.add_argument("--stdout", action="store_true", help="print instead of writing into staging")
    r.add_argument("--force", action="store_true", help="overwrite a retro edited by hand")
    c = sp.add_parser("check", help="leak scan as publish would see it")
    c.add_argument("paths", nargs="*", type=Path, help="files or folders (default: the staging folder)")
    c.add_argument("--pattern-only", action="store_true", help="no workdir: scan without known values")
    pb = sp.add_parser("publish", help="DRY RUN: build the public tree and the publish plan")
    pb.add_argument("--out", type=Path, help="public tree (default: <workdir>/writeups-public)")
    pb.add_argument("--plan", type=Path, help="plan file (default: next to the public tree)")
    pb.add_argument("--pattern-only", action="store_true", help="no workdir: redact by pattern only")
    _writeup_assist.add_parsers(sp)


def _workdir(args, prof) -> Path:
    return Path(args.workdir).expanduser().resolve() if args.workdir else _paths.workdir(prof.slug)


def _staging(args, wd: Path) -> Path:
    return Path(args.staging).expanduser() if args.staging else wd / "writeups"


def _known(args, wd: Path) -> tuple[set[str], set[str], str]:
    """(known values, known flag hashes, where they came from)."""
    if args.pattern_only:
        return set(), set(), "pattern-only"
    if not wd.is_dir():
        raise common.WriteupError(f"workdir {wd} does not exist, so the known flag values cannot be read; pass "
                                  "--workdir, or --pattern-only to rely on the event format and Flag sections")
    records = evidence.read_records(wd)
    evs = evidence.collect(wd, records)
    return evidence.known_values(evs, records), evidence.known_hashes(records), f"workdir {wd}"


def _print_findings(findings, limit: int = 200) -> None:
    for f in findings[:limit]:
        print(f"  {f}")
    if len(findings) > limit:
        print(f"  ... {len(findings) - limit} more (see the plan file)")


def run(args: argparse.Namespace) -> int:
    try:
        prof = _event.load(args.event) if args.event else _event.current()
        wd = _workdir(args, prof)
        staging = _staging(args, wd)
        if args.action == "draft":
            rep = _draft.run(prof, wd, staging, only=args.challenge, force=args.force)
            print(f"staging {rep.staging}: {len(rep.written)} draft(s) written, {len(rep.kept)} kept "
                  f"(edited by hand; --force overwrites), {len(rep.scripts)} script(s) copied, "
                  f"{rep.challenges} challenge(s)")
            for k in rep.kept:
                print(f"  kept {k}")
            return 0
        if args.action == "retro":
            since = until = None
            if args.day:
                if args.until:
                    raise common.WriteupError("--until goes with --since, not --day")
                since, until = _retro.day_window(args.day)
            else:
                since = _retro.parse_when(args.since) if args.since else None
                until = _retro.parse_when(args.until) if args.until else None
            text = _retro.render(prof, wd, since=since, until=until)
            if args.stdout:
                sys.stdout.write(text)
                return 0
            label = args.day or ("event" if since is None and until is None else
                                 _retro.window_label(since, until).replace(" ", "_").replace(":", ""))
            path, written = _retro.write(prof, staging, label, text, force=args.force)
            print(f"{'wrote' if written else 'kept (edited by hand; --force overwrites)'} {path}")
            return 0
        if args.action in _writeup_assist.ACTIONS:
            return _writeup_assist.run(args, prof, wd, staging, _known)
        if args.action == "check":
            known, hashes, source = _known(args, wd)
            targets = args.paths or [staging]
            findings, excluded = _publish.check(prof, targets, known=known, known_hashes=hashes)
            blocking = [f for f in findings if f.blocking]
            print(f"check ({source}; redaction {'on' if _policy.for_profile(prof).redact else 'off'}): "
                  f"{len(blocking)} blocking, {len(findings) - len(blocking)} note(s), {len(excluded)} excluded")
            _print_findings(findings)
            return 1 if blocking else 0
        # publish (dry run)
        known, hashes, source = _known(args, wd)
        out = Path(args.out).expanduser() if args.out else wd / "writeups-public"
        plan = _publish.build(prof, staging, out, known=known, known_source=source, known_hashes=hashes)
        plan_path = _publish.write_plan(plan, args.plan or _publish.default_plan_path(plan.out))
        print(f"DRY RUN: nothing was pushed and no repository was created.")
        print(f"public tree {plan.out}: {len(plan.files)} file(s), {len(plan.excluded)} excluded, "
              f"redaction {'on' if plan.redacted else 'off'} ({source})")
        for g in plan.gates:
            print(f"  [{'ok' if g.ok else 'BLOCKED'}] {g.name}: {g.reason}")
        _print_findings(plan.blocking)
        print(f"plan: {plan_path}")
        print("status: " + ("ready (a person runs the plan's would_run after the player's go)" if plan.ready
                            else "blocked"))
        return 0 if plan.ready else 1
    except (common.WriteupError, _event.EventError, _policy.PolicyError, evidence.EvidenceError) as e:
        print(f"ctf writeup {args.action}: {e}", file=sys.stderr)
        return 2
