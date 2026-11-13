"""`ctf writeup assist` and `ctf writeup review` (B-097): the drafting pass on the docs model and the
one review pass on the primary model. Not a command module of its own (leading underscore): the
writeup command (ctf/cli/writeup.py) adds these two actions.

    python -m ctf writeup assist [--dry-run] [--only REL ...] [--claude-bin BIN] [--timeout S] [--pattern-only]
        write the TODO prose of staged writeups and retros (models.docs; retro recommendations and
        models.docs_on_primary categories on models.primary)
    python -m ctf writeup review [--dry-run] [--only REL ...] [--claude-bin BIN] [--timeout S] [--pattern-only]
        the one pass on models.primary over every drafted block whose pass is pending

--dry-run calls no model: it lists the jobs and writes each brief to <staging>/.assist/briefs/ for
reading. There is no --model option: the route comes from the task type and the profile only.
Exit codes: 0 every job done (or nothing to do), 1 a job declined, failed, answered out of format or
found its file changed, 2 a configuration error (named).
"""
from __future__ import annotations

import argparse
from pathlib import Path

from ..writeup import assist as _assist, evidence, scan as _scan

ACTIONS = ("assist", "review")
BRIEF_DIR = (".assist", "briefs")


def add_parsers(sp) -> None:
    for name, helptext in (("assist", "draft the TODO prose of staged files (docs model; see --dry-run)"),
                           ("review", "the one review pass on the primary model over pending drafted blocks")):
        a = sp.add_parser(name, help=helptext)
        a.add_argument("--dry-run", action="store_true", help="call no model: list the jobs, write the briefs")
        a.add_argument("--only", action="append", metavar="REL",
                       help="only this staged file, relative to the staging folder (repeatable)")
        a.add_argument("--claude-bin", default="claude", help="the Claude Code CLI (default: claude on PATH)")
        a.add_argument("--timeout", type=float, default=900.0, help="seconds per model call (default 900)")
        a.add_argument("--pattern-only", action="store_true",
                       help="no workdir: redact briefs by pattern only (with --dry-run; a real run needs the "
                            "workdir's ledger)")


def _brief_path(staging: Path, job: _assist.Job) -> Path:
    return staging.joinpath(*BRIEF_DIR) / f"{job.rel.replace('/', '__')}.{job.kind}.{job.task}.txt"


def run(args: argparse.Namespace, prof, wd: Path, staging: Path, known) -> int:
    kind = "draft" if args.action == "assist" else "review"
    values, hashes, source = known(args, wd)
    scanner = _scan.Scanner(prof, known=values, known_hashes=hashes)
    records = evidence.read_records(wd) if wd.is_dir() else []
    jobs, skipped = _assist.plan(prof, staging, kind=kind, scanner=scanner, records=records, only=args.only)
    for rel, why in skipped:
        print(f"  skipped {rel}: {why}")
    if not jobs:
        print(f"{args.action}: nothing to do ({len(skipped)} skipped)")
        return 1 if skipped else 0
    if args.dry_run:
        print(f"DRY RUN: no model was called ({source}).")
        for job in jobs:
            p = _brief_path(staging, job)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(job.brief, encoding="utf-8")
            print(f"  {kind} {job.rel}  task={job.task}  model={job.model}  sections={len(job.keys)}  "
                  f"brief={len(job.brief):,} chars  pass after={_assist.route(job.task, prof.models).pass_ if kind == 'draft' else job.model}")
        print(f"briefs: {staging.joinpath(*BRIEF_DIR)}")
        return 1 if skipped else 0
    runner = _assist.ClaudeRunner(args.claude_bin, timeout=args.timeout)
    outcomes = _assist.run(prof, staging, wd, jobs, runner=runner, scanner=scanner)
    usd = sum(o.usd or 0.0 for o in outcomes)
    for o in outcomes:
        cost = f"${o.usd:.4f}" if o.usd is not None else "cost not reported"
        moved = f" (ran on {o.model_used})" if o.model_used and o.model_used != o.job.model else ""
        print(f"  [{o.outcome}] {kind} {o.job.rel} task={o.job.task} model={o.job.model}{moved}: {cost}"
              + (f": {o.detail}" if o.detail else ""))
        if o.outcome == "declined":
            print("    not re-sent and not moved to another model: write these sections by hand")
    done = sum(1 for o in outcomes if o.ok)
    print(f"{args.action}: {done} of {len(outcomes)} job(s) done, ${usd:.4f} reported; recorded in {wd / 'ledger.jsonl'}")
    if kind == "draft" and done:
        print("next: `ctf writeup review` runs the one pass on the primary model before anything is published")
    return 0 if done == len(outcomes) and not skipped else 1
