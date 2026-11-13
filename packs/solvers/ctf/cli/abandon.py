"""ctf abandon <challenge-id> --reason "<why>" — record a gated decision to stop an attempt.

The sanctioned way to give up on a challenge: instead of a forced interrupt, this appends one
line to <workdir>/abandoned.jsonl naming the challenge, the required reason and the time. The
reason is mandatory and must be more than a token word (the gate), so an abandonment is always
explained and auditable. Nothing is killed and nothing on the platform is touched.

Exit: 0 recorded, 2 usage error (missing/too-thin reason, unresolved workdir).
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import sys
from pathlib import Path

from .. import event as _event
from .. import paths as _paths

HELP = "record a gated decision to abandon an attempt, with a required reason"

LOG_NAME = "abandoned.jsonl"
MIN_REASON_CHARS = 8


class AbandonError(ValueError):
    """The abandonment is not acceptable (no reason, or a reason too thin to be a real one)."""


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("challenge", metavar="CHALLENGE-ID", help="the challenge id or slug being abandoned")
    p.add_argument("--reason", required=True, help="why it is being abandoned (required; must be specific)")
    p.add_argument("--event", metavar="SLUG", help="default: $CTF_EVENT, else the only event")
    p.add_argument("--workdir", type=Path, metavar="DIR", help="override the resolved workdir")


def record_abandon(workdir: Path, challenge: str, reason: str, *, slug: str | None = None,
                   now: _dt.datetime | None = None) -> dict:
    """Append one abandonment record to <workdir>/abandoned.jsonl and return it.

    Raises AbandonError when the challenge id is empty or the reason is missing or too thin
    (fewer than MIN_REASON_CHARS non-space characters). The gate lives here, not in argparse, so
    it holds for every caller."""
    cid = (challenge or "").strip()
    if not cid:
        raise AbandonError("a challenge id is required")
    text = (reason or "").strip()
    if len("".join(text.split())) < MIN_REASON_CHARS:
        raise AbandonError(
            f"--reason must be a specific explanation of at least {MIN_REASON_CHARS} characters; "
            f"got {text!r}")
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    rec = {
        "challenge": cid,
        "reason": text,
        "event": slug,
        "ts": (now or _dt.datetime.now(_dt.timezone.utc)).isoformat(),
    }
    log = workdir / LOG_NAME
    with log.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec, sort_keys=True) + "\n")
    return rec


def run(args: argparse.Namespace) -> int:
    slug = args.event
    try:
        if args.workdir is not None:
            workdir = args.workdir
            if slug is None:
                # --workdir was given explicitly, so we do not need an event to find where to
                # write. The event is recorded only as a label; when none resolves we write the
                # record with event=null rather than refuse. This is intended: pass --event to
                # label it. (Without --workdir, below, an unresolved event is a hard error,
                # because then there is no workdir to write to.)
                try:
                    slug = _event.current().slug
                except _event.EventError:
                    slug = None
        else:
            if slug is None:
                slug = _event.current().slug
            workdir = _paths.workdir(slug)
    except _event.EventError as e:
        print(f"ctf abandon: {e}", file=sys.stderr)
        return 2
    try:
        rec = record_abandon(workdir, args.challenge, args.reason, slug=slug)
    except AbandonError as e:
        print(f"ctf abandon: {e}", file=sys.stderr)
        return 2
    print(f"recorded: abandoned {rec['challenge']} — {rec['reason']}")
    print(f"  -> {workdir / LOG_NAME}")
    return 0
