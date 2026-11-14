"""`ctf submit-queue`: the team's cross-process submit queue (B-006, ctf/platform/queue.py).

    python -m ctf submit-queue status                    budget used, shared pause, spooled sends
    python -m ctf submit-queue pending                   every spooled send (in flight / orphaned)
    python -m ctf submit-queue drain                     re-send orphaned spooled sends through the gate
    python -m ctf submit-queue approve <id> --reason R [--count N]
                                                         the player's approval for N more sends past
                                                         the wrong-answer stop on one challenge

`python -m ctf submit <id> <flag>` (and `python -m ctf.submit send`) submit through the same gate
and queue with submit_one() below: every solver submits on sight, there is no orchestrator step.

Exit codes: 0 ok (submit: accepted), 1 not accepted (incorrect, or still unjudged and left queued),
2 error, 4 refused before anything was sent (the event's rules, the wrong-answer stop, dedupe).
"""
from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

from .. import event as _event
from .. import flagcheck as _flagcheck
from .. import paths
from ..platform import NotAllowed, NotSupported, PlatformError, SubmitStatus, get_adapter
from ..platform import legacy as _legacy
from ..platform.queue import QueueError, SubmitQueue
from ..platform.rules import EventRules

HELP = "the team's submit queue: status, pending, drain, approve (B-006)"
REFUSED_EXIT = 4


def _refuse_manual(profile, call: str) -> None:
    """R-02: a manual event (or submit_mode manual) is refused before any adapter, lock or file."""
    err = _legacy.refusal(profile, call, submit=True)
    if isinstance(err, NotAllowed):
        raise err


def _workspace_note(profile, challenge_id: str, line: str, accepted_flag: str | None) -> None:
    """Append to the challenge's existing workspace folder (<workdir>/<id>-<slug>/), if there is one:
    notes.md gets the line, flag.txt the accepted flag. Nothing is created when no folder exists."""
    if not challenge_id.isdigit():
        return
    root = paths.workdir(profile.slug)
    hits = [d for d in root.glob(f"{int(challenge_id)}-*") if d.is_dir()] if root.is_dir() else []
    if len(hits) != 1:
        return
    with open(hits[0] / "notes.md", "a", encoding="utf-8") as fh:
        fh.write(line.rstrip("\n") + "\n")
    if accepted_flag is not None:
        (hits[0] / "flag.txt").write_text(accepted_flag + "\n", encoding="utf-8")


def submit_one(challenge_id: str, flag: str, *, note: str, confirmed: bool = False,
               allow_nonstandard: bool = False, guess: bool = False, call: str = "ctf submit",
               source: str | None = None, local_checks=()) -> int:
    """Submit one flag for the current event through get_adapter's gate and queue. Prints the verdict
    and returns the exit code. Raises NotAllowed (the caller prints `refused`) for a manual event."""
    profile = _legacy.resolve(call)            # no loadable profile: NoProfile (NotAllowed), fail closed
    _refuse_manual(profile, call)
    # B-154: the plausibility check runs before every CLI send. Its warnings (decoy, lost case,
    # spaces, a format slip) are printed and the send goes on; a value that can never be a flag
    # (control characters, an empty body) is refused. The format itself stays the gate's check.
    # `source` (how the value was found) and `local_checks` feed the decoy and case warnings.
    try:
        pc = _flagcheck.check(flag, profile, source=source, local_checks=local_checks,
                              allow_nonstandard=allow_nonstandard)
    except _flagcheck.FlagCheckError as e:
        print(f"{call}: error: {e}", file=sys.stderr)
        return 2
    for f in pc.findings:
        if f.level != "info" and f.code != "not_in_format":
            print(f"{call}: plausibility {f.level} ({f.code}): {f.message}", file=sys.stderr)
    if pc.refuses:
        print(f"{call}: refused: the plausibility check blocks this value (nothing sent)", file=sys.stderr)
        return REFUSED_EXIT
    try:
        gate = get_adapter(profile)
        res = gate.submit(str(challenge_id), flag, provenance=note, confirmed=confirmed,
                          allow_nonstandard=allow_nonstandard, guess=guess)
    except NotSupported:
        raise
    except (PlatformError, QueueError) as e:
        # e.g. no CTF_TOKEN/CTF_COOKIE, a failed POST, an unusable workdir: named, never a traceback
        notes = "".join(f"; {n}" for n in getattr(e, "__notes__", ()))
        print(f"{call}: error: {e}{notes}", file=sys.stderr)
        return 2
    if res.status is SubmitStatus.NOT_ALLOWED and not res.sent:
        print(f"{call}: refused: {res.message}", file=sys.stderr)
        return REFUSED_EXIT
    shown = flag.strip() if profile.rules.flag_sharing == "allowed" else "<flag>"
    _workspace_note(profile, str(challenge_id), f"- submit {shown!s} -> {res.status.value} ({note})",
                    flag.strip() if res.accepted else None)
    print(f"{res.status.value}: {res.message}")
    return 0 if res.accepted else 1


def add_arguments(p: argparse.ArgumentParser) -> None:
    sub = p.add_subparsers(dest="action", required=True)
    sub.add_parser("status", help="team budget used, shared pause, spooled sends")
    sub.add_parser("pending", help="every spooled send: in flight or orphaned")
    sub.add_parser("drain", help="re-send orphaned spooled sends through the gate")
    a = sub.add_parser("approve", help="the player's approval for N more sends past the wrong-answer stop")
    a.add_argument("challenge_id")
    a.add_argument("--reason", required=True, help="who approved and why (goes into the write-up)")
    a.add_argument("--count", type=int, default=1)


def _shown(profile, rec: dict) -> str:
    if profile.rules.flag_sharing == "allowed":
        return str(rec.get("flag"))
    return "sha256:" + hashlib.sha256(str(rec.get("flag")).encode("utf-8")).hexdigest()[:12]


def run(args: argparse.Namespace) -> int:
    try:
        profile = _event.current()
    except _event.EventError as e:
        print(f"ctf submit-queue: {e}", file=sys.stderr)
        return 2
    if args.action == "approve":
        try:
            rec = EventRules(profile).grant(args.challenge_id, args.reason, args.count)
        except ValueError as e:
            print(f"ctf submit-queue approve: {e}", file=sys.stderr)
            return 2
        left = EventRules(profile).approvals_left(args.challenge_id)
        print(f"approved {rec['count']} more send(s) past the wrong-answer stop on challenge "
              f"{rec['challenge_id']}; unused now: {left}")
        return 0
    if args.action == "drain":
        _refuse_manual(profile, "ctf submit-queue drain")
    gate = get_adapter(profile) if args.action == "drain" else None
    q = gate.queue if gate is not None else SubmitQueue(profile)
    if args.action == "status":
        try:
            st = q.status()
        except QueueError as e:
            print(f"ctf submit-queue status: error: {e}", file=sys.stderr)
            return 2
        print(f"event {st['event']}: {st['sent_last_window']}/{st['per_minute']} sends in the last "
              f"{q.window_s:.0f}s; spacing {st['interval_s']}s (per challenge "
              f"{st['per_challenge_interval_s']}s); max hold {st['max_hold_s']}s")
        if st["paused_for_s"] > 0:
            print(f"shared pause: {st['paused_for_s']:.0f}s left ({st['last_block']})")
        print(f"spooled: {st['pending_in_flight']} in flight, {st['pending_orphaned']} orphaned")
        return 0
    if args.action == "pending":
        try:
            rows = q.pending()
        except QueueError as e:
            print(f"ctf submit-queue pending: error: {e}", file=sys.stderr)
            return 2
        for r in rows:
            print(f"{r['state']:<9} challenge {r['challenge_id']}  {_shown(profile, r)}  ({r['provenance']})  "
                  f"{Path(r['path']).name}")
        if not rows:
            print("no spooled sends")
        return 0
    try:
        done = q.drain(gate)
    except NotSupported:
        raise
    except (PlatformError, QueueError) as e:
        notes = "".join(f"; {n}" for n in getattr(e, "__notes__", ()))
        print(f"ctf submit-queue drain: error: {e}{notes}", file=sys.stderr)
        return 2
    worst = 0
    for rec, res in done:
        print(f"challenge {rec['challenge_id']}: {res.status.value}: {res.message}")
        if not res.accepted:
            worst = 1
    if not done:
        print("nothing orphaned to drain")
    return worst
