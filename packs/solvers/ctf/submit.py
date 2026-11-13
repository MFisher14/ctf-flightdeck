"""The carried guarded flag-submission path, and `python -m ctf.submit`.

B-006: `python -m ctf.submit send|approve` (like `python -m ctf submit`) now go through the submit gate
and the team's cross-process queue (ctf.platform.get_adapter, ctf/platform/queue.py): the ledger is
the memory, an approval past the wrong-answer stop is a "platform.approval" ledger record, and nothing
here reads or writes tried.json any more. guarded_submit() below is the carried library function,
kept for any outside script; nothing in the repo calls it, and its tried.json memory is not the
gate's. New code submits with get_adapter(profile).submit(...).

What follows is the carried description of guarded_submit.

The player's standing decision (2026-11-03) is **guarded auto-submit**: a flag is submitted as soon
as it is pulled from real challenge output and matches the event flag format, with these guards, which
also keep us inside the CSCTF rules (no flag brute-forcing, no submission flooding):

  * flag-format check     a candidate that is not one flag in the event format (ctf.flagfmt) is never sent
  * one try per value     a flag already tried on this challenge is never re-sent (dedupe via tried.json)
  * pacing                at least submit_interval_min_s between submissions (client-enforced)
  * skip solved           if the team already solved the challenge, we do not submit
  * 3-wrong-then-ask      after submit_wrong_limit incorrect answers on ONE challenge, stop and ask the
                          player instead of trying more (this is the line that separates "a reasoned
                          submission" from "brute forcing")

`require_human` lets the caller force a confirmation step. Callers pass the flag's provenance so we
never auto-submit something that was not actually recovered from the challenge.

Two narrow exceptions to the wrong-answer guard, both locked down after they were misused live:

  * count_wrong=False     the rotating-flag carve-out. Only ctf.dynamic may pass it (solver scripts used
                          it on static challenges to walk past the guard); any other caller gets a
                          ValueError and nothing is sent.
  * player approval       after the guard stops a challenge, the player may approve N more reasoned
                          sends. The approval is a counted, per-challenge, logged record in tried.json
                          (`python -m ctf.submit approve <cid> --reason ...`), and a send spends it only
                          when the caller also passes human_authorized_after_maxwrong=True
                          (`python -m ctf.submit send <cid> <flag> --after-approval`).

Manual mode is code-enforced (R-02, ctf/platform/legacy.py): guarded_submit raises NotAllowed before
any check, note or send when the event (the client's `profile`, else ctf.event.current()) is manual,
forbids automation on its platform, or has submit_mode manual. `python -m ctf.submit send` refuses the
same way before a client exists and exits REFUSED_EXIT.
"""
from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass

from . import client as _client
from . import workspace as _ws
from .platform import NotSupported
from .platform import legacy as _legacy

REFUSED_EXIT = 4   # the event's rules forbid the call (manual mode); nothing was sent


# Modules allowed to pass count_wrong=False (the rotating-flag carve-out).
DYNAMIC_CALLERS = frozenset({"ctf.dynamic"})


@dataclass
class Result:
    status: str          # correct | incorrect | already_solved | skipped-solved | duplicate | bad-format | blocked-maxwrong | not-submitted
    message: str
    submitted: bool

    @property
    def correct(self) -> bool:
        return self.status in ("correct", "already_solved")


def guarded_submit(
    ctfd: _client.CTFd,
    ch: _ws.Challenge,
    flag: str,
    *,
    provenance: str = "",
    team_solved: set[int] | None = None,
    allow: bool = True,
    allow_nonstandard: bool = False,
    count_wrong: bool = True,
    human_authorized_after_maxwrong: bool = False,
) -> Result:
    """Submit `flag` for challenge `ch` under all the guards. `provenance` is a short note on where the
    flag came from (e.g. "xor-decode of body", "nc output") and is recorded for the write-up. `allow`
    may be set False by the caller to force a dry run (checks only, never sends).

    `allow_nonstandard=True` skips the CSCTF{...} format check — use it ONLY for OSINT-style challenges
    whose answer is a freeform value in a format the brief defines (coords, a name, a hash), where the
    value was still reasoned from the challenge (never a guess). There is no wrong-submit penalty, but the
    no-brute-force / no-guessing discipline still holds: one reasoned value per submission, never a sweep.

    `count_wrong=False` means an `incorrect` here does NOT count toward the 3-wrong-then-ask guard — used by
    the dynamic-flag path, where a rejected *rotating* flag is a timing miss (the organizer sanctions
    immediate re-retrieval), not a wrong guess. The attempt is still recorded (as `stale`) for the write-up,
    and the caller's own attempt cap bounds the retries.

    Only ctf.dynamic may pass `count_wrong=False`; any other caller raises ValueError before anything
    is checked or sent.

    `human_authorized_after_maxwrong=True` is the narrow escape hatch after the guard has stopped: it
    spends one player approval recorded on this challenge (`ch.grant_post_guard_approval`). With no
    unused approval on record the send stays blocked. It does not bypass format, duplicate, or
    already-solved checks, and an unjudged verdict (ratelimited, paused, auth) does not spend it.

    Raises NotAllowed (ctf.platform.legacy) before anything else when the event's rules make
    submission manual; the event is `ctfd.profile` when the client carries one, else the current one."""
    _legacy.require("guarded_submit", submit=True, profile=getattr(ctfd, "profile", None))
    if not count_wrong:
        caller = sys._getframe(1).f_globals.get("__name__", "?")
        if caller not in DYNAMIC_CALLERS:
            raise ValueError(
                f"count_wrong=False is reserved for the dynamic-flag path (ctf.dynamic.solve_dynamic); "
                f"called from {caller!r}. A static challenge's wrong answer always counts.")
    cfg = ctfd.cfg
    flag = flag.strip()

    if not allow_nonstandard and not cfg.looks_like_flag(flag):
        ch.note(f"- not a flag-format match, not submitted: {flag!r} ({provenance}). "
                f"If this is an OSINT/templated answer, resubmit with allow_nonstandard=True.")
        return Result("bad-format", f"{flag!r} does not match the flag format", False)

    if team_solved is not None and ch.cid in team_solved:
        ch.mark_solved(flag)
        return Result("skipped-solved", "challenge already solved by the team", False)

    if ch.already_tried(flag):
        return Result("duplicate", "this exact flag was already submitted for this challenge", False)

    post_guard = count_wrong and ch.wrong_count() >= cfg.submit_wrong_limit
    if post_guard:
        if not human_authorized_after_maxwrong:
            ch.note(f"- BLOCKED after {ch.wrong_count()} wrong answers; asking the player before more. "
                    f"(candidate: {flag!r}, {provenance})")
            return Result("blocked-maxwrong",
                          f"{ch.wrong_count()} wrong answers already on this challenge; stop and ask the player",
                          False)
        if ch.post_guard_approvals_left() < 1:
            ch.note(f"- BLOCKED after {ch.wrong_count()} wrong answers: human_authorized_after_maxwrong was "
                    f"passed but no unused player approval is recorded (candidate: {flag!r}, {provenance})")
            return Result("blocked-maxwrong",
                          "no unused player approval recorded for this challenge; "
                          "record one with `python -m ctf.submit approve <cid> --reason ...`",
                          False)

    if not allow:
        return Result("not-submitted", "dry run (allow=False)", False)

    sub = ctfd.submit(ch.cid, flag)
    if post_guard and sub.status not in _ws.UNJUDGED_STATUSES:
        ch.consume_post_guard_approval(flag, provenance)
        ch.note(f"- PLAYER-AUTHORIZED post-guard submission after {ch.wrong_count()} wrong answers: "
                f"{flag!r} ({provenance}); approvals left: {ch.post_guard_approvals_left()}")
    # A rotating-flag miss is recorded as `stale` (not `incorrect`) so it doesn't trip the wrong-guard.
    recorded = "stale" if (sub.status == "incorrect" and not count_wrong) else sub.status
    ch.record_attempt(flag, recorded)
    ch.note(f"- submit {flag!r} -> {sub.status} ({provenance})")
    if sub.correct:
        ch.mark_solved(flag)
    return Result(sub.status, sub.message, True)


# ---------------------------------------------------------------- CLI
def main(argv: list[str] | None = None) -> int:
    """`send` and `approve` through the submit gate and queue (the same code as `python -m ctf submit`
    and `python -m ctf submit-queue approve`)."""
    ap = argparse.ArgumentParser(prog="python -m ctf.submit",
                                 description="Submit through the gate and queue; player approvals.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("approve", help="record the player's approval for N more sends past the wrong guard")
    a.add_argument("cid")
    a.add_argument("--reason", required=True, help="who approved and why (goes into the write-up)")
    a.add_argument("--count", type=int, default=1)
    s = sub.add_parser("send", help="submit one reasoned flag through the gate and the team's queue")
    s.add_argument("cid")
    s.add_argument("flag")
    s.add_argument("--note", default="manual submit")
    s.add_argument("--after-approval", "--confirm", dest="confirm", action="store_true",
                   help="the player confirmed this send; past the wrong-answer stop it spends one "
                        "recorded approval")
    args = ap.parse_args(argv)
    from .cli import submit_queue as _sq

    if args.cmd == "approve":
        return _sq.run(argparse.Namespace(action="approve", challenge_id=args.cid, reason=args.reason,
                                          count=args.count))
    try:
        return _sq.submit_one(args.cid, args.flag, note=args.note, confirmed=args.confirm,
                              call="python -m ctf.submit send")
    except NotSupported as e:
        print(f"refused: {e}", file=sys.stderr)
        return REFUSED_EXIT


if __name__ == "__main__":
    raise SystemExit(main())
