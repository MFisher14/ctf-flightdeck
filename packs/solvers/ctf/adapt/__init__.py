"""The per-lane adaptation loop (B-036): a new lane component becomes a no-model close by the next clock.

At Huntress 2026 one new component per lane on most mornings reset the lane: agent-closed modes ran
p50 145/279/352 s against 4.4/7.7/11.6 s for Layer 1. The capabilities mostly existed; what failed was
the loop around them: a lane gate that went falsely red under release load (a cap-cut replay read as
NO), a gate that ran cold at the first clock because nothing had prewarmed it, a cache voided by any
new day module, timed modes that waited for an agent after a teammate or a hand closed the base, a
Mastery that was never retried after a fold, and a set pool that deadlocked when sets outnumbered
workers. This package is that loop, platform-free:

    regress   the lane regression set (the lane's B-014 opener cases and controls, plus "yesterday":
              event cases recorded from an accepted run) and its warm gate: per-case content keys
              (engine static closure + lane folder or declared prefix scope), load-scaled caps, a
              cap-cut case re-replayed once at >= 2x the cap before it counts as NO, a failing case
              re-gated once before the lane stops, green results cached and reused (prewarm)
    chain     timed-mode chaining: base -> time_trial -> mastery, each opened when its predecessor is
              closed by us, by a teammate (watch stream) or by hand, behind the lane gate; one
              automatic retry of a failed timed mode, refused when the lane's code has not changed
              since a wrong answer; the kill-time not_submitted marker
    qdiff     the contract diff of a timed start's questions against the base's (kind changes,
              literal-none sentences, added and removed ids), surfaced before solving
    setpool   the set pool: forked workers fed one set at a time (no deadlock when sets outnumber
              workers), each set a share of the budget, every set not returned solved serially, a
              no-deadline budget scaled to the set count
    clocks    running clocks (AttemptGuard holds one) and the deadline-aware quiet check: only a clock
              with a deadline throttles offline replays (B-253)
    replay    saved attempts replayed through the set pool: two concurrent stability replays, a
              profile, and a lane's rows behind a per-prefix (lane minus other days) cache (B-253)

`python -m ctf adapt gate|prewarm|record|chain|mark|attempt|qdiff` is the command
(ctf/cli/adapt.py). The contract is docs/CONTRACTS.md section 29.

Nothing here starts a clock or talks to a platform: the opener starts clocks (B-252/B-003) and the
submit gate sends answers (section 5). This package decides whether a timed mode may start and keeps
the lane's regression honest.
"""
from __future__ import annotations


class AdaptError(ValueError):
    """A regression set, case record or chain request is unusable; the message names what and why."""


__all__ = ["AdaptError"]
