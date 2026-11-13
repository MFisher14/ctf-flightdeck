"""Dynamic (rotating) flags, submitted through the submit gate (B-006).

Some CSCTF challenges use per-team flags that rotate every 5 minutes on clock boundaries
(:00, :05, :10, ...). A flag retrieved at 16:04:58 is already dead at 16:05:02. The rules say:
retrieve fresh immediately before submitting, never cache, script the retrieval.

    from ctf import dynamic, event
    from ctf.platform import get_adapter
    gate = get_adapter(event.current())
    res = dynamic.solve_dynamic(gate, "42", retrieve)       # a SubmitResult

`retrieve` is a challenge-specific callable you supply that fetches ONE fresh flag from the assigned
target (e.g. an nc read or an HTTP GET). This helper fetches and submits back-to-back, and refuses to
submit when the fetch landed too close to a window boundary (where the flag would die mid-flight) --
it waits out the boundary and fetches again instead.

Every send goes through gate.submit(..., rotating=True): the event rules, the submit queue (pacing,
dedupe, the shared rate-limit pause) and the ledger all apply, and an incorrect answer is recorded as
a rotating miss that does not count toward wrong_answer_stop (the organizer sanctions immediate
re-retrieval). That carve-out is bounded in the ledger, not by `attempts`: past the profile's
submit.rotating_miss_budget misses on a challenge (default 6), every further miss counts as a wrong
answer, so a long sweep, or a call on a static challenge, stops at the wrong-answer stop like any
other submit. Only this module may pass rotating=True.

The window is aligned to the platform's clock: `offset` is server time minus local time, read once
from the adapter's server_time() (CTFd: the Date header of one HEAD) unless the caller passes it. A
platform without server_time() fails loudly; pass offset=0.0 to accept the local clock.

Manual mode is code-enforced (R-02): solve_dynamic raises NotAllowed before the clock probe, the
first retrieve() and any submit when the event's rules make submission manual.
"""
from __future__ import annotations

import time
from typing import Callable

from . import flagfmt
from .platform import NotAllowed, NotSupported, SubmitResult, SubmitStatus
from .platform import legacy as _legacy

WINDOW_S = 300           # 5-minute rotation, on wall-clock boundaries (:00,:05,:10,...), global -- NOT
                         # relative to when we pulled the challenge (per the /dynamic_flags page).
SAFETY_S = 8.0           # don't submit if fewer than this many seconds remain in the window


def server_offset(gate, clock: Callable[[], float] = time.time) -> float:
    """server_time - local_time from the platform adapter. Raises NotSupported when the adapter has no
    server clock, PlatformError when the probe fails: never a silent zero."""
    probe = getattr(gate, "server_time", None)
    if probe is None:
        raise NotSupported(f"solve_dynamic: the {getattr(gate, 'kind', '?')} adapter has no server_time(); "
                           "pass offset=0.0 to use the local clock")
    return float(probe()) - clock()


def seconds_left_in_window(now: float | None = None, window_s: int = WINDOW_S, offset: float = 0.0) -> float:
    # epoch % 300 lands exactly on wall-clock :00/:05/:10 in whole-hour-offset zones (ET/EET); `offset`
    # shifts local time onto the server's clock so we never submit just past the server's boundary.
    now = (time.time() if now is None else now) + offset
    return window_s - (now % window_s)


def _refuse_manual(gate) -> None:
    err = _legacy.refusal(gate.profile, "solve_dynamic", submit=True)
    if isinstance(err, NotAllowed):
        raise err


def solve_dynamic(gate, challenge_id: str, retrieve: Callable[[], str], *, attempts: int = 6,
                  offset: float | None = None, provenance: str = "dynamic-flag (fresh fetch)",
                  clock: Callable[[], float] = time.time,
                  sleep: Callable[[float], None] = time.sleep) -> SubmitResult:
    """Retrieve a fresh flag and submit it inside the same rotation window. Retries up to `attempts`
    windows while the answer is a rotating miss (incorrect) or the fetch returned no new flag-format
    value. Stops at once on an accepted answer and on any other verdict or gate refusal (a teammate's
    solve, the wrong-answer stop, manual mode), returning it."""
    _refuse_manual(gate)
    if offset is None:
        offset = server_offset(gate, clock)       # align the window to the SERVER's boundary
    fmt = flagfmt.for_profile(gate.profile)
    tried: set[str] = set()
    last = SubmitResult(SubmitStatus.NOT_ALLOWED, "no attempt made", sent=False)
    for _ in range(max(1, attempts)):
        left = seconds_left_in_window(now=clock(), offset=offset)
        if left < SAFETY_S:
            sleep(left + 0.3)                     # cross the boundary, then fetch in the fresh window
        flag = retrieve().strip()
        if flag in tried or not fmt.is_flag(flag):
            # The target answered a value already tried (it has not rotated yet) or garbage around a
            # rotation: nothing worth sending; wait for the next window and fetch again.
            last = SubmitResult(SubmitStatus.NOT_ALLOWED,
                                "fetched value " + ("was already tried" if flag in tried else
                                                    "is not in the event flag format") + "; not sent",
                                sent=False)
            sleep(seconds_left_in_window(now=clock(), offset=offset) + 0.3)
            continue
        tried.add(flag)
        res = gate.submit(challenge_id, flag, provenance=provenance, rotating=True)
        last = res
        if res.status is not SubmitStatus.INCORRECT:
            return res                            # accepted, refused, or unjudged after the queue's hold
    return last
