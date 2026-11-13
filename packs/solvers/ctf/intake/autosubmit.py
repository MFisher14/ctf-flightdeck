"""Capped auto-submit of an unambiguous intake flag, through the SubmitGate (B-012).

Intake itself (ctf/intake/__init__.py) never submits: it finds flags and classifies the result as
`solved` (one distinct flag in the event format), `candidate` (several, or metadata joins) or `none`.
This module is the one place that turns a `solved` intake into a submission, and only ever through
`ctf.platform.get_adapter(profile)` -- the SubmitGate, which enforces manual mode, the flag format,
provenance, the wrong-answer stop and the team's send pacing. A manual-mode event is refused by the
gate (profile.manual) before any adapter call, so this path adds nothing a manual event can bypass.

Four guards sit in front of the gate, so intake never spends the wrong-answer budget on noise:

  * **unambiguous only** -- `eligible()` submits a flag only when the intake result is `solved` with
    exactly one distinct flag-format value, and that value is not a placeholder/template string
    (`CSCTF{...}`, `flag{example}`, a row of dashes). A `candidate` (several readings, decoys
    possible) is never auto-submitted; the player picks.
  * **printable only** -- a flag whose body holds a control or non-printable character is decoder
    noise (ctf/intake/decode.py) and is never sent, whatever status the caller passes.
  * **not a decoy** -- the B-154 plausibility check (ctf/flagcheck.py, source `intake`) runs on the
    one flag; a body that reads as a decoy (not_the_flag, fake, try_harder... after undoing leet)
    is not sent and is handed to the player.
  * **capped per challenge** -- at most `cap` judged sends per challenge across every intake run
    (default 1). The cap counts the `intake.autosubmit` ledger records the platform judged (correct,
    incorrect, already solved) and the ones whose outcome is unknown (the send raised: it may have
    reached the platform, so it counts). A gate refusal (manual mode, format, a full wrong-answer
    budget) is not a send, and a send the platform did not judge (rate limited, paused, refused) is
    not a judgement: neither consumes the cap. Once the cap is reached intake hands the challenge to
    the player.

    a = autosubmit.auto_submit(cid, status, flags, gate, profile=profile,
                               provenance="intake: CSCTF{...} decoded from handout", cap=1,
                               workdir=workdir)
    if a.accepted: ...        # the platform took it
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .. import flagcheck as _flagcheck
from .. import flagfmt as _flagfmt
from .. import ledger as _ledger
from ..event import EventProfile
from ..platform.base import PlatformError, SubmitStatus
from ..platform.policy import RecordError
from .decode import body_is_printable
from ..sweep import _norm as _sweep_norm
from ..sweep import _placeholder as _sweep_placeholder

LEDGER_EVENT = "intake.autosubmit"
DEFAULT_CAP = 1                       # judged sends per challenge, across every intake run; 1 is the safe floor
ERROR = "error"                       # ledger status of a send that raised: outcome unknown, counted as judged
# Sent but not judged by the platform: these do not consume the cap.
_UNJUDGED = frozenset({SubmitStatus.RATE_LIMITED.value, SubmitStatus.PAUSED.value, SubmitStatus.NOT_ALLOWED.value})
# B-154 plausibility findings that make intake stand down: a body that reads as a decoy. The other
# stand-down reasons (several flags, a placeholder, noise) are eligible()'s own.
STAND_DOWN_CODES = frozenset({"decoy_marker"})


def distinct_flags(flags: Iterable[str], profile: EventProfile) -> list[str]:
    """Normalized, de-duplicated flag-format values from `flags` (drops anything not a flag)."""
    ff = _flagfmt.for_profile(profile)
    out: list[str] = []
    for f in flags:
        key = _sweep_norm(ff, f)
        if key is not None and key not in out:
            out.append(key)
    return out


def eligible(status: str, flags: Iterable[str], profile: EventProfile) -> tuple[str | None, str]:
    """(flag, why) -- `flag` is set only for an unambiguous, non-placeholder, flag-format result.

    `flag` is None, with a reason, whenever auto-submit must stand down: no flag in the format, more
    than one distinct reading, an intake status other than `solved`, or a placeholder/template value.
    """
    uniq = distinct_flags(flags, profile)
    if not uniq:
        return None, "no value in the event flag format"
    if status != "solved" or len(uniq) != 1:
        return (None, f"ambiguous: {len(uniq)} distinct flag(s), intake status {status!r} "
                      "(auto-submit needs exactly one, status 'solved')")
    flag = uniq[0]
    if _sweep_placeholder(flag):
        return None, "the one flag is a placeholder/template value"
    if not body_is_printable(flag):
        return None, "the one flag has control or non-printable characters in its body (decoder noise)"
    return flag, "one unambiguous flag in the event format"


@dataclass
class AutoSubmit:
    challenge_id: str
    flag: str | None            # the eligible flag, or None when nothing was submittable
    submitted: bool             # a send reached (or may have reached) the platform
    accepted: bool              # the platform took it (correct / already solved)
    status: str | None          # SubmitStatus value when a send was made, else None
    reason: str
    cap: int
    prior: int                  # sends already counted for this challenge before this attempt
    error: str | None = None    # the gate raised: the send's outcome is unknown (counted against the cap)

    def line(self) -> str:
        head = f"autosubmit {self.challenge_id}:"
        if self.flag is None:
            return f"{head} not submitted ({self.reason})"
        if self.error is not None:
            return f"{head} {self.flag} send FAILED, outcome unknown, counted against the cap ({self.error})"
        if not self.submitted:
            return f"{head} {self.flag} not sent ({self.reason})"
        verdict = "ACCEPTED" if self.accepted else self.status
        return f"{head} {self.flag} sent -> {verdict} ({self.reason})"


def counts_against_cap(rec: dict) -> bool:
    """An `intake.autosubmit` record consumes the cap when it was sent and either judged by the
    platform or of unknown outcome; a refusal or an unjudged answer (rate limited, paused) does not."""
    return bool(rec.get("sent")) and rec.get("status") not in _UNJUDGED


def prior_sends(challenge_id: str, workdir: Path | None) -> int:
    """How many `intake.autosubmit` records for this challenge count against the cap."""
    cid = str(challenge_id)
    return sum(1 for r in _ledger.read(workdir)
               if r.get("event") == LEDGER_EVENT and str(r.get("challenge_id")) == cid and counts_against_cap(r))


def auto_submit(challenge_id: str, status: str, flags: Iterable[str], gate, *, profile: EventProfile,
                provenance: str, cap: int = DEFAULT_CAP, workdir: Path | None = None,
                record: bool = True) -> AutoSubmit:
    """Submit the one unambiguous intake flag through `gate`, at most `cap` sends per challenge.

    `gate` must be a SubmitGate (ctf.platform.get_adapter). The gate alone decides manual mode, the
    format, provenance and pacing; this function only withholds ambiguous, noisy or capped
    submissions and records each attempt it hands the gate in the ledger (`intake.autosubmit`). A
    RecordError (answered, but the gate's observer failed) still records the answer here; any other
    PlatformError or OSError from the gate is recorded as status `error`, sent, and counts against
    the cap, since the send may have reached the platform.
    """
    cid = str(challenge_id)
    if cap < 0:
        raise ValueError(f"cap must be >= 0, got {cap}")
    flag, why = eligible(status, flags, profile)
    if flag is None:
        return AutoSubmit(cid, None, False, False, None, why, cap, 0)
    # B-154: the plausibility check every lane calls. An intake flag is a static find by definition
    # (eligible() already stood down on a second flag-format value, a placeholder and noise); a body
    # that reads as a decoy hands it to the player instead of spending the cap on it.
    pc = _flagcheck.check(flag, profile, source="intake")
    stand_down = [f for f in pc.findings if f.code in STAND_DOWN_CODES]
    if stand_down:
        return AutoSubmit(cid, flag, False, False, None,
                          "plausibility check: " + "; ".join(f"{f.code}: {f.message}" for f in stand_down)
                          + " (not sent; the player picks)", cap, 0)
    prior = prior_sends(cid, workdir)
    if prior >= cap:
        return AutoSubmit(cid, flag, False, False, None,
                          f"auto-submit cap {cap} reached for this challenge ({prior} prior send(s))",
                          cap, prior)
    if not (provenance or "").strip():
        provenance = f"intake auto-submit of {cid}"
    note = None
    try:
        res = gate.submit(cid, flag, provenance=provenance)
    except RecordError as e:              # answered, but the gate's own record failed: ours still stands
        res, note = e.result, f"the gate could not record the answer: {e}"
    except (PlatformError, OSError) as e:  # outcome unknown: it may have reached the platform
        err = f"{type(e).__name__}: {e}"
        if record:
            _ledger.append(LEDGER_EVENT, workdir=workdir, challenge_id=cid, sent=True, status=ERROR,
                           accepted=False, cap=cap, error=err)
        return AutoSubmit(cid, flag, True, False, ERROR, err, cap, prior, error=err)
    if record:
        _ledger.append(LEDGER_EVENT, workdir=workdir, challenge_id=cid, sent=bool(res.sent),
                       status=res.status.value, accepted=bool(res.accepted), cap=cap)
    reason = res.message or res.status.value
    if note:
        reason = f"{reason}; {note}"
    return AutoSubmit(cid, flag, bool(res.sent), bool(res.accepted), res.status.value, reason, cap, prior)
