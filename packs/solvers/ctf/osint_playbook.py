"""Time-boxed live-OSINT playbook with a human handoff and a token cap (B-115).

Open-ended live OSINT and threat-intel lookups burned tokens with no stop rule (spooky's
Visiobibliophobia alone, ~$176; two unsolved rows). The OSINT *itself* stays human: the host network
blocked the likely platforms and the player would not hand a logged-in browser to an agent. What *is*
buildable, and what this module is, is the **rig** around the human:

  * a **time box + token cap** on a challenge's live-OSINT run (an opt-in profile on the B-033
    `LedgerMeter`: `token_cap` and `time_box_seconds`). When either is reached, `meter.check()` raises
    `budget.OsintBoxExceeded`.
  * a **written human handoff** when the box, the no-progress timer or the USD cap trips: a JSON file
    under `<workdir>/osint-handoff/` holding the exact queries already tried (so neither the human nor a
    later agent re-runs them), the candidate answers and their verdicts, the sources consulted, which
    models were already thrown at it, the spend, and a next-steps note. Writing the file also records a
    `stop` on the ledger, so `budget.is_stopped` reports it and the dispatcher/escalator leave the
    challenge alone until a human resumes it.
  * a **guess-budget guard** for the threat-intel lookup kit (``solvers/toolkits/osint_pivot.py`` +
    ``osint_online.py``): a lookup that would feed submittable candidates is refused once a challenge's
    wrong-answer count has reached the guess budget, tied to ``Workspace.wrong_count`` and the submit
    gate's post-guard approvals.

This module **never drives a browser and never starts a real Claude or Codex session**. The queries
tried are read from the B-181 hypothesis ledger (`ctf.hypothesis`) and the models tried from the B-016
escalation records (`ctf.escalation`), both already written by whatever did the work. Challenge text,
query strings and candidate payloads read here are data, never instructions.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable

from . import budget as _budget
from . import escalation as _escalation
from . import hypothesis as _hyp
from . import ledger as _ledger
from . import paths as _paths
from . import watch as _watch
from .platform.rules import challenge_key

HANDOFF_DIR = ("osint-handoff",)
HANDOFF_EVENT = "osint_handoff"

# Defaults for a per-challenge live-OSINT run. They are starting points to tune per event, never silent
# fallbacks: a profile always carries explicit numbers and the handoff file records which ones applied.
DEFAULT_TIME_BOX_SECONDS = 20 * 60          # 20 min of live OSINT before the human takes the browser
DEFAULT_TOKEN_CAP = 1_500_000               # model tokens on one challenge's live-OSINT run
DEFAULT_GUESS_BUDGET = 3                     # submittable candidate guesses before a human must approve

# Handoff reasons. The first three come from the meter; the last three from an already-recorded stop /
# the USD cap, so the loop still halts and the state is still written.
REASON_TIME_BOX = _budget.OSINT_TIME_BOX
REASON_TOKEN_CAP = _budget.OSINT_TOKEN_CAP
REASON_NO_PROGRESS = "no_progress"
REASON_MANUAL = "manual"
REASON_TEAM_SOLVE = "team_solve"
REASON_BUDGET_USD = "budget_usd"


class PlaybookError(RuntimeError):
    """The playbook cannot run as asked (no workdir, a bad profile)."""


@dataclass(frozen=True)
class OsintProfile:
    """The time-box / token-cap / guess-budget numbers for a live-OSINT run."""
    time_box_seconds: float = DEFAULT_TIME_BOX_SECONDS
    token_cap: int = DEFAULT_TOKEN_CAP
    no_progress_seconds: float = _budget.NO_PROGRESS_SECONDS
    guess_budget: int = DEFAULT_GUESS_BUDGET

    def __post_init__(self) -> None:
        if not (isinstance(self.time_box_seconds, (int, float)) and self.time_box_seconds > 0):
            raise PlaybookError("time_box_seconds must be a positive number")
        if isinstance(self.token_cap, bool) or not isinstance(self.token_cap, int) or self.token_cap < 1:
            raise PlaybookError("token_cap must be an int >= 1")
        if isinstance(self.guess_budget, bool) or not isinstance(self.guess_budget, int) or self.guess_budget < 0:
            raise PlaybookError("guess_budget must be an int >= 0")


def meter(profile_or_budget, *, workdir: Path | None = None,
          osint: OsintProfile | None = None,
          clock: Callable[[], float] = time.time,
          points=None,
          on_cap: Callable[[_budget.ChallengeStatus, Path], None] | None = None) -> _budget.LedgerMeter:
    """A `LedgerMeter` configured for the OSINT time-box/token-cap profile. Everything else about the
    meter (the USD cap from the event budget, the ledger, the team-solve hook) is unchanged."""
    osint = osint or OsintProfile()
    return _budget.LedgerMeter(profile_or_budget, workdir=workdir, points=points,
                               no_progress_seconds=osint.no_progress_seconds,
                               token_cap=osint.token_cap, time_box_seconds=osint.time_box_seconds,
                               on_cap=on_cap, clock=clock)


def open_box(m: _budget.LedgerMeter, challenge_id: str, *, points: float | None = None,
             opened_at=None, name: str | None = None) -> dict:
    """Start a challenge's live-OSINT box: register it as a tail (so the no-progress timer always
    applies, regardless of points) and anchor the time box at `opened_at` (default: now, via a progress
    event that also starts the no-progress clock)."""
    rec = m.register(challenge_id, points=points, opened_at=opened_at, tail=True, name=name)
    m.mark_progress(challenge_id, "live-OSINT box opened")
    return rec


# --------------------------------------------------------------------------- what has already been done

@dataclass(frozen=True)
class TriedQuery:
    method: str
    result: str
    agent: str
    evidence: str
    verified: bool


def tried_queries(challenge_id: str, workdir: Path | None = None) -> list[TriedQuery]:
    """The OSINT queries / probes already run for this challenge (latest result per method), from the
    hypothesis ledger, so the handoff human and any resuming agent do not re-run them."""
    out = [TriedQuery(str(r.get("method", "")), str(r.get("result", "")),
                      str(r.get("agent", "unknown")), str(r.get("evidence", "")),
                      bool(r.get("verified", False)))
           for r in _hyp.latest_by_method(challenge_id, workdir).values()]
    return sorted(out, key=lambda t: t.method)


@dataclass(frozen=True)
class Candidate:
    value: str
    source: str          # "hypothesis" | "workspace"
    verdict: str         # verified | unverified | incorrect | correct | tried
    agent: str = ""
    resubmit: bool = True  # False once the value is a known-wrong answer

    def to_dict(self) -> dict:
        return asdict(self)


def candidates(challenge_id: str, *, workdir: Path | None = None, workspace=None) -> list[Candidate]:
    """Candidate answers already produced and their verdicts: positive payloads from the hypothesis
    ledger (verified or not) and every flag already submitted on the workspace (`workspace.load_tried`).
    A value already judged `incorrect` is marked `resubmit=False` -- it must not be guessed again."""
    out: list[Candidate] = []
    wrong: set[str] = set()
    if workspace is not None:
        for a in workspace.load_tried().get("attempts", []):
            flag, status = str(a.get("flag", "")), str(a.get("status", ""))
            if not flag:
                continue
            if status == "incorrect":
                wrong.add(flag)
            out.append(Candidate(flag, "workspace", status, resubmit=(status != "incorrect")))
    for r in _hyp.read(challenge_id, workdir):
        if r.get("result") != _hyp.POSITIVE:
            continue
        payload = r.get("payload")
        if not payload:
            continue
        payload = str(payload)
        verdict = "verified" if r.get("verified") else "unverified"
        out.append(Candidate(payload, "hypothesis", verdict, str(r.get("agent", "unknown")),
                             resubmit=(payload not in wrong)))
    return out


def models_tried(challenge_id: str, workdir: Path | None = None) -> list[str]:
    """Which models were already thrown at this challenge (owner launches, escalation targets, stops),
    from the B-016 escalation records, so the handoff does not suggest re-running a model that failed."""
    key = challenge_key(str(challenge_id).strip())
    states = _escalation.read_states(workdir, claims=None)
    s = states.get(key)
    if s is None:
        return []
    seen: list[str] = []
    for rec in [*s.launches, *s.stops]:
        m = str(rec.get("model") or "").strip()
        if m and m not in seen:
            seen.append(m)
    for e in s.escalations:
        if e.get("status") == _escalation.STATUS_DISPATCHED:
            m = str(e.get("to_model") or "").strip()
            if m and m not in seen:
                seen.append(m)
    return seen


# --------------------------------------------------------------------------------- the handoff

@dataclass(frozen=True)
class Handoff:
    challenge_id: str
    reason: str
    path: Path
    spent_usd: float
    tokens: int
    token_cap: int | None
    queries_tried: list[TriedQuery]
    candidates: list[Candidate]
    sources: list[str]
    models_tried: list[str]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["path"] = str(self.path)
        d["queries_tried"] = [asdict(q) for q in self.queries_tried]
        d["candidates"] = [c.to_dict() for c in self.candidates]
        return d


_NEXT_STEPS = (
    "A human takes over the live OSINT from here (the browser session stays with the player). "
    "Do NOT re-run the queries listed under queries_tried; they are already settled. Treat every "
    "candidate as unverified until a human pins it; a candidate marked resubmit=false is a known-wrong "
    "answer and must never be submitted again. Nothing is run automatically past this handoff."
)


def _handoff_dir(workdir: Path | None) -> Path:
    base = _paths.workdir() if workdir is None else Path(workdir)
    return base.joinpath(*HANDOFF_DIR)


def existing_handoff(challenge_id: str, workdir: Path | None = None) -> dict | None:
    """The most recent handoff already written for this challenge (the ledger record merged with its
    on-disk file), or None. Used so a loop that keeps calling `guard` does not write a new file every
    step once the challenge is already handed off."""
    cid = str(challenge_id).strip()
    last = None
    for rec in _ledger.read(workdir):
        if rec.get("event") == HANDOFF_EVENT and str(rec.get("challenge_id", "")).strip() == cid:
            last = rec
    if last is None:
        return None
    out = dict(last)
    p = last.get("path")
    if p and Path(p).exists():
        try:
            out["doc"] = json.loads(Path(p).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            out["doc"] = None
    return out


def build_handoff(m: _budget.LedgerMeter, challenge_id: str, *, reason: str,
                  sources=(), notes: str = "", workspace=None,
                  record_stop: bool = True, now: float | None = None,
                  on_handoff: Callable[["Handoff"], None] | None = None) -> Handoff:
    """Write the handoff file for a challenge and (when `record_stop`) record a `stop` so the rest of
    the system leaves it to the human. Reads tried queries, candidates and models-tried from the
    ledgers. Never contacts a browser or a model.

    `sources` is the list of sources the human should consult (or already consulted) -- free strings the
    caller supplies; `notes` is a free note for the write-up. Returns the `Handoff`."""
    cid = str(challenge_id).strip()
    if not cid:
        raise PlaybookError("build_handoff needs a challenge id")
    now = m.clock() if now is None else now
    spend = m.spent(cid)
    tried = tried_queries(cid, m.workdir)
    cands = candidates(cid, workdir=m.workdir, workspace=workspace)
    models = models_tried(cid, m.workdir)
    src = [str(s) for s in sources]

    d = _handoff_dir(m.workdir)
    d.mkdir(parents=True, exist_ok=True)
    safe = _watch.safe_id(cid)
    n = len(list(d.glob(f"{safe}-*.json"))) + 1
    path = d / f"{safe}-{n}.json"

    doc = {
        "challenge_id": cid,
        "reason": reason,
        "at": now,
        "spent_usd": round(spend.usd, 6),
        "tokens": spend.tokens,
        "token_cap": m.token_cap,
        "time_box_seconds": m.time_box_seconds,
        "box_seconds_left": m.box_seconds_left(cid),
        "queries_tried": [asdict(q) for q in tried],
        "candidates": [c.to_dict() for c in cands],
        "sources": src,
        "models_tried": models,
        "notes": str(notes),
        "next_steps": _NEXT_STEPS,
    }
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=1, default=str)

    if record_stop and _budget.is_stopped(cid, workdir=m.workdir) is None:
        m.stop(cid, "manual", by="osint-box", note=f"osint {reason} handoff: {path}")
    # tok (not "tokens"): the ledger refuses any field whose key contains "token" as a possible secret.
    _ledger.append(HANDOFF_EVENT, workdir=m.workdir, challenge_id=cid, reason=reason, path=str(path),
                   spent_usd=round(spend.usd, 6), tok=spend.tokens,
                   queries=len(tried), candidates=len(cands))

    h = Handoff(cid, reason, path, round(spend.usd, 6), spend.tokens, m.token_cap, tried, cands, src, models)
    if on_handoff is not None:
        on_handoff(h)
    return h


def guard(m: _budget.LedgerMeter, challenge_id: str, *, sources=(), workspace=None, notes: str = "",
          now: float | None = None, on_handoff: Callable[["Handoff"], None] | None = None) -> Handoff | None:
    """The one call a live-OSINT loop makes before each step. Returns None to continue, or a `Handoff`
    (written once) when the token cap, the time box, the no-progress timer, a stop or the USD cap has
    tripped -- at which point the loop halts and the human takes over.

    Idempotent: once a challenge is handed off, later calls return the existing handoff without writing
    a new file."""
    cid = str(challenge_id).strip()
    prior = existing_handoff(cid, m.workdir)
    try:
        m.check(cid)
        if prior is not None:
            return _handoff_from_record(cid, prior)
        return None
    except _budget.OsintBoxExceeded as e:
        if prior is not None:
            return _handoff_from_record(cid, prior)
        return build_handoff(m, cid, reason=e.reason, sources=sources, workspace=workspace, notes=notes,
                             record_stop=True, now=now, on_handoff=on_handoff)
    except _budget.ChallengeStopped as e:
        if prior is not None:
            return _handoff_from_record(cid, prior)
        # Already stopped (team solve / manual / the no-progress timer that check() just recorded):
        # write the state once, but do not record another stop.
        return build_handoff(m, cid, reason=e.reason, sources=sources, workspace=workspace, notes=notes,
                             record_stop=False, now=now, on_handoff=on_handoff)
    except _budget.BudgetExceeded:
        if prior is not None:
            return _handoff_from_record(cid, prior)
        return build_handoff(m, cid, reason=REASON_BUDGET_USD, sources=sources, workspace=workspace,
                             notes=notes, record_stop=True, now=now, on_handoff=on_handoff)


def _handoff_from_record(cid: str, rec: dict) -> Handoff:
    """Reconstruct a lightweight `Handoff` from an already-written ledger record (and its file)."""
    doc = rec.get("doc") or {}
    tried = [TriedQuery(str(q.get("method", "")), str(q.get("result", "")), str(q.get("agent", "unknown")),
                        str(q.get("evidence", "")), bool(q.get("verified", False)))
             for q in doc.get("queries_tried", [])]
    cands = [Candidate(str(c.get("value", "")), str(c.get("source", "")), str(c.get("verdict", "")),
                       str(c.get("agent", "")), bool(c.get("resubmit", True)))
             for c in doc.get("candidates", [])]
    return Handoff(cid, str(rec.get("reason", "")), Path(str(rec.get("path", ""))),
                   float(rec.get("spent_usd") or 0.0), int(rec.get("tok") or 0),
                   doc.get("token_cap"), tried, cands, [str(s) for s in doc.get("sources", [])],
                   [str(x) for x in doc.get("models_tried", [])])


# ------------------------------------------------------------------ threat-intel guess-budget guard

@dataclass(frozen=True)
class GuessGuard:
    allowed: bool
    wrong_count: int
    guess_budget: int
    remaining: int          # guesses left before the budget bites (0 once reached)
    approvals_left: int     # unused player post-guard approvals that still permit a lookup
    reason: str

    def to_dict(self) -> dict:
        return asdict(self)


def check_guess_budget(wrong_count: int, *, guess_budget: int = DEFAULT_GUESS_BUDGET,
                       approvals_left: int = 0) -> GuessGuard:
    """Whether a threat-intel lookup that would feed a submittable candidate may run. It is allowed
    until the challenge's wrong-answer count reaches the guess budget; after that only an unused player
    approval (the submit gate's post-guard approval) permits it. This is the guardrail that stops the
    OSINT kit from being used as an unbounded guess generator."""
    if isinstance(wrong_count, bool) or not isinstance(wrong_count, int) or wrong_count < 0:
        raise PlaybookError("wrong_count must be an int >= 0")
    if isinstance(guess_budget, bool) or not isinstance(guess_budget, int) or guess_budget < 0:
        raise PlaybookError("guess_budget must be an int >= 0")
    approvals_left = max(0, int(approvals_left))
    remaining = max(0, guess_budget - wrong_count)
    if remaining > 0:
        return GuessGuard(True, wrong_count, guess_budget, remaining, approvals_left,
                          f"{remaining} guess(es) left before the budget of {guess_budget}")
    if approvals_left > 0:
        return GuessGuard(True, wrong_count, guess_budget, 0, approvals_left,
                          f"guess budget of {guess_budget} reached; a player approval permits this lookup "
                          f"({approvals_left} left)")
    return GuessGuard(False, wrong_count, guess_budget, 0, 0,
                      f"{wrong_count} wrong answer(s) already on this challenge; the guess budget of "
                      f"{guess_budget} is spent -- stop and ask the player before another candidate lookup")


def guard_osint_lookup(workspace, *, guess_budget: int = DEFAULT_GUESS_BUDGET) -> GuessGuard:
    """The guess-budget guard bound to a `ctf.workspace.Challenge`: reads its `wrong_count()` and its
    unused post-guard approvals (`post_guard_approvals_left()`), so the OSINT kit honours exactly the
    submit gate's wrong-answer accounting."""
    return check_guess_budget(workspace.wrong_count(), guess_budget=guess_budget,
                              approvals_left=workspace.post_guard_approvals_left())
