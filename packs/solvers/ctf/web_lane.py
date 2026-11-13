"""ctf.web_lane: the Huntress web Layer-1 release lane (B-007).

At release this starts a web Layer-1 on every web row: it forces the attempt open (with a bounded
retry), waits through provisioning, runs the read-only proof reader (``solvers/web/proof_hunt.py``)
on the attempt's own targets, and banks each ``proof_<32 hex>`` it reads.

This is the Huntress ``tools/web_open.py`` release race ported onto the B-005 platform adapter
(``ctf.platform``).  ``tools/web_open.py`` and the 18 Game Master modules it dragged in are NOT
carried (B-240 deferred); only the machinery it drove is -- ``solvers/web/proof_hunt.py`` and the
Day-26/27 readers.  The adapter already does the Game Master wire (start/status/submit).  The Game
Master wire ops ``op=retry`` and ``op=practice`` are still unported (``ctf.platform.gamemaster``
lists both as not carried); this lane's ``--dry-run`` is a local no-submit read, not that wire op.

Policy boundaries this lane keeps (it never relaxes them):

  * **GET-only (enforced, not assumed).**  Whether Layer 1 may take a state-changing web action on a
    scope-locked target is an open decision (Open O-2).  ``proof_hunt`` is NOT read-only by
    construction: after recon its clue-gated siblings can send explicitly authorized state-changing
    requests (POST reset/forge/race/stored-XSS paths -- see the reader's own docstring).  Until an
    event-profile O-2 setting authorizes them, the lane forces the reader into GET-only mode
    (``ctx['get_only']`` -> every scope-locked ``WebClient`` the reader builds, its siblings' included,
    refuses any non-GET HTTP method and any WebSocket conversation before it reaches the wire).  What
    is enforced is exactly that: no non-GET HTTP request and no WebSocket application message reaches
    the target (a GET with side effects on a badly built app is outside what a client can enforce).
    The POST, SSRF, authorization and header-trust classes are B-233..B-236.  The server-first
    WebSocket read (B-237, ``ctf.web_ws``) runs inside this rule: one GET upgrade, zero frames sent.
    A WebSocket class that needs a client message stays refused until O-2.
  * **Game Master only.**  The lane reads the Game Master attempt shape (``spec.raw['status']``) and
    forces attempts open with ``start_instance``.  It refuses any other platform kind with a named
    reason before any start, so it can never fire a CTFd ``start_instance`` on a web row.
  * **Released-and-unsolved filter (not an active-day fence).**  ``select_web_rows`` returns the web
    rows the platform currently lists as released and visible to our team, minus those our team has
    solved (``run_lane`` -> ``select_web_rows`` -> ``gate.list_challenges``).  It is a category +
    solved-status filter, not a per-day release band: it does not restrict to the active day's
    published ids (the archived ``release_scope.py`` did, and whether to re-add that needs a human
    policy decision).  It still cannot touch an unreleased id or another squad's attempt.
  * **The opener owns the clock.**  A Time Trial or Mastery id (``.../time_trial``, ``.../mastery``)
    is never *started* here: its start runs a scored clock and only the opener starts a clock
    (B-003/B-252; the adapter refuses ``start_instance`` on a timed id).  The lane reads an *already
    running* timed attempt and skips one that is not, with a named reason.
  * **It banks only a proof.**  A value is submitted only when both ``proof_hunt.is_proof`` and the
    active event's ``[proof]`` format (``flagfmt``) accept it; a non-proof is never sent.  ``--dry-run``
    runs the whole read but submits nothing.

The lane never runs a model and never guesses.  Every submission goes through the SubmitGate
(``ctf.platform.get_adapter`` -> ``submit_answers``), which is the one road to the platform.
"""
from __future__ import annotations

import dataclasses
import importlib.util
import time as _time
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from . import paths as _paths
from . import web_ws as _web_ws
from .platform import gamemaster as _gm

PROVENANCE = "web-lane/proof_hunt (B-007)"
GAMEMASTER_KIND = "gamemaster"
MANUAL_KIND = "manual"

# Default knobs (the user's bar is "web solved in under 60 s no matter what we get").
DEFAULT_MAX_REQUESTS = 400          # per target, matching proof_hunt's own default
DEFAULT_DEADLINE_S = 55.0           # the read budget per row (capped further by the attempt deadline)
DEFAULT_START_RETRIES = 2           # "one or two capped forced starts"
DEFAULT_START_BACKOFF_S = 2.0       # between forced-start tries
DEFAULT_POLL_TOTAL_S = 180.0        # how long to wait through provisioning
DEFAULT_POLL_INTERVAL_S = 3.0       # between provisioning polls

# The timed-id test is the adapter's (one definition, no fork): the lane re-exports it.
TIMED_SUFFIXES = _gm.TIMED_SUFFIXES
is_timed = _gm.is_timed

# Row states.
BANKED = "banked"                   # a proof read and the platform JUDGED it correct (or already solved)
FOUND = "found"                     # proof read; not submitted (dry-run mode)
NO_PROOF = "no-proof"               # ran, read nothing bankable
SUBMIT_INCORRECT = "submit-incorrect"   # a proof was read and sent, but the platform judged it wrong
SUBMIT_REFUSED = "submit-refused"       # the submission was refused (policy/manual/closed: NOT_ALLOWED)
SUBMIT_RATE_LIMITED = "submit-rate-limited"  # not judged: the platform rate-limited the submit
SUBMIT_PENDING = "submit-pending"       # not judged yet: paused, queued or spooled -- verify later
NOT_STARTED = "not-started"         # the attempt never reached a running state (e.g. a 503 that persists)
SKIPPED_TIMED = "skipped-timed"     # a timed id not already running: the opener owns its clock
SKIPPED_SOLVED = "skipped-solved"   # already solved by our team
ERROR = "error"                     # an unexpected failure (named in .reason)


class WebLaneError(RuntimeError):
    """A web-lane precondition failed with a named reason (no silent fallback)."""


@dataclasses.dataclass(frozen=True)
class RowResult:
    challenge_id: str
    state: str
    reason: str = ""
    proofs: Mapping[str, str] = dataclasses.field(default_factory=dict)
    targets: tuple[str, ...] = ()
    seconds: float = 0.0
    submitted: Any = None           # the SubmitResult, or None when nothing was sent
    notes: tuple[str, ...] = ()     # B-237: why a class did not read an unread target (ctf.web_ws)

    @property
    def ok(self) -> bool:
        return self.state in (BANKED, FOUND)


# --------------------------------------------------------------------------------------------------
#  proof_hunt loader (by file name, exactly as tools/web_open.py loaded it; loud on absence)
# --------------------------------------------------------------------------------------------------
_PROOF_HUNT = None


def load_proof_hunt():
    """Load ``solvers/web/proof_hunt.py`` by file name.  A missing file fails loudly (contract 6)."""
    global _PROOF_HUNT
    if _PROOF_HUNT is not None:
        return _PROOF_HUNT
    path = _paths.repo_root() / "solvers" / "web" / "proof_hunt.py"
    if not path.is_file():
        raise WebLaneError(f"web lane: the proof reader {path} is missing; the web lane cannot run "
                           "(carry solvers/web/proof_hunt.py -- B-240)")
    spec = importlib.util.spec_from_file_location("proof_hunt", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    for name in ("solve_targets", "is_proof"):
        if not callable(getattr(mod, name, None)):
            raise WebLaneError(f"web lane: {path} has no {name}(); its contract changed (B-240/B-007)")
    _PROOF_HUNT = mod
    return mod


# --------------------------------------------------------------------------------------------------
#  row selection (the release scope fence)
# --------------------------------------------------------------------------------------------------
def is_web_row(challenge) -> bool:
    """A web lane row.  The Game Master puts the lane in ``Challenge.category``."""
    return str(getattr(challenge, "category", "") or "").strip().lower() == "web"


def parse_deadline(value) -> float | None:
    """Parse an ISO-8601 attempt deadline to epoch seconds, or None.  A local helper so the lane does
    not reach into the adapter's private ``_epoch``; kept identical to ``gamemaster`` on an ISO string."""
    if not isinstance(value, str) or not value:
        return None
    import datetime as _dt
    try:
        return _dt.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def require_gamemaster(gate) -> None:
    """Refuse any platform kind but the Game Master, with a named reason, before any start_instance.
    The lane reads the Game Master attempt shape and would mis-drive a CTFd/other event's instances.

    A manual-mode event (``kind == "manual"``: the event forbids automation on its platform) raises
    ``NotAllowed`` -- the event's rules forbid the lane, which the CLI reports as exit 4.  Any other
    non-Game-Master kind raises ``WebLaneError`` (the lane does not support it: exit 2)."""
    from .platform import NotAllowed
    kind = getattr(gate, "kind", None)
    if kind == MANUAL_KIND:
        raise NotAllowed(
            "web lane: the active event is in manual mode (its rules forbid automated instances and "
            "submissions); the player works it by hand. Refusing before any start_instance.")
    if kind != GAMEMASTER_KIND:
        raise WebLaneError(
            f"web lane: this lane drives the Game Master attempt shape only; the active event's "
            f"platform is {kind!r}, not {GAMEMASTER_KIND!r}. Refusing before any start_instance "
            "(a non-Game-Master start_instance would be a state-changing platform action).")


def select_web_rows(gate, *, include_solved: bool = False) -> list:
    """The web rows the platform currently lists as released and visible to our team, minus those our
    team has solved.  A category + solved-status filter -- not a per-day release band (see the module
    docstring): the lane acts only on what this returns."""
    rows = []
    for ch in gate.list_challenges():
        if not is_web_row(ch):
            continue
        if ch.solved_by_team and not include_solved:
            continue
        rows.append(ch)
    return rows


# --------------------------------------------------------------------------------------------------
#  forced start + provisioning-aware polling
# --------------------------------------------------------------------------------------------------
def _is_running(inst) -> bool:
    return inst is not None and getattr(inst, "state", None) == "running"


def ensure_running(gate, challenge_id: str, *, retries: int = DEFAULT_START_RETRIES,
                   backoff_s: float = DEFAULT_START_BACKOFF_S, poll_total_s: float = DEFAULT_POLL_TOTAL_S,
                   poll_interval_s: float = DEFAULT_POLL_INTERVAL_S, sleep: Callable[[float], None] = _time.sleep,
                   now: Callable[[], float] = _time.monotonic):
    """Drive the attempt for ``challenge_id`` to a running instance and return it.

    A **timed** id is never started here (the opener owns the clock): its current status is read and
    returned as-is; a non-running one is the caller's cue to skip it.

    A **base** id is forced open: ``start_instance`` is retried up to ``retries`` extra times on a
    *transient* platform failure (a 503 at release), then ``instance_status`` is polled through
    ``starting``/``preparing`` until it is running or ``poll_total_s`` elapses.  The last instance
    (possibly non-running) is returned either way -- a persistent server-side 503 is detected, not
    papered over.  ``reason`` on the returned ``_StartOutcome`` names why if it is not running.

    A **refusal** that can never succeed (``NotSupported``/``NotAllowed``: manual mode, instances
    forbidden, no instance support) is NOT retried -- it is re-raised so the CLI's loud refusal path
    runs.  Only a plain transient ``PlatformError`` (e.g. a 5xx) is retried.
    """
    from .platform import NotSupported, PlatformError

    if is_timed(challenge_id):
        try:
            inst = gate.instance_status(challenge_id)
        except NotSupported:
            raise
        except PlatformError as e:
            return _StartOutcome(None, f"instance_status failed: {e}")
        if _is_running(inst):
            return _StartOutcome(inst, "")
        return _StartOutcome(inst, "a timed id is not running and only the opener starts its clock "
                             "(B-003); the lane does not start a scored clock")

    inst = None
    last_err = ""
    for attempt in range(retries + 1):
        try:
            inst = gate.start_instance(challenge_id)
            last_err = ""
            break
        except NotSupported:
            raise                       # a refusal, not a transient error: never retried, never swallowed
        except PlatformError as e:
            last_err = str(e)
            if attempt < retries:
                sleep(backoff_s)
    if inst is None:
        return _StartOutcome(None, f"forced start failed after {retries + 1} tries: {last_err}")
    if _is_running(inst):
        return _StartOutcome(inst, "")

    deadline = now() + poll_total_s
    while now() < deadline:
        sleep(poll_interval_s)
        try:
            inst = gate.instance_status(challenge_id)
        except NotSupported:
            raise
        except PlatformError as e:
            last_err = str(e)
            continue
        if _is_running(inst):
            return _StartOutcome(inst, "")
    return _StartOutcome(inst, f"the attempt never reached running within {poll_total_s:.0f}s "
                         f"(last state {getattr(inst, 'state', '?')!r}{'; ' + last_err if last_err else ''})")


@dataclasses.dataclass(frozen=True)
class _StartOutcome:
    instance: Any
    reason: str


# --------------------------------------------------------------------------------------------------
#  attempt spec -> proof_hunt targets
# --------------------------------------------------------------------------------------------------
def _target_urls(status: Mapping[str, Any], instance) -> list[str]:
    urls = [t.get("url") for t in status.get("targets") or () if isinstance(t, dict) and t.get("url")]
    if not urls and instance is not None and getattr(instance, "connection_info", ""):
        urls = [u for u in instance.connection_info.splitlines() if u.strip()]
    return urls


def _answer_ids(status: Mapping[str, Any]) -> list[str]:
    ids = status.get("answer_ids")
    if not isinstance(ids, list) or not ids:
        ids = [q.get("id") for q in status.get("questions") or () if isinstance(q, dict)]
    return [i for i in ids if isinstance(i, str) and i]


def _question_text(status: Mapping[str, Any], answer_id: str) -> str:
    for q in status.get("questions") or ():
        if isinstance(q, dict) and q.get("id") == answer_id:
            return str(q.get("question") or q.get("text") or "")
    return ""


def build_targets(status: Mapping[str, Any], instance) -> list[dict]:
    """Pair each answer id with a target URL for ``proof_hunt.solve_targets``.

    One target and many answers -> every answer runs against that target.  Equal counts -> paired by
    order.  Otherwise answer i takes target i, falling back to the first target.  An answer with no
    target at all is dropped (it has nothing to read).
    """
    urls = _target_urls(status, instance)
    aids = _answer_ids(status)
    if not urls or not aids:
        return []
    out = []
    for i, aid in enumerate(aids):
        url = urls[i] if i < len(urls) else urls[0]
        out.append({"answer_id": aid, "url": url, "index": i + 1,
                    "question": _question_text(status, aid)})
    return out


def _prompt_text(status: Mapping[str, Any]) -> str:
    parts = [str(status.get("prompt") or ""), str(status.get("guidance") or "")]
    parts += [str(q.get("question") or "") for q in status.get("questions") or () if isinstance(q, dict)]
    return "\n".join(p for p in parts if p)


# --------------------------------------------------------------------------------------------------
#  per-row and whole-lane runs
# --------------------------------------------------------------------------------------------------
def _is_event_proof(gate, value: str) -> bool:
    """Cross-check a value against the active event's ``[proof]`` format at the lane, so banking is not
    gated by ``proof_hunt.is_proof`` alone (that is ``flagfmt.PROOF_TEXT`` for Huntress, but the lane
    should not depend on the coupling).  An event with no ``[proof]`` token banks nothing (fail-closed)."""
    from . import flagfmt as _flagfmt
    profile = getattr(gate, "profile", None)
    if profile is None:
        # Every SubmitGate carries .profile; a gate without one cannot be cross-checked, so refuse
        # loudly rather than bank on proof_hunt.is_proof alone (no silent fallback).
        raise WebLaneError("web lane: the gate carries no event profile, so a read value cannot be "
                           "checked against the event's [proof] format; refusing to bank")
    try:
        return _flagfmt.for_profile(profile).is_proof(value)
    except LookupError:
        return False                    # no [proof] format defined: refuse to bank (no silent fallback)


def _submit_state(status) -> tuple[str, str]:
    """Map a ``SubmitStatus`` to a named row state and note.  Only a JUDGED-correct (or already-solved)
    verdict is ``BANKED``; every other verdict gets its own state so the operator is not misinformed."""
    from .platform import SubmitStatus
    if status in (SubmitStatus.CORRECT, SubmitStatus.ALREADY_SOLVED):
        return BANKED, status.value
    if status is SubmitStatus.INCORRECT:
        return SUBMIT_INCORRECT, status.value
    if status is SubmitStatus.NOT_ALLOWED:
        return SUBMIT_REFUSED, status.value
    if status is SubmitStatus.RATE_LIMITED:
        return SUBMIT_RATE_LIMITED, status.value
    return SUBMIT_PENDING, status.value     # PAUSED / queued / spooled: not judged yet


def run_row(gate, challenge, *, practice: bool = False, include_solved: bool = False,
            max_requests: int = DEFAULT_MAX_REQUESTS,
            retries: int = DEFAULT_START_RETRIES, backoff_s: float = DEFAULT_START_BACKOFF_S,
            poll_total_s: float = DEFAULT_POLL_TOTAL_S, poll_interval_s: float = DEFAULT_POLL_INTERVAL_S,
            deadline_s: float = DEFAULT_DEADLINE_S, sleep: Callable[[float], None] = _time.sleep,
            now: Callable[[], float] = _time.monotonic, proof_hunt=None) -> RowResult:
    """Open one released web row and bank the proofs it yields.  ``challenge`` is a released web
    ``Challenge`` (from ``select_web_rows``).  A row our team already solved is skipped unless
    ``include_solved`` is set (the operator opted in to re-run it).

    The read budget is ``min(attempt deadline, now + deadline_s)``: the attempt's own deadline never
    extends one row's read past ``deadline_s`` (the 60 s bar), so a slow row cannot hold up the next."""
    ph = proof_hunt or load_proof_hunt()
    require_gamemaster(gate)
    cid = challenge.id
    if challenge.solved_by_team and not include_solved:
        return RowResult(cid, SKIPPED_SOLVED, "already solved by our team")

    outcome = ensure_running(gate, cid, retries=retries, backoff_s=backoff_s, poll_total_s=poll_total_s,
                             poll_interval_s=poll_interval_s, sleep=sleep, now=now)
    inst = outcome.instance
    if not _is_running(inst):
        state = SKIPPED_TIMED if is_timed(cid) else NOT_STARTED
        return RowResult(cid, state, outcome.reason)

    try:
        spec = gate.get_challenge(cid)
        status = spec.raw.get("status") if isinstance(spec.raw, dict) else None
    except Exception as e:
        return RowResult(cid, ERROR, f"reading the attempt spec failed: {e}")
    if not isinstance(status, Mapping):
        return RowResult(cid, ERROR, "the attempt has no status body (no questions/targets to read)")

    targets = build_targets(status, inst)
    if not targets:
        return RowResult(cid, NO_PROOF, "the attempt lists no target+answer pair to read")
    target_urls = tuple(dict.fromkeys(t["url"] for t in targets))

    inst_deadline = parse_deadline(status.get("deadline"))
    if inst_deadline is None:
        inst_deadline = getattr(inst, "expires_at", None)
    # get_only=True: proof_hunt's clue-gated siblings may send explicitly authorized state-changing
    # requests after recon; until Open O-2 settles the lane forbids them, so the scope-locked WebClient
    # refuses any non-GET before it reaches the wire.  This is the lane's GET-only guarantee, enforced.
    read_deadline = _time.time() + deadline_s
    if inst_deadline is not None:
        read_deadline = min(float(inst_deadline), read_deadline)
    class_sink: dict = {}
    ctx = {"deadline": read_deadline,
           "max_requests": max_requests, "log_dir": None, "challenge": cid,
           "prompt": _prompt_text(status), "get_only": True, "class_sink": class_sink}

    t0 = _time.time()
    try:
        answers = ph.solve_targets(targets, ctx)      # never raises, GET-only (enforced), same-host reads
    except Exception as e:                            # defensive: the contract says it never raises
        return RowResult(cid, ERROR, f"proof_hunt raised: {e}", targets=target_urls,
                         seconds=_time.time() - t0)
    secs = _time.time() - t0

    proofs = {aid: v for aid, v in (answers or {}).items() if ph.is_proof(v) and _is_event_proof(gate, v)}
    # B-237: name why a class did not read each unread target (WebSocket class outcome, class hint).
    notes = tuple(_web_ws.class_notes(class_sink, proofs))
    if not proofs:
        reason = "no proof read from the target" + (f" -- {notes[0]}" if notes else "")
        return RowResult(cid, NO_PROOF, reason, targets=target_urls, seconds=secs, notes=notes)
    if practice:
        return RowResult(cid, FOUND, "dry-run: read but not submitted", proofs=proofs,
                         targets=target_urls, seconds=secs, notes=notes)
    # allow_nonstandard: a Huntress web answer is the brief-defined proof_<32 hex>, not the event's
    # flag{...} format, so base_checks' flag-format gate does not apply.  The lane has already dropped
    # every value that is not is_proof() AND not the active event's [proof] format (_is_event_proof),
    # so nothing off-format can reach the platform this way.
    result = gate.submit_answers(cid, proofs, provenance=PROVENANCE, allow_nonstandard=True)
    state, note = _submit_state(result.status)
    return RowResult(cid, state, f"submitted {len(proofs)} proof(s): {note}",
                     proofs=proofs, targets=target_urls, seconds=secs, submitted=result, notes=notes)


# --------------------------------------------------------------------------------------------------
#  B-150: the pinned isolated browser worker, exposed to the lane (detection first, agents second)
# --------------------------------------------------------------------------------------------------
# The browser-execution web classes (DOM/reflected XSS, postMessage, CSP effects) need a real browser
# to run the target's own JavaScript.  ctf.web_browser is that pinned, sandboxed worker; the lane
# exposes it here so detection (and B-122) have one import site.  availability() never raises -- a
# browser that is not installed makes detection fall back to a web agent with a named reason.

def browser_availability():
    """(True, detail) when the isolated browser can be started, else (False, reason).  Detection
    calls this first; a False is the cue to hand a browser-required class to an agent."""
    from . import web_browser
    return web_browser.availability()


def browser_observe(url: str, script: str = "observe_load", **kw):
    """One bounded evaluate-and-observe on a scope-locked target through the pinned browser worker
    (``ctf.web_browser.observe``).  Raises ``BrowserUnavailable`` (agents second) when no browser is
    installed, and ``ctf.scope.OutOfScope`` for an out-of-scope host (never bypassed)."""
    from . import web_browser
    return web_browser.observe(url, script, **kw)


def run_lane(gate, *, rows: Sequence | None = None, practice: bool = False,
             include_solved: bool = False, **row_kw) -> list[RowResult]:
    """Start a web Layer-1 on every released web row and bank what it reads.  ``rows`` defaults to
    ``select_web_rows(gate)`` -- the released-and-unsolved filter.  Refuses any platform kind but the
    Game Master before any start (``require_gamemaster``).  ``include_solved`` both lists and runs
    rows our team already solved.

    Rows run one after another; each row's read is capped at ``deadline_s`` (see ``run_row``).  Running
    rows concurrently is not done here: the SubmitGate's queue/wire journal are not shown thread-safe."""
    require_gamemaster(gate)
    if rows is None:
        rows = select_web_rows(gate, include_solved=include_solved)
    return [run_row(gate, ch, practice=practice, include_solved=include_solved, **row_kw) for ch in rows]
