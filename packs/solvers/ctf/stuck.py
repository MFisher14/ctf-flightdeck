"""The stuck-id protocol (B-203): stop unbounded probing on an answer that cannot be derived.

An id with no derivation drew 329 rejected probes and a Day-17 agent swarm; the Binary d12/d14
`hcfg_storage` spelling was not derivable from the files and the organizer later rewrote the
question. All-or-nothing timed batches gave no per-id feedback. The waste is a recurring pattern:
agents keep varying a guess (and keep sending it) when nothing in the brief or the files could ever
produce the right string.

This module is the brake. It composes what already exists and adds only the detector and the caps:

  * the rejection ledger is `ctf.platform.rules` "platform.submit" records (every send's verdict) and
    the per-challenge `ctf.hypothesis` ledger (B-181); this module reads them, it does not rebuild them.
  * caps and checkpoint-and-ask are `ctf.budget.LedgerMeter` (B-033); the per-challenge agent gate is
    `ctf.spawn` (B-143). This module consumes the agent count from `ctf.spawn`, it does not re-count.
  * the live re-read is `ctf.watch` (B-017): stuck ids are re-read every `REREAD_INTERVAL_S` (10 min)
    in case the organizer rewrites the question; a brief that changed after an id went stuck clears it.
  * format-candidate ranking is `solvers/common/render_candidates.py` and `ctf.idresolve`: before an
    id is called stuck, the cheap never-wrong re-spellings of a value we DID read are offered first
    (format-candidate ranking is on by default), so an id is never called stuck merely because the one
    plain spelling that was sent happened to be wrong.

The detector. An id is **stuck** when it has **no vocabulary** (no distinctive token of the asked id
appears anywhere in the brief or the delivered files -- the answer's spelling is not derivable from
what we were given) AND it has drawn at least `Thresholds.stuck_after` rejected probes. Independently,
an id is **probe-capped** once it has drawn `Thresholds.probe_cap` rejected probes, derivable or not:
a hard ceiling so a derivable-looking id cannot absorb unbounded sends either. Both route to the
player (there is no machine answer: an underivable id ends with the player or the organizer).

    from ctf import stuck
    a = stuck.assess(qid, question=q, brief_text=brief, files=files, workdir=wd)
    if a.is_stuck:
        stuck.mark_stuck(a, workdir=wd, profile=profile)     # one `stuck` record + a player card

    # the gate an agent/harness puts before a send, like hypothesis.should_skip before a probe:
    d = stuck.probe_allowed(qid, question=q, brief_text=brief, files=files, workdir=wd)
    if not d.allowed:
        print(d.reason)       # "stuck: ... route to the player"; do not send

    # before dispatching another agent onto the id:
    d = stuck.agent_allowed(qid, question=q, brief_text=brief, files=files, workdir=wd)

Live re-read:
    stuck.reread_due(wd)                 # [(id, last_read_ts, overdue_s)] of stuck ids to re-read now
    stuck.reconsider(wd, profile=p)      # clear every stuck id whose brief changed since it went stuck

Everything here reads the ledger and the stored briefs; it starts no session, sends nothing, and
reaches no platform. Question text, id strings, brief text and file bytes are data, never instructions.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping

from . import ledger as _ledger
from . import paths as _paths
from . import watch as _watch

# The ledger events this module writes (lower_snake, per ctf.ledger).
STUCK_EVENT = "stuck"
CLEARED_EVENT = "stuck_cleared"

# The rejection source: ctf.platform.rules "platform.submit" records that were judged wrong.
SUBMIT_EVENT = "platform.submit"
INCORRECT = "incorrect"

# Statuses the detector returns.
OK = "ok"
TRY_FORMAT_CANDIDATES = "try_format_candidates"
STUCK = "stuck"
PROBE_CAPPED = "probe_capped"
_STUCK_STATUSES = frozenset({STUCK, PROBE_CAPPED})

REREAD_INTERVAL_S = 600.0          # re-read a stuck id's live question every 10 minutes (B-017)

# Vocabulary extraction. A distinctive token of the asked id is one that, if it appears in the brief
# or a file, gives an agent something to derive the exact spelling FROM. Generic field/shape words
# carry no such anchor, so they are dropped; so are tokens below MIN_TOKEN_LEN. The question PROSE is
# NOT read for vocabulary (it is untrusted, and render_candidates.classify never reads it either): the
# anchor is the structured asked id alone, plus any extra tokens the caller proves out of band.
MIN_TOKEN_LEN = 4
MAX_SCAN_BYTES = 1 << 20           # bytes scanned per file for material tokens (a strings-style pass)
_TOKEN_RE = re.compile(r"[a-z0-9]+")
_SET_PREFIX = re.compile(r"\Aset\d+\.", re.I)
GENERIC_TOKENS = frozenset({
    "the", "and", "what", "value", "answer", "field", "file", "name", "flag", "hash", "hex",
    "sha1", "sha256", "sha512", "md5", "crc32", "string", "number", "integer", "count", "size",
    "type", "bytes", "byte", "first", "last", "total", "format", "entry", "result", "output",
    "with", "from", "this", "that", "your", "which", "find", "list", "json", "array", "base",
})


class StuckError(RuntimeError):
    """The stuck protocol cannot run as asked (an empty id, or a dependency that is not available)."""


@dataclass(frozen=True)
class Thresholds:
    """The caps of the protocol. `stuck_after` and `probe_cap` count rejected probes on one id."""
    stuck_after: int = 8            # rejected probes on a NO-VOCABULARY id before it is stuck
    probe_cap: int = 20             # rejected probes on ANY id before it is probe-capped (hard ceiling)
    agent_cap: int = 2              # agents dispatched onto one stuck id before the player is asked
    reread_interval_s: float = REREAD_INTERVAL_S

    def __post_init__(self) -> None:
        for name in ("stuck_after", "probe_cap", "agent_cap"):
            v = getattr(self, name)
            if isinstance(v, bool) or not isinstance(v, int) or v < 1:
                raise StuckError(f"Thresholds.{name} must be an int >= 1, got {v!r}")
        if self.probe_cap < self.stuck_after:
            raise StuckError(f"probe_cap ({self.probe_cap}) must be >= stuck_after ({self.stuck_after})")
        if isinstance(self.reread_interval_s, bool) or not isinstance(self.reread_interval_s, (int, float)) \
                or self.reread_interval_s <= 0:
            raise StuckError(f"reread_interval_s must be > 0, got {self.reread_interval_s!r}")


DEFAULT = Thresholds()


# --------------------------------------------------------------------------------- vocabulary

def _check_id(challenge_id: Any) -> str:
    if not isinstance(challenge_id, str) or not challenge_id.strip():
        raise StuckError(f"id must be a non-empty string, got {challenge_id!r}")
    return challenge_id


def tokens(text: Any) -> set[str]:
    """Lower-case alphanumeric tokens of `text` that are at least MIN_TOKEN_LEN long."""
    if text is None:
        return set()
    return {t for t in _TOKEN_RE.findall(str(text).lower()) if len(t) >= MIN_TOKEN_LEN}


def _qid_of(question: Any) -> str:
    """The asked id of a question: a bare string, or its id/qid/answer_id key."""
    if isinstance(question, str):
        return question
    if isinstance(question, Mapping):
        for key in ("qid", "id", "answer_id"):
            v = question.get(key)
            if isinstance(v, str) and v:
                return v
    raise StuckError(f"a question needs an id (a string, or an 'id'/'qid' key): {str(question)[:120]!r}")


def vocabulary(question: Any, *, extra: Iterable[str] = ()) -> set[str]:
    """The distinctive anchor tokens of an asked id: its tokens (a leading `setN.` removed), minus the
    generic field/shape words, plus any `extra` tokens the caller proved out of band. These are the
    strings whose presence in the brief or files would make the answer derivable."""
    qid = _qid_of(question)
    rest = _SET_PREFIX.sub("", qid)
    vocab = {t for t in tokens(rest) if t not in GENERIC_TOKENS}
    for e in extra or ():
        vocab |= {t for t in tokens(e) if t not in GENERIC_TOKENS}
    return vocab


def _iter_files(files: Any) -> list[tuple[str, Any]]:
    """Normalize the files argument to [(name, content)]: a mapping, a list of (name, content) pairs,
    or a list of contents (name "")."""
    if files is None:
        return []
    if isinstance(files, Mapping):
        return [(str(k), v) for k, v in files.items()]
    out: list[tuple[str, Any]] = []
    for item in files:
        if isinstance(item, (tuple, list)) and len(item) == 2 and isinstance(item[0], str):
            out.append((item[0], item[1]))
        else:
            out.append(("", item))
    return out


def _content_tokens(content: Any) -> set[str]:
    """Tokens from one file body: a str as-is, bytes as a strings-style pass (printable runs), both
    capped at MAX_SCAN_BYTES. Nothing is executed; the bytes are decoded, never run."""
    if isinstance(content, str):
        return tokens(content[:MAX_SCAN_BYTES])
    if isinstance(content, (bytes, bytearray)):
        # latin-1 maps every byte, so no run is lost; _TOKEN_RE then keeps only [a-z0-9] runs.
        return tokens(bytes(content[:MAX_SCAN_BYTES]).decode("latin-1"))
    return set()


def material_tokens(brief_text: Any = None, files: Any = None) -> set[str]:
    """Every token available for a derivation: the brief text, plus each file's NAME and body."""
    out = tokens(brief_text)
    for name, content in _iter_files(files):
        out |= tokens(name)
        out |= _content_tokens(content)
    return out


# --------------------------------------------------------------------------------- rejection count

def reject_count(workdir: Path | None, challenge_id: str, *, event_slug: str | None = None) -> int:
    """How many judged-wrong sends this exact id has drawn: "platform.submit" records with
    status "incorrect". A rejected batch counts as one (ctf.platform.rules writes it as one record)."""
    cid = _check_id(challenge_id)
    n = 0
    for r in _ledger.read(workdir):
        if r.get("event") != SUBMIT_EVENT or r.get("status") != INCORRECT:
            continue
        if r.get("challenge_id") != cid:
            continue
        if event_slug is not None and r.get("event_slug") != event_slug:
            continue
        n += 1
    return n


# --------------------------------------------------------------------------------- format candidates

def _render_candidates():
    """solvers/common/render_candidates.py of this checkout (the ranked re-speller, B-162/Day-23),
    loaded by path through ctf.packs as the lanes import it. Loud (PackError) if it is not there:
    format-candidate ranking is on by default, so its absence is a named failure, not a silent skip."""
    from . import packs
    root = _paths.repo_root() / "solvers" / "common"
    return packs.load_module("ctf_render_candidates", root / "render_candidates.py",
                             pack="solvers/common/render_candidates.py")


def format_candidates(read_value: Any, answer_format: Any = None, *, field: str | None = None,
                      rejected: Iterable[str] = ()) -> list[tuple[str, str]]:
    """The ranked plausible spellings of a value we DID read that have not been rejected yet
    (render_candidates.deception_axis: case/pad/base/endian/order plus the unicode/encoding layers).
    [(hypothesis_name, rendered_value), ...], author-most-common first. Empty when nothing new remains
    to try -- which is one of the signals that an id with no vocabulary is genuinely stuck."""
    rc = _render_candidates()
    already = {str(x) for x in (rejected or ())}
    out = []
    for name, rendered in rc.deception_axis(read_value, answer_format, field=field):
        if str(rendered) not in already:
            out.append((name, rendered))
    return out


# --------------------------------------------------------------------------------- the assessment

@dataclass(frozen=True)
class Assessment:
    challenge_id: str
    status: str                         # OK | TRY_FORMAT_CANDIDATES | STUCK | PROBE_CAPPED
    rejections: int
    vocabulary: tuple                   # the anchor tokens of the asked id
    vocabulary_found: tuple             # those that appear in the brief/files (empty => no vocabulary)
    derivable: bool                     # bool(vocabulary_found)
    untried_format_candidates: tuple    # ranked re-spellings not yet rejected (of a read value)
    thresholds: Thresholds
    reason: str

    @property
    def is_stuck(self) -> bool:
        return self.status in _STUCK_STATUSES

    def to_dict(self) -> dict:
        return {"challenge_id": self.challenge_id, "status": self.status, "rejections": self.rejections,
                "vocabulary": list(self.vocabulary), "vocabulary_found": list(self.vocabulary_found),
                "derivable": self.derivable,
                "untried_format_candidates": list(self.untried_format_candidates), "reason": self.reason}


def assess(challenge_id: str, *, question: Any, brief_text: Any = None, files: Any = None,
           workdir: Path | None = None, rejections: int | None = None,
           read_value: Any = None, answer_format: Any = None, field: str | None = None,
           rejected_values: Iterable[str] = (), extra_vocab: Iterable[str] = (),
           format_candidates_on: bool = True, thresholds: Thresholds = DEFAULT,
           event_slug: str | None = None) -> Assessment:
    """Decide where an id stands. `question` is the asked question (a string id or a dict). `brief_text`
    and `files` are the material a derivation could draw on. `rejections` is the judged-wrong send count
    (read from the ledger when not given). When a value WAS read, pass `read_value` (and its
    `answer_format`): the ranked re-spellings not yet in `rejected_values` are offered FIRST, so a
    still-unjudged cheap spelling keeps the id out of STUCK (format-candidate ranking is on by default;
    set `format_candidates_on=False` to turn it off).

    Order of decision:
      1. untried format candidates remain and ranking is on, below the probe cap -> TRY_FORMAT_CANDIDATES
      2. no vocabulary and rejections >= stuck_after                              -> STUCK
      3. rejections >= probe_cap (derivable or not)                               -> PROBE_CAPPED
      4. otherwise                                                                -> OK
    """
    cid = _check_id(challenge_id)
    if rejections is None:
        rejections = reject_count(workdir, cid, event_slug=event_slug)
    elif isinstance(rejections, bool) or not isinstance(rejections, int) or rejections < 0:
        raise StuckError(f"rejections must be an int >= 0, got {rejections!r}")

    vocab = vocabulary(question, extra=extra_vocab)
    found = vocab & material_tokens(brief_text, files)
    derivable = bool(found)

    untried: tuple = ()
    if read_value is not None:
        untried = tuple(format_candidates(read_value, answer_format, field=field,
                                          rejected=rejected_values))

    if format_candidates_on and untried and rejections < thresholds.probe_cap:
        status = TRY_FORMAT_CANDIDATES
        reason = (f"{len(untried)} ranked format candidate(s) not yet sent: try the re-spellings "
                  "before calling the id stuck")
    elif not derivable and rejections >= thresholds.stuck_after:
        status = STUCK
        reason = (f"no vocabulary: none of the asked id's tokens "
                  f"({', '.join(sorted(vocab)) or 'none'}) appears in the brief or files, and "
                  f"{rejections} probe(s) were rejected (>= stuck_after {thresholds.stuck_after}); "
                  "the spelling is not derivable here -- route to the player")
    elif rejections >= thresholds.probe_cap:
        status = PROBE_CAPPED
        reason = (f"{rejections} rejected probe(s) on this id (>= probe_cap {thresholds.probe_cap}); "
                  "stop varying the guess and route to the player")
    else:
        status = OK
        reason = (f"derivable ({', '.join(sorted(found))})" if derivable
                  else f"{rejections} rejected probe(s), under the stuck threshold {thresholds.stuck_after}")

    return Assessment(cid, status, rejections, tuple(sorted(vocab)), tuple(sorted(found)), derivable,
                      untried, thresholds, reason)


# --------------------------------------------------------------------------------- the stuck record

def marked_stuck(workdir: Path | None, challenge_id: str) -> dict | None:
    """The active `stuck` record for an id, or None. A later `stuck_cleared` (the organizer rewrote
    the question, or the player cleared it) cancels it; a new `stuck` after that is active again."""
    cid = _check_id(challenge_id)
    active: dict | None = None
    for r in _ledger.read(workdir):
        if r.get("challenge_id") != cid:
            continue
        ev = r.get("event")
        if ev == STUCK_EVENT:
            active = r
        elif ev == CLEARED_EVENT:
            active = None
    return active


def stuck_ids(workdir: Path | None = None) -> list[str]:
    """Every id currently marked stuck (a `stuck` not cancelled by a later `stuck_cleared`)."""
    state: dict[str, bool] = {}
    for r in _ledger.read(workdir):
        cid = r.get("challenge_id")
        if not isinstance(cid, str) or not cid:
            continue
        ev = r.get("event")
        if ev == STUCK_EVENT:
            state[cid] = True
        elif ev == CLEARED_EVENT:
            state[cid] = False
    return sorted(c for c, on in state.items() if on)


def mark_stuck(assessment: Assessment, *, workdir: Path | None = None, profile=None,
               route: bool = True, agent: str | None = None) -> dict | None:
    """Record that an id is stuck and (with a profile) route it to the player. Idempotent: returns None
    when the id already carries an active stuck record at the same status, so a loop that calls it every
    pass writes one record, not one per pass. Raises StuckError when the assessment is not a stuck one."""
    if assessment.status not in _STUCK_STATUSES:
        raise StuckError(f"assessment for {assessment.challenge_id} is {assessment.status}, not stuck; "
                         "nothing to mark")
    cid = assessment.challenge_id
    prior = marked_stuck(workdir, cid)
    if prior is not None and prior.get("status") == assessment.status:
        return None
    card_id = None
    if route and profile is not None:
        card_id = _route_to_player(assessment, workdir=workdir, profile=profile)
    fields: dict[str, Any] = {
        "challenge_id": cid,
        "status": assessment.status,
        "rejections": assessment.rejections,
        "derivable": assessment.derivable,
        "vocabulary": list(assessment.vocabulary),
        "reason": assessment.reason,
        "routed": bool(card_id),
    }
    if card_id:
        fields["card_id"] = card_id
    if agent:
        fields["agent"] = str(agent)
    return _ledger.append(STUCK_EVENT, workdir=workdir, **fields)


def clear_stuck(challenge_id: str, *, workdir: Path | None = None, reason: str = "",
                by: str | None = None) -> dict | None:
    """Cancel an id's stuck state (the question was rewritten, or the player cleared it). Returns None
    when the id is not currently stuck (nothing to clear -- never a silent no-op record)."""
    cid = _check_id(challenge_id)
    if marked_stuck(workdir, cid) is None:
        return None
    fields: dict[str, Any] = {"challenge_id": cid, "reason": str(reason)}
    if by:
        fields["by"] = str(by)
    return _ledger.append(CLEARED_EVENT, workdir=workdir, **fields)


def _route_to_player(assessment: Assessment, *, workdir: Path | None, profile) -> str | None:
    """Open a human task card for a stuck id (ctf.humanops, B-169). Returns the card id, or None when
    the card could not be opened (its reason is on stderr via humanops); never raises into the caller."""
    from . import humanops
    ops = humanops.HumanOps(profile, workdir=workdir)
    label = "probe-capped" if assessment.status == PROBE_CAPPED else "no-derivation"
    ask = (f"Stuck id {assessment.challenge_id} ({label}): {assessment.rejections} rejected probe(s). "
           "The answer is not derivable from the brief or files as given. Re-read the live question "
           "(the organizer may have rewritten it); if it still has no vocabulary, this ends with the "
           "player or the organizer.")
    need = "a correct value for the id, a rewritten question, or a decision to abandon it"
    try:
        card = ops.add_card("other", ask=ask, need=need, challenge_id=assessment.challenge_id,
                            why=assessment.reason, source="stuck")
        return card.id
    except humanops.HumanOpsError:
        return None


# --------------------------------------------------------------------------------- the caps

@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    assessment: Assessment
    agents: int = 0            # agents on the id (agent_allowed only)

    def to_dict(self) -> dict:
        return {"allowed": self.allowed, "reason": self.reason, "agents": self.agents,
                "assessment": self.assessment.to_dict()}


def probe_allowed(challenge_id: str, *, question: Any, brief_text: Any = None, files: Any = None,
                  workdir: Path | None = None, thresholds: Thresholds = DEFAULT, **kw) -> Decision:
    """Whether another probe (platform.submit) on this id should go. The gate an agent/harness puts
    before a send, as `hypothesis.should_skip` gates a method. Refused when the id is STUCK or
    PROBE_CAPPED (route to the player); allowed otherwise. Extra keyword args (read_value, rejected_values,
    ...) pass through to `assess`."""
    a = assess(challenge_id, question=question, brief_text=brief_text, files=files, workdir=workdir,
               thresholds=thresholds, **kw)
    if a.is_stuck:
        return Decision(False, f"{a.status}: {a.reason}", a)
    if a.status == TRY_FORMAT_CANDIDATES:
        return Decision(True, a.reason, a)
    return Decision(True, "not stuck: " + a.reason, a)


def agents_on(workdir: Path | None, challenge_id: str) -> int:
    """How many agents the per-challenge gate counts on this id's challenge (ctf.spawn, B-143). The
    stuck protocol consumes this count, it does not re-derive it."""
    from . import spawn
    key = spawn.challenge_key(_check_id(challenge_id))
    view = spawn.read_views(_ledger.read(workdir)).get(key)
    return view.agents if view is not None else 0


def agent_allowed(challenge_id: str, *, question: Any, brief_text: Any = None, files: Any = None,
                  workdir: Path | None = None, thresholds: Thresholds = DEFAULT, **kw) -> Decision:
    """Whether another agent should be dispatched onto this id. Refused when the id is stuck (an
    underivable id does not want more agents -- it wants the player), or when the agent count on its
    challenge has reached `thresholds.agent_cap`. The 5-per-challenge numeric gate stays in ctf.spawn;
    this adds only the stuck-and-cap refusal that routes to the player."""
    a = assess(challenge_id, question=question, brief_text=brief_text, files=files, workdir=workdir,
               thresholds=thresholds, **kw)
    n = agents_on(workdir, challenge_id)
    if a.is_stuck:
        return Decision(False, f"{a.status}: {a.reason}; no more agents, route to the player", a, n)
    if n >= thresholds.agent_cap:
        return Decision(False, f"{n} agent(s) already on this id (>= agent_cap {thresholds.agent_cap}); "
                               "route to the player before dispatching more", a, n)
    return Decision(True, f"{n} agent(s) on this id, under the cap {thresholds.agent_cap}", a, n)


# --------------------------------------------------------------------------------- the live re-read

def last_read_ts(workdir: Path | None, challenge_id: str) -> float | None:
    """When a stuck id's live question was last read into a stored brief (ctf.watch): the timestamp of
    its highest stored version, or None when no brief has been stored (never read)."""
    cid = _check_id(challenge_id)
    versions = _watch.versions(workdir, cid)
    if not versions:
        return None
    rec = _watch.load_version(workdir, cid, versions[-1])
    ts = rec.get("ts")
    return float(ts) if isinstance(ts, (int, float)) else None


def reread_due(workdir: Path | None = None, *, clock=time.time,
               thresholds: Thresholds = DEFAULT) -> list[tuple[str, float | None, float]]:
    """The stuck ids whose live question is due for a re-read now: each as (id, last_read_ts, overdue_s).
    An id never read has last_read_ts None and overdue_s the interval. A caller (the watch driver, or an
    operator) prioritises these for a detail fetch; this module makes no platform call itself."""
    now = clock()
    out = []
    for cid in stuck_ids(workdir):
        last = last_read_ts(workdir, cid)
        if last is None:
            out.append((cid, None, thresholds.reread_interval_s))
        else:
            age = now - last
            if age >= thresholds.reread_interval_s:
                out.append((cid, last, age))
    return out


def brief_changed_since_stuck(workdir: Path | None, challenge_id: str) -> bool:
    """Whether the live brief of a stuck id changed after it went stuck -- the signal that the organizer
    rewrote the question, so the id should be reconsidered (its new text may carry vocabulary). Reads the
    `stuck` record's time and the ctf.watch `brief_changed` events for the id."""
    cid = _check_id(challenge_id)
    rec = marked_stuck(workdir, cid)
    if rec is None:
        return False
    since = float(rec.get("ts") or 0.0)
    for ev in _watch.read_events(workdir):
        if ev.get("event") == "brief_changed" and str(ev.get("challenge_id")) == cid \
                and float(ev.get("ts") or 0.0) > since:
            return True
    return False


def reconsider(workdir: Path | None = None, *, profile=None, by: str = "watch") -> list[str]:
    """Clear every stuck id whose brief changed since it went stuck, and return the ids cleared. The
    live-re-read payoff: when the organizer rewrites an underivable question, the id stops being stuck
    so the engine reconsiders it instead of staying parked on the player's desk."""
    cleared = []
    for cid in stuck_ids(workdir):
        if brief_changed_since_stuck(workdir, cid):
            clear_stuck(cid, workdir=workdir, reason="brief changed since the id went stuck "
                        "(the live question was rewritten); reconsidering", by=by)
            cleared.append(cid)
    return cleared
