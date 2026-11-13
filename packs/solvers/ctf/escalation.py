"""Escalation timers and reroutes for the dispatcher (B-016): the live ladder the B-004 handout only
described as an advisory default.

    from ctf import escalation
    esc = escalation.Escalator(profile, workdir=wd, roster=["claude-opus-5-5", "glm-5.3", "gpt-6-sol"])
    esc.once()            # emit any escalation now due for every active challenge
    esc.run(until=...)    # follow the ledger and escalate as timers fire and stops arrive

Why. At CSCTF the second opinion came at p50 1,590 s (his 3-minute rule), 16 Codex handoffs died on a
provider error giving 120 s of false coverage, and model refusals were never rerouted
(dev/SPEED-STUDY.md section 6 item 7, dev/mechanisms.md M6). This module reproduces his rule-based,
no-model ladder in our terms:

  * a **second** agent on a different model at `second_s` (default 180 s) after the challenge's first
    agent or claim (the earliest `agent_launch`, claim or claim `dispatched_at`; with none of those,
    the earliest `agent_stop`; then a `detect`), or at once on the first rejected flag;
  * a **third** agent on a third model at `third_s` (default 480 s);
  * a **reroute** within one poll when an agent run stops on a refusal or a provider error, so a dead
    handoff never counts as coverage. One reroute per agent run: every stop recorded for the same run
    (the latest `agent_launch` of that harness/model before the stop) is answered by one reroute.

Each decision is written, with no model, as one `escalation` ledger record (so the replay times it and
`ctf escalate show` prints the plan) naming the action, what triggered it, the model it moves onto and
the model it moves off. Nothing is launched here: an orchestrator or a warm-standby agent reads the
record and starts the agent, exactly as the dispatcher writes a claim and something else runs intake.

A challenge is escalated once something owns it: a claim (ledger or dispatch claim), an
`agent_launch`, or an `agent_stop` (an agent was working on it: tools/codex_handoff.sh writes no
launch and no claim, only the stop, and that stop must still reroute). A bare `detect` owns nothing.

Challenge ids are keyed with `ctf.platform.rules.challenge_key`: a multi-answer part `9#a` (the Game
Master's addressing) counts toward challenge `9`. A rejected answer on any part triggers the parent's
early second. A correct answer on one part does NOT by itself resolve the parent (the Game Master's
SubmitStatus is CORRECT for a banked part with others remaining); it resolves the parent only when its
`platform.submit` record says `remaining = 0` (ctf.platform.rules records the Game Master reply's
count: `accepted` -> its `remaining`, `CORRECT` -> 0). The parent also resolves on a correct /
already-solved submit of the bare id that is not `partial` and not `remaining > 0` (a batch banked with
answers still open), an `accepted` stage of the bare id, any `stop` record (team solve, manual,
no-progress, wrong-answer stop), or a dispatch claim B-015 marked `solved` or `gone` (the challenge
left the board; a returning challenge's claim goes back to `dispatched` and escalates again). An
`accepted` stage on a part only marks that part solved.

The owner's model is the model on the challenge's first `agent_launch` (the metered launchers record
it), else roster[0]. A reroute moves off the stopped run's model (`agent_stop.model`, else its
launch's, else the owner's). Every model already launched on, stopped on or escalated onto is skipped,
so each agent is a *different* model. Models come from the roster (default
`[models.primary, *models.fallback]`, extended with `ctf escalate --model`); when the roster holds no
unused model a decision is still written, loudly, with `status = "no_model"`, never a silent reuse of a
model that already failed. A `no_model` decision is not final: a later pass with a free model (a grown
roster) writes the dispatched decision; until then the same `no_model` is not written again but is
reported on every pass (`Escalator.unrouted`, exit 1 from the CLI).

B-201: an Escalator built with `router=` (a ctf.router.Router; `ctf escalate` passes one when the
profile has a [routing] table) orders each challenge's roster by its route instead: the model routed
for the solve role at the challenge's difficulty and category (read from its first `agent_launch`,
else routing.default_difficulty), then the models routed at each harder difficulty, then
`[models.primary, *models.fallback]`, then the `roster` extension. The base effort the ramp steps from
is the effort the first `agent_launch` records (a routed launch records the effort it ran at), else
that route's effort on the first launch's harness (an explicit `effort=` still wins). Without a router
nothing changes.

Agent stops reach the ledger as `agent_stop` records. The metered launchers detect them from the
agent's own output (ctf/stages.py AgentStreamTap -> `record`, at most one per launched agent);
`ctf escalate stop` records one by hand, and tools/codex_handoff.sh calls it when its codex run fails.
Only terminal signals count: a Claude `stop_reason: refusal`, a Claude `result` flagged as an error
that is not a self-imposed limit (`error_max_*`), a Codex `turn.failed`. A Codex `error` line alone
(a reconnect notice the agent may recover from) is not a stop. Agent output is data: only the
protocol's stop/error fields are read from it, never challenge text.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

from . import ledger as _ledger
from . import paths as _paths
from .event import EFFORT_LEVELS, ROUTE_DIFFICULTIES, ROUTE_HARNESSES
from .platform.rules import challenge_key
from .solved import GONE_STATUS, SOLVED_STATUS

LEDGER_EVENT = "escalation"
STOP_EVENT = "agent_stop"

SECOND_S = 180.0      # his 3-minute second-opinion rule (dev/mechanisms.md M6)
THIRD_S = 480.0       # the 8-minute third
POLL_S = 5.0          # default poll: well under the 30 s reroute budget
REROUTE_BUDGET_S = 30.0   # acceptance target: a refusal / provider error is rerouted within this

ACTIONS = ("second", "third", "reroute")

# B-095: effort tiers. Each decision carries the reasoning effort the new agent launches at. The first
# agent runs at the profile's launch-pinned base (default "medium", ctf.event.Models.effort); the
# second and third ramp up a tier at a time (medium -> high -> max), ALWAYS by starting a fresh agent
# -- never a mid-session effort change, which rewrites the prompt cache (~$0.32/rewrite, B-095 spec).
# A reroute is a replacement for a dead handoff, not a ramp step, so it relaunches at the base tier.
EFFORT_STEPS = {"second": 1, "third": 2, "reroute": 0}
DEFAULT_EFFORT = "medium"
TIMER_TRIGGERS = ("timer", "rejected_flag")
STOP_REASONS = ("refusal", "provider_error")   # what reroutes a stopped agent
STATUS_DISPATCHED = "dispatched"
STATUS_NO_MODEL = "no_model"

# Claude `result` subtypes that are a limit the run set itself (max turns, max budget, max structured-
# output retries), not a provider failure: they never reroute.
LIMIT_SUBTYPE_PREFIX = "error_max"

# platform.submit statuses that solve the challenge (the bare id) or one part of it ("9#a").
_RESOLVED_SUBMIT = {"correct", "already_solved"}


class EscalationError(RuntimeError):
    """Escalation cannot run as asked (no workdir, an unknown stop reason, a corrupt escalation record)."""


def _num(v: Any) -> float | None:
    return float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else None


def _str(v: Any) -> str:
    return v.strip() if isinstance(v, str) else ""


def step_effort(base: str, steps: int) -> str:
    """The effort tier `steps` above `base` in EFFORT_LEVELS, clamped to the top tier. `steps` < 0 is
    treated as 0 (never ramps below the launch-pinned base). Raises on an unknown base tier, loudly."""
    try:
        i = EFFORT_LEVELS.index(base)
    except ValueError:
        raise EscalationError(
            f"unknown effort tier {base!r}; tiers are: {', '.join(EFFORT_LEVELS)}") from None
    return EFFORT_LEVELS[min(i + max(0, steps), len(EFFORT_LEVELS) - 1)]


# ----------------------------------------------------------------------------- recording agent stops

def record_agent_stop(reason: str, challenge_id: str, *, harness: str, workdir: Path | None = None,
                      detail: str | None = None, model: str | None = None) -> dict:
    """Write one `agent_stop` ledger record: an agent on `challenge_id` stopped on a refusal or a
    provider error, so the escalator reroutes it. `reason` must be one of STOP_REASONS. `model` is the
    stopped agent's model when known (the reroute moves off it)."""
    if reason not in STOP_REASONS:
        raise EscalationError(f"unknown agent-stop reason {reason!r}; reasons are: {', '.join(STOP_REASONS)}")
    cid = str(challenge_id).strip()
    if not cid:
        raise EscalationError("record_agent_stop needs a challenge id")
    fields: dict = {"challenge_id": cid, "harness": str(harness), "reason": reason}
    if detail:
        fields["detail"] = str(detail)[:400]
    if _str(model):
        fields["model"] = _str(model)
    return _ledger.append(STOP_EVENT, workdir=workdir, **fields)


def detect_stop(line: str) -> tuple[str, str] | None:
    """Read one line of a metered agent's JSON output and return `(reason, detail)` when it is a
    terminal refusal or provider error, else None. Structural only: it reads the harness protocol's own
    stop/error fields, never free challenge text, so quoted text never trips it.

    Claude `--output-format stream-json`: an assistant message with `stop_reason == "refusal"`, or a
    `result` line flagged as an error (`is_error` true or an `error*` subtype) other than a
    self-imposed limit (`error_max_*`). Codex `exec --json`: a `turn.failed` event. A bare Codex
    `error` event is a notice the run may recover from (a reconnect), not a stop."""
    s = line.lstrip()
    if not s.startswith("{"):
        return None
    try:
        d = json.loads(s)
    except ValueError:
        return None
    if not isinstance(d, dict):
        return None
    kind = str(d.get("type") or "")
    # Claude: a refusal stop on an assistant message.
    if kind == "assistant":
        msg = d.get("message")
        if isinstance(msg, dict) and msg.get("stop_reason") == "refusal":
            return "refusal", "stop_reason: refusal"
        return None
    # Codex: the turn failed (the run is over).
    if kind == "turn.failed":
        return "provider_error", _error_detail(d) or kind
    # Claude: the run ended on an error.
    if kind == "result":
        subtype = str(d.get("subtype") or "")
        if subtype.startswith(LIMIT_SUBTYPE_PREFIX):
            return None
        if d.get("is_error") is True or subtype.startswith("error"):
            if subtype and subtype != "success":
                return "provider_error", subtype
            return "provider_error", "result is_error"
    return None


def _error_detail(d: dict) -> str:
    for key in ("error", "message", "reason"):
        v = d.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()[:200]
        if isinstance(v, dict):
            m = v.get("message") or v.get("error")
            if isinstance(m, str) and m.strip():
                return m.strip()[:200]
    return ""


# ----------------------------------------------------------------------------- per-challenge state

@dataclass
class ChallengeState:
    """One challenge's escalation-relevant history, read from the ledger (and the dispatch claim).
    Keyed by `challenge_key` (a multi-answer part `9#a` belongs to `9`)."""
    challenge_id: str
    t0: float | None = None                 # the earliest agent_launch / claim (else agent_stop, else
                                            # detect) time
    resolved: bool = False                  # solved or stopped: no more escalation
    rejected: bool = False                  # a wrong flag was judged (the earlier second-opinion trigger)
    stops: list[dict] = field(default_factory=list)       # agent_stop records, in order
    escalations: list[dict] = field(default_factory=list)  # escalation records already written
    launches: list[dict] = field(default_factory=list)     # agent_launch records, in order
    solved_parts: set[str] = field(default_factory=set)    # multi-answer parts judged correct
    has_owner: bool = False                 # a claim, a launched agent or a stopped agent exists
    difficulty: str | None = None           # B-201: the first agent_launch's routed difficulty
    category: str | None = None             # B-201: the first agent_launch's category
    effort: str | None = None               # B-201: the first agent_launch's launched effort
    harness: str | None = None              # B-201: the first agent_launch's harness


def read_states(workdir: Path | None, *, claims: dict[str, dict] | None = None) -> dict[str, ChallengeState]:
    """Build each active challenge's ChallengeState from the ledger and the dispatch claims."""
    states: dict[str, ChallengeState] = {}
    owner_ts: dict[str, list[float]] = {}
    detect_ts: dict[str, list[float]] = {}
    stop_ts: dict[str, list[float]] = {}

    def st(key: str) -> ChallengeState:
        return states.setdefault(key, ChallengeState(key))

    if claims:
        for cid, rec in claims.items():
            key = challenge_key(str(cid).strip())
            st(key).has_owner = True
            if isinstance(rec, dict) and rec.get("status") in (SOLVED_STATUS, GONE_STATUS):
                st(key).resolved = True    # B-015 marked the claim solved, or the challenge left the board
            da = _num(rec.get("dispatched_at")) if isinstance(rec, dict) else None
            if da is not None:
                owner_ts.setdefault(key, []).append(da)

    for rec in _ledger.read(workdir):
        ev = rec.get("event")
        cid = rec.get("challenge_id")
        if cid is None or not str(cid).strip():
            continue
        raw = str(cid).strip()
        key = challenge_key(raw)
        part = raw != key
        ts = _num(rec.get("ts"))
        if ev == "agent_launch":
            s = st(key)
            s.has_owner = True
            s.launches.append(rec)
            if s.difficulty is None and rec.get("difficulty") in ROUTE_DIFFICULTIES:
                s.difficulty = rec["difficulty"]            # B-201: the launch's route
            if s.category is None and _str(rec.get("category")):
                s.category = _str(rec.get("category"))
            if len(s.launches) == 1:                        # B-201: the first agent's own launch
                if rec.get("effort") in EFFORT_LEVELS:
                    s.effort = rec["effort"]
                if _str(rec.get("harness")):
                    s.harness = _str(rec.get("harness"))
            if ts is not None:
                owner_ts.setdefault(key, []).append(ts)
        elif ev == "claim":
            st(key).has_owner = True       # a claim (dispatcher / orchestrator) owns the challenge
            if ts is not None:
                owner_ts.setdefault(key, []).append(ts)
        elif ev == "detect":
            st(key)                        # a bare detection is not ownership; only a t0 fallback
            if ts is not None:
                detect_ts.setdefault(key, []).append(ts)
        elif ev == STOP_EVENT:
            s = st(key)
            s.has_owner = True             # an agent was working on it (the codex-handoff path writes
            s.stops.append(rec)            # no agent_launch and no claim, only this stop)
            if ts is not None:
                stop_ts.setdefault(key, []).append(ts)
        elif ev == LEDGER_EVENT:
            st(key).escalations.append(rec)
        elif ev == "accepted":
            if part:
                st(key).solved_parts.add(raw)
            else:
                st(key).resolved = True
        elif ev == "stop":
            st(key).resolved = True
        elif ev == "platform.submit":
            status = str(rec.get("status"))
            if status in _RESOLVED_SUBMIT:
                remaining = rec.get("remaining")
                remaining = remaining if isinstance(remaining, int) and not isinstance(remaining, bool) else None
                if part:
                    st(key).solved_parts.add(raw)
                    if remaining == 0:         # the platform says this part completed the challenge
                        st(key).resolved = True
                elif rec.get("partial") is True or (remaining is not None and remaining > 0):
                    st(key)                    # a batch banked with answers still open: not solved
                else:
                    st(key).resolved = True
            elif status == "incorrect":
                st(key).rejected = True
        elif ev == "rejected":
            st(key).rejected = True

    for key, s in states.items():
        times = owner_ts.get(key) or stop_ts.get(key) or detect_ts.get(key)
        s.t0 = min(times) if times else None
    return states


# ----------------------------------------------------------------------------- decisions

@dataclass(frozen=True)
class Decision:
    challenge_id: str
    action: str                 # second | third | reroute
    trigger: str                # timer | rejected_flag | refusal | provider_error
    to_model: str               # the model this moves onto ("" when none is free)
    from_model: str             # the model it moves off
    elapsed_s: float            # seconds since t0 (timer) or since the stop (reroute)
    status: str                 # dispatched | no_model
    effort: str = ""            # B-095: the reasoning effort the new agent launches at (pinned, a ramp)
    detail: str = ""
    for_stop_ts: float | None = None   # a reroute answers this agent_stop record's ts

    def to_fields(self) -> dict:
        f: dict = {"challenge_id": self.challenge_id, "action": self.action, "trigger": self.trigger,
                   "to_model": self.to_model, "from_model": self.from_model,
                   "elapsed_s": round(self.elapsed_s, 3), "status": self.status}
        if self.effort:
            f["effort"] = self.effort
        if self.detail:
            f["detail"] = self.detail
        if self.for_stop_ts is not None:
            f["for_stop_ts"] = round(self.for_stop_ts, 3)
        return f


def _roster(profile, extra: Iterable[str] | None = None) -> list[str]:
    return _roster_list([profile.models.primary, *profile.models.fallback, *(extra or [])])


def _roster_list(models: Iterable[str]) -> list[str]:
    out: list[str] = []
    for m in models:
        m = str(m).strip()
        if m and m not in out:
            out.append(m)
    return out


def _dispatched(records: Iterable[dict]) -> bool:
    return any(r.get("status") == STATUS_DISPATCHED for r in records)


def _no_model_written(records: Iterable[dict]) -> bool:
    return any(r.get("status") == STATUS_NO_MODEL for r in records)


class Escalator:
    """Reads the ledger (and the B-004 claims) and writes one `escalation` record per decision due,
    with no model. `roster` extends the models escalation may route across (default
    `[models.primary, *models.fallback]`, in that order; an owner with no recorded model runs
    roster[0]). `on_decision` is called for each decision written; `on_problem` for a loud `no_model`,
    a still-unrouted escalation or a corrupt record."""

    def __init__(self, profile, *, workdir: Path | None = None, roster: Iterable[str] | None = None,
                 second_s: float = SECOND_S, third_s: float = THIRD_S, effort: str | None = None,
                 clock: Callable[[], float] = time.time, record: bool = True,
                 read_claims: Callable[[Path | None], tuple[dict, list]] | None = None,
                 on_decision: Callable[[Decision], None] | None = None,
                 on_problem: Callable[[str], None] | None = None, router=None):
        if second_s < 0 or third_s < 0:
            raise EscalationError("second_s and third_s must be >= 0")
        self.profile = profile
        self.workdir = Path(workdir) if workdir is not None else _paths.workdir(profile.slug)
        self.roster = _roster(profile, roster if roster is not None else ())
        self._extra = [str(m).strip() for m in (roster or ()) if str(m).strip()]
        # B-201: a ctf.router.Router orders each challenge's roster by its route (the routed model at
        # the challenge's difficulty, then harder routes) and sets its base effort. None: as before.
        self.router = router
        self._effort_given = effort is not None
        self.second_s = second_s
        self.third_s = third_s
        # B-095: the launch-pinned base effort. The first agent runs at it; the ramp (second/third)
        # raises it a tier per fresh agent. From the profile's [models].effort unless overridden.
        base = effort if effort is not None else getattr(getattr(profile, "models", None), "effort",
                                                         DEFAULT_EFFORT)
        if base not in EFFORT_LEVELS:
            raise EscalationError(
                f"unknown effort tier {base!r}; tiers are: {', '.join(EFFORT_LEVELS)}")
        self.effort = base
        self.clock = clock
        self.record = record
        self._read_claims = read_claims
        self.on_decision = on_decision
        self.on_problem = on_problem
        self.decisions: list[Decision] = []
        self.problems: list[str] = []
        self.unrouted: list[Decision] = []          # no_model decisions already written, still unmet
        self._reported_unrouted: set[tuple] = set()

    # ------------------------------------------------------------------ reading
    def _claims(self) -> dict[str, dict]:
        if self._read_claims is not None:
            good, _bad = self._read_claims(self.workdir)
            return good
        from . import dispatch as _dispatch
        good, bad = _dispatch.read_claims(self.workdir)
        for p, reason in bad:
            self._problem(f"{reason}")
        return good

    def states(self) -> dict[str, ChallengeState]:
        return read_states(self.workdir, claims=self._claims())

    # ------------------------------------------------------------------ models
    def roster_for(self, s: ChallengeState) -> list[str]:
        """B-201: the challenge's roster. With a router: its route's order for the solve role at the
        challenge's difficulty and category (from its first agent_launch, else the routing default),
        then the `roster` extension; without one, the profile roster. The router's roster is
        deliberately harness-spanning: at each difficulty it lists the harness-free route's model, then
        the claude and the codex rules' models, because an escalation may move to the other harness.
        The owner's own model comes from its agent_launch (owner_model) and is never picked again."""
        if self.router is None:
            return self.roster
        return _roster_list([*self.router.roster("solve", s.difficulty, category=s.category),
                             *self._extra])

    def base_effort(self, s: ChallengeState) -> str:
        """B-201: the base effort the ramp steps from. Without a router, or with an explicit `effort`,
        the Escalator's effort (the profile's [models].effort, B-095). With a router: the effort the
        challenge's first agent launched at, as its `agent_launch` records it (a routed launch records
        the effort it ran at, a harness rule's or an explicit --effort included); when that launch
        records none, the solve route's effort for the challenge's difficulty and category on that
        launch's harness (harness-free when it names none)."""
        if self.router is None or self._effort_given:
            return self.effort
        if s.effort is not None:
            return s.effort
        harness = s.harness if s.harness in ROUTE_HARNESSES else None
        return self.router.resolve("solve", s.difficulty, harness=harness, category=s.category).effort

    @staticmethod
    def _next_model(roster: list[str], used: set[str]) -> str | None:
        for m in roster:
            if m not in used:
                return m
        return None

    def owner_model(self, s: ChallengeState) -> str:
        """The model of the challenge's first agent_launch that names one, else the roster's first."""
        timed = [(_num(r.get("ts")), _str(r.get("model"))) for r in s.launches]
        timed = [(t, m) for t, m in timed if t is not None and m]
        if timed:
            return min(timed, key=lambda tm: tm[0])[1]
        roster = self.roster_for(s)
        return roster[0] if roster else ""

    @staticmethod
    def _run_of(s: ChallengeState, stop: dict, sts: float) -> dict | None:
        """The agent_launch this stop belongs to: the latest launch at or before it with the same
        harness (and the same model when both name one). None when no launch matches (a manual stop)."""
        harness, model = _str(stop.get("harness")), _str(stop.get("model"))
        best, best_ts = None, None
        for r in s.launches:
            lts = _num(r.get("ts"))
            if lts is None or lts > sts or _str(r.get("harness")) != harness:
                continue
            lm = _str(r.get("model"))
            if model and lm and lm != model:
                continue
            if best_ts is None or lts >= best_ts:
                best, best_ts = r, lts
        return best

    # ------------------------------------------------------------------ one challenge's due decisions
    def decisions_for(self, s: ChallengeState, pending: list[Decision] | None = None) -> list[Decision]:
        """The escalation decisions due for one challenge right now that have not been written yet.
        A `no_model` decision already written and still without a free model is not returned again;
        it is appended to `pending` (when given) instead."""
        if s.resolved or not s.has_owner:
            return []
        owner = self.owner_model(s)
        used = {owner} if owner else set()
        used |= {_str(r.get("model")) for r in [*s.launches, *s.stops] if _str(r.get("model"))}
        by_action: dict[str, list[dict]] = {"second": [], "third": []}
        by_stop: dict[float, list[dict]] = {}
        for e in s.escalations:
            if e.get("status") == STATUS_DISPATCHED and _str(e.get("to_model")):
                used.add(_str(e.get("to_model")))
            act = str(e.get("action") or "")
            if act in by_action:
                by_action[act].append(e)
            elif act == "reroute" and _num(e.get("for_stop_ts")) is not None:
                by_stop.setdefault(round(_num(e.get("for_stop_ts")), 3), []).append(e)
        now = self.clock()
        out: list[Decision] = []
        roster, base = self.roster_for(s), self.base_effort(s)

        def due(d: Decision, prior: list[dict]) -> None:
            if d.status == STATUS_NO_MODEL and _no_model_written(prior):
                if pending is not None:
                    pending.append(d)
                return
            out.append(d)

        # Reroutes first: a refusal / provider error is time-critical (the 30 s budget). One per run.
        runs: dict[tuple, list[tuple[float, dict]]] = {}
        for stop in s.stops:
            if str(stop.get("reason") or "") not in STOP_REASONS:
                continue
            sts = _num(stop.get("ts"))
            if sts is None:
                continue
            launch = self._run_of(s, stop, sts)
            key = (("run", _str(stop.get("harness")), _num(launch.get("ts"))) if launch is not None
                   else ("stop", round(sts, 3)))
            runs.setdefault(key, []).append((sts, stop))
        for members in runs.values():
            prior = [e for sts, _ in members for e in by_stop.get(round(sts, 3), [])]
            if _dispatched(prior):
                continue
            sts, stop = members[0]
            launch = self._run_of(s, stop, sts)
            from_model = (_str(stop.get("model")) or (_str(launch.get("model")) if launch else "")
                          or owner)
            due(self._make(s.challenge_id, "reroute", str(stop.get("reason")), from_model, used,
                           elapsed_s=max(0.0, now - sts), detail=str(stop.get("detail") or ""),
                           for_stop_ts=sts, roster=roster, base=base), prior)

        # Timers: the second at second_s or the first rejected flag; the third at third_s.
        if s.t0 is not None:
            elapsed = max(0.0, now - s.t0)
            if (elapsed >= self.second_s or s.rejected) and not _dispatched(by_action["second"]):
                trigger = "rejected_flag" if (s.rejected and elapsed < self.second_s) else "timer"
                due(self._make(s.challenge_id, "second", trigger, owner, used, elapsed_s=elapsed,
                               roster=roster, base=base), by_action["second"])
            if elapsed >= self.third_s and not _dispatched(by_action["third"]):
                due(self._make(s.challenge_id, "third", "timer", owner, used, elapsed_s=elapsed,
                               roster=roster, base=base), by_action["third"])
        return out

    def _make(self, cid: str, action: str, trigger: str, from_model: str, used: set[str], *,
              elapsed_s: float, detail: str = "", for_stop_ts: float | None = None,
              roster: list[str] | None = None, base: str | None = None) -> Decision:
        roster = self.roster if roster is None else roster
        eff = step_effort(base or self.effort, EFFORT_STEPS.get(action, 0))   # B-095: the ramped tier
        to = self._next_model(roster, used)
        if to is None:
            return Decision(cid, action, trigger, "", from_model, elapsed_s, STATUS_NO_MODEL,
                            effort=eff, detail=(detail + "; " if detail else "")
                            + f"no unused model in roster {roster}", for_stop_ts=for_stop_ts)
        used.add(to)          # within this pass, two decisions never pick the same model
        return Decision(cid, action, trigger, to, from_model, elapsed_s, STATUS_DISPATCHED,
                        effort=eff, detail=detail, for_stop_ts=for_stop_ts)

    # ------------------------------------------------------------------ emitting
    def _problem(self, msg: str) -> None:
        self.problems.append(msg)
        if self.on_problem is not None:
            self.on_problem(msg)

    def _emit(self, d: Decision) -> None:
        if self.record:
            _ledger.append(LEDGER_EVENT, workdir=self.workdir, **d.to_fields())
        self.decisions.append(d)
        if d.status == STATUS_NO_MODEL:
            self._problem(f"challenge {d.challenge_id}: {d.action} escalation has no model: {d.detail}")
        if self.on_decision is not None:
            self.on_decision(d)

    def _still_unrouted(self, d: Decision) -> None:
        key = (d.challenge_id, d.action, d.for_stop_ts)
        if key in self._reported_unrouted:
            return
        self._reported_unrouted.add(key)
        self.unrouted.append(d)
        self._problem(f"challenge {d.challenge_id}: {d.action} escalation still has no model "
                      f"({d.detail}); add one with --model")

    def once(self) -> list[Decision]:
        """One pass: write every decision now due for every active challenge. Returns them."""
        made: list[Decision] = []
        for s in self.states().values():
            pending: list[Decision] = []
            for d in self.decisions_for(s, pending):
                self._emit(d)
                made.append(d)
            for d in pending:
                self._still_unrouted(d)
        return made

    def run(self, *, stop: Callable[[], bool] | None = None, poll: float = POLL_S,
            until: float | None = None, sleep: Callable[[float], None] = time.sleep) -> list[Decision]:
        """Follow the ledger; escalate as timers fire and stops arrive. Returns when stop() is true or
        `until` (on this escalator's clock) passes."""
        made: list[Decision] = []
        while True:
            made += self.once()
            if stop is not None and stop():
                break
            if until is not None and self.clock() >= until:
                break
            sleep(poll)
        return made

    def show(self, challenge_id: str) -> dict:
        """The current escalation view of one challenge: its state and the decisions written so far."""
        cid = challenge_key(str(challenge_id).strip())
        s = self.states().get(cid)
        if s is None:
            raise EscalationError(f"challenge {cid!r} has no claim and no agent activity in this event")
        now = self.clock()
        pending: list[Decision] = []
        due = self.decisions_for(s, pending)
        return {"challenge_id": cid, "resolved": s.resolved, "rejected": s.rejected,
                "solved_parts": sorted(s.solved_parts),
                "owner_model": self.owner_model(s), "owner_effort": self.base_effort(s),
                "roster": list(self.roster_for(s)), "difficulty": s.difficulty, "category": s.category,
                "t0": s.t0, "elapsed_s": None if s.t0 is None else round(max(0.0, now - s.t0), 3),
                "stops": [{"reason": r.get("reason"), "ts": r.get("ts"), "harness": r.get("harness"),
                           "model": r.get("model"), "detail": r.get("detail")} for r in s.stops],
                "escalations": [{"action": e.get("action"), "trigger": e.get("trigger"),
                                 "to_model": e.get("to_model"), "status": e.get("status"),
                                 "elapsed_s": e.get("elapsed_s")} for e in s.escalations],
                "due_now": [d.to_fields() for d in due],
                "unrouted": [d.to_fields() for d in pending]}
