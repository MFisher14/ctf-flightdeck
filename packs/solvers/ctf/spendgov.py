"""Build and review spend governors (B-202): phase caps, risk-tiered review, a review stopping rule, a
review dispatcher that dedupes scope and caps spawns, a standing diff audit, time-boxed investigations
and per-mode (speed-run) budgets decided before spending.

Review and build spend had no brake in 2026: one overnight Huntress build was about 48% of a cohort's
spend, verification was a quarter of workflow spend, single build nights forked 200+ near-duplicate
review subagents, validation re-ran on near-identical trees, a one-day rate-limit analysis had no
numeric question or stop, and one Codex session spent $496.81 on Hall of Fame speed-runs before anyone
decided what a board place was worth. How much review is enough, and what a board position is worth,
are player decisions: this module never picks a dollar figure. It makes the decision a recorded
prerequisite and enforces it once made.

    from ctf import spendgov
    spendgov.set_cap("build", 300.0, period="day", by="max", reason="...")      # spend.cap
    spendgov.gate(phase="build")            # Verdict: held while no cap is decided or the cap is spent
    spendgov.decide_mode("speedrun", 150.0, by="max", reason="...", value="$12 per first place")
    spendgov.gate(challenge_id="w-day-01/time_trial")   # a solved timed id is speed-run work
    spendgov.scope_tier(["ctf/platform/ctfd.py", "docs/x.md"])  # "full": the riskiest file decides
    spendgov.plan_reviews(tasks, root, records=...)     # dedupe, stopping rule, spawn cap, dry-run count
    spendgov.record_round("gate-review", root, files, {"high": 1}, by="max")   # review.round + snapshot
    spendgov.diff_since_review("gate-review", root, files)                     # what changed since then
    spendgov.open_investigation("poll-cut", "Does cutting the poll save over 20 requests/min?",
                                metric="requests/min saved", threshold=20, minutes=60, usd=40, by="max")

Phases are the ledger's spend categories (`ctf.stages.SPEND_CATEGORIES`: review is `verify`, writeups
and retros are `doc`). A spend record's phase is its `category`; challenge spend without one is
`solve`; other spend without one is uncategorized and counts toward no cap (status reports it). A cap
is per day (midnight to midnight in `tz`) or per event (all of the ledger). A phase with no cap is
held by `gate`: deciding the cap is the player's step, as the B-008 effort budget is.

Modes. `speedrun` is built in: work on a timed Game Master id (`.../time_trial`, `.../mastery`) after
the team solved it (a `team_solve` stop, an accepted submit or an `accepted` mark) is a ranked retry
for the board, and its spend is speed-run spend. Any other mode is defined by its decision's
challenge globs and counts spend on matching challenges from the decision on. A mode with no decision
is held: the budget is decided before spending. A decision may also set `minutes`, a time box (e.g.
how long speed-run hardening may run) counted from the mode's first spend: past it the mode is
`over_time` and held, like a spent budget.

Review. A scope (a named set of files) gets a tier from its riskiest file (`TIER_RULES`, first match
wins: solve-path and armed code `full`, other code `standard`, tests `light`, docs `none`). The tier
sets the rounds and reviewer agents it may use and the severity that justifies another round
(`TIER_LIMITS`). `next_step` is the stopping rule: stop when the last round found nothing at or above
the tier's `continue_at`; refuse to re-review a tree a round already saw (fix first); escalate to a
person when the tier's rounds are spent and the last still found something serious. `plan_reviews`
applies it to a task list, folds a task whose files another task already covers into that task, and
caps the agents a workflow may start; its `agents` total is the dry-run count, printed before
anything starts. `record_round` keeps a snapshot of every file's hash so `diff_since_review` lists
what changed since that review: the standing, deterministic diff audit that replaces a re-spawned
review swarm.

Investigations are time-boxed and carry a numeric question: a metric, a threshold, a time box and a
dollar cap. Spend whose `source` is `investigation:<id>` counts toward it. `investigation()` reports
`over_time` / `over_budget` as stop signals; closing records the measured answer.

Ledger records (docs/CONTRACTS.md section 10): `spend.cap`, `spend.mode`, `review.round`,
`investigation.open`, `investigation.close`. Snapshots: `<workdir>/spend/reviewed/<scope>.json`.
No model, no network.
"""
from __future__ import annotations

import datetime as _dt
import fnmatch
import hashlib
import json
import math
import os
import posixpath
import re
import time
import zoneinfo
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable, Mapping, Sequence

from . import ledger as _ledger
from . import paths as _paths
from .platform.gamemaster import is_timed
from .stages import SPEND_CATEGORIES

PHASES = SPEND_CATEGORIES
PERIODS = ("day", "event")
SEVERITIES = ("info", "low", "medium", "high", "critical")          # ascending
TIERS = ("none", "light", "standard", "full")                        # ascending
ACTIONS = ("review", "stop", "fix", "escalate")
PLAN_ACTIONS = ("spawn", "duplicate", "stop", "fix", "escalate", "over_cap")
BUILTIN_MODES = {"speedrun": "timed ids (.../time_trial, .../mastery) after the team solved them: "
                             "ranked retries for a board place"}
INVESTIGATION_SOURCE = "investigation:"     # spend source prefix that charges an investigation
DEFAULT_MAX_AGENTS = 4                      # review agents one workflow may start (the dry-run cap)
SNAPSHOT_DIR = ("spend", "reviewed")

_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_ACCEPTED = frozenset({"correct", "already_solved"})


class SpendGovError(ValueError):
    """A governor input or state is unusable; the message names it."""


@dataclass(frozen=True)
class TierLimits:
    rounds: int          # review rounds the tier may use before a person decides
    agents: int          # reviewer agents per round
    continue_at: str     # a last round with a finding at or above this severity justifies another


TIER_LIMITS = {
    "none": TierLimits(0, 0, "critical"),
    "light": TierLimits(1, 1, "critical"),
    "standard": TierLimits(2, 1, "high"),
    "full": TierLimits(3, 2, "medium"),
}

# First match wins (fnmatch on the repo-relative POSIX path; "*" crosses "/"). Anything unmatched is
# "standard": an unknown file never escapes review silently. Agent-steering files (CLAUDE.md, AGENTS.md,
# SKILL.md, anything under .claude/) and dependency pins (requirements*) come before the doc catch-alls:
# they are Markdown or text, but they change what agents do and what code is installed.
TIER_RULES: tuple[tuple[str, str], ...] = (
    ("*CLAUDE.md", "standard"), ("*AGENTS.md", "standard"), ("*SKILL.md", "standard"),
    (".claude/*", "standard"), ("*/.claude/*", "standard"),
    ("requirements*", "standard"), ("*/requirements*", "standard"),
    ("docs/*", "none"), ("*.md", "none"), ("*.txt", "none"),
    ("tests/*", "light"),
    ("solvers/*", "full"), ("openers/*", "full"), ("ctf/platform/*", "full"), ("ctf/intake/*", "full"),
    ("ctf/openers/*", "full"), ("ctf/submit.py", "full"), ("ctf/scope.py", "full"), ("ctf/fence*.py", "full"),
    ("ctf/budget.py", "full"), ("ctf/ledger.py", "full"), ("ctf/flagfmt.py", "full"), (".githooks/*", "full"),
    ("tools/*launch*", "full"),
    ("*", "standard"),
)


def _rank(seq: Sequence[str], value: str, what: str) -> int:
    try:
        return seq.index(value)
    except ValueError:
        raise SpendGovError(f"unknown {what} {value!r}; {what}s are: {', '.join(seq)}") from None


def _name(value, what: str) -> str:
    if not isinstance(value, str) or not _NAME_RE.match(value):
        raise SpendGovError(f"{what} must match {_NAME_RE.pattern}, got {value!r}")
    return value


def _usd(value, what: str = "usd") -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
        raise SpendGovError(f"{what} must be a finite number > 0, got {value!r}")
    return float(value)


def _text(value, what: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SpendGovError(f"{what} is required (a person's name or reason, not empty)")
    return value.strip()


def _wd(workdir) -> Path:
    return _paths.workdir() if workdir is None else Path(workdir)


def _records(records, workdir) -> list[dict]:
    return list(_ledger.read(_wd(workdir)) if records is None else records)


def _ts(rec: Mapping) -> float | None:
    t = rec.get("ts")
    if isinstance(t, (int, float)) and not isinstance(t, bool) and math.isfinite(t):
        return float(t)
    return None


def spend_phase(rec: Mapping) -> str:
    """The phase a `spend` record counts toward: its category, else solve (challenge) / uncategorized."""
    return rec.get("category") or ("solve" if rec.get("challenge_id") else "uncategorized")


# ------------------------------------------------------------------------------------- phase caps

@dataclass(frozen=True)
class Cap:
    phase: str
    usd: float
    period: str
    by: str
    reason: str
    ts: float


@dataclass(frozen=True)
class PhaseStatus:
    phase: str
    cap: Cap | None
    spent: float
    since: float | None       # start of the counted period (None: the whole ledger)
    state: str                # ok | over | uncapped
    undated: int = 0          # spend records with no usable time (counted only for an event period)

    @property
    def left(self) -> float | None:
        return None if self.cap is None else max(0.0, self.cap.usd - self.spent)

    def to_dict(self) -> dict:
        return dict(asdict(self), left=self.left)


def set_cap(phase: str, usd: float, *, period: str = "day", by: str, reason: str,
            workdir: Path | None = None) -> dict:
    """The player's cap on one phase. The latest cap for a phase wins (raising or lowering it)."""
    _rank(PHASES, phase, "phase")
    _rank(PERIODS, period, "period")
    return _ledger.append("spend.cap", workdir=workdir, phase=phase, usd=_usd(usd), period=period,
                          by=_text(by, "by"), reason=_text(reason, "reason"))


def caps(records: Iterable[dict]) -> dict[str, Cap]:
    out: dict[str, Cap] = {}
    for r in records:
        if r.get("event") == "spend.cap" and r.get("phase") in PHASES:
            out[r["phase"]] = Cap(r["phase"], float(r["usd"]), r.get("period", "day"), r.get("by", ""),
                                  r.get("reason", ""), _ts(r) or 0.0)
    return out


def day_start(now: float, tz: str = "UTC") -> float:
    try:
        zone = zoneinfo.ZoneInfo(tz)
    except (zoneinfo.ZoneInfoNotFoundError, ValueError):
        raise SpendGovError(f"tz {tz!r} is not an IANA time zone") from None
    d = _dt.datetime.fromtimestamp(now, zone).date()
    return _dt.datetime(d.year, d.month, d.day, tzinfo=zone).timestamp()


def phase_status(phase: str, records: Iterable[dict], *, now: float, tz: str = "UTC") -> PhaseStatus:
    _rank(PHASES, phase, "phase")
    recs = list(records)
    cap = caps(recs).get(phase)
    since = day_start(now, tz) if cap is None or cap.period == "day" else None
    spent, undated = 0.0, 0
    for r in recs:
        if r.get("event") != "spend" or spend_phase(r) != phase:
            continue
        t = _ts(r)
        if t is None:
            undated += 1
            if since is not None:
                continue
        elif since is not None and not since <= t <= now:
            continue
        spent += float(r.get("usd") or 0.0)
    state = "uncapped" if cap is None else ("over" if spent >= cap.usd else "ok")
    return PhaseStatus(phase, cap, round(spent, 6), since, state, undated)


# ------------------------------------------------------------------------------------- mode budgets

@dataclass(frozen=True)
class ModeBudget:
    mode: str
    usd: float
    challenges: tuple[str, ...]     # globs; () for a built-in mode
    by: str
    reason: str
    value: str | None               # what the player decided a board place / the mode is worth
    ts: float                       # the latest decision
    first_ts: float                 # the first decision: custom-mode spend counts from here
    minutes: float | None = None    # optional time box: wall-clock minutes from the mode's first spend


@dataclass(frozen=True)
class ModeStatus:
    mode: str
    budget: ModeBudget | None
    spent: float
    state: str                      # ok | over | over_time | undecided
    started: float | None = None    # the mode's first counted spend (its time box runs from here)
    elapsed_min: float | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def decide_mode(mode: str, usd: float, *, by: str, reason: str, challenges: Sequence[str] = (),
                value: str | None = None, minutes: float | None = None, workdir: Path | None = None) -> dict:
    """The player's budget for one mode, decided before its spend. A built-in mode takes no globs; any
    other mode needs at least one (it is defined by them). `minutes` is an optional time box (e.g. how
    long speed-run hardening may run): wall-clock minutes from the mode's first counted spend."""
    _name(mode, "mode")
    globs = tuple(challenges)
    if mode in BUILTIN_MODES and globs:
        raise SpendGovError(f"mode {mode!r} is built in ({BUILTIN_MODES[mode]}); it takes no --challenge globs")
    if mode not in BUILTIN_MODES and not globs:
        raise SpendGovError(f"mode {mode!r} is not built in: name its challenges with at least one glob")
    if any(not isinstance(g, str) or not g.strip() for g in globs):
        raise SpendGovError(f"challenge globs must be non-empty strings, got {list(globs)!r}")
    fields: dict = {"mode": mode, "usd": _usd(usd), "by": _text(by, "by"), "reason": _text(reason, "reason")}
    if globs:
        fields["challenges"] = list(globs)
    if value:
        fields["value"] = value
    if minutes is not None:
        fields["minutes"] = _num(minutes, "minutes", True)
    return _ledger.append("spend.mode", workdir=workdir, **fields)


def mode_budgets(records: Iterable[dict]) -> dict[str, ModeBudget]:
    out: dict[str, ModeBudget] = {}
    for r in records:
        if r.get("event") != "spend.mode" or not isinstance(r.get("mode"), str):
            continue
        prev = out.get(r["mode"])
        t = _ts(r) or 0.0
        mins = r.get("minutes")
        out[r["mode"]] = ModeBudget(r["mode"], float(r["usd"]), tuple(r.get("challenges") or ()), r.get("by", ""),
                                    r.get("reason", ""), r.get("value"), t, prev.first_ts if prev else t,
                                    None if mins is None else float(mins))
    return out


def solved_at(records: Iterable[dict]) -> dict[str, float]:
    """{challenge id: the first time the team solved it}: a team-solve stop, an accepted submit or an
    `accepted` stage mark."""
    out: dict[str, float] = {}
    for r in records:
        cid, t = r.get("challenge_id"), _ts(r)
        if cid is None or t is None:
            continue
        ev = r.get("event")
        if ((ev == "stop" and r.get("reason") == "team_solve") or ev == "accepted"
                or (ev == "platform.submit" and r.get("status") in _ACCEPTED)):
            cid = str(cid)
            out[cid] = min(t, out.get(cid, t))
    return out


def modes_of(challenge_id: str, at: float, solved: Mapping[str, float],
             budgets: Mapping[str, ModeBudget]) -> list[str]:
    """The modes work (or spend) on `challenge_id` at time `at` belongs to."""
    cid = str(challenge_id)
    out = []
    s = solved.get(cid)
    if is_timed(cid) and s is not None and at >= s:
        out.append("speedrun")
    for m, b in budgets.items():
        if m not in BUILTIN_MODES and at >= b.first_ts and any(fnmatch.fnmatchcase(cid, g) for g in b.challenges):
            out.append(m)
    return out


def mode_status(mode: str, records: Iterable[dict], *, now: float | None = None) -> ModeStatus:
    """A mode's spend against its budget, and against its time box when the decision set `minutes`."""
    _name(mode, "mode")
    now = time.time() if now is None else now
    recs = list(records)
    budgets = mode_budgets(recs)
    solved = solved_at(recs)
    spent, started = 0.0, None
    for r in recs:
        if r.get("event") != "spend" or r.get("challenge_id") is None:
            continue
        t = _ts(r)
        if t is not None and mode in modes_of(r["challenge_id"], t, solved, budgets):
            spent += float(r.get("usd") or 0.0)
            started = t if started is None else min(started, t)
    b = budgets.get(mode)
    elapsed = None if started is None else round(max(0.0, now - started) / 60.0, 3)
    if b is None:
        state = "undecided"
    elif spent >= b.usd:
        state = "over"
    elif b.minutes is not None and elapsed is not None and elapsed >= b.minutes:
        state = "over_time"
    else:
        state = "ok"
    return ModeStatus(mode, b, round(spent, 6), state, started, elapsed)


# ------------------------------------------------------------------------------------------- gate

@dataclass(frozen=True)
class Verdict:
    allowed: bool
    reasons: tuple[str, ...]        # why it is held (empty when allowed)
    checked: tuple[str, ...]        # what was checked, e.g. "phase build", "mode speedrun"

    def to_dict(self) -> dict:
        return asdict(self)


def _phase_reason(st: PhaseStatus) -> str | None:
    if st.state == "uncapped":
        return (f"no {st.phase} cap is decided: python -m ctf spend cap {st.phase} --usd N "
                f"[--period day|event] --reason WHY (in an interactive terminal)")
    if st.state == "over":
        return (f"{st.phase} spent ${st.spent:.2f} of its ${st.cap.usd:.2f} {st.cap.period} cap "
                f"(set by {st.cap.by}); raising it is the player's call")
    return None


def _mode_reason(st: ModeStatus) -> str | None:
    if st.state == "undecided":
        hint = "" if st.mode in BUILTIN_MODES else " --challenge GLOB"
        return (f"no {st.mode} budget is decided before spending: python -m ctf spend decide {st.mode} "
                f"--usd N{hint} [--minutes N] --reason WHY [--value 'what a place is worth'] "
                "(in an interactive terminal)")
    if st.state == "over":
        return f"{st.mode} spent ${st.spent:.2f} of its ${st.budget.usd:.2f} budget (decided by {st.budget.by})"
    if st.state == "over_time":
        return (f"{st.mode} has run {st.elapsed_min:.0f} of its {st.budget.minutes:g} minute time box "
                f"(decided by {st.budget.by}); extending it is the player's call")
    return None


def gate(*, phase: str | None = None, mode: str | None = None, challenge_id: str | None = None,
         workdir: Path | None = None, now: float | None = None, tz: str = "UTC",
         records: Iterable[dict] | None = None) -> Verdict:
    """May work of this phase / mode / on this challenge start now? Held when a cap or budget is not
    decided yet or is spent. A challenge is checked against every mode its work belongs to now."""
    if phase is None and mode is None and challenge_id is None:
        raise SpendGovError("gate needs a phase, a mode or a challenge id")
    now = time.time() if now is None else now
    recs = _records(records, workdir)
    reasons, checked = [], []
    if phase is not None:
        checked.append(f"phase {phase}")
        r = _phase_reason(phase_status(phase, recs, now=now, tz=tz))
        if r:
            reasons.append(r)
    modes = [] if mode is None else [mode]
    if challenge_id is not None:
        checked.append(f"challenge {challenge_id}")
        modes += [m for m in modes_of(challenge_id, now, solved_at(recs), mode_budgets(recs)) if m not in modes]
    for m in modes:
        checked.append(f"mode {m}")
        r = _mode_reason(mode_status(m, recs, now=now))
        if r:
            reasons.append(r)
    return Verdict(not reasons, tuple(reasons), tuple(checked))


# ------------------------------------------------------------------------------------ review tiers

def tier_of(path: str, rules: Sequence[tuple[str, str]] = TIER_RULES, *, root: Path | None = None) -> str:
    """The review tier of one file. A relative path is taken as repo-relative and normalized ("." and
    ".." segments folded); an absolute one is resolved (symlinks and "..") and made relative to `root`
    (default: this repo's root) first. Either one that lands outside the root is an error: the tier
    must be decided on the path the file really has, not on a prefix like "docs/../"."""
    if Path(str(path)).is_absolute():
        base = Path(_paths.repo_root() if root is None else root).resolve()
        try:
            p = Path(str(path)).resolve().relative_to(base).as_posix()
        except ValueError:
            raise SpendGovError(f"{path} is outside the root {base}: a tier is decided by the "
                                "repo-relative path") from None
    else:
        p = posixpath.normpath(str(path).replace(os.sep, "/"))
        if p == ".." or p.startswith("../"):
            raise SpendGovError(f"{path} climbs out of the repo root: a tier is decided by the "
                                "repo-relative path")
    for glob, tier in rules:
        if fnmatch.fnmatchcase(p, glob):
            _rank(TIERS, tier, "tier")
            return tier
    return "standard"           # a rules table with no catch-all: an unmatched file is still reviewed


def scope_tier(paths: Iterable[str], rules: Sequence[tuple[str, str]] = TIER_RULES, *,
               root: Path | None = None) -> str:
    """The tier of a scope: its riskiest file's."""
    tiers = [tier_of(p, rules, root=root) for p in paths]
    if not tiers:
        raise SpendGovError("a review scope needs at least one file")
    return max(tiers, key=TIERS.index)


@dataclass(frozen=True)
class Round:
    scope: str
    tree: str
    tier: str
    findings: Mapping[str, int]
    ts: float
    by: str | None = None

    @property
    def worst(self) -> str | None:
        found = [s for s, n in self.findings.items() if n]
        return max(found, key=SEVERITIES.index) if found else None


@dataclass(frozen=True)
class Step:
    action: str          # review | stop | fix | escalate
    reason: str
    round: int           # the round this step would be (rounds so far + 1 for review)


def check_findings(findings: Mapping) -> dict[str, int]:
    if not isinstance(findings, Mapping):
        raise SpendGovError(f"findings must be a mapping of severity to count, got {findings!r}")
    out = {}
    for k, v in findings.items():
        _rank(SEVERITIES, k, "severity")
        if isinstance(v, bool) or not isinstance(v, int) or v < 0:
            raise SpendGovError(f"findings[{k!r}] must be an int >= 0, got {v!r}")
        out[k] = v
    return out


def count_findings(report) -> dict[str, int]:
    """Severity counts from a reviewer's structured output: a list of finding objects, or an object whose
    "findings" key holds that list (the verification report shape). Each finding needs a "severity" that
    is one of SEVERITIES (any case). A finding with no or an unknown severity is an error, never a
    silent zero: an uncounted finding would let the stopping rule stop a review that found something."""
    if isinstance(report, Mapping):
        if "findings" not in report:
            raise SpendGovError('reviewer output is an object with no "findings" list')
        report = report["findings"]
    if not isinstance(report, list):
        raise SpendGovError(f"reviewer findings must be a list of objects, got {type(report).__name__}")
    out: dict[str, int] = {}
    for i, f in enumerate(report):
        if not isinstance(f, Mapping):
            raise SpendGovError(f"finding {i} is not an object: {f!r}")
        sev = f.get("severity")
        if not isinstance(sev, str) or not sev.strip():
            raise SpendGovError(f"finding {i} has no severity; give each finding one of {', '.join(SEVERITIES)}")
        sev = sev.strip().lower()
        _rank(SEVERITIES, sev, "severity")
        out[sev] = out.get(sev, 0) + 1
    return out


def rounds(scope: str, records: Iterable[dict]) -> list[Round]:
    return [Round(r["scope"], r["tree"], r.get("tier", "standard"), dict(r.get("findings") or {}), _ts(r) or 0.0,
                  r.get("by"))
            for r in records if r.get("event") == "review.round" and r.get("scope") == scope]


def next_step(done: Sequence[Round], tier: str, tree: str) -> Step:
    """The review stopping rule, from the severity of the last round's findings."""
    lim = TIER_LIMITS[TIERS[_rank(TIERS, tier, "tier")]]
    n = len(done)
    if lim.rounds == 0:
        return Step("stop", f"tier {tier}: no review (documentation or inert files only)", n)
    if not done:
        return Step("review", f"tier {tier}: first round ({lim.agents} agent(s), up to {lim.rounds} round(s))", 1)
    last = done[-1]
    worst = last.worst
    serious = worst is not None and SEVERITIES.index(worst) >= SEVERITIES.index(lim.continue_at)
    if last.tree == tree:
        if serious:
            return Step("fix", f"round {n} found {worst} at this exact tree: fix it, then review the changed "
                               "tree (re-reviewing an unchanged tree finds nothing new)", n)
        return Step("stop", f"round {n} already reviewed this exact tree and found nothing at or above "
                            f"{lim.continue_at}", n)
    if not serious:
        found = f"its worst was {worst}" if worst else "it found nothing"
        return Step("stop", f"stopping rule: round {n} found nothing at or above {lim.continue_at} ({found}); "
                            "audit the change since with python -m ctf spend diff", n)
    if n >= lim.rounds:
        return Step("escalate", f"{n} round(s) spent (tier {tier} allows {lim.rounds}) and round {n} still found "
                                f"{worst}: a person decides whether more review is worth it", n)
    return Step("review", f"round {n} found {worst} (at or above {lim.continue_at}): round {n + 1}", n + 1)


# ---------------------------------------------------------------------------- scope files and trees

def resolve_scope(root: Path, patterns: Iterable[str]) -> list[str]:
    """Repo-relative POSIX paths of the files the patterns name under root (a path or a glob). A pattern
    that names nothing, or reaches outside root, is an error."""
    root = Path(root).resolve()
    out: set[str] = set()
    for pat in patterns:
        if not isinstance(pat, str) or not pat.strip():
            raise SpendGovError(f"scope pattern must be a non-empty string, got {pat!r}")
        if Path(pat).is_absolute() or ".." in Path(pat).parts:
            raise SpendGovError(f"scope pattern {pat!r} must be relative to the root and stay inside it")
        hits = [p for p in root.glob(pat) if p.is_file()] if any(c in pat for c in "*?[") else (
            [root / pat] if (root / pat).is_file() else [])
        if not hits:
            raise SpendGovError(f"scope pattern {pat!r} names no file under {root}")
        for p in hits:
            rp = p.resolve()
            if root != rp and root not in rp.parents:
                raise SpendGovError(f"{pat!r} resolves outside the root ({rp})")
            out.add(p.relative_to(root).as_posix())
    return sorted(out)


def file_hashes(root: Path, files: Iterable[str]) -> dict[str, str]:
    out = {}
    for f in files:
        p = Path(root) / f
        try:
            out[f] = hashlib.sha256(p.read_bytes()).hexdigest()
        except FileNotFoundError:
            raise SpendGovError(f"scope file {f} is missing under {root}") from None
    return dict(sorted(out.items()))


def tree_hash(hashes: Mapping[str, str]) -> str:
    h = hashlib.sha256()
    for f, d in sorted(hashes.items()):
        h.update(f"{f}\0{d}\n".encode())
    return h.hexdigest()


def snapshot_path(scope: str, workdir: Path | None = None) -> Path:
    return _wd(workdir).joinpath(*SNAPSHOT_DIR, f"{_name(scope, 'scope')}.json")


def record_round(scope: str, root: Path, files: Sequence[str], findings: Mapping[str, int], *,
                 by: str | None = None, workdir: Path | None = None) -> dict:
    """One finished review round: a `review.round` ledger record and the snapshot of what it reviewed."""
    _name(scope, "scope")
    fnd = check_findings(findings)
    hashes = file_hashes(root, files)
    if not hashes:
        raise SpendGovError("a review round needs at least one file")
    tree = tree_hash(hashes)
    tier = scope_tier(hashes)
    snap = snapshot_path(scope, workdir)
    snap.parent.mkdir(parents=True, exist_ok=True)
    tmp = snap.with_name(f".{snap.name}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps({"scope": scope, "tree": tree, "tier": tier, "ts": time.time(), "files": hashes},
                              indent=1, sort_keys=True), encoding="utf-8")
    os.replace(tmp, snap)
    fields: dict = {"scope": scope, "tree": tree, "tier": tier, "files": len(hashes), "findings": fnd}
    if by:
        fields["by"] = by
    return _ledger.append("review.round", workdir=workdir, **fields)


@dataclass(frozen=True)
class Diff:
    scope: str
    base_tree: str
    tree: str
    added: tuple[str, ...]
    changed: tuple[str, ...]
    removed: tuple[str, ...]
    unchanged: int

    @property
    def clean(self) -> bool:
        return not (self.added or self.changed or self.removed)

    def to_dict(self) -> dict:
        return dict(asdict(self), clean=self.clean)


def diff_since_review(scope: str, root: Path, files: Sequence[str] | None = None, *,
                      workdir: Path | None = None) -> Diff:
    """The standing diff audit: what changed in the scope since its last recorded review round.
    `files` is the scope now; None means the files that round reviewed (a missing one is removed)."""
    snap = snapshot_path(scope, workdir)
    try:
        base = json.loads(snap.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise SpendGovError(f"no reviewed snapshot for scope {scope!r} ({snap}): record a round first "
                            "(python -m ctf spend record)") from None
    except json.JSONDecodeError as e:
        raise SpendGovError(f"{snap}: corrupt snapshot ({e})") from None
    old = base.get("files")
    if not isinstance(old, dict):
        raise SpendGovError(f"{snap}: corrupt snapshot (no files table)")
    bad = [f for f in old if not isinstance(f, str) or Path(f).is_absolute() or ".." in Path(f).parts]
    if bad:
        raise SpendGovError(f"{snap}: corrupt snapshot (paths outside the root: {bad[:3]})")
    if files is None:
        files = [f for f in old if (Path(root) / f).is_file()]
    now = file_hashes(root, files)
    added = tuple(f for f in now if f not in old)
    changed = tuple(f for f in now if f in old and old[f] != now[f])
    removed = tuple(sorted(f for f in old if f not in now))
    return Diff(scope, str(base.get("tree", "")), tree_hash(now), added, changed, removed,
                sum(1 for f in now if old.get(f) == now[f]))


# ------------------------------------------------------------------------------- review dispatcher

@dataclass(frozen=True)
class ReviewTask:
    name: str
    patterns: tuple[str, ...]


def load_tasks(data) -> list[ReviewTask]:
    """A JSON list of {name, scope: [path or glob, ...]}. Names are unique."""
    if not isinstance(data, list) or not data:
        raise SpendGovError("review tasks must be a non-empty JSON list of {name, scope}")
    out, seen = [], set()
    for i, t in enumerate(data):
        if not isinstance(t, dict):
            raise SpendGovError(f"task {i} must be an object, got {t!r}")
        extra = set(t) - {"name", "scope"}
        if extra:
            raise SpendGovError(f"task {i}: unknown key(s) {', '.join(sorted(extra))}")
        name = _name(t.get("name"), f"task {i} name")
        if name in seen:
            raise SpendGovError(f"task name {name!r} appears twice")
        seen.add(name)
        sc = t.get("scope")
        if not isinstance(sc, list) or not sc:
            raise SpendGovError(f"task {name}: scope must be a non-empty list of paths or globs")
        out.append(ReviewTask(name, tuple(sc)))
    return out


@dataclass(frozen=True)
class PlanEntry:
    name: str
    action: str          # spawn | duplicate | stop | fix | escalate | over_cap
    tier: str
    agents: int          # reviewer agents this entry starts (0 unless spawn)
    files: int
    tree: str
    reason: str
    round: int = 0
    covered_by: str | None = None


@dataclass(frozen=True)
class ReviewPlan:
    entries: tuple[PlanEntry, ...]
    agents: int          # the dry-run count: agents the plan would start
    max_agents: int

    @property
    def needs_person(self) -> bool:
        return any(e.action in ("escalate", "over_cap") for e in self.entries)

    def to_dict(self) -> dict:
        return {"entries": [asdict(e) for e in self.entries], "agents": self.agents, "max_agents": self.max_agents,
                "needs_person": self.needs_person}


def plan_reviews(tasks: Sequence[ReviewTask], root: Path, *, records: Iterable[dict] = (),
                 max_agents: int = DEFAULT_MAX_AGENTS) -> ReviewPlan:
    """Plan a review wave: each task's tier and stopping-rule step; a task whose files another task
    already covers is folded into it; spawns stop at `max_agents`. Riskiest and widest tasks go first."""
    if isinstance(max_agents, bool) or not isinstance(max_agents, int) or max_agents < 0:
        raise SpendGovError(f"max_agents must be an int >= 0, got {max_agents!r}")
    recs = list(records)
    resolved = []
    for t in tasks:
        files = resolve_scope(root, t.patterns)
        hashes = file_hashes(root, files)
        resolved.append((t, files, tree_hash(hashes), scope_tier(files)))
    resolved.sort(key=lambda x: (-TIERS.index(x[3]), -len(x[1])))
    kept: list[tuple[str, set[str]]] = []
    entries, total = [], 0
    for t, files, tree, tier in resolved:
        fs = set(files)
        cover = next((n for n, k in kept if fs <= k), None)
        if cover is not None:
            entries.append(PlanEntry(t.name, "duplicate", tier, 0, len(files), tree,
                                     f"every file is already in task {cover}", 0, cover))
            continue
        kept.append((t.name, fs))
        step = next_step(rounds(t.name, recs), tier, tree)
        if step.action != "review":
            entries.append(PlanEntry(t.name, step.action, tier, 0, len(files), tree, step.reason, step.round))
            continue
        want = TIER_LIMITS[tier].agents
        if total + want > max_agents:
            entries.append(PlanEntry(t.name, "over_cap", tier, 0, len(files), tree,
                                     f"would start {want} agent(s) past the workflow cap of {max_agents} "
                                     f"({total} already planned)", step.round))
            continue
        total += want
        entries.append(PlanEntry(t.name, "spawn", tier, want, len(files), tree, step.reason, step.round))
    return ReviewPlan(tuple(entries), total, max_agents)


# ---------------------------------------------------------------------------------- investigations

@dataclass(frozen=True)
class InvestigationStatus:
    inv_id: str
    question: str
    metric: str
    threshold: float
    minutes: float
    usd: float
    by: str
    opened_at: float
    elapsed_min: float
    spent: float
    state: str                       # open | over_time | over_budget | closed
    answer: float | None = None
    crossed: bool | None = None      # answer >= threshold, once closed
    note: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def _num(value, what: str, positive: bool) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise SpendGovError(f"{what} must be a finite number, got {value!r}")
    if positive and value <= 0:
        raise SpendGovError(f"{what} must be > 0, got {value!r}")
    return float(value)


def open_investigation(inv_id: str, question: str, *, metric: str, threshold: float, minutes: float,
                       usd: float, by: str, workdir: Path | None = None, records: Iterable[dict] | None = None) -> dict:
    """Open a time-boxed investigation with a numeric question: what is measured (metric), the value
    that decides it (threshold), the time box and the dollar cap. Its spend is source
    `investigation:<id>`."""
    _name(inv_id, "investigation id")
    if any(r.get("event") == "investigation.open" and r.get("inv_id") == inv_id
           for r in _records(records, workdir)):
        raise SpendGovError(f"investigation {inv_id!r} is already open (or was): pick a new id")
    return _ledger.append("investigation.open", workdir=workdir, inv_id=inv_id,
                          question=_text(question, "question"), metric=_text(metric, "metric"),
                          threshold=_num(threshold, "threshold", False), minutes=_num(minutes, "minutes", True),
                          usd=_usd(usd), by=_text(by, "by"))


def close_investigation(inv_id: str, answer: float, *, by: str, note: str | None = None,
                        workdir: Path | None = None, records: Iterable[dict] | None = None) -> dict:
    """Close it with the measured answer (a number: the question was numeric)."""
    recs = _records(records, workdir)
    if not any(r.get("event") == "investigation.open" and r.get("inv_id") == inv_id for r in recs):
        raise SpendGovError(f"no investigation {inv_id!r} is open")
    if any(r.get("event") == "investigation.close" and r.get("inv_id") == inv_id for r in recs):
        raise SpendGovError(f"investigation {inv_id!r} is already closed")
    fields: dict = {"inv_id": inv_id, "answer": _num(answer, "answer", False), "by": _text(by, "by")}
    if note:
        fields["note"] = note
    return _ledger.append("investigation.close", workdir=workdir, **fields)


def investigations(records: Iterable[dict], *, now: float) -> list[InvestigationStatus]:
    recs = list(records)
    opened = {r["inv_id"]: r for r in recs if r.get("event") == "investigation.open"}
    closed = {r["inv_id"]: r for r in recs if r.get("event") == "investigation.close"}
    spent: dict[str, float] = {}
    for r in recs:
        src = r.get("source")
        if r.get("event") == "spend" and isinstance(src, str) and src.startswith(INVESTIGATION_SOURCE):
            k = src[len(INVESTIGATION_SOURCE):]
            spent[k] = spent.get(k, 0.0) + float(r.get("usd") or 0.0)
    out = []
    for k, o in opened.items():
        t0 = _ts(o) or 0.0
        c = closed.get(k)
        end = (_ts(c) or now) if c else now
        elapsed = max(0.0, end - t0) / 60.0
        usd = spent.get(k, 0.0)
        if c:
            state = "closed"
        elif usd >= float(o["usd"]):
            state = "over_budget"
        elif elapsed >= float(o["minutes"]):
            state = "over_time"
        else:
            state = "open"
        ans = float(c["answer"]) if c else None
        out.append(InvestigationStatus(k, o["question"], o["metric"], float(o["threshold"]), float(o["minutes"]),
                                       float(o["usd"]), o.get("by", ""), t0, round(elapsed, 3), round(usd, 6), state,
                                       ans, None if ans is None else ans >= float(o["threshold"]),
                                       c.get("note") if c else None))
    return out


def investigation(inv_id: str, records: Iterable[dict], *, now: float) -> InvestigationStatus:
    for s in investigations(records, now=now):
        if s.inv_id == inv_id:
            return s
    raise SpendGovError(f"no investigation {inv_id!r}")


# ------------------------------------------------------------------------------------------ status

@dataclass(frozen=True)
class Status:
    now: float
    tz: str
    phases: tuple[PhaseStatus, ...]
    modes: tuple[ModeStatus, ...]
    investigations: tuple[InvestigationStatus, ...]
    uncategorized_usd: float = 0.0

    def to_dict(self) -> dict:
        return {"now": self.now, "tz": self.tz, "phases": [p.to_dict() for p in self.phases],
                "modes": [m.to_dict() for m in self.modes],
                "investigations": [i.to_dict() for i in self.investigations],
                "uncategorized_usd": self.uncategorized_usd}


def status(*, workdir: Path | None = None, now: float | None = None, tz: str = "UTC",
           records: Iterable[dict] | None = None) -> Status:
    now = time.time() if now is None else now
    recs = _records(records, workdir)
    modes = sorted(set(BUILTIN_MODES) | set(mode_budgets(recs)))
    unc = sum(float(r.get("usd") or 0.0) for r in recs if r.get("event") == "spend" and spend_phase(r) == "uncategorized")
    return Status(now, tz, tuple(phase_status(p, recs, now=now, tz=tz) for p in PHASES),
                  tuple(mode_status(m, recs, now=now) for m in modes), tuple(investigations(recs, now=now)), round(unc, 6))
