"""The daily look-ahead for rolling-release events (B-256): the deterministic plumbing around the
`day-lookahead` workflow (workflows/day-lookahead.js).

Huntress ran a look-ahead every night by hand: agents wrote a prediction page per lane, a lane could drop
silently (Day 17: the Warmups agent failed on an API-classifier false positive and the README read "All
five lanes"), the tagged-copy staging was left to the prompt (row 355), and the harnesses had no fixtures
for the computed class (row 494). Predicting the next day's shapes is agent work; everything around it
is here, and none of it starts a model:

    require_rolling(profile)                       # LookaheadError unless the event releases more than once
    lanes = profile_lanes(profile)                 # the event's lanes: slugs of its categories, in order
    plans = plan_day(profile, matrix_dir, reports) # forecast.plan over exactly the profile's lanes
    args = workflow_args(profile, plans, ...)      # the day-lookahead args; workflows.preflight passes
    rep = finish(plan_doc, result, out_dir, previous_forecast=None)   # README + forecast.toml

Lanes. A lane is the slug of an event category (lower case, every run of other characters a `-`):
"Script Analysis" is `script-analysis`. It is NOT the canonical dispatch category (triage aliases map
"Binary" to `pwn`; a look-ahead lane is the event's own lane). Matrix lanes and gate-report lanes must
be among the profile's lanes; one that is not is an error naming both lists (a misspelt lane would
otherwise look like a missing one). A profile lane with no matrix entry, no gate report or no previous
base gets an agent (forecast.plan: coverage or shape unknown).

The no-model staging step (prepare, in ctf/cli/lookahead_daily.py) runs tagged.stage and
fixtures.stage_computed into the matrix before the workflow launches, and records what it staged in
the plan document, so each lane brief can name its staged specimens.

finish() is the missing-lane check after the run, independent of the workflow's own: every lane the
plan gave an agent and the result does not carry as staged is written `<lane>: NOT staged`, followed by
that lane's last forecast (from the previous forecast file, or "none on record"). The README never says
"all lanes"; it counts. A result entry for a lane the plan did not give an agent is an error. The staged
lanes' globs become `forecast.toml`, which forecast.load reads back before finish returns, so the next
day `ctf lookahead score` can score it.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from . import LookaheadError
from . import forecast as _forecast
from . import matrix as _matrix

DAY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")
PLAN_FILE = "plan.json"
ARGS_FILE = "workflow-args.json"
README_FILE = "README.md"
FORECAST_FILE = "forecast.toml"
WORKFLOW = "day-lookahead"


def lane_slug(category: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", str(category).strip().lower()).strip("-")
    return s


def profile_lanes(profile) -> tuple[str, ...]:
    """The event's look-ahead lanes, in the profile's category order, without repeats."""
    out = []
    for c in profile.categories:
        s = lane_slug(c)
        if s and s not in out:
            out.append(s)
    if not out:
        raise LookaheadError(f"event {profile.slug!r} declares no categories: the daily look-ahead has no "
                             "lanes (set `categories` in its event.toml)")
    return tuple(out)


def is_rolling(profile) -> bool:
    a = profile.allowance
    return bool(a.daily_release) or len(a.releases) >= 2


def require_rolling(profile) -> None:
    if not is_rolling(profile):
        raise LookaheadError(
            f"event {profile.slug!r} is not a rolling-release event: [allowance] has no daily_release and "
            "fewer than two releases. The daily look-ahead only runs for an event that releases more than "
            "once; declare allowance.daily_release (\"HH:MM\") or allowance.releases in its event.toml")


def check_day(day) -> str:
    if not isinstance(day, str) or not DAY_RE.match(day):
        raise LookaheadError(f"day {day!r}: a short label of letters, digits, '.', '_' or '-' (e.g. d29)")
    return day


def _report_lane(r) -> str:
    return r.get("lane") if isinstance(r, dict) else r.lane


def plan_day(profile, matrix_dir, reports=None) -> list:
    """forecast.plan over exactly the profile's lanes. `reports`: gate LaneReports or their JSON dicts
    (None or [] on a first night: every lane then has no report, so every lane gets an agent)."""
    lanes = profile_lanes(profile)
    m = _matrix.load(matrix_dir)
    stray = sorted(set(m.lanes) - set(lanes))
    if stray:
        raise LookaheadError(f"{m.path}: matrix lane(s) {', '.join(stray)} are not lanes of event "
                             f"{profile.slug!r} (its lanes: {', '.join(lanes)})")
    reports = list(reports or [])
    rstray = sorted({str(_report_lane(r)) for r in reports} - set(lanes))
    if rstray:
        raise LookaheadError(f"gate report lane(s) {', '.join(rstray)} are not lanes of event "
                             f"{profile.slug!r} (its lanes: {', '.join(lanes)})")
    shapes = {}
    for lane in lanes:
        cfg = m.lanes.get(lane)
        if cfg is not None and cfg.previous is not None and cfg.base is not None:
            shapes[lane] = (_read_json(cfg.previous, "previous"), _read_json(cfg.base, "base"))
        else:
            shapes[lane] = None
    plans = {p.lane: p for p in _forecast.plan(reports, shapes)}
    missing = [ln for ln in lanes if ln not in plans]
    if missing:      # forecast.plan covers every lane it is given; this would be a contract break
        raise LookaheadError(f"forecast.plan left out lane(s) {', '.join(missing)}")
    return [plans[ln] for ln in lanes]


def _read_json(path, what: str):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise LookaheadError(f"{what} {path}: not there") from None
    except (OSError, ValueError) as e:
        raise LookaheadError(f"{what} {path}: not readable JSON ({e})") from None


def plan_doc(profile, plans, *, day: str, matrix_dir, staged=None) -> dict:
    """The plan document finish() reads: every profile lane, whether it gets an agent and why, and the
    specimens the no-model step staged per lane."""
    check_day(day)
    staged = {k: list(v) for k, v in (staged or {}).items()}
    lanes = [p.lane for p in plans]
    bad = sorted(set(staged) - set(lanes))
    if bad:
        raise LookaheadError(f"staged specimens for lane(s) {', '.join(bad)}, which are not planned lanes")
    return {"event": profile.slug, "day": day, "matrix": str(Path(matrix_dir)),
            "lanes": [{"key": p.lane, "agent": bool(p.agent), "reasons": list(p.reasons),
                       "staged": staged.get(p.lane, [])} for p in plans]}


def workflow_args(profile, doc: dict, *, repo, out, agent_cap: int | None = None) -> dict:
    """The day-lookahead workflow args: only the lanes the plan gives an agent, each with its own
    reasons and staged specimens. LookaheadError when no lane needs an agent (nothing to launch)."""
    lanes = [{"key": ln["key"], "reasons": ln["reasons"], "staged": ln["staged"]}
             for ln in doc["lanes"] if ln["agent"]]
    if not lanes:
        raise LookaheadError(f"day {doc['day']}: no lane needs an agent (every gate green and every shape "
                             "unchanged); run finish without a result to write the README")
    args = {"event": profile.name, "repo": str(repo), "out": str(out), "day": doc["day"],
            "matrix": doc["matrix"], "lanes": lanes}
    if agent_cap is not None:
        args["agentCap"] = agent_cap
    return args


@dataclass
class FinishReport:
    day: str
    staged: list = field(default_factory=list)          # lane keys
    not_staged: list = field(default_factory=list)      # lane keys the plan gave an agent, not staged
    no_agent: list = field(default_factory=list)        # lane keys the plan gave no agent
    dropped_globs: list = field(default_factory=list)   # (lane, field, value) blank globs dropped
    readme: Path | None = None
    forecast: Path | None = None

    @property
    def ok(self) -> bool:
        return not self.not_staged


def _strlist(v, where: str) -> list:
    if v is None:
        return []
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        raise LookaheadError(f"{where}: expected a list of strings")
    return v


def _toml_str(s: str) -> str:
    return json.dumps(s, ensure_ascii=True)


def _last_forecast_lines(prev, lane: str) -> list[str]:
    if prev is None or lane not in prev.lanes:
        return ["  last forecast: none on record"]
    lf = prev.lanes[lane]
    out = [f"  last forecast ({prev.day or 'undated'}): new {', '.join(lf.new) or '(none)'}; "
           f"gaps {', '.join(lf.gaps) or '(none)'}"]
    if lf.note:
        out.append(f"  note: {lf.note}")
    return out


def finish(doc: dict, result, out_dir, previous_forecast=None) -> FinishReport:
    """Write <out_dir>/README.md (every lane named) and, when a lane was staged, forecast.toml.
    `result`: the day-lookahead workflow's return value (None only when the plan gave no lane an agent).
    `previous_forecast`: the last forecast file (path) or a loaded Forecast, for NOT staged lanes."""
    day = check_day(doc.get("day"))
    planned = {ln["key"]: ln for ln in doc.get("lanes", [])}
    agent_lanes = [k for k, ln in planned.items() if ln["agent"]]
    if result is None:
        if agent_lanes:
            raise LookaheadError(f"day {day}: the plan gave {', '.join(agent_lanes)} an agent but no workflow "
                                 "result was given; pass the day-lookahead result")
        result = {"staged": [], "notStaged": []}
    if not isinstance(result, dict) or not isinstance(result.get("staged"), list):
        raise LookaheadError("result: expected the day-lookahead return value {staged: [...], notStaged: [...]}")
    prev = previous_forecast
    if prev is not None and not isinstance(prev, _forecast.Forecast):
        prev = _forecast.load(prev)
    got = {}
    for i, e in enumerate(result["staged"]):
        if not isinstance(e, dict) or not isinstance(e.get("lane"), str):
            raise LookaheadError(f"result staged #{i + 1}: no lane")
        lane = e["lane"]
        if lane not in planned or not planned[lane]["agent"]:
            raise LookaheadError(f"result staged #{i + 1}: lane {lane!r} was not given an agent by the plan "
                                 f"(agent lanes: {', '.join(agent_lanes) or 'none'})")
        if lane in got:
            raise LookaheadError(f"result: lane {lane!r} is staged twice")
        got[lane] = e
    rep = FinishReport(day)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    fc_lines = [f"day = {_toml_str(day)}"]
    body = []
    for key, ln in planned.items():
        staged_specimens = ln.get("staged") or []
        sp = f"; {len(staged_specimens)} specimen(s) staged by the no-model step" if staged_specimens else ""
        if not ln["agent"]:
            rep.no_agent.append(key)
            body.append(f"- {key}: no agent ({'; '.join(ln['reasons'])}){sp}")
            continue
        e = got.get(key)
        if e is None:
            rep.not_staged.append(key)
            body.append(f"- {key}: NOT staged (its agent returned nothing twice){sp}")
            body += _last_forecast_lines(prev, key)
            continue
        rep.staged.append(key)
        globs = {}
        for f in ("new", "gaps"):
            vals = _strlist(e.get(f), f"result lane {key} {f}")
            keep = [v.strip() for v in vals if v.strip()]
            rep.dropped_globs += [(key, f, v) for v in vals if not v.strip()]
            globs[f] = keep
        note = e.get("note") if isinstance(e.get("note"), str) else ""
        file = e.get("file") if isinstance(e.get("file"), str) else ""
        specimens = _strlist(e.get("specimens"), f"result lane {key} specimens")
        body.append(f"- {key}: staged: {file or '(no page named)'}; {len(globs['new'])} new glob(s), "
                    f"{len(globs['gaps'])} gap glob(s), {len(specimens)} specimen(s) by its agent{sp}")
        fc_lines += [f"[lane.{_toml_key(key)}]",
                     "new = [" + ", ".join(_toml_str(g) for g in globs["new"]) + "]",
                     "gaps = [" + ", ".join(_toml_str(g) for g in globs["gaps"]) + "]",
                     f"note = {_toml_str(note)}"]
    head = (f"# Look-ahead {day} ({doc.get('event', '')})\n\n"
            f"{len(rep.staged)} of {len(agent_lanes)} agent lane(s) staged; "
            f"{len(rep.not_staged)} NOT staged"
            + (f" ({', '.join(rep.not_staged)})" if rep.not_staged else "")
            + f"; {len(rep.no_agent)} lane(s) needed no agent. {len(planned)} lane(s) in the event.\n")
    tail = []
    if rep.dropped_globs:
        tail.append("\nBlank forecast globs dropped (not scorable): "
                    + ", ".join(f"{lane}.{f}" for lane, f, _ in rep.dropped_globs) + "\n")
    rep.readme = out / README_FILE
    rep.readme.write_text(head + "\n" + "\n".join(body) + "\n" + "".join(tail), encoding="utf-8")
    fc = out / FORECAST_FILE
    if rep.staged:
        fc.write_text("\n".join(fc_lines) + "\n", encoding="utf-8")
        _forecast.load(fc)          # what score will read: it must load
        rep.forecast = fc
    elif fc.exists():
        fc.unlink()                 # a stale forecast from an earlier run of this day would be scored
    return rep


def _toml_key(key: str) -> str:
    return key if re.fullmatch(r"[A-Za-z0-9_-]+", key) else _toml_str(key)
