"""Score a look-ahead forecast against the day, and plan the next look-ahead (B-174).

Huntress: the forecasts named 9 of 25 lane-days' real gaps on Days 9-13 (36%), and nobody measured
it; the look-ahead ran six to eight agents on every lane every night. Two functions:

    fc = load(path)                                           # Forecast(day, lanes)
    s = score(fc, lane, previous, actual, report=None, workdir=None, record=True)    # Score
    plans = plan(reports, shapes)                             # [LanePlan]: which lanes get an agent

Forecast file (TOML; unknown keys are an error):

    day = "d29"                       # optional label, recorded with each score
    [lane.binary]
    new = ["d29_*", "structural_*_count"]   # globs over the ids the forecast expects to be new or changed
    gaps = ["structural_*"]                 # globs over the ids it expects the armed lane to miss
    note = "..."

score(): the day's new shape is the qdiff (ctf.adapt.qdiff) from the previous base's questions to the
day's: every changed id that needs attention (added, kind, none, syntax, accepted; removed ids are not
asked, so not counted), a leading `setN.` dropped. `hit` = those a `new` glob matches, `missed` = the
rest, `unused` = `new` globs that match none. `recall` = hit / new (None when nothing was new). With a
gate report of the day (LaneReport, or its to_json() dict), the release gaps are its wrong,
unanswered, unsure and uncovered ids: `gap_missed` lists those no `gaps` glob named. One `lookahead.score`
ledger record.

plan(): a lane gets an agent when its last gate report has a gap, or its shape changed (the qdiff of
`previous` to `base` has a change that needs attention), or its shape is unknown (no previous base
to compare). A green lane with an unchanged shape gets none: the scripted gate is its look-ahead.
"""
from __future__ import annotations

import fnmatch
import tomllib
from dataclasses import dataclass
from pathlib import Path

from .. import ledger as _ledger
from ..adapt import qdiff as _qdiff
from . import LookaheadError
from . import matrix as _matrix

_FC_KEYS = {"day", "lane"}
_FC_LANE_KEYS = {"new", "gaps", "note"}
GAP_ID_KINDS = ("wrong", "unanswered", "unsure", "uncovered")


@dataclass(frozen=True)
class LaneForecast:
    new: tuple[str, ...] = ()
    gaps: tuple[str, ...] = ()
    note: str = ""


@dataclass(frozen=True)
class Forecast:
    day: str
    lanes: dict          # lane -> LaneForecast


@dataclass(frozen=True)
class Score:
    lane: str
    day: str
    new: tuple[str, ...]
    hit: tuple[str, ...]
    missed: tuple[str, ...]
    unused: tuple[str, ...]
    gap_ids: tuple[str, ...] | None = None
    gap_missed: tuple[str, ...] | None = None

    @property
    def recall(self) -> float | None:
        return round(len(self.hit) / len(self.new), 4) if self.new else None

    def lines(self) -> list[str]:
        r = "n/a (nothing new)" if self.recall is None else f"{self.recall:.0%}"
        out = [f"FORECAST {self.lane} {self.day or ''}".rstrip()
               + f": {len(self.hit)}/{len(self.new)} new id(s) named, recall {r}; "
               f"{len(self.unused)} glob(s) matched nothing"]
        out += [f"MISSED  {q}" for q in self.missed]
        out += [f"UNUSED  {g}" for g in self.unused]
        if self.gap_missed is not None:
            out.append(f"release gaps: {len(self.gap_ids)} id(s), {len(self.gap_missed)} not forecast")
            out += [f"GAP-MISSED {q}" for q in self.gap_missed]
        return out


@dataclass(frozen=True)
class LanePlan:
    lane: str
    agent: bool
    reasons: tuple[str, ...]

    def line(self) -> str:
        return f"{'AGENT' if self.agent else 'none '} {self.lane}: {'; '.join(self.reasons)}"


def load(path) -> Forecast:
    p = Path(path)
    try:
        raw = tomllib.loads(p.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise LookaheadError(f"{p}: forecast not there") from None
    except (OSError, tomllib.TOMLDecodeError) as e:
        raise LookaheadError(f"{p}: not readable TOML ({e})") from None
    extra = sorted(set(raw) - _FC_KEYS)
    if extra:
        raise LookaheadError(f"{p}: unknown key(s) {', '.join(extra)}")
    day = raw.get("day", "")
    if not isinstance(day, str):
        raise LookaheadError(f"{p}: day is a string")
    lanes = {}
    for name, v in (raw.get("lane") or {}).items():
        where = f"{p} [lane.{name}]"
        if not isinstance(v, dict):
            raise LookaheadError(f"{where}: expected a table")
        bad = sorted(set(v) - _FC_LANE_KEYS)
        if bad:
            raise LookaheadError(f"{where}: unknown key(s) {', '.join(bad)}")
        for k in ("new", "gaps"):
            if k in v and (not isinstance(v[k], list) or not all(isinstance(g, str) and g for g in v[k])):
                raise LookaheadError(f"{where}: {k} is a list of id globs")
        lanes[name] = LaneForecast(tuple(v.get("new", ())), tuple(v.get("gaps", ())), str(v.get("note", "")))
    if not lanes:
        raise LookaheadError(f"{p}: no [lane.<name>] table: a forecast that names nothing cannot be scored")
    return Forecast(day, lanes)


def _matches(qid: str, globs) -> bool:
    return any(fnmatch.fnmatchcase(qid, g) for g in globs)


def new_shape(previous, actual) -> tuple[str, ...]:
    """The bare ids whose contract changed from `previous` to `actual` (bodies or question lists)."""
    try:
        d = _qdiff.qdiff(previous, actual)
    except _qdiff.QDiffError as e:
        raise LookaheadError(f"qdiff: {e}") from None
    return tuple(sorted({_matrix.bare_id(c.qid) for c in d.attention if c.what != "removed"}))


def _gap_ids(report) -> tuple[str, ...]:
    gaps = report.get("gaps") if isinstance(report, dict) else [g.__dict__ for g in report.gaps]
    if not isinstance(gaps, list):
        raise LookaheadError("report: no gap list (pass a gate report's JSON)")
    return tuple(sorted({_matrix.bare_id(str(g.get("qid") or "")) for g in gaps
                         if isinstance(g, dict) and g.get("kind") in GAP_ID_KINDS and g.get("qid")}))


def score(fc: Forecast, lane: str, previous, actual, report=None, workdir: Path | None = None,
          record: bool = True) -> Score:
    if lane not in fc.lanes:
        raise LookaheadError(f"the forecast has no [lane.{lane}] (it has {', '.join(fc.lanes)})")
    lf = fc.lanes[lane]
    new = new_shape(previous, actual)
    hit = tuple(q for q in new if _matches(q, lf.new))
    missed = tuple(q for q in new if q not in hit)
    unused = tuple(g for g in lf.new if not any(fnmatch.fnmatchcase(q, g) for q in new))
    gap_ids = gap_missed = None
    if report is not None:
        rl = report.get("lane") if isinstance(report, dict) else report.lane
        if rl != lane:
            raise LookaheadError(f"report is for lane {rl!r}, not {lane!r}")
        gap_ids = _gap_ids(report)
        gap_missed = tuple(q for q in gap_ids if not _matches(q, lf.gaps))
    s = Score(lane, fc.day, new, hit, missed, unused, gap_ids, gap_missed)
    if record:
        extra = {} if gap_ids is None else {"gap_ids": len(gap_ids), "gap_missed": len(gap_missed)}
        _ledger.append("lookahead.score", workdir=workdir, lane=lane, day=fc.day, new=len(new), hit=len(hit),
                       missed=len(missed), unused=len(unused), recall=s.recall, **extra)
    return s


def plan(reports, shapes: dict) -> list[LanePlan]:
    """reports: LaneReports or their JSON dicts; shapes: {lane: (previous, base) bodies, or None}."""
    by_lane = {}
    for r in reports or []:
        lane = r.get("lane") if isinstance(r, dict) else r.lane
        by_lane[lane] = r
    out = []
    for lane in sorted(set(by_lane) | set(shapes)):
        reasons, agent = [], False
        r = by_lane.get(lane)
        if r is None:
            agent = True
            reasons.append("no gate report: coverage unknown")
        else:
            gaps = r.get("gaps") if isinstance(r, dict) else r.gaps
            if gaps:
                agent = True
                kinds = sorted({(g.get("kind") if isinstance(g, dict) else g.kind) for g in gaps})
                reasons.append(f"{len(gaps)} open gap(s) ({', '.join(kinds)})")
            else:
                reasons.append("gate green")
        pair = shapes.get(lane)
        if pair is None:
            agent = True
            reasons.append("shape unknown: no previous base to compare")
        else:
            changed = new_shape(*pair)
            if changed:
                agent = True
                reasons.append(f"new shape: {len(changed)} changed id(s), e.g. {', '.join(changed[:3])}")
            else:
                reasons.append("shape unchanged")
        out.append(LanePlan(lane, agent, tuple(reasons)))
    return out
