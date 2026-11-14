"""The wave ledger, generated from the event ledger (B-101): a second-by-second replay of one wave
and the live spend summary.

    from ctf import replay
    recs = list(ledger.read(workdir))
    for w in replay.waves(recs): ...
    r = replay.wave_replay(recs, "W1")          # pipeline rows + one row per challenge
    print(replay.render(r))
    s = replay.summarize(recs, tail_of=lambda cid: meter.status(cid).timer_applies)
    print(replay.render_summary(s))

`python -m ctf ledger replay|summary` prints both.

Reading the ledger into stages (stage_events):
  * the stage events of ctf/stages.py as written;
  * agent_launch -> agent_launch (by agent:<harness>);
  * engine.run -> first_tool at the run's start (ts - seconds), by engine:<id>; with status solved or
    candidate also a candidate at its end;
  * platform.submit -> submit; accepted when the status is correct or already_solved (what
    SubmitResult.accepted means), rejected when incorrect. "<cid>#<answer>" counts against <cid>.

Waves: each wave_open starts a wave. T0 is its `announced` start when recorded, else the time it was
detected. A challenge belongs to the wave its detect names; one never detected belongs to the last
wave opened at or before its first stage. With no wave_open in the ledger there is one wave, "all",
timed from its first stage (or from a T0 the caller gives), and the output says so.

Who closed a solved challenge (closed_by): the `layer` field of an accepted mark when given; else
"agent" when an agent launched, spent, or used a tool on it before it was accepted; else "layer1"
when an engine ran on it before; else "other" (a person, or a path that wrote no stage).
"""
from __future__ import annotations

import datetime as _dt
import statistics
from dataclasses import asdict, dataclass, field
from typing import Callable, Iterable

from . import stages as _stages

ACCEPTED_STATUSES = frozenset({"correct", "already_solved"})
ENGINE_CANDIDATE_STATUSES = frozenset({"solved", "candidate"})
NO_WAVE = "all"

# per-challenge columns, in pipeline order: (column, stage); each cell is the stage's first time
# (for intake, the first intake_done that did not fail)
COLUMNS = (("detect", "detect"), ("claim", "claim"), ("intake", "intake_done"), ("agent", "agent_launch"),
           ("tool", "first_tool"), ("cand", "candidate"), ("submit", "submit"), ("accepted", "accepted"))


@dataclass(frozen=True)
class Stage:
    ts: float
    stage: str
    challenge_id: str | None
    by: str | None = None
    detail: dict = field(default_factory=dict)


@dataclass
class Wave:
    label: str
    t0: float
    opened_ts: float | None
    announced: float | None = None
    count: int | None = None
    synthetic: bool = False

    @property
    def start(self) -> float:
        return min(x for x in (self.t0, self.opened_ts) if x is not None)


def _key(cid) -> str:
    return str(cid).split("#", 1)[0]


def _by(rec: dict) -> str | None:
    if rec.get("by"):
        return str(rec["by"])
    if rec.get("harness"):
        return f"agent:{rec['harness']}"
    return None


def stage_events(records: Iterable[dict]) -> list[Stage]:
    """Every record that marks a stage, as Stage, sorted by time."""
    out: list[Stage] = []
    for r in records:
        ev, ts = r.get("event"), r.get("ts")
        if not isinstance(ts, (int, float)):
            continue
        ts = float(ts)
        cid = _key(r["challenge_id"]) if r.get("challenge_id") not in (None, "") else None
        if ev in _stages.STAGES:
            detail = {k: v for k, v in r.items() if k not in ("ts", "event", "challenge_id", "by")}
            out.append(Stage(ts, ev, cid, _by(r), detail))
        elif ev == "agent_launch" and cid:
            out.append(Stage(ts, "agent_launch", cid, _by(r), {"mode": r.get("mode")}))
        elif ev == "engine.run" and cid:
            by = f"engine:{r.get('engine')}"
            secs = r.get("seconds") if isinstance(r.get("seconds"), (int, float)) else 0.0
            out.append(Stage(ts - max(0.0, float(secs)), "first_tool", cid, by, {"engine": r.get("engine")}))
            if r.get("status") in ENGINE_CANDIDATE_STATUSES:
                out.append(Stage(ts, "candidate", cid, by, {"status": r.get("status")}))
        elif ev == "platform.submit" and cid:
            status = r.get("status")
            by = f"submit:{r['provenance']}" if r.get("provenance") else None
            out.append(Stage(ts, "submit", cid, by, {"status": status}))
            if status in ACCEPTED_STATUSES:
                out.append(Stage(ts, "accepted", cid, by, {"status": status}))
            elif status == "incorrect":
                out.append(Stage(ts, "rejected", cid, by, {"status": status}))
    out.sort(key=lambda s: s.ts)
    return out


def waves(records: Iterable[dict], *, stages: list[Stage] | None = None) -> list[Wave]:
    st = stage_events(records) if stages is None else stages
    out = []
    for s in st:
        if s.stage == "wave_open":
            ann = s.detail.get("announced")
            ann = float(ann) if isinstance(ann, (int, float)) and not isinstance(ann, bool) else None
            out.append(Wave(str(s.detail.get("wave")), ann if ann is not None else s.ts, s.ts, ann,
                            s.detail.get("count")))
    return out


def assign(stages: list[Stage], wave_list: list[Wave]) -> dict[str, str]:
    """challenge id -> wave label."""
    labels = {w.label for w in wave_list}
    out: dict[str, str] = {}
    for s in stages:                            # an explicit detect wins
        if s.stage == "detect" and s.challenge_id and s.detail.get("wave") in labels:
            out.setdefault(s.challenge_id, str(s.detail["wave"]))
    if not wave_list:
        return {s.challenge_id: NO_WAVE for s in stages if s.challenge_id}
    for s in stages:                            # stages are in time order: the first one decides
        if not s.challenge_id or s.challenge_id in out:
            continue
        opened = [w for w in wave_list if w.start <= s.ts]
        if opened:
            out[s.challenge_id] = max(opened, key=lambda w: w.start).label
    return out


@dataclass
class Row:
    challenge_id: str
    cells: dict                     # column -> seconds after T0, or None
    hold: float | None              # accepted - first candidate (the flag in hand)
    closed_by: str | None


@dataclass
class Replay:
    wave: Wave
    pipeline: list                  # [(seconds after T0, step, seconds since the previous step)]
    rows: list[Row]
    medians: dict                   # column -> (median, n)
    notes: list[str]

    def to_dict(self) -> dict:
        return {"wave": asdict(self.wave), "pipeline": [list(p) for p in self.pipeline],
                "rows": [asdict(r) for r in self.rows], "medians": self.medians, "notes": self.notes}


def _first(stages: list[Stage], stage: str) -> Stage | None:
    return next((s for s in stages if s.stage == stage), None)


def _last(stages: list[Stage], stage: str) -> Stage | None:
    hits = [s for s in stages if s.stage == stage]
    return hits[-1] if hits else None


def _intake_ok(s: Stage) -> bool:
    """An intake_done that did not fail: a pull with ok False is not a finished intake."""
    return s.stage == "intake_done" and s.detail.get("ok") is not False


def closed_by(cs: list[Stage], spend_ts: list[float]) -> str | None:
    """Who closed one challenge, from its stages (time ordered) and the times of its spend records."""
    acc = _first(cs, "accepted")
    if acc is None:
        return None
    layer = acc.detail.get("layer")
    if layer:
        return str(layer)
    before = [s for s in cs if s.ts <= acc.ts]
    if any(s.stage == "agent_launch" or (s.by or "").startswith("agent:") for s in before) \
            or any(t <= acc.ts for t in spend_ts):
        return "agent"
    if any((s.by or "").startswith("engine:") for s in before):
        return "layer1"
    return "other"


def _spend_times(records: Iterable[dict]) -> dict[str, list[float]]:
    out: dict[str, list[float]] = {}
    for r in records:
        if r.get("event") == "spend" and r.get("challenge_id") not in (None, "") \
                and isinstance(r.get("ts"), (int, float)):
            out.setdefault(_key(r["challenge_id"]), []).append(float(r["ts"]))
    return out


def wave_replay(records: list[dict], wave: str | None = None, *, t0: float | None = None) -> Replay:
    """The replay of one wave (the label; None = the only or the latest wave). `t0` overrides T0."""
    st = stage_events(records)
    wl = waves(records, stages=st)
    notes: list[str] = []
    if not wl:
        if wave not in (None, NO_WAVE):
            raise KeyError(f"no wave {wave!r}: the ledger has no wave_open record")
        cstages = [s for s in st if s.challenge_id]
        if not cstages and t0 is None:
            raise KeyError("the ledger has no stage records to replay")
        w = Wave(NO_WAVE, t0 if t0 is not None else cstages[0].ts, None, synthetic=True)
        notes.append("no wave_open in the ledger: one wave, timed from "
                     + ("the given T0" if t0 is not None else "the first recorded stage"))
    else:
        if wave is None:
            w = wl[-1]
            if len(wl) > 1:
                notes.append(f"{len(wl)} waves in the ledger ({', '.join(x.label for x in wl)}); "
                             f"showing the latest, {w.label} (pick one with --wave)")
        else:
            hits = [x for x in wl if x.label == wave]
            if not hits:
                raise KeyError(f"no wave {wave!r}; waves in the ledger: {', '.join(x.label for x in wl)}")
            w = hits[0]
        if t0 is not None:
            w = Wave(w.label, t0, w.opened_ts, w.announced, w.count)
            notes.append("T0 given by the caller")
        elif w.announced is not None:
            notes.append("T0 is the announced start; 'wave detected' is when the board was seen open")
    member = assign(st, wl)
    cids = sorted({c for c, lab in member.items() if lab == w.label},
                  key=lambda c: (len(c), c))
    by_c: dict[str, list[Stage]] = {c: [] for c in cids}
    for s in st:
        if s.challenge_id in by_c:
            by_c[s.challenge_id].append(s)
    wstages = [s for s in st if s.challenge_id in by_c]
    spend_ts = _spend_times(records)

    # the pipeline: first / last occurrences across the wave
    steps: list[tuple[float, str]] = []
    if w.announced is not None or t0 is not None:
        steps.append((w.t0, "T0"))
    if w.opened_ts is not None:
        n = w.count if w.count is not None else len(cids)
        steps.append((w.opened_ts, f"wave {w.label} detected ({n} challenges listed)"))

    def first(stage, text):
        s = _first(wstages, stage)
        if s is not None:
            steps.append((s.ts, text(s)))

    def last(stage, text, minimum=2, keep=lambda s: True):
        hits = [s for s in wstages if s.stage == stage and keep(s)]
        if len(hits) >= minimum:
            steps.append((hits[-1].ts, text(hits)))

    first("claim", lambda s: f"first claim ({s.challenge_id})")
    first("intake_start", lambda s: f"first intake started ({s.challenge_id})")
    last("intake_done", lambda h: f"last intake done ({len({x.challenge_id for x in h})} of {len(cids)})",
         minimum=1, keep=_intake_ok)
    failed = sorted({s.challenge_id for s in wstages if s.stage == "intake_done" and not _intake_ok(s)}
                    - {s.challenge_id for s in wstages if _intake_ok(s)}, key=lambda c: (len(c), c))
    if failed:
        notes.append(f"intake failed and never succeeded for {len(failed)} challenge(s): {', '.join(failed)}"
                     " (not counted as done)")
    first("agent_launch", lambda s: f"first agent launched ({s.challenge_id})")
    last("agent_launch", lambda h: f"last agent launched ({len(h)} launches)")
    first("first_tool", lambda s: f"first tool call ({s.challenge_id}, {s.by or '?'})")
    first("candidate", lambda s: f"first candidate flag ({s.challenge_id}, {s.by or '?'})")
    first("submit", lambda s: f"first submit ({s.challenge_id})")
    first("accepted", lambda s: f"first accepted ({s.challenge_id})")
    acc_c = {c for c, cs in by_c.items() if _first(cs, "accepted")}
    if len(acc_c) > 1:
        last_acc = max(_first(by_c[c], "accepted").ts for c in acc_c)
        steps.append((last_acc, f"last first-accept ({len(acc_c)} of {len(cids)} solved)"))
    steps.sort(key=lambda x: x[0])
    pipeline, prev = [], None
    for ts, text in steps:
        pipeline.append((round(ts - w.t0, 3), text, None if prev is None else round(ts - prev, 3)))
        prev = ts

    rows = []
    for c in cids:
        cs = by_c[c]
        cells = {}
        for col, stage in COLUMNS:
            s = _first([x for x in cs if _intake_ok(x)] if stage == "intake_done" else cs, stage)
            cells[col] = None if s is None else round(s.ts - w.t0, 3)
        cand, acc = _first(cs, "candidate"), _first(cs, "accepted")
        hold = round(acc.ts - cand.ts, 3) if cand is not None and acc is not None and acc.ts >= cand.ts else None
        rows.append(Row(c, cells, hold, closed_by(cs, spend_ts.get(c, []))))
    medians = {}
    for col, _ in COLUMNS:
        vals = [r.cells[col] for r in rows if r.cells[col] is not None]
        medians[col] = (round(statistics.median(vals), 3), len(vals)) if vals else (None, 0)
    holds = [r.hold for r in rows if r.hold is not None]
    medians["hold"] = (round(statistics.median(holds), 3), len(holds)) if holds else (None, 0)
    return Replay(w, pipeline, rows, medians, notes)


# ------------------------------------------------------------------ rendering

def _utc(ts: float) -> str:
    return _dt.datetime.fromtimestamp(ts, _dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + "Z"


def _num(v) -> str:
    return "-" if v is None else f"{v:.1f}"


def render(r: Replay) -> str:
    w = r.wave
    lines = [f"Wave {w.label}, T0 = {_utc(w.t0)}" + (" (announced)" if w.announced is not None and w.t0 == w.announced else "")]
    lines += [f"note: {n}" for n in r.notes]
    lines += ["", f"{'T+ s':>9} | {'Seconds':>8} | Step", f"{'-' * 9}-+-{'-' * 8}-+-{'-' * 40}"]
    for tplus, text, delta in r.pipeline:
        lines.append(f"{tplus:>9.1f} | {_num(delta):>8} | {text}")
    if not r.pipeline:
        lines.append("(no pipeline stages recorded)")
    head = ["challenge"] + [c for c, _ in COLUMNS] + ["hold", "closed by"]
    lines += ["", "Per challenge, seconds after T0 (hold = accepted - first candidate):", ""]
    widths = [max(9, max((len(x.challenge_id) for x in r.rows), default=0))] + [8] * (len(COLUMNS) + 1) + [9]
    lines.append(" | ".join(h.rjust(wd) if i else h.ljust(wd) for i, (h, wd) in enumerate(zip(head, widths))))
    for row in r.rows:
        vals = [row.challenge_id] + [_num(row.cells[c]) for c, _ in COLUMNS] + [_num(row.hold), row.closed_by or "-"]
        lines.append(" | ".join(v.rjust(wd) if i else v.ljust(wd) for i, (v, wd) in enumerate(zip(vals, widths))))
    med = ["median"] + [_num(r.medians[c][0]) for c, _ in COLUMNS] + [_num(r.medians["hold"][0]), ""]
    cnt = ["n"] + [str(r.medians[c][1]) for c, _ in COLUMNS] + [str(r.medians["hold"][1]), ""]
    for vals in (med, cnt):
        lines.append(" | ".join(v.rjust(wd) if i else v.ljust(wd) for i, (v, wd) in enumerate(zip(vals, widths))))
    return "\n".join(lines)


# ------------------------------------------------------------------ the live summary

@dataclass
class Summary:
    by_category: dict               # category -> {"usd", "tok"}
    total_usd: float
    challenge_usd: float
    solved: list                    # challenge ids accepted
    usd_per_solve: float | None
    solve_usd_per_solve: float | None
    tail: list                      # hard-tail challenge ids with spend
    tail_usd: float
    tail_share: float | None        # of challenge spend
    top5_share: float | None        # of challenge spend
    after_team_solve_usd: float
    closed_by: dict                 # closer -> count
    layer1_rate: float | None       # layer-1 closes / solved
    engine_challenges: int          # challenges an engine ran on
    layer1_armed_rate: float | None  # layer-1 closes / challenges an engine ran on
    wave: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def summarize(records: list[dict], *, tail_of: Callable[[str], bool], wave: str | None = None) -> Summary:
    """Spend by category, dollars per solve, hard-tail share, layer-1 close rate. `tail_of(cid)` says
    whether a challenge is a hard tail (the budget meter's high-value-tail rule). With `wave`, only
    that wave's challenges, and the unattributed spend recorded while it was the latest wave."""
    st = stage_events(records)
    wl = waves(records, stages=st)
    member = assign(st, wl)
    keep_c: Callable[[str], bool] = lambda c: True       # noqa: E731
    keep_t: Callable[[float], bool] = lambda t: True     # noqa: E731
    if wave is not None:
        hits = [w for w in wl if w.label == wave]
        if not hits:
            raise KeyError(f"no wave {wave!r}; waves in the ledger: {', '.join(x.label for x in wl) or 'none'}")
        i = wl.index(hits[0])
        lo = hits[0].start
        hi = wl[i + 1].start if i + 1 < len(wl) else float("inf")
        keep_c = lambda c: member.get(c) == wave          # noqa: E731
        keep_t = lambda t: lo <= t < hi                   # noqa: E731

    team_solve: dict[str, float] = {}
    for r in records:
        if r.get("event") == "stop" and r.get("reason") == "team_solve" and r.get("challenge_id"):
            c = _key(r["challenge_id"])
            team_solve.setdefault(c, float(r.get("ts") or 0.0))

    by_cat: dict[str, dict] = {}
    per_c: dict[str, float] = {}
    after = 0.0
    for r in records:
        if r.get("event") != "spend":
            continue
        usd, tok = float(r.get("usd") or 0.0), int(r.get("tok") or 0)
        cid = _key(r["challenge_id"]) if r.get("challenge_id") not in (None, "") else None
        if cid is not None and not keep_c(cid):
            continue
        if cid is None and not keep_t(float(r.get("ts") or 0.0)):
            continue
        cat = r.get("category") or ("solve" if cid is not None else "uncategorized")
        b = by_cat.setdefault(str(cat), {"usd": 0.0, "tok": 0})
        b["usd"] += usd
        b["tok"] += tok
        if cid is not None:
            per_c[cid] = per_c.get(cid, 0.0) + usd
            if cid in team_solve and float(r.get("ts") or 0.0) > team_solve[cid]:
                after += usd
    total = sum(b["usd"] for b in by_cat.values())
    ch_usd = sum(per_c.values())

    by_c: dict[str, list[Stage]] = {}
    for s in st:
        if s.challenge_id and keep_c(s.challenge_id):
            by_c.setdefault(s.challenge_id, []).append(s)
    spend_ts = _spend_times(records)
    solved, closers = [], {}
    for c, cs in sorted(by_c.items()):
        who = closed_by(cs, spend_ts.get(c, []))
        if who is not None:
            solved.append(c)
            closers[who] = closers.get(who, 0) + 1
    engine_c = {c for c, cs in by_c.items() if any((s.by or "").startswith("engine:") for s in cs)}
    l1 = closers.get("layer1", 0)
    tail = sorted(c for c in per_c if tail_of(c))
    tail_usd = sum(per_c[c] for c in tail)
    top5 = sum(sorted(per_c.values(), reverse=True)[:5])
    solve_usd = by_cat.get("solve", {}).get("usd", 0.0)
    return Summary(
        by_category={k: {"usd": round(v["usd"], 6), "tok": v["tok"]} for k, v in sorted(by_cat.items())},
        total_usd=round(total, 6), challenge_usd=round(ch_usd, 6), solved=solved,
        usd_per_solve=round(total / len(solved), 6) if solved else None,
        solve_usd_per_solve=round(solve_usd / len(solved), 6) if solved else None,
        tail=tail, tail_usd=round(tail_usd, 6), tail_share=(tail_usd / ch_usd) if ch_usd else None,
        top5_share=(top5 / ch_usd) if ch_usd else None, after_team_solve_usd=round(after, 6),
        closed_by=dict(sorted(closers.items())), layer1_rate=(l1 / len(solved)) if solved else None,
        engine_challenges=len(engine_c), layer1_armed_rate=(l1 / len(engine_c)) if engine_c else None,
        wave=wave)


def _pct(x) -> str:
    return "-" if x is None else f"{100 * x:.1f}%"


def _usd(x) -> str:
    return "-" if x is None else f"${x:,.2f}"


def render_summary(s: Summary) -> str:
    lines = [f"Ledger summary{' for wave ' + s.wave if s.wave else ''}", "", "Spend by category:"]
    for cat, v in s.by_category.items():
        share = v["usd"] / s.total_usd if s.total_usd else None
        lines.append(f"  {cat:<14} {_usd(v['usd']):>12} {_pct(share):>7}  {v['tok']:>14,} tok")
    lines.append(f"  {'total':<14} {_usd(s.total_usd):>12}")
    n = len(s.solved)
    lines += ["",
              f"Solved: {n}   dollars/solve: {_usd(s.usd_per_solve)} (all spend), "
              f"{_usd(s.solve_usd_per_solve)} (solve spend)",
              f"Hard-tail share: {_pct(s.tail_share)} of challenge spend ({_usd(s.tail_usd)} on "
              f"{len(s.tail)} tail challenge(s){': ' + ', '.join(s.tail) if s.tail else ''})",
              f"Top-5 challenges: {_pct(s.top5_share)} of challenge spend",
              f"Spent after a team solve: {_usd(s.after_team_solve_usd)}",
              f"Layer-1 close rate: {_pct(s.layer1_rate)} of solves "
              f"({s.closed_by.get('layer1', 0)} of {n}); engines ran on {s.engine_challenges} challenge(s), "
              f"closed {_pct(s.layer1_armed_rate)} of them",
              "Closed by: " + (", ".join(f"{k} {v}" for k, v in s.closed_by.items()) or "-")]
    return "\n".join(lines)
