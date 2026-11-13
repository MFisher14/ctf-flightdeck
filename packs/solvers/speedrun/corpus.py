#!/usr/bin/env python3
"""Speed-regression gate: replay saved, already-solved cases against a solver and time them.

Generalized from Huntress speedrun/corpus.py (SPEC.md section 5.3), whose replay of saved Game
Master attempts with median and maximum timing is kept as one case source. The gate itself is
platform-neutral: a Case is a call (args) plus the answer the judge accepted (expected), and a lane
may carry a time budget. No request is sent and nothing is written.

    Case(name, lane, args, expected)       expected: {answer id: accepted wire string}
    run_gate(cases, solver, budgets_ms)    -> Report (rows, per-lane median/max, ok)
    gm_cases(lane, root)                   saved Game Master attempts (attempt.json + key.json)
    workspace_cases(root)                  solved CTFd workspace folders (challenge.json + flag.txt)

A case fails the gate when the solver returns a value it says it READ that the accepted key
disagrees with (WRONG), when it crashes or leaves an id unanswered (MISSING), or when its best time
is over its lane's budget (SLOW). A value the solver marks as guessed (a `guessed` set on its
result) that misses is GUESS-MISS: reported, and also a gate failure, since a first solve never
guesses. No case at all is a loud failure, never a silent pass.

    python -I speedrun/corpus.py replay <lane> [--day N] [--mode time_trial|mastery|base]
                                               [--speed] [--repeat K] [--json] [--verbose]
                                               [--budget-ms MS]
    python -I speedrun/corpus.py gate --workspace DIR --solver pkg.module:function
                                      [--budget LANE=MS ...] [--default-budget-ms MS]
                                      [--repeat K] [--json]

Exit 0 when every case passes, 1 on any gate failure, 2 on a usage problem (no solver, no cases).
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import argparse
import hashlib
import importlib
import json
import statistics
import time
from dataclasses import dataclass, field
from typing import Callable, Iterable, Iterator

from speedrun.common import (LANES, Delivery, _key_answers, attempt_folders, compact, data_root, lane_name,
                             questions, speed_variants_root)

MODES = ("time_trial", "mastery")
MODULES = {lane: f"speedrun.solvers.{lane}" for lane in LANES}
FLAG_ID = "flag"     # the one answer id of a workspace (CTFd) case


class GateError(RuntimeError):
    """A usage problem the gate refuses to paper over (no solver, no cases, a bad budget)."""


@dataclass
class Case:
    name: str                 # shown in every row (a path relative to the root, or a challenge folder)
    lane: str                 # the budget key
    args: tuple               # what the solver is called with
    expected: dict            # {answer id: accepted wire string}
    normalization: dict = field(default_factory=dict)   # {answer id: "exact"|"case_insensitive"|...}
    sets: int = 1             # parts of the case (Mastery sets), for the per-set time
    dir: Path | None = None

    def __repr__(self):
        return f"Case({self.lane} {self.name})"


@dataclass
class Diff:
    exact: bool
    wrong_read: list
    wrong_guess: list
    missing: list
    extra: list
    seconds: float
    answers: dict = field(default_factory=dict, repr=False)


@dataclass
class Row:
    word: str                 # OK | WRONG | MISSING | GUESS-MISS | SLOW
    name: str
    lane: str
    ms: float
    sets: int
    budget_ms: float | None
    diff: Diff
    error: str | None = None
    ids: int = 0              # answer ids the key holds

    @property
    def ok(self) -> bool:
        return self.word == "OK"

    def as_dict(self) -> dict:
        return {"word": self.word, "dir": self.name, "lane": self.lane, "ms": round(self.ms, 2),
                "sets": self.sets, "ms_per_set": round(self.ms / max(1, self.sets), 3),
                "budget_ms": self.budget_ms, "ids": self.ids,
                "wrong_read": self.diff.wrong_read, "wrong_guess": self.diff.wrong_guess,
                "missing": self.diff.missing, "extra": self.diff.extra, "error": self.error}


@dataclass
class Report:
    rows: list
    prepare_s: float = 0.0
    skipped: list = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return bool(self.rows) and all(r.ok for r in self.rows)

    def lanes(self) -> dict:
        """{lane: {cases, ok, median_ms, max_ms, budget_ms, over_budget, median_ms_per_set}}."""
        out = {}
        for lane in dict.fromkeys(r.lane for r in self.rows):
            rows = [r for r in self.rows if r.lane == lane]
            ms = [r.ms for r in rows]
            out[lane] = {"cases": len(rows), "ok": sum(r.ok for r in rows),
                         "wrong_read": sum(r.word == "WRONG" for r in rows),
                         "guess_miss": sum(r.word == "GUESS-MISS" for r in rows),
                         "missing": sum(r.word == "MISSING" for r in rows),
                         "over_budget": sum(r.word == "SLOW" for r in rows),
                         "median_ms": round(statistics.median(ms), 2), "max_ms": round(max(ms), 2),
                         "median_ms_per_set": round(statistics.median(r.ms / max(1, r.sets) for r in rows), 3),
                         "budget_ms": rows[0].budget_ms}
        return out

    def summary(self) -> dict:
        return {"cases": len(self.rows), "ok": sum(r.ok for r in self.rows), "pass": self.ok,
                "prepare_s": round(self.prepare_s, 3), "lanes": self.lanes(),
                "skipped": [(str(d), w) for d, w in self.skipped]}


# ---- comparing ---------------------------------------------------------------------------------------

def _same(value: str, want: str, norm) -> bool:
    if value == want:
        return True
    if norm == "exact":
        return False
    if norm == "case_insensitive":
        return value.strip().casefold() == want.strip().casefold()
    return value.strip() == want.strip()


def compare(answers, case: Case, seconds: float = 0.0) -> Diff:
    """The solver's answers against the accepted key. `answers` is a dict (a `guessed` attribute,
    when present, names the ids the solver did not read from the bytes)."""
    if answers is None:
        answers = {}
    guessed = getattr(answers, "guessed", set()) or set()
    wrong_read, wrong_guess, missing, extra = [], [], [], []
    for aid, want in case.expected.items():
        if aid not in answers or answers[aid] is None:
            missing.append(aid)
            continue
        v = compact(answers[aid])
        if not _same(v, want, case.normalization.get(aid)):
            (wrong_guess if aid in guessed else wrong_read).append((aid, v, want))
    for aid in answers:
        if aid not in case.expected:
            extra.append(aid)
    exact = not (wrong_read or wrong_guess or missing)
    return Diff(exact, wrong_read, wrong_guess, missing, extra, seconds, dict(answers))


def _as_answers(result, case: Case):
    """A solver of a one-answer case (a workspace flag) may return the bare string."""
    if isinstance(result, str) and len(case.expected) == 1:
        return {next(iter(case.expected)): result}
    return result


def replay(solver: Callable, case: Case, repeat: int = 1) -> Diff:
    """The best of `repeat` timed calls (the first pays for cold caches) and the last answers."""
    best, answers = None, None
    for _ in range(max(1, repeat)):
        t = time.perf_counter()
        answers = solver(*case.args)
        dt = time.perf_counter() - t
        best = dt if best is None else min(best, dt)
    return compare(_as_answers(answers, case), case, best)


def judge(diff: Diff, budget_ms: float | None, err: str | None = None) -> str:
    if diff.wrong_read:
        return "WRONG"
    if diff.missing or err:
        return "MISSING"
    if diff.wrong_guess:
        return "GUESS-MISS"
    if budget_ms is not None and diff.seconds * 1000 > budget_ms:
        return "SLOW"
    return "OK"


def run_gate(cases: Iterable[Case], solver: Callable, budgets_ms: dict | None = None,
             default_budget_ms: float | None = None, repeat: int = 1, skipped: list | None = None,
             prepare_s: float = 0.0) -> Report:
    """Replay every case. budgets_ms: {lane: ms}; a lane without one uses default_budget_ms (None:
    no time limit for that lane). Raises GateError when there is no case to run."""
    budgets_ms = dict(budgets_ms or {})
    for lane, ms in budgets_ms.items():
        if not isinstance(ms, (int, float)) or isinstance(ms, bool) or ms <= 0:
            raise GateError(f"budget for lane {lane!r} must be a positive number of ms, not {ms!r}")
    rows = []
    for case in cases:
        budget = budgets_ms.get(case.lane, default_budget_ms)
        try:
            diff = replay(solver, case, repeat)
            err = None
        except Exception as e:  # a crash is a miss of every id, and is shown
            diff = Diff(False, [], [], list(case.expected), [], 0.0)
            err = f"{type(e).__name__}: {e}"
        rows.append(Row(judge(diff, budget, err), case.name, case.lane, diff.seconds * 1000, case.sets,
                        budget, diff, err, len(case.expected)))
    if not rows:
        why = "; ".join(f"{d}: {w}" for d, w in (skipped or [])[:5])
        raise GateError("no saved case to replay" + (f" (skipped: {why})" if why else ""))
    return Report(rows, prepare_s, list(skipped or []))


# ---- case source: saved Game Master attempts (the Huntress speed runner's layout) --------------------

def _normalize(attempt: dict) -> dict:
    """artifacts[] for every shape (a live Single Solve / Time Trial body has only top-level download)."""
    if not attempt.get("artifacts") and (attempt.get("sha256") or attempt.get("download")):
        attempt = dict(attempt)
        attempt["artifacts"] = [{"filename": None, "sha256": attempt.get("sha256"),
                                 "download": attempt.get("download")}]
    return attempt


_HASH_CACHE: dict = {}


def _sha_files(folder: Path) -> dict:
    """{sha256: path} of every file in artifact/ and artifact/delivery-NN/ (other folders ignored)."""
    out = {}
    if not folder.is_dir():
        return out
    cands = [p for p in folder.iterdir() if p.is_file()]
    for sub in folder.iterdir():
        if sub.is_dir() and sub.name.startswith("delivery-"):
            cands += [p for p in sub.iterdir() if p.is_file()]
    for p in sorted(cands):
        st = p.stat()
        ck = (str(p), st.st_size, st.st_mtime_ns)
        h = _HASH_CACHE.get(ck)
        if h is None:
            h = hashlib.sha256(p.read_bytes()).hexdigest()
            _HASH_CACHE[ck] = h
        out.setdefault(h, p)
    return out


def load_gm_case(d: Path, base: str, mode: str, lane: str, root: Path | None = None) -> tuple:
    """(Case, None) or (None, reason). The case calls solve(attempt, deliveries, ctx)."""
    try:
        attempt = _normalize(json.loads((d / "attempt.json").read_text()))
    except (OSError, ValueError) as e:
        return None, f"no attempt.json ({type(e).__name__})"
    if not attempt.get("questions"):
        return None, "attempt.json has no questions"
    got = _key_answers(d, attempt.get("attempt_id"))
    if not got:
        return None, "no key"
    key, _key_file = got
    arts = attempt.get("artifacts") or []
    files = _sha_files(d / "artifact")
    dels = []
    for i, a in enumerate(arts):
        want = (a.get("sha256") or "").lower()
        p = files.get(want) if want else None
        if p is None and not want and len(arts) == 1 and len(files) == 1:
            p = next(iter(files.values()))
        if p is None:
            return None, f"delivery {i + 1} of {len(arts)} is not saved"
        dels.append(Delivery(i, a.get("filename") or p.name, p.read_bytes()))
    if not dels:
        return None, "no deliveries"
    day = int(base.split("-day-")[1][:2]) if "-day-" in base else 0
    cid = base if mode == "base" else f"{base}/{mode}"
    qs = questions(attempt)
    ctx = {"challenge": cid, "base": base, "day": day, "mode": mode}
    name = str(d)
    if root is not None:
        try:
            name = str(d.relative_to(root))
        except ValueError:
            pass
    return Case(name, lane, (attempt, dels, ctx), key,
                {q["answer_id"]: q["normalization"] for q in qs},
                len({q["set"] for q in qs}) or 1, d), None


def gm_cases(lane: str | None = None, root: Path | None = None, day: int | None = None, modes=MODES,
             skipped: list | None = None, speed: bool = False) -> Iterator[Case]:
    """Every saved attempt with a key: the current variant plus every history/<id>/. A case whose
    bytes are missing is skipped; with `skipped` a list, (dir, reason) is appended to it."""
    root = Path(root) if root else data_root()
    lanes = [lane_name(lane)] if lane else list(LANES)
    if isinstance(modes, str):
        modes = (modes,)
    roots = [root] + ([speed_variants_root()] if speed and speed_variants_root().is_dir() else [])
    for ln in lanes:
        prefix = LANES[ln][0]
        for r in roots:
            for base, mode, d in attempt_folders(r, prefix):
                if mode not in modes:
                    continue
                if day is not None and f"-day-{day:02d}" not in base:
                    continue
                if not (d / "attempt.json").is_file():
                    continue
                case, why = load_gm_case(d, base, mode, ln, root)
                if case is None:
                    if skipped is not None:
                        skipped.append((d, why))
                    continue
                yield case


# ---- case source: solved CTFd workspace folders (ctf/workspace.py's layout) ---------------------------

def workspace_cases(root: Path, skipped: list | None = None, lane_key: str = "category") -> Iterator[Case]:
    """Every <root>/<id>-<slug>/ with challenge.json and a confirmed flag.txt. The case calls
    solve(challenge_dir) and expects {"flag": <flag.txt>} (a bare string return is that flag). The
    lane is the challenge's category (lower-cased), the key for its time budget."""
    root = Path(root)
    if not root.is_dir():
        raise GateError(f"workspace root {root} is not a folder")
    for d in sorted(p for p in root.iterdir() if p.is_dir()):
        detail_p, flag_p = d / "challenge.json", d / "flag.txt"
        if not detail_p.is_file():
            continue
        if not flag_p.is_file():
            if skipped is not None:
                skipped.append((d, "not solved (no flag.txt)"))
            continue
        try:
            detail = json.loads(detail_p.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            if skipped is not None:
                skipped.append((d, f"challenge.json unreadable ({type(e).__name__})"))
            continue
        flag = flag_p.read_text(encoding="utf-8").strip()
        if not flag:
            if skipped is not None:
                skipped.append((d, "flag.txt is empty"))
            continue
        lane = str((detail.get(lane_key) if isinstance(detail, dict) else None) or "uncategorized").strip().lower()
        yield Case(d.name, lane, (d,), {FLAG_ID: flag}, {FLAG_ID: "exact"}, 1, d)


# ---- solvers ----------------------------------------------------------------------------------------

def load_module(lane: str):
    return importlib.import_module(MODULES[lane_name(lane)])


def load_solver(spec: str) -> Callable:
    """'pkg.module:function' -> the callable. GateError (with the reason) when it cannot be loaded."""
    mod_name, _, attr = spec.partition(":")
    if not mod_name or not attr:
        raise GateError(f"--solver must be pkg.module:function, not {spec!r}")
    try:
        fn = getattr(importlib.import_module(mod_name), attr)
    except Exception as e:
        raise GateError(f"solver {spec} did not load: {type(e).__name__}: {e}") from e
    if not callable(fn):
        raise GateError(f"solver {spec} is not callable")
    return fn


def parse_budgets(items) -> dict:
    out = {}
    for item in items or []:
        lane, sep, ms = str(item).partition("=")
        try:
            val = float(ms)
        except ValueError:
            val = None
        if not sep or not lane.strip() or val is None or val <= 0:
            raise GateError(f"--budget must be LANE=MS with MS > 0, not {item!r}")
        out[lane.strip().lower()] = val
    return out


# ---- printing ---------------------------------------------------------------------------------------

def _print(report: Report, as_json: bool, verbose: bool = False, label: str = "") -> None:
    if as_json:
        print(json.dumps({"summary": report.summary(), "cases": [r.as_dict() for r in report.rows]},
                         ensure_ascii=False, default=str))
        return
    for r in report.rows:
        extra = f" sets={r.sets} per_set={r.ms / r.sets:.3f}" if r.sets > 1 else ""
        budget = f" budget={r.budget_ms:g}" if r.word == "SLOW" else ""
        print(f"{r.word} {r.name} {r.ms:.2f}{extra}{budget}" + (f" {r.error}" if r.error else ""))
        if verbose or r.word not in ("OK", "SLOW"):
            for aid, v, w in (r.diff.wrong_read + r.diff.wrong_guess)[:8]:
                kind = "read " if (aid, v, w) in r.diff.wrong_read else "guess"
                print(f"   {kind} {aid}: {v[:80]!r} != {w[:80]!r}")
            if r.diff.missing:
                print(f"   missing {len(r.diff.missing)}: {', '.join(r.diff.missing[:6])}")
    for d, w in report.skipped:
        print(f"SKIP {d}: {w}")
    for lane, s in report.lanes().items():
        print(f"SUMMARY {label or lane} cases={s['cases']} ok={s['ok']} wrong_read={s['wrong_read']} "
              f"guess_miss={s['guess_miss']} missing={s['missing']} over_budget={s['over_budget']} "
              f"median_ms={s['median_ms']} max_ms={s['max_ms']} median_ms_per_set={s['median_ms_per_set']} "
              f"budget_ms={s['budget_ms']} prepare_s={round(report.prepare_s, 3)}")
    print("GATE " + ("PASS" if report.ok else "FAIL"))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="corpus.py")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("replay", help="saved Game Master attempts against speedrun.solvers.<lane>")
    r.add_argument("lane")
    r.add_argument("--day", type=int)
    r.add_argument("--mode", choices=("time_trial", "mastery", "base"))
    r.add_argument("--json", action="store_true")
    r.add_argument("--speed", action="store_true")
    r.add_argument("--repeat", type=int, default=1)
    r.add_argument("--budget-ms", type=float)
    r.add_argument("--verbose", "-v", action="store_true")
    g = sub.add_parser("gate", help="solved CTFd workspace folders against one solver")
    g.add_argument("--workspace", required=True)
    g.add_argument("--solver", required=True)
    g.add_argument("--budget", action="append", default=[])
    g.add_argument("--default-budget-ms", type=float)
    g.add_argument("--repeat", type=int, default=1)
    g.add_argument("--json", action="store_true")
    g.add_argument("--verbose", "-v", action="store_true")
    a = ap.parse_args(argv)
    skipped: list = []
    try:
        if a.cmd == "replay":
            lane = lane_name(a.lane)
            try:
                mod = load_module(lane)
            except Exception as e:
                print(f"NO SOLVER {MODULES[lane]}: {type(e).__name__}: {e}")
                return 2
            t = time.perf_counter()
            if hasattr(mod, "prepare"):
                mod.prepare(data_root())
            prep = time.perf_counter() - t
            modes = (a.mode,) if a.mode else MODES
            cases = gm_cases(lane, None, a.day, modes, skipped=skipped, speed=a.speed)
            budgets = {lane: a.budget_ms} if a.budget_ms else {}
            report = run_gate(cases, mod.solve, budgets, None, a.repeat, skipped, prep)
            _print(report, a.json, a.verbose, lane)
        else:
            solver = load_solver(a.solver)
            budgets = parse_budgets(a.budget)
            cases = list(workspace_cases(Path(a.workspace), skipped))
            report = run_gate(cases, solver, budgets, a.default_budget_ms, a.repeat, skipped)
            _print(report, a.json, a.verbose)
    except (GateError, ValueError) as e:
        print(f"GATE ERROR: {e}")
        return 2
    return 0 if report.ok else 1


if __name__ == "__main__":
    sys.exit(main())
