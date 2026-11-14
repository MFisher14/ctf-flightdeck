"""The look-ahead completeness gate (B-174): run a lane's reader over the forecast matrix and fail on
every kind of missing coverage, not only on wrong answers.

    reports = gate(matrix_dir, lanes=None, root=None, workdir=None, guard="auto", timeout=None,
                   record_to_ledger=True)
    runs = run_lane(m, lane, root=None, guard="auto", timeout=None, workdir=None)  # {name: SpecimenRun}
    rep = evaluate(m, lane, runs, seconds=0.0)                                    # LaneReport
    rep.ok; rep.gaps; rep.counts(); rep.lines(); rep.to_json()

Running. The lane's `solve_set` reader runs over every specimen that is not declared `skip`, in ONE
child process (ctf/lookahead/_child.py) under the intake network guard (ctf.intake.guard, `auto`: the
OS sandbox when it works, else the audit hook) with no secret-named variable, no ledger and a fresh
workdir (`openers.engine_env`), each specimen under the lane's per-specimen cap (SIGALRM), the whole
child under cap x specimens + CHILD_SLACK seconds. A specimen the child never reported (it died, or
was killed) is `crashed`; one it did not reach is `skipped`.

Classification of each asked id of a specimen that ran (key.json, when present, is the judge):
    correct     the answer equals the key (scalars compared as stripped text, lists and objects as JSON)
    answered    an answer and no key for the id
    wrong       differs from the key; the literal `none` where the format does not allow it
                (ctf.idresolve.permits_literal_none); an unsure answer (`??` + JSON options) none of
                whose options is the key, or that cannot be read
    unsure      an unsure answer (one option is the key, or there is no key)
    unanswered  None, missing or blank
    skipped     the specimen did not run (declared skip, crashed, cut)

Gaps (each one fails the lane; the gate is green only with none):
    wrong               a wrong answer
    unanswered          a deterministic id left unanswered (judged ids are reported, not gaps); the
                        computed tier's value is shown when it has one (ctf.lookahead.computed)
    unsure              a deterministic id answered unsure: an unsure answer is never sent
                        (gamemaster.is_unsure), so at release the fact is not answered. Judged ids are
                        reported, not gaps; a lane with `allow_unsure = true` reports them too
    skipped             a specimen declared skip, not reached, or left out by the generator
                        ([[skipped]] in matrix.toml)
    crashed / cut       the reader raised, returned a non-dict, died, or ran past its cap
    bad_encoding        a member's bytes do not carry the chain its specimen claims
    uncovered           an id of the lane's newest base that no specimen which ran asks
    threshold           a declared size threshold no specimen that ran reaches, or none stays under
    unexercised_encoding  a real delivery encoding (real_encodings) no specimen that ran uses
    empty               the lane has no specimen that ran

One `lookahead.gate` ledger record per lane (docs/CONTRACTS.md section 10).
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from .. import idresolve as _idresolve
from .. import ledger as _ledger
from .. import paths as _paths
from ..intake import guard as _guard
from . import LookaheadError
from . import computed as _computed
from . import matrix as _matrix

GREEN = "green"
RED = "red"
CHILD_SLACK = 30.0

RAN, CRASHED, CUT, SKIPPED = "ran", "crashed", "cut", "skipped"
CORRECT, ANSWERED, WRONG, UNSURE, UNANSWERED = "correct", "answered", "wrong", "unsure", "unanswered"
GAP_KINDS = ("wrong", "unanswered", "unsure", "skipped", "crashed", "cut", "bad_encoding", "uncovered",
             "threshold", "unexercised_encoding", "empty")


@dataclass(frozen=True)
class SpecimenRun:
    name: str
    status: str                    # ran | crashed | cut | skipped
    reason: str = ""
    answers: dict = field(default_factory=dict)
    seconds: float = 0.0


@dataclass(frozen=True)
class Gap:
    kind: str
    lane: str
    specimen: str = ""
    qid: str = ""
    detail: str = ""

    def line(self) -> str:
        where = "/".join(x for x in (self.specimen, self.qid) if x)
        return f"GAP {self.kind:<20} {self.lane}{(' ' + where) if where else ''}: {self.detail}"


@dataclass(frozen=True)
class Row:
    specimen: str
    qid: str
    determinism: str
    status: str
    answer: object = None
    expected: object = None
    computed: object = None


@dataclass(frozen=True)
class LaneReport:
    lane: str
    gaps: tuple
    rows: tuple
    runs: tuple
    seconds: float = 0.0

    @property
    def ok(self) -> bool:
        return not self.gaps

    @property
    def verdict(self) -> str:
        return GREEN if self.ok else RED

    def counts(self) -> dict:
        det = [r for r in self.rows if r.determinism == _matrix.DETERMINISTIC]
        st = [r.status for r in self.rows]
        return {
            "specimens": len(self.runs),
            "ran": sum(1 for r in self.runs if r.status == RAN),
            "questions": len(self.rows),
            "deterministic": len(det),
            "answered": st.count(CORRECT) + st.count(ANSWERED),
            "correct": st.count(CORRECT),
            "wrong": st.count(WRONG),
            "unsure": st.count(UNSURE),
            "unanswered": sum(1 for r in det if r.status == UNANSWERED),
            "unanswered_judged": sum(1 for r in self.rows
                                     if r.status == UNANSWERED and r.determinism == _matrix.JUDGED),
            "skipped": st.count(SKIPPED),
            "computed_ready": sum(1 for r in det if r.status == UNANSWERED and r.computed is not None),
            "gaps": len(self.gaps),
        }

    def headline(self) -> str:
        c = self.counts()
        return (f"LOOKAHEAD {self.lane}: {self.verdict.upper()}  {c['gaps']} gap(s); "
                f"{c['specimens']} specimen(s), ran {c['ran']}; {c['questions']} id(s): "
                f"{c['unanswered']} unanswered deterministic, {c['wrong']} wrong, {c['skipped']} skipped, "
                f"{c['answered']} answered ({c['correct']} against a key), {c['unsure']} unsure, "
                f"{c['unanswered_judged']} judged open")

    def lines(self, limit: int = 200) -> list[str]:
        out = [self.headline()]
        out += [g.line() for g in self.gaps[:limit]]
        if len(self.gaps) > limit:
            out.append(f"... {len(self.gaps) - limit} more gap(s) (use --json)")
        return out

    def to_json(self) -> dict:
        return {"lane": self.lane, "verdict": self.verdict, "counts": self.counts(), "seconds": self.seconds,
                "gaps": [g.__dict__ for g in self.gaps],
                "runs": [{"name": r.name, "status": r.status, "reason": r.reason, "seconds": r.seconds}
                         for r in self.runs],
                "rows": [{"specimen": r.specimen, "qid": r.qid, "determinism": r.determinism, "status": r.status,
                          "answer": r.answer, "expected": r.expected, "computed": r.computed} for r in self.rows]}


# ----------------------------------------------------------------------------------------- running


def _kill_group(proc: subprocess.Popen) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        proc.kill()


def child_command(root: Path, g: _guard.Guard, job: Path, out: Path) -> list[str]:
    from ..engines import runner as _runner
    boot = _runner.boot_script(root)
    cmd = [sys.executable, "-I", str(boot), "--repo", str(root), "--via", "lookahead", "--no-ledger",
           "-m", "ctf.lookahead._child", str(job), str(out)]
    return _guard.wrap(g, cmd, root)


def run_lane(m: _matrix.Matrix, lane: str, *, root: Path | None = None, guard="auto",
             timeout: float | None = None, workdir: Path | None = None) -> dict:
    """{specimen name: SpecimenRun} for every specimen of `lane`. `guard` is a mode or a Guard."""
    if lane not in m.lanes:
        raise LookaheadError(f"lane {lane!r} is not in {m.path / _matrix.MATRIX_FILE}")
    cfg = m.lanes[lane]
    root = Path(root) if root is not None else _paths.repo_root()
    reader = cfg.reader_path(root)
    if not reader.is_file():
        raise LookaheadError(f"lane {lane}: reader {cfg.reader!r} is not a file under {root}")
    cap = float(timeout if timeout is not None else cfg.timeout)
    runs = {}
    todo = []
    for s in m.specimens[lane]:
        if s.skip:
            runs[s.name] = SpecimenRun(s.name, SKIPPED, f"declared skip: {s.skip}")
        else:
            todo.append(s)
    if not todo:
        return runs
    g = guard if isinstance(guard, _guard.Guard) else _guard.resolve(guard)
    from ..openers import engine_env
    base_dir = Path(workdir) if workdir is not None else None
    if base_dir is not None:
        base_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="lookahead-", dir=base_dir) as td:
        t = Path(td)
        job, out, work, cwd = t / "job.json", t / "out.jsonl", t / "work", t / "run"
        work.mkdir()
        cwd.mkdir()
        job.write_text(json.dumps({"reader": str(reader.resolve()), "timeout": cap,
                                   "specimens": [{"name": s.name, "dir": str(s.path.resolve()), "ctx": s.ctx}
                                                 for s in todo]}), encoding="utf-8")
        out.touch()
        proc = subprocess.Popen(child_command(root, g, job, out), cwd=str(cwd), env=engine_env(work),
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, encoding="utf-8", errors="replace", start_new_session=True)
        wall = cap * len(todo) + CHILD_SLACK
        try:
            _, err = proc.communicate(timeout=wall)
            code = proc.returncode
        except subprocess.TimeoutExpired:
            _kill_group(proc)
            _, err = proc.communicate()
            code = None
        recs = []
        for line in out.read_text(encoding="utf-8").splitlines():
            try:
                recs.append(json.loads(line))
            except ValueError:
                break                                   # a torn last line: the child died writing it
    load = [r for r in recs if r.get("status") == "load_error"]
    if load:
        raise LookaheadError(f"lane {lane}: reader {cfg.reader} does not load: {load[0].get('reason')}")
    got = {r["name"]: r for r in recs if isinstance(r, dict) and "name" in r}
    tail = (err or "").strip().splitlines()
    why = ("killed at the whole-run cap of %gs" % wall) if code is None else f"reader process exited {code}"
    if tail:
        why += f" ({tail[-1][:200]})"
    first_missing = True
    for s in todo:
        r = got.get(s.name)
        if r is None:
            if first_missing:
                runs[s.name] = SpecimenRun(s.name, CRASHED, f"no result: {why}")
                first_missing = False
            else:
                runs[s.name] = SpecimenRun(s.name, SKIPPED, f"not reached: {why}")
            continue
        status = r.get("status")
        if status not in (RAN, CRASHED, CUT):
            raise LookaheadError(f"lane {lane}: child wrote status {status!r} for {s.name}")
        answers = r.get("answers") if isinstance(r.get("answers"), dict) else {}
        runs[s.name] = SpecimenRun(s.name, status, str(r.get("reason") or ""), answers,
                                   float(r.get("seconds") or 0.0))
    return runs


# -------------------------------------------------------------------------------------- evaluating


def _canon(v) -> str:
    if isinstance(v, (list, dict)):
        return json.dumps(v, sort_keys=True, separators=(",", ":"))
    return str(v).strip()


def _unsure_options(answer: str):
    """The option values of an unsure answer ("??" + JSON), or None when it cannot be read."""
    try:
        body = json.loads(answer[2:])
    except ValueError:
        return None
    # the labels encoding the solvers write is the compact {"k": key, "o": [[name, value], ...]} (labels.pick); the
    # long field names are read too (B-249: a mobile Hermes reading, `??{"k":...,"o":...}`, read as WRONG before)
    opts = (body.get("options", body.get("o")) if isinstance(body, dict) else body)
    if not isinstance(opts, list):
        return None
    vals = []
    for o in opts:
        if isinstance(o, (list, tuple)) and len(o) == 2:
            vals.append(o[1])
        elif isinstance(o, dict) and "value" in o:
            vals.append(o["value"])
        else:
            vals.append(o)
    return vals


def classify(question: dict, answer, key: dict | None) -> tuple[str, str]:
    """(status, why) for one asked id; why is '' unless the status needs one."""
    qid = _matrix.qid_of(question)
    has_key = key is not None and qid in key
    expected = key.get(qid) if has_key else None
    if answer is None or (isinstance(answer, str) and not answer.strip()):
        return UNANSWERED, ""
    if isinstance(answer, str) and answer.startswith("??"):
        opts = _unsure_options(answer)
        if opts is None:
            return WRONG, "an unsure answer that cannot be read"
        if has_key and _canon(expected) not in {_canon(o) for o in opts}:
            return WRONG, f"unsure, and no option is the key {_canon(expected)!r}"
        return UNSURE, ""
    if (isinstance(answer, str) and answer.strip().lower() == "none"
            and not _idresolve.permits_literal_none(question)
            and not (has_key and _canon(expected).lower() == "none")):
        return WRONG, "the literal none, which this answer format does not allow"
    if has_key:
        if _canon(answer) == _canon(expected):
            return CORRECT, ""
        return WRONG, f"answered {_canon(answer)[:80]!r}, the key is {_canon(expected)[:80]!r}"
    return ANSWERED, ""


def evaluate(m: _matrix.Matrix, lane: str, runs: dict, seconds: float = 0.0) -> LaneReport:
    cfg = m.lanes[lane]
    gaps: list[Gap] = []
    rows: list[Row] = []
    ran: list[_matrix.Specimen] = []
    for s in m.specimens[lane]:
        run = runs.get(s.name)
        if run is None:
            raise LookaheadError(f"lane {lane}: no run result for specimen {s.name}")
        for member, why in ([] if s.skip else _matrix.bad_encodings(s)):
            gaps.append(Gap("bad_encoding", lane, s.name, "", f"member {member}: {why}"))
        if run.status != RAN:
            kind = run.status if run.status in (CRASHED, CUT) else "skipped"
            gaps.append(Gap(kind, lane, s.name, "", f"{run.reason}; {len(s.questions)} id(s) not exercised"))
            rows += [Row(s.name, _matrix.qid_of(q), _matrix.determinism(q, cfg.judged), SKIPPED)
                     for q in s.questions]
            continue
        ran.append(s)
        files = None
        for q in s.questions:
            qid = _matrix.qid_of(q)
            det = _matrix.determinism(q, cfg.judged)
            ans = run.answers.get(qid)
            status, why = classify(q, ans, s.key)
            exp = s.key.get(qid) if s.key else None
            comp = None
            if status == UNANSWERED and det == _matrix.DETERMINISTIC:
                if files is None:
                    files = s.read_files()
                comp = _computed.answer(q, files)
                detail = "deterministic and unanswered"
                if comp is not None:
                    detail += (f"; the computed tier has {_canon(comp)[:80]!r}: wire "
                               "ctf.lookahead.computed.wrap into the lane reader")
                    if s.key and qid in s.key and _canon(comp) != _canon(s.key[qid]):
                        detail += f" (it disagrees with the key {_canon(s.key[qid])[:80]!r}: fix the tier)"
                gaps.append(Gap("unanswered", lane, s.name, qid, detail))
            elif status == WRONG:
                gaps.append(Gap("wrong", lane, s.name, qid, why))
            elif status == UNSURE and det == _matrix.DETERMINISTIC and not cfg.allow_unsure:
                gaps.append(Gap("unsure", lane, s.name, qid,
                                "deterministic and answered unsure: an unsure answer is never sent "
                                "(declare the id judged, or the lane allow_unsure, if a human pick is meant)"))
            rows.append(Row(s.name, qid, det, status, ans, exp, comp))
    for sk in m.skipped:
        if sk.lane == lane:
            n = f"; {sk.ids} id(s) not exercised" if sk.ids is not None else ""
            gaps.append(Gap("skipped", lane, sk.name, "", f"left out by the generator: {sk.reason}{n}"))
    if not ran:
        gaps.append(Gap("empty", lane, "", "", "no specimen of this lane ran: nothing is covered"))
    if cfg.base is not None:
        asked = {_matrix.bare_id(_matrix.qid_of(q)) for s in ran for q in s.questions}
        for q in _matrix.read_questions(cfg.base):
            bid = _matrix.bare_id(_matrix.qid_of(q))
            if bid not in asked:
                asked.add(bid)                      # one gap per id, however many sets ask it
                gaps.append(Gap("uncovered", lane, "", bid,
                                f"the newest base ({cfg.base.name}) asks it; no specimen that ran does"))
    for t in cfg.thresholds:
        sizes = [s.measure(t.measure) for s in ran]
        below = any(x <= t.bytes for x in sizes)
        above = any(x > t.bytes for x in sizes)
        if not (below and above):
            side = "above" if not above else "at or below"
            gaps.append(Gap("threshold", lane, "", "",
                            f"{t.name} ({t.bytes} bytes, {t.measure}): no specimen that ran is {side} it; "
                            "build one with `python -m ctf lookahead scale`"))
    used = {chain for s in ran for chain in s.encodings.values()}
    for chain in cfg.real_encodings:
        if chain not in used:
            gaps.append(Gap("unexercised_encoding", lane, "", "",
                            f"real deliveries use {'+'.join(chain)}; no specimen that ran does"))
    return LaneReport(lane, tuple(gaps), tuple(rows),
                      tuple(runs[s.name] for s in m.specimens[lane]), round(seconds, 3))


def record(rep: LaneReport, workdir: Path | None = None) -> dict:
    c = rep.counts()
    return _ledger.append("lookahead.gate", workdir=workdir, lane=rep.lane, verdict=rep.verdict,
                          specimens=c["specimens"], ran=c["ran"], questions=c["questions"],
                          deterministic=c["deterministic"], answered=c["answered"], wrong=c["wrong"],
                          unsure=c["unsure"], unanswered=c["unanswered"], skipped=c["skipped"],
                          gaps=c["gaps"], seconds=rep.seconds)


def gate(matrix_dir, lanes=None, *, root: Path | None = None, workdir: Path | None = None, guard="auto",
         timeout: float | None = None, record_to_ledger: bool = True) -> list[LaneReport]:
    """Load the matrix, run and evaluate each lane (all of them by default), record each verdict."""
    m = _matrix.load(matrix_dir)
    chosen = list(lanes) if lanes else list(m.lanes)
    unknown = [ln for ln in chosen if ln not in m.lanes]
    if unknown:
        raise LookaheadError(f"lane(s) {', '.join(unknown)} not in {m.path / _matrix.MATRIX_FILE} "
                             f"(it has {', '.join(m.lanes)})")
    g = _guard.resolve(guard) if isinstance(guard, str) else guard
    reports = []
    for lane in chosen:
        t0 = time.perf_counter()
        runs = run_lane(m, lane, root=root, guard=g, timeout=timeout, workdir=workdir)
        rep = evaluate(m, lane, runs, time.perf_counter() - t0)
        if record_to_ledger:
            record(rep, workdir)
        reports.append(rep)
    return reports
