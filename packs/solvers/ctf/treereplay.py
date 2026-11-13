"""Replay a lane across checkouts and compare (B-210): the one shipped replay tool.

At Huntress 2026 builders rewrote the same scratch scripts by hand on most days: `replay_all.py` (25 writes),
`baseline.py`, `cmp.py`/`compare.py`, `timing.py`, `prof.py`. Each replayed a lane's saved inputs on a
before and an after tree, compared the answers, timed each attempt and sometimes profiled it. This module
is that script, once:

    rep = replay(["/path/tree-a", "/path/tree-b"], lane="binary", repeat=3, workdir=wd)
    rep.attempts                       # one Attempt per (tree, case, repeat): exit, wall, CPU, answer lines
    d = diff(rep)                      # per case: same | differs | unstable | missing, CPU ratio B/A
    print("\\n".join(render(rep, d)))
    prof = lane_profile(rep)           # with cprofile=True: per-case CPU and the top functions of the lane

**Cases.** With `lane`, the lane's regression set (`ctf.adapt.regress.regression_set`: its armed opener's
cases and controls, plus the event cases recorded under `<workdir>/adapt/cases/<lane>/`), read from each
tree's own `openers/layer1.toml`; a case one tree lacks is reported `missing`. With `engine` and `inputs`,
one ad-hoc case per input file (`input:<file name>`), the same in every tree.

**Runs.** Every attempt is a fresh process, run as the lane gate runs a case (`openers.run_engine`'s
shape): the tree's own `ctf/engines/_boot.py` under the tree's intake network guard, with
`openers.engine_env` (no secret-named variable, no ledger, its own fresh workdir), stdin closed, a new
session whose whole process group is killed at the cap. The run folders are a temporary folder inside the
event workdir (an event input never leaves it). The cap is load-scaled like the lane gate's
(`gate.runner.scaled_wall`). An engine that needs the OS sandbox where only the audit hook is available,
or a tool that is not installed, is `not-run`, never green.

**Measures.** `seconds` is wall time; `cpu` is the user + system CPU of the engine process (getrusage of
reaped children, measured around each run; one run at a time, so the difference is that run's). A
grandchild the engine leaves behind is not counted. With `cprofile`, the engine runs under
`ctf/_profboot.py` and its stats file is kept per attempt; `lane_profile` sums them.

**Answers.** An attempt's answer lines are its stdout lines, stripped, blank ones dropped, optionally only
those matching `lines` (a regex, e.g. `ANSWER|=`). Two trees agree on a case when every attempt of both
gives the same lines; a tree whose repeats disagree with each other is `unstable`.

Nothing here talks to a platform, starts a model or records to the ledger. ReplayError names what is
unusable (no tree, a tree that is not a checkout, no case, a bad regex, no workdir).
"""
from __future__ import annotations

import os
import pstats
import re
import resource
import statistics
import subprocess
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from . import paths as _paths

PROFBOOT = Path(__file__).resolve().parent / "_profboot.py"
DEFAULT_CAP = 60.0
DEFAULT_TOP = 15
TOP_KEPT = 60                  # functions a cprofile replay keeps in its report

SAME, DIFFERS, UNSTABLE, MISSING = "same", "differs", "unstable", "missing"
OK, FAIL, CUT, NOT_RUN = "ok", "fail", "cut", "not-run"


class ReplayError(RuntimeError):
    """The replay cannot run: the message names the tree, case, file or argument."""


@dataclass(frozen=True)
class Case:
    name: str
    engine: str
    kind: str = "case"                         # case | control
    expect: tuple[str, ...] = ()
    fixture: str | None = None
    input: Path | None = None
    needs_tools: tuple[str, ...] = ()
    needs_os_sandbox: bool = False
    offline: bool = True
    reason: str = ""
    keys: tuple[tuple[str, ...], ...] = ()     # a control: the case keys that must not hold on it


@dataclass(frozen=True)
class Attempt:
    tree: str                                  # the tree's label (A, B, ...)
    case: str
    n: int                                     # 1..repeat
    status: str                                # ok | fail | cut | not-run
    code: int | None = None
    seconds: float = 0.0
    cpu: float = 0.0
    lines: tuple[str, ...] = ()
    expect_ok: bool | None = None              # every expect string in stdout (a case with expects)
    reason: str = ""
    profile: str | None = None                 # the .prof file (cprofile)
    stderr_tail: str = ""


@dataclass
class ReplayReport:
    trees: dict[str, str]                      # label -> path
    lane: str | None
    repeat: int
    cap: float
    attempts: list[Attempt] = field(default_factory=list)
    cases: dict[str, list[str]] = field(default_factory=dict)   # label -> case names in that tree
    notes: list[str] = field(default_factory=list)
    top: list[tuple[str, int, float, float]] = field(default_factory=list)   # cprofile: (where, calls, own, cum)

    def of(self, label: str, case: str) -> list[Attempt]:
        return [a for a in self.attempts if a.tree == label and a.case == case]

    def to_dict(self) -> dict:
        return {"trees": dict(self.trees), "lane": self.lane, "repeat": self.repeat, "cap": self.cap,
                "cases": {k: list(v) for k, v in self.cases.items()}, "notes": list(self.notes),
                "top": [list(t) for t in self.top],
                "attempts": [dict(asdict(a), lines=list(a.lines)) for a in self.attempts]}


@dataclass(frozen=True)
class CaseDiff:
    case: str
    verdict: str                               # same | differs | unstable | missing
    only: dict[str, tuple[str, ...]]           # label -> answer lines no other tree gave
    cpu: dict[str, float]                      # label -> median CPU seconds of the attempts that ran
    status: dict[str, str]                     # label -> worst attempt status
    note: str = ""

    def to_dict(self) -> dict:
        return {"case": self.case, "verdict": self.verdict, "only": {k: list(v) for k, v in self.only.items()},
                "cpu": dict(self.cpu), "status": dict(self.status), "note": self.note}


# --------------------------------------------------------------------------- trees and cases

def labels_for(trees) -> dict[str, Path]:
    """{label: path} for the trees in order: A, B, C, ... A `LABEL=PATH` entry keeps its own label."""
    out: dict[str, Path] = {}
    for i, raw in enumerate(trees):
        text = str(raw)
        label, sep, rest = text.partition("=")
        if sep and re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,31}", label):
            path = Path(rest).expanduser()
        else:
            label, path = (chr(ord("A") + i) if i < 26 else f"T{i + 1}"), Path(text).expanduser()
        if label in out:
            raise ReplayError(f"tree label {label!r} is given twice")
        if not (path / "ctf" / "engines" / "_boot.py").is_file():
            raise ReplayError(f"--tree {text}: {path} is not a ctf-tools checkout (no ctf/engines/_boot.py)")
        out[label] = path.resolve()
    if not out:
        raise ReplayError("give at least one --tree")
    return out


def lane_cases(lane: str, root: Path, workdir: Path) -> list[Case]:
    """The lane's regression set in one tree, as replay cases."""
    from .adapt import AdaptError
    from .adapt import regress as _regress
    try:
        reg = _regress.regression_set(lane, root=root, workdir=workdir)
    except AdaptError as e:
        raise ReplayError(f"{root}: {e}") from None
    return [Case(name=c.name, engine=c.engine, kind=c.kind, expect=tuple(c.expect), fixture=c.fixture,
                 input=c.input, needs_tools=tuple(c.needs_tools), needs_os_sandbox=c.needs_os_sandbox,
                 offline=c.offline, reason=c.reason, keys=tuple(tuple(k) for k in c.keys)) for c in reg]


def input_cases(engine: str, inputs) -> list[Case]:
    """One ad-hoc case per input file (`input:<name>`), the same in every tree."""
    out, seen = [], set()
    for raw in inputs:
        p = Path(raw).expanduser()
        if not p.is_file():
            raise ReplayError(f"--input {raw}: not a file")
        name = f"input:{p.name}"
        if name in seen:
            raise ReplayError(f"two inputs are named {p.name}: give each a distinct file name")
        seen.add(name)
        out.append(Case(name=name, engine=engine, input=p.resolve()))
    if not out:
        raise ReplayError("--engine needs at least one --input")
    return out


# --------------------------------------------------------------------------- one attempt

def _children_cpu() -> float:
    ru = resource.getrusage(resource.RUSAGE_CHILDREN)
    return ru.ru_utime + ru.ru_stime


def _kill_group(proc: subprocess.Popen) -> None:
    import signal
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        proc.kill()


def answer_lines(stdout: str, pattern: re.Pattern | None = None) -> tuple[str, ...]:
    """The stdout lines an attempt is compared on: stripped, blank ones dropped, optionally only those
    matching `pattern`."""
    out = []
    for ln in stdout.splitlines():
        s = ln.strip()
        if not s:
            continue
        if pattern is not None and not pattern.search(s):
            continue
        out.append(s)
    return tuple(out)


def command(engine_id: str, input_path: Path, *, root: Path, guard, profile_out: Path | None = None) -> list[str]:
    """The argv of one attempt: the tree's engine boot under the tree's intake guard, optionally inside
    the cProfile shim (between the guard boot and the engine boot, so the guard is in first)."""
    from .engines import runner as _runner
    from .intake import guard as _guard
    cmd = _guard.wrap(guard, _runner.command(engine_id, [str(input_path)], via="replay", record=False, root=root),
                      root)
    if profile_out is not None:
        at = cmd.index("--") + 1                    # the guard boot's separator; the engine boot follows
        cmd[at:at] = [str(PROFBOOT), str(profile_out), "--"]
    return cmd


def run_attempt(case: Case, *, label: str, n: int, root: Path, guard, base: Path, cap: float,
                profile=None, pattern: re.Pattern | None = None, cprofile: bool = False,
                profile_dir: Path | None = None) -> Attempt:
    """One fresh-process run of `case` in tree `root` (see the module docstring)."""
    from .engines import runner as _runner
    from .intake import engines as _intake_engines
    from . import openers as _openers
    from .openers import fixtures as _fixtures
    try:
        m = _runner.resolve(case.engine, root=root)
    except _runner.EngineError as e:
        return Attempt(label, case.name, n, FAIL, reason=f"engine does not resolve: {e}")
    if not case.offline:
        return Attempt(label, case.name, n, NOT_RUN, reason=case.reason or "not offline-armable")
    missing = _intake_engines.tool_missing(list(dict.fromkeys((*m.needs_tools, *case.needs_tools))))
    if missing:
        return Attempt(label, case.name, n, NOT_RUN, reason=f"needs {', '.join(missing)} (not installed)")
    why = _openers.os_sandbox_need(case, m)
    if why and not guard.allows_spawn:
        return Attempt(label, case.name, n, NOT_RUN, reason=f"{why}, so it needs the OS network sandbox; {guard.reason}")
    slot = base / f"{label}-{n}-{re.sub(r'[^A-Za-z0-9_.-]', '_', case.name)}"
    slot.mkdir(parents=True)
    if case.fixture is not None:
        try:
            input_path = _fixtures.build(case.fixture, slot / "in")
        except _fixtures.FixtureError as e:
            return Attempt(label, case.name, n, FAIL, reason=f"fixture: {e}")
    elif case.input is not None:
        input_path = case.input
    else:
        return Attempt(label, case.name, n, NOT_RUN, reason="the case has no input (fixture or file)")
    prof_out = None
    if cprofile:
        d = profile_dir if profile_dir is not None else slot
        d.mkdir(parents=True, exist_ok=True)
        prof_out = d / f"{label}-{re.sub(r'[^A-Za-z0-9_.-]', '_', case.name)}-{n}.prof"
    cmd = command(m.id, input_path, root=root, guard=guard, profile_out=prof_out)
    run_dir, work = slot / "run", slot / "work"
    run_dir.mkdir()
    work.mkdir()
    cpu0 = _children_cpu()
    t0 = time.perf_counter()
    try:
        proc = subprocess.Popen(cmd, cwd=str(run_dir), env=_openers.engine_env(work, profile),
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, encoding="utf-8", errors="replace", start_new_session=True)
    except OSError as e:
        return Attempt(label, case.name, n, FAIL, reason=f"could not start the engine: {type(e).__name__}: {e}")
    try:
        out, err = proc.communicate(timeout=cap)
        code = proc.returncode
    except subprocess.TimeoutExpired:
        _kill_group(proc)
        out, err = proc.communicate()
        code = None
    seconds = time.perf_counter() - t0
    cpu = max(0.0, _children_cpu() - cpu0)
    out, err = out or "", err or ""
    expect_ok = all(e in out for e in case.expect) if case.expect and case.kind == "case" else None
    if code is None:
        status, reason = CUT, f"cut at its {cap:.1f}s cap"
    elif code != 0:
        status, reason = FAIL, f"engine exited {code}"
    elif expect_ok is False:
        status, reason = FAIL, "missing from output: " + ", ".join(e for e in case.expect if e not in out)
    elif case.kind == "control" and any(k and all(e in out for e in k) for k in case.keys):
        held = next(k for k in case.keys if k and all(e in out for e in k))
        status, reason = FAIL, f"the key [{', '.join(held)}] also holds on this control"
    else:
        status, reason = OK, ""
    tail = err.strip().splitlines()[-3:]
    return Attempt(label, case.name, n, status, code, round(seconds, 4), round(cpu, 4),
                   answer_lines(out, pattern), expect_ok, reason,
                   str(prof_out) if prof_out is not None and prof_out.is_file() else None,
                   " | ".join(tail)[:400])


# --------------------------------------------------------------------------- the replay

def _workdir(workdir) -> Path:
    if workdir is not None:
        return Path(workdir).expanduser()
    try:
        return _paths.workdir()
    except Exception as e:  # noqa: BLE001 - no event and no CTF_WORKDIR: name both
        raise ReplayError(f"no workdir for the replay's run folders: pass --workdir, or set CTF_WORKDIR or "
                          f"CTF_EVENT ({e})") from None


def replay(trees, *, lane: str | None = None, engine: str | None = None, inputs=(), repeat: int = 1,
           workdir: Path | None = None, cap: float = DEFAULT_CAP, guard="auto", profile=None,
           lines: str | None = None, cases=(), cprofile: bool = False, profile_dir: Path | None = None,
           load: float | None = None, cpus: int | None = None, max_scale: float = 4.0) -> ReplayReport:
    """Replay the cases on every tree `repeat` times, one fresh process per attempt (module docstring)."""
    from .gate.runner import host_load, scaled_wall
    from .intake import guard as _guard
    if (lane is None) == (engine is None):
        raise ReplayError("give --lane L (the lane's regression set) or --engine ID --input FILE..., not both")
    if not (isinstance(repeat, int) and repeat >= 1):
        raise ReplayError(f"--repeat {repeat!r}: at least 1")
    if not (isinstance(cap, (int, float)) and cap > 0):
        raise ReplayError(f"--cap {cap!r}: a positive number of seconds")
    try:
        pattern = re.compile(lines) if lines else None
    except re.error as e:
        raise ReplayError(f"--lines {lines!r}: {e}") from None
    labelled = labels_for(trees)
    wd = _workdir(workdir)
    wd.mkdir(parents=True, exist_ok=True)
    g = guard if isinstance(guard, _guard.Guard) else None
    if g is None:
        try:
            g = _guard.resolve(guard)
        except _guard.GuardError as e:
            raise ReplayError(str(e)) from None
    load = host_load() if load is None else float(load)
    cpus = (os.cpu_count() or 1) if cpus is None else int(cpus)
    run_cap, _scale = scaled_wall(float(cap), float(max_scale), load, cpus)
    rep = ReplayReport({k: str(v) for k, v in labelled.items()}, lane, repeat, round(run_cap, 3))
    rep.notes.append(f"guard: {g.mode} ({g.reason})")
    per_tree: dict[str, list[Case]] = {}
    for label, root in labelled.items():
        cs = lane_cases(lane, root, wd) if lane is not None else input_cases(engine, inputs)
        if cases:
            cs = [c for c in cs if c.name in set(cases)]
        per_tree[label] = cs
        rep.cases[label] = [c.name for c in cs]
    if cases:
        known = {n for v in rep.cases.values() for n in v}
        unknown = [c for c in cases if c not in known]
        if unknown:
            raise ReplayError(f"--case {', '.join(unknown)}: in no tree's case list")
    if not any(per_tree.values()):
        raise ReplayError("no case to replay")
    with tempfile.TemporaryDirectory(dir=wd, prefix="replay-") as tmp:
        base = Path(tmp)
        for label, root in labelled.items():
            for case in per_tree[label]:
                for n in range(1, repeat + 1):
                    rep.attempts.append(run_attempt(case, label=label, n=n, root=root, guard=g, base=base,
                                                    cap=run_cap, profile=profile, pattern=pattern,
                                                    cprofile=cprofile, profile_dir=profile_dir))
        if cprofile:
            # read the stats before the temporary folder (where they live without --profile-dir) goes
            rep.top = top_functions([a.profile for a in rep.attempts if a.profile], TOP_KEPT)
            if profile_dir is None:
                rep.notes.append("profiles were not kept (pass --profile-dir DIR to keep the .prof files)")
                rep.attempts = [Attempt(**{**asdict(a), "profile": None}) for a in rep.attempts]
    return rep


# --------------------------------------------------------------------------- compare

_RANK = {OK: 0, NOT_RUN: 1, FAIL: 2, CUT: 3}


def diff(rep: ReplayReport) -> list[CaseDiff]:
    """Per case, in first-seen order: whether the trees agree on its answer lines (module docstring)."""
    order: list[str] = []
    for label in rep.trees:
        for c in rep.cases.get(label, []):
            if c not in order:
                order.append(c)
    out: list[CaseDiff] = []
    for case in order:
        present = [lb for lb in rep.trees if case in rep.cases.get(lb, [])]
        status = {}
        cpu = {}
        outputs: dict[str, set[tuple[str, ...]]] = {}
        for lb in present:
            atts = rep.of(lb, case)
            status[lb] = max((a.status for a in atts), key=lambda s: _RANK[s]) if atts else NOT_RUN
            ran = [a for a in atts if a.status != NOT_RUN]
            if ran:
                cpu[lb] = round(statistics.median(a.cpu for a in ran), 4)
                outputs[lb] = {a.lines for a in ran}
        if len(present) < len(rep.trees):
            gone = [lb for lb in rep.trees if lb not in present]
            out.append(CaseDiff(case, MISSING, {}, cpu, status, f"not in tree(s) {', '.join(gone)}"))
            continue
        unstable = [lb for lb, outs in outputs.items() if len(outs) > 1]
        if unstable:
            out.append(CaseDiff(case, UNSTABLE, {}, cpu, status,
                                f"repeats disagree in tree(s) {', '.join(unstable)}"))
            continue
        lines_of = {lb: next(iter(outs)) for lb, outs in outputs.items()}
        only = {}
        for lb, ls in lines_of.items():
            others = set().union(*(set(v) for k, v in lines_of.items() if k != lb)) if len(lines_of) > 1 else set(ls)
            mine = tuple(x for x in ls if x not in others)
            if mine:
                only[lb] = mine
        same_lines = len(set(lines_of.values())) <= 1
        same_status = len(set(status.values())) <= 1
        verdict = SAME if same_lines and same_status else DIFFERS
        note = "" if same_status else "status " + ", ".join(f"{lb}={s}" for lb, s in status.items())
        if same_lines is False and not only:
            note = (note + "; " if note else "") + "same lines in another order or count"
        out.append(CaseDiff(case, verdict, only, cpu, status, note))
    return out


# --------------------------------------------------------------------------- profile

def top_functions(prof_files, top: int = DEFAULT_TOP) -> list[tuple[str, int, float, float]]:
    """The top functions by own (total) time across the stats files: (where, calls, tottime, cumtime)."""
    files = [str(p) for p in prof_files if p]
    if not files:
        return []
    st = pstats.Stats(files[0])
    for f in files[1:]:
        st.add(f)
    rows = []
    for (fn, line, name), (cc, nc, tt, ct, _callers) in st.stats.items():   # type: ignore[attr-defined]
        where = f"{Path(fn).name}:{line}({name})" if fn != "~" else name
        rows.append((where, int(nc), float(tt), float(ct)))
    rows.sort(key=lambda r: (-r[2], r[0]))
    return rows[:top]


def lane_profile(rep: ReplayReport, top: int = DEFAULT_TOP) -> list[str]:
    """Per-case CPU (heaviest first) and the lane's top functions, from a cprofile replay."""
    lines = []
    rows = []
    for label in rep.trees:
        for case in rep.cases.get(label, []):
            ran = [a for a in rep.of(label, case) if a.status != NOT_RUN]
            if ran:
                rows.append((max(a.cpu for a in ran), statistics.median(a.cpu for a in ran),
                             statistics.median(a.seconds for a in ran), label, case))
    rows.sort(key=lambda r: (-r[1], r[3], r[4]))
    total = sum(r[1] for r in rows)
    lines.append(f"lane profile {rep.lane or '-'}: {len(rows)} case(s), {total:.3f}s CPU (median per case summed)")
    for mx, med, wall, label, case in rows:
        share = (med / total * 100) if total else 0.0
        lines.append(f"  {med:8.3f}s cpu  {share:5.1f}%  max {mx:.3f}s  wall {wall:.3f}s  {label} {case}")
    tops = rep.top or top_functions([a.profile for a in rep.attempts if a.profile], top)
    if tops:
        lines.append(f"top {min(top, len(tops))} functions by own time:")
        for where, calls, tt, ct in tops[:top]:
            lines.append(f"  {tt:8.3f}s own  {ct:8.3f}s cum  {calls:>8} calls  {where}")
    else:
        lines.append("no profile data (run with --cprofile)")
    return lines


# --------------------------------------------------------------------------- render

def render(rep: ReplayReport, d: list[CaseDiff] | None = None, *, show_lines: int = 6) -> list[str]:
    out = [f"replay {('lane ' + rep.lane) if rep.lane else 'inputs'}: {len(rep.trees)} tree(s), "
           f"repeat {rep.repeat}, cap {rep.cap:g}s"]
    for lb, p in rep.trees.items():
        out.append(f"  tree {lb} = {p}")
    for n in rep.notes:
        out.append(f"  note: {n}")
    for a in rep.attempts:
        extra = f"  {a.reason}" if a.reason else ""
        out.append(f"{a.tree} {a.case} #{a.n}: {a.status} exit={a.code if a.code is not None else '-'} "
                   f"wall={a.seconds:.3f}s cpu={a.cpu:.3f}s lines={len(a.lines)}{extra}")
    if d is not None:
        counts: dict[str, int] = {}
        for c in d:
            counts[c.verdict] = counts.get(c.verdict, 0) + 1
            cpu = " ".join(f"{lb}={v:.3f}s" for lb, v in c.cpu.items())
            ratio = ""
            labels = list(rep.trees)
            if len(labels) >= 2 and c.cpu.get(labels[0]) and labels[1] in c.cpu:
                ratio = f" ({labels[1]}/{labels[0]} x{c.cpu[labels[1]] / c.cpu[labels[0]]:.2f})"
            out.append(f"DIFF {c.verdict:<8} {c.case}  cpu {cpu}{ratio}" + (f"  [{c.note}]" if c.note else ""))
            for lb, ls in c.only.items():
                for x in ls[:show_lines]:
                    out.append(f"    only {lb}: {x[:160]}")
                if len(ls) > show_lines:
                    out.append(f"    only {lb}: ... {len(ls) - show_lines} more")
        out.append("summary: " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items())))
    return out


def has_difference(d: list[CaseDiff]) -> bool:
    return any(c.verdict != SAME for c in d)
