"""Armed Layer-1 openers per lane (B-014).

On day 1 of the 2026 events, Layer 1 did not exist: the master opener and the per-lane decoders were
not armed, so the first release of each lane needed a model (Day-1 base opened 57 minutes late). The
master now ships a ready-to-arm *opener* for each day-1 lane: the engine that opens the first release,
synthetic first-days fixtures (cases), the frozen answer key the engine must print on each, and neutral
controls on which no key may hold, so the first release of any event is played with no model.

`python -m ctf arm` is the day-1 regression gate. For each opener it builds every case fixture, runs
the engine under the intake network guard (ctf.intake.guard) with no secret-named variable, no ledger
and a fresh empty workdir, and checks every `expect` string is in the output (and, for a timed case,
that the run fits its window). It then runs the engine on each control and fails the opener when any
case's key also holds there: a key the engine prints on anything is a tautology, not a check. An
opener whose engine has drifted *fails*; an opener whose required tool is absent, that needs the OS
network sandbox where only the audit hook is available, or that can only be armed against a live
service, is reported *not-run* with a named reason -- never silently green.

    openers = load()                      # declarations from openers/layer1.toml, validated loudly
    results = [arm(o) for o in openers]   # ArmResult per opener (ArmResult.cases: one per case/control)
    opener  = for_lane("warmups")         # the opener a lane's day-1 intake runs with no model
    chosen  = select(openers, lanes=["binary"], profile=event.load("huntress"))
    run     = run_engine(engine, input_path, root=r, g=guard, run_dir=d, work=w, timeout=60)  # one guarded run
    run     = run_input(engine, input_path, ...)  # the same; a saved multi-set attempt runs once per set

A case whose fixture is a saved multi-delivery Mastery (`ctf.openers.set_fixtures`: an `attempt.json`
beside its deliveries) is run by `run_input` as the Mastery is played (B-042): `ctf.deliveries` pairs
each set with its own delivery and the engine runs once per set on that delivery. Its key names the
set, the delivery and the answer (`set2> delivery 2: blob.txt: <slug>`), and its control is the same
attempt with two sets' files exchanged (`ctf.openers.sets`).

The declaration lives in `openers/layer1.toml` at the repo root; the fixture builders are in
`ctf.openers.fixtures`. Adding a lane's opener is a new [[opener]] block plus its builders. The
contract is docs/CONTRACTS.md section 21.
"""
from __future__ import annotations

import os
import re
import shutil
import signal
import subprocess
import tempfile
import time
import tomllib
from dataclasses import dataclass
from pathlib import Path

from .. import event as _event
from .. import paths as _paths
from ..engines import manifest as _manifest
from ..engines import runner as _runner
from ..intake import engines as _intake_engines
from ..intake import guard as _guard
from .. import deliveries as _deliveries
from . import fixtures as _fixtures
from . import sets as _sets

DECLARATION = ("openers", "layer1.toml")               # <repo>/openers/layer1.toml
# Names whose value must never reach an opener's environment: intake's rule, the one copy.
SECRET_ENV = _intake_engines.SECRET_ENV

ARMED = "armed"
FAILED = "failed"
NOT_RUN = "not-run"

_OPENER_KEYS = {"lane", "category", "engine", "label", "fixture", "expect", "needs_tools", "offline",
                "reason", "case", "controls", "needs_os_sandbox"}
_CASE_KEYS = {"fixture", "expect", "mode", "within"}


class OpenerError(ValueError):
    """The opener declaration is malformed, names an engine that does not resolve, or names a fixture
    builder that does not exist. Raised at load time so the gate never runs a half-defined opener."""


@dataclass(frozen=True)
class Case:
    """One input the opener must solve: a fixture builder, the key it must print, the row mode it
    stands for (base, time_trial, mastery, single...), and for a timed case the window in seconds."""
    fixture: str
    expect: tuple[str, ...]
    mode: str = "base"
    within: float | None = None


@dataclass(frozen=True)
class Opener:
    lane: str                       # the opener's key (unique): the solvers/<lane>/ folder, or a name of its own
    category: str                   # the event category it serves (matched against event.toml)
    engine: str                     # the engine id, e.g. "warmups.layered_decode"
    label: str                      # a one-line human name
    fixture: str | None = None      # the base case's fixtures builder (required when offline)
    expect: tuple[str, ...] = ()    # every string the base case's output must contain
    needs_tools: tuple[str, ...] = ()   # tools beyond the engine manifest's own needs_tools
    offline: bool = True            # False: armed only against a live/fake service, not here
    reason: str = ""                # why offline is False (shown in the not-run report)
    cases: tuple[Case, ...] = ()    # further shapes ([[opener.case]]): mastery, timed, other days
    controls: tuple[str, ...] = ()  # neutral fixtures on which no case's key may hold
    needs_os_sandbox: bool = False  # the engine loads ctypes or starts programs: OS sandbox only

    @property
    def all_cases(self) -> tuple[Case, ...]:
        head = (Case(self.fixture, self.expect),) if self.fixture else ()
        return head + self.cases


@dataclass(frozen=True)
class CaseResult:
    fixture: str
    mode: str                       # the case's mode, or "control"
    status: str                     # ARMED | FAILED (a control that discriminates is ARMED)
    reason: str
    found: tuple[str, ...] = ()
    missing: tuple[str, ...] = ()
    seconds: float = 0.0
    exit_code: int | None = None
    output: str = ""


@dataclass(frozen=True)
class ArmResult:
    lane: str
    engine: str
    status: str                     # ARMED | FAILED | NOT_RUN
    reason: str                     # "" when armed; why otherwise
    found: tuple[str, ...] = ()     # expect strings seen in the output (every case)
    missing: tuple[str, ...] = ()   # expect strings not seen (every case)
    seconds: float = 0.0
    exit_code: int | None = None    # the first failing run's, else the base case's
    output: str = ""                # a trimmed excerpt of that run, for the report
    cases: tuple[CaseResult, ...] = ()

    @property
    def ok(self) -> bool:
        return self.status == ARMED


def _repo(root: Path | None) -> Path:
    return _paths.repo_root() if root is None else Path(root)


def declaration_path(root: Path | None = None) -> Path:
    return _repo(root).joinpath(*DECLARATION)


# --------------------------------------------------------------------------- the declaration

def _strs(raw: dict, key: str, where: str) -> tuple[str, ...]:
    v = raw.get(key, [])
    if not isinstance(v, list) or any(not isinstance(x, str) or not x for x in v):
        raise OpenerError(f"{where}: {key!r} must be a list of non-empty strings")
    return tuple(v)


def _builder(name, where: str, what: str) -> str:
    if not isinstance(name, str) or name not in _fixtures.BUILDERS:
        raise OpenerError(f"{where}: no fixture builder {name!r} for {what}; known: "
                          f"{', '.join(sorted(_fixtures.BUILDERS))}")
    return name


def _parse_case(raw, where: str) -> Case:
    if not isinstance(raw, dict):
        raise OpenerError(f"{where}: each [[opener.case]] must be a table")
    unknown = set(raw) - _CASE_KEYS
    if unknown:
        raise OpenerError(f"{where}: unknown case key(s) {', '.join(sorted(unknown))}")
    fixture = _builder(raw.get("fixture"), where, "a case")
    expect = _strs(raw, "expect", where)
    if not expect:
        raise OpenerError(f"{where}: case {fixture!r} needs a non-empty 'expect' key")
    mode = raw.get("mode", "base")
    if not isinstance(mode, str) or not mode:
        raise OpenerError(f"{where}: case {fixture!r}: 'mode' must be a non-empty string")
    within = raw.get("within")
    if within is not None and (isinstance(within, bool) or not isinstance(within, (int, float)) or within <= 0):
        raise OpenerError(f"{where}: case {fixture!r}: 'within' must be a positive number of seconds")
    return Case(fixture, expect, mode, float(within) if within is not None else None)


def _parse_one(raw: dict, where: str) -> Opener:
    if not isinstance(raw, dict):
        raise OpenerError(f"{where}: each opener must be a table, got {type(raw).__name__}")
    unknown = set(raw) - _OPENER_KEYS
    if unknown:
        raise OpenerError(f"{where}: unknown key(s) {', '.join(sorted(unknown))}")

    def req_str(key: str) -> str:
        v = raw.get(key)
        if not isinstance(v, str) or not v.strip():
            raise OpenerError(f"{where}: {key!r} is required and must be a non-empty string")
        return v

    def flag(key: str, default: bool) -> bool:
        v = raw.get(key, default)
        if not isinstance(v, bool):
            raise OpenerError(f"{where}: {key!r} must be true or false")
        return v

    lane = req_str("lane")
    where = f"{where} ({lane})"
    offline = flag("offline", True)
    raw_cases = raw.get("case", [])
    if not isinstance(raw_cases, list):
        raise OpenerError(f"{where}: 'case' must be an array of tables ([[opener.case]])")
    opener = Opener(
        lane=lane,
        category=req_str("category"),
        engine=req_str("engine"),
        label=req_str("label"),
        fixture=raw.get("fixture"),
        expect=_strs(raw, "expect", where),
        needs_tools=_strs(raw, "needs_tools", where),
        offline=offline,
        reason=raw.get("reason", ""),
        cases=tuple(_parse_case(c, f"{where} case {i}") for i, c in enumerate(raw_cases)),
        controls=_strs(raw, "controls", where),
        needs_os_sandbox=flag("needs_os_sandbox", False),
    )
    if offline:
        if not opener.fixture:
            raise OpenerError(f"{where}: an offline opener needs a 'fixture' builder")
        _builder(opener.fixture, where, "the base case")
        if not opener.expect:
            raise OpenerError(f"{where}: an offline opener needs a non-empty 'expect' key")
        if not opener.controls:
            raise OpenerError(f"{where}: an offline opener needs at least one 'controls' fixture (a neutral "
                              "input on which no key may hold, so the key is shown to discriminate)")
        for c in opener.controls:
            _builder(c, where, "a control")
    elif not opener.reason:
        raise OpenerError(f"{where}: a non-offline opener needs a 'reason'")
    return opener


def load(root: Path | None = None) -> list[Opener]:
    """Parse and validate `openers/layer1.toml`. Raises OpenerError (naming the lane) on a malformed
    block, a duplicate lane, an engine that does not resolve, an offline opener whose engine is not a
    command-line entry, or an unknown fixture builder."""
    root = _repo(root)
    path = declaration_path(root)
    if not path.is_file():
        raise OpenerError(f"no opener declaration at {path} (openers/layer1.toml)")
    try:
        data = tomllib.loads(path.read_text("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as e:
        raise OpenerError(f"{path}: not valid TOML: {e}") from e
    blocks = data.get("opener", [])
    if not isinstance(blocks, list) or not blocks:
        raise OpenerError(f"{path}: no [[opener]] blocks")
    openers = [_parse_one(b, f"{path.name}[opener {i}]") for i, b in enumerate(blocks)]

    seen: set[str] = set()
    for o in openers:
        if o.lane in seen:
            raise OpenerError(f"{path.name}: two openers for lane {o.lane!r}")
        seen.add(o.lane)

    manifests = _manifest.discover(root)
    for o in openers:
        try:
            m = _runner.resolve(o.engine, root=root, manifests=manifests)
        except _runner.EngineError as e:
            raise OpenerError(f"openers/layer1.toml ({o.lane}): engine {o.engine!r} does not resolve: {e}") from e
        if o.offline and m.entry.kind != "cli":
            raise OpenerError(f"openers/layer1.toml ({o.lane}): engine {o.engine!r} is a {m.entry.kind} entry; "
                              "an offline opener runs a command-line engine on its fixture file")
    return openers


def _canon(cat: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (cat or "").lower())


def for_lane(lane: str, openers: list[Opener] | None = None, *, root: Path | None = None) -> Opener:
    """The opener a lane's day-1 intake runs with no model. OpenerError if the lane has no opener."""
    openers = load(root) if openers is None else openers
    for o in openers:
        if o.lane == lane:
            return o
    raise OpenerError(f"no armed opener for lane {lane!r}; have: {', '.join(o.lane for o in openers)}")


def select(openers: list[Opener], *, lanes=None, profile: _event.EventProfile | None = None) -> list[Opener]:
    """Filter openers to the given lanes and/or the categories of an event profile (both when both
    are given). A profile category matches an opener's category or its lane name, compared without
    case or punctuation. An unknown lane raises OpenerError, so `--lane typo` never selects nothing."""
    out = list(openers)
    if profile is not None:
        want = {_canon(c) for c in profile.categories}
        out = [o for o in out if _canon(o.category) in want or _canon(o.lane) in want]
    if lanes:
        have = {o.lane for o in openers}
        bad = [name for name in lanes if name not in have]
        if bad:
            raise OpenerError(f"no opener for lane(s) {', '.join(bad)}; have: {', '.join(sorted(have))}")
        out = [o for o in out if o.lane in set(lanes)]
    return out


# --------------------------------------------------------------------------- arming

def engine_env(work: Path, profile: _event.EventProfile | None = None) -> dict:
    """The opener's environment: ours without secret-named variables, no ledger, a fresh empty workdir
    (no judge history, no prior attempt), and the event only when one was asked for."""
    env = {k: v for k, v in os.environ.items() if not SECRET_ENV.search(k)}
    env["CTF_ENGINE_LEDGER"] = "0"
    env["CTF_WORKDIR"] = str(work)
    if profile is not None:
        env["CTF_EVENT"] = profile.slug
    else:
        env.pop("CTF_EVENT", None)
    return env


def excerpt(stdout: str, stderr: str, limit: int = 2000) -> str:
    """The part of a run's output a result carries: stdout, or stderr when stdout is blank, capped."""
    text = stdout if stdout.strip() else stderr
    text = text.strip()
    return text if len(text) <= limit else text[:limit] + "\n...[truncated]"


def _kill_group(proc: subprocess.Popen) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        proc.kill()


def os_sandbox_need(item, m: _manifest.Manifest) -> str:
    """Why this engine can run only under the OS network sandbox, or ''. `item` is anything with a
    `needs_os_sandbox` flag: an Opener, or a lane-gate case (ctf.adapt.regress) replaying one."""
    if item.needs_os_sandbox:
        return "the opener is declared needs_os_sandbox (its engine loads a native library or starts programs)"
    if m.intake is not None and m.intake.spawns:
        return "the engine starts other programs (spawns = true)"
    if m.entry.kind == "cli" and not m.entry.is_python_cli:
        return "an external-command entry"
    return ""


@dataclass(frozen=True)
class EngineRun:
    code: int | None                # None: killed at the timeout
    out: str
    err: str
    seconds: float

    @property
    def cut(self) -> bool:
        """Killed at its timeout (the whole process group)."""
        return self.code is None


def run_engine(engine: str, input_path: Path, *, root: Path, g: _guard.Guard, run_dir: Path, work: Path,
               timeout: float, profile=None, via: str = "arm", nice: int = 0) -> EngineRun:
    """Run one engine on one input the way every no-model replay runs it (arming here, the lane gate in
    ctf.adapt.regress): `runner.command(engine, [input], via=via, record=False)` wrapped by the intake
    network guard `g`, with cwd `run_dir` (made here), `engine_env(work, profile)` (no secret-named
    variable, no ledger), stdin closed, and a new session whose whole process group is killed at
    `timeout`. `nice` > 0 runs it under `nice -n <nice>` (B-253: the gate's replays while a deadline
    clock runs). OSError when the engine cannot be started, or `nice` is asked for and not on PATH."""
    run_dir.mkdir()
    work.mkdir(exist_ok=True)
    cmd = _guard.wrap(g, _runner.command(engine, [str(input_path)], via=via, record=False, root=root), root)
    if nice:
        nice_bin = shutil.which("nice")
        if nice_bin is None:
            raise FileNotFoundError("nice is not on PATH: the replay was asked to run at nice "
                                    f"{int(nice)} and is not started without it")
        cmd = [nice_bin, "-n", str(int(nice)), *cmd]
    t0 = time.perf_counter()
    proc = subprocess.Popen(cmd, cwd=str(run_dir), env=engine_env(work, profile), stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8",
                            errors="replace", start_new_session=True)
    try:
        out, err = proc.communicate(timeout=timeout)
        code = proc.returncode
    except subprocess.TimeoutExpired:
        _kill_group(proc)
        out, err = proc.communicate()
        code = None
    return EngineRun(code, out or "", err or "", time.perf_counter() - t0)


def run_input(engine: str, input_path: Path, *, root: Path, g: _guard.Guard, run_dir: Path, work: Path,
              timeout: float, profile=None, via: str = "arm", nice: int = 0) -> EngineRun:
    """`run_engine` for one opener or lane-gate input (`nice` as there, for every run). An input that is a saved attempt (a file named
    attempt.json) is run as a Mastery is played (B-042, `ctf.openers.sets`): the engine once per set, on
    the bytes of the set's own delivery (`ctf.deliveries`), each run in its own cwd under `run_dir` with
    the whole `timeout`; the EngineRun holds every set's lines under `set<N>> ` and the sum of the
    seconds, and its code is None when a set's run was cut. Every other input is one `run_engine` call."""
    if not _deliveries.is_attempt(input_path):
        return run_engine(engine, input_path, root=root, g=g, run_dir=run_dir, work=work, timeout=timeout,
                          profile=profile, via=via, nice=nice)

    def one(path: Path, cwd: Path) -> EngineRun:
        return run_engine(engine, path, root=root, g=g, run_dir=cwd, work=work, timeout=timeout,
                          profile=profile, via=via, nice=nice)

    return EngineRun(*_sets.run(Path(input_path), run_dir, one))


def _execute(engine: str, fixture: str, *, root: Path, g: _guard.Guard, base: Path, n: int,
             timeout: float, profile) -> EngineRun:
    input_path = _fixtures.build(fixture, base / f"in-{n}")          # FixtureError: the caller names it
    return run_input(engine, input_path, root=root, g=g, run_dir=base / f"run-{n}", work=base / "work",
                     timeout=timeout, profile=profile, via="arm")


def _check_case(case: Case, run: EngineRun, timeout: float) -> CaseResult:
    found = tuple(e for e in case.expect if e in run.out)
    missing = tuple(e for e in case.expect if e not in run.out)
    if run.code is None:
        status, reason = FAILED, f"timed out after {timeout:g}s"
    elif run.code != 0:
        status, reason = FAILED, f"engine exited {run.code}"
    elif missing:
        status, reason = FAILED, f"missing from output: {', '.join(missing)}"
    elif case.within is not None and run.seconds > case.within:
        status, reason = FAILED, f"took {run.seconds:.2f}s, over its {case.within:g}s window"
    else:
        status, reason = ARMED, ""
    return CaseResult(case.fixture, case.mode, status, reason, found, missing, run.seconds, run.code,
                      excerpt(run.out, run.err))


def _check_control(fixture: str, cases: tuple[Case, ...], run: EngineRun, timeout: float) -> CaseResult:
    if run.code is None:
        return CaseResult(fixture, "control", FAILED, f"timed out after {timeout:g}s", seconds=run.seconds,
                          output=excerpt(run.out, run.err))
    holds = [c.fixture for c in cases if all(e in run.out for e in c.expect)]
    if holds:
        reason = (f"the key of {', '.join(holds)} also holds on this neutral input, so it does not tell a "
                  "solved fixture from an unsolved one")
        return CaseResult(fixture, "control", FAILED, reason, seconds=run.seconds, exit_code=run.code,
                          output=excerpt(run.out, run.err))
    return CaseResult(fixture, "control", ARMED, "", seconds=run.seconds, exit_code=run.code,
                      output=excerpt(run.out, run.err))


def _not_run(opener: Opener, reason: str) -> ArmResult:
    return ArmResult(opener.lane, opener.engine, NOT_RUN, reason,
                     missing=tuple(e for c in opener.all_cases for e in c.expect))


def arm(opener: Opener, *, root: Path | None = None, workdir: Path | None = None, timeout: float = 60.0,
        guard: str | _guard.Guard = "auto", profile: _event.EventProfile | None = None) -> ArmResult:
    """Build each case's fixture, run the engine on it with no model and no secret, check its key;
    then run the engine on each control and check that no key holds there.

    ARMED   -- every case ran to exit 0 within its window with every `expect` string in its output, and
               no case's key holds on any control.
    FAILED  -- a case exited non-zero, timed out, overran its window or missed a key string; a fixture
               failed to build; or a key also holds on a control.
    NOT_RUN -- the opener is not offline-armable, a required tool is absent (the manifest's needs_tools
               and the opener's own), or the engine needs the OS network sandbox and the guard is the
               audit hook only (reason given).
    `guard` is a ctf.intake.guard mode or Guard; asking for "os" where it is unavailable raises
    GuardError. Each run gets its own cwd, a fresh workdir, a new session (the whole process group
    is killed at the timeout), and `profile`'s slug as CTF_EVENT when one is given."""
    root = _repo(root)
    if not opener.offline:
        return _not_run(opener, opener.reason or "not offline-armable")
    try:
        m = _runner.resolve(opener.engine, root=root)
    except _runner.EngineError as e:
        return ArmResult(opener.lane, opener.engine, FAILED, f"engine does not resolve: {e}")
    needs = list(dict.fromkeys((*m.needs_tools, *opener.needs_tools)))
    missing_tools = _intake_engines.tool_missing(needs)
    if missing_tools:
        return _not_run(opener, f"needs {', '.join(missing_tools)} (not installed)")
    g = guard if isinstance(guard, _guard.Guard) else _guard.resolve(guard)
    why = os_sandbox_need(opener, m)
    if why and not g.allows_spawn:
        return _not_run(opener, f"{why}, so it needs the OS network sandbox; {g.reason}")

    cases = opener.all_cases
    results: list[CaseResult] = []
    with tempfile.TemporaryDirectory(dir=workdir, prefix="arm-") as tmp:
        base = Path(tmp)
        jobs = [(c.fixture, c) for c in cases] + [(fx, None) for fx in opener.controls]
        for n, (fixture, case) in enumerate(jobs):
            try:
                run = _execute(m.id, fixture, root=root, g=g, base=base, n=n, timeout=timeout, profile=profile)
            except _fixtures.FixtureError as e:
                results.append(CaseResult(fixture, case.mode if case else "control", FAILED, str(e)))
                continue
            except OSError as e:
                results.append(CaseResult(fixture, case.mode if case else "control", FAILED,
                                          f"could not start the engine: {type(e).__name__}: {e}"))
                continue
            results.append(_check_case(case, run, timeout) if case is not None
                           else _check_control(fixture, cases, run, timeout))

    positive = results[:len(cases)]
    failing = [r for r in results if r.status != ARMED]
    shown = failing[0] if failing else (positive[0] if positive else None)
    return ArmResult(
        opener.lane, opener.engine,
        FAILED if failing else ARMED,
        "; ".join(f"{r.fixture} ({r.mode}): {r.reason}" for r in failing),
        found=tuple(dict.fromkeys(e for r in positive for e in r.found)),
        missing=tuple(dict.fromkeys(e for r in positive for e in r.missing)),
        seconds=sum(r.seconds for r in results),
        exit_code=shown.exit_code if shown else None,
        output=shown.output if shown else "",
        cases=tuple(results),
    )
