"""Which engines intake runs on a challenge, and how its files reach them (B-002).

    p = engines.plan(manifests, category, description, folder, guard=g, max_cost="cheap")
    for job in p.jobs:
        run = engines.run_job(job, ctx)            # EngineRun: status, exit code, output file, flags

An engine runs at intake only when its manifest has an `[intake]` table (its input adapter, docs/
CONTRACTS.md section 6): `select = "route"` runs it when the router routes the challenge to it
(category, keywords, files), `select = "files"` whenever one of the challenge's files matches its
`match`. `run` says what it is given: `per-file` (one run per matching file, `{file}`), `all-files`
(one run, `{files}`), `folder` (the unpacked folder, `{folder}`), `challenge` (a module:function engine,
called as fn(challenge_dir, profile)). The files are the sweep's scratch copy (originals plus every
unpacked member), so members of archives reach engines too. Routed engines without the table are
listed for the agent (run by hand), never guessed at.

Every engine runs through ctf.engines.runner.command (the `ctf run` path, `engine.run` ledger record
with via = "intake") inside the network guard (ctf/intake/guard.py), with a timeout, in its own
working folder, with secret-named variables removed from its environment. Skipped engines are listed
with the reason: wrong status, over the cost cap, a missing tool, no matching file, or one that starts
programs while only the Python guard is available.
"""
from __future__ import annotations

import importlib.util
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from ..engines import manifest as _manifest
from ..engines import router as _router
from ..engines import runner as _runner
from ..result import SolverResult

COST_ORDER = {c: i for i, c in enumerate(_manifest.COST_CLASSES)}
OUT_CAP = 1 << 20                     # bytes of an engine's stdout kept and scanned
HEAD_BYTES = 4096
MAX_INPUT_FILES = 5000                # files of one challenge considered for matching
SCRATCH_OWN = (".sweep.json", ".sweep-owner", ".lock")    # the sweep's own files at the scratch root
SECRET_ENV = re.compile(r"TOKEN|COOKIE|AUTHORIZATION|PASSWORD|PASSWD|SECRET|API_?KEY|CREDENTIAL", re.I)


@dataclass(frozen=True)
class Job:
    manifest: _manifest.Manifest
    files: tuple[Path, ...]           # per-file: one; all-files: several; folder/challenge: ()
    reason: str
    priority: int
    index: int = 0                    # the n-th run of this engine (per-file)

    @property
    def engine(self) -> str:
        return self.manifest.id


@dataclass(frozen=True)
class Skip:
    engine: str
    reason: str


@dataclass
class Plan:
    jobs: list[Job] = field(default_factory=list)
    skipped: list[Skip] = field(default_factory=list)
    unadapted: list[tuple[str, int, str]] = field(default_factory=list)   # routed, no [intake]: (id, prio, why)
    routed: dict[str, tuple[int, str]] = field(default_factory=dict)      # every routed engine: id -> (prio, why)
    claims: dict[str, list[str]] = field(default_factory=dict)  # file (relative to the folder) -> engine ids


def claims(manifests, heads, folder: Path | None) -> dict[str, list[str]]:
    """{file relative to folder: [engine id]} of the engines whose route file matchers or [intake]
    match name the file: what the engines say about each file, category and brief aside."""
    out: dict[str, list[str]] = {}
    for m in manifests:
        if m.status == "retired":
            continue
        matchers = tuple(dict.fromkeys([f for r in m.routes for f in r.files]
                                       + list(m.intake.match if m.intake else ())))
        if not matchers:
            continue
        for f, _why in files_matching(matchers, heads):
            key = _rel(f, folder) if folder is not None else str(f)
            out.setdefault(key, []).append(m.id)
    return out


def input_files(folder: Path | None) -> list[tuple[Path, bytes]]:
    """[(file, first bytes)] under folder, sorted; links and the sweep's own files left out."""
    if folder is None or not Path(folder).is_dir():
        return []
    folder = Path(folder)
    out = []
    for dirpath, dirnames, filenames in os.walk(folder):
        here = Path(dirpath)
        dirnames[:] = sorted(d for d in dirnames if not (here / d).is_symlink())
        for n in sorted(filenames):
            f = here / n
            if f.is_symlink() or not f.is_file() or (here == folder and n in SCRATCH_OWN):
                continue
            with open(f, "rb") as fh:
                out.append((f, fh.read(HEAD_BYTES)))
            if len(out) >= MAX_INPUT_FILES:
                return out
    return out


def left_out(originals: Path | None, read) -> list[tuple[Path, bytes]]:
    """[(file, first bytes)] of the handout's files the sweep did not read, sorted: one over its size
    limits (ctf.sweep.MAX_SOURCE, MAX_SOURCE_TOTAL) is not in the scratch copy the engines get, and a
    memory or disk image is nearly always over them. `read`: the paths, relative to `originals`, of
    the files the sweep did read (its manifest's originals). Links and the sweep's secret folders are
    never entered, as the sweep never enters them. plan() gives these only to an engine whose
    [intake] table says `originals = true` (it reads its input by offset, never whole)."""
    from .. import sweep as _sweep
    if originals is None or not Path(originals).is_dir():
        return []
    originals, read, out = Path(originals), set(read), []
    for dirpath, dirnames, filenames in os.walk(originals):
        here = Path(dirpath)
        dirnames[:] = sorted(d for d in dirnames if d not in _sweep.SECRET_DIRS)      # os.walk enters no linked folder
        for n in sorted(filenames):
            f = here / n
            if f.is_symlink() or not f.is_file() or f.relative_to(originals).as_posix() in read:
                continue
            with open(f, "rb") as fh:
                out.append((f, fh.read(HEAD_BYTES)))
            if len(out) >= MAX_INPUT_FILES:
                return out
    return out


def route_hits(manifests, category: str, description: str, heads) -> dict[str, tuple[int, str]]:
    """{engine id: (priority, why)}, best first: ctf.engines.router.route_heads (the router's own
    ranking) over the given file heads instead of a folder walk, so the sweep's own files are not
    routed on."""
    return {h.manifest.id: (h.priority, h.reason)
            for h in _router.route_heads(list(manifests), category, description, list(heads))}


def files_matching(matchers, heads) -> list[tuple[Path, str]]:
    """[(file, why)] of every file one of the matchers (route syntax) matches, in file order."""
    only_files = _manifest.Route(files=tuple(matchers))
    out = []
    for f, head in heads:
        why = _router.route_matches(only_files, "", "", [(f, head)])
        if why:
            out.append((f, why))
    return out


def tool_missing(needs) -> list[str]:
    """The needs_tools entries not available to the engine interpreter (binaries on PATH or in the
    interpreter's bin folder, `py:<module>` importable)."""
    missing = []
    for name in needs:
        if name.startswith("py:"):
            try:
                ok = importlib.util.find_spec(name[3:]) is not None
            except (ImportError, ValueError):
                ok = False
        else:
            venv_bin = Path(sys.executable).parent / name
            ok = bool(shutil.which(name)) or (venv_bin.is_file() and os.access(venv_bin, os.X_OK))
        if not ok:
            missing.append(name)
    return missing


def plan(manifests, category: str, description: str, folder: Path | None, *, guard, max_cost: str = "cheap",
         heads=None, originals=()) -> Plan:
    """The engines intake runs on this challenge, the ones it skips (with why), and the routed engines
    that have no input adapter. originals: [(file, first bytes)] of the handout's files that are not in
    `folder` (left_out: the sweep's size limits); an engine whose [intake] table says
    `originals = true` is matched against them too and is given each by its own path."""
    if max_cost not in COST_ORDER:
        raise ValueError(f"max_cost {max_cost!r}: use one of {', '.join(COST_ORDER)}")
    heads = input_files(folder) if heads is None else heads
    routed = route_hits(manifests, category, description, heads)
    p = Plan(routed=routed, claims=claims(manifests, heads, folder))
    picked = []
    for m in manifests:
        spec = m.intake
        if spec is None:
            if m.id in routed:
                p.unadapted.append((m.id, routed[m.id][0], routed[m.id][1]))
            continue
        matching = files_matching(spec.match, heads) if spec.match else []
        if spec.originals and originals:
            matching += files_matching(spec.match, originals)
        if spec.select == "route":
            if m.id not in routed:
                continue
            prio, why = routed[m.id]
        else:
            if not matching:
                continue
            prio, why = routed.get(m.id, (_manifest.DEFAULT_PRIORITY, f"{matching[0][0].name}: {matching[0][1]}"))
        reason = None
        if m.status != "active":
            reason = f"status {m.status}: intake runs active engines only"
        elif COST_ORDER[m.cost_class] > COST_ORDER[max_cost]:
            reason = f"cost_class {m.cost_class} is over the intake cap {max_cost} (raise it with --max-cost)"
        elif missing := tool_missing(m.needs_tools):
            reason = "needs " + ", ".join(missing) + " (not installed)"
        elif spec.run in ("per-file", "all-files") and not matching:
            reason = "no file matches " + ", ".join(spec.match)
        elif not guard.allows_spawn and (spec.spawns or (m.entry.kind == "cli" and not m.entry.is_python_cli)):
            reason = ("it starts other programs, and " + guard.reason if spec.spawns
                      else "an external-command entry needs the OS network sandbox; " + guard.reason)
        if reason:
            p.skipped.append(Skip(m.id, reason))
            continue
        if spec.run == "per-file":
            for i, (f, fwhy) in enumerate(matching[:spec.max_files]):
                picked.append(Job(m, (f,), f"{why}; {fwhy}" if spec.select == "route" else why, prio, i))
            if len(matching) > spec.max_files:
                p.skipped.append(Skip(m.id, f"{len(matching) - spec.max_files} more matching file(s) over "
                                            f"its max_files = {spec.max_files}"))
        elif spec.run == "all-files":
            picked.append(Job(m, tuple(f for f, _ in matching[:spec.max_files]), why, prio))
            if len(matching) > spec.max_files:
                p.skipped.append(Skip(m.id, f"{len(matching) - spec.max_files} matching file(s) left out "
                                            f"(max_files = {spec.max_files})"))
        else:
            picked.append(Job(m, (), why, prio))
    picked.sort(key=lambda j: (-j.priority, j.engine, j.index))
    p.jobs = picked
    p.unadapted.sort(key=lambda u: (-u[1], u[0]))
    return p


# ---------------------------------------------------------------- running one job

@dataclass
class Context:
    challenge_dir: Path
    folder: Path                      # the files given to engines (the sweep's scratch copy)
    out_root: Path                    # <challenge>/recon/engines
    profile: object
    guard: object
    root: Path
    python: str
    challenge_id: str | None
    record: bool = True
    workdir: Path | None = None       # the event workdir: CTF_WORKDIR for the engine, the ledger's folder


@dataclass
class EngineRun:
    engine: str
    inputs: tuple[str, ...]           # relative to the challenge folder
    status: str                       # ok | failed | timeout | error
    exit_code: int | None
    seconds: float
    output: str                       # stdout file, relative to the challenge folder
    errors: str                       # stderr file
    result_status: str | None = None  # the SolverResult status, when the engine printed one
    flags: tuple[str, ...] = ()
    note: str = ""
    disputed: tuple[str, ...] = ()    # flags its own result calls a possible decoy (evidence kind `decoy`, B-132)

    def to_dict(self) -> dict:
        return {"engine": self.engine, "inputs": list(self.inputs), "status": self.status,
                "exit_code": self.exit_code, "seconds": round(self.seconds, 3), "output": self.output,
                "errors": self.errors, "result_status": self.result_status, "flags": list(self.flags),
                "note": self.note, "disputed": list(self.disputed)}


def expand_args(spec: _manifest.IntakeSpec, files, *, folder: Path, challenge: Path, out: Path) -> list[str]:
    values = {"folder": str(folder), "challenge": str(challenge), "out": str(out),
              "file": str(files[0]) if files else ""}
    argv = []
    for a in spec.args:
        if a == "{files}":
            argv += [str(f) for f in files]
            continue
        argv.append(_manifest._PLACEHOLDER_RE.sub(lambda mt: values[mt.group(1)], a))
    return argv


def engine_env(profile, workdir: Path | None = None) -> dict:
    """The engine's environment: ours without secret-named variables, with the event (and the workdir,
    so its engine.run record lands in the intake's ledger) set."""
    env = {k: v for k, v in os.environ.items() if not SECRET_ENV.search(k)}
    env["CTF_EVENT"] = profile.slug
    if workdir is not None:
        env["CTF_WORKDIR"] = str(workdir)
    return env


def _rel(p: Path, base: Path) -> str:
    try:
        return Path(p).relative_to(base).as_posix()
    except ValueError:
        return str(p)


def _kill(proc) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        proc.kill()


def run_job(job: Job, ctx: Context, *, timeout: float | None = None) -> EngineRun:
    from .. import flagfmt
    from . import guard as _guard
    m, spec = job.manifest, job.manifest.intake
    work = ctx.out_root / m.id
    work.mkdir(parents=True, exist_ok=True)
    tag = f".{job.index}" if spec.run == "per-file" else ""
    out_f, err_f = work / f"out{tag}.txt", work / f"err{tag}.txt"
    if m.entry.kind == "function":
        args = [str(ctx.challenge_dir), "--event", ctx.profile.slug]
    else:
        args = expand_args(spec, job.files, folder=ctx.folder, challenge=ctx.challenge_dir, out=work)
    cmd = _guard.wrap(ctx.guard, _runner.command(m.id, args, python=ctx.python, root=ctx.root, via="intake",
                                                 record=ctx.record, challenge_id=ctx.challenge_id), ctx.root)
    limit = float(spec.timeout if timeout is None else min(spec.timeout, timeout))
    inputs = tuple(_rel(f, ctx.challenge_dir) for f in job.files)
    t0 = time.monotonic()
    with open(out_f, "wb") as fo, open(err_f, "wb") as fe:
        try:
            proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=fo, stderr=fe, cwd=work,
                                    env=engine_env(ctx.profile, ctx.workdir), start_new_session=True)
        except OSError as e:
            return EngineRun(m.id, inputs, "error", None, time.monotonic() - t0, _rel(out_f, ctx.challenge_dir),
                             _rel(err_f, ctx.challenge_dir), note=f"could not start: {type(e).__name__}: {e}")
        try:
            code = proc.wait(timeout=limit)
            status = "ok" if code == 0 else "failed"
        except subprocess.TimeoutExpired:
            _kill(proc)
            proc.wait()
            code, status = None, "timeout"
    seconds = time.monotonic() - t0
    note = ""
    if status == "timeout":
        note = f"killed after {limit:g}s"
        if ctx.record and _runner.recording_enabled():
            _runner.record_run(m.id, exit_code=-int(signal.SIGKILL), seconds=seconds, via="intake",
                               challenge_id=ctx.challenge_id, workdir=ctx.workdir)
    size = out_f.stat().st_size
    if size > OUT_CAP:
        os.truncate(out_f, OUT_CAP)
        note = (note + "; " if note else "") + f"stdout cut to {OUT_CAP} of {size} bytes"
    esize = err_f.stat().st_size
    if esize > OUT_CAP:
        os.truncate(err_f, OUT_CAP)
        note = (note + "; " if note else "") + f"stderr cut to {OUT_CAP} of {esize} bytes"
    text = out_f.read_bytes().decode("utf-8", "replace")
    ff = flagfmt.for_profile(ctx.profile)
    result_status, flags, disputed = None, (), ()
    if not m.has("legacy-output"):
        lines = [ln for ln in text.splitlines() if ln.strip()]
        try:
            res = SolverResult.from_json(lines[-1]) if lines else None
        except (ValueError, TypeError, KeyError) as e:
            res = None
            note = (note + "; " if note else "") + f"no SolverResult JSON line ({e})"
        if res is not None:
            result_status, flags = res.status, tuple(res.flags)
            # B-132: an engine that found a flag-shaped value where decoys sit says so with an evidence
            # item of kind `decoy`; intake then never calls that value `solved` on its own.
            disputed = tuple(dict.fromkeys(f for e in res.evidence if e.kind == "decoy"
                                           for f in ff.find_flags(e.detail)))
    if not flags:            # an engine's own SolverResult flags win: its stdout is scanned only without them
        flags = tuple(ff.find_flags(text))
    return EngineRun(m.id, inputs, status, code, seconds, _rel(out_f, ctx.challenge_dir),
                     _rel(err_f, ctx.challenge_dir), result_status, flags, note, disputed)
