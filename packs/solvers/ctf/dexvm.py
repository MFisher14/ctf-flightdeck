"""Trace the mobile dex-chain VM, and replay earlier builds through the lane's reader (B-229).

    traces = show([apk, ...], workdir=wd)              # one trace dict per APK (dex_chain_replay's JSON)
    rep = replay(folder, workdir=wd)                    # every build under folder through codec_search
    rep = replay(folder, workdir=wd, record=True)       # ... and record each plain one as an adapt event case

Every delivery is parsed in an engine process, never in this one: each run is `openers.run_engine` (B-014/B-036),
the one runner `ctf arm` and `ctf adapt gate` use: the engine's runner.command under the intake network guard
(ctf.intake.guard), in its own cwd and process group, with `openers.engine_env` (no secret-named variable, no ledger,
a fresh workdir), killed at its timeout. The run folders are a temporary folder inside the event workdir, as the lane
gate's are, so a saved challenge's bytes never leave it.

**show** runs `mobile_android.dex_chain_replay` (a diagnostic engine: its route, a mobile .apk/.apks at priority 20,
ranks it after codec_search's at 25, and it has no [intake] table) on each APK: the VM's verdict, every ANS entry
method's outcome with the decline's reason, and the armed reader's answer.

**replay** runs `mobile_android.codec_search` (the lane's reader, the engine the openers and the lane gate run) on
every *.apk / *.apks / *.xapk / *.aab under a folder; symlinks are not followed and a file past MAX_BUILD_BYTES is
reported, never read. Before a release (Day 31 dealt the Day 20 build into Mastery, and the shipped VM had never read
it) every build must still answer:
  * a build recorded as a B-036 event case of the mobile lane (same input sha256, same engine) must print every
    expect line of that case (its accepted answer);
  * any other build must answer plain (an ANS code, not unsure, not None).
A failing build is traced (the tracer engine) so the report names the call or opcode the VM declined at.

**record** writes each plain build that is not recorded yet as an event case (`ctf.adapt.regress.record_case`,
name `dexvm-<sha256[:12]>`, expect `: <code>  [<confidence>]`): from then on `ctf adapt prewarm` / `ctf adapt gate
mobile-android` replay it with every other case, warm-cached by B-036's keys, and `replay` holds the build to it.
Record only builds whose answers the judge accepted. A build that is not answered plain is never recorded.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import re
import tempfile
from pathlib import Path

from . import openers as _openers
from . import paths as _paths
from .adapt import AdaptError
from .adapt import regress as _regress
from .engines import runner as _runner
from .intake import guard as _guard

LANE = "mobile-android"
READER = "mobile_android.codec_search"            # the lane's reader: what an opener case and an event case run
TRACER = "mobile_android.dex_chain_replay"        # the diagnostic: one JSON trace line per APK
BUILD_SUFFIXES = (".apk", ".apks", ".xapk", ".aab")
MAX_BUILD_BYTES = 256 << 20                       # a delivery larger than this is reported, never read
DEFAULT_TIMEOUT = 120.0                           # seconds one engine run may take
CASE_PREFIX = "dexvm-"
ANS = re.compile(r"ANS-[0-9A-F]{16}\Z")
_TAIL = re.compile(r"(?P<shown>.*?)  \[(?P<conf>[^\]]*)\] (?P<route>.*)\Z")


class DexvmError(ValueError):
    """What cannot run: a missing file or folder, no build, an engine that does not resolve or cannot be guarded."""


def find_builds(root: Path) -> list[Path]:
    """Every delivery under `root` (*.apk, *.apks, *.xapk, *.aab), in path order. A symlink is not followed: a saved
    folder that links elsewhere is not read. DexvmError when `root` is not a folder."""
    root = Path(root)
    if not root.is_dir():
        raise DexvmError(f"replay folder not found: {root}")
    return [p for p in sorted(root.rglob("*"))
            if p.suffix.lower() in BUILD_SUFFIXES and not p.is_symlink() and p.is_file()]


def read_line(out: str, input_path: Path) -> dict:
    """codec_search's answer line for `input_path` (`<path>: <answer>  [<confidence>] <route>`): {"answer": the
    plain code or None, "shown", "confidence", "route", "plain"}. No such line: everything None, plain False."""
    lead = f"{input_path}: "
    for line in reversed(out.splitlines()):
        if line.startswith(lead):
            m = _TAIL.match(line[len(lead):])
            if m:
                shown = m["shown"]
                plain = bool(ANS.fullmatch(shown))
                return {"answer": shown if plain else None, "shown": shown, "confidence": m["conf"],
                        "route": m["route"], "plain": plain}
    return {"answer": None, "shown": None, "confidence": None, "route": None, "plain": False}


def _sha(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class _Runs:
    """One temporary folder inside the event workdir and the resolved guard; each run gets a new cwd and workdir."""

    def __init__(self, base: Path, root: Path, g: _guard.Guard, timeout: float):
        self.base, self.root, self.g, self.timeout, self.n = base, root, g, timeout, 0
        self.checked: set[str] = set()

    def run(self, engine: str, input_path: Path, via: str) -> _openers.EngineRun:
        if engine not in self.checked:
            try:
                m = _runner.resolve(engine, root=self.root)
            except _runner.EngineError as e:
                raise DexvmError(f"engine {engine} does not resolve: {e}") from None
            why = _openers.os_sandbox_need(_NoSandbox(), m)
            if why and not self.g.allows_spawn:
                raise DexvmError(f"{engine}: {why}, so it needs the OS network sandbox; {self.g.reason}")
            self.checked.add(engine)
        self.n += 1
        return _openers.run_engine(engine, input_path, root=self.root, g=self.g, run_dir=self.base / f"run-{self.n}",
                                   work=self.base / f"work-{self.n}", timeout=self.timeout, via=via)


class _NoSandbox:
    needs_os_sandbox = False


@contextlib.contextmanager
def _session(workdir: Path | None, root: Path | None, guard, timeout: float):
    root = _paths.repo_root() if root is None else Path(root)
    if workdir is None:
        workdir = _paths.workdir()          # EventError (a ValueError) names CTF_EVENT / CTF_WORKDIR
    workdir = Path(workdir)
    if not (isinstance(timeout, (int, float)) and timeout > 0):
        raise DexvmError(f"timeout {timeout!r} must be a positive number of seconds")
    g = guard if isinstance(guard, _guard.Guard) else _guard.resolve(guard)
    workdir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=workdir, prefix="dexvm-") as tmp:
        yield _Runs(Path(tmp), root, g, float(timeout)), workdir, g


def _trace_run(runs: _Runs, p: Path) -> dict:
    run = runs.run(TRACER, p, "dexvm-show")
    if run.cut:
        return {"verdict": "error", "reasons": [f"the trace was cut at its {runs.timeout:g}s timeout"]}
    lines = [ln for ln in run.out.splitlines() if ln.strip()]
    try:
        t = json.loads(lines[-1]) if run.code == 0 and lines else None
    except ValueError:
        t = None
    if not isinstance(t, dict):
        return {"verdict": "error",
                "reasons": [f"the trace engine exited {run.code}: {_openers.excerpt(run.out, run.err, 400)}"]}
    return t


def _size_note(p: Path) -> str | None:
    size = p.stat().st_size
    return f"{size} bytes is past the {MAX_BUILD_BYTES} a dexvm run reads" if size > MAX_BUILD_BYTES else None


def show(apks, *, root: Path | None = None, workdir: Path | None = None, guard="auto",
         timeout: float = DEFAULT_TIMEOUT) -> list[dict]:
    """One trace per APK, in the order given (the tracer engine's JSON, plus `path`). A run that fails or is cut gives
    verdict `error` with the reason. DexvmError for a missing file; GuardError when the guard cannot hold."""
    paths = [Path(a) for a in apks]
    for p in paths:
        if p.is_symlink() or not p.is_file():
            raise DexvmError(f"{p}: not a regular file")
    out = []
    with _session(workdir, root, guard, timeout) as (runs, _wd, _g):
        for p in paths:
            big = _size_note(p)
            t = ({"name": p.name, "verdict": "unreadable", "answer": None, "reasons": [big]} if big
                 else _trace_run(runs, p.resolve()))
            t["path"] = str(p)
            out.append(t)
    return out


def _held_cases(workdir: Path) -> dict[str, _regress.RegCase]:
    """{input sha256: event case} of the mobile lane's recorded cases that run the reader."""
    return {_sha(c.input): c for c in _regress.event_cases(LANE, workdir) if c.engine == READER and c.input}


def replay(folder: Path, *, root: Path | None = None, workdir: Path | None = None, guard="auto",
           timeout: float = DEFAULT_TIMEOUT, record: bool = False) -> dict:
    """Every build under `folder` through the reader (see the module text). {"root", "builds", "failures", "ok",
    "recorded", "held"}. DexvmError when the folder is missing or holds no build; AdaptError for a bad event case."""
    folder = Path(folder)
    found = find_builds(folder)
    if not found:
        raise DexvmError(f"no build (*{', *'.join(BUILD_SUFFIXES)}) under {folder}")
    builds, failures, recorded = [], [], []
    with _session(workdir, root, guard, timeout) as (runs, wd, _g):
        held = _held_cases(wd)
        for p in found:
            rel = str(p.relative_to(folder))
            big = _size_note(p)
            run = None
            if big:
                rec = {"path": rel, "sha256": None, "answer": None, "plain": False, "verdict": "unreadable",
                       "reasons": [big]}
            else:
                sha = _sha(p)
                run = runs.run(READER, p.resolve(), "dexvm-replay")
                rec = {"path": rel, "sha256": sha, "seconds": round(run.seconds, 3), "exit": run.code,
                       **read_line(run.out, p.resolve())}
                if run.cut:
                    rec["verdict"] = "cut"
                    rec["reasons"] = [f"cut at its {timeout:g}s timeout"]
            case = held.get(rec["sha256"] or "")
            rec["held"] = case.name if case else None
            if case is not None:
                ok = run is not None and run.code == 0 and all(e in run.out for e in case.expect)
                why = None if ok else ("regressed: %s expects %s; the reader now prints %s"
                                       % (case.name, " | ".join(case.expect), rec.get("shown") or "nothing"))
            else:
                ok = bool(rec.get("plain")) and rec.get("exit") == 0
                why = None if ok else "not answered plain (%s)" % (rec.get("shown") or rec.get("verdict") or "nothing")
            if not ok:
                if big is None and not rec.get("reasons"):
                    t = _trace_run(runs, p.resolve())
                    rec["verdict"] = t.get("verdict")
                    rec["reasons"] = list(t.get("reasons") or [])
                failures.append({"path": rel, "why": why, "reasons": rec.get("reasons", [])})
            # only a build that passed as plain (ok with no held case means plain, exit 0) is ever recorded
            if record and ok and case is None and CASE_PREFIX + rec["sha256"][:12] not in recorded:
                name = CASE_PREFIX + rec["sha256"][:12]
                try:
                    _regress.record_case(LANE, name, engine=READER, input_file=p,
                                         expect=[f": {rec['answer']}  [{rec['confidence']}]"], workdir=wd,
                                         root=runs.root, note=f"recorded by ctf dexvm replay --record from {rel}")
                except AdaptError as e:
                    raise DexvmError(f"could not record {rel}: {e}") from None
                rec["held"] = f"event:{name}"
                recorded.append(name)
            builds.append(rec)
    return {"root": str(folder), "builds": builds, "failures": failures, "ok": not failures, "recorded": recorded,
            "held": len(held)}
