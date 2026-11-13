"""The lane regression set and its warm gate (B-036).

The question before every timed clock is "does the lane still answer what it answered yesterday, with
today's fold in it?". At Huntress 2026 that gate (a) went falsely red under release load, because a
replay cut at its cap read as NO and stopped a lane whose base was already CORRECT (Days 16, 18), (b)
ran cold at the first clock, because nothing had prewarmed it after the morning's live fix (Days 10, 28),
(c) was voided by any new day module, because its cache key was the whole lane (Day 30), and (d) had a
wall sized for an idle machine (Day 26). This module is that gate, with each of those fixed:

    cases = regression_set("binary", workdir=wd)       # opener cases + controls + event cases
    g = gate("binary", workdir=wd)                     # LaneGate: verdict yes / no / not-run
    g.verdict, g.reason, g.cases                       # one CaseOutcome per case (pass/warm/fail/cut/not-run)
    prewarm(["binary", "warmups"], workdir=wd)         # the same gate, run ahead so the clock finds it warm
    record_case("binary", "d07-base", engine="binary.evidence", input_file=f, expect=["recover_code = 81"],
                workdir=wd, scope=["solvers/binary/d07*.py"])   # "yesterday", from an accepted run

**The set.** A lane's regression set is its armed opener's cases and controls from
`openers/layer1.toml` (B-014, section 24) plus the event cases recorded under
`<workdir>/adapt/cases/<lane>/<name>/` (`case.toml` + `input/<file>`): the input of an accepted run and
the answer lines the engine printed on it. Event cases are challenge data and stay in the workdir, never
in the repo. A lane with neither raises AdaptError; a case file with an unknown key, a missing input or
an input whose sha256 changed since it was recorded raises AdaptError.

**Keys (the warm cache, prefix-scoped).** Each case has its own key: sha256 over the engine's manifest,
the static import closure of its entry file (`ctf.gate.impact`, the regression gate's inventory, so it is
warm and shared), the lane part, the two runner boot files, the fixture builder or the input bytes (for
a multi-delivery Mastery case also the set-to-delivery code, `SET_CODE`), the
expect strings, mode, window, interpreter, and for a control every case key it must not match. The lane
part is every file in the engine's folder, because lanes load day modules by name at run time (binary
`evidence.py` imports `dNN` by prefix) and no static closure sees that. A case that declares `scope`
(globs such as `solvers/binary/d07*.py`) uses those files instead: a new `d30.py` then leaves the d07
case warm. A scope that matches no file raises AdaptError, so a typo never makes a key blind.

**Day-scoped keys (B-253: the lane key minus unrelated dNN modules).** An event case without `scope`
whose days are known keys the engine folder minus the day modules of other days. A day module is a
folder file named `dNN...` or `fields_dNN...` (`d03_container.py`, `fields_d30.py`, `d30.manifest.toml`).
The case's days are every `dNN` followed by `--` or `_` in its input's name, its input's bytes, the
member names of a zip or tar input, and its expect lines (a `dNN--` member, a `dNN_` question id). Kept:
every non-day file, the case's own days' modules, the day modules of any day a kept file names (a string
or import such as `"d04"` or `import d03_container`: the import audit, iterated to a fixpoint), and the
static closure of every kept Python file (`generic.py` imports `d01`/`d03`, so those stay in every key;
a kept file's import from outside the folder, such as `solvers/common/*`, is in the key too). A case with
no day found keys the whole folder (with the same closure). Adding `fields_d99.py` thus leaves the d07
case warm, and changing `generic.py` voids every case. `Keyer(day_scoped=False)` keys the whole folder
always. The day scan reads only names and bytes: a `dNN` inside a nested compressed archive is not seen.

**The lane key is not day-scoped.** Day scoping keys the warm cache only. The lane key (`LaneGate.lane_key`,
`current_lane_key`, what `chain` compares for its wrong-answer and same-artifact retry rules and what
`watch` re-gates on) is the set key over every case's key with day scoping off (`Keyer.lane_part_key`),
so any change to the lane folder changes it. Otherwise a fix folded into a day module no case covers
(a new `d30.py` after a failed d30 attempt, in a lane whose set holds only other days' event cases)
would leave the lane key unchanged and the chain would refuse the retry the fix was for. The re-gate
that follows is cheap: every case whose day-scoped key did not change is WARM.

**Pooled replay and the quiet check (B-253).** `gate(jobs=N)` replays the cases that are not warm N at a
time (each in its own process, as before); `jobs="auto"` takes `ctf.adapt.clocks.replay_policy`: 10 at
nice 0 when no clock with a deadline runs, 3 at nice 10 while one does, never more than the gate's `cpus`
(the same count its load scaling uses). A clock without a deadline does
not throttle the gate. Verdicts, recut, re-gate and caching are the same at any `jobs`.

**The gate.** Each case runs through `openers.run_engine`, the one runner the openers' arming uses: its
engine's `runner.command` under the intake network guard (`ctf.intake.guard`), in its own cwd and
process group, with `openers.engine_env` (no secret-named variable, no ledger, a fresh workdir). The
run folders (fixture inputs, cwd, workdir) are a temporary folder inside the event workdir, as arming's
are, so a replayed event input never leaves it. Its cap is `cap * clamp(load1 / cpus, 1, max_scale)` (the same
load scaling as the test gate), and a case's `within` window scales by the same factor.
  * PASS: exit 0 with every expect string in stdout, within its window (a control: no case key holds).
  * CUT: killed at its cap. Not a verdict: the case is re-replayed once at `recut` (>= 2) times the cap.
    Passing there is PASS (`recut`); cut again is a real NO.
  * FAIL: a wrong answer, a non-zero exit, a missing key, an overrun window, a key holding on a control.
    With `regate` (default) the case is run once more at the recut cap before the lane stops; passing
    there is PASS (`regated`) and is not cached, so the next gate runs it again.
  * NOT_RUN: the opener is not offline-armable, a needed tool is missing, or the engine needs the OS
    sandbox where only the audit hook is available. Never green.
  * WARM: an earlier PASS under the exact same key, reused (`warm=True`, the default).
Lane verdict: NO when any case is FAIL or CUT, else NOT_RUN when any is, else YES. Only a first-time
PASS (and a recut PASS) is cached, per key, in `<workdir>/adapt/gate/<lane>.json`; a red result drops its
key. Every gate writes one `adapt.gate` ledger record (`record=False` skips it).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sys
import tarfile
import tempfile
import threading
import time
import tomllib
import zipfile
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, ContextManager

from .. import event as _event
from .. import ledger as _ledger
from .. import openers as _openers
from .. import paths as _paths
from ..engines import manifest as _manifest
from ..engines import runner as _runner
from ..gate import GateError
from ..gate import config as _gconfig
from ..gate import impact as _impact
from ..gate.runner import host_load, scaled_wall
from ..gate.warm import checkout_state
from ..intake import engines as _intake_engines
from ..intake import guard as _guard
from ..openers import fixtures as _fixtures
from ..openers import set_fixtures as _set_fixtures
from . import AdaptError
from . import clocks as _clocks

PASS, WARM, FAIL, CUT, NOT_RUN = "pass", "warm", "fail", "cut", "not-run"
YES, NO = "yes", "no"                  # lane verdicts, with NOT_RUN
GREEN = (PASS, WARM)

KEY_VERSION = "adapt-1"
CACHE_VERSION = 1
DEFAULT_CAP = 60.0                     # seconds per case run at idle load (openers.arm's timeout)
DEFAULT_MAX_SCALE = 4.0                # the most the cap grows with load (tests/gate.toml's [wall])
RECUT_MIN = 2.0                        # a cap-cut case is re-replayed at no less than twice the cap
CASE_FILE = "case.toml"
RUN_FILES = ("ctf/engines/_boot.py", "ctf/intake/_guardboot.py")   # how every case runs: in every key
FIXTURE_CODE = "ctf/openers/fixtures.py"
# B-042: a multi-delivery Mastery case (a set_fixtures builder) also runs through the set-to-delivery map,
# the per-set runner and the expander that lists a bundle, so its key covers them too.
SET_CODE = ("ctf/openers/set_fixtures.py", "ctf/openers/sets.py", "ctf/deliveries.py", "ctf/idresolve.py",
            "tools/archive_expand.py")
FIXTURE_GLOB = "ctf/openers/*fixtures.py"      # fixtures.py and the builder modules its BUILDERS come from
LEDGER_EVENT = "adapt.gate"

_NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}\Z")
_MODE = re.compile(r"[a-z][a-z_]{0,31}\Z")
_CASE_KEYS = {"engine", "expect", "mode", "within", "scope", "input", "input_sha256", "note"}


# --------------------------------------------------------------------------- the set

@dataclass(frozen=True)
class RegCase:
    lane: str
    name: str                                  # opener:<fixture> | control:<fixture> | event:<name>
    engine: str                                # engine id
    kind: str                                  # "case" | "control"
    source: str                                # "opener" | "event"
    expect: tuple[str, ...] = ()               # a case: every string its stdout must hold
    fixture: str | None = None                 # an opener case or control: its fixtures builder
    input: Path | None = None                  # an event case: its recorded input file
    mode: str = "base"
    within: float | None = None                # a timed case's window at idle load (seconds)
    scope: tuple[str, ...] = ()                # globs replacing the engine folder in the key
    keys: tuple[tuple[str, ...], ...] = ()     # a control: the case keys that must not hold on it
    needs_tools: tuple[str, ...] = ()
    needs_os_sandbox: bool = False
    offline: bool = True
    reason: str = ""                           # why offline is False


def lane_dir(lane: str, workdir: Path) -> Path:
    return Path(workdir) / "adapt" / "cases" / _check_name(lane, "lane")


def _check_name(value: str, what: str) -> str:
    if not isinstance(value, str) or not _NAME.match(value):
        raise AdaptError(f"{what} {value!r}: use lower-case letters, digits, '.', '_' or '-' (at most 64)")
    return value


def _check_globs(scope, where: str) -> tuple[str, ...]:
    if isinstance(scope, str) or not all(isinstance(s, str) and s for s in scope):
        raise AdaptError(f"{where}: scope must be a list of repo-relative globs")
    for s in scope:
        if s.startswith("/") or ".." in s.split("/"):
            raise AdaptError(f"{where}: scope glob {s!r} must be repo-relative")
    return tuple(scope)


def _sha_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _toml_str(s: str) -> str:
    return json.dumps(s, ensure_ascii=True)          # a JSON string is a valid TOML basic string


def record_case(lane: str, name: str, *, engine: str, input_file: Path, expect, workdir: Path,
                root: Path | None = None, mode: str = "base", within: float | None = None, scope=(),
                note: str = "", force: bool = False) -> RegCase:
    """Record "yesterday": the input of an accepted run and the answer lines the engine printed on it,
    as an event case of `lane`'s regression set. The input is copied (never moved or linked) into
    `<workdir>/adapt/cases/<lane>/<name>/input/`. AdaptError for a bad name, an engine that does not
    resolve, an empty expect, a missing input, a bad scope, or an existing case without `force`."""
    root = _paths.repo_root() if root is None else Path(root)
    _check_name(name, "case name")
    d = lane_dir(lane, workdir) / name
    expect = tuple(expect)
    if not expect or not all(isinstance(e, str) and e.strip() for e in expect):
        raise AdaptError(f"case {lane}/{name}: expect needs at least one non-blank answer line")
    if not isinstance(mode, str) or not _MODE.match(mode):
        raise AdaptError(f"case {lane}/{name}: mode {mode!r} must be a lower-case word")
    if within is not None and not (isinstance(within, (int, float)) and within > 0):
        raise AdaptError(f"case {lane}/{name}: within must be a positive number of seconds")
    scope = _check_globs(scope, f"case {lane}/{name}")
    try:
        m = _runner.resolve(engine, root=root)
    except _runner.EngineError as e:
        raise AdaptError(f"case {lane}/{name}: engine does not resolve: {e}") from None
    src = Path(input_file)
    if src.is_symlink() or not src.is_file():
        raise AdaptError(f"case {lane}/{name}: input {src} is not a regular file")
    if d.exists():
        if not force:
            raise AdaptError(f"case {lane}/{name} exists at {d}; pass force to replace it")
        shutil.rmtree(d)
    (d / "input").mkdir(parents=True)
    dest = d / "input" / src.name
    shutil.copyfile(src, dest)
    lines = [f"engine = {_toml_str(m.id)}",
             "expect = [" + ", ".join(_toml_str(e) for e in expect) + "]",
             f"mode = {_toml_str(mode)}",
             f"input = {_toml_str(src.name)}",
             f"input_sha256 = {_toml_str(_sha_file(dest))}"]
    if within is not None:
        lines.append(f"within = {float(within)!r}")
    if scope:
        lines.append("scope = [" + ", ".join(_toml_str(s) for s in scope) + "]")
    if note:
        lines.append(f"note = {_toml_str(note)}")
    (d / CASE_FILE).write_text("\n".join(lines) + "\n", encoding="utf-8")
    return _load_event_case(lane, d)


def _load_event_case(lane: str, d: Path) -> RegCase:
    f = d / CASE_FILE
    where = f"event case {lane}/{d.name} ({f})"
    try:
        raw = tomllib.loads(f.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as e:
        raise AdaptError(f"{where}: unreadable: {e}") from None
    unknown = set(raw) - _CASE_KEYS
    if unknown:
        raise AdaptError(f"{where}: unknown key(s) {sorted(unknown)}")
    for k in ("engine", "expect", "input", "input_sha256"):
        if k not in raw:
            raise AdaptError(f"{where}: missing {k!r}")
    expect = raw["expect"]
    if not isinstance(expect, list) or not expect or not all(isinstance(e, str) and e.strip() for e in expect):
        raise AdaptError(f"{where}: expect must be a non-empty list of answer lines")
    inp = d / "input" / str(raw["input"])
    if "/" in str(raw["input"]) or not inp.is_file() or inp.is_symlink():
        raise AdaptError(f"{where}: its input {inp} is missing")
    if _sha_file(inp) != raw["input_sha256"]:
        raise AdaptError(f"{where}: its input changed since it was recorded (sha256 differs); re-record it")
    within = raw.get("within")
    if within is not None and (isinstance(within, bool) or not isinstance(within, (int, float)) or within <= 0):
        raise AdaptError(f"{where}: within must be a positive number")
    mode = raw.get("mode", "base")
    if not isinstance(mode, str) or not _MODE.match(mode):
        raise AdaptError(f"{where}: bad mode {mode!r}")
    return RegCase(lane=lane, name=f"event:{d.name}", engine=str(raw["engine"]), kind="case", source="event",
                   expect=tuple(expect), input=inp, mode=mode,
                   within=None if within is None else float(within),
                   scope=_check_globs(raw.get("scope", []), where))


def event_cases(lane: str, workdir: Path | None) -> list[RegCase]:
    """The lane's recorded event cases, by name. [] when none are recorded."""
    if workdir is None:
        return []
    d = lane_dir(lane, workdir)
    if not d.is_dir():
        return []
    out = []
    for sub in sorted(p for p in d.iterdir() if p.is_dir()):
        if not (sub / CASE_FILE).is_file():
            raise AdaptError(f"event case folder {sub} has no {CASE_FILE}")
        out.append(_load_event_case(lane, sub))
    return out


def recorded_lanes(workdir: Path | None) -> list[str]:
    if workdir is None:
        return []
    d = Path(workdir) / "adapt" / "cases"
    return sorted(p.name for p in d.iterdir() if p.is_dir()) if d.is_dir() else []


def regression_set(lane: str, *, root: Path | None = None, workdir: Path | None = None) -> list[RegCase]:
    """The lane's opener cases and controls (openers/layer1.toml) plus its recorded event cases.
    AdaptError when the declaration is malformed, a case file is bad, or the lane has no case at all."""
    _check_name(lane, "lane")
    try:
        declared = _openers.load(root)
    except _openers.OpenerError as e:
        raise AdaptError(f"openers/layer1.toml: {e}") from None
    opener = next((o for o in declared if o.lane == lane), None)
    evs = event_cases(lane, workdir)
    out: list[RegCase] = []
    if opener is not None:
        common = dict(lane=lane, engine=opener.engine, source="opener", needs_tools=opener.needs_tools,
                      needs_os_sandbox=opener.needs_os_sandbox, offline=opener.offline, reason=opener.reason)
        for c in opener.all_cases:
            out.append(RegCase(name=f"opener:{c.fixture}", kind="case", expect=c.expect, fixture=c.fixture,
                               mode=c.mode, within=c.within, **common))
        if not opener.offline and not opener.all_cases:
            # armed only against a live or fake service (the web opener): one case that reports why
            out.append(RegCase(name=f"opener:{lane}", kind="case", **common))
        keys = tuple(c.expect for c in opener.all_cases) + tuple(e.expect for e in evs if e.engine == opener.engine)
        for fx in opener.controls:
            out.append(RegCase(name=f"control:{fx}", kind="control", fixture=fx, mode="control", keys=keys,
                               **common))
    out += evs
    if not out:
        raise AdaptError(f"lane {lane!r} has no regression set: no opener in openers/layer1.toml and no "
                         f"event case under {lane_dir(lane, workdir) if workdir else '<workdir>/adapt/cases'}")
    return out


def lanes_for(profile: _event.EventProfile | None, *, root: Path | None = None,
              workdir: Path | None = None) -> list[str]:
    """The lanes to prewarm: those whose opener serves one of the profile's categories (every declared
    lane without a profile), plus every lane with recorded event cases."""
    try:
        declared = _openers.load(root)
        chosen = _openers.select(declared, profile=profile) if profile is not None else declared
    except _openers.OpenerError as e:
        raise AdaptError(f"openers/layer1.toml: {e}") from None
    return sorted({o.lane for o in chosen} | set(recorded_lanes(workdir)))


# --------------------------------------------------------------------------- days

DAY_FILE = re.compile(r"(?:fields_)?(d\d{2})(?![0-9])[A-Za-z0-9_.-]*\Z")    # a day module's base name
DAY_REF = re.compile(r"(?:fields_)?(d\d{2})(?![0-9])\w*(?:\.py)?\Z")          # a string or module naming one
_DAY_TOKEN = re.compile(r"(?<![A-Za-z0-9])[dD](\d{2})(?=--|_)")                 # d07--member, d07_question
_DAY_TOKEN_B = re.compile(rb"(?<![A-Za-z0-9])[dD](\d{2})(?=--|_)")
_SCAN_CHUNK = 1 << 20


def day_of(rel: str) -> str | None:
    """The day (`d07`) of a day module's repo path, None for any other file."""
    m = DAY_FILE.match(rel.rsplit("/", 1)[-1])
    return m.group(1) if m else None


def days_in_text(*texts: str) -> set[str]:
    """Every day named as `dNN--` (a member) or `dNN_` (a question id) in the texts."""
    return {f"d{m.group(1)}" for t in texts for m in _DAY_TOKEN.finditer(t)}


def days_in_file(path: Path) -> set[str]:
    """Days named by a file: its name, its bytes (a zip's member names are stored plainly), and the member
    names of a zip or tar (any compression). Read only; nothing is extracted or run."""
    p = Path(path)
    out = days_in_text(p.name)
    tail = b""
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(_SCAN_CHUNK), b""):
            buf = tail + chunk
            out |= {f"d{m.group(1).decode()}" for m in _DAY_TOKEN_B.finditer(buf)}
            tail = buf[-8:]
    names: list[str] = []
    try:
        if zipfile.is_zipfile(p):
            with zipfile.ZipFile(p) as z:
                names = z.namelist()
        elif tarfile.is_tarfile(p):
            with tarfile.open(p, "r:*") as t:
                names = t.getnames()
    except (zipfile.BadZipFile, tarfile.TarError, OSError, EOFError, ValueError):
        names = []                      # not a readable archive: its bytes were scanned above
    return out | days_in_text(*names)


# --------------------------------------------------------------------------- keys

class Keyer:
    """Per-case content keys over the regression gate's dependency graph (ctf.gate.impact)."""

    def __init__(self, root: Path | None = None, *, state: Path | None = None, day_scoped: bool = True):
        self.root = _paths.repo_root() if root is None else Path(root)
        try:
            cfg = _gconfig.load(self.root)
            st = Path(state) if state is not None else _paths.gate_state(self.root)
            self.graph = _impact.Graph(self.root, cfg, checkout_state(st, self.root))
        except (GateError, FileNotFoundError) as e:
            raise AdaptError(f"cannot key the lane regression set: {e}") from None
        self.day_scoped = bool(day_scoped)
        self._ext: dict[str, str] = {}
        self._days: dict[tuple, frozenset] = {}

    def days(self, case: RegCase, *, whole: bool = False) -> frozenset:
        """The days an event case is about (empty: unknown, not day-scoped, or `whole`; the whole folder
        is keyed)."""
        if whole or not self.day_scoped or case.source != "event" or case.scope or case.input is None:
            return frozenset()
        st = case.input.stat()
        k = (str(case.input), st.st_size, st.st_mtime_ns, case.expect)
        if k not in self._days:
            self._days[k] = frozenset(days_in_file(case.input) | days_in_text(*case.expect))
        return self._days[k]

    def day_refs(self, rel: str) -> set[str]:
        """Days a repo Python file names in a string constant or an import (`"d04"`, `import d03_container`,
        `"fields_d30.py"`): the import audit's edges. Empty for a file that is not parsed Python."""
        if not rel.endswith(".py") or rel not in self.graph.inventory:
            return set()
        p = self.graph.inventory.get(rel)
        names = list(p.get("strings", ()))
        for _level, mod, imported in p.get("imports", ()):
            names += [x for x in str(mod).split(".") if x] + [str(x) for x in imported]
        return {m.group(1) for s in names if (m := DAY_REF.match(s.rsplit("/", 1)[-1]))}

    def folder_files(self, folder: str, days=frozenset()) -> list[str]:
        """The lane part of a key: every file directly in `folder`; with `days`, minus the day modules of
        other days (see the module docstring for what is kept)."""
        pre = (folder + "/") if folder else ""
        direct = [f for f in self.graph.files if f.startswith(pre) and "/" not in f[len(pre):]]
        kept = direct
        if days:
            want = set(days)
            while True:
                kept = [f for f in direct if (d := day_of(f)) is None or d in want]
                more = set().union(*(self.day_refs(f) for f in kept)) - want
                if not more:
                    break
                want |= more
        out = set(kept)
        for f in kept:
            if f.endswith(".py"):
                out |= self.graph.closure(f)
        return sorted(out)

    def _ext_sha(self, rel: str) -> str:
        """sha256 of a file read through the root (a run file, the fixture builders), cached."""
        if rel not in self._ext:
            p = self.root / rel
            self._ext[rel] = _sha_file(p) if p.is_file() else "<missing>"
        return self._ext[rel]

    def _rel(self, p: Path) -> str | None:
        try:
            return Path(p).resolve().relative_to(self.root.resolve()).as_posix()
        except ValueError:
            return None

    def inputs(self, case: RegCase, m: _manifest.Manifest, *, whole: bool = False) -> list[str]:
        """The repo files a case's key covers (`whole`: with day scoping off)."""
        files = set()
        man = self._rel(m.path)
        if man:
            files.add(man)
        target = m.entry.target_file(self.root)
        tgt = self._rel(target) if target is not None else None
        if tgt:
            files |= self.graph.closure(tgt)
        if case.scope:
            hit = [f for f in self.graph.files if _gconfig.matches(f, case.scope)]
            if not hit:
                raise AdaptError(f"case {case.lane}/{case.name}: scope {list(case.scope)} matches no file, "
                                 "so its key would not see the lane's code")
            files |= set(hit)
        else:
            folder = self._rel(m.path.parent)
            files |= set(self.folder_files(folder or "", self.days(case, whole=whole)))
        return sorted(files)

    def case_key(self, case: RegCase, m: _manifest.Manifest, *, whole: bool = False) -> str:
        """The case's warm-cache key (`whole`: with day scoping off, as the lane key takes it)."""
        h = hashlib.sha256()

        def put(*parts) -> None:
            for x in parts:
                b = str(x).encode("utf-8", "surrogateescape")
                h.update(len(b).to_bytes(8, "big"))
                h.update(b)

        put(KEY_VERSION, sys.version, sys.executable, case.kind, case.source, m.id, case.mode, repr(case.within))
        put("expect", len(case.expect), *case.expect)
        for k in case.keys:
            put("key", len(k), *k)
        days = self.days(case, whole=whole)
        if days:
            put("days", len(days), *sorted(days))
        for f in self.inputs(case, m, whole=whole):
            put("file", f, self.graph.sha(f) or "<missing>")
        for f in RUN_FILES:
            put("run", f, self._ext_sha(f))
        if case.source == "opener":
            # Every builder module, not fixtures.py alone: the mobile and memory builders live in files of
            # their own, and an edited builder must make its lane's verdict cold.
            for f in sorted({FIXTURE_CODE, *(p.relative_to(self.root).as_posix() for p in self.root.glob(FIXTURE_GLOB))}):
                put("fixture", case.fixture, f, self._ext_sha(f))
            if case.fixture in _set_fixtures.BUILDERS:
                for f in SET_CODE:
                    put("sets", f, self._ext_sha(f))
        else:
            put("input", case.input.name if case.input else "", _sha_file(case.input) if case.input else "")
        return h.hexdigest()

    def lane_part_key(self, case: RegCase, m: _manifest.Manifest, key: str | None = None) -> str:
        """The case's part of the lane key: its key with day scoping off. `key` (its case key, when known)
        is reused when the case has no days, since the two keys are then the same."""
        if key is not None and not self.days(case):
            return key
        return self.case_key(case, m, whole=True)


def _set_key(rows) -> str:
    """The lane key: sha256 over every (case name, lane part key), an unresolvable engine's being ''.
    It changes when any case's code (its whole lane folder), input or key changes."""
    return hashlib.sha256("".join(f"{n}\0{k}\n" for n, k in sorted(rows)).encode()).hexdigest()


# --------------------------------------------------------------------------- the warm cache

def cache_path(lane: str, workdir: Path) -> Path:
    return Path(workdir) / "adapt" / "gate" / f"{_check_name(lane, 'lane')}.json"


class WarmCache:
    """Green case results by key. An unreadable or other-version file is started afresh, and says so."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.notes: list[str] = []
        self.results: dict[str, dict] = {}
        if self.path.exists():
            try:
                raw = json.loads(self.path.read_text(encoding="utf-8"))
                if not isinstance(raw, dict) or raw.get("version") != CACHE_VERSION \
                        or not isinstance(raw.get("results"), dict):
                    self.notes.append(f"warm cache {self.path} is another format: started afresh")
                else:
                    self.results = raw["results"]
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as e:
                self.notes.append(f"warm cache {self.path} unreadable ({type(e).__name__}): started afresh")

    def get(self, key: str) -> dict | None:
        return self.results.get(key)

    def put(self, key: str, case: str, seconds: float) -> None:
        self.results[key] = {"case": case, "seconds": round(seconds, 3), "at": time.time()}

    def drop(self, key: str) -> None:
        self.results.pop(key, None)

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_name(self.path.name + f".{os.getpid()}.tmp")
        tmp.write_text(json.dumps({"version": CACHE_VERSION, "results": self.results}, indent=1, sort_keys=True),
                       encoding="utf-8")
        os.replace(tmp, self.path)


# --------------------------------------------------------------------------- running a case

@dataclass(frozen=True)
class CaseOutcome:
    case: str
    mode: str
    status: str                        # PASS | WARM | FAIL | CUT | NOT_RUN
    reason: str
    key: str = ""
    seconds: float = 0.0               # the last run's (a WARM case: the cached run's)
    exit_code: int | None = None
    runs: int = 0                      # engine runs this gate made for the case
    cap: float = 0.0                   # the cap of the last run
    recut: bool = False                # cut once at the cap, then re-replayed at the recut cap
    regated: bool = False              # failed once, then run again before the lane could stop
    output: str = ""


@dataclass(frozen=True)
class LaneGate:
    lane: str
    verdict: str                       # YES | NO | NOT_RUN
    reason: str
    lane_key: str
    cases: tuple[CaseOutcome, ...]
    seconds: float
    cap: float                         # the load-scaled cap of a first run
    scale: float
    notes: tuple[str, ...] = ()
    jobs: int = 1                      # cases replayed at once
    nice: int = 0                      # the replays' niceness

    @property
    def ok(self) -> bool:
        return self.verdict == YES

    def count(self, status: str) -> int:
        return sum(1 for c in self.cases if c.status == status)

    @property
    def ran(self) -> int:
        return sum(1 for c in self.cases if c.runs)


_Run = _openers.EngineRun             # code None: killed at its cap (`cut`)


def _input_for(case: RegCase, base: Path, n: int) -> Path:
    if case.source == "opener":
        return _fixtures.build(case.fixture, base / f"in-{n}")
    return case.input


def _execute(m: _manifest.Manifest, case: RegCase, *, root: Path, g: _guard.Guard, base: Path, n: int,
             cap: float, profile, nice: int = 0) -> _Run:
    """One replay, run exactly as openers.arm runs an opener (openers.run_engine: guard, environment,
    process group), with its own cwd and its own fresh workdir. The workdir is made here, and must be new
    (FileExistsError, an OSError the caller names): run_engine accepts an existing one, and a re-replay or
    a re-gate must not pass on what the first run left behind."""
    work = base / f"work-{n}"
    work.mkdir()
    return _openers.run_input(m.id, _input_for(case, base, n), root=root, g=g, run_dir=base / f"run-{n}",
                              work=work, timeout=cap, profile=profile, via="adapt-gate", nice=nice)


def _excerpt(run: _Run) -> str:
    return _openers.excerpt(run.out, run.err)


def _judge(case: RegCase, run: _Run, cap: float, scale: float) -> tuple[str, str]:
    if run.cut:
        return CUT, f"cut at its {cap:.1f}s cap"
    if case.kind == "control":
        holds = [", ".join(k) for k in case.keys if k and all(e in run.out for e in k)]
        if holds:
            return FAIL, (f"the key [{holds[0]}] also holds on this neutral input, so it does not tell a solved "
                          "input from an unsolved one")
        return PASS, ""
    if run.code != 0:
        return FAIL, f"engine exited {run.code}"
    missing = [e for e in case.expect if e not in run.out]
    if missing:
        return FAIL, f"missing from output: {', '.join(missing)}"
    if case.within is not None and run.seconds > case.within * scale:
        return FAIL, (f"took {run.seconds:.2f}s, over its {case.within:g}s window"
                      + (f" (x{scale:.2f} for load)" if scale > 1 else ""))
    return PASS, ""


def _verdict(outs: list[CaseOutcome]) -> tuple[str, str]:
    bad = [o for o in outs if o.status in (FAIL, CUT)]
    if bad:
        return NO, "; ".join(f"{o.case} ({o.mode}): {o.reason}" for o in bad)
    held = [o for o in outs if o.status == NOT_RUN]
    if held:
        return NOT_RUN, "; ".join(f"{o.case}: {o.reason}" for o in held)
    return YES, ""


def gate(lane: str, *, root: Path | None = None, workdir: Path | None = None, cap: float = DEFAULT_CAP,
         warm: bool = True, regate: bool = True, recut: float = RECUT_MIN, guard: str | _guard.Guard = "auto",
         profile: _event.EventProfile | None = None, load: float | None = None, cpus: int | None = None,
         max_scale: float = DEFAULT_MAX_SCALE, keyer: Keyer | None = None, record: bool = True,
         jobs: int | str = 1, nice: int | None = None,
         idle: Callable[[], ContextManager] | None = None) -> LaneGate:
    """Replay the lane's regression set and say whether a timed mode may start on it (see the module
    docstring for the rules). `jobs`: cases replayed at once, or "auto" for the deadline-aware quiet
    check's policy (`clocks.replay_policy`, which also sets `nice` unless it is given). AdaptError for an
    unusable set or argument; GuardError when `guard="os"` is asked for where the OS sandbox is
    unavailable. `idle` (B-213) is a factory for the idle-machine
    lock (ctf.workreg.IdleLock): when given it is taken just before the first case actually replays and
    held until the last ends, so no other timing suite shares the host with this one's caps and windows.
    A gate where every case is reused warm (or not run) never takes it, as `run_gate` does."""
    if not (isinstance(recut, (int, float)) and recut >= RECUT_MIN):
        raise AdaptError(f"recut {recut!r}: a cap-cut case is re-replayed at no less than {RECUT_MIN:g}x the cap")
    if not (isinstance(cap, (int, float)) and cap > 0):
        raise AdaptError(f"cap {cap!r} must be a positive number of seconds")
    if not (jobs == "auto" or (isinstance(jobs, int) and not isinstance(jobs, bool) and jobs >= 1)):
        raise AdaptError(f"jobs {jobs!r}: a positive number of replays at once, or 'auto'")
    if nice is not None and (isinstance(nice, bool) or not isinstance(nice, int) or not 0 <= nice <= 20):
        raise AdaptError(f"nice {nice!r}: an integer from 0 to 20")
    root = _paths.repo_root() if root is None else Path(root)
    if workdir is None:
        try:
            workdir = _paths.workdir()
        except Exception as e:  # noqa: BLE001 - no event and no CTF_WORKDIR: say which
            raise AdaptError(f"no workdir for the lane gate: set CTF_WORKDIR or CTF_EVENT ({e})") from None
    workdir = Path(workdir)
    t0 = time.perf_counter()
    cases = regression_set(lane, root=root, workdir=workdir)
    keyer = keyer or Keyer(root)
    load = host_load() if load is None else float(load)
    cpus = (os.cpu_count() or 1) if cpus is None else int(cpus)
    first_cap, scale = scaled_wall(float(cap), float(max_scale), load, cpus)
    second_cap = first_cap * float(recut)
    cache = WarmCache(cache_path(lane, workdir))
    notes = list(cache.notes)
    if jobs == "auto":
        policy = _clocks.replay_policy(workdir, cpus=cpus)
        jobs = policy.jobs
        nice = policy.nice if nice is None else nice
        notes.append(f"replay {jobs} at a time at nice {nice}: {policy.reason}")
    nice = 0 if nice is None else nice
    g: _guard.Guard | None = guard if isinstance(guard, _guard.Guard) else None

    got: dict[int, CaseOutcome] = {}
    lane_parts: dict[int, str] = {}                    # the lane key's part of each case (day scoping off)
    todo: list[tuple[int, RegCase, _manifest.Manifest, str]] = []
    workdir.mkdir(parents=True, exist_ok=True)
    with ExitStack() as held, tempfile.TemporaryDirectory(dir=workdir, prefix="adapt-gate-") as tmp:
        base = Path(tmp)
        counter = iter(range(1, 1 << 30))
        lock = threading.Lock()
        locked = False
        for i, case in enumerate(cases):
            if not case.offline:
                got[i] = CaseOutcome(case.name, case.mode, NOT_RUN, case.reason or "not offline-armable")
                continue
            try:
                m = _runner.resolve(case.engine, root=root)
            except _runner.EngineError as e:
                got[i] = CaseOutcome(case.name, case.mode, FAIL, f"engine does not resolve: {e}")
                continue
            key = keyer.case_key(case, m)
            lane_parts[i] = keyer.lane_part_key(case, m, key)
            missing = _intake_engines.tool_missing(list(dict.fromkeys((*m.needs_tools, *case.needs_tools))))
            if missing:
                got[i] = CaseOutcome(case.name, case.mode, NOT_RUN, f"needs {', '.join(missing)} (not installed)", key)
                continue
            hit = cache.get(key) if warm else None
            if hit is not None:
                got[i] = CaseOutcome(case.name, case.mode, WARM, "", key, seconds=float(hit.get("seconds", 0.0)))
                continue
            if g is None:
                g = _guard.resolve(guard)
            why = _openers.os_sandbox_need(case, m)
            if why and not g.allows_spawn:
                got[i] = CaseOutcome(case.name, case.mode, NOT_RUN,
                                      f"{why}, so it needs the OS network sandbox; {g.reason}", key)
                continue
            todo.append((i, case, m, key))

        def replay(case: RegCase, m: _manifest.Manifest, key: str) -> CaseOutcome:
            """One stale case: its run, its recut or re-gate, its outcome. No shared state but the counter."""
            def once(c: float) -> tuple[_Run | None, str, str]:
                nonlocal locked
                with lock:
                    if idle is not None and not locked:
                        held.enter_context(idle())      # a timed replay is next: hold the idle lock from here
                        locked = True
                    n = next(counter)
                try:
                    r = _execute(m, case, root=root, g=g, base=base, n=n, cap=c, profile=profile, nice=nice)
                except _fixtures.FixtureError as e:
                    return None, FAIL, str(e)
                except OSError as e:
                    return None, FAIL, f"could not start the engine: {type(e).__name__}: {e}"
                st, why_ = _judge(case, r, c, scale)
                return r, st, why_

            run, status, reason = once(first_cap)
            runs, recut_used, regated, last_cap = 1, False, False, first_cap
            if status == CUT:
                first_reason = reason
                run, status, reason = once(second_cap)
                runs, recut_used, last_cap = runs + 1, True, second_cap
                if status == CUT:
                    reason = f"{first_reason}, and again on its re-replay at {second_cap:.1f}s ({recut:g}x)"
                elif status == FAIL:
                    reason = f"{first_reason}; on its re-replay at {second_cap:.1f}s: {reason}"
            elif status == FAIL and run is not None and regate:
                first_reason = reason
                run, status, reason = once(second_cap)
                runs, regated, last_cap = runs + 1, True, second_cap
                if status != PASS:
                    reason = f"{first_reason}; again on the re-gate: {reason}"
            return CaseOutcome(case.name, case.mode, status, reason, key,
                               seconds=run.seconds if run else 0.0, exit_code=run.code if run else None,
                               runs=runs, cap=last_cap, recut=recut_used, regated=regated,
                               output=_excerpt(run) if run else "")

        if jobs > 1 and len(todo) > 1:
            with ThreadPoolExecutor(max_workers=min(jobs, len(todo)), thread_name_prefix="adapt-gate") as ex:
                futs = {i: ex.submit(replay, case, m, key) for i, case, m, key in todo}
                done = {i: f.result() for i, f in futs.items()}
        else:
            done = {i: replay(case, m, key) for i, case, m, key in todo}
        for i, o in done.items():                      # the cache is written by this thread only
            if o.status == PASS and not o.regated:
                cache.put(o.key, o.case, o.seconds)
            elif o.status != PASS:
                cache.drop(o.key)
        got.update(done)
    cache.save()
    outs = [got[i] for i in sorted(got)]
    verdict, why_all = _verdict(outs)
    lk = _set_key((got[i].case, lane_parts.get(i, "")) for i in sorted(got))
    res = LaneGate(lane, verdict, why_all, lk, tuple(outs), time.perf_counter() - t0, first_cap, scale, tuple(notes),
                   jobs=jobs, nice=nice)
    if record:
        record_gate(res, workdir=workdir)
    return res


def prewarm(lanes, *, root: Path | None = None, workdir: Path | None = None, **kw) -> list[LaneGate]:
    """Run the warm gate for each lane ahead of the clock (before the first release, at a base CORRECT,
    when a live-fix file appears): stale cases run and their green results are cached; warm ones are
    reused. The first clock's gate then finds every unchanged case WARM."""
    root = _paths.repo_root() if root is None else Path(root)
    keyer = kw.pop("keyer", None) or Keyer(root)
    return [gate(lane, root=root, workdir=workdir, keyer=keyer, warm=True, **kw) for lane in lanes]


def watch(lanes, *, interval: float = 5.0, duration: float | None = None, root: Path | None = None,
          workdir: Path | None = None, on_gate=None, clock=time.monotonic, sleep=time.sleep, day_scoped: bool = True,
          **gate_kw) -> list[LaneGate]:
    """Prewarm on change: every `interval` seconds recompute each lane's key (a fresh dependency graph,
    so a new or edited file is seen) and run the warm gate for every lane whose key differs from the
    last one gated, starting with all of them. A live fix dropped into a lane folder is thus gated
    within one interval, before the next clock asks. Runs until `duration` seconds have passed (None:
    until interrupted). `on_gate(LaneGate)` is called after each gate. Returns every gate run."""
    if not (isinstance(interval, (int, float)) and interval > 0):
        raise AdaptError(f"interval {interval!r} must be a positive number of seconds")
    root = _paths.repo_root() if root is None else Path(root)
    last: dict[str, str] = {}
    out: list[LaneGate] = []
    end = None if duration is None else clock() + float(duration)
    while True:
        keyer = Keyer(root, day_scoped=day_scoped)
        for lane in lanes:
            key = current_lane_key(lane, root=root, workdir=workdir, keyer=keyer)
            if last.get(lane) == key:
                continue
            g = gate(lane, root=root, workdir=workdir, keyer=keyer, warm=True, **gate_kw)
            last[lane] = g.lane_key
            out.append(g)
            if on_gate is not None:
                on_gate(g)
        if end is not None and clock() >= end:
            return out
        sleep(interval)


def record_gate(res: LaneGate, *, workdir: Path | None = None) -> dict:
    """The `adapt.gate` ledger record of one gate (section 10)."""
    return _ledger.append(LEDGER_EVENT, workdir=workdir, lane=res.lane, verdict=res.verdict, lane_key=res.lane_key,
                          cases=len(res.cases), ran=res.ran, warm=res.count(WARM),
                          recut=sum(1 for c in res.cases if c.recut),
                          regated=sum(1 for c in res.cases if c.regated), not_run=res.count(NOT_RUN),
                          seconds=round(res.seconds, 3), scale=round(res.scale, 3), reason=res.reason,
                          jobs=res.jobs, nice=res.nice)


def current_lane_key(lane: str, *, root: Path | None = None, workdir: Path | None = None,
                     keyer: Keyer | None = None) -> str:
    """The lane key a gate run now would report, computed without running anything (day scoping off:
    see the module docstring)."""
    root = _paths.repo_root() if root is None else Path(root)
    cases = regression_set(lane, root=root, workdir=workdir)
    keyer = keyer or Keyer(root)
    rows = []
    for c in cases:
        try:
            k = keyer.lane_part_key(c, _runner.resolve(c.engine, root=root)) if c.offline else ""
        except _runner.EngineError:
            k = ""
        rows.append((c.name, k))
    return _set_key(rows)
