"""tests/gate.toml: what the gate treats as a test file, an import root, a global or inert input, a
tree-scanning test, a lane, and how long a file may run.

    version = 1
    tests   = ["tests/test_*.py"]            test files (globs, repo-relative)
    roots   = ["", "solvers/common", ...]    import roots besides each file's own folder ("" = repo root)
    global  = ["conftest.py", ...]           inputs of every test: a change runs everything; in every warm key
    inert   = ["docs/**", "*.md"]            a change no test maps to selects nothing (instead of a full run)
    basename_max = 8                         a bare file name referenced in code maps to at most this many files
    env     = ["CTF_EVENT", ...]             environment knobs that enter every warm key
    no_warm = ["tests/real/**"]              test files whose green result is never reused
    not_run_ok = ["live"]                    not-run kinds a strict gate run accepts (B-196, gate/notrun.py)

    [wall]
    base_seconds = 600                       a file's wall on an idle host
    max_scale    = 4.0                       the wall scales with load1/cpus, between 1 and this

    [[scan]]                                 tests that read the tree rather than import it
    why    = "..."
    tests  = ["tests/test_single_sources.py"]
    inputs = ["**/*.py"]

    [lanes]
    web = ["solvers/web/**"]                 a test is in a lane when the file itself or what it imports or
                                             names directly matches one of these globs ...
    core = ["ctf/**", "!ctf/paths.py"]       ... and a "!glob" of the lane does not match that file (B-153:
                                             a hub every test imports does not put every test in the lane)

    [budget]                                 B-153: a lane gate's time budget (ctf/gate/budget.py)
    lane_seconds = 300                       default for every lane; at most 300 (5 minutes)
    full_only = ["tests/test_slow.py"]       test files a lane gate never runs: listed as left to the full
                                             and pre-arm gates on every lane run, plan and estimate
    [budget.lanes]
    binary = 240                             a tighter budget for one lane (also at most 300)

    baseline = "tests/gate_baseline.toml"    B-153: the tracked baseline ledger (ctf/gate/baseline.py)

    [[prearm]]                               B-153: preflight commands of `ctf gate prearm`, each run as
    name = "requirements"                    <python> <argv...> in the checkout; exit 0 = ok
    argv = ["tools/requirements_gen.py", "--check"]

Glob rules: `*` matches within one path segment, `**` any number of segments, `?` one character. A pattern
with no `/` also matches a file's base name anywhere (gitignore style). Every key above is required except
basename_max, env, no_warm, not_run_ok, scan, lanes, budget (absent: 300 s for every lane), baseline and prearm; an
unknown key is an error, so a typo never silently does nothing. In [lanes] only, a glob starting with
`!` excludes the files it matches from the lane (it never adds one).
"""
from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from . import GateError

CONFIG_NAME = "tests/gate.toml"
_TOP_KEYS = {"version", "tests", "roots", "global", "inert", "basename_max", "env", "no_warm", "not_run_ok", "wall", "scan",
             "lanes", "budget", "baseline", "prearm"}
_WALL_KEYS = {"base_seconds", "max_scale"}
_SCAN_KEYS = {"why", "tests", "inputs"}
_BUDGET_KEYS = {"lane_seconds", "lanes", "full_only"}
_PREARM_KEYS = {"name", "argv"}
MAX_LANE_SECONDS = 300.0            # five minutes: a longer gate is the pre-arm full gate (B-153)
_LANE_NAME = re.compile(r"[a-z][a-z0-9_-]*\Z")


@lru_cache(maxsize=512)
def glob_re(pattern: str) -> re.Pattern:
    out, i = [], 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("".join(out) + r"\Z")


def matches(rel: str, patterns) -> bool:
    """True when the repo-relative path `rel` matches any of the globs."""
    base = rel.rsplit("/", 1)[-1]
    for p in patterns:
        rx = glob_re(p)
        if rx.match(rel) or ("/" not in p and rx.match(base)):
            return True
    return False


@dataclass(frozen=True)
class ScanRule:
    why: str
    tests: tuple[str, ...]
    inputs: tuple[str, ...]


@dataclass(frozen=True)
class GateConfig:
    path: Path
    tests: tuple[str, ...]
    roots: tuple[str, ...]
    global_inputs: tuple[str, ...]
    inert: tuple[str, ...]
    basename_max: int = 8
    env: tuple[str, ...] = ()
    no_warm: tuple[str, ...] = ()
    not_run_ok: tuple[str, ...] = ()
    wall_base: float = 600.0
    wall_max_scale: float = 4.0
    scan: tuple[ScanRule, ...] = ()
    lanes: dict = field(default_factory=dict)
    lane_budget: float = MAX_LANE_SECONDS
    lane_budgets: dict = field(default_factory=dict)
    full_only: tuple[str, ...] = ()     # B-153: test globs a lane gate leaves to the full gate
    baseline: str = ""
    prearm: tuple = ()                  # ((name, (argv, ...)), ...)

    def is_test(self, rel: str) -> bool:
        return matches(rel, self.tests)

    def is_global(self, rel: str) -> bool:
        return matches(rel, self.global_inputs)

    def is_inert(self, rel: str) -> bool:
        return matches(rel, self.inert)

    def is_full_only(self, rel: str) -> bool:
        return matches(rel, self.full_only)


def _strs(d: dict, key: str, where: str, *, required: bool = True) -> tuple[str, ...]:
    if key not in d:
        if required:
            raise GateError(f"{where}: missing required key {key!r}")
        return ()
    v = d[key]
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        raise GateError(f"{where}: {key!r} must be a list of strings")
    for x in v:
        if x.startswith("/") or ".." in x.split("/"):
            raise GateError(f"{where}: {key!r} entry {x!r} must be repo-relative")
    return tuple(v)


def load(root: Path, path: Path | None = None) -> GateConfig:
    """Read and validate the gate config (default <root>/tests/gate.toml). Raises GateError naming the
    problem: a missing file, a TOML error, a missing or unknown key, a bad value."""
    path = Path(path) if path else Path(root) / CONFIG_NAME
    if not path.is_file():
        raise GateError(f"gate config not found: {path} (the gate needs its map; see ctf/gate/config.py)")
    try:
        d = tomllib.loads(path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as e:
        raise GateError(f"{path}: not valid TOML: {e}") from e
    where = str(path)
    unknown = set(d) - _TOP_KEYS
    if unknown:
        raise GateError(f"{where}: unknown key(s) {sorted(unknown)}")
    if d.get("version") != 1:
        raise GateError(f"{where}: version must be 1, got {d.get('version')!r}")
    tests = _strs(d, "tests", where)
    if not tests:
        raise GateError(f"{where}: 'tests' is empty")
    roots = _strs(d, "roots", where)
    glob_ = _strs(d, "global", where)
    inert = _strs(d, "inert", where)
    env_keys = _strs(d, "env", where, required=False)
    for k in env_keys:
        if not k.startswith("CTF_"):
            raise GateError(f"{where}: env knob {k!r} is not a CTF_ name")
    no_warm = _strs(d, "no_warm", where, required=False)
    not_run_ok = _strs(d, "not_run_ok", where, required=False)
    from .notrun import ANY, KINDS
    for k in not_run_ok:
        if k not in KINDS:
            raise GateError(f"{where}: not_run_ok kind {k!r} is not one of {', '.join(KINDS)}"
                            + (f" ({ANY!r} is for one run, --allow-not-run, never the config)" if k == ANY else ""))
    bmax = d.get("basename_max", 8)
    if not isinstance(bmax, int) or isinstance(bmax, bool) or bmax < 1:
        raise GateError(f"{where}: basename_max must be a positive integer")
    wall = d.get("wall")
    if not isinstance(wall, dict):
        raise GateError(f"{where}: missing required table [wall]")
    if set(wall) - _WALL_KEYS or _WALL_KEYS - set(wall):
        raise GateError(f"{where}: [wall] needs exactly {sorted(_WALL_KEYS)}, got {sorted(wall)}")
    base, scale = wall["base_seconds"], wall["max_scale"]
    for name, v in (("base_seconds", base), ("max_scale", scale)):
        if isinstance(v, bool) or not isinstance(v, (int, float)) or v <= 0:
            raise GateError(f"{where}: [wall] {name} must be a positive number")
    if scale < 1:
        raise GateError(f"{where}: [wall] max_scale must be at least 1")
    rules = []
    scan = d.get("scan", [])
    if not isinstance(scan, list):
        raise GateError(f"{where}: 'scan' must be an array of tables ([[scan]])")
    for i, r in enumerate(scan):
        w = f"{where} [[scan]] #{i + 1}"
        if not isinstance(r, dict) or set(r) != _SCAN_KEYS:
            raise GateError(f"{w}: needs exactly {sorted(_SCAN_KEYS)}")
        if not isinstance(r["why"], str) or not r["why"].strip():
            raise GateError(f"{w}: 'why' must say why these tests read the tree")
        rt, ri = _strs(r, "tests", w), _strs(r, "inputs", w)
        if not rt or not ri:
            raise GateError(f"{w}: 'tests' and 'inputs' must be non-empty")
        rules.append(ScanRule(r["why"], rt, ri))
    lanes_raw = d.get("lanes", {})
    if not isinstance(lanes_raw, dict):
        raise GateError(f"{where}: [lanes] must be a table")
    lanes = {}
    for name, globs in lanes_raw.items():
        if not _LANE_NAME.match(name):
            raise GateError(f"{where}: bad lane name {name!r}")
        lanes[name] = _strs(lanes_raw, name, f"{where} [lanes]")
        if not lanes[name]:
            raise GateError(f"{where}: lane {name!r} has no globs")
        bad = [g for g in lanes[name] if g in ("!", "") or g.startswith("!!")]
        if bad:
            raise GateError(f"{where}: lane {name!r} has an empty or doubled exclusion {bad[0]!r}")
        if all(g.startswith("!") for g in lanes[name]):
            raise GateError(f"{where}: lane {name!r} has only \"!\" exclusions; it needs a glob to include")
    lane_budget, lane_budgets, full_only = _budget(d.get("budget"), lanes, where)
    baseline = d.get("baseline", "")
    if not isinstance(baseline, str) or (baseline and (baseline.startswith("/") or ".." in baseline.split("/"))):
        raise GateError(f"{where}: 'baseline' must be a repo-relative path to the baseline ledger")
    return GateConfig(path=path, tests=tests, roots=roots, global_inputs=glob_, inert=inert, basename_max=bmax,
                      env=env_keys, no_warm=no_warm, not_run_ok=not_run_ok, wall_base=float(base), wall_max_scale=float(scale),
                      scan=tuple(rules), lanes=lanes, lane_budget=lane_budget, lane_budgets=lane_budgets,
                      full_only=full_only, baseline=baseline, prearm=_prearm(d.get("prearm", []), where))


def _seconds(v, what: str, where: str) -> float:
    if isinstance(v, bool) or not isinstance(v, (int, float)) or v <= 0:
        raise GateError(f"{where}: {what} must be a positive number of seconds")
    if v > MAX_LANE_SECONDS:
        raise GateError(f"{where}: {what} = {v} is over {MAX_LANE_SECONDS:.0f}s: a lane gate must fit in five "
                        f"minutes; a longer gate is the pre-arm full gate (ctf gate prearm)")
    return float(v)


def lane_matches(rel: str, globs) -> bool:
    """True when `rel` matches one of a lane's globs and none of its "!glob" exclusions."""
    include = [g for g in globs if not g.startswith("!")]
    exclude = [g[1:] for g in globs if g.startswith("!")]
    return matches(rel, include) and not matches(rel, exclude)


def _budget(raw, lanes: dict, where: str) -> tuple[float, dict, tuple]:
    """[budget]: (default lane seconds, {lane: seconds}, full-only test globs). Absent = the 300 s default
    for every lane and no full-only file."""
    if raw is None:
        return MAX_LANE_SECONDS, {}, ()
    if not isinstance(raw, dict):
        raise GateError(f"{where}: [budget] must be a table")
    unknown = set(raw) - _BUDGET_KEYS
    if unknown:
        raise GateError(f"{where}: [budget] unknown key(s) {sorted(unknown)}")
    if "lane_seconds" not in raw:
        raise GateError(f"{where}: [budget] needs lane_seconds")
    default = _seconds(raw["lane_seconds"], "[budget] lane_seconds", where)
    per = raw.get("lanes", {})
    if not isinstance(per, dict):
        raise GateError(f"{where}: [budget.lanes] must be a table")
    out = {}
    for name, v in per.items():
        if name not in lanes:
            raise GateError(f"{where}: [budget.lanes] names {name!r}, which is not a lane in [lanes]")
        out[name] = _seconds(v, f"[budget.lanes] {name}", where)
    full_only = _strs(raw, "full_only", f"{where} [budget]", required=False)
    if any(not g for g in full_only):
        raise GateError(f"{where}: [budget] full_only has an empty glob")
    return default, out, full_only


def _prearm(raw, where: str) -> tuple:
    """[[prearm]]: ((name, argv), ...), each run by `ctf gate prearm` as <python> <argv...>."""
    if not isinstance(raw, list):
        raise GateError(f"{where}: 'prearm' must be an array of tables ([[prearm]])")
    out, seen = [], set()
    for i, r in enumerate(raw):
        w = f"{where} [[prearm]] #{i + 1}"
        if not isinstance(r, dict) or set(r) != _PREARM_KEYS:
            raise GateError(f"{w}: needs exactly {sorted(_PREARM_KEYS)}")
        name, argv = r["name"], r["argv"]
        if not isinstance(name, str) or not _LANE_NAME.match(name):
            raise GateError(f"{w}: name must be a short lower-case word, got {name!r}")
        if name in seen:
            raise GateError(f"{w}: duplicate name {name!r}")
        seen.add(name)
        if not isinstance(argv, list) or not argv or not all(isinstance(a, str) and a for a in argv):
            raise GateError(f"{w}: argv must be a non-empty list of strings (run as <python> <argv...>)")
        out.append((name, tuple(argv)))
    return tuple(out)
