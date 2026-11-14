"""Engine manifests: one `<module>.manifest.toml` sidecar per engine (docs/CONTRACTS.md section 6).

    from ctf.engines import manifest
    ms = manifest.discover()                 # every sidecar under the engine roots; ManifestError if any is bad
    ms, problems = manifest.scan()           # the same, collecting problems instead of raising (lint uses it)
    m = manifest.load(path)                  # one file

A manifest is validated like an event profile: unknown keys are an error, required keys name
themselves, enums are checked, a boolean is never accepted where a number or string is asked.

Module paths in `entry` are dotted repo paths ("solvers.common.rsa_lattice:solve"). They are resolved
to a file by splitting on dots, so a lane folder with a dash ("solvers.metadata-forensics.x") works
even though it is not an importable package name; the runner loads engines by file, not by package.
"""
from __future__ import annotations

import os
import re
import shlex
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .. import paths

SUFFIX = ".manifest.toml"
# Folders (relative to the repo root) searched for sidecars. A sidecar elsewhere is not an engine.
ENGINE_ROOTS = ("solvers", "tools")

LANE_RE = re.compile(r"^[a-z][a-z0-9_-]*$")
ID_RE = re.compile(r"^[a-z][a-z0-9_]*\.[a-z0-9][a-z0-9_]*$")
FUNC_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
TAG_RE = re.compile(r"^[a-z0-9][a-z0-9_.+-]*$")
COST_CLASSES = ("cheap", "medium", "heavy")
STATUSES = ("active", "experimental", "plan-only", "retired")
FILE_MATCH_KINDS = ("magic", "ext", "name")
DEFAULT_PRIORITY = 50

_TOP_KEYS = {"id", "lane", "entry", "capabilities", "inputs", "needs_tools", "cost_class", "status", "routes",
             "intake"}
_REQUIRED = ("id", "lane", "entry")
_ROUTE_KEYS = {"category", "keywords", "files", "priority"}
# [intake] (B-002): how intake hands a challenge's files to the engine. Without it intake never runs it.
_INTAKE_KEYS = {"select", "run", "match", "args", "max_files", "timeout", "spawns", "originals"}
INTAKE_SELECT = ("route", "files")                                # when intake runs it
INTAKE_RUN = ("per-file", "all-files", "folder", "challenge")     # what it is given
INTAKE_PLACEHOLDERS = ("file", "files", "folder", "challenge", "out")
_PLACEHOLDER_RE = re.compile(r"\{([^{}]*)\}")


class ManifestError(ValueError):
    """A manifest is malformed. The message names the file and the dotted key."""


@dataclass(frozen=True)
class Route:
    category: tuple[str, ...] = ()
    keywords: tuple[str, ...] = ()
    files: tuple[str, ...] = ()
    priority: int | None = None          # None = not set in the file (lint treats that as ambiguous)

    @property
    def effective_priority(self) -> int:
        return DEFAULT_PRIORITY if self.priority is None else self.priority

    @property
    def matches_everything(self) -> bool:
        return not (self.category or self.keywords or self.files)


@dataclass(frozen=True)
class Entry:
    kind: str                            # "function" | "cli"
    module: str | None = None            # dotted repo path, function entries
    function: str | None = None
    argv: tuple[str, ...] = ()           # cli entries

    @property
    def is_python_cli(self) -> bool:
        return self.kind == "cli" and len(self.argv) >= 2 and self.argv[0] == "python"

    def target_file(self, root: Path) -> Path | None:
        """The file this entry runs: the module file, or the script of a `cli:python <script>` entry."""
        if self.kind == "function":
            base = root.joinpath(*self.module.split("."))
            for cand in (base.with_name(base.name + ".py"), base / "__init__.py"):
                if cand.is_file():
                    return cand
            return base.with_name(base.name + ".py")
        if self.is_python_cli:
            return root / self.argv[1]
        return None


@dataclass(frozen=True)
class IntakeSpec:
    """The engine's input adapter for intake (B-002): which files it takes and how they are passed."""
    run: str                             # per-file | all-files | folder | challenge
    select: str = "route"                # route: when the router routes the challenge here; files: on a match
    match: tuple[str, ...] = ()          # file matchers (route syntax) picking its input files
    args: tuple[str, ...] = ()           # argv after a cli entry, with {placeholders}
    max_files: int = 8                   # per-file: runs at most; all-files: files at most
    timeout: int = 30                    # seconds for one run
    spawns: bool = False                 # it starts other programs: needs the OS network sandbox
    originals: bool = False              # per-file: also the handout's files the sweep left out for size, by path


@dataclass(frozen=True)
class Manifest:
    id: str
    lane: str
    entry_raw: str
    entry: Entry
    path: Path                           # the .manifest.toml file
    capabilities: tuple[str, ...] = ()
    inputs: tuple[str, ...] = ()
    needs_tools: tuple[str, ...] = ()
    cost_class: str = "medium"
    status: str = "active"
    routes: tuple[Route, ...] = field(default_factory=tuple)
    intake: IntakeSpec | None = None     # None: intake lists it as routed but never runs it

    @property
    def module_path(self) -> Path:
        """The engine module beside the sidecar (`x.manifest.toml` -> `x.py`)."""
        return self.path.with_name(self.path.name[: -len(SUFFIX)] + ".py")

    @property
    def name(self) -> str:
        return self.id.split(".", 1)[1]

    @property
    def basename(self) -> str:
        return self.module_path.stem

    def rel_module(self, root: Path | None = None) -> str:
        root = paths.repo_root() if root is None else Path(root)
        try:
            return self.module_path.relative_to(root).as_posix()
        except ValueError:
            return str(self.module_path)

    def has(self, capability: str) -> bool:
        return capability in self.capabilities


@dataclass(frozen=True)
class Problem:
    path: Path
    message: str


def _err(path: Path, key: str, msg: str) -> ManifestError:
    return ManifestError(f"{path}: {key}: {msg}")


def _str(path, key, v, *, allow_empty=False) -> str:
    if not isinstance(v, str) or isinstance(v, bool):
        raise _err(path, key, f"expected a string, got {type(v).__name__}")
    if not allow_empty and not v.strip():
        raise _err(path, key, "must not be empty")
    return v


def _str_list(path, key, v, *, pattern: re.Pattern | None = None) -> tuple[str, ...]:
    if not isinstance(v, list):
        raise _err(path, key, f"expected a list of strings, got {type(v).__name__}")
    out = []
    for i, item in enumerate(v):
        s = _str(path, f"{key}[{i}]", item)
        if pattern is not None and not pattern.match(s):
            raise _err(path, f"{key}[{i}]", f"{s!r} does not match {pattern.pattern}")
        out.append(s)
    if len(set(out)) != len(out):
        raise _err(path, key, "duplicate entries")
    return tuple(out)


def _file_matchers(path, key, v) -> tuple[str, ...]:
    items = _str_list(path, key, v)
    for i, s in enumerate(items):
        kind, sep, rest = s.partition(":")
        if not sep or kind not in FILE_MATCH_KINDS or not rest:
            raise _err(path, f"{key}[{i}]", f"{s!r}: use one of " + ", ".join(f"{k}:<value>" for k in FILE_MATCH_KINDS))
        if kind == "ext" and not rest.startswith("."):
            raise _err(path, f"{key}[{i}]", f"{s!r}: an ext matcher starts with a dot (ext:.pcap)")
    return items


def parse_entry(path: Path, raw: str) -> Entry:
    raw = _str(path, "entry", raw)
    if raw.startswith("cli:"):
        try:
            argv = tuple(shlex.split(raw[4:]))
        except ValueError as e:
            raise _err(path, "entry", f"cli entry does not parse: {e}") from None
        if not argv:
            raise _err(path, "entry", "cli entry has no command")
        if argv[0] == "python" and len(argv) < 2:
            raise _err(path, "entry", "cli:python needs a script path")
        if argv[0] == "python" and (argv[1].startswith("/") or ".." in Path(argv[1]).parts):
            raise _err(path, "entry", "cli:python script must be a repo-relative path")
        return Entry("cli", argv=argv)
    mod, sep, fn = raw.partition(":")
    if not sep or not mod or not fn:
        raise _err(path, "entry", f"{raw!r}: expected 'module:function' or 'cli:<argv0 ...>'")
    parts = mod.split(".")
    if any(not p or not re.match(r"^[A-Za-z0-9_][A-Za-z0-9_-]*$", p) for p in parts):
        raise _err(path, "entry", f"{mod!r} is not a dotted repo path")
    if not FUNC_RE.match(fn):
        raise _err(path, "entry", f"{fn!r} is not a function name")
    return Entry("function", module=mod, function=fn)


def _bounded_int(path, key, v, default, lo, hi) -> int:
    if v is None:
        return default
    if isinstance(v, bool) or not isinstance(v, int):
        raise _err(path, key, f"expected an integer {lo}-{hi}, got {type(v).__name__}")
    if not lo <= v <= hi:
        raise _err(path, key, f"{v} outside {lo}-{hi}")
    return v


_DEFAULT_INTAKE_ARGS = {"per-file": ("{file}",), "all-files": ("{files}",), "folder": ("{folder}",),
                        "challenge": ()}


def parse_intake(path: Path, raw, entry: Entry, capabilities: tuple[str, ...] = ()) -> IntakeSpec:
    """The [intake] table: validated against the entry kind, so a bad adapter fails at discovery."""
    if not isinstance(raw, dict):
        raise _err(path, "intake", "expected a table ([intake])")
    unk = sorted(set(raw) - _INTAKE_KEYS)
    if unk:
        raise _err(path, f"intake.{unk[0]}", "unknown key")
    if "run" not in raw:
        raise _err(path, "intake.run", "required key missing (" + " | ".join(INTAKE_RUN) + ")")
    run = _str(path, "intake.run", raw["run"])
    if run not in INTAKE_RUN:
        raise _err(path, "intake.run", f"{run!r} not one of {', '.join(INTAKE_RUN)}")
    select = _str(path, "intake.select", raw.get("select", "route"))
    if select not in INTAKE_SELECT:
        raise _err(path, "intake.select", f"{select!r} not one of {', '.join(INTAKE_SELECT)}")
    if "library" in capabilities:
        raise _err(path, "intake", "a library engine is import-only; intake cannot run it")
    if entry.kind == "function" and run != "challenge":
        raise _err(path, "intake.run", f"{run!r}: a module:function entry takes the challenge folder "
                                        "(run = \"challenge\")")
    if entry.kind == "cli" and run == "challenge":
        raise _err(path, "intake.run", "\"challenge\" is the module:function contract; a cli engine "
                                       "takes per-file, all-files or folder")
    match = _file_matchers(path, "intake.match", raw.get("match", []))
    if not match and (run in ("per-file", "all-files") or select == "files"):
        raise _err(path, "intake.match", f"required for run = {run!r} / select = {select!r}: "
                                         "which files the engine takes")
    if "args" in raw:
        if entry.kind == "function":
            raise _err(path, "intake.args", "a module:function entry takes no argv")
        if not isinstance(raw["args"], list):
            raise _err(path, "intake.args", f"expected a list of strings, got {type(raw['args']).__name__}")
        args = tuple(_str(path, f"intake.args[{i}]", a) for i, a in enumerate(raw["args"]))
    else:
        args = _DEFAULT_INTAKE_ARGS[run]
    used = set()
    for i, a in enumerate(args):
        for name in _PLACEHOLDER_RE.findall(a):
            if name not in INTAKE_PLACEHOLDERS:
                raise _err(path, f"intake.args[{i}]", f"{{{name}}} is not one of "
                           + ", ".join("{" + p + "}" for p in INTAKE_PLACEHOLDERS))
            used.add(name)
        if "{files}" in a and a != "{files}":
            raise _err(path, f"intake.args[{i}]", "{files} expands to several arguments: use it alone")
    if "file" in used and run != "per-file":
        raise _err(path, "intake.args", "{file} needs run = \"per-file\"")
    if "files" in used and run != "all-files":
        raise _err(path, "intake.args", "{files} needs run = \"all-files\"")
    need = {"per-file": {"file"}, "all-files": {"files"}, "folder": {"folder", "challenge"}}.get(run)
    if need and not need & used:
        raise _err(path, "intake.args", f"run = {run!r} but no " + " or ".join("{" + n + "}" for n in sorted(need))
                   + " passes the input to the engine")
    spawns = raw.get("spawns", False)
    if not isinstance(spawns, bool):
        raise _err(path, "intake.spawns", f"expected true or false, got {type(spawns).__name__}")
    originals = raw.get("originals", False)
    if not isinstance(originals, bool):
        raise _err(path, "intake.originals", f"expected true or false, got {type(originals).__name__}")
    if originals and run != "per-file":
        raise _err(path, "intake.originals", "needs run = \"per-file\": a file the sweep left out is passed as {file}")
    return IntakeSpec(run=run, select=select, match=match, args=args,
                      max_files=_bounded_int(path, "intake.max_files", raw.get("max_files"), 8, 1, 64),
                      timeout=_bounded_int(path, "intake.timeout", raw.get("timeout"), 30, 1, 600),
                      spawns=spawns, originals=originals)


def parse(data: dict, path: Path) -> Manifest:
    path = Path(path)
    if not isinstance(data, dict):
        raise _err(path, "(top)", "expected a table")
    unknown = sorted(set(data) - _TOP_KEYS)
    if unknown:
        raise _err(path, unknown[0], "unknown key" + (f" (also: {', '.join(unknown[1:])})" if unknown[1:] else ""))
    for k in _REQUIRED:
        if k not in data:
            raise _err(path, k, "required key missing")
    mid = _str(path, "id", data["id"])
    if not ID_RE.match(mid):
        raise _err(path, "id", f"{mid!r}: use <lane>.<name>, lower_snake")
    lane = _str(path, "lane", data["lane"])
    if not LANE_RE.match(lane):
        raise _err(path, "lane", f"{lane!r}: lower-case folder or lane name")
    entry_raw = data["entry"]
    entry = parse_entry(path, entry_raw)
    cost = _str(path, "cost_class", data.get("cost_class", "medium"))
    if cost not in COST_CLASSES:
        raise _err(path, "cost_class", f"{cost!r} not one of {', '.join(COST_CLASSES)}")
    status = _str(path, "status", data.get("status", "active"))
    if status not in STATUSES:
        raise _err(path, "status", f"{status!r} not one of {', '.join(STATUSES)}")
    raw_routes = data.get("routes", [])
    if not isinstance(raw_routes, list):
        raise _err(path, "routes", "expected an array of tables ([[routes]])")
    routes = []
    for i, r in enumerate(raw_routes):
        key = f"routes[{i}]"
        if not isinstance(r, dict):
            raise _err(path, key, "expected a table")
        unk = sorted(set(r) - _ROUTE_KEYS)
        if unk:
            raise _err(path, f"{key}.{unk[0]}", "unknown key")
        prio = r.get("priority")
        if prio is not None:
            if isinstance(prio, bool) or not isinstance(prio, int):
                raise _err(path, f"{key}.priority", f"expected an integer 0-100, got {type(prio).__name__}")
            if not 0 <= prio <= 100:
                raise _err(path, f"{key}.priority", f"{prio} outside 0-100")
        kws = _str_list(path, f"{key}.keywords", r.get("keywords", []))
        for j, k in enumerate(kws):
            if k != k.lower():
                raise _err(path, f"{key}.keywords[{j}]", f"{k!r}: keywords are lower-case substrings")
        cats = _str_list(path, f"{key}.category", r.get("category", []))
        for j, c in enumerate(cats):
            if c != c.strip().lower():
                raise _err(path, f"{key}.category[{j}]", f"{c!r}: categories are lower-case canonical names")
        routes.append(Route(category=cats, keywords=kws,
                            files=_file_matchers(path, f"{key}.files", r.get("files", [])), priority=prio))
    caps = _str_list(path, "capabilities", data.get("capabilities", []), pattern=TAG_RE)
    return Manifest(
        id=mid, lane=lane, entry_raw=entry_raw, entry=entry, path=path,
        capabilities=caps,
        inputs=_str_list(path, "inputs", data.get("inputs", [])),
        needs_tools=_str_list(path, "needs_tools", data.get("needs_tools", [])),
        cost_class=cost, status=status, routes=tuple(routes),
        intake=parse_intake(path, data["intake"], entry, caps) if "intake" in data else None,
    )


def load(path: Path) -> Manifest:
    path = Path(path)
    try:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    except tomllib.TOMLDecodeError as e:
        raise ManifestError(f"{path}: not valid TOML: {e}") from None
    return parse(data, path)


_FILES_CACHE: dict[str, tuple[tuple, list[Path]]] = {}


def _dirs_unchanged(sig: tuple) -> bool:
    try:
        return all(os.stat(d).st_mtime_ns == m for d, m in sig)
    except FileNotFoundError:
        return False


def manifest_files(root: Path | None = None) -> list[Path]:
    """Every sidecar under the engine roots, sorted.

    The listing is cached per root against the mtimes of every folder walked (adding, removing or
    renaming a file changes its folder's mtime), so a repeat call costs a few stats, not a walk."""
    root = paths.repo_root() if root is None else Path(root)
    if not root.is_dir():
        return []
    key = str(root)
    hit = _FILES_CACHE.get(key)
    if hit and _dirs_unchanged(hit[0]):
        return list(hit[1])
    out, sig = [], []
    for sub in ENGINE_ROOTS:
        base = root / sub
        if not base.is_dir():
            sig.append((str(root), os.stat(root).st_mtime_ns))     # the root appears if it is created
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            sig.append((dirpath, os.stat(dirpath).st_mtime_ns))
            dirnames[:] = sorted(d for d in dirnames if not d.startswith((".", "__pycache__")))
            out.extend(Path(dirpath) / f for f in filenames if f.endswith(SUFFIX))
    out.sort()
    _FILES_CACHE[key] = (tuple(sig), out)
    return list(out)


def scan(root: Path | None = None) -> tuple[list[Manifest], list[Problem]]:
    ms, problems = [], []
    for p in manifest_files(root):
        try:
            ms.append(load(p))
        except ManifestError as e:
            problems.append(Problem(p, str(e)))
    return ms, problems


_CACHE: dict[str, tuple[tuple, list[Manifest]]] = {}


def discover(root: Path | None = None) -> list[Manifest]:
    """All manifests, sorted by id. Raises ManifestError naming every bad file, or a duplicate id.

    Cached per root on the (path, mtime) signature of the sidecars, so repeated triage calls in one
    process do not re-parse hundreds of files."""
    root = paths.repo_root() if root is None else Path(root)
    files = manifest_files(root)
    sig = tuple((str(p), p.stat().st_mtime_ns) for p in files)
    hit = _CACHE.get(str(root))
    if hit and hit[0] == sig:
        return list(hit[1])
    ms, problems = [], []
    for p in files:
        try:
            ms.append(load(p))
        except ManifestError as e:
            problems.append(str(e))
    seen: dict[str, Path] = {}
    for m in ms:
        if m.id in seen:
            problems.append(f"{m.path}: id: {m.id!r} already used by {seen[m.id]}")
        seen.setdefault(m.id, m.path)
    if problems:
        raise ManifestError(f"{len(problems)} bad engine manifest(s):\n  " + "\n  ".join(problems))
    ms.sort(key=lambda m: m.id)
    _CACHE[str(root)] = (sig, ms)
    return list(ms)


def sidecar_for(module: Path) -> Path:
    module = Path(module)
    return module.with_name(module.stem + SUFFIX)
