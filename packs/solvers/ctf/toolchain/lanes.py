"""The per-lane environment (B-188): the env-check a lane's agent runs first, and its exports.

    from ctf.toolchain import lanes
    rep = lanes.check("binary")                 # EnvReport: modules, binaries, assets, venv pins
    rep.passed; rep.problems()                  # required items that are not ok
    values, prepend = lanes.exports()           # {VAR: value}, [dirs to put in front of PATH]

Why: fresh agents hit ModuleNotFoundError and command-not-found from an environment nobody had
checked (hundreds of threads in one event), then lost turns to PYTHONPATH juggling and absolute
interpreter paths. The master keeps ONE pinned venv (requirements.in is the single install source, R-14),
so a lane does not get a venv of its own; it gets a check of that venv against what the lane needs, and
the exports that make a shell see what the engines see.

What a lane needs:

  modules  every third-party module the lane's engines import, found by reading their source (ast),
           following the repo's own modules they import (the engine sys.path, ctf.engines.layout). An
           import at the top of a module, reached only through top-of-module imports, is `required`
           (the engine cannot even load without it); one inside a function, a try or an if is optional.
           Plus the lane's `modules` in tools/lanes.toml (required) and its engines' `py:` needs_tools.
  bins     the lane's `bins` (required) and the non-py needs_tools of its active engines (advisory).
  assets   the lane's `assets` (tools/assets.toml; required).
  pins     tools/venv_pins.py: every requirements.in pin installed at its version (required).

Modules are looked up with `<python> -I` (importlib.util.find_spec of each top-level name: nothing is
imported), so the check is about the interpreter the lane runs, not the one running the check.
"""
from __future__ import annotations

import ast
import json
import os
import shutil
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from .. import paths
from . import assets as _assets

SPECS_REL = Path("tools") / "lanes.toml"
KINDS = ("module", "bin", "asset", "pins", "source")
FIND_TIMEOUT = 60.0
PINS_TIMEOUT = 120.0
_SPEC_KEYS = {"modules", "bins", "assets", "image", "note"}
_FIND = ("import importlib.util, json, sys\n"
         "out = {}\n"
         "for n in json.loads(sys.argv[1]):\n"
         "    try:\n"
         "        out[n] = importlib.util.find_spec(n) is not None\n"
         "    except (ImportError, ValueError):\n"
         "        out[n] = False\n"
         "print(json.dumps(out))\n")


class LaneError(ValueError):
    """An unknown lane, an invalid lanes.toml, or a module lookup that did not answer."""


@dataclass(frozen=True)
class LaneSpec:
    lane: str
    modules: tuple[str, ...] = ()
    bins: tuple[str, ...] = ()
    assets: tuple[str, ...] = ()
    image: str | None = None            # the toolchain image for what the host does not carry
    note: str = ""


@dataclass(frozen=True)
class ImportUse:
    module: str
    required_by: tuple[str, ...] = ()    # engine files that cannot load without it
    optional_by: tuple[str, ...] = ()    # engine files that import it lazily or guarded


@dataclass(frozen=True)
class Item:
    kind: str
    name: str
    required: bool
    ok: bool
    detail: str = ""
    fix: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "name": self.name, "required": self.required, "ok": self.ok,
                "detail": self.detail, "fix": self.fix}

    def line(self) -> str:
        state = "OK" if self.ok else ("MISSING" if self.required else "absent")
        head = f"{state:<8} {self.kind:<6} {self.name}" + ("" if self.required else " (optional)")
        return head + (f": {self.detail}" if self.detail else "") + \
            (f"\n    fix: {self.fix}" if self.fix and not self.ok else "")


@dataclass(frozen=True)
class EnvReport:
    lane: str
    python: str
    items: tuple[Item, ...]
    image: str | None = None

    def problems(self) -> list[Item]:
        return [i for i in self.items if i.required and not i.ok]

    @property
    def passed(self) -> bool:
        return not self.problems()

    def to_dict(self) -> dict[str, Any]:
        return {"lane": self.lane, "python": self.python, "passed": self.passed, "image": self.image,
                "items": [i.to_dict() for i in self.items]}


# ------------------------------------------------------------------------------------------ specs

def specs_path(root: Path | None = None) -> Path:
    return (paths.repo_root() if root is None else Path(root)) / SPECS_REL


def parse_specs(data: Mapping[str, Any], src: str = "lanes.toml") -> dict[str, LaneSpec]:
    if set(data) - {"lane"}:
        raise LaneError(f"{src}: unknown top-level key(s) {sorted(set(data) - {'lane'})}")
    out = {}
    for lane, r in (data.get("lane") or {}).items():
        where = f"{src}: lane {lane!r}"
        if not isinstance(r, dict):
            raise LaneError(f"{where}: not a table")
        unknown = set(r) - _SPEC_KEYS
        if unknown:
            raise LaneError(f"{where}: unknown key(s) {sorted(unknown)}")
        lists = {}
        for k in ("modules", "bins", "assets"):
            v = r.get(k, [])
            if not isinstance(v, list) or not all(isinstance(x, str) and x for x in v) or len(set(v)) != len(v):
                raise LaneError(f"{where}: {k} must be a list of distinct non-empty strings")
            lists[k] = tuple(v)
        bad = [m for m in lists["modules"] if "." in m]
        if bad:
            raise LaneError(f"{where}: modules are top-level import names, not {bad}")
        image = r.get("image")
        if image is not None and not (isinstance(image, str) and image):
            raise LaneError(f"{where}: image must be an image name from tools/images.toml")
        out[lane] = LaneSpec(lane, lists["modules"], lists["bins"], lists["assets"], image, str(r.get("note", "")))
    return out


def load_specs(path: Path | None = None) -> dict[str, LaneSpec]:
    p = specs_path() if path is None else Path(path)
    try:
        data = tomllib.loads(p.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise LaneError(f"{p}: lane spec file not found") from None
    except tomllib.TOMLDecodeError as e:
        raise LaneError(f"{p}: not valid TOML: {e}") from None
    return parse_specs(data, str(p))


def known_lanes(root: Path | None = None) -> list[str]:
    from ..engines import layout
    return layout.lanes(root)


# ---------------------------------------------------------------------------------------- imports

def _search_dirs(root: Path) -> list[Path]:
    from ..engines import layout
    return [Path(d) for d in layout.sys_path(root)]


def _is_local(top: str, dirs: Sequence[Path]) -> bool:
    return any((d / f"{top}.py").is_file() or (d / top).is_dir() for d in dirs)


def _local_files(dotted: str, dirs: Sequence[Path], extra: Sequence[str] = ()) -> list[Path]:
    """The repo files a dotted import names (the module, a package __init__, or a sub-module named in
    `from x import y`)."""
    out = []
    for name in [f"{dotted}.{e}" for e in extra] + [dotted]:
        parts = name.split(".")
        for d in dirs:
            base = d.joinpath(*parts)
            for cand in (base.with_name(base.name + ".py"), base / "__init__.py"):
                if cand.is_file():
                    out.append(cand)
                    break
            else:
                continue
            break
    return out


def _imports_of(tree: ast.Module) -> list[tuple[ast.AST, bool]]:
    """(import node, at the top of the module) for every import statement."""
    top = {id(n) for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))}
    return [(n, id(n) in top) for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))]


def scan_imports(files: Sequence[Path], root: Path | None = None) -> tuple[dict[str, ImportUse], list[str]]:
    """({third-party top-level module: ImportUse}, [files that did not parse]) for the given engine
    files, following the repo modules they import. Standard-library modules are left out."""
    root = paths.repo_root() if root is None else Path(root)
    dirs = _search_dirs(root)
    stdlib = set(sys.stdlib_module_names) | {"__future__", "__main__"}
    cache: dict[Path, ast.Module | None] = {}
    unparsed: list[str] = []
    req: dict[str, set[str]] = {}
    opt: dict[str, set[str]] = {}

    def tree_of(p: Path) -> ast.Module | None:
        if p not in cache:
            try:
                cache[p] = ast.parse(p.read_bytes(), filename=str(p))
            except (SyntaxError, ValueError, OSError):
                cache[p] = None
                unparsed.append(_rel(p, root))
        return cache[p]

    for eng in files:
        origin = _rel(eng, root)
        best: dict[Path, bool] = {}
        queue: list[tuple[Path, bool]] = [(Path(eng), True)]
        while queue:
            f, hard = queue.pop()
            if f in best and (best[f] or not hard):
                continue
            best[f] = hard
            tree = tree_of(f)
            if tree is None:
                continue
            for node, at_top in _imports_of(tree):
                h = hard and at_top
                if isinstance(node, ast.ImportFrom) and node.level:
                    base = f.parent
                    for _ in range(node.level - 1):
                        base = base.parent
                    mod = (node.module or "").split(".") if node.module else []
                    names = [a.name for a in node.names]
                    tgt = base.joinpath(*mod) if mod else base
                    for cand in [tgt.with_name(tgt.name + ".py"), tgt / "__init__.py",
                                 *[tgt / f"{n}.py" for n in names]]:
                        if cand.is_file():
                            queue.append((cand, h))
                    continue
                if isinstance(node, ast.Import):
                    targets = [(a.name, ()) for a in node.names]
                else:
                    targets = [(node.module or "", tuple(a.name for a in node.names))]
                for dotted, extra in targets:
                    top = dotted.split(".")[0]
                    if not top or top in stdlib:
                        continue
                    if _is_local(top, dirs):
                        for lf in _local_files(dotted, dirs, extra):
                            queue.append((lf, h))
                        continue
                    (req if h else opt).setdefault(top, set()).add(origin)
    out = {}
    for m in sorted(set(req) | set(opt)):
        r = tuple(sorted(req.get(m, ())))
        o = tuple(sorted(opt.get(m, set()) - set(r)))
        out[m] = ImportUse(m, r, o)
    return out, sorted(set(unparsed))


def _rel(p: Path, root: Path) -> str:
    try:
        return Path(p).resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return str(p)


def lane_engines(lane: str, root: Path | None = None) -> list:
    """The lane's engine manifests that are not retired."""
    from ..engines import manifest
    try:
        found = manifest.discover(root)
    except manifest.ManifestError as e:
        raise LaneError(f"cannot read the engine manifests: {e}") from None
    return [m for m in found if m.lane == lane and m.status != "retired"]


def engine_files(lane: str, root: Path | None = None) -> list[Path]:
    root = paths.repo_root() if root is None else Path(root)
    out = []
    for m in lane_engines(lane, root):
        f = m.entry.target_file(root) or m.module_path
        if f.is_file() and f.suffix == ".py":
            out.append(f)
        elif m.module_path.is_file():
            out.append(m.module_path)
    return sorted(set(out))


# ------------------------------------------------------------------------------------------ check

def find_modules(names: Sequence[str], python: str, *, environ: Mapping[str, str] | None = None,
                 run: Callable[..., Any] = subprocess.run) -> dict[str, bool]:
    """{name: findable} as `<python> -I` sees it (find_spec, nothing imported). LaneError when the
    interpreter does not answer."""
    if not names:
        return {}
    e = dict(os.environ if environ is None else environ)
    try:
        p = run([python, "-I", "-c", _FIND, json.dumps(sorted(set(names)))], capture_output=True, text=True,
                timeout=FIND_TIMEOUT, env=e, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired) as ex:
        raise LaneError(f"{python} did not answer the module lookup: {ex}") from None
    if p.returncode != 0:
        raise LaneError(f"{python} -I exited {p.returncode} on the module lookup: {(p.stderr or '').strip()[:200]}")
    try:
        got = json.loads((p.stdout or "").strip().splitlines()[-1])
    except (json.JSONDecodeError, IndexError):
        raise LaneError(f"{python} gave no module lookup result: {(p.stdout or '').strip()[:200]}") from None
    return {n: bool(got.get(n)) for n in names}


def _which(name: str, e: Mapping[str, str], python: str) -> str | None:
    path = e.get("PATH", "")
    venv_bin = str(Path(python).parent)
    return shutil.which(name, path=os.pathsep.join(x for x in (venv_bin, path) if x))


def _short(files: Sequence[str], n: int = 3) -> str:
    return ", ".join(files[:n]) + (f" (+{len(files) - n})" if len(files) > n else "")


def check(lane: str, *, root: Path | None = None, python: str | None = None,
          environ: Mapping[str, str] | None = None, run: Callable[..., Any] = subprocess.run,
          specs: Mapping[str, LaneSpec] | None = None, pins: bool = True,
          asset_items: Sequence[_assets.Asset] | None = None) -> EnvReport:
    """The lane's env-check (module docstring). LaneError for a lane that is neither a solvers/ lane
    nor in tools/lanes.toml."""
    root = paths.repo_root() if root is None else Path(root)
    python = python or sys.executable
    e = dict(os.environ if environ is None else environ)
    specs = load_specs(specs_path(root)) if specs is None else specs
    lanes = known_lanes(root)
    if lane not in lanes and lane not in specs:
        raise LaneError(f"unknown lane {lane!r}; lanes: {', '.join(lanes)}")
    spec = specs.get(lane, LaneSpec(lane))
    items: list[Item] = []

    files = engine_files(lane, root) if lane in lanes else []
    uses, unparsed = scan_imports(files, root)
    manifests = lane_engines(lane, root) if lane in lanes else []
    py_needs: dict[str, list[str]] = {}
    bin_needs: dict[str, list[str]] = {}
    for m in manifests:
        for t in m.needs_tools:
            (py_needs if t.startswith("py:") else bin_needs).setdefault(t[3:] if t.startswith("py:") else t,
                                                                       []).append(m.id)
    names = set(uses) | set(spec.modules) | {n.split(".")[0] for n in py_needs}
    found = find_modules(sorted(names), python, environ=e, run=run)
    fix = ("a PyPI package: pin it in requirements.in, run `.venv/bin/python tools/requirements_gen.py`, then "
           f"`uv pip install --python {python} -r requirements.txt`; a module of another repo: carry it into "
           "the lane (or retire the engine that needs it)")
    for n in sorted(names):
        u = uses.get(n, ImportUse(n))
        required = bool(u.required_by) or n in spec.modules
        why = []
        if u.required_by:
            why.append("loaded by " + _short(u.required_by))
        if n in spec.modules:
            why.append("listed for the lane in tools/lanes.toml")
        if u.optional_by:
            why.append("imported lazily by " + _short(u.optional_by))
        needers = [i for k, v in py_needs.items() if k.split(".")[0] == n for i in v]
        if needers:
            why.append("needs_tools of " + _short(needers))
        items.append(Item("module", n, required, found[n], "; ".join(why), "" if found[n] else fix))
    for f in unparsed:
        items.append(Item("source", f, False, False, "not parseable as Python 3: its imports were not read"))
    for b in sorted(set(spec.bins) | set(bin_needs)):
        w = _which(b, e, python)
        req = b in spec.bins
        why = "listed for the lane" if req else "needs_tools of " + _short(bin_needs[b])
        items.append(Item("bin", b, req, w is not None, w or why,
                          "" if w else "install it (python -m ctf toolbox install lists the toolbox tools)"))
    if spec.assets:
        a_items = _assets.load(_assets.manifest_path(root)) if asset_items is None else asset_items
        for s in _assets.resolve(a_items, environ=e, run=run, only=spec.assets):
            items.append(Item("asset", s.name, True, s.ok, s.path if s.ok else s.detail, s.fix))
    if pins:
        script = root / "tools" / "venv_pins.py"
        try:
            p = run([python, "-I", str(script)], capture_output=True, text=True, timeout=PINS_TIMEOUT, env=e,
                    stdin=subprocess.DEVNULL)
            rc, txt = p.returncode, ((p.stdout or "") + (p.stderr or "")).strip()
        except (OSError, subprocess.TimeoutExpired) as ex:
            rc, txt = None, str(ex)
        lines = txt.splitlines()
        items.append(Item("pins", "requirements.in", True, rc == 0,
                          lines[0] if rc == 0 and lines else "; ".join(lines[:6]) or f"exit {rc}",
                          next((ln[5:] for ln in lines if ln.startswith("FIX  ")), "")
                          if rc != 0 else ""))
    return EnvReport(lane, python, tuple(items), spec.image)


def exports(*, root: Path | None = None, python: str | None = None,
            environ: Mapping[str, str] | None = None, run: Callable[..., Any] = subprocess.run,
            asset_items: Sequence[_assets.Asset] | None = None) -> tuple[dict[str, str], list[str]]:
    """({VAR: value}, [PATH prefixes]) for any lane (they share the one venv): CTF_PYTHON (the
    interpreter), PYTHONPATH (the engine sys.path, so `python script.py` imports what `ctf run`
    imports), every ok asset's variables; the venv's bin folder goes in front of PATH."""
    root = paths.repo_root() if root is None else Path(root)
    python = python or sys.executable
    values = {"CTF_PYTHON": python,
              "PYTHONPATH": os.pathsep.join(str(d) for d in _search_dirs(root))}
    a_items = _assets.load(_assets.manifest_path(root)) if asset_items is None else asset_items
    values.update(_assets.exports(a_items, _assets.resolve(a_items, environ=environ, run=run)))
    return values, [str(Path(python).parent)]


__all__ = ["EnvReport", "ImportUse", "Item", "LaneError", "LaneSpec", "check", "engine_files", "exports",
           "find_modules", "known_lanes", "lane_engines", "load_specs", "parse_specs", "scan_imports",
           "specs_path"]
