"""The asset manifest (B-188): wordlists and install folders that live outside the repo, resolved once.

    from ctf.toolchain import assets
    items = assets.load()                       # [Asset] from tools/assets.toml (AssetsError if bad)
    report = assets.resolve(items)              # [AssetStatus]: where each one is, or why it is not ok
    assets.problems(report, core_only=True)     # what the doctor warns about
    assets.exports(items, report)               # {VAR: path} for every ok asset
    print(assets.render_env(assets.exports(items, report)))   # `export VAR='path'` lines

Why: a rockyou path mismatch broke an engine (one list of candidates in the doctor, another in the
engine), tools lived under the player's home folder with nothing recording where, and 7z2john failed for
a missing Perl module. Each asset is now listed once with its candidates in order; the doctor resolves
them and the result is exported under the names the engines already read (ROCKYOU for hashcrack,
GHIDRA_INSTALL_DIR for Ghidra's own launchers).

Resolution, per asset: the first override variable in `env` that is set wins, and if it names nothing
usable the asset is `broken` (never a silent fall-through to a candidate). Otherwise the candidates are
tried in order: `{toolbox}` is paths.toolbox_dir(), `~` the home folder, and a glob takes its highest
(natural-sort) match. A found file or folder must have every `contains` entry (a folder), at least
`min_bytes` (a file; a truncated download is broken), and its `probe` must exit 0 (`{path}` is
replaced by the path; run once with no stdin and PROBE_TIMEOUT).

States: ok | missing | broken. A core asset that is not ok is a doctor `warn` (it blocks one archetype,
not the wave); an optional one is reported only.
"""
from __future__ import annotations

import glob as _glob
import os
import re
import shlex
import subprocess
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from .. import env as _env
from .. import paths

MANIFEST_REL = Path("tools") / "assets.toml"
KINDS = ("file", "dir")
ROLES = ("core", "optional")
STATES = ("ok", "missing", "broken")
PROBE_TIMEOUT = 30.0

_KEYS = {"name", "kind", "role", "env", "candidates", "export", "contains", "min_bytes", "probe", "install",
         "used_by", "note"}
_NAME = re.compile(r"^[a-z0-9][a-z0-9_.-]*$")
_VAR = re.compile(r"^[A-Z][A-Z0-9_]*$")


class AssetsError(ValueError):
    """The asset manifest is missing or invalid, or an unknown asset was named."""


@dataclass(frozen=True)
class Asset:
    name: str
    kind: str
    role: str
    candidates: tuple[str, ...]
    env: tuple[str, ...] = ()            # override variables, first set wins
    export: tuple[str, ...] = ()         # variables the resolved path is exported under
    contains: tuple[str, ...] = ()       # dir: relative paths that must exist inside it
    min_bytes: int = 0                   # file: smallest acceptable size
    probe: tuple[str, ...] = ()          # argv run once, {path} replaced; must exit 0
    install: str = ""
    used_by: tuple[str, ...] = ()
    note: str = ""


@dataclass(frozen=True)
class AssetStatus:
    name: str
    role: str
    state: str
    path: str | None = None
    source: str = ""                     # env:VAR | candidate | ""
    detail: str = ""
    fix: str = ""

    def __post_init__(self):
        if self.state not in STATES:
            raise ValueError(f"asset {self.name!r}: state {self.state!r} is not one of {STATES}")

    @property
    def ok(self) -> bool:
        return self.state == "ok"

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "role": self.role, "state": self.state, "path": self.path,
                "source": self.source, "detail": self.detail, "fix": self.fix}

    def line(self) -> str:
        head = f"{self.state.upper():<8} {self.name}" + (f" ({self.role})" if self.role != "core" else "")
        body = self.path if self.ok else self.detail
        return head + (f": {body}" if body else "") + (f"\n    fix: {self.fix}" if self.fix and not self.ok else "")


def manifest_path(root: Path | None = None) -> Path:
    return (paths.repo_root() if root is None else Path(root)) / MANIFEST_REL


def _strs(where: str, key: str, v: Any, pattern: re.Pattern | None = None) -> tuple[str, ...]:
    if not isinstance(v, list) or not all(isinstance(x, str) and x for x in v):
        raise AssetsError(f"{where}: {key} must be a list of non-empty strings")
    if pattern is not None:
        bad = [x for x in v if not pattern.match(x)]
        if bad:
            raise AssetsError(f"{where}: {key} entries {bad} must match {pattern.pattern}")
    if len(set(v)) != len(v):
        raise AssetsError(f"{where}: {key} lists an entry twice")
    return tuple(v)


def parse(data: Mapping[str, Any], src: str = "assets.toml") -> list[Asset]:
    if set(data) - {"asset"}:
        raise AssetsError(f"{src}: unknown top-level key(s) {sorted(set(data) - {'asset'})}")
    raw = data.get("asset")
    if not isinstance(raw, list) or not raw:
        raise AssetsError(f"{src}: no [[asset]] entries")
    out, seen = [], set()
    for i, r in enumerate(raw):
        where = f"{src}: asset #{i + 1}"
        if not isinstance(r, dict):
            raise AssetsError(f"{where}: not a table")
        unknown = set(r) - _KEYS
        if unknown:
            raise AssetsError(f"{where}: unknown key(s) {sorted(unknown)}")
        name = r.get("name")
        if not isinstance(name, str) or not _NAME.match(name):
            raise AssetsError(f"{where}: name must match {_NAME.pattern}")
        if name in seen:
            raise AssetsError(f"{src}: asset {name!r} is listed twice")
        seen.add(name)
        where = f"{src}: asset {name!r}"
        kind = r.get("kind")
        if kind not in KINDS:
            raise AssetsError(f"{where}: kind must be one of {KINDS}")
        role = r.get("role", "core")
        if role not in ROLES:
            raise AssetsError(f"{where}: role must be one of {ROLES}")
        cands = _strs(where, "candidates", r.get("candidates"))
        contains = _strs(where, "contains", r.get("contains", []))
        if contains and kind != "dir":
            raise AssetsError(f"{where}: contains is for a dir asset")
        min_bytes = r.get("min_bytes", 0)
        if isinstance(min_bytes, bool) or not isinstance(min_bytes, int) or min_bytes < 0:
            raise AssetsError(f"{where}: min_bytes must be a non-negative integer")
        if min_bytes and kind != "file":
            raise AssetsError(f"{where}: min_bytes is for a file asset")
        probe = _strs(where, "probe", r.get("probe", []))
        exports = _strs(where, "export", r.get("export", []), _VAR)
        if not exports:
            raise AssetsError(f"{where}: export must name at least one variable (the point is to export it)")
        out.append(Asset(name=name, kind=kind, role=role, candidates=cands,
                         env=_strs(where, "env", r.get("env", []), _VAR), export=exports, contains=contains,
                         min_bytes=min_bytes, probe=probe, install=str(r.get("install", "")),
                         used_by=_strs(where, "used_by", r.get("used_by", [])), note=str(r.get("note", ""))))
    claimed: dict[str, str] = {}
    for a in out:
        for v in a.export:
            if v in claimed:
                raise AssetsError(f"{src}: {v} is exported by both {claimed[v]!r} and {a.name!r}")
            claimed[v] = a.name
    return out


def load(path: Path | None = None) -> list[Asset]:
    p = manifest_path() if path is None else Path(path)
    try:
        data = tomllib.loads(p.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise AssetsError(f"{p}: asset manifest not found") from None
    except tomllib.TOMLDecodeError as e:
        raise AssetsError(f"{p}: not valid TOML: {e}") from None
    return parse(data, str(p))


def select(items: Sequence[Asset], only: Sequence[str] | None) -> list[Asset]:
    if not only:
        return list(items)
    names = {a.name for a in items}
    bad = [n for n in only if n not in names]
    if bad:
        raise AssetsError(f"unknown asset(s) {bad}; known: {sorted(names)}")
    return [a for a in items if a.name in only]


def _natural(s: str) -> list:
    return [int(t) if t.isdigit() else t for t in re.split(r"(\d+)", s)]


def expand(candidate: str, environ: Mapping[str, str] | None = None) -> list[Path]:
    """The paths one candidate names: {toolbox} and ~ expanded; a glob gives its matches, highest first."""
    text = candidate.replace("{toolbox}", str(paths.toolbox_dir(environ)))
    e = os.environ if environ is None else environ
    if text.startswith("~"):
        home = e.get("HOME") or str(Path.home())
        text = home + text[1:]
    if any(c in text for c in "*?["):
        return [Path(p) for p in sorted(_glob.glob(text), key=_natural, reverse=True)]
    return [Path(text)]


def _override(name: str, e: Mapping[str, str]) -> str | None:
    if name.startswith(_env.CANONICAL_PREFIX):
        return _env.get(name, environ=e)
    return e.get(name) or None


def _check(a: Asset, p: Path, e: Mapping[str, str], run) -> str:
    """'' when p is a usable asset, else why not."""
    if a.kind == "file" and not p.is_file():
        return f"{p} is not a file"
    if a.kind == "dir" and not p.is_dir():
        return f"{p} is not a folder"
    if a.kind == "file" and a.min_bytes and p.stat().st_size < a.min_bytes:
        return f"{p} is {p.stat().st_size} bytes, under the {a.min_bytes} expected (truncated?)"
    missing = [c for c in a.contains if not (p / c).exists()]
    if missing:
        return f"{p} lacks {', '.join(missing)}"
    if a.probe:
        argv = [x.replace("{path}", str(p)) for x in a.probe]
        try:
            r = run(argv, capture_output=True, text=True, timeout=PROBE_TIMEOUT, stdin=subprocess.DEVNULL,
                    env=dict(e))
            rc, txt = r.returncode, ((r.stdout or "") + (r.stderr or "")).strip()
        except subprocess.TimeoutExpired:
            rc, txt = None, f"timed out after {PROBE_TIMEOUT:.0f} s"
        except OSError as ex:
            rc, txt = 127, str(ex)
        if rc != 0:
            return f"probe `{' '.join(argv)}` exited {rc}" + (f": {txt.splitlines()[-1][:160]}" if txt else "")
    return ""


def resolve(items: Sequence[Asset], *, environ: Mapping[str, str] | None = None,
            run: Callable[..., Any] = subprocess.run, only: Sequence[str] | None = None) -> list[AssetStatus]:
    e = dict(os.environ if environ is None else environ)
    out = []
    for a in select(items, only):
        fix = (a.install or f"place it at {a.candidates[0]}").replace("{toolbox}", str(paths.toolbox_dir(e)))
        hit = next(((v, val) for v in a.env if (val := _override(v, e))), None)
        if hit is not None:
            var, val = hit
            hits = expand(val, e)
            p = hits[0] if hits else Path(val)
            why = _check(a, p, e, run)
            if why:
                out.append(AssetStatus(a.name, a.role, "broken", str(p), f"env:{var}",
                                       f"{var} is set, and {why}", f"fix or unset {var}"))
            else:
                out.append(AssetStatus(a.name, a.role, "ok", str(p), f"env:{var}"))
            continue
        found, first_bad = None, None
        for c in a.candidates:
            for p in expand(c, e):
                if not p.exists():
                    continue
                why = _check(a, p, e, run)
                if not why:
                    found = p
                    break
                first_bad = first_bad or (p, why)
            if found:
                break
        if found is not None:
            out.append(AssetStatus(a.name, a.role, "ok", str(found), "candidate"))
        elif first_bad is not None:
            out.append(AssetStatus(a.name, a.role, "broken", str(first_bad[0]), "candidate", first_bad[1], fix))
        else:
            out.append(AssetStatus(a.name, a.role, "missing", None, "",
                                   "none of " + ", ".join(a.candidates).replace(
                                       "{toolbox}", str(paths.toolbox_dir(e))), fix))
    return out


def problems(report: Sequence[AssetStatus], core_only: bool = False) -> list[AssetStatus]:
    return [s for s in report if not s.ok and (s.role == "core" or not core_only)]


def exports(items: Sequence[Asset], report: Sequence[AssetStatus]) -> dict[str, str]:
    """{VAR: path} for every ok asset, under each of its export names, in manifest order."""
    by = {s.name: s for s in report}
    out: dict[str, str] = {}
    for a in items:
        s = by.get(a.name)
        if s is not None and s.ok and s.path:
            for v in a.export:
                out[v] = s.path
    return out


def render_env(values: Mapping[str, str], *, path_prepend: Sequence[str] = ()) -> str:
    """POSIX shell `export` lines (values single-quoted); path_prepend goes in front of $PATH."""
    lines = [f"export {k}={shlex.quote(v)}" for k, v in values.items()]
    if path_prepend:
        lines.append("export PATH=" + ":".join(shlex.quote(p) for p in path_prepend) + ':"$PATH"')
    return "\n".join(lines) + ("\n" if lines else "")


__all__ = ["Asset", "AssetStatus", "AssetsError", "expand", "exports", "load", "manifest_path", "parse",
           "problems", "render_env", "resolve", "select"]
