"""The binary toolbox (B-142): install and verify the host tools past editions needed.

    from ctf import toolbox
    tools = toolbox.load()                      # [Tool] from tools/toolbox.toml (ToolboxError if bad)
    report = toolbox.verify(tools)              # [Status], one per tool, with its runtime needs
    toolbox.problems(report)                    # the statuses that are not ok (core and optional)
    steps = toolbox.plan_install(tools, report) # [Step] for what is missing, old or drifted
    toolbox.apply(steps)                        # runs the brew/git steps (never a manual one; a
                                                #   system step only with allow_system=True)
    toolbox.render_brewfile(tools)              # the Brewfile at the repo root
    toolbox.capabilities_section(tools)         # the "Binary toolbox" section of docs/CAPABILITIES.md

The CSCTF prep bundle's tool-gap list named binaries that past editions needed to solve a challenge
(firefox_decrypt, veracrypt, websocat, keepassxc-cli, and the key-leak decrypt set) and that were
installed by hand mid-wave. This makes them one checked list: present, answering a version probe, at
or above a minimum version, with their runtime needs (NSS for firefox_decrypt, macFUSE for veracrypt)
present too.

States of a Status:

  ok        found, the probe answered, the version is accepted, every need is ok
  missing   not found (no bin on PATH, no app path, no clone, no candidate file)
  broken    found, but the probe failed (non-zero exit, timeout, no version in the output)
  old       found and answering, below min_version
  drift     a clone at another commit than the pin (works; reported so the pin is deliberate)
  needs     found and answering, but something it needs at runtime is not ok

A core tool in any state but ok is a problem for `ctf toolbox verify` (exit 1); an optional one is
reported and never fails. The preflight doctor reports the same as an advisory `warn` (a missing tool
blocks one archetype, not the wave).

Installs are never run by tests or by build work: `apply` refuses under CTF_TESTING unless every
program it would start carries STUB_MARKER near its top (a test stub). Manual steps (sage) are
printed for a human and never run. A `system = true` tool (macFUSE, VeraCrypt: an installer that asks
for an admin password, a system extension or a reboot) is planned like any other, but `apply` runs it
only with allow_system=True (`ctf toolbox install --apply --system`). A step whose program (brew,
git) is not on PATH is skipped and named; the steps whose program is present still run.

Every step that did not complete (failed, program absent, system step not allowed) skips the rest of
that tool's steps and the steps of every tool that needs it, each with its reason.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from . import env as _env
from . import paths

MANIFEST_REL = Path("tools") / "toolbox.toml"
BREWFILE_REL = Path("Brewfile")
CAPABILITIES_DIR = "docs"          # docs/CAPABILITIES.md links the playbooks relative to this
KINDS = ("binary", "clone", "file")
ROLES = ("core", "optional")
INSTALL_METHODS = ("brew", "cask", "git", "manual")
STATES = ("ok", "missing", "broken", "old", "drift", "needs")
DEFAULT_VERSION_RE = r"(\d+(?:\.\d+)+)"
PROBE_TIMEOUT = 30.0
STUB_MARKER = "ctf-toolbox-stub"   # under CTF_TESTING, apply only starts programs carrying this
STUB_MARKER_WINDOW = 4096

_KEYS = {"name", "kind", "role", "bins", "extra_bins", "app_paths", "version_args", "version_re",
         "min_version", "dest", "entry", "rev", "candidates", "env_dir", "file_name", "needs", "install",
         "provides", "past_need", "playbook", "note", "system"}
SKIP_REASONS = ("manual", "absent", "system", "blocked")   # StepResult.reason when a step did not run
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
_SHA = re.compile(r"^[0-9a-f]{40}$")


class ToolboxError(ValueError):
    """The toolbox manifest is missing or invalid, or an install step was refused."""


@dataclass(frozen=True)
class Tool:
    name: str
    kind: str
    role: str
    install_method: str
    install_target: str
    bins: tuple[str, ...] = ()
    extra_bins: tuple[str, ...] = ()
    app_paths: tuple[str, ...] = ()
    version_args: tuple[str, ...] = ()
    version_re: str = DEFAULT_VERSION_RE
    min_version: str | None = None
    dest: str | None = None
    entry: str | None = None
    rev: str | None = None
    candidates: tuple[str, ...] = ()
    env_dir: str | None = None
    file_name: str | None = None
    needs: tuple[str, ...] = ()
    provides: str = ""
    past_need: str = ""
    playbook: str | None = None
    note: str = ""
    system: bool = False              # its installer needs admin rights, a system extension or a reboot


@dataclass(frozen=True)
class Status:
    name: str
    role: str
    state: str
    path: str | None = None
    version: str | None = None
    detail: str = ""
    fix: str = ""

    def __post_init__(self):
        if self.state not in STATES:
            raise ValueError(f"toolbox status {self.name!r}: state {self.state!r} is not one of {STATES}")

    @property
    def ok(self) -> bool:
        return self.state == "ok"

    def line(self) -> str:
        s = f"{self.state.upper():<7} {self.name} ({self.role})"
        if self.version:
            s += f" {self.version}"
        if self.path:
            s += f" at {self.path}"
        if self.detail:
            s += f": {self.detail}"
        return s + (f"\n        fix: {self.fix}" if self.fix else "")

    def to_dict(self) -> dict:
        return {"name": self.name, "role": self.role, "state": self.state, "path": self.path,
                "version": self.version, "detail": self.detail, "fix": self.fix}


@dataclass(frozen=True)
class Step:
    tool: str
    argv: tuple[str, ...] | None      # None: a manual step, printed and never run
    note: str = ""
    after: tuple[str, ...] = ()       # the tools this one needs: a failed one skips this step
    system: bool = False              # runs only when apply is given allow_system=True

    def line(self) -> str:
        if self.argv is None:
            return f"[{self.tool}] MANUAL: {self.note}"
        return (f"[{self.tool}] " + " ".join(self.argv)
                + ("    [SYSTEM: runs only with --system]" if self.system else "")
                + (f"    # {self.note}" if self.note else ""))


@dataclass
class StepResult:
    step: Step
    returncode: int | None
    output: str = ""
    skipped: bool = False
    reason: str = ""                  # why a skipped step did not run: one of SKIP_REASONS


# ------------------------------------------------------------------------------------------ load

def manifest_path(root: Path | None = None) -> Path:
    return (paths.repo_root() if root is None else Path(root)) / MANIFEST_REL


def _strs(name: str, key: str, v: Any) -> tuple[str, ...]:
    if not isinstance(v, list) or not all(isinstance(x, str) and x for x in v):
        raise ToolboxError(f"toolbox tool {name!r}: {key} must be a list of non-empty strings")
    return tuple(v)


def _str(name: str, key: str, v: Any) -> str:
    if not isinstance(v, str) or not v:
        raise ToolboxError(f"toolbox tool {name!r}: {key} must be a non-empty string")
    return v


def _tool(raw: Any, i: int) -> Tool:
    if not isinstance(raw, dict):
        raise ToolboxError(f"toolbox entry {i}: not a table")
    name = raw.get("name")
    if not isinstance(name, str) or not _NAME.match(name):
        raise ToolboxError(f"toolbox entry {i}: name {name!r} is missing or not a plain word")
    unknown = sorted(set(raw) - _KEYS)
    if unknown:
        raise ToolboxError(f"toolbox tool {name!r}: unknown key(s) {', '.join(unknown)}")
    kind = raw.get("kind")
    if kind not in KINDS:
        raise ToolboxError(f"toolbox tool {name!r}: kind {kind!r} is not one of {KINDS}")
    role = raw.get("role")
    if role not in ROLES:
        raise ToolboxError(f"toolbox tool {name!r}: role {role!r} is not one of {ROLES}")
    inst = raw.get("install")
    if not isinstance(inst, dict) or len(inst) != 1 or next(iter(inst)) not in INSTALL_METHODS:
        raise ToolboxError(f"toolbox tool {name!r}: install must be one of "
                           + ", ".join(f"{{ {m} = ... }}" for m in INSTALL_METHODS))
    method, target = next(iter(inst.items()))
    target = _str(name, f"install.{method}", target)
    kw: dict[str, Any] = {}
    for key in ("bins", "extra_bins", "app_paths", "version_args", "candidates", "needs"):
        if key in raw:
            kw[key] = _strs(name, key, raw[key])
    for key in ("version_re", "min_version", "dest", "entry", "rev", "env_dir", "file_name", "playbook"):
        if key in raw:
            kw[key] = _str(name, key, raw[key])
    for key in ("provides", "past_need", "note"):
        if key in raw:
            if not isinstance(raw[key], str):
                raise ToolboxError(f"toolbox tool {name!r}: {key} must be a string")
            kw[key] = raw[key]
    if "system" in raw:
        if not isinstance(raw["system"], bool):
            raise ToolboxError(f"toolbox tool {name!r}: system must be true or false")
        if raw["system"] and method == "manual":
            raise ToolboxError(f"toolbox tool {name!r}: a manual install never runs, so it is not a system step")
        kw["system"] = raw["system"]
    try:
        rx = re.compile(kw.get("version_re", DEFAULT_VERSION_RE))
    except re.error as e:
        raise ToolboxError(f"toolbox tool {name!r}: version_re does not compile: {e}") from None
    if rx.groups < 1:
        raise ToolboxError(f"toolbox tool {name!r}: version_re needs a group for the version")
    if "min_version" in kw and _vtuple(kw["min_version"]) is None:
        raise ToolboxError(f"toolbox tool {name!r}: min_version {kw['min_version']!r} is not a dotted number")
    for key in ("app_paths", "candidates"):
        rel = [p for p in kw.get(key, ()) if not p.startswith("/")]
        if rel:
            raise ToolboxError(f"toolbox tool {name!r}: {key} must be absolute, got {rel}")
    if kind == "binary":
        if not kw.get("bins"):
            raise ToolboxError(f"toolbox tool {name!r}: a binary needs bins")
        if method == "git":
            raise ToolboxError(f"toolbox tool {name!r}: a binary is not installed by git (use kind = clone)")
    elif kind == "clone":
        for key in ("dest", "entry", "rev"):
            if key not in kw:
                raise ToolboxError(f"toolbox tool {name!r}: a clone needs {key}")
        if not _SHA.match(kw["rev"]):
            raise ToolboxError(f"toolbox tool {name!r}: rev must be a full 40-hex commit, got {kw['rev']!r}")
        if Path(kw["dest"]).is_absolute() or ".." in Path(kw["dest"]).parts:
            raise ToolboxError(f"toolbox tool {name!r}: dest must be a folder name under $CTF_TOOLBOX_DIR")
        if method not in ("git", "manual"):
            raise ToolboxError(f"toolbox tool {name!r}: a clone is installed by git (or manual)")
    else:  # file
        if not kw.get("candidates"):
            raise ToolboxError(f"toolbox tool {name!r}: a file needs candidates")
        if ("env_dir" in kw) != ("file_name" in kw):
            raise ToolboxError(f"toolbox tool {name!r}: env_dir and file_name go together")
        if "version_args" in kw or "min_version" in kw:
            raise ToolboxError(f"toolbox tool {name!r}: a file has no version probe")
        if method == "git":
            raise ToolboxError(f"toolbox tool {name!r}: a file is not installed by git")
    return Tool(name=name, kind=kind, role=role, install_method=method, install_target=target, **kw)


def parse(data: Mapping[str, Any], src: str = "<toolbox>") -> list[Tool]:
    entries = data.get("tool")
    if not isinstance(entries, list) or not entries:
        raise ToolboxError(f"{src}: no [[tool]] entries")
    extra = sorted(set(data) - {"tool"})
    if extra:
        raise ToolboxError(f"{src}: unknown top-level key(s) {', '.join(extra)}")
    tools = [_tool(raw, i) for i, raw in enumerate(entries)]
    names = [t.name for t in tools]
    dup = sorted({n for n in names if names.count(n) > 1})
    if dup:
        raise ToolboxError(f"{src}: duplicate tool name(s) {', '.join(dup)}")
    by = {t.name: t for t in tools}
    for t in tools:
        bad = [n for n in t.needs if n not in by]
        if bad:
            raise ToolboxError(f"{src}: {t.name} needs unknown tool(s) {', '.join(bad)}")
        if t.role == "core" and any(by[n].role == "optional" for n in t.needs):
            raise ToolboxError(f"{src}: core tool {t.name} needs an optional one")
    _order(tools)   # raises on a cycle
    return tools


def load(path: Path | None = None) -> list[Tool]:
    p = manifest_path() if path is None else Path(path)
    if not p.is_file():
        raise ToolboxError(f"toolbox manifest not found at {p}")
    try:
        data = tomllib.loads(p.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as e:
        raise ToolboxError(f"{p}: not valid TOML: {e}") from None
    return parse(data, str(p))


def _order(tools: Sequence[Tool]) -> list[Tool]:
    """Tools with their needs first (manifest order otherwise); ToolboxError on a cycle."""
    by = {t.name: t for t in tools}
    out: list[Tool] = []
    state: dict[str, int] = {}

    def visit(t: Tool, chain: tuple[str, ...]):
        if state.get(t.name) == 2:
            return
        if state.get(t.name) == 1:
            raise ToolboxError("toolbox needs form a cycle: " + " -> ".join(chain + (t.name,)))
        state[t.name] = 1
        for n in t.needs:
            if n in by:
                visit(by[n], chain + (t.name,))
        state[t.name] = 2
        out.append(t)

    for t in tools:
        visit(t, ())
    return out


# ------------------------------------------------------------------------------------------ verify

def _vtuple(v: str) -> tuple[int, ...] | None:
    m = re.fullmatch(r"\d+(?:\.\d+)*", v.strip())
    return tuple(int(x) for x in v.strip().split(".")) if m else None


def version_ok(found: str, minimum: str | None) -> bool:
    """found >= minimum, comparing dotted numbers (missing parts count as 0)."""
    if minimum is None:
        return True
    a, b = _vtuple(found), _vtuple(minimum)
    if a is None or b is None:
        return False
    n = max(len(a), len(b))
    return a + (0,) * (n - len(a)) >= b + (0,) * (n - len(b))


def _git_head(repo: Path) -> str | None:
    """The commit a checkout is at, read from .git without running git (None when unreadable)."""
    g = repo / ".git"
    try:
        head = (g / "HEAD").read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if _SHA.match(head):
        return head
    if not head.startswith("ref: "):
        return None
    ref = head[5:].strip()
    try:
        sha = (g / ref).read_text(encoding="utf-8").strip()
        return sha if _SHA.match(sha) else None
    except OSError:
        pass
    try:
        for ln in (g / "packed-refs").read_text(encoding="utf-8").splitlines():
            parts = ln.split()
            if len(parts) == 2 and parts[1] == ref and _SHA.match(parts[0]):
                return parts[0]
    except OSError:
        pass
    return None


def _install_hint(t: Tool) -> str:
    if t.install_method == "brew":
        return f"brew install {t.install_target}"
    if t.install_method == "cask":
        return f"brew install --cask {t.install_target}"
    if t.install_method == "git":
        return f"python -m ctf toolbox install --apply --only {t.name} (clones {t.install_target} at {t.rev})"
    return t.install_target


def _probe(argv: list[str], rx: re.Pattern, *, run: Callable[..., Any], cwd: Path | None,
           environ: Mapping[str, str]) -> tuple[str | None, str]:
    """(version, why-not). Runs the probe once, with no stdin."""
    try:
        p = run(argv, capture_output=True, text=True, timeout=PROBE_TIMEOUT, stdin=subprocess.DEVNULL,
                cwd=str(cwd) if cwd else None, env=dict(environ))
    except subprocess.TimeoutExpired:
        return None, f"`{' '.join(argv)}` timed out after {PROBE_TIMEOUT:.0f} s"
    except OSError as e:
        return None, f"cannot run {argv[0]}: {e}"
    out = (p.stdout or "") + (p.stderr or "")
    if p.returncode != 0:
        tail = " ".join(out.split())[:160]
        return None, f"version probe exited {p.returncode}" + (f": {tail}" if tail else "")
    m = rx.search(out)
    if not m:
        return None, f"no version in the probe output: {' '.join(out.split())[:160]!r}"
    return m.group(1), ""


def _locate_binary(t: Tool, path_env: str | None) -> str | None:
    for b in t.bins:
        w = shutil.which(b, path=path_env)
        if w:
            return w
    for a in t.app_paths:
        if os.path.isfile(a) and os.access(a, os.X_OK):
            return a
    return None


def _verify_one(t: Tool, environ: Mapping[str, str], run: Callable[..., Any], python: str) -> Status:
    rx = re.compile(t.version_re)
    path_env = environ.get("PATH")
    fix = _install_hint(t)
    if t.kind == "file":
        cands = list(t.candidates)
        if t.env_dir and environ.get(t.env_dir):
            cands.insert(0, str(Path(environ[t.env_dir]) / t.file_name))
        hit = next((c for c in cands if os.path.exists(c)), None)
        if hit is None:
            return Status(t.name, t.role, "missing", detail="none of " + ", ".join(cands) + " exists", fix=fix)
        return Status(t.name, t.role, "ok", path=hit)
    cwd = None
    drift = ""
    if t.kind == "binary":
        where = _locate_binary(t, path_env)
        if where is None:
            looked = "PATH" + (" or " + ", ".join(t.app_paths) if t.app_paths else "")
            return Status(t.name, t.role, "missing", detail=f"no {' / '.join(t.bins)} on {looked}", fix=fix)
        absent = [b for b in t.extra_bins if not shutil.which(b, path=path_env)
                  and not os.path.isfile(os.path.join(os.path.dirname(where), b))]
        if absent:
            return Status(t.name, t.role, "missing", path=where,
                          detail=f"{', '.join(absent)} (installed with {t.name}) not found", fix=fix)
        argv = [where, *t.version_args]
    else:  # clone
        dest = paths.toolbox_dir(environ) / t.dest
        script = dest / t.entry
        if not script.is_file():
            return Status(t.name, t.role, "missing", detail=f"no {t.entry} in {dest}", fix=fix)
        where = str(script)
        head = _git_head(dest)
        if head != t.rev:
            drift = (f"checkout is at {head or 'an unreadable commit'}, the pin is {t.rev}")
        argv = [python, "-I", str(script), *t.version_args]
        cwd = dest
    if not t.version_args:
        version, why = None, ""
    else:
        version, why = _probe(argv, rx, run=run, cwd=cwd, environ=environ)
        if version is None:
            return Status(t.name, t.role, "broken", path=where, detail=why,
                          fix=f"reinstall: {fix}")
    if version is not None and not version_ok(version, t.min_version):
        return Status(t.name, t.role, "old", path=where, version=version,
                      detail=f"below the minimum {t.min_version}", fix=f"upgrade: {fix}")
    if drift:
        return Status(t.name, t.role, "drift", path=where, version=version, detail=drift,
                      fix=f"python -m ctf toolbox install --apply --only {t.name} (moves it to the pin), "
                          "or change rev in tools/toolbox.toml if the new commit is wanted")
    return Status(t.name, t.role, "ok", path=where, version=version)


def verify(tools: Sequence[Tool], *, environ: Mapping[str, str] | None = None,
           run: Callable[..., Any] = subprocess.run, python: str | None = None,
           only: Sequence[str] | None = None) -> list[Status]:
    """One Status per tool (with `only`: those tools and what they need), needs before the tools
    that need them. A tool whose own check is ok but one of its needs is not becomes `needs`."""
    e = os.environ if environ is None else environ
    py = python or sys.executable
    chosen = _select(tools, only)
    out: dict[str, Status] = {}
    for t in _order(chosen):
        st = _verify_one(t, e, run, py)
        if st.ok:
            bad = [n for n in t.needs if not out[n].ok]
            if bad:
                st = Status(t.name, t.role, "needs", path=st.path, version=st.version,
                            detail="needs " + ", ".join(f"{n} ({out[n].state})" for n in bad),
                            fix="; ".join(out[n].fix for n in bad if out[n].fix))
        out[t.name] = st
    return [out[t.name] for t in _order(chosen)]


def _select(tools: Sequence[Tool], only: Sequence[str] | None) -> list[Tool]:
    if not only:
        return list(tools)
    by = {t.name: t for t in tools}
    unknown = [n for n in only if n not in by]
    if unknown:
        raise ToolboxError(f"unknown toolbox tool(s) {', '.join(unknown)}; known: {', '.join(by)}")
    want: set[str] = set()

    def add(n: str):
        if n not in want:
            want.add(n)
            for m in by[n].needs:
                add(m)

    for n in only:
        add(n)
    return [t for t in tools if t.name in want]


def problems(report: Sequence[Status], *, core_only: bool = False) -> list[Status]:
    """The statuses that are not ok; with core_only, only the core tools'."""
    return [s for s in report if not s.ok and (s.role == "core" or not core_only)]


# ------------------------------------------------------------------------------------------ install

def plan_install(tools: Sequence[Tool], report: Sequence[Status], *,
                 environ: Mapping[str, str] | None = None) -> list[Step]:
    """Steps for every tool whose state is missing, old, broken or drift (a `needs` tool is fixed
    by its needs' steps). Needs come first. Nothing runs here."""
    e = os.environ if environ is None else environ
    by = {s.name: s for s in report}
    steps: list[Step] = []
    for t in _order([t for t in tools if t.name in by]):
        st = by[t.name]
        if st.state in ("ok", "needs"):
            continue
        upgrade = st.state in ("old", "broken")
        after = t.needs
        if t.install_method == "manual":
            steps.append(Step(t.name, None, t.install_target, after))
        elif t.install_method == "brew":
            steps.append(Step(t.name, ("brew", "upgrade" if upgrade else "install", t.install_target),
                              t.note, after, t.system))
        elif t.install_method == "cask":
            steps.append(Step(t.name, ("brew", "upgrade" if upgrade else "install", "--cask",
                                       t.install_target), t.note, after, t.system))
        else:  # git clone, pinned
            dest = str(paths.toolbox_dir(e) / t.dest)
            if st.state == "missing" and Path(dest).exists():
                steps.append(Step(t.name, None, f"{dest} exists but holds no {t.entry}: move it aside, "
                                  "then re-run the install", after))
                continue
            if st.state == "missing":
                steps.append(Step(t.name, ("git", "init", "-q", dest), "", after, t.system))
            steps.append(Step(t.name, ("git", "-C", dest, "fetch", "-q", "--depth", "1",
                                       t.install_target, t.rev), "", after, t.system))
            steps.append(Step(t.name, ("git", "-C", dest, "checkout", "-q", "--detach", t.rev), "", after,
                              t.system))
    return steps


def _is_stub(prog: str, path_env: str | None) -> bool:
    w = shutil.which(prog, path=path_env)
    if not w:
        return False
    try:
        with open(w, "rb") as fh:
            return STUB_MARKER.encode() in fh.read(STUB_MARKER_WINDOW)
    except OSError:
        return False


def apply(steps: Sequence[Step], *, environ: Mapping[str, str] | None = None,
          run: Callable[..., Any] = subprocess.run, allow_system: bool = False) -> list[StepResult]:
    """Run the brew/git steps in order. A step does not run, and its StepResult says why (`reason`),
    when it is manual (never run), its program is not on PATH (`absent`, named), it is a system step
    and allow_system is False (`system`), or an earlier step of its tool or of a tool it needs did not
    complete (`blocked`). A step that fails or does not run blocks the rest of its tool's steps and
    every tool that needs it (Step.after). Under CTF_TESTING every program present must be a stub
    carrying STUB_MARKER (ToolboxError otherwise, before anything runs)."""
    e = os.environ if environ is None else environ
    path_env = e.get("PATH")
    progs = {s.argv[0] for s in steps if s.argv}
    absent = {p for p in progs if not shutil.which(p, path=path_env)}
    if _env.get_bool("CTF_TESTING", environ=e):
        real = sorted(p for p in progs - absent if not _is_stub(p, path_env))
        if real:
            raise ToolboxError(f"refused under CTF_TESTING: {', '.join(real)} is not a test stub "
                               f"(a stub carries {STUB_MARKER!r}); no install runs from tests")
    failed: dict[str, str] = {}       # tool -> why it did not complete
    out: list[StepResult] = []
    for s in steps:
        if s.argv is None:
            out.append(StepResult(s, None, "manual step: do it by hand", skipped=True, reason="manual"))
            continue
        blocked = [n for n in (s.tool, *s.after) if n in failed]
        if blocked:
            failed.setdefault(s.tool, "an earlier step did not complete")
            out.append(StepResult(s, None, "skipped: " + "; ".join(f"{n}: {failed[n]}" for n in blocked),
                                  skipped=True, reason="blocked"))
            continue
        if s.argv[0] in absent:
            why = f"{s.argv[0]} not found on PATH" + (" (Homebrew: https://brew.sh)" if s.argv[0] == "brew"
                                                      else "")
            failed[s.tool] = why
            out.append(StepResult(s, None, f"skipped: {why}", skipped=True, reason="absent"))
            continue
        if s.system and not allow_system:
            why = "a system install (admin password, system extension, reboot): run with --system"
            failed[s.tool] = why
            out.append(StepResult(s, None, f"skipped: {why}", skipped=True, reason="system"))
            continue
        try:
            p = run(list(s.argv), capture_output=True, text=True, env=dict(e))
            rc, txt = p.returncode, (p.stdout or "") + (p.stderr or "")
        except OSError as ex:
            rc, txt = 127, str(ex)
        if rc != 0:
            failed[s.tool] = f"`{' '.join(s.argv)}` exited {rc}"
        out.append(StepResult(s, rc, txt))
    return out


# ------------------------------------------------------------------------------------------ render

def render_brewfile(tools: Sequence[Tool]) -> str:
    out = ["# Generated by `python -m ctf toolbox brewfile --write` from tools/toolbox.toml (B-142).\n",
           "# Do not edit by hand: tests/test_toolbox.py fails when it is stale. `brew bundle` installs\n",
           "# these; `python -m ctf toolbox install` adds the pinned clones; `python -m ctf toolbox\n",
           "# verify` checks the result.\n"]
    sys_note = "  # system: admin password, system extension, reboot (`ctf toolbox install --apply --system`)"
    for t in tools:
        if t.install_method == "brew":
            out.append(f'brew "{t.install_target}"' + (sys_note if t.system else "") + "\n")
    for t in tools:
        if t.install_method == "cask":
            out.append(f'cask "{t.install_target}"' + (sys_note if t.system else "") + "\n")
    rest = [t for t in tools if t.install_method in ("git", "manual")]
    if rest:
        out.append("# Not Homebrew:\n")
        for t in rest:
            how = (f"git clone {t.install_target} at {t.rev} into $CTF_TOOLBOX_DIR/{t.dest}"
                   if t.install_method == "git" else t.install_target)
            out.append(f"#   {t.name}: {how}\n")
    return "".join(out)


def brewfile_path(root: Path | None = None) -> Path:
    return (paths.repo_root() if root is None else Path(root)) / BREWFILE_REL


def _cell(s: str) -> str:
    return s.replace("|", "\\|").replace("\n", " ")


def capabilities_section(tools: Sequence[Tool] | None, *, missing_reason: str = "") -> str:
    """The "Binary toolbox" section of docs/CAPABILITIES.md. With tools None the section says why
    there is no list (never left out silently)."""
    out = ["\n## Binary toolbox\n\n"]
    if tools is None:
        out.append(f"No toolbox manifest: {missing_reason}\n")
        return "".join(out)
    out.append("Host tools no engine ships, which past editions needed to solve a challenge. Listed in\n"
               "`tools/toolbox.toml`; `python -m ctf toolbox verify` checks them (the preflight doctor\n"
               "runs it as check `toolbox`), `python -m ctf toolbox install` plans or runs the installs.\n\n")
    out.append("| tool | role | what it gives | past need | install | playbook |\n|---|---|---|---|---|---|\n")
    for t in tools:
        how = {"brew": f"brew `{t.install_target}`", "cask": f"cask `{t.install_target}`",
               "git": "pinned clone", "manual": "manual"}[t.install_method]
        if t.needs:
            how += " (needs " + ", ".join(f"`{n}`" for n in t.needs) + ")"
        pb = (f"[{Path(t.playbook).stem}]({os.path.relpath(t.playbook, CAPABILITIES_DIR)})"
              if t.playbook else "")
        out.append(f"| `{t.name}` | {t.role} | {_cell(t.provides)} | {_cell(t.past_need)} | {how} | {pb} |\n")
    return "".join(out)
