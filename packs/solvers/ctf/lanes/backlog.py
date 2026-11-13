"""The lane backlog: one file that describes a batch of Codex build lanes (B-179).

YAML (`.yaml`/`.yml`, needs PyYAML) or TOML (`.toml`). Unknown keys anywhere are an error, like
event profiles and engine manifests.

    batch: crypto-r3                  # required; [a-z0-9-]; names the batch folder and lane branches
    base: build/phases-0-3            # required; the git ref every lane branches from
    concurrency: 4                    # default 4 (1-16): codex processes running at once
    timeout_minutes: 120              # default 120: a lane still running after this is killed
    preamble: |                       # optional text placed in every prompt
      ...
    context: [docs/CONTRACTS.md]      # optional: files every lane reads first
    protected: [ctf/triage.py]        # optional: paths no lane may own (docs/CAPABILITIES.md always is)
    codex:                            # optional
      model: gpt-6-astra
      effort: high
      extra: []                       # passthrough codex args (fence_launch refuses fence-breaking ones)
      strict_home: false              # fence: deny all of $HOME outside the lane's roots
    lanes:
      - id: pqc-parse                 # required; [a-z0-9-], unique
        title: PQC raw-object parser  # required
        goal: |                       # required: what to build
          ...
        acceptance: [...]             # required, non-empty
        owns: [solvers/crypto/pqc_*.py, tests/test_crypto_pqc*.py]   # required: repo-relative globs
        tests: [tests/test_crypto_pqc.py]                            # required; each one owned
        context: []                   # optional: extra files to read
        depends: []                   # optional: lane ids that must finish "built" first
        notes: ""                     # optional

Structural checks (each a BacklogError naming the lane and key): duplicate ids, a dependency that
does not exist, names itself or forms a cycle, two lanes owning overlapping paths (glob vs glob is
checked both ways with fnmatch, an approximation that catches `x/*.py` vs `x/a_*.py`), a lane owning a
protected path, a test file the lane does not own, an absolute or `..` path.
"""
from __future__ import annotations

import fnmatch
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,47}$")
BATCH_RE = ID_RE
ALWAYS_PROTECTED = ("docs/CAPABILITIES.md",)
DEFAULT_CONCURRENCY = 4
MAX_CONCURRENCY = 16
DEFAULT_TIMEOUT_MIN = 120

_TOP_KEYS = {"batch", "base", "concurrency", "timeout_minutes", "preamble", "context", "protected",
             "codex", "lanes"}
_CODEX_KEYS = {"model", "effort", "extra", "strict_home"}
_LANE_KEYS = {"id", "title", "goal", "acceptance", "owns", "tests", "context", "depends", "notes"}


class BacklogError(ValueError):
    """The backlog is malformed or structurally unsafe. The message names the file and key."""


@dataclass(frozen=True)
class CodexOpts:
    model: str | None = None
    effort: str | None = None
    extra: tuple[str, ...] = ()
    strict_home: bool = False


@dataclass(frozen=True)
class Lane:
    id: str
    title: str
    goal: str
    acceptance: tuple[str, ...]
    owns: tuple[str, ...]
    tests: tuple[str, ...]
    context: tuple[str, ...] = ()
    depends: tuple[str, ...] = ()
    notes: str = ""

    def owns_path(self, rel: str) -> bool:
        return any(fnmatch.fnmatchcase(rel, g) for g in self.owns)


@dataclass(frozen=True)
class Backlog:
    batch: str
    base: str
    lanes: tuple[Lane, ...]
    concurrency: int = DEFAULT_CONCURRENCY
    timeout_minutes: int = DEFAULT_TIMEOUT_MIN
    preamble: str = ""
    context: tuple[str, ...] = ()
    protected: tuple[str, ...] = ALWAYS_PROTECTED
    codex: CodexOpts = field(default_factory=CodexOpts)
    source: str = ""

    def lane(self, lane_id: str) -> Lane:
        for ln in self.lanes:
            if ln.id == lane_id:
                return ln
        raise KeyError(f"no lane {lane_id!r} in batch {self.batch!r}")

    def branch(self, lane_id: str) -> str:
        return f"lane/{self.batch}/{lane_id}"

    def order(self) -> list[str]:
        """Lane ids in dependency order (a lane after everything it depends on), stable."""
        return _topo(self.lanes, self.source)


# ----------------------------------------------------------------------------------------- loading

def read_raw(path: Path) -> dict:
    path = Path(path)
    if not path.is_file():
        raise BacklogError(f"{path}: backlog file not found")
    text = path.read_text(encoding="utf-8")
    suffix = path.suffix.lower()
    if suffix == ".toml":
        try:
            data = tomllib.loads(text)
        except tomllib.TOMLDecodeError as e:
            raise BacklogError(f"{path}: not valid TOML: {e}") from None
    elif suffix in (".yaml", ".yml"):
        try:
            import yaml
        except ImportError:
            raise BacklogError(f"{path}: a YAML backlog needs PyYAML (pinned in requirements.in); "
                               "install it into the venv or write the backlog as .toml") from None
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as e:
            raise BacklogError(f"{path}: not valid YAML: {e}") from None
    else:
        raise BacklogError(f"{path}: backlog must be .yaml, .yml or .toml (got {suffix or 'no suffix'})")
    if not isinstance(data, dict):
        raise BacklogError(f"{path}: the top level must be a table/mapping")
    return data


def load(path: Path | str) -> Backlog:
    path = Path(path)
    return parse(read_raw(path), str(path))


def _e(src: str, key: str, msg: str) -> BacklogError:
    return BacklogError(f"{src}: {key}: {msg}")


def _str(src, key, v, *, required=True) -> str:
    if v is None and not required:
        return ""
    if not isinstance(v, str) or (required and not v.strip()):
        raise _e(src, key, "must be a non-empty string" if required else "must be a string")
    return v


def _int(src, key, v, lo, hi) -> int:
    if isinstance(v, bool) or not isinstance(v, int):
        raise _e(src, key, "must be an integer")
    if not lo <= v <= hi:
        raise _e(src, key, f"must be between {lo} and {hi} (got {v})")
    return v


def _strs(src, key, v, *, required=False) -> tuple[str, ...]:
    if v is None:
        v = []
    if not isinstance(v, list) or not all(isinstance(x, str) and x.strip() for x in v):
        raise _e(src, key, "must be a list of non-empty strings")
    if required and not v:
        raise _e(src, key, "must not be empty")
    return tuple(v)


def _relpaths(src, key, v, *, required=False) -> tuple[str, ...]:
    out = _strs(src, key, v, required=required)
    for p in out:
        pp = PurePosixPath(p)
        if p.startswith(("/", "~")) or ".." in pp.parts or "\\" in p:
            raise _e(src, key, f"{p!r} must be a repo-relative path (no leading /, ~ or ..)")
    return out


def _unknown(src, where, data, allowed):
    bad = sorted(set(data) - allowed)
    if bad:
        raise _e(src, where, f"unknown key(s) {', '.join(bad)}")


def parse(data: dict, src: str = "<backlog>") -> Backlog:
    _unknown(src, "(top level)", data, _TOP_KEYS)
    for req in ("batch", "base", "lanes"):
        if req not in data:
            raise _e(src, req, "required key missing")
    batch = _str(src, "batch", data["batch"])
    if not BATCH_RE.match(batch):
        raise _e(src, "batch", f"{batch!r} must match [a-z0-9][a-z0-9-]*, at most 48 characters")
    base = _str(src, "base", data["base"])
    if base.startswith("-") or any(c.isspace() for c in base):
        raise _e(src, "base", f"{base!r} is not a git ref")
    conc = _int(src, "concurrency", data.get("concurrency", DEFAULT_CONCURRENCY), 1, MAX_CONCURRENCY)
    tmo = _int(src, "timeout_minutes", data.get("timeout_minutes", DEFAULT_TIMEOUT_MIN), 1, 24 * 60)
    preamble = _str(src, "preamble", data.get("preamble"), required=False)
    context = _relpaths(src, "context", data.get("context"))
    protected = tuple(dict.fromkeys(ALWAYS_PROTECTED + _relpaths(src, "protected", data.get("protected"))))

    craw = data.get("codex", {}) or {}
    if not isinstance(craw, dict):
        raise _e(src, "codex", "must be a table")
    _unknown(src, "codex", craw, _CODEX_KEYS)
    strict = craw.get("strict_home", False)
    if not isinstance(strict, bool):
        raise _e(src, "codex.strict_home", "must be true or false")
    codex = CodexOpts(model=_str(src, "codex.model", craw.get("model"), required=False) or None,
                      effort=_str(src, "codex.effort", craw.get("effort"), required=False) or None,
                      extra=_strs(src, "codex.extra", craw.get("extra")), strict_home=strict)
    # fence_launch refuses passthrough args that would undo the fence; fail at load, not at launch.
    from .. import fence_launch
    try:
        fence_launch.check_codex_extra(codex.extra)
    except fence_launch.LaunchError as e:
        raise _e(src, "codex.extra", str(e)) from None

    lraw = data["lanes"]
    if not isinstance(lraw, list) or not lraw:
        raise _e(src, "lanes", "must be a non-empty list of lane tables")
    lanes: list[Lane] = []
    for i, ld in enumerate(lraw):
        where = f"lanes[{i}]"
        if not isinstance(ld, dict):
            raise _e(src, where, "must be a table")
        _unknown(src, where, ld, _LANE_KEYS)
        for req in ("id", "title", "goal", "acceptance", "owns", "tests"):
            if req not in ld:
                raise _e(src, f"{where}.{req}", "required key missing")
        lid = _str(src, f"{where}.id", ld["id"])
        if not ID_RE.match(lid):
            raise _e(src, f"{where}.id", f"{lid!r} must match [a-z0-9][a-z0-9-]*, at most 48 characters")
        where = f"lanes[{lid}]"
        lane = Lane(id=lid, title=_str(src, f"{where}.title", ld["title"]),
                    goal=_str(src, f"{where}.goal", ld["goal"]),
                    acceptance=_strs(src, f"{where}.acceptance", ld["acceptance"], required=True),
                    owns=_relpaths(src, f"{where}.owns", ld["owns"], required=True),
                    tests=_relpaths(src, f"{where}.tests", ld["tests"], required=True),
                    context=_relpaths(src, f"{where}.context", ld.get("context")),
                    depends=_strs(src, f"{where}.depends", ld.get("depends")),
                    notes=_str(src, f"{where}.notes", ld.get("notes"), required=False))
        for t in lane.tests:
            if not lane.owns_path(t):
                raise _e(src, f"{where}.tests", f"{t!r} is not matched by the lane's owns; a lane owns its tests")
        for g in lane.owns:
            for p in protected:
                if _overlap(g, p):
                    raise _e(src, f"{where}.owns", f"{g!r} covers protected path {p!r}"
                             + (" (lanes declare CAPABILITIES entries in their result; integrate applies them)"
                                if p in ALWAYS_PROTECTED else ""))
        lanes.append(lane)

    ids = [ln.id for ln in lanes]
    dup = sorted({x for x in ids if ids.count(x) > 1})
    if dup:
        raise _e(src, "lanes", f"duplicate lane id(s) {', '.join(dup)}")
    for ln in lanes:
        for d in ln.depends:
            if d == ln.id:
                raise _e(src, f"lanes[{ln.id}].depends", "a lane cannot depend on itself")
            if d not in ids:
                raise _e(src, f"lanes[{ln.id}].depends", f"unknown lane {d!r}")
    for a in range(len(lanes)):
        for b in range(a + 1, len(lanes)):
            for ga in lanes[a].owns:
                for gb in lanes[b].owns:
                    if _overlap(ga, gb):
                        raise _e(src, "lanes", f"lanes {lanes[a].id!r} and {lanes[b].id!r} both own "
                                 f"{ga!r} / {gb!r}: give each path one owner")
    bl = Backlog(batch=batch, base=base, lanes=tuple(lanes), concurrency=conc, timeout_minutes=tmo,
                 preamble=preamble, context=context, protected=protected, codex=codex, source=src)
    bl.order()   # raises on a cycle
    return bl


def _overlap(a: str, b: str) -> bool:
    return a == b or fnmatch.fnmatchcase(a, b) or fnmatch.fnmatchcase(b, a)


def _topo(lanes, src) -> list[str]:
    deps = {ln.id: list(ln.depends) for ln in lanes}
    out: list[str] = []
    state: dict[str, int] = {}

    def visit(n, stack):
        s = state.get(n, 0)
        if s == 2:
            return
        if s == 1:
            cyc = stack[stack.index(n):] + [n]
            raise _e(src, "lanes", f"dependency cycle {' -> '.join(cyc)}")
        state[n] = 1
        for d in deps[n]:
            visit(d, stack + [n])
        state[n] = 2
        out.append(n)

    for ln in lanes:
        visit(ln.id, [])
    return out
