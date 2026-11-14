"""Shipped workflow scripts: the registry, the pre-launch schema check, and the hard agent cap (B-194).

The repo's workflow scripts live in `workflows/*.js` (outside `.claude/`) and run under the Workflow
tool. Each is paired with a `workflows/<name>.wf.toml` manifest read here so the launcher can, BEFORE
the script is started and any agent is spawned:

    from ctf import workflows as wf
    reg = wf.load_all()                       # [Workflow(...)], one per manifest, each with its .js present
    w = wf.get("lane-fanout")                 # one, or WorkflowError naming the unknown name
    wf.validate(w, args)                       # raises WorkflowError naming the first missing required arg
    n = wf.plan_agents(w, args)                # the dry-run agent count for these args
    wf.check_cap(w, args)                      # raises WorkflowError when the dry-run count exceeds max_agents

Lanes come from the board or the profile, never a hard-coded list in a workflow:

    wf.lanes_from_board(workdir=None)          # distinct lanes across the dispatch claims (ctf.dispatch)
    wf.lanes_from_profile(profile)             # the profile's categories, canonicalised (ctf.event)

Nothing here runs a model, reads a token, or launches the script; it only validates. A missing manifest
field, a manifest with no script, or an unknown workflow fails loudly with a named reason (never a silent
default). The JS enforces the same required args and cap at run time (defence in depth); the manifest is
the pre-launch copy and tests assert the two agree.
"""
from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from . import paths

WORKFLOWS_DIRNAME = "workflows"
MANIFEST_SUFFIX = ".wf.toml"

# Every manifest key, with its type. Unknown keys are an error (a typo must not be ignored).
_REQUIRED_KEYS = {
    "name": str,
    "script": str,
    "description": str,
    "required": list,
    "lane_arg": str,
    "stages_per_lane": int,
    "extra_agents": int,
    "max_agents": int,
}


class WorkflowError(Exception):
    """A workflow cannot be loaded, its arguments are invalid, or its dry-run agent count exceeds the
    cap. Always names the workflow and the exact field or count at fault."""


@dataclass(frozen=True)
class Workflow:
    name: str
    script: str                    # the .js filename, relative to the workflows dir
    description: str
    required: tuple[str, ...]      # required argument names (the pre-launch schema)
    lane_arg: str                  # the argument that carries the board-derived lane/target list
    stages_per_lane: int           # agents spawned per lane (writer + checker = 2, verifier = 1)
    extra_agents: int              # agents spawned once regardless of lane count (e.g. the index)
    max_agents: int                # the hard per-workflow cap
    path: Path                     # the manifest path

    @property
    def script_path(self) -> Path:
        return self.path.parent / self.script


def workflows_dir() -> Path:
    return paths.repo_root() / WORKFLOWS_DIRNAME


def _parse_manifest(path: Path) -> Workflow:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as e:
        raise WorkflowError(f"{path}: unreadable workflow manifest ({e})") from None
    unknown = set(data) - set(_REQUIRED_KEYS)
    if unknown:
        raise WorkflowError(f"{path}: unknown manifest key(s): {', '.join(sorted(unknown))}")
    for key, typ in _REQUIRED_KEYS.items():
        if key not in data:
            raise WorkflowError(f"{path}: missing manifest key {key!r}")
        if typ is int and isinstance(data[key], bool):
            raise WorkflowError(f"{path}: manifest key {key!r} must be an integer, not a boolean")
        if not isinstance(data[key], typ):
            raise WorkflowError(f"{path}: manifest key {key!r} must be {typ.__name__}")
    required = data["required"]
    if not all(isinstance(x, str) and x for x in required):
        raise WorkflowError(f"{path}: 'required' must be a list of non-empty argument names")
    name = data["name"]
    if name != path.name[: -len(MANIFEST_SUFFIX)]:
        raise WorkflowError(f"{path}: manifest name {name!r} does not match its filename")
    if data["lane_arg"] not in required:
        raise WorkflowError(f"{path}: lane_arg {data['lane_arg']!r} is not in 'required'")
    for key in ("stages_per_lane", "max_agents"):
        if data[key] < 1:
            raise WorkflowError(f"{path}: manifest key {key!r} must be >= 1")
    if data["extra_agents"] < 0:
        raise WorkflowError(f"{path}: manifest key 'extra_agents' must be >= 0")
    wf = Workflow(
        name=name,
        script=data["script"],
        description=data["description"],
        required=tuple(required),
        lane_arg=data["lane_arg"],
        stages_per_lane=data["stages_per_lane"],
        extra_agents=data["extra_agents"],
        max_agents=data["max_agents"],
        path=path,
    )
    if not wf.script_path.is_file():
        raise WorkflowError(f"{path}: script {wf.script!r} not found next to the manifest")
    return wf


def load_all() -> list[Workflow]:
    """Every shipped workflow, sorted by name. The workflows dir must exist (it is part of the repo);
    a missing one is a loud error, not an empty list."""
    d = workflows_dir()
    if not d.is_dir():
        raise WorkflowError(f"{d}: workflows directory is missing")
    out = [_parse_manifest(p) for p in sorted(d.glob(f"*{MANIFEST_SUFFIX}"))]
    return out


def names() -> list[str]:
    return [w.name for w in load_all()]


def get(name: str) -> Workflow:
    path = workflows_dir() / f"{name}{MANIFEST_SUFFIX}"
    if not path.is_file():
        known = ", ".join(names()) or "(none)"
        raise WorkflowError(f"unknown workflow {name!r} (known: {known})")
    return _parse_manifest(path)


def _missing(args: Mapping[str, Any], key: str) -> bool:
    return key not in args or args[key] is None or args[key] == ""


def validate(wf: Workflow, args: Mapping[str, Any]) -> None:
    """Raise WorkflowError naming the first missing required argument (the pre-launch schema check).
    The lane argument must also be a non-empty list."""
    if not isinstance(args, Mapping):
        raise WorkflowError(f"{wf.name}: args must be a mapping, not {type(args).__name__}")
    for key in wf.required:
        if _missing(args, key):
            raise WorkflowError(f'{wf.name}: missing required argument "{key}"')
    lanes = args[wf.lane_arg]
    if not isinstance(lanes, list) or not lanes:
        raise WorkflowError(
            f'{wf.name}: "{wf.lane_arg}" must be a non-empty list from the board '
            f"(got {type(lanes).__name__}); this workflow has no built-in lane list")


def plan_agents(wf: Workflow, args: Mapping[str, Any]) -> int:
    """The dry-run agent count for these args: lanes * stages_per_lane + extra_agents."""
    lanes = args.get(wf.lane_arg)
    if not isinstance(lanes, list):
        raise WorkflowError(f'{wf.name}: "{wf.lane_arg}" must be a list to count agents')
    return len(lanes) * wf.stages_per_lane + wf.extra_agents


def effective_cap(wf: Workflow, args: Mapping[str, Any]) -> int:
    """The cap in force: the hard max, lowered (never raised) by an optional agentCap argument."""
    cap = wf.max_agents
    override = args.get("agentCap")
    if override is not None:
        if isinstance(override, bool) or not isinstance(override, int) or override < 1:
            raise WorkflowError(f"{wf.name}: agentCap must be a positive integer")
        cap = min(cap, override)
    return cap


def check_cap(wf: Workflow, args: Mapping[str, Any]) -> int:
    """Raise WorkflowError when the dry-run agent count exceeds the cap; return the count otherwise.
    Enforced before launch, so an over-cap fan-out spawns zero agents."""
    planned = plan_agents(wf, args)
    cap = effective_cap(wf, args)
    if planned > cap:
        raise WorkflowError(
            f"{wf.name}: agent cap exceeded: dry-run plans {planned} agents > cap {cap}. "
            f"Narrow the lanes or lower the count (hard ceiling {wf.max_agents}).")
    return planned


def preflight(wf: Workflow, args: Mapping[str, Any]) -> int:
    """The full pre-launch gate: schema check then cap check. Returns the dry-run agent count."""
    validate(wf, args)
    return check_cap(wf, args)


# --------------------------------------------------------------------------- lanes from the board

def lanes_from_board(workdir: Path | None = None) -> list[str]:
    """The distinct lanes the dispatch board currently shows, sorted. Each claim's canonical lane
    (ctf.dispatch), falling back to its canonicalised category. An unreadable claim raises (never
    skipped: a skipped claim would silently drop that lane)."""
    from . import dispatch, triage
    claims, bad = dispatch.read_claims(workdir)
    if bad:
        p, reason = bad[0]
        raise WorkflowError(f"{p}: unreadable dispatch claim ({reason}); fix it before deriving lanes")
    lanes: set[str] = set()
    for rec in claims.values():
        lane = rec.get("lane") or triage.canonical_category(rec.get("category", ""))
        if lane:
            lanes.add(lane)
    return sorted(lanes)


def lanes_from_profile(profile) -> list[str]:
    """The event's categories, canonicalised and sorted (ctf.event EventProfile.categories)."""
    from . import triage
    return sorted({triage.canonical_category(c) for c in profile.categories if c})
