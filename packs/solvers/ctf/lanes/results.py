"""Lane results: the machine-readable manifest each lane writes, the checks run against its branch,
and integration into a target checkout (B-179).

result.json (written by the lane; unknown keys are an error):

    {"schema": 1, "lane": "<id>", "status": "built" | "partial" | "blocked",
     "summary": "...",                                   # required, non-empty
     "commit": "<sha>",                                  # optional: the lane's final commit
     "engines": [{"id": "crypto.pqc_parse", "manifest": "solvers/crypto/pqc_parse.manifest.toml"}],
     "capabilities": [{"section": "Crypto — RSA", "key": "pqc_parse", "text": "..."}],
     "tests": ["tests/test_crypto_pqc.py"], "tests_run": "12 passed",
     "gaps": "", "human_steps": [], "followups": [], "shared_files": []}

collect() checks each lane against its checkout: the result parses and names the lane; a "built"
lane has commits; a claimed commit is on the branch; every changed file is owned by the lane or
declared in shared_files (a protected file such as docs/CAPABILITIES.md is never acceptable: lanes
declare capability entries, integrate applies them); each declared engine manifest exists at HEAD,
parses, and carries the declared id; each test file exists at HEAD.

integrate() adds cross-lane checks: an engine id or engine basename claimed twice (two lanes, or a
lane and the target), route conflicts between engines from different lanes (lint's rule: shared claim,
overlapping categories, missing or equal priority), route-lint errors a lane introduces relative to
the target, CAPABILITIES keys claimed twice or already present, and unknown sections. Every lane in a
collision is held; the operator decides. With merge=True the clean lanes' branches are fetched from
their checkouts and merged into the target in dependency order (a conflict aborts that merge and holds
its dependents). With apply=True the entries are written into the target's docs/CAPABILITIES.md
(left uncommitted for review).
"""
from __future__ import annotations

import fnmatch
import re
import tomllib
from dataclasses import asdict, dataclass, field
from itertools import combinations
from pathlib import Path

from . import checkout as _co
from .backlog import Backlog
from .layout import BatchDirs, read_json, write_json

SCHEMA = 1
STATUSES = ("built", "partial", "blocked")
KEY_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
SHA_RE = re.compile(r"^[0-9a-f]{7,40}$")
CAPABILITIES_REL = "docs/CAPABILITIES.md"
MANIFEST_SUFFIX = ".manifest.toml"

_KEYS = {"schema", "lane", "status", "summary", "commit", "engines", "capabilities", "tests",
         "tests_run", "gaps", "human_steps", "followups", "shared_files"}

EXAMPLE = {
    "schema": SCHEMA, "lane": "<lane id>", "status": "built",
    "summary": "what you built and how it meets the acceptance",
    "commit": "<the sha of your last commit>",
    "engines": [{"id": "<lane>.<name>", "manifest": "solvers/<lane>/<name>.manifest.toml"}],
    "capabilities": [{"section": "<an existing '## ' heading of docs/CAPABILITIES.md, without '## '>",
                      "key": "<engine basename>", "text": "<one bullet line describing it>"}],
    "tests": ["tests/test_<area>_<topic>.py"], "tests_run": "<command and pass/fail counts you saw>",
    "gaps": "", "human_steps": [], "followups": [], "shared_files": [],
}


class ResultError(ValueError):
    """result.json is missing or malformed. Names the file and key."""


@dataclass(frozen=True)
class EngineDecl:
    id: str
    manifest: str

    @property
    def basename(self) -> str:
        return Path(self.manifest).name[: -len(MANIFEST_SUFFIX)]


@dataclass(frozen=True)
class CapEntry:
    section: str
    key: str
    text: str

    def bullet(self) -> str:
        t = " ".join(self.text.split())
        return f"- {t}" if f"`{self.key}" in t else f"- {t} (`{self.key}`)"


@dataclass(frozen=True)
class LaneResult:
    lane: str
    status: str
    summary: str
    commit: str | None = None
    engines: tuple[EngineDecl, ...] = ()
    capabilities: tuple[CapEntry, ...] = ()
    tests: tuple[str, ...] = ()
    tests_run: str = ""
    gaps: str = ""
    human_steps: tuple[str, ...] = ()
    followups: tuple[str, ...] = ()
    shared_files: tuple[str, ...] = ()


def _e(src, key, msg):
    return ResultError(f"{src}: {key}: {msg}")


def _strlist(src, key, v):
    if v is None:
        return ()
    if not isinstance(v, list) or not all(isinstance(x, str) and x.strip() for x in v):
        raise _e(src, key, "must be a list of non-empty strings")
    return tuple(v)


def _s(src, key, v, required=False):
    if v is None and not required:
        return ""
    if not isinstance(v, str) or (required and not v.strip()):
        raise _e(src, key, "must be a non-empty string" if required else "must be a string")
    return v


def parse_result(data, lane_id: str, src: str = "result.json") -> LaneResult:
    if not isinstance(data, dict):
        raise _e(src, "(top level)", "must be a JSON object")
    bad = sorted(set(data) - _KEYS)
    if bad:
        raise _e(src, "(top level)", f"unknown key(s) {', '.join(bad)}")
    for k in ("schema", "lane", "status", "summary"):
        if k not in data:
            raise _e(src, k, "required key missing")
    if data["schema"] != SCHEMA or isinstance(data["schema"], bool):
        raise _e(src, "schema", f"must be {SCHEMA} (got {data['schema']!r})")
    if data["lane"] != lane_id:
        raise _e(src, "lane", f"names {data['lane']!r}, expected {lane_id!r}")
    if data["status"] not in STATUSES:
        raise _e(src, "status", f"must be one of {', '.join(STATUSES)} (got {data['status']!r})")
    commit = data.get("commit")
    if commit is not None and (not isinstance(commit, str) or not SHA_RE.match(commit)):
        raise _e(src, "commit", f"must be a hex commit id (got {commit!r})")
    for k in ("engines", "capabilities"):
        if data.get(k) is not None and not isinstance(data[k], list):
            raise _e(src, k, "must be a list")
    engines = []
    for i, e in enumerate(data.get("engines") or []):
        if not isinstance(e, dict) or set(e) != {"id", "manifest"} or not all(
                isinstance(e[k], str) and e[k] for k in ("id", "manifest")):
            raise _e(src, f"engines[{i}]", "must be {\"id\": str, \"manifest\": str}")
        if not e["manifest"].endswith(MANIFEST_SUFFIX) or e["manifest"].startswith("/") or ".." in e["manifest"]:
            raise _e(src, f"engines[{i}].manifest", f"{e['manifest']!r} must be a repo-relative *{MANIFEST_SUFFIX}")
        engines.append(EngineDecl(e["id"], e["manifest"]))
    caps = []
    for i, c in enumerate(data.get("capabilities") or []):
        if not isinstance(c, dict) or set(c) != {"section", "key", "text"} or not all(
                isinstance(c[k], str) and c[k].strip() for k in ("section", "key", "text")):
            raise _e(src, f"capabilities[{i}]", "must be {\"section\": str, \"key\": str, \"text\": str}")
        if not KEY_RE.match(c["key"]):
            raise _e(src, f"capabilities[{i}].key", f"{c['key']!r} must match {KEY_RE.pattern}")
        if "\n" in c["text"] or "\n" in c["section"]:
            raise _e(src, f"capabilities[{i}]", "section and text are single lines")
        caps.append(CapEntry(c["section"].strip(), c["key"], c["text"].strip()))
    return LaneResult(lane=lane_id, status=data["status"], summary=_s(src, "summary", data["summary"], True),
                      commit=commit, engines=tuple(engines), capabilities=tuple(caps),
                      tests=_strlist(src, "tests", data.get("tests")),
                      tests_run=_s(src, "tests_run", data.get("tests_run")),
                      gaps=_s(src, "gaps", data.get("gaps")),
                      human_steps=_strlist(src, "human_steps", data.get("human_steps")),
                      followups=_strlist(src, "followups", data.get("followups")),
                      shared_files=_strlist(src, "shared_files", data.get("shared_files")))


def load_result(path: Path, lane_id: str) -> LaneResult:
    import json
    if not Path(path).is_file():
        raise ResultError(f"{path}: no result.json (the lane did not write its result)")
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise ResultError(f"{path}: not valid JSON: {e}") from None
    return parse_result(data, lane_id, str(path))


# ---------------------------------------------------------------------------------------- collect

@dataclass
class LaneReport:
    lane: str
    state: str                                  # runner state, or "not-run"
    result: LaneResult | None = None
    head: str | None = None
    base: str | None = None
    commits: int = 0
    changed: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)       # block integration
    warnings: list[str] = field(default_factory=list)
    held: list[str] = field(default_factory=list)           # cross-lane reasons (integrate)
    integrated: str | None = None                            # merged | ready | None

    @property
    def ok(self) -> bool:
        return not self.problems and not self.held

    def to_dict(self) -> dict:
        d = asdict(self)
        d["result"] = asdict(self.result) if self.result else None
        return d


def _manifest_id(text: str, where: Path) -> str:
    from ..engines import manifest as _m
    return _m.parse(tomllib.loads(text), where).id


def check_lane(backlog: Backlog, dirs: BatchDirs, lane_id: str) -> LaneReport:
    lane = backlog.lane(lane_id)
    st = read_json(dirs.status(lane_id)) or {}
    rep = LaneReport(lane=lane_id, state=st.get("state", "not-run"))
    co = dirs.checkout(lane_id)
    if not (co / ".git").is_dir():
        rep.problems.append(f"no checkout at {co} (run setup)")
        return rep
    try:
        rep.result = load_result(dirs.result(lane_id), lane_id)
    except ResultError as e:
        rep.problems.append(str(e))
    rep.base = _co.start_of(co)          # the base, or the merge of the lane's dependencies
    rep.head = _co.head(co)
    rep.commits = _co.commits_since(co, rep.base)
    rep.changed = _co.changed_files(co, rep.base)
    res = rep.result
    if res is not None and res.status == "built" and rep.commits == 0:
        rep.problems.append("status built but the branch has no commits past the base")
    if res is not None and res.commit and not _co.is_ancestor(co, res.commit, "HEAD"):
        rep.problems.append(f"result commit {res.commit} is not on the lane branch")
    shared = set(res.shared_files) if res else set()
    for f in rep.changed:
        if any(f == p or fnmatch.fnmatchcase(f, p) for p in backlog.protected):   # protected may be globs
            rep.problems.append(f"changed protected file {f}"
                                + (" (declare capabilities in result.json instead)"
                                   if f == CAPABILITIES_REL else ""))
        elif not lane.owns_path(f):
            if f in shared:
                rep.warnings.append(f"declared shared file {f}")
            else:
                rep.problems.append(f"out of scope: {f} (not owned, not declared in shared_files)")
    dirty = _co.uncommitted(co)
    if dirty:
        rep.warnings.append(f"{len(dirty)} uncommitted path(s): {', '.join(dirty[:5])}"
                            + (" ..." if len(dirty) > 5 else ""))
    if res is not None:
        for e in res.engines:
            text = _co.show(co, "HEAD", e.manifest)
            if text is None:
                rep.problems.append(f"engine {e.id}: {e.manifest} is not committed on the branch")
                continue
            try:
                got = _manifest_id(text, co / e.manifest)
            except (tomllib.TOMLDecodeError, ValueError) as ex:
                rep.problems.append(f"engine {e.id}: {ex}")
                continue
            if got != e.id:
                rep.problems.append(f"engine {e.id}: {e.manifest} declares id {got!r}")
        if res.status == "built":
            for t in sorted(set(res.tests) | set(lane.tests)):
                if _co.show(co, "HEAD", t) is None:
                    rep.problems.append(f"test file {t} is not committed on the branch")
    return rep


def collect(backlog: Backlog, dirs: BatchDirs) -> dict[str, LaneReport]:
    return {lid: check_lane(backlog, dirs, lid) for lid in backlog.order()}


# -------------------------------------------------------------------------------------- integrate

def capability_sections(text: str) -> list[str]:
    return [ln[3:].strip() for ln in text.splitlines() if ln.startswith("## ")]


def capability_keys(text: str) -> set[str]:
    """Every backticked token in the document, with and without a .py suffix."""
    out = set()
    for tok in re.findall(r"`([^`\n]+)`", text):
        tok = tok.strip()
        out.add(tok)
        if tok.endswith(".py"):
            out.add(tok[:-3])
    return out


def apply_capabilities(text: str, entries: list[CapEntry]) -> str:
    lines = text.splitlines()
    for sec in dict.fromkeys(e.section for e in entries):
        start = next((i for i, ln in enumerate(lines) if ln.startswith("## ") and ln[3:].strip() == sec), None)
        if start is None:
            raise KeyError(f"no section '## {sec}' in {CAPABILITIES_REL}")
        end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("#")), len(lines))
        last = end
        while last > start + 1 and not lines[last - 1].strip():
            last -= 1
        new = [e.bullet() for e in entries if e.section == sec]
        lines[last:last] = new
    return "\n".join(lines) + ("\n" if text.endswith("\n") or not text else "")


def _route_conflicts(a: list, b: list) -> list[str]:
    from ..engines.lint import claims_overlap
    out = []
    for ma in a:
        for mb in b:
            if ma.id == mb.id or "retired" in (ma.status, mb.status):
                continue
            for ra in ma.routes:
                for rb in mb.routes:
                    if ra.matches_everything or rb.matches_everything:
                        continue
                    shared = claims_overlap(ra.category, ra.keywords, ra.files, rb.category, rb.keywords, rb.files)
                    if shared and (ra.priority is None or rb.priority is None or ra.priority == rb.priority):
                        out.append(f"{ma.id} and {mb.id} both claim {sorted(shared)[0]!r} "
                                   "with a missing or equal priority")
    return out


def _lane_manifests(dirs: BatchDirs, rep: LaneReport) -> list:
    from ..engines import manifest as _m
    out = []
    co = dirs.checkout(rep.lane)
    for e in rep.result.engines if rep.result else ():
        try:
            out.append(_m.load(co / e.manifest))
        except (OSError, _m.ManifestError):
            pass        # already a problem from check_lane
    return out


def _lint_errors(root: Path) -> set[tuple[str, str]]:
    from ..engines import lint as _lint
    return {(f.code, f.subject) for f in _lint.lint(root) if f.severity == "error"}


def integrate(backlog: Backlog, dirs: BatchDirs, target: Path, *, apply: bool = False,
              merge: bool = False, include_partial: bool = False, lint: bool = True) -> dict:
    from ..engines import layout as _layout, manifest as _m
    target = Path(target).resolve()
    reports = collect(backlog, dirs)
    wanted = ("built", "partial") if include_partial else ("built",)
    cand = {}
    for lid, rep in reports.items():
        if rep.result is None:
            rep.held.append("no valid result")
        elif rep.result.status not in wanted:
            rep.held.append(f"status {rep.result.status}")
        elif rep.problems:
            rep.held.append("lane checks failed")
        else:
            cand[lid] = rep

    # --- engine ids and basenames: across lanes and against the target
    tms, _ = _m.scan(target)
    target_ids = {m.id: m.path.relative_to(target).as_posix() for m in tms}
    target_mods = {}
    for p in _layout.engine_modules(target):
        target_mods.setdefault(p.stem, set()).add(p.relative_to(target).as_posix())
    claims_id: dict[str, list[tuple[str, str]]] = {}
    claims_base: dict[str, list[tuple[str, str]]] = {}
    for lid, rep in cand.items():
        for e in rep.result.engines:
            claims_id.setdefault(e.id, []).append((lid, e.manifest))
            mod = e.manifest[: -len(MANIFEST_SUFFIX)] + ".py"
            claims_base.setdefault(e.basename, []).append((lid, mod))
            if e.id in target_ids and target_ids[e.id] != e.manifest:
                rep.held.append(f"engine id {e.id} already used by {target_ids[e.id]} in the target")
            others = target_mods.get(e.basename, set()) - {mod}
            if others:
                rep.held.append(f"engine basename {e.basename} already used by {', '.join(sorted(others))} "
                                "in the target (flat imports would shadow)")
    for what, claims in (("engine id", claims_id), ("engine basename", claims_base)):
        for key, holders in claims.items():
            lanes = sorted({h[0] for h in holders})
            if len(lanes) > 1:
                for lid in lanes:
                    cand[lid].held.append(f"{what} {key} also claimed by lane(s) "
                                          f"{', '.join(x for x in lanes if x != lid)}")

    # --- route conflicts between lanes
    mans = {lid: _lane_manifests(dirs, rep) for lid, rep in cand.items()}
    for la, lb in combinations(sorted(cand), 2):
        for msg in _route_conflicts(mans[la], mans[lb]):
            cand[la].held.append(f"route conflict with lane {lb}: {msg}")
            cand[lb].held.append(f"route conflict with lane {la}: {msg}")

    # --- lint errors a lane introduces relative to the target
    if lint and cand:
        before = _lint_errors(target)
        for lid, rep in cand.items():
            new = sorted(_lint_errors(dirs.checkout(lid)) - before)
            for code, subj in new:
                rep.held.append(f"route lint {code} {subj}")

    # --- CAPABILITIES entries
    capdoc = target / CAPABILITIES_REL
    cap_text = capdoc.read_text(encoding="utf-8") if capdoc.is_file() else None
    by_key: dict[str, list[str]] = {}
    for lid, rep in cand.items():
        for c in rep.result.capabilities:
            by_key.setdefault(c.key, []).append(lid)
            if cap_text is None:
                rep.held.append(f"capability {c.key}: the target has no {CAPABILITIES_REL}")
                continue
            if c.section not in capability_sections(cap_text):
                rep.held.append(f"capability {c.key}: no section '## {c.section}' in {CAPABILITIES_REL}")
            if c.key in capability_keys(cap_text):
                rep.held.append(f"capability key {c.key} already in {CAPABILITIES_REL}")
    for key, lanes in by_key.items():
        if len(set(lanes)) > 1:
            for lid in sorted(set(lanes)):
                cand[lid].held.append(f"capability key {key} also claimed by lane(s) "
                                      f"{', '.join(x for x in sorted(set(lanes)) if x != lid)}")
        elif len(lanes) > 1:
            cand[lanes[0]].held.append(f"capability key {key} declared twice")

    # --- dependencies: a lane integrates only after everything it depends on
    for lid in backlog.order():          # dependencies come first, so their verdict is final here
        rep = reports[lid]
        bad = [d for d in backlog.lane(lid).depends if reports[d].integrated != "ready"]
        if bad:
            rep.held.append(f"dependency {', '.join(bad)} is not integrable")
        if rep.ok:
            rep.integrated = "ready"

    ready = [lid for lid in backlog.order() if reports[lid].integrated == "ready"]
    merge_log: list[str] = []
    if merge and ready:
        _require_clean_branch(target)
        for lid in ready:
            rep = reports[lid]
            if any(reports[d].integrated != "merged" for d in backlog.lane(lid).depends):
                rep.held.append("a dependency was not merged")
                rep.integrated = None
                continue
            br = backlog.branch(lid)
            _co.git(target, "fetch", "--quiet", "--no-tags", str(dirs.checkout(lid)), f"+refs/heads/{br}:refs/heads/{br}")
            p = _co.git(target, "merge", "--no-ff", "--no-edit", "-m",
                        f"Merge lane {lid} ({backlog.batch}): {backlog.lane(lid).title}", br, check=False)
            if p.returncode != 0:
                _co.git(target, "merge", "--abort", check=False)
                rep.held.append(f"merge conflict: {(p.stdout + p.stderr).strip().splitlines()[-1:]}")
                rep.integrated = None
                merge_log.append(f"{lid}: conflict, aborted")
            else:
                rep.integrated = "merged"
                merge_log.append(f"{lid}: merged {br}")

    applied: list[str] = []
    if apply:
        done = [lid for lid in backlog.order()
                if reports[lid].integrated == ("merged" if merge else "ready")]
        entries = [c for lid in done for c in reports[lid].result.capabilities]
        if entries:
            text = capdoc.read_text(encoding="utf-8")
            capdoc.write_text(apply_capabilities(text, entries), encoding="utf-8")
            applied = [f"{c.section}: {c.key}" for c in entries]

    out = {"batch": backlog.batch, "target": str(target), "merge": merge, "apply": apply,
           "lanes": {lid: reports[lid].to_dict() for lid in backlog.order()},
           "merged": merge_log, "capabilities_applied": applied}
    write_json(dirs.integration, out)
    return out


def _require_clean_branch(target: Path) -> None:
    if _co.current_branch(target) is None:
        raise _co.CheckoutError(f"{target}: HEAD is detached; check out the integration branch first")
    dirty = _co.git(target, "status", "--porcelain", "--untracked-files=no").stdout.strip()
    if dirty:
        raise _co.CheckoutError(f"{target}: uncommitted changes; commit or stash them before --merge")
