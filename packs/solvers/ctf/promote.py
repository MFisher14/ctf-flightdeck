"""Post-event promotion (B-038): inventory what an event changed, propose where each piece goes in
the master, and record the decisions the fold-audit gate (ctf/foldaudit.py) checks.

An event runs from a master commit, anchored by the git tag `event/<slug>/start` (made by
`python -m ctf promote start <slug>`). During the event, fixes land in an event fork (a clone or a
worktree of the master, often uncommitted) and solve scripts pile up in the workspace. After the
event:

    rec = promote.inventory("csctf", fork=Path("..."), workspace=Path("..."))   # or the CLI
    promote.save_record(rec)                       # <master>/events/<slug>/promotion.json
    promote.decide(rec, "fork:tools/unpack.py", {"action": "fold"})
    promote.accept(rec, ["workspace:12-baby-rsa/solve_ww.py"])   # take the proposal as the decision

Inventory rules:

- fork: every file that differs between the start commit and the fork's working tree (committed,
  uncommitted or untracked-but-not-ignored). The state says which, because uncommitted live fixes are
  the ones that got lost before.
- workspace: every script file (by extension) under the workdir, except downloaded challenge files
  (`files/` folders) and tool state. Data files there are not inventoried.
- `.git`, `.ctf`, virtualenvs and caches are never read.

Decisions (`action`):

- `engine`: the script becomes an engine: `module`, `manifest` (its sidecar) and `test`.
- `fold`: the change reaches the master at `dest` (default: the same path); `commit` optionally names
  the master commit that folded it, for a fix that was adapted rather than copied.
- `drop`: not promoted; `reason` is required.

Content is identified by its git blob id, so "the fix is in the master" can be checked against any
master ref without reading the fork again. Nothing here executes a file it inventories.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import re
import stat
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable

from . import ledger, paths

SCHEMA = 1
RECORD_NAME = "promotion.json"
TAG_PREFIX = "event/"
ACTIONS = ("engine", "fold", "drop")
SOURCES = ("fork", "workspace")

SCRIPT_EXTS = frozenset({
    ".py", ".sage", ".sh", ".bash", ".zsh", ".js", ".mjs", ".cjs", ".ts", ".rb", ".pl", ".php",
    ".go", ".rs", ".c", ".cc", ".cpp", ".h", ".java", ".kt", ".lua", ".ps1", ".r", ".jl", ".gdb",
})
# Never read: tool state, credentials folders, environments, caches.
SKIP_PARTS = frozenset({".git", ".ctf", ".venv", "venv", "__pycache__", "node_modules", ".pytest_cache",
                        ".mypy_cache", ".ruff_cache", ".tox", ".idea", ".vscode"})
SKIP_SUFFIXES = frozenset({".pyc", ".pyo"})
SKIP_NAMES = frozenset({".DS_Store"})
# Workspace folders that hold challenge attachments, not our code.
WORKSPACE_DATA_DIRS = frozenset({"files", "dist", "handout", "attachments"})
# Master folders whose new files are master code already (fold as they are, not new engines).
MASTER_CODE_TOPS = frozenset({"ctf", "tools", "tests", "docs", "events", "templates", "docker", "speedrun"})
GENERIC_STEMS = frozenset({"solve", "solver", "sol", "solution", "exploit", "exp", "x", "a", "b", "run",
                           "main", "script", "poc", "attack", "pwn", "sa", "decode", "s", "test", "tmp",
                           "foo", "go", "do", "try", "work", "check", "get", "flag"})


class PromoteError(RuntimeError):
    """A promotion step cannot proceed; the message names what is missing."""


# ------------------------------------------------------------------------------------------- git

def git(repo: Path, *args: str, check: bool = True) -> str:
    """Run git in `repo` and return stdout (stripped of the final newline). Fails naming the call."""
    try:
        proc = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True,
                              timeout=120, env={**os.environ, "GIT_TERMINAL_PROMPT": "0",
                                                "GIT_OPTIONAL_LOCKS": "0"})
    except FileNotFoundError:
        raise PromoteError("git is not installed (needed to compare the event with the master)") from None
    if check and proc.returncode != 0:
        raise PromoteError(f"git {' '.join(args)} failed in {repo}: "
                           f"{(proc.stderr or proc.stdout).strip() or 'exit ' + str(proc.returncode)}")
    return proc.stdout[:-1] if proc.stdout.endswith("\n") else proc.stdout


def _git_z(repo: Path, *args: str) -> list[str]:
    out = git(repo, *args)
    return [p for p in out.split("\0") if p]


def is_repo(path: Path) -> bool:
    try:
        return git(path, "rev-parse", "--is-inside-work-tree") == "true"
    except PromoteError:
        return False


def require_repo(path: Path, role: str) -> Path:
    path = Path(path)
    if not path.is_dir():
        raise PromoteError(f"{role} {path} is not a directory")
    if not is_repo(path):
        raise PromoteError(f"{role} {path} is not a git checkout")
    return Path(git(path, "rev-parse", "--show-toplevel"))


def commit_of(repo: Path, ref: str) -> str | None:
    out = git(repo, "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}", check=False)
    return out.strip() or None


def blob_at(repo: Path, ref: str, path: str) -> str | None:
    """The blob id of `path` at `ref`, or None when the path is not a file there."""
    out = git(repo, "rev-parse", "--verify", "--quiet", f"{ref}:{path}", check=False).strip()
    if not out:
        return None
    kind = git(repo, "cat-file", "-t", out, check=False).strip()
    return out if kind == "blob" else None


def read_blob(repo: Path, blob: str) -> bytes:
    proc = subprocess.run(["git", "-C", str(repo), "cat-file", "blob", blob], capture_output=True, timeout=120)
    if proc.returncode != 0:
        raise PromoteError(f"git cat-file blob {blob} failed in {repo}")
    return proc.stdout


def is_ancestor(repo: Path, commit: str, of: str) -> bool:
    proc = subprocess.run(["git", "-C", str(repo), "merge-base", "--is-ancestor", commit, of],
                          capture_output=True, timeout=120)
    if proc.returncode not in (0, 1):
        raise PromoteError(f"git merge-base --is-ancestor {commit} {of} failed in {repo}: "
                           f"{proc.stderr.decode(errors='replace').strip()}")
    return proc.returncode == 0


def changed_paths(repo: Path, commit: str) -> set[str]:
    """Paths `commit` changes against its first parent (every path of a root commit). A merge
    commit counts what it brought into the first-parent line."""
    parents = git(repo, "rev-list", "--parents", "-n", "1", commit).split()[1:]
    if parents:
        return set(_git_z(repo, "diff", "--name-only", "-z", "--no-renames", parents[0], commit))
    return set(_git_z(repo, "diff-tree", "--root", "-r", "--name-only", "-z", "--no-renames",
                      "--no-commit-id", commit))


def decision_paths(d: dict) -> list[str]:
    """The master paths a fold or engine decision puts the event's change at."""
    return list(d["dest"]) if d["action"] == "fold" else [d["module"], d["manifest"], d["test"]]


def start_tag(slug: str) -> str:
    _check_slug(slug)
    return f"{TAG_PREFIX}{slug}/start"


def _check_slug(slug: str) -> None:
    if not re.match(r"^[a-z0-9][a-z0-9-]{0,63}$", slug or ""):
        raise PromoteError(f"bad event slug {slug!r}")


def blob_id(path: Path) -> str:
    """The git blob id of a file (or of a symlink's target text, as git stores it). Never follows
    a symlink, never executes anything."""
    st = os.lstat(path)
    h = hashlib.sha1()
    if stat.S_ISLNK(st.st_mode):
        data = os.fsencode(os.readlink(path))
        h.update(b"blob %d\0" % len(data))
        h.update(data)
        return h.hexdigest()
    h.update(b"blob %d\0" % st.st_size)
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ----------------------------------------------------------------------------------------- record

@dataclass
class Entry:
    source: str                    # fork | workspace
    path: str                      # posix, relative to the fork root or the workspace
    change: str                    # added | modified | deleted
    state: str                     # committed | uncommitted | untracked | workspace
    blob: str | None               # git blob id of the event's content; None when deleted
    size: int = 0
    proposal: dict = field(default_factory=dict)
    decision: dict | None = None
    stale: bool = False            # no longer in the event's tree; kept because it was decided

    @property
    def key(self) -> str:
        return f"{self.source}:{self.path}"


@dataclass
class Record:
    event: str
    base: str                      # the master commit the event started from
    base_ref: str                  # how it was named (normally the start tag)
    fork_head: str | None
    inventoried: str
    entries: list[Entry] = field(default_factory=list)
    schema: int = SCHEMA

    def get(self, key: str) -> Entry:
        return find_entry(self, key)

    def pending(self) -> list[Entry]:
        return [e for e in self.entries if e.decision is None]

    def to_json(self) -> str:
        d = asdict(self)
        d["entries"] = [asdict(e) for e in sorted(self.entries, key=lambda e: e.key)]
        return json.dumps(d, indent=1, sort_keys=True) + "\n"


_ENTRY_KEYS = {f for f in Entry.__dataclass_fields__}
_RECORD_KEYS = {f for f in Record.__dataclass_fields__}


def record_path(slug: str, master: Path | None = None) -> Path:
    _check_slug(slug)
    if master is None:
        return paths.event_dir(slug) / RECORD_NAME
    return Path(master) / "events" / slug / RECORD_NAME


def parse_record(data: Any, src: str = "<record>") -> Record:
    if not isinstance(data, dict):
        raise PromoteError(f"{src}: a promotion record is a JSON object")
    if data.get("schema") != SCHEMA:
        raise PromoteError(f"{src}: schema {data.get('schema')!r} is not {SCHEMA}")
    unknown = set(data) - _RECORD_KEYS
    if unknown:
        raise PromoteError(f"{src}: unknown key(s) {', '.join(sorted(unknown))}")
    for k in ("event", "base", "base_ref", "inventoried"):
        if not isinstance(data.get(k), str) or not data[k]:
            raise PromoteError(f"{src}: '{k}' must be a non-empty string")
    entries = []
    for n, raw in enumerate(data.get("entries") or []):
        where = f"{src}: entries[{n}]"
        if not isinstance(raw, dict):
            raise PromoteError(f"{where} is not an object")
        bad = set(raw) - _ENTRY_KEYS
        if bad:
            raise PromoteError(f"{where}: unknown key(s) {', '.join(sorted(bad))}")
        try:
            e = Entry(**raw)
        except TypeError as exc:
            raise PromoteError(f"{where}: {exc}") from None
        if e.source not in SOURCES:
            raise PromoteError(f"{where}: source {e.source!r} is not one of {SOURCES}")
        if e.change not in ("added", "modified", "deleted"):
            raise PromoteError(f"{where}: change {e.change!r} is not added|modified|deleted")
        if (e.blob is None) != (e.change == "deleted"):
            raise PromoteError(f"{where}: blob must be null exactly when the change is 'deleted'")
        if e.decision is not None:
            try:
                e.decision = validate_decision(e, e.decision)
            except PromoteError as exc:
                raise PromoteError(f"{where} ({e.key}): {exc}") from None
        entries.append(e)
    keys = [e.key for e in entries]
    if len(set(keys)) != len(keys):
        raise PromoteError(f"{src}: duplicate entries")
    return Record(event=data["event"], base=data["base"], base_ref=data["base_ref"],
                  fork_head=data.get("fork_head"), inventoried=data["inventoried"], entries=entries)


def load_record(slug: str, master: Path | None = None, path: Path | None = None) -> Record:
    p = Path(path) if path else record_path(slug, master)
    if not p.is_file():
        raise PromoteError(f"no promotion record for '{slug}' at {p}: run "
                           f"`python -m ctf promote inventory {slug} --fork <event checkout>` first")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise PromoteError(f"{p}: unreadable promotion record: {e}") from None
    rec = parse_record(data, str(p))
    if rec.event != slug:
        raise PromoteError(f"{p}: the record is for event '{rec.event}', not '{slug}'")
    return rec


def save_record(rec: Record, master: Path | None = None, path: Path | None = None) -> Path:
    p = Path(path) if path else record_path(rec.event, master)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + ".tmp")
    tmp.write_text(rec.to_json(), encoding="utf-8")
    os.replace(tmp, p)
    return p


def find_entry(rec: Record, key: str) -> Entry:
    """By full key (`fork:<path>`, `workspace:<path>`) or by a path that names one entry."""
    for e in rec.entries:
        if e.key == key:
            return e
    hits = [e for e in rec.entries if e.path == key]
    if len(hits) == 1:
        return hits[0]
    if hits:
        raise PromoteError(f"'{key}' is in both the fork and the workspace: use "
                           + " or ".join(e.key for e in hits))
    raise PromoteError(f"no inventoried entry '{key}' in the record for '{rec.event}'")


# ------------------------------------------------------------------------------------- inventory

def _skipped(rel: str) -> bool:
    parts = rel.split("/")
    return (any(p in SKIP_PARTS for p in parts[:-1]) or parts[-1] in SKIP_NAMES
            or parts[-1] in SKIP_PARTS or Path(rel).suffix in SKIP_SUFFIXES)


def _size(p: Path) -> int:
    st = os.lstat(p)
    return len(os.readlink(p)) if stat.S_ISLNK(st.st_mode) else st.st_size


def inventory_fork(fork: Path, base: str) -> list[Entry]:
    """Every file that differs between `base` and the fork's working tree, with its state."""
    root = require_repo(fork, "event fork")
    if commit_of(root, base) is None:
        raise PromoteError(f"the event fork {root} does not contain the start commit {base}: fetch the "
                           f"master (with tags) into the fork first")
    head = commit_of(root, "HEAD")
    committed = set(_git_z(root, "diff", "--name-only", "-z", "--no-renames", base, head)) if head else set()
    dirty = set(_git_z(root, "diff", "--name-only", "-z", "--no-renames", "HEAD")) if head else set()
    status = _git_z(root, "diff", "--name-status", "-z", "--no-renames", base)
    out: list[Entry] = []
    it = iter(status)
    for code in it:
        rel = next(it)
        if _skipped(rel):
            continue
        change = {"A": "added", "D": "deleted"}.get(code[0], "modified")
        state = "uncommitted" if rel in dirty else "committed" if rel in committed else "uncommitted"
        p = root / rel
        if change == "deleted" or not os.path.lexists(p):
            out.append(Entry("fork", rel, "deleted", state, None))
        else:
            out.append(Entry("fork", rel, change, state, blob_id(p), _size(p)))
    for rel in _git_z(root, "ls-files", "--others", "--exclude-standard", "-z"):
        if _skipped(rel):
            continue
        p = root / rel
        if os.path.lexists(p) and not p.is_dir():
            out.append(Entry("fork", rel, "added", "untracked", blob_id(p), _size(p)))
    return sorted(out, key=lambda e: e.path)


def inventory_workspace(workspace: Path) -> list[Entry]:
    """Script files we wrote in the event workdir. Attachments (`files/` and similar) and data are
    not inventoried; nothing is opened except to hash it."""
    ws = Path(workspace)
    if not ws.is_dir():
        raise PromoteError(f"workspace {ws} is not a directory")
    out: list[Entry] = []
    for dirpath, dirnames, filenames in os.walk(ws, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_PARTS and d not in WORKSPACE_DATA_DIRS)
        for name in sorted(filenames):
            p = Path(dirpath) / name
            rel = p.relative_to(ws).as_posix()
            if _skipped(rel) or Path(name).suffix.lower() not in SCRIPT_EXTS:
                continue
            if not (p.is_file() or p.is_symlink()):
                continue
            out.append(Entry("workspace", rel, "added", "workspace", blob_id(p), _size(p)))
    return out


def resolve_base(slug: str, *, master: Path, fork: Path | None, base: str | None = None) -> tuple[str, str]:
    """(ref name, commit) of the master commit the event started from: `base` if given, else the
    start tag, looked up in the fork and then the master. Fails loudly when neither has it."""
    ref = base or start_tag(slug)
    for repo in [r for r in (fork, master) if r is not None]:
        if is_repo(repo):
            sha = commit_of(repo, ref if base else f"refs/tags/{ref}")
            if sha:
                return ref, sha
    where = " or ".join(str(r) for r in (fork, master) if r is not None)
    if base:
        raise PromoteError(f"--base {base} is not a commit in {where}")
    raise PromoteError(f"no tag {ref} in {where}: tag the master commit the event started from "
                       f"(`python -m ctf promote start {slug}` before the event, or "
                       f"`git tag {ref} <commit>` now) or pass --base <commit>")


# -------------------------------------------------------------------------------------- proposals

def _snake(s: str) -> str:
    s = re.sub(r"[^0-9a-zA-Z]+", "_", s).strip("_").lower()
    return re.sub(r"_+", "_", s)


def engine_name(path: str) -> str:
    """A lower_snake engine name from a script path. A generic stem (solve, exploit, sa, ...) is
    qualified by its folder, minus a leading challenge id (`12-baby-rsa/solve.py` -> baby_rsa_solve)."""
    p = Path(path)
    stem = _snake(p.stem)
    if stem in GENERIC_STEMS or len(stem) < 3:
        parent = _snake(re.sub(r"^\d+[-_]+", "", p.parent.name)) if p.parent.name else ""
        stem = f"{parent}_{stem}" if parent else stem
    if not stem or not stem[0].isalpha():
        stem = f"e_{stem}" if stem else "event_script"
    return stem


def engine_paths(lane: str, name: str, suffix: str = ".py") -> dict[str, str]:
    if not re.match(r"^[a-z][a-z0-9_-]*$", lane or ""):
        raise PromoteError(f"bad lane {lane!r} (a solvers/<lane> folder name)")
    if not re.match(r"^[a-z][a-z0-9_]*$", name or ""):
        raise PromoteError(f"bad engine name {name!r} (lower_snake)")
    return {"module": f"solvers/{lane}/{name}{suffix}",
            "manifest": f"solvers/{lane}/{name}.manifest.toml",
            "test": f"tests/test_{lane.replace('-', '_')}_{name}.py"}


def is_script(path: str) -> bool:
    return Path(path).suffix.lower() in SCRIPT_EXTS


def propose(e: Entry, master: Path, ref: str = "HEAD") -> dict:
    """Where this change should go in the master. A proposal only: the decision is the player's."""
    if e.change == "deleted":
        return {"action": "fold", "dest": [e.path],
                "why": "the event deleted a master file: delete it in the master too, or drop it with a reason"}
    if e.source == "fork" and blob_at(master, ref, e.path) == e.blob:
        return {"action": "fold", "dest": [e.path], "why": "already in the master (identical content)"}
    if not is_script(e.path):
        if e.source == "fork" and e.change == "modified":
            return {"action": "fold", "dest": [e.path], "why": "change to a master file"}
        top = e.path.split("/", 1)[0]
        if e.source == "fork" and top in MASTER_CODE_TOPS:
            return {"action": "fold", "dest": [e.path], "why": "new master file"}
        return {"action": "drop", "reason": "not code: challenge data and outputs never enter the master"}
    if e.source == "fork" and e.change == "modified":
        return {"action": "fold", "dest": [e.path],
                "why": "live fix to a master file: fold it and add a regression test that fails without it"}
    parts = e.path.split("/")
    if e.source == "fork" and parts[0] in MASTER_CODE_TOPS:
        return {"action": "fold", "dest": [e.path], "why": "new master file"}
    if e.source == "fork" and parts[0] == "solvers" and len(parts) >= 3:
        lane, name = parts[1], _snake(Path(e.path).stem)
        prop = {"action": "engine", **engine_paths(lane, name if name[:1].isalpha() else f"e_{name}"),
                "why": "new engine file: add its manifest and a test"}
        prop["module"] = e.path
        return prop
    name = engine_name(e.path)
    prop = {"action": "engine", **engine_paths("common", name, Path(e.path).suffix.lower()),
            "why": "event script: make it an engine (the lane is a guess; set it when deciding)"}
    if blob_at(master, ref, prop["module"]) is not None:
        prop["why"] += f"; {prop['module']} already exists in the master: pick another name"
    return prop


# -------------------------------------------------------------------------------------- decisions

def validate_decision(e: Entry, d: dict) -> dict:
    """A normalised decision, or PromoteError naming what is wrong."""
    if not isinstance(d, dict):
        raise PromoteError("a decision is an object")
    action = d.get("action")
    if action not in ACTIONS:
        raise PromoteError(f"decision action {action!r} is not one of {', '.join(ACTIONS)}")
    allowed = {"engine": {"action", "module", "manifest", "test", "commit", "why", "decided"},
               "fold": {"action", "dest", "commit", "why", "decided"},
               "drop": {"action", "reason", "why", "decided"}}[action]
    extra = set(d) - allowed
    if extra:
        raise PromoteError(f"'{action}' decision has unknown key(s) {', '.join(sorted(extra))}")
    out = dict(d)
    if action == "drop":
        if not isinstance(d.get("reason"), str) or not d["reason"].strip():
            raise PromoteError("a 'drop' decision needs a reason")
    elif action == "fold":
        # a fork change defaults to its own path; a workspace script has no master path to default to
        dest = (d.get("dest") or [e.path]) if e.source == "fork" else d.get("dest")
        if not dest or not isinstance(dest, list) or not all(isinstance(x, str) and x for x in dest):
            raise PromoteError("a 'fold' decision needs dest (the master path(s) it reached)")
        for x in dest:
            _rel_path(x, "dest")
        out["dest"] = list(dest)
    else:
        from .engines import manifest as _m
        for k in ("module", "manifest", "test"):
            if not isinstance(d.get(k), str) or not d[k]:
                raise PromoteError(f"an 'engine' decision needs {k}")
            _rel_path(d[k], k)
        mod = d["module"]
        if mod.split("/", 1)[0] not in _m.ENGINE_ROOTS:
            raise PromoteError(f"engine module {mod} is not under {' or '.join(_m.ENGINE_ROOTS)}/")
        if d["manifest"] != _m.sidecar_for(Path(mod)).as_posix():
            raise PromoteError(f"engine manifest must be the module's sidecar "
                               f"{_m.sidecar_for(Path(mod)).as_posix()}, not {d['manifest']}")
        t = Path(d["test"])
        if t.parts[0] != "tests" or not (t.name.startswith("test_") and t.suffix == ".py"):
            raise PromoteError(f"engine test {d['test']} must be tests/**/test_*.py")
    if "commit" in out and (not isinstance(out["commit"], str) or not re.match(r"^[0-9a-f]{7,64}$", out["commit"])):
        raise PromoteError(f"commit {out['commit']!r} is not a commit id")
    return out


def _rel_path(p: str, what: str) -> None:
    if p.startswith("/") or ".." in Path(p).parts or "\\" in p:
        raise PromoteError(f"{what} {p!r} must be a path relative to the master root")


def decide(rec: Record, key: str, decision: dict, *, master: Path | None = None,
           now: _dt.datetime | None = None, log: bool = True) -> Entry:
    """Record a decision for one entry. A `commit` is resolved to its full id in the master and must
    come after the event's start commit and change one of the decision's paths (the gate re-checks)."""
    e = find_entry(rec, key)
    d = validate_decision(e, decision)
    if d.get("commit"):
        if master is None:
            raise PromoteError("a decision with a commit needs the master checkout to resolve it")
        full = commit_of(master, d["commit"])
        if full is None:
            raise PromoteError(f"commit {d['commit']} is not in the master {master}")
        base = commit_of(master, rec.base)
        if base is not None and is_ancestor(master, full, base):
            raise PromoteError(f"commit {d['commit']} is at or before the event's start commit "
                               f"{base[:12]}: name the master commit that folded the change")
        touched = decision_paths(d)
        if not changed_paths(master, full) & set(touched):
            raise PromoteError(f"commit {d['commit']} does not change {', '.join(touched)}: name the "
                               f"master commit that folded the change")
        d["commit"] = full
    d["decided"] = (now or _dt.datetime.now(_dt.timezone.utc)).isoformat(timespec="seconds")
    e.decision = d
    if log:
        ledger.append("promote.decide", workdir=paths.workdir(rec.event), slug=rec.event, entry=e.key,
                      action=d["action"])
    return e


def accept(rec: Record, keys: Iterable[str] | None, *, master: Path | None = None, log: bool = True,
           now: _dt.datetime | None = None) -> list[Entry]:
    """Take each entry's proposal as its decision (all undecided entries when keys is None)."""
    targets = rec.pending() if keys is None else [find_entry(rec, k) for k in keys]
    done = []
    for e in targets:
        if not e.proposal:
            raise PromoteError(f"{e.key} has no proposal to accept")
        prop = {k: v for k, v in e.proposal.items() if k != "why"}
        done.append(decide(rec, e.key, prop, master=master, log=log, now=now))
    return done


# ----------------------------------------------------------------------------------------- driver

def inventory(slug: str, *, master: Path | None = None, fork: Path | None = None,
              workspace: Path | None = None, base: str | None = None, previous: Record | None = None,
              now: _dt.datetime | None = None, log: bool = True) -> Record:
    """Build the promotion record for an event. Decisions in `previous` carry over for content that
    has not changed; a decided entry that left the event's tree is kept and marked stale."""
    _check_slug(slug)
    if fork is None and workspace is None:
        raise PromoteError("nothing to inventory: give the event fork, the workspace, or both")
    master = require_repo(paths.repo_root() if master is None else Path(master), "master")
    base_ref, base_sha = resolve_base(slug, master=master, fork=fork, base=base)
    entries: list[Entry] = []
    fork_head = None
    if fork is not None:
        entries += inventory_fork(fork, base_sha)
        fork_head = commit_of(require_repo(fork, "event fork"), "HEAD")
    if workspace is not None:
        entries += inventory_workspace(workspace)
    for e in entries:
        e.proposal = propose(e, master)
    if previous is not None:
        if previous.event != slug:
            raise PromoteError(f"the previous record is for '{previous.event}', not '{slug}'")
        old = {e.key: e for e in previous.entries}
        new_keys = {e.key for e in entries}
        for e in entries:
            o = old.get(e.key)
            if o is not None and o.decision is not None and o.blob == e.blob and o.change == e.change:
                e.decision = o.decision
        entries += [replace_stale(o) for k, o in old.items() if k not in new_keys and o.decision is not None]
    rec = Record(event=slug, base=base_sha, base_ref=base_ref, fork_head=fork_head,
                 inventoried=(now or _dt.datetime.now(_dt.timezone.utc)).isoformat(timespec="seconds"),
                 entries=sorted(entries, key=lambda e: e.key))
    if log:
        ledger.append("promote.inventory", workdir=paths.workdir(slug), slug=slug, base=base_sha,
                      entries=len(rec.entries), pending=len(rec.pending()))
    return rec


def replace_stale(e: Entry) -> Entry:
    return Entry(e.source, e.path, e.change, e.state, e.blob, e.size, dict(e.proposal),
                 dict(e.decision) if e.decision else None, stale=True)


def tag_start(slug: str, *, master: Path | None = None, ref: str = "HEAD",
              now: _dt.datetime | None = None, log: bool = True) -> tuple[str, list]:
    """Tag the master commit an event starts from as event/<slug>/start, after the fold-audit of
    every earlier event passes against that commit. Returns (commit, audit results). Refuses
    (FoldAuditFailed) when an earlier event's live fix has not reached it."""
    from . import foldaudit
    master = require_repo(paths.repo_root() if master is None else Path(master), "master")
    tag = start_tag(slug)
    sha = commit_of(master, ref)
    if sha is None:
        raise PromoteError(f"{ref} is not a commit in {master}")
    if commit_of(master, f"refs/tags/{tag}"):
        raise PromoteError(f"tag {tag} already exists in {master}; an event has one start")
    results = foldaudit.audit_all(master=master, target=sha, exclude={slug}, now=now, log=log)
    failed = [r for r in results if not r.passed]
    if failed:
        raise foldaudit.FoldAuditFailed(failed)
    git(master, "tag", "-a", tag, "-m", f"{slug}: the master commit this event starts from", sha)
    if log:
        ledger.append("promote.start", workdir=paths.workdir(slug), slug=slug, commit=sha,
                      audited=len(results))
    return sha, results
