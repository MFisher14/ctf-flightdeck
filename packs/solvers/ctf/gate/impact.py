"""Test-impact selection over a static dependency graph.

A Python file's edges, read with `ast` (never imported or run):

    imports        `import a.b`, `from a.b import c`, relative imports; each resolved against the file's
                   own folder, the config's import roots and any repo folder the file names in a string
                   (the `sys.path.insert(0, REPO / "solvers" / "x")` idiom). Every root that resolves counts
                   (a superset of what Python would pick), and the `__init__.py` of each package on the way.
    module strings a string constant `a.b.c` or `a.b:func` that resolves to a repo module (importlib, -m, an
                   engine spec)
    file strings   a string constant naming a repo file: a repo-relative path, a path suffix (`web/x.py`) or
                   a bare base name shared by at most `basename_max` files. A `.py` file reached this way is
                   followed like an import (a script run by subprocess).
    dir strings    a string naming a repo folder at least two levels deep. It is an import root for that file
                   and, for a changed file nothing else maps, a dependency on everything under it.

A test file's closure is itself, the `conftest.py` files of its folders, and everything reachable from it.
`select()` maps changed files to test files:

  - a changed global input (config `global`) -> full run, naming the file
  - a changed file inside a test's closure, or matching a scan rule's inputs -> that test
  - a deleted file -> the tests whose closure has an import or file string that resolved to nothing and
    names it (a deleted module breaks its importers; they must run)
  - else a test whose closure names a folder holding the file
  - else, inert (docs) -> nothing; anything else is unmapped -> full run, naming the file

Static analysis misses what code computes at run time (a module name built from parts, a file found by
walking a folder no test names). That is why a full run happens once per batch (runner/CLI): selection
saves time between full runs, it never replaces them.
"""
from __future__ import annotations

import ast
import os
import re
import subprocess
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from . import GateError
from .config import GateConfig, lane_matches, matches
from .inventory import ContentHashes, Inventory

PARSE_VERSION = "deps-1"
_DOTTED = re.compile(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+(?::[A-Za-z_]\w*)?\Z")
_PATHISH = re.compile(r"[\w./@+-]+\Z")
_EXT = re.compile(r"\.[A-Za-z0-9]{1,8}\Z")
_NOT_A_REF = frozenset({"__init__.py", "__main__.py", "conftest.py", "setup.py"})


# --- parsing (content only: the result depends on the bytes, never on where the file sits) ----------------

def parse_source(text: str) -> dict:
    """Edges of one Python source. {"imports": [[level, module, [names]]], "strings": [...], "error": str}."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError) as e:
        return {"imports": [], "strings": [], "error": f"{type(e).__name__}: {e}"}
    imports, strings = [], set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                imports.append([0, a.name, []])
        elif isinstance(node, ast.ImportFrom):
            imports.append([node.level or 0, node.module or "", [a.name for a in node.names]])
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            s = node.value
            if 1 < len(s) <= 240 and _PATHISH.match(s) and ("/" in s or "." in s or s.isidentifier()):
                strings.add(s)
    return {"imports": imports, "strings": sorted(strings), "error": ""}


# --- the repo's file list -----------------------------------------------------------------------------------

def list_files(root: Path, *, use_index: bool = True) -> list[str]:
    """Tracked plus untracked-not-ignored files, repo-relative, present on disk. Raises GateError if not
    a checkout.

    `use_index=True` lists with `git ls-files` (the index): fast, and right for an impact run, which is
    about what changed in the working tree. `use_index=False` (B-137) walks the filesystem and drops
    only gitignored paths, never reading the index -- so a staged deletion, a staged add or a
    `git rm --cached` cannot change which files a FULL run sees. A full run runs everything on disk; the
    index must not be able to add a false red (or hide a file) by what happens to be staged."""
    if not use_index:
        return list_files_fs(root)
    try:
        out = subprocess.run(["git", "-C", str(root), "ls-files", "-z", "--cached", "--others",
                              "--exclude-standard"], capture_output=True, timeout=120)
    except FileNotFoundError as e:
        raise GateError("git is not on PATH: the gate lists the tree with git ls-files") from e
    if out.returncode != 0:
        raise GateError(f"{root} is not a git checkout: {out.stderr.decode(errors='replace').strip()}")
    files = sorted({f for f in out.stdout.decode("utf-8", "surrogateescape").split("\0") if f})
    return [f for f in files if (root / f).is_file()]


def _ignored(root: Path, rels: list[str]) -> set[str]:
    """The subset of `rels` that git's ignore rules exclude, judged with `--no-index` so the answer does
    not depend on what is staged. Empty when git is not on PATH or has nothing to exclude."""
    if not rels:
        return set()
    proc = subprocess.run(["git", "-C", str(root), "check-ignore", "--no-index", "-z", "--stdin"],
                          input="\0".join(rels).encode("utf-8", "surrogateescape"),
                          capture_output=True, timeout=120)
    # exit 0: some paths matched; 1: none matched; 128: a real error (no .gitignore handling etc.)
    if proc.returncode not in (0, 1):
        raise GateError(f"git check-ignore failed in {root}: {proc.stderr.decode(errors='replace').strip()}")
    return {p for p in proc.stdout.decode("utf-8", "surrogateescape").split("\0") if p}


def list_files_fs(root: Path) -> list[str]:
    """Every file on disk under `root` that git's ignore rules keep, repo-relative, sorted -- without
    reading the git index (B-137). Walks the tree, prunes `.git` and any ignored directory (so huge
    ignored trees like `.venv` are never descended), then drops ignored files."""
    root = Path(root)
    if not (root / ".git").exists():
        raise GateError(f"{root} is not a git checkout (no .git): the gate lists the tree with git")
    out: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != ".git"]
        base = Path(dirpath)
        sub = [(base / d).relative_to(root).as_posix() for d in dirnames]
        drop = _ignored(root, sub)
        dirnames[:] = [d for d in dirnames if (base / d).relative_to(root).as_posix() not in drop]
        # `.git` is a directory in a plain checkout (pruned above) but a FILE in a linked worktree; drop
        # it either way so the gitdir pointer never looks like a tracked file.
        names = [f for f in filenames if not (base == root and f == ".git")]
        rels = [(base / f).relative_to(root).as_posix() for f in names]
        keep = set(rels) - _ignored(root, rels)
        out.extend(f for f in keep if (root / f).is_file())
    return sorted(out)


def changed_files(root: Path, base: str) -> list[str]:
    """Files that differ between `base` and the working tree (committed, staged, unstaged, deleted, and
    untracked-not-ignored). Raises GateError for an unknown ref."""
    def git(*a):
        r = subprocess.run(["git", "-C", str(root), *a], capture_output=True, timeout=120)
        if r.returncode != 0:
            raise GateError(f"git {' '.join(a[:2])} failed: {r.stderr.decode(errors='replace').strip()}")
        return [x for x in r.stdout.decode("utf-8", "surrogateescape").split("\0") if x]
    git("rev-parse", "--verify", "--quiet", base + "^{commit}")
    diff = git("diff", "--name-only", "-z", "--no-renames", base)
    new = git("ls-files", "-z", "--others", "--exclude-standard")
    return sorted(set(diff) | set(new))


class FileIndex:
    """Lookups over the repo's file list: by path, base name and folder."""

    def __init__(self, files: list[str], basename_max: int):
        self.files = set(files)
        self.basename_max = basename_max
        self.by_base: dict[str, list[str]] = defaultdict(list)
        self.dirs: set[str] = set()
        self.dir_by_base: dict[str, list[str]] = defaultdict(list)
        for f in files:
            self.by_base[f.rsplit("/", 1)[-1]].append(f)
            parts = f.split("/")[:-1]
            for i in range(1, len(parts) + 1):
                self.dirs.add("/".join(parts[:i]))
        for d in self.dirs:
            self.dir_by_base[d.rsplit("/", 1)[-1]].append(d)

    def files_for(self, s: str) -> list[str]:
        s = s[2:] if s.startswith("./") else s
        if s.startswith("/") or not s:
            return []
        if s in self.files:
            return [s]
        if "/" not in s:
            hits = self.by_base.get(s, [])
            return list(hits) if len(hits) <= self.basename_max else []
        base = s.rsplit("/", 1)[-1]
        return [f for f in self.by_base.get(base, []) if f.endswith("/" + s)]

    def dirs_for(self, s: str) -> list[str]:
        s = s.strip("/")
        if s.startswith("./"):
            s = s[2:]
        if "/" in s:
            if s in self.dirs:
                return [s]
            return [d for d in self.dir_by_base.get(s.rsplit("/", 1)[-1], []) if d.endswith("/" + s)
                    and d.count("/") >= 1]
        hits = [d for d in self.dir_by_base.get(s, []) if d.count("/") >= 1]
        return hits if len(hits) == 1 else []


@dataclass
class Node:
    """A file's resolved edges in this tree."""
    deps: set = field(default_factory=set)            # repo files it depends on directly (followed)
    leaves: set = field(default_factory=set)          # files it names by bare base name (content only)
    dirs: set = field(default_factory=set)            # repo folders it names
    unresolved_mods: set = field(default_factory=set)  # imported module names that resolved to no repo file
    unresolved_names: set = field(default_factory=set)  # file-like strings that resolved to no repo file
    error: str = ""


@dataclass
class Selection:
    mode: str                                   # "full" | "impact" | "lane"
    tests: list                                 # repo-relative test files, sorted
    reasons: list                               # human lines: why full, or what selected what
    why: dict = field(default_factory=dict)     # test -> sorted changed files (or ["<full>"]/["<lane>"])
    unmapped: list = field(default_factory=list)
    inert: list = field(default_factory=list)

    def to_json(self) -> dict:
        return {"mode": self.mode, "tests": self.tests, "reasons": self.reasons, "why": self.why,
                "unmapped": self.unmapped, "inert": self.inert}


class Graph:
    """The dependency graph of one checkout, built from the content-hash inventory."""

    def __init__(self, root: Path, cfg: GateConfig, state_dir: Path, files: list[str] | None = None,
                 *, use_index: bool = True):
        self.root = Path(root)
        self.cfg = cfg
        self.files = list_files(self.root, use_index=use_index) if files is None else sorted(files)
        self.index = FileIndex(self.files, cfg.basename_max)
        state_dir = Path(state_dir)
        self.hashes = ContentHashes(state_dir / "hashes.json")
        self.inventory = Inventory(state_dir / "deps.json", PARSE_VERSION)
        py = {f: self.hashes.sha(self.root / f) for f in self.files if f.endswith(".py")}
        py = {f: h for f, h in py.items() if h is not None}
        self.inventory.refresh(py, self._parse)
        self.hashes.save()
        self.inventory.save()
        self.tests = sorted(f for f in self.files if cfg.is_test(f))
        self._nodes: dict[str, Node] = {}
        self._closures: dict[str, frozenset] = {}
        self._followed: dict[str, frozenset] = {}
        self._scan_cache: dict = {}
        self._data_cache: dict = {}
        self._globals: list | None = None
        self._sha_cache: dict = {}

    def sha(self, rel: str) -> str | None:
        """Content sha256 of a repo file (None when missing), cached for this graph's lifetime."""
        got = self._sha_cache.get(rel, False)
        if got is False:
            got = self._sha_cache[rel] = self.hashes.sha(self.root / rel)
        return got

    @property
    def stats(self):
        return self.inventory.stats

    def _parse(self, rel: str) -> dict:
        try:
            text = (self.root / rel).read_text(encoding="utf-8", errors="surrogateescape")
        except OSError as e:
            return {"imports": [], "strings": [], "error": f"unreadable: {e}"}
        return parse_source(text)

    # -- resolution ------------------------------------------------------------------------------------------

    def _module_files(self, mod: str, roots: list[str]) -> list[str]:
        """The repo files importing `mod` would load under any of `roots`: the module and the `__init__.py`
        of every package on its way. Empty when no root resolves it."""
        parts = [x for x in mod.split(".") if x]
        if not parts:
            return []
        files, dirs, out = self.index.files, self.index.dirs, []
        for r in roots:
            pre = (r + "/") if r else ""
            chain, ok = [], True
            for i in range(1, len(parts)):
                stem = pre + "/".join(parts[:i])
                if stem + "/__init__.py" in files:
                    chain.append(stem + "/__init__.py")
                elif stem not in dirs:
                    ok = False
                    break
            if not ok:
                continue
            stem = pre + "/".join(parts)
            final = [x for x in (stem + ".py", stem + "/__init__.py") if x in files]
            if final:
                out += chain + final
        return out

    def node(self, rel: str) -> Node:
        n = self._nodes.get(rel)
        if n is not None:
            return n
        n = Node()
        self._nodes[rel] = n
        if not rel.endswith(".py") or rel not in self.inventory:
            return n
        p = self.inventory.get(rel)
        n.error = p.get("error", "")
        here = rel.rsplit("/", 1)[0] if "/" in rel else ""
        strings = set(p["strings"])
        is_conftest = rel.rsplit("/", 1)[-1] == "conftest.py"
        path_roots = set()
        for s in strings:
            for d in self.index.dirs_for(s):
                n.dirs.add(d)
                # an import root only when spelled as a path, or built from parts the file also names
                # (REPO / "solvers" / "binary"); a bare word that happens to name a folder is not one
                parent = d.rsplit("/", 2)[-2] if d.count("/") >= 1 else ""
                if "/" in s or parent in strings:
                    path_roots.add(d)
        roots = [here, *self.cfg.roots, *sorted(path_roots)]
        seen_roots = list(dict.fromkeys(roots))
        for level, mod, names in p["imports"]:
            if level:
                hp = here.split("/") if here else []
                if level - 1 > len(hp):
                    continue
                base = "/".join(hp[:len(hp) - (level - 1)])
                targets = ([mod] if mod else []) + [f"{mod}.{nm}" if mod else nm for nm in names if nm != "*"]
                got = [f for t in targets for f in self._module_files(t, [base])]
                n.deps.update(got)
                init = (base + "/__init__.py") if base else "__init__.py"
                if init in self.index.files:
                    n.deps.add(init)
                if not got:
                    n.unresolved_mods.add((mod or (names[0] if names else "")).rsplit(".", 1)[-1])
                continue
            if mod.split(".", 1)[0] == "__main__":
                continue
            got = self._module_files(mod, seen_roots)
            if got or self._is_namespace(mod, seen_roots):
                n.deps.update(got)
                for nm in names:
                    if nm != "*":
                        sub = self._module_files(f"{mod}.{nm}", seen_roots)
                        n.deps.update(sub)
                        if not got and not sub:
                            n.unresolved_mods.add(nm)   # `from ns import x`: x is a module or nothing
            else:
                n.unresolved_mods.add(mod.rsplit(".", 1)[-1])
        for s in p["strings"]:
            if _DOTTED.match(s):
                n.deps.update(self._module_files(s.split(":")[0], seen_roots))
            if "/" in s or _EXT.search(s):
                hits = self.index.files_for(s)
                if is_conftest:
                    # a conftest names test files to leave them out (collect_ignore), never to load them
                    hits = [h for h in hits if not self.cfg.is_test(h)]
                if "/" not in s:
                    if s in _NOT_A_REF:
                        continue
                    # a bare file name may be a script it runs or just a name it prints: its content counts,
                    # but it is not followed (only an import or a spelled-out path is)
                    if hits:
                        n.leaves.update(hits)
                    elif _EXT.search(s):
                        n.unresolved_names.add(s)
                elif hits:
                    n.deps.update(hits)
                elif _EXT.search(s) and not s.startswith("/"):
                    n.unresolved_names.add(s.rsplit("/", 1)[-1])
        n.deps.discard(rel)
        n.leaves -= n.deps | {rel}
        return n

    def _is_namespace(self, mod: str, roots: list[str]) -> bool:
        stem = mod.replace(".", "/")
        return any(((r + "/") if r else "") + stem in self.index.dirs for r in roots)

    def _conftests(self, rel: str) -> list[str]:
        parts = rel.split("/")[:-1]
        out = []
        for i in range(len(parts) + 1):
            c = "/".join(parts[:i] + ["conftest.py"])
            if c in self.index.files and c != rel:
                out.append(c)
        return out

    def closure(self, rel: str) -> frozenset:
        """Every repo file `rel` depends on, itself included: the files followed (imports, spelled-out
        paths, folder conftests) plus the files they name by bare base name (content only)."""
        got = self._closures.get(rel)
        if got is not None:
            return got
        followed, seen = set(), {rel}
        stack = [rel, *self._conftests(rel)]
        while stack:
            cur = stack.pop()
            if cur in followed:
                continue
            followed.add(cur)
            seen.add(cur)
            n = self.node(cur)
            seen.update(n.leaves)
            stack.extend(d for d in n.deps if d not in followed)
        got = frozenset(seen)
        self._closures[rel] = got
        self._followed[rel] = frozenset(followed)
        return got

    def followed(self, rel: str) -> frozenset:
        """The part of closure(rel) whose own edges were followed (leaves excluded)."""
        self.closure(rel)
        return self._followed[rel]

    def scan_inputs(self, test: str) -> list[str]:
        """Files a scan rule says this test reads (it walks the tree rather than importing)."""
        pats = tuple(p for r in self.cfg.scan if matches(test, r.tests) for p in r.inputs)
        if not pats:
            return []
        got = self._scan_cache.get(pats)
        if got is None:
            got = self._scan_cache[pats] = [f for f in self.files if matches(f, pats)]
        return got

    def _data_under(self, d: str) -> list[str]:
        got = self._data_cache.get(d)
        if got is None:
            pre = d + "/"
            got = self._data_cache[d] = [f for f in self.files if f.startswith(pre) and not f.endswith(".py")]
        return got

    def inputs(self, test: str) -> list[str]:
        """Everything that enters this test's warm key: closure, scan inputs, global inputs, data files
        under the folders its closure names."""
        if self._globals is None:
            self._globals = [f for f in self.files if self.cfg.is_global(f)]
        cl = self.closure(test)
        out = set(cl)
        out.update(self.scan_inputs(test))
        out.update(self._globals)
        for d in {d for f in self.followed(test) for d in self.node(f).dirs}:
            out.update(self._data_under(d))
        return sorted(out)

    def lanes_of(self, test: str) -> set:
        """The lanes a test file tests: those whose globs match the file itself or what it imports or names
        directly. Not the whole closure: every test loads the shared harness (conftest, ctf.event), and a
        test of the web lane is not a test of every module the web engines happen to import. A lane's
        "!glob" drops the files it matches (B-153): importing an excluded hub does not put a test in it."""
        n = self.node(test)
        direct = {test, *n.deps, *n.leaves}
        return {lane for lane, globs in self.cfg.lanes.items() if any(lane_matches(f, globs) for f in direct)}

    def lane_tests(self, lane: str) -> list[str]:
        if lane not in self.cfg.lanes:
            raise GateError(f"unknown lane {lane!r}; known: {', '.join(sorted(self.cfg.lanes)) or '(none)'}")
        return [t for t in self.tests if lane in self.lanes_of(t)]

    # -- selection -------------------------------------------------------------------------------------------

    def select(self, changed: list[str]) -> Selection:
        changed = sorted(set(changed))
        reasons, why = [], defaultdict(set)
        glob_hits = [c for c in changed if self.cfg.is_global(c)]
        if glob_hits:
            reasons.append(f"full: global input changed: {', '.join(glob_hits[:5])}"
                           + (f" (+{len(glob_hits) - 5} more)" if len(glob_hits) > 5 else ""))
            return self.full_selection(reasons)
        closures = {t: self.closure(t) for t in self.tests}
        scan_rules = [(r, [t for t in self.tests if matches(t, r.tests)]) for r in self.cfg.scan]
        unmapped, inert = [], []
        for c in changed:
            hit = False
            for t, cl in closures.items():
                if c in cl:
                    why[t].add(c)
                    hit = True
            for r, ts in scan_rules:
                if matches(c, r.inputs):
                    for t in ts:
                        why[t].add(c)
                        hit = True
            exists = c in self.index.files
            if not exists:
                hit = self._map_deleted(c, closures, why) or hit
            if not hit:
                for t in closures:
                    if any(c.startswith(d + "/") for f in self.followed(t) for d in self.node(f).dirs):
                        why[t].add(c)
                        hit = True
            if not hit:
                (inert if self.cfg.is_inert(c) else unmapped).append(c)
        if unmapped:
            reasons.append(f"full: no test maps to {', '.join(unmapped[:5])}"
                           + (f" (+{len(unmapped) - 5} more)" if len(unmapped) > 5 else "")
                           + " (not inert; add a scan rule or an inert glob in tests/gate.toml if that is wrong)")
            sel = self.full_selection(reasons)
            sel.unmapped, sel.inert = unmapped, inert
            return sel
        tests = sorted(t for t in why if t in self.index.files)
        if inert:
            reasons.append(f"inert (no test reads them): {', '.join(inert[:5])}"
                           + (f" (+{len(inert) - 5} more)" if len(inert) > 5 else ""))
        reasons.append(f"impact: {len(changed)} changed file(s) select {len(tests)} of {len(self.tests)} test files")
        return Selection("impact", tests, reasons, {t: sorted(why[t]) for t in tests}, [], inert)

    def _map_deleted(self, c: str, closures: dict, why: dict) -> bool:
        base = c.rsplit("/", 1)[-1]
        stem = base[:-3] if base.endswith(".py") else None
        if base == "__init__.py":
            stem = c.rsplit("/", 2)[-2] if c.count("/") >= 1 else None
        hit = False
        for t in closures:
            for f in self.followed(t):
                n = self.node(f)
                if (stem and stem in n.unresolved_mods) or base in n.unresolved_names:
                    why[t].add(c)
                    hit = True
                    break
        return hit

    def full_selection(self, reasons: list) -> Selection:
        return Selection("full", list(self.tests), reasons, {t: ["<full>"] for t in self.tests})
