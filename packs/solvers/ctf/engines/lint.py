"""Route lint over the engine manifests.

    python -m ctf engines lint            exit 1 on any error not in the baseline

Errors:
  schema               a manifest does not parse or validate
  duplicate-id         two manifests share an id
  orphan-manifest      a sidecar with no module beside it
  unmanifested-engine  an engine module (solvers/<lane>/<name>.py) with no sidecar
  missing-entry        the entry's module/script does not exist, or the module does not define the name
  no-route             an engine that is not retired has no [[routes]]
  match-all-route      a route with no category, keyword or file condition (it would route everything)
  route-conflict       two engines claim one route (same keyword, file matcher or bare category, in
                       overlapping categories) and a priority is missing or the priorities are equal
  duplicate-basename   two engine modules share a basename, so a flat `import <name>` picks one silently,
                       and the pair is not documented in docs/coverage/duplicate-basenames.toml (or the
                       entry there no longer matches the files or the file a flat import resolves to)
  ambiguous-import     a flat `import <name>` of a duplicated basename from a folder other than the one
                       the engine sys.path resolves it to (load the exact file: solvers/common/_shadowed.py)
  stale-duplicate-doc  docs/coverage/duplicate-basenames.toml documents a basename that is no longer shared
Warnings:
  unknown-category     a route category triage does not know
  id-lane              the id's lane part is not the lane
  cli-tool-undeclared  a non-python cli entry whose argv0 is not in needs_tools

Baseline: docs/coverage/lint-baseline.txt lists `<code> <subject>` lines for the no-route and
duplicate-basename errors that existed when B-186 landed (R-10 documented every duplicate basename and
routed the engines whose input formats are obvious), and the ambiguous-import errors that existed
when R-10 added that check (warmups modules whose fix changes which readers run; see
docs/build-log/R-10.md). A listed error is reported as `known`, not
failed. The file only shrinks: `lint --shrink-baseline` drops lines that no longer fire, and the repo
test fails on a listed line that no longer fires, so routing an engine also removes its line.
"""
from __future__ import annotations

import ast
import re
import tomllib
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from .. import paths
from . import layout, manifest as _manifest

BASELINE_REL = "docs/coverage/lint-baseline.txt"
BASELINABLE = ("no-route", "duplicate-basename", "ambiguous-import")
DUPLICATES_REL = "docs/coverage/duplicate-basenames.toml"
BASELINE_HEADER = (
    "# Lint errors that existed when their check landed (no-route, duplicate-basename: B-186;\n"
    "# ambiguous-import: R-10). This file only shrinks: route an engine, document or remove a duplicate\n"
    "# basename, load a shared name by file, then `python -m ctf engines lint --shrink-baseline`.\n"
    "# Never add a line: a new engine gets a route in its manifest.\n")
_DUP_KEYS = {"basename", "files", "flat_import", "reason"}


@dataclass(frozen=True)
class Finding:
    code: str
    severity: str            # error | warning | known
    subject: str             # engine id, basename or path
    message: str

    def line(self) -> str:
        return f"{self.severity:7} {self.code:20} {self.subject}: {self.message}"


def claims_overlap(cat_a, kw_a, files_a, cat_b, kw_b, files_b) -> set[tuple]:
    """The claim keys two routes share in overlapping categories (empty set = no overlap)."""
    if cat_a and cat_b and not set(cat_a) & set(cat_b):
        return set()
    return _claims(kw_a, files_a) & _claims(kw_b, files_b)


def _claims(keywords, files) -> set[tuple]:
    if keywords and files:
        return {("keyword+file", k, f) for k in keywords for f in files}
    if keywords:
        return {("keyword", k) for k in keywords}
    if files:
        return {("file", f) for f in files}
    return {("category",)}


def baseline_path(root: Path | None = None) -> Path:
    return (paths.repo_root() if root is None else Path(root)) / BASELINE_REL


def load_baseline(root: Path | None = None) -> set[tuple[str, str]]:
    p = baseline_path(root)
    if not p.exists():
        return set()
    out = set()
    for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        code, _, subject = line.partition(" ")
        if code not in BASELINABLE or not subject:
            raise ValueError(f"{p}:{n}: expected '<{'|'.join(BASELINABLE)}> <subject>', got {line!r}")
        out.add((code, subject.strip()))
    return out


def _defined_names(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"), filename=str(path))
    names = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            names.update(t.id for t in node.targets if isinstance(t, ast.Name))
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            names.update((a.asname or a.name).split(".")[0] for a in node.names)
    return names


def _known_categories() -> set[str]:
    from .. import triage
    return set(triage.CATEGORIES) | set(triage.ALIASES.values())


@dataclass(frozen=True)
class DuplicateDoc:
    basename: str
    files: tuple[str, ...]          # repo-relative, sorted
    flat_import: str                # the file a flat import resolves to on the engine sys.path
    reason: str


def load_duplicate_docs(root: Path | None = None) -> dict[str, DuplicateDoc]:
    """docs/coverage/duplicate-basenames.toml: one [[duplicate]] table per basename that is shared on
    purpose. Raises ValueError naming the file and the entry when it is malformed."""
    p = (paths.repo_root() if root is None else Path(root)) / DUPLICATES_REL
    if not p.exists():
        return {}
    try:
        data = tomllib.loads(p.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as e:
        raise ValueError(f"{p}: not valid TOML: {e}") from None
    extra = sorted(set(data) - {"duplicate"})
    if extra:
        raise ValueError(f"{p}: unknown key {extra[0]!r} (only [[duplicate]] tables)")
    out: dict[str, DuplicateDoc] = {}
    for i, d in enumerate(data.get("duplicate", [])):
        where = f"{p}: duplicate[{i}]"
        if not isinstance(d, dict) or set(d) != _DUP_KEYS:
            raise ValueError(f"{where}: needs exactly the keys {', '.join(sorted(_DUP_KEYS))}")
        files = d["files"]
        if (not isinstance(files, list) or len(files) < 2
                or not all(isinstance(f, str) and f for f in files)):
            raise ValueError(f"{where}: files must list at least two repo-relative paths")
        for k in ("basename", "flat_import", "reason"):
            if not isinstance(d[k], str) or not d[k].strip():
                raise ValueError(f"{where}: {k} must be a non-empty string")
        if d["basename"] in out:
            raise ValueError(f"{where}: {d['basename']!r} is documented twice")
        out[d["basename"]] = DuplicateDoc(d["basename"], tuple(sorted(files)), d["flat_import"], d["reason"])
    return out


def _flat_imports(path: Path, names: set[str]) -> list[tuple[str, int]]:
    """[(name, line)] for each absolute `import <name>` / `from <name> import ...` of one of `names`."""
    src = path.read_text(encoding="utf-8", errors="replace")
    if not any(re.search(rf"\b(?:import|from)\s+{re.escape(n)}\b", src) for n in names):
        return []
    try:
        tree = ast.parse(src, filename=str(path))
    except SyntaxError:
        return []
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            out += [(a.name, node.lineno) for a in node.names if a.name in names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module in names:
            out.append((node.module, node.lineno))
    return out


def _import_scan_files(root: Path) -> list[Path]:
    """Every .py directly in tools/ or a solvers/<lane>/ folder (engines, helpers and lane tests)."""
    dirs = [root / "tools"] + [root / "solvers" / lane for lane in layout.lanes(root)]
    return [f for d in dirs if d.is_dir() for f in sorted(d.glob("*.py"))]


def lint(root: Path | None = None, *, baseline: set[tuple[str, str]] | None = None,
         known_categories: set[str] | None = None) -> list[Finding]:
    root = paths.repo_root() if root is None else Path(root)
    baseline = load_baseline(root) if baseline is None else baseline
    known_categories = _known_categories() if known_categories is None else known_categories
    ms, problems = _manifest.scan(root)
    out: list[Finding] = []

    def add(code, subject, msg, severity="error"):
        if severity == "error" and (code, subject) in baseline:
            severity = "known"
        out.append(Finding(code, severity, subject, msg))

    for p in problems:
        add("schema", str(p.path.relative_to(root)), p.message)
    by_id = defaultdict(list)
    for m in ms:
        by_id[m.id].append(m)
    for mid, group in by_id.items():
        if len(group) > 1:
            add("duplicate-id", mid, "used by " + ", ".join(m.rel_module(root) for m in group))

    for m in ms:
        if not m.module_path.is_file():
            add("orphan-manifest", m.id, f"{m.path.relative_to(root)} has no {m.module_path.name} beside it")
        target = m.entry.target_file(root)
        if m.entry.kind == "function":
            if not target.is_file():
                add("missing-entry", m.id, f"entry {m.entry_raw}: {target.relative_to(root)} does not exist")
            else:
                try:
                    defined = _defined_names(target)
                except SyntaxError as e:
                    add("missing-entry", m.id, f"entry {m.entry_raw}: module does not parse ({e.msg})")
                else:
                    if m.entry.function not in defined:
                        add("missing-entry", m.id, f"entry {m.entry_raw}: {m.entry.function} is not defined "
                                                   f"in {target.relative_to(root)}")
        elif m.entry.is_python_cli:
            if not target.is_file():
                add("missing-entry", m.id, f"entry {m.entry_raw}: script {m.entry.argv[1]} does not exist")
        elif m.entry.argv[0] not in m.needs_tools:
            add("cli-tool-undeclared", m.id, f"entry runs {m.entry.argv[0]!r}; list it in needs_tools",
                "warning")
        if m.id.split(".")[0] != m.lane.replace("-", "_"):
            add("id-lane", m.id, f"id lane part differs from lane {m.lane!r}", "warning")
        if m.status != "retired" and not m.routes:
            add("no-route", m.id, "no [[routes]]: triage never suggests it (add a route, or set status = \"retired\")")
        for i, r in enumerate(m.routes):
            if r.matches_everything:
                add("match-all-route", m.id, f"routes[{i}] has no category, keyword or file condition")
            for c in r.category:
                if c not in known_categories:
                    add("unknown-category", m.id, f"routes[{i}] category {c!r} is not a triage category",
                        "warning")

    # route conflicts: group every route's claim keys, compare across engines
    claims = defaultdict(list)        # key -> [(manifest, route index, route)]
    for m in ms:
        if m.status == "retired":
            continue
        for i, r in enumerate(m.routes):
            if r.matches_everything:
                continue
            for key in _claims(r.keywords, r.files):
                claims[key].append((m, i, r))
    reported = set()
    for key, holders in sorted(claims.items(), key=lambda kv: str(kv[0])):
        for a in range(len(holders)):
            for b in range(a + 1, len(holders)):
                (ma, ia, ra), (mb, ib, rb) = holders[a], holders[b]
                if ma.id == mb.id:
                    continue
                if ra.category and rb.category and not set(ra.category) & set(rb.category):
                    continue
                if ra.priority is not None and rb.priority is not None and ra.priority != rb.priority:
                    continue
                pair = (min(ma.id, mb.id), max(ma.id, mb.id), str(key))
                if pair in reported:
                    continue
                reported.add(pair)
                why = ("priority missing" if ra.priority is None or rb.priority is None
                       else f"both priority {ra.priority}")
                what = key[0] if len(key) == 1 else f"{key[0]} {key[1:]!r}"
                add("route-conflict", f"{pair[0]}~{pair[1]}",
                    f"{ma.id} routes[{ia}] and {mb.id} routes[{ib}] both claim {what} ({why}); "
                    "set distinct priorities")

    # every engine module has a sidecar
    for mod in layout.engine_modules(root):
        if not _manifest.sidecar_for(mod).exists():
            add("unmanifested-engine", mod.relative_to(root).as_posix(),
                "engine module without a .manifest.toml (python -m ctf engines generate)")

    # flat-import shadowing
    by_base = defaultdict(list)
    for mod in layout.engine_modules(root):
        by_base[mod.stem].append(mod)
    for m in ms:
        if m.module_path.parent == root / "tools":
            by_base[m.basename].append(m.module_path)
    try:
        docs = load_duplicate_docs(root)
    except ValueError as e:
        add("schema", DUPLICATES_REL, str(e))
        docs = {}
    owners: dict[str, Path] = {}
    for base, mods in sorted(by_base.items()):
        mods = sorted(set(mods))
        if len(mods) < 2:
            continue
        owner = layout.flat_owner(base, root)
        owners[base] = owner
        rels = tuple(p.relative_to(root).as_posix() for p in mods)
        owner_rel = owner.relative_to(root).as_posix() if owner else "?"
        doc = docs.get(base)
        if doc is None:
            add("duplicate-basename", base,
                f"{', '.join(rels)}; flat `import {base}` gets {owner_rel} "
                f"(rename one, or document the pair in {DUPLICATES_REL})")
        elif doc.files != rels or doc.flat_import != owner_rel:
            add("duplicate-basename", base,
                f"{DUPLICATES_REL} is out of date: it says files {', '.join(doc.files)} and flat import "
                f"{doc.flat_import}; the tree has {', '.join(rels)} and flat import {owner_rel}")
    for base in sorted(set(docs) - set(owners)):
        add("stale-duplicate-doc", base, f"documented in {DUPLICATES_REL} but no longer shared by two engine "
                                         "modules: remove the entry")
    if owners:
        for f in _import_scan_files(root):
            for name, line in _flat_imports(f, set(owners)):
                owner = owners[name]
                if owner is not None and f.parent != owner.parent:
                    rel = f.relative_to(root).as_posix()
                    add("ambiguous-import", f"{rel}:{name}",
                        f"line {line}: flat `import {name}` resolves to {owner.relative_to(root).as_posix()} on "
                        f"the engine sys.path, not a file of this folder's choosing; load the exact file "
                        f"(solvers/common/_shadowed.py: common_module / module_at)")

    out.sort(key=lambda f: ({"error": 0, "warning": 1, "known": 2}[f.severity], f.code, f.subject))
    return out


def stale_baseline(findings: list[Finding], baseline: set[tuple[str, str]]) -> set[tuple[str, str]]:
    """Baseline lines that no longer fire."""
    firing = {(f.code, f.subject) for f in findings if f.severity == "known"}
    return baseline - firing


def write_baseline(lines: set[tuple[str, str]], root: Path | None = None) -> Path:
    p = baseline_path(root)
    p.parent.mkdir(parents=True, exist_ok=True)
    body = "".join(f"{c} {s}\n" for c, s in sorted(lines))
    p.write_text(
        BASELINE_HEADER + body, encoding="utf-8")
    return p
