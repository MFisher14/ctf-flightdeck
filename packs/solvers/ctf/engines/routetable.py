"""The triage route table, ctf/engines/route_table.jsonl, generated from the engine manifests (R-10).

    python -m ctf engines generate            writes it (with docs/CAPABILITIES.md and the matrix)
    python -m ctf engines generate --check    exit 1 when a generated file is stale

ctf/triage.py ranks a challenge's engines from this table: every engine with a matching route, best
route priority first (router.rank, the same matching as `ctf engines route`). The table is never
edited by hand; tests/test_engines_routetable.py fails when it differs from a fresh render of the
manifests, and triage refuses a missing or malformed table instead of routing with nothing.

Format: JSON Lines, so branches that add engines touch different lines and merge cleanly. Line 1 is
a header `{"schema": 1, "generated_by": ...}`; every other line is one route of one engine that is
not retired: `{"id", "path", "class", "priority", "category", "keywords", "files"}`, sorted by id and
then by the route's position in its manifest. `priority` is the effective one (an omitted priority
is the default 50). `class` is the engine's class tag (executes | analysis | plan | library).
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from .. import paths
from . import manifest as _manifest
from . import router as _router
from .generate import CLASS_TAGS

TABLE_REL = "ctf/engines/route_table.jsonl"
SCHEMA = 1
GENERATED_BY = "python -m ctf engines generate"
_ROW_KEYS = ("id", "path", "class", "priority", "category", "keywords", "files")


class RouteTableError(RuntimeError):
    """The route table is missing or malformed. The message names the file and the fix."""


@dataclass(frozen=True)
class Row:
    id: str
    path: str                      # repo-relative engine module, what triage lists
    cls: str                       # executes | analysis | plan | library | ?
    priority: int
    category: tuple[str, ...]
    keywords: tuple[str, ...]
    files: tuple[str, ...]

    @property
    def route(self) -> _manifest.Route:
        return _manifest.Route(category=self.category, keywords=self.keywords, files=self.files,
                               priority=self.priority)

    def to_json(self) -> str:
        return json.dumps({"id": self.id, "path": self.path, "class": self.cls, "priority": self.priority,
                           "category": list(self.category), "keywords": list(self.keywords),
                           "files": list(self.files)}, ensure_ascii=False)


@dataclass(frozen=True)
class Hit:
    id: str
    path: str
    cls: str
    priority: int
    reason: str


def engine_class(m: _manifest.Manifest) -> str:
    return next((c for c in m.capabilities if c in CLASS_TAGS), "?")


def rows_from(manifests: list[_manifest.Manifest], root: Path) -> list[Row]:
    out = []
    for m in sorted(manifests, key=lambda m: m.id):
        if m.status == "retired":
            continue
        for r in m.routes:
            out.append(Row(m.id, m.rel_module(root), engine_class(m), r.effective_priority,
                           r.category, r.keywords, r.files))
    return out


def table_path(root: Path | None = None) -> Path:
    return (paths.repo_root() if root is None else Path(root)) / TABLE_REL


def render(root: Path | None = None, manifests: list[_manifest.Manifest] | None = None) -> str:
    root = paths.repo_root() if root is None else Path(root)
    ms = _manifest.discover(root) if manifests is None else manifests
    head = json.dumps({"schema": SCHEMA, "generated_by": GENERATED_BY,
                       "note": "generated from the engine manifests; do not edit"})
    return head + "\n" + "".join(r.to_json() + "\n" for r in rows_from(ms, root))


def write(root: Path | None = None) -> Path:
    p = table_path(root)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(render(root), encoding="utf-8")
    return p


def is_stale(root: Path | None = None) -> bool:
    p = table_path(root)
    return not p.exists() or p.read_text(encoding="utf-8") != render(root)


def _str_tuple(v, where: str) -> tuple[str, ...]:
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        raise RouteTableError(f"{where}: expected a list of strings")
    return tuple(v)


def parse(text: str, where: str = TABLE_REL) -> list[Row]:
    lines = text.splitlines()
    if not lines:
        raise RouteTableError(f"{where}: empty; regenerate it with `{GENERATED_BY}`")
    try:
        head = json.loads(lines[0])
    except json.JSONDecodeError as e:
        raise RouteTableError(f"{where}:1: not JSON ({e})") from None
    if not isinstance(head, dict) or head.get("schema") != SCHEMA:
        raise RouteTableError(f"{where}:1: header must carry schema {SCHEMA}; regenerate with `{GENERATED_BY}`")
    rows = []
    for n, line in enumerate(lines[1:], 2):
        at = f"{where}:{n}"
        try:
            d = json.loads(line)
        except json.JSONDecodeError as e:
            raise RouteTableError(f"{at}: not JSON ({e})") from None
        if not isinstance(d, dict) or sorted(d) != sorted(_ROW_KEYS):
            raise RouteTableError(f"{at}: a row has exactly the keys {', '.join(_ROW_KEYS)}")
        prio = d["priority"]
        if isinstance(prio, bool) or not isinstance(prio, int) or not 0 <= prio <= 100:
            raise RouteTableError(f"{at}: priority must be an integer 0-100")
        for k in ("id", "path", "class"):
            if not isinstance(d[k], str) or not d[k]:
                raise RouteTableError(f"{at}: {k} must be a non-empty string")
        row = Row(d["id"], d["path"], d["class"], prio, _str_tuple(d["category"], at),
                  _str_tuple(d["keywords"], at), _str_tuple(d["files"], at))
        if row.route.matches_everything:
            raise RouteTableError(f"{at}: {row.id} has a route with no category, keyword or file condition")
        rows.append(row)
    return rows


_CACHE: dict[str, tuple[tuple, list[Row]]] = {}


def load(root: Path | None = None) -> list[Row]:
    """The committed table. Raises RouteTableError (naming the file and the command) when it is
    missing or malformed. Cached on the file's mtime and size."""
    p = table_path(root)
    try:
        st = os.stat(p)
    except FileNotFoundError:
        raise RouteTableError(f"{p}: the triage route table is missing; generate it with "
                              f"`{GENERATED_BY}`") from None
    sig = (st.st_mtime_ns, st.st_size)
    hit = _CACHE.get(str(p))
    if hit and hit[0] == sig:
        return list(hit[1])
    rows = parse(p.read_text(encoding="utf-8"), str(p))
    _CACHE[str(p)] = (sig, rows)
    return list(rows)


def match(category: str, description: str = "", files_dir: Path | None = None, *,
          root: Path | None = None, rows: list[Row] | None = None) -> list[Hit]:
    """Engines whose routes match, best priority first (ties by id), from the table."""
    rows = load(root) if rows is None else rows
    by_id: dict[str, list[Row]] = {}
    for r in rows:
        by_id.setdefault(r.id, []).append(r)
    ranked = _router.rank(((i, [r.route for r in rs]) for i, rs in by_id.items()),
                          category, description, files_dir)
    return [Hit(i, by_id[i][0].path, by_id[i][0].cls, p, why) for i, p, why in ranked]
