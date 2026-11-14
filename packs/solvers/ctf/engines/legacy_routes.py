"""Read the routes a carried keyword router (the pre-R-10 ctf/triage.py shape) hard-codes, without importing it.

B-186 used it to generate the carried manifests' routes from the old ctf/triage.py; R-10 made the
manifests the routing source (ctf/triage.py now ranks from a table generated from them), so it is
kept for migrating another carried router: `generate.plan(triage_path=...)`.

The carried router has three shapes, read from `suggest()` in source order:

  CATEGORY_ENGINES[cat] = [path, ...]             category list; earlier = tried first
  if any(k in text for k in (...)) and P not in engines: engines.append(P) | engines.insert(0, P)
                                                  "append" | "insert": only when P is not listed yet
  _nudge((kw, ...), P)                            moved to the front; a later nudge wins
  if cat == "web": ... _nudge(...)                the same, only in that category

Anything else in `suggest()` that names an engine path is reported as unparsed, so a new shape in
triage.py fails the generator loudly instead of being dropped.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path



@dataclass(frozen=True)
class LegacyRoute:
    path: str                       # repo-relative engine path, e.g. "solvers/toolkits/network.py"
    category: tuple[str, ...]       # () = any category
    keywords: tuple[str, ...]       # () = category-only
    kind: str                       # "category" | "nudge" | "insert" | "append"
    order: int                      # source order (category lists: position in the list)


class LegacyParseError(RuntimeError):
    pass


def _const_strs(node) -> tuple[str, ...] | None:
    if isinstance(node, (ast.Tuple, ast.List)) and all(
            isinstance(e, ast.Constant) and isinstance(e.value, str) for e in node.elts):
        return tuple(e.value for e in node.elts)
    return None


def _cat_guard(test) -> str | None:
    """`cat == "web"` -> "web"."""
    if (isinstance(test, ast.Compare) and isinstance(test.left, ast.Name) and test.left.id == "cat"
            and len(test.ops) == 1 and isinstance(test.ops[0], ast.Eq)
            and isinstance(test.comparators[0], ast.Constant) and isinstance(test.comparators[0].value, str)):
        return test.comparators[0].value
    return None


def _any_keywords(test) -> tuple[str, ...] | None:
    """`any(k in text for k in (...)) [and P not in engines]` -> the keyword tuple."""
    if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.And):
        test = test.values[0]
    if (isinstance(test, ast.Call) and isinstance(test.func, ast.Name) and test.func.id == "any"
            and test.args and isinstance(test.args[0], ast.GeneratorExp)):
        gen = test.args[0]
        if len(gen.generators) == 1:
            return _const_strs(gen.generators[0].iter)
    return None


def _engines_call(stmt) -> tuple[str, str] | None:
    """`engines.append(P)` -> ("append", P); `engines.insert(0, P)` -> ("insert", P)."""
    if not (isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call)):
        return None
    f = stmt.value.func
    if not (isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id == "engines"):
        return None
    args = stmt.value.args
    if f.attr == "append" and len(args) == 1 and isinstance(args[0], ast.Constant):
        return "append", args[0].value
    if f.attr == "insert" and len(args) == 2 and isinstance(args[1], ast.Constant):
        return "insert", args[1].value
    return None


def _nudge_call(stmt) -> tuple[tuple[str, ...], str] | None:
    if not (isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call)):
        return None
    c = stmt.value
    if isinstance(c.func, ast.Name) and c.func.id == "_nudge" and len(c.args) == 2:
        kws = _const_strs(c.args[0])
        if kws is not None and isinstance(c.args[1], ast.Constant) and isinstance(c.args[1].value, str):
            return kws, c.args[1].value
        raise LegacyParseError(f"triage.py:{c.lineno}: _nudge with non-literal arguments")
    return None


def _mentions_engine(node) -> list[str]:
    return [n.value for n in ast.walk(node) if isinstance(n, ast.Constant) and isinstance(n.value, str)
            and n.value.endswith(".py") and n.value.startswith(("solvers/", "tools/"))]


def parse(triage_path: Path) -> list[LegacyRoute]:
    """The routes a carried keyword router hard-codes. Since R-10 ctf/triage.py is not one (it ranks
    from the manifests), so the path is always explicit: a carried router being migrated."""
    triage_path = Path(triage_path)
    tree = ast.parse(triage_path.read_text(encoding="utf-8"), filename=str(triage_path))
    routes: list[LegacyRoute] = []
    order = 0
    suggest = None
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "CATEGORY_ENGINES"
                                                for t in node.targets):
            if not isinstance(node.value, ast.Dict):
                raise LegacyParseError("CATEGORY_ENGINES is not a dict literal")
            for k, v in zip(node.value.keys, node.value.values):
                cat = k.value
                lst = _const_strs(v)
                if lst is None:
                    raise LegacyParseError(f"CATEGORY_ENGINES[{cat!r}] is not a list of literals")
                for pos, p in enumerate(lst):
                    routes.append(LegacyRoute(p, (cat,), (), "category", pos))
        if isinstance(node, ast.FunctionDef) and node.name == "suggest":
            suggest = node
    if suggest is None:
        raise LegacyParseError("triage.py has no suggest()")

    def walk(stmts, guard: str | None):
        nonlocal order
        for st in stmts:
            nd = _nudge_call(st)
            if nd:
                order += 1
                routes.append(LegacyRoute(nd[1], (guard,) if guard else (), nd[0], "nudge", order))
                continue
            if isinstance(st, ast.If):
                g = _cat_guard(st.test)
                kws = _any_keywords(st.test)
                if g is not None and not st.orelse:
                    walk(st.body, g)
                    continue
                if kws is not None and not st.orelse and len(st.body) == 1 and _engines_call(st.body[0]):
                    how, p = _engines_call(st.body[0])
                    order += 1
                    routes.append(LegacyRoute(p, (guard,) if guard else (), kws,
                                              how, order))
                    continue
            if isinstance(st, ast.FunctionDef):
                continue                     # the _nudge helper itself
            stray = _mentions_engine(st)
            if stray:
                raise LegacyParseError(f"triage.py:{st.lineno}: unparsed routing statement naming {stray[0]}")
    walk(suggest.body, None)
    return routes
