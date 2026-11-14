#!/usr/bin/env python3
"""Find tests that do not test.

    python tools/test_audit.py [PATH ...] [--json] [--markdown] [--rule RULE ...]

PATH defaults to tests/. Static (AST) only: nothing is imported or run. Exit 0 when nothing is
found, 1 when something is, 2 on a usage error or a file that does not parse.

Rules, one finding per test function (a function named test_* at module level or in a Test* class;
pytest fixtures are not tests):

  empty-body        the body is `pass`, `...` or only a docstring
  only-main         no assertion, and the body calls main(): a script wrapped as a test, its result unread
  records-only      no assertion; the test calls a helper (check(), ...) that prints FAIL or records the
                    failure somewhere pytest never looks, and never raises: pytest reports it passed.
                    (A helper that feeds a module-level FAILED / FAILS / FAILURES list or FAIL counter
                    is an assertion: the plugin's failure-sink guard fails the test when one grows.)
  no-assert         no assertion at all (a smoke test: it passes whenever nothing raises; a fuzz test
                    whose try/except names only specific declared errors is a contract, not flagged). An assertion
                    is an `assert`, a `raise`, pytest.raises / warns / fail, self.assert* / self.fail,
                    any call to a function whose name starts with `assert` (assert_called_once_with,
                    np.testing.assert_equal, ...), a subprocess call with check=True, or a call to a
                    helper of this module (or of a sibling module it imports) that itself asserts.
  assert-constant   every assertion in the test is a constant that is always true (assert True, assert 1,
                    assert "x")
  assert-tuple      an `assert (cond, "message")`: a non-empty tuple, always true (flagged even beside
                    real assertions: it is always a bug)
  mock-of-unit      the test replaces the thing its name says it tests with a Mock (patch, patch.object,
                    mocker.patch, monkeypatch.setattr with a Mock) and then asserts on that mock
  return-as-skip    a top-level `if ...: return` before the test's first assertion: the test passes
                    when the condition holds, where pytest.skip or a needs_tool marker would say it did
                    not run
  swallowed-assert  assertions inside a try whose handler catches AssertionError / Exception /
                    BaseException / everything and neither re-raises nor asserts

File-level findings:

  not-collected     a file named in a conftest.py collect_ignore list: pytest never runs it
  import-time-run   module-level code (outside `if __name__ == "__main__":`) calls the file's own test
                    functions or sys.exit: the checks run at collection, a failure aborts collection
                    (under xdist, the whole session) instead of failing one test

Directories whose conftest.py defines pytest_pycollect_makemodule (tests/real: its scripts run as
subprocess items judged on their FAIL lines) are collected another way; their functions are not
pytest tests and are skipped, with one note per directory.
"""
from __future__ import annotations

import argparse
import ast
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

RULES = ("empty-body", "only-main", "records-only", "no-assert", "assert-constant", "assert-tuple", "mock-of-unit",
         "return-as-skip", "swallowed-assert", "not-collected", "import-time-run")

PYTEST_ASSERTING = {"raises", "warns", "fail", "deprecated_call"}
MOCK_FACTORIES = {"Mock", "MagicMock", "AsyncMock", "NonCallableMock", "NonCallableMagicMock",
                  "create_autospec", "PropertyMock"}
BROAD = {"AssertionError", "Exception", "BaseException"}
# The module-level failure sinks ctf/testing/pytest_plugin.py guards (FAILURE_SINKS): a helper that
# appends to one of these lists, or increments one of these counters, fails the test under pytest.
GUARDED_SINKS = {"FAILED", "FAILS", "FAILURES", "FAIL", "RESULTS"}   # RESULTS: a list of booleans


def _feeds_guarded_sink(fn) -> bool:
    for n in ast.walk(fn):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in ("append", "extend") \
                and isinstance(n.func.value, ast.Name) and n.func.value.id in GUARDED_SINKS:
            return True
        if isinstance(n, ast.AugAssign) and isinstance(n.target, ast.Name) and n.target.id in GUARDED_SINKS:
            return True
    return False


@dataclass
class Finding:
    path: str
    line: int
    test: str
    rule: str
    detail: str

    def text(self) -> str:
        return f"{self.path}:{self.line}: {self.test}: {self.rule}: {self.detail}"


# ---------------------------------------------------------------------------------------------- helpers

def _name(node) -> str | None:
    """The last name of a call target: f, mod.f, a.b.f -> 'f'."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _root(node) -> str | None:
    """The first name of a dotted expression: a.b.c() -> 'a'."""
    while isinstance(node, (ast.Attribute, ast.Call, ast.Subscript)):
        node = node.func if isinstance(node, ast.Call) else node.value
    return node.id if isinstance(node, ast.Name) else None


def _dotted(node) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _body(fn) -> list:
    body = list(fn.body)
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
            and isinstance(body[0].value.value, str):
        body = body[1:]
    return body


def _is_fixture(fn) -> bool:
    for d in fn.decorator_list:
        target = d.func if isinstance(d, ast.Call) else d
        if _name(target) == "fixture":
            return True
    return False


def _walk_own(node):
    """ast.walk that does not descend into nested function or class definitions."""
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        for child in ast.iter_child_nodes(n):
            if child is not node and isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef,
                                                        ast.Lambda)):
                continue
            stack.append(child)


def _always_true(expr) -> bool:
    if isinstance(expr, ast.Constant):
        return bool(expr.value)
    if isinstance(expr, (ast.Tuple, ast.List, ast.Set)):
        return len(expr.elts) > 0 and not any(isinstance(e, ast.Starred) for e in expr.elts)
    if isinstance(expr, ast.Dict):
        return len(expr.keys) > 0
    return False


class Module:
    """One parsed file: its functions, imports and the per-function 'does it assert' answers."""

    def __init__(self, path: Path, tree: ast.Module, index: "Index"):
        self.path, self.tree, self.index = path, tree, index
        self.functions: dict[str, ast.AST] = {}
        self.imported: dict[str, tuple[str, str]] = {}   # local name -> (module, attr or "")
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.functions[node.name] = node
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                for a in node.names:
                    self.imported[a.asname or a.name] = (node.module, a.name)
            elif isinstance(node, ast.Import):
                for a in node.names:
                    self.imported[a.asname or a.name.split(".")[0]] = (a.name, "")
        self._asserts: dict[str, bool] = {}

    def helper(self, call: ast.Call):
        """(module, function node) a call resolves to inside the scanned tree, or None."""
        f = call.func
        if isinstance(f, ast.Name):
            if f.id in self.functions:
                return self, self.functions[f.id]
            if f.id in self.imported:
                mod, attr = self.imported[f.id]
                other = self.index.module(mod, near=self.path)
                if other and attr in other.functions:
                    return other, other.functions[attr]
        elif isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id in self.imported:
            mod, attr = self.imported[f.value.id]
            other = self.index.module(mod if not attr else f"{mod}.{attr}", near=self.path) \
                or (self.index.module(attr, near=self.path) if attr else None)
            if other and f.attr in other.functions:
                return other, other.functions[f.attr]
        return None

    def function_asserts(self, fn, depth: int = 0, seen=None) -> bool:
        key = f"{id(fn)}"
        if key in self._asserts:
            return self._asserts[key]
        seen = seen if seen is not None else set()
        if key in seen or depth > 4:
            return False
        seen.add(key)
        result = _feeds_guarded_sink(fn) or any(self.is_assertion(n, depth, seen) for n in _walk_own(fn))
        self._asserts[key] = result
        return result

    def is_assertion(self, node, depth: int = 0, seen=None) -> bool:
        if isinstance(node, (ast.Assert, ast.Raise)):
            return True
        if isinstance(node, ast.Call):
            name = _name(node.func)
            if name is None:
                return False
            if name.startswith("assert") or name.startswith("_assert") or name in ("fail", "failIf", "failUnless"):
                return True
            if _dotted(node.func) in {f"pytest.{n}" for n in PYTEST_ASSERTING} or \
                    (isinstance(node.func, ast.Name) and node.func.id in PYTEST_ASSERTING and
                     self.imported.get(node.func.id, ("", ""))[0] == "pytest"):
                return True
            if any(k.arg == "check" and isinstance(k.value, ast.Constant) and k.value.value is True
                   for k in node.keywords):
                return True
            target = self.helper(node)
            if target is not None:
                mod, fn = target
                return mod.function_asserts(fn, depth + 1, seen)
        return False


class Index:
    """Every module under the scanned roots, by dotted name relative to each root and by file stem."""

    def __init__(self):
        self.by_path: dict[Path, Module] = {}
        self.by_stem: dict[str, list[Module]] = {}

    def add(self, mod: Module):
        self.by_path[mod.path] = mod
        self.by_stem.setdefault(mod.path.stem, []).append(mod)

    def module(self, dotted: str, near: Path):
        stem = dotted.split(".")[-1]
        cands = self.by_stem.get(stem, [])
        if not cands:
            return None
        same_dir = [m for m in cands if m.path.parent == near.parent]
        return (same_dir or cands)[0]


# ---------------------------------------------------------------------------------------------- the rules

def _mock_names(fn, mod: Module) -> dict[str, str]:
    """{local name: what it replaced ('' when unknown)} for the mocks a test makes."""
    out: dict[str, str] = {}
    patch_decorators = []
    for d in fn.decorator_list:
        if isinstance(d, ast.Call) and _name(d.func) in ("patch", "object") and "patch" in _dotted(d.func):
            patch_decorators.append(_patched_target(d))
    if patch_decorators:   # @patch decorators pass their mocks bottom-up as the trailing positional args
        args = [a.arg for a in fn.args.args if a.arg not in ("self", "cls")]
        for name, target in zip(reversed(args), patch_decorators[::-1][::-1]):
            out[name] = target
    for node in _walk_own(fn):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            made = _mock_call(node.value)
            if made is not None:
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        out[t.id] = made
        if isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if isinstance(item.context_expr, ast.Call) and isinstance(item.optional_vars, ast.Name):
                    made = _mock_call(item.context_expr)
                    if made is not None:
                        out[item.optional_vars.id] = made
        if isinstance(node, ast.Call) and _dotted(node.func).endswith("setattr") and len(node.args) >= 3:
            value = node.args[2]
            target = node.args[1].value if isinstance(node.args[1], ast.Constant) else ""
            if isinstance(value, ast.Name) and value.id in out:
                out[value.id] = out[value.id] or str(target)
            elif isinstance(value, ast.Call) and _name(value.func) in MOCK_FACTORIES:
                out.setdefault(f"<setattr {target}>", str(target))
    return out


def _declared_error_contract(nodes) -> bool:
    """A fuzz-style contract: calls inside a try whose handlers name only specific exception types
    (`except mod.DecodeError: pass`). Any other exception fails the test, so it does test something:
    that only the declared error escapes. Not flagged."""
    for n in nodes:
        if isinstance(n, ast.Try) and n.handlers and all(h.type is not None for h in n.handlers):
            names = set()
            for h in n.handlers:
                elts = h.type.elts if isinstance(h.type, ast.Tuple) else [h.type]
                names |= {_name(e) for e in elts}
            if names and not (names & BROAD):
                return True
    return False


def _records(mod: "Module", fn) -> bool:
    """A helper that reports a failure without raising: it prints a FAIL line, or appends to a list that
    is not its own (a module-level FAILED-style list pytest never looks at)."""
    local = {a.arg for a in fn.args.args + fn.args.kwonlyargs}
    for n in ast.walk(fn):
        if isinstance(n, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.For, ast.comprehension, ast.With)):
            targets = n.targets if isinstance(n, ast.Assign) else [getattr(n, "target", None)]
            if isinstance(n, ast.With):
                targets = [i.optional_vars for i in n.items]
            for tgt in targets:
                for x in ast.walk(tgt) if tgt is not None else ():
                    if isinstance(x, ast.Name):
                        local.add(x.id)
    for n in ast.walk(fn):
        if not isinstance(n, ast.Call):
            continue
        if _name(n.func) == "print" and any(isinstance(c, ast.Constant) and isinstance(c.value, str) and "FAIL" in c.value
                                             for a in n.args for c in ast.walk(a)):
            return True
        if isinstance(n.func, ast.Attribute) and n.func.attr == "append" and isinstance(n.func.value, ast.Name) \
                and n.func.value.id not in local:
            return True
    return False


def _patched_target(call: ast.Call) -> str:
    """'submit' for patch('ctf.submit.submit') / patch.object(mod, 'submit') / mocker.patch(...)."""
    name = _name(call.func)
    if name == "object" and len(call.args) >= 2 and isinstance(call.args[1], ast.Constant):
        return str(call.args[1].value)
    if call.args and isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str):
        return call.args[0].value.split(".")[-1]
    return ""


def _mock_call(call: ast.Call) -> str | None:
    """What a call that makes a mock replaces ('' when nothing named), or None for any other call."""
    name = _name(call.func)
    dotted = _dotted(call.func)
    if name in MOCK_FACTORIES:
        return ""
    if "patch" in dotted.split(".") or name == "patch" or dotted.endswith("patch.object"):
        return _patched_target(call)
    if name == "start" and isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Call):
        return _mock_call(call.func.value)
    return None


def _assertion_roots(node) -> set[str]:
    if isinstance(node, ast.Assert):
        return {n.id for n in ast.walk(node.test) if isinstance(n, ast.Name)}
    if isinstance(node, ast.Call):
        r = _root(node.func)
        return {r} if r else set()
    return set()


def _token_match(target: str, test: str) -> bool:
    if not target or len(target) < 3:
        return False
    return f"_{target.lower()}_" in f"_{test.lower()}_"


def audit_function(fn, mod: Module, label: str) -> list[Finding]:
    rel = str(mod.path)
    out = []
    body = _body(fn)

    def add(rule, detail, line=None):
        out.append(Finding(rel, line or fn.lineno, label, rule, detail))

    if not body or all(isinstance(s, ast.Pass) or (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant))
                       for s in body):
        add("empty-body", "the body is pass, ... or only a docstring")
        return out

    nodes = list(_walk_own(fn))
    assertions = [n for n in nodes if mod.is_assertion(n)]
    asserts = [n for n in nodes if isinstance(n, ast.Assert)]
    for a in asserts:
        if isinstance(a.test, ast.Tuple) and a.test.elts:
            add("assert-tuple", "assert on a non-empty tuple is always true (did you mean assert x, 'msg'?)", a.lineno)

    if not assertions:
        helpers = [mod.helper(n) for n in nodes if isinstance(n, ast.Call)]
        if _declared_error_contract(nodes) or any(
                h and _declared_error_contract(list(_walk_own(h[1]))) for h in helpers):
            return out
    if not assertions:
        calls = [n for n in nodes if isinstance(n, ast.Call)]
        if any(_name(c.func) == "main" for c in calls):
            add("only-main", "calls main() and never looks at what it returned or printed")
        else:
            recorders = sorted({_name(c.func) for c in calls if mod.helper(c) is not None
                                and _records(*mod.helper(c))})
            if recorders:
                add("records-only", f"calls {', '.join(f'{c}()' for c in recorders[:3])}, which print or record a "
                    f"failure and never raise")
            else:
                add("no-assert", "no assert, raise, pytest.raises or asserting helper: passes whenever nothing raises")
        return out

    if asserts and len(asserts) == len(assertions) and all(_always_true(a.test) for a in asserts):
        add("assert-constant", "every assertion is a constant that is always true")

    mocks = _mock_names(fn, mod)
    if mocks:
        for a in assertions:
            roots = _assertion_roots(a)
            for name in roots & set(mocks):
                if _token_match(mocks[name], fn.name):
                    add("mock-of-unit", f"replaces {mocks[name]!r} (named by the test) with a mock and asserts "
                        f"on that mock", getattr(a, "lineno", fn.lineno))
                    break
            else:
                continue
            break

    first_assert = min(getattr(a, "lineno", fn.lineno) for a in assertions)
    for s in body:
        if s.lineno >= first_assert:
            break
        if isinstance(s, ast.If) and not s.orelse and len(s.body) == 1 and isinstance(s.body[0], ast.Return) \
                and s.body[0].value is None:
            add("return-as-skip", "returns early (reported as passed) where pytest.skip or a marker would "
                "report it as not run", s.lineno)
            break

    for node in nodes:
        if isinstance(node, ast.Try) and any(mod.is_assertion(n) for st in node.body for n in _walk_own(st)):
            for h in node.handlers:
                caught = set()
                if h.type is None:
                    caught = {"BaseException"}
                elif isinstance(h.type, ast.Tuple):
                    caught = {_name(e) for e in h.type.elts}
                else:
                    caught = {_name(h.type)}
                checks = any(mod.is_assertion(n) for st in h.body for n in _walk_own(st))
                if caught & BROAD and not checks:
                    add("swallowed-assert", f"assertions inside try/except {', '.join(sorted(c for c in caught if c))} "
                        f"whose handler neither re-raises nor asserts", h.lineno)
                    break
    return out


def _import_time_run(tree: ast.Module) -> tuple[int, str] | None:
    """(line, what) of the first module-level statement that runs the file's tests or exits."""
    tests = {n.name for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
             and n.name.startswith("test")}
    for stmt in tree.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Import, ast.ImportFrom)):
            continue
        if isinstance(stmt, ast.If) and "__name__" in ast.unparse(stmt.test):
            continue
        refs = {n.id for n in ast.walk(stmt) if isinstance(n, ast.Name)}
        if isinstance(stmt, ast.For) and refs & tests:
            return stmt.lineno, f"loops over and calls {', '.join(sorted(refs & tests)[:2])} at import"
        for n in ast.walk(stmt):
            if isinstance(n, ast.Call):
                name = _name(n.func)
                if name in tests:
                    return stmt.lineno, f"calls {name}() at import"
                if _dotted(n.func) in ("sys.exit", "exit", "os._exit"):
                    return stmt.lineno, "calls sys.exit at import"
    return None


def tests_of(tree: ast.Module):
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test") \
                and not _is_fixture(node):
            yield node.name, node
        elif isinstance(node, ast.ClassDef) and node.name.startswith("Test"):
            for sub in node.body:
                if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)) and sub.name.startswith("test") \
                        and not _is_fixture(sub):
                    yield f"{node.name}.{sub.name}", sub


# ---------------------------------------------------------------------------------------------- driver

def _conftest_facts(path: Path):
    """(collect_ignore names, takes over module collection) of one conftest.py."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except SyntaxError:
        return set(), False
    ignored, custom = set(), False
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "pytest_pycollect_makemodule":
            custom = True
        if isinstance(node, (ast.Assign, ast.AugAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(t, ast.Name) and t.id in ("collect_ignore", "collect_ignore_glob") for t in targets) \
                    and isinstance(node.value, (ast.List, ast.Tuple)):
                ignored |= {e.value for e in node.value.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)}
    return ignored, custom


def audit(paths: list[Path], rules: set[str] | None = None, display_base: Path | None = None):
    """(findings, notes, parse_errors) for every test file under the given paths."""
    files: list[Path] = []
    for p in paths:
        if p.is_file():
            files.append(p)
        elif p.is_dir():
            files += sorted(x for x in p.rglob("*.py") if "__pycache__" not in x.parts)
        else:
            raise FileNotFoundError(f"test_audit: no such path: {p}")
    files = sorted(set(files))
    index = Index()
    errors, mods = [], {}
    for f in files:
        try:
            tree = ast.parse(f.read_text(encoding="utf-8", errors="replace"), filename=str(f))
        except SyntaxError as e:
            errors.append(f"{f}: does not parse: {e.msg} (line {e.lineno})")
            continue
        mods[f] = Module(f, tree, index)
        index.add(mods[f])

    def show(p: Path) -> str:
        if display_base:
            try:
                return str(p.resolve().relative_to(display_base.resolve()))
            except ValueError:
                pass
        return str(p)

    conftests = {f.parent: _conftest_facts(f) for f in files if f.name == "conftest.py"}
    findings, notes, custom_dirs = [], [], set()
    for f, mod in mods.items():
        if not f.name.startswith("test") or f.name == "conftest.py":
            continue
        ignored, custom = conftests.get(f.parent, (set(), False))
        if custom:
            custom_dirs.add(f.parent)
            continue
        if f.name in ignored:
            findings.append(Finding(show(f), 1, "<file>", "not-collected",
                                    f"named in {show(f.parent / 'conftest.py')} collect_ignore: pytest never runs it"))
            continue
        hit = _import_time_run(mod.tree)
        if hit:
            findings.append(Finding(show(f), hit[0], "<module>", "import-time-run", hit[1]))
        for label, fn in tests_of(mod.tree):
            for x in audit_function(fn, mod, label):
                x.path = show(f)
                findings.append(x)
    for d in sorted(custom_dirs):
        notes.append(f"{show(d)}/: its conftest.py collects the test files itself (pytest_pycollect_makemodule); "
                     f"their functions are not pytest tests and were not audited")
    if rules:
        findings = [x for x in findings if x.rule in rules]
    findings.sort(key=lambda x: (x.path, x.line, x.rule))
    return findings, notes, errors


def markdown(findings) -> str:
    lines = ["| file | line | test | rule | detail |", "|---|---|---|---|---|"]
    for x in findings:
        lines.append(f"| `{x.path}` | {x.line} | `{x.test}` | {x.rule} | {x.detail.replace('|', '/')} |")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("paths", nargs="*", type=Path, help="test files or folders (default: tests/)")
    ap.add_argument("--json", action="store_true", help="print the findings as JSON")
    ap.add_argument("--markdown", action="store_true", help="print the findings as a Markdown table")
    ap.add_argument("--rule", action="append", choices=RULES, help="only this rule (repeatable)")
    args = ap.parse_args(argv)
    repo = Path(__file__).resolve().parent.parent
    paths = args.paths or [repo / "tests"]
    missing = [p for p in paths if not p.exists()]
    if missing:
        print(f"test_audit: no such path: {', '.join(map(str, missing))}", file=sys.stderr)
        return 2
    findings, notes, errors = audit(paths, set(args.rule or ()), display_base=Path.cwd())
    if args.json:
        print(json.dumps({"findings": [asdict(x) for x in findings], "notes": notes, "errors": errors}, indent=1))
    elif args.markdown:
        print(markdown(findings))
    else:
        for x in findings:
            print(x.text())
        for n in notes:
            print(f"note: {n}")
        counts = {}
        for x in findings:
            counts[x.rule] = counts.get(x.rule, 0) + 1
        print(f"test_audit: {len(findings)} finding(s)" + (": " + ", ".join(f"{r} {counts[r]}" for r in RULES if r in counts)
                                                        if counts else ""))
    for e in errors:
        print(f"test_audit: {e}", file=sys.stderr)
    if errors:
        return 2
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
