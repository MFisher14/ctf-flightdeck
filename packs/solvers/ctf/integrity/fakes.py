"""Fake-branch audit (B-196): every branch that reads the testing flag needs a test that takes it OFF.

At Huntress a test double hid the failing path and the gate passed: the suite ran every test with the
flag on (the root conftest sets CTF_TESTING=1), so the real branch never ran under test. This audit finds
each such branch statically and asks for evidence that some test reaches it with the flag off.

**A fake branch** is an `if` (or `x if c else y`) in a non-test source file whose condition reads a fake
flag (FLAGS: CTF_TESTING, PYTEST_CURRENT_TEST, CTF_OFFLINE_AUDIT; `audit(flags=...)` takes another list).
A flag may be written as its literal or as a module-level string constant holding it (`FLAG = "CTF_TESTING"`),
named bare, imported (`from ctf.x import FLAG`) or as `mod.FLAG`: constants are collected from every source
and test file that names a flag literally, matched by name, and files that name such a constant are
audited like files that name the literal. Each read is one of:
  * a call naming the flag (`env.get_bool("CTF_TESTING", environ=e)`, `os.environ.get(...)`, `x.get(...)`),
    a subscript `os.environ["CTF_TESTING"]`, or `"CTF_TESTING" in os.environ`;
  * a local name assigned from such a read earlier in the function;
  * a call to a module function that returns such a read (a predicate such as `_under_test(e)`).
A read is *process* (it sees the process environment: `os.environ`, `os.getenv`, `env.get(...)` with no
`environ=`, or an expression that also names `os.environ`) or *injected* (it reads an environ handed in:
an `environ=`/`env=` keyword, or `.get` on a local mapping).

**Evidence** for a branch is a test function in a collected test file that
  1. imports the branch's module (`import labels`, `from ctf import doctor`, `from ctf.doctor import f`),
  2. names, through that import, the function that holds the branch or a function of the same module
     that calls it (transitively, inside the module): `doctor.check_token(...)` or `check_token(...)`, and
  3. turns OFF every flag the branch reads, in its own body, in a fixture it requests, or in an autouse
     fixture of its file or a tests/ conftest: `monkeypatch.delenv(FLAG)`, `monkeypatch.setenv(FLAG, "0")`,
     `os.environ.pop(FLAG)`, `del os.environ[FLAG]`, `patch.dict(os.environ, clear=True)`, a keyword
     `FLAG=None`/falsy to a helper; or, for an *injected* read only, an `environ=`/`env=` mapping written
     as a dict literal (or `dict(...)`) without the flag or with it falsy.

**Waivers**: tests/fake_branches.toml, one table per `<file>::<function>`:
    ["ctf/doctor.py::_under_test"]
    reason = "why no non-fake test can exist"      # a waiver, listed loudly
    tests  = ["tests/test_x.py::test_y"]           # or evidence the static audit cannot see (each must exist)
An entry that names no fake branch, or a test that does not exist, is a finding: the list cannot rot.

    audit(root) -> FakeAudit           .branches, .findings (MISSING / STALE-WAIVER / BAD-WAIVER), .ok
"""
from __future__ import annotations

import ast
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from . import IntegrityError
from .testfiles import collected_test_files, parse, source_files

FLAGS = ("CTF_TESTING", "PYTEST_CURRENT_TEST", "CTF_OFFLINE_AUDIT")
SOURCE_DIRS = ("ctf", "solvers", "tools")
# The test harness itself sets and reads the flag on purpose.
EXCLUDE_PREFIXES = ("ctf/testing/",)
WAIVERS = "tests/fake_branches.toml"
FALSY = {"", "0", "false", "no", "off"}
_ENV_KWARGS = ("environ", "env")


@dataclass
class Branch:
    path: str                       # repo-relative source file
    line: int
    function: str                   # qualified name of the function holding it ("<module>" at top level)
    flags: tuple                    # the flags its condition reads
    process: bool                   # a read sees the process environment
    evidence: list = field(default_factory=list)   # test node ids that take it with the flag off
    waived: str = ""                # waiver reason

    @property
    def key(self) -> str:
        return f"{self.path}::{self.function}"

    @property
    def status(self) -> str:
        return "COVERED" if self.evidence else "WAIVED" if self.waived else "MISSING"

    def text(self) -> str:
        how = "process env" if self.process else "injected env"
        s = f"{self.status:<8} {self.path}:{self.line} {self.function} reads {', '.join(self.flags)} ({how})"
        if self.evidence:
            s += f"  <- {self.evidence[0]}" + (f" (+{len(self.evidence) - 1})" if len(self.evidence) > 1 else "")
        elif self.waived:
            s += f"  waived: {self.waived}"
        return s


@dataclass
class FakeAudit:
    branches: list
    findings: list                  # human lines; empty = ok

    @property
    def ok(self) -> bool:
        return not self.findings


# ----------------------------------------------------------------------------------------- source side

@dataclass(frozen=True)
class Flags:
    """The fake flags an audit looks for, and the string constants that hold them (name -> flag)."""
    names: tuple = FLAGS
    consts: dict = field(default_factory=dict)

    def of(self, node) -> str | None:
        """The flag `node` spells: the literal, or a constant holding it (`FLAG`, `mod.FLAG`)."""
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value in self.names:
            return node.value
        if isinstance(node, ast.Name):
            return self.consts.get(node.id)
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            return self.consts.get(node.attr)
        return None


_DEFAULT = Flags()


def module_constants(tree: ast.Module, names=FLAGS) -> dict:
    """{NAME: flag} for each module-level `NAME = "<flag>"` (or annotated) assignment of `tree`."""
    out = {}
    for n in tree.body:
        targets = n.targets if isinstance(n, ast.Assign) else [n.target] if isinstance(n, ast.AnnAssign) else []
        v = getattr(n, "value", None)
        if isinstance(v, ast.Constant) and isinstance(v.value, str) and v.value in names:
            for t in targets:
                if isinstance(t, ast.Name):
                    out[t.id] = v.value
    return out


def _dotted(node) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _names_os_environ(expr) -> bool:
    for n in ast.walk(expr):
        if isinstance(n, ast.Attribute) and _dotted(n) in ("os.environ", "os.getenv"):
            return True
    return False


class _Reads:
    """Fake reads of one module: direct reads, tainted locals, predicate functions."""

    def __init__(self, tree: ast.Module, flags: Flags = _DEFAULT):
        self.flags = flags
        self.modules = set()                     # names bound to imported modules (receiver = process)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.modules.add(a.asname or a.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                for a in node.names:
                    self.modules.add(a.asname or a.name)
        self.predicates: dict[str, tuple[set, bool]] = {}
        funcs = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
        for _ in range(3):                       # predicates calling predicates
            for fn in funcs:
                taint = self.tainted(fn)
                flags, proc = set(), False
                for n in ast.walk(fn):
                    if isinstance(n, ast.Return) and n.value is not None:
                        f, p = self.reads(n.value, taint)
                        flags |= f
                        proc = proc or p
                if flags:
                    self.predicates[fn.name] = (flags, proc)

    def _direct(self, node) -> tuple[str | None, bool]:
        """(flag, process) when `node` itself reads a flag."""
        if isinstance(node, ast.Call):
            flag = next((f for f in map(self.flags.of, node.args) if f), None)
            if flag is None:
                return None, False
            if any(k.arg in _ENV_KWARGS for k in node.keywords):
                return flag, False
            f = node.func
            if isinstance(f, ast.Attribute) and f.attr == "get":
                if isinstance(f.value, ast.Name) and f.value.id not in self.modules:
                    return flag, False           # .get on a local mapping: an injected environ
            return flag, True
        if isinstance(node, ast.Subscript):
            flag = self.flags.of(node.slice)
            if flag:
                return flag, _dotted(node.value) == "os.environ" or not isinstance(node.value, ast.Name) \
                    or node.value.id in self.modules
        if isinstance(node, ast.Compare) and len(node.ops) == 1 and isinstance(node.ops[0], (ast.In, ast.NotIn)):
            flag = self.flags.of(node.left)
            if flag:
                return flag, _names_os_environ(node.comparators[0])
        return None, False

    def reads(self, expr, taint: dict) -> tuple[set, bool]:
        """(flags, process) read anywhere in `expr`."""
        flags, proc = set(), False
        for n in ast.walk(expr):
            flag, p = self._direct(n)
            if flag:
                flags.add(flag)
                proc = proc or p
            elif isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load) and n.id in taint:
                flags |= taint[n.id][0]
                proc = proc or taint[n.id][1]
            elif isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in self.predicates:
                f, p = self.predicates[n.func.id]
                flags |= f
                proc = proc or p
        if flags and _names_os_environ(expr):
            proc = True
        return flags, proc

    def tainted(self, fn) -> dict:
        taint: dict[str, tuple[set, bool]] = {}
        for _ in range(2):
            for n in ast.walk(fn):
                if isinstance(n, (ast.Assign, ast.AnnAssign)) and n.value is not None:
                    flags, proc = self.reads(n.value, taint)
                    if not flags:
                        continue
                    targets = n.targets if isinstance(n, ast.Assign) else [n.target]
                    for t in targets:
                        if isinstance(t, ast.Name):
                            taint[t.id] = (flags, proc)
        return taint


def _functions(tree: ast.Module):
    """(qualname, node) of every function, methods as Class.method, nested as outer.inner."""
    out = []

    def walk(body, prefix):
        for n in body:
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                q = f"{prefix}{n.name}"
                out.append((q, n))
                walk(n.body, q + ".")
            elif isinstance(n, ast.ClassDef):
                walk(n.body, f"{prefix}{n.name}.")
    walk(tree.body, "")
    return out


def find_branches(root: Path, rel: str, flags: Flags = _DEFAULT) -> list[Branch]:
    tree = parse(Path(root) / rel)
    if tree is None:
        return []
    r = _Reads(tree, flags)
    out = []
    owned = set()
    for qual, fn in sorted(_functions(tree), key=lambda x: -x[0].count(".")):
        taint = r.tainted(fn)
        for n in ast.walk(fn):
            if isinstance(n, (ast.If, ast.IfExp, ast.While)) and id(n) not in owned:
                flags, proc = r.reads(n.test, taint)
                if flags:
                    owned.add(id(n))
                    out.append(Branch(rel, n.lineno, qual, tuple(sorted(flags)), proc))
    for n in ast.walk(tree):
        if isinstance(n, (ast.If, ast.IfExp)) and id(n) not in owned:
            if isinstance(n, ast.If) and "__name__" in ast.unparse(n.test):
                continue
            flags, proc = r.reads(n.test, {})
            if flags:
                out.append(Branch(rel, n.lineno, "<module>", tuple(sorted(flags)), proc))
    return sorted(out, key=lambda b: b.line)


def _module_callers(tree: ast.Module) -> dict[str, set]:
    """simple function name -> the simple names of the module's functions that call it (transitively)."""
    calls: dict[str, set] = {}
    for qual, fn in _functions(tree):
        name = qual.rsplit(".", 1)[-1]
        for n in ast.walk(fn):
            if isinstance(n, ast.Call):
                callee = n.func.id if isinstance(n.func, ast.Name) else \
                    n.func.attr if isinstance(n.func, ast.Attribute) else None
                if callee and callee != name:
                    calls.setdefault(callee, set()).add(name)
    out: dict[str, set] = {}
    for start in calls:
        seen, stack = set(), [start]
        while stack:
            for c in calls.get(stack.pop(), ()):
                if c not in seen:
                    seen.add(c)
                    stack.append(c)
        out[start] = seen
    return out


# ------------------------------------------------------------------------------------------- test side

def _is_falsy(node) -> bool:
    if isinstance(node, ast.Constant):
        v = node.value
        if v is None or v is False or v == 0:
            return True
        return isinstance(v, str) and v.strip().lower() in FALSY
    return False


def _dict_without(node, flag: str, assigns: dict, flags: Flags = _DEFAULT) -> bool:
    """True when `node` is a mapping literal that does not turn `flag` on: a dict literal with no `**`
    spread and no truthy `flag` key, or `dict(...)` with no positional base and no truthy `flag=`."""
    if isinstance(node, ast.Name) and node.id in assigns:
        node = assigns[node.id]
    if isinstance(node, ast.Dict):
        for k, v in zip(node.keys, node.values):
            if k is None:                         # a ** spread: may carry the flag
                return False
            if flags.of(k) == flag and not _is_falsy(v):
                return False
        return True
    if isinstance(node, ast.Call) and _dotted(node.func) == "dict":
        if node.args:
            return False
        return all(_is_falsy(k.value) for k in node.keywords if k.arg == flag) and \
            not any(k.arg is None for k in node.keywords)
    return False


def turns_off(fn, flag: str, injected_ok: bool, flags: Flags = _DEFAULT) -> bool:
    """Does the body of `fn` turn `flag` off (see the module docstring)?"""
    assigns = {}
    for n in ast.walk(fn):
        if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
            assigns[n.targets[0].id] = n.value
    for n in ast.walk(fn):
        if isinstance(n, ast.Call):
            name = n.func.attr if isinstance(n.func, ast.Attribute) else n.func.id if isinstance(n.func, ast.Name) else ""
            first = flags.of(n.args[0]) if n.args else None
            if name == "delenv" and first == flag:
                return True
            if name == "setenv" and first == flag and len(n.args) > 1 and _is_falsy(n.args[1]):
                return True
            if name == "pop" and first == flag and _dotted(n.func.value if isinstance(n.func, ast.Attribute)
                                                           else n.func) == "os.environ":
                return True
            if name == "dict" and isinstance(n.func, ast.Attribute) and n.args and \
                    _dotted(n.args[0]) == "os.environ":                     # patch.dict(os.environ, ...)
                clear = any(k.arg == "clear" and isinstance(k.value, ast.Constant) and k.value.value is True
                            for k in n.keywords)
                given = n.args[1] if len(n.args) > 1 else None
                if clear and (given is None or _dict_without(given, flag, assigns, flags)):
                    return True
                if isinstance(given, ast.Dict) and any(flags.of(k) == flag and _is_falsy(v)
                                                       for k, v in zip(given.keys, given.values)):
                    return True
            for k in n.keywords:
                if k.arg == flag and _is_falsy(k.value):
                    return True
                if injected_ok and k.arg in _ENV_KWARGS and _dict_without(k.value, flag, assigns, flags):
                    return True
        if isinstance(n, ast.Delete):
            for t in n.targets:
                if isinstance(t, ast.Subscript) and _dotted(t.value) == "os.environ" and flags.of(t.slice) == flag:
                    return True
        if isinstance(n, ast.Assign):
            for t in n.targets:
                if isinstance(t, ast.Subscript) and _dotted(t.value) == "os.environ" and \
                        flags.of(t.slice) == flag and _is_falsy(n.value):
                    return True
    return False


@dataclass
class _TestFile:
    rel: str
    tree: ast.Module
    modalias: dict                   # local name -> the dotted module it is bound to by an import
    from_names: dict                 # local name -> (module, attribute) for `from module import name`
    fixtures: dict                   # fixture name -> node (this file + tests/ conftests)
    autouse: list                    # autouse fixture nodes that apply to it
    tests: list                      # (node id, node)


def _fixture_info(fn) -> tuple[bool, bool]:
    """(is a fixture, autouse)."""
    for d in fn.decorator_list:
        target = d.func if isinstance(d, ast.Call) else d
        name = target.attr if isinstance(target, ast.Attribute) else target.id if isinstance(target, ast.Name) else ""
        if name == "fixture":
            auto = isinstance(d, ast.Call) and any(k.arg == "autouse" and isinstance(k.value, ast.Constant)
                                                   and k.value.value is True for k in d.keywords)
            return True, auto
    return False, False


def _mentions(path: Path, words) -> bool:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return any(w in text for w in words)


def _load_tests(root: Path, stems=None) -> list[_TestFile]:
    """The collected test files (only those whose text names one of `stems`, when given)."""
    root = Path(root)
    conf_fixtures: dict[Path, tuple[dict, list]] = {}

    def fixtures_of(tree):
        fx, auto = {}, []
        for n in ast.walk(tree):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                is_fx, is_auto = _fixture_info(n)
                if is_fx:
                    fx[n.name] = n
                    if is_auto:
                        auto.append(n)
        return fx, auto

    out = []
    for rel in collected_test_files(root):
        if stems is not None and not _mentions(root / rel, stems):
            continue
        tree = parse(root / rel)
        if tree is None:
            continue
        fx, auto = {}, []
        p = (root / rel).parent
        chain = []
        while True:
            c = p / "conftest.py"
            if c.is_file():
                chain.append(c)
            if p == root:
                break
            p = p.parent
        for c in reversed(chain):
            if c not in conf_fixtures:
                ct = parse(c)
                conf_fixtures[c] = fixtures_of(ct) if ct is not None else ({}, [])
            cf, ca = conf_fixtures[c]
            fx.update(cf)
            auto += ca
        own_fx, own_auto = fixtures_of(tree)
        fx.update(own_fx)
        auto += own_auto
        modalias, from_names = {}, {}
        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                for a in n.names:
                    if a.asname:
                        modalias[a.asname] = a.name
                    else:
                        modalias[a.name.split(".")[0]] = a.name.split(".")[0]
                        modalias.setdefault(a.name, a.name)
            elif isinstance(n, ast.ImportFrom) and n.module and not n.level:
                for a in n.names:
                    local = a.asname or a.name
                    modalias[local] = f"{n.module}.{a.name}"       # `from pkg import mod`
                    from_names[local] = (n.module, a.name)         # `from mod import func`
        tests = []
        for n in tree.body:
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name.startswith("test"):
                tests.append((f"{rel}::{n.name}", n))
            elif isinstance(n, ast.ClassDef) and n.name.startswith("Test"):
                for s in n.body:
                    if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef)) and s.name.startswith("test"):
                        tests.append((f"{rel}::{n.name}::{s.name}", s))
        out.append(_TestFile(rel, tree, modalias, from_names, fx, auto, tests))
    return out


def _module_names(rel: str) -> set:
    """Spellings a test may use to import or name the source file `rel`."""
    stem = rel[:-3] if rel.endswith(".py") else rel
    parts = stem.split("/")
    if parts[-1] == "__init__":
        parts = parts[:-1]
    names = {parts[-1], rel, rel.rsplit("/", 1)[-1]}
    for i in range(len(parts)):
        names.add(".".join(parts[i:]))
    return names


def _refs_to(fn, aliases: set, direct: dict) -> set:
    """The attribute names `fn` reaches through a module alias (`doctor.check_token`) plus the bare names
    it uses that were imported from the module (`check_token`)."""
    out = set()
    for n in ast.walk(fn):
        if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id in aliases:
            out.add(n.attr)
        elif isinstance(n, ast.Name) and n.id in direct:
            out.add(direct[n.id])
    return out


def _attrs(fn) -> set:
    return {n.attr for n in ast.walk(fn) if isinstance(n, ast.Attribute)}


def _test_exists(root: Path, node_id: str) -> bool:
    """A node id `<file>::<test>` or `<file>::<Class>::<test>` names a test of a collected test file."""
    parts = node_id.split("::")
    if len(parts) < 2 or parts[0] not in collected_test_files(root):
        return False
    tree = parse(Path(root) / parts[0])
    body = tree.body if tree is not None else []
    for i, name in enumerate(parts[1:]):
        last = i == len(parts) - 2
        kinds = (ast.FunctionDef, ast.AsyncFunctionDef) if last else (ast.ClassDef,)
        hit = next((n for n in body if isinstance(n, kinds) and n.name == name.split("[")[0]), None)
        if hit is None:
            return False
        body = getattr(hit, "body", [])
    return True


def _fixture_closure(fn, fixtures: dict) -> list:
    """The test plus every fixture it requests, transitively."""
    seen, out, stack = set(), [fn], [fn]
    while stack:
        cur = stack.pop()
        for a in cur.args.args + cur.args.kwonlyargs:
            f = fixtures.get(a.arg)
            if f is not None and id(f) not in seen:
                seen.add(id(f))
                out.append(f)
                stack.append(f)
    return out


# ------------------------------------------------------------------------------------------------ audit

def load_waivers(root: Path) -> dict:
    path = Path(root) / WAIVERS
    if not path.is_file():
        return {}
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as e:
        raise IntegrityError(f"{WAIVERS}: not valid TOML: {e}") from e
    out = {}
    for key, entry in raw.items():
        if not isinstance(entry, dict) or "::" not in key:
            raise IntegrityError(f"{WAIVERS}: [{key!r}] must be a table keyed <file>::<function>")
        extra = set(entry) - {"reason", "tests"}
        if extra:
            raise IntegrityError(f"{WAIVERS}: [{key!r}] unknown key(s) {sorted(extra)}")
        reason, tests = entry.get("reason", ""), entry.get("tests", [])
        if not isinstance(reason, str) or not isinstance(tests, list) or not all(isinstance(t, str) for t in tests):
            raise IntegrityError(f"{WAIVERS}: [{key!r}] reason must be a string and tests a list of node ids")
        if not reason.strip() and not tests:
            raise IntegrityError(f"{WAIVERS}: [{key!r}] needs a non-empty reason or tests")
        out[key] = (reason.strip(), tests)
    return out


def flag_constants(root: Path, files, names=FLAGS) -> dict:
    """{NAME: flag} from the module-level constants of `files` (repo-relative) that name a flag literally."""
    out: dict = {}
    for rel in files:
        if _mentions(Path(root) / rel, names):
            tree = parse(Path(root) / rel)
            if tree is not None:
                out.update(module_constants(tree, names))
    return out


def audit(root: Path, *, source_dirs=SOURCE_DIRS, only: list | None = None, flags=FLAGS) -> FakeAudit:
    """Find every fake branch under `source_dirs` (or in `only`, repo-relative files) and its evidence.
    `flags` is the list of fake flag names (default FLAGS)."""
    root = Path(root)
    names = tuple(flags)
    if not names or not all(isinstance(f, str) and f for f in names):
        raise IntegrityError(f"fake-branch audit: flags must be a non-empty list of names, got {flags!r}")
    files = [f for f in (only if only is not None else source_files(root, source_dirs))
             if not f.startswith(EXCLUDE_PREFIXES)]
    every_source = source_files(root, source_dirs) if only is not None else files
    consts = flag_constants(root, sorted(set(every_source) | set(files)) + collected_test_files(root), names)
    fl = Flags(names, consts)
    words = names + tuple(consts)
    branches = []
    for rel in files:
        if _mentions(root / rel, words):        # a file that names no flag (or flag constant) has no fake branch
            branches += find_branches(root, rel, fl)
    stems = {n for b in branches for n in _module_names(b.path) if "/" not in n and "." not in n}
    tests = _load_tests(root, stems) if branches else []
    for rel in sorted({b.path for b in branches}):
        tree = parse(root / rel)
        callers = _module_callers(tree)
        names = _module_names(rel)
        for b in (x for x in branches if x.path == rel):
            simple = b.function.rsplit(".", 1)[-1]
            parts = b.function.split(".")
            cls = parts[-2] if len(parts) > 1 and parts[-2][:1].isupper() else ""   # Box.method: Box()...method
            reach = {simple} | callers.get(simple, set())
            if b.function == "<module>":
                reach = set()
            for tf in tests:
                aliases = {loc for loc, dotted in tf.modalias.items() if dotted in names}
                direct = {loc: attr for loc, (mod, attr) in tf.from_names.items() if mod in names}
                if not aliases and not direct:
                    continue
                for nid, node in tf.tests:
                    refs = _refs_to(node, aliases, direct)
                    if not (refs & reach or (cls and cls in refs and simple in _attrs(node))):
                        continue
                    scope = _fixture_closure(node, tf.fixtures) + list(tf.autouse)
                    if all(any(turns_off(f, flag, not b.process, fl) for f in scope) for flag in b.flags):
                        b.evidence.append(nid)
    findings = []
    waivers = load_waivers(root) if only is None else {}
    keys = {b.key for b in branches}
    for key, (reason, wtests) in sorted(waivers.items()):
        if key not in keys:
            findings.append(f"STALE-WAIVER {WAIVERS} [{key}]: no fake branch in that function any more; "
                            f"remove the entry")
            continue
        bad = [t for t in wtests if not _test_exists(root, t)]
        if bad:
            findings.append(f"BAD-WAIVER {WAIVERS} [{key}]: test(s) not found in a collected file: {', '.join(bad)}")
        for b in branches:
            if b.key == key and not b.evidence:
                if wtests and not bad:
                    b.evidence = list(wtests)
                else:
                    b.waived = reason or "listed"
    for b in branches:
        if b.status == "MISSING":
            findings.append(f"MISSING {b.path}:{b.line} {b.function}: no test reaches this branch with "
                            f"{', '.join(b.flags)} off ({'process' if b.process else 'injected'} env); add one, "
                            f"or a waiver in {WAIVERS}")
    return FakeAudit(branches, findings)
