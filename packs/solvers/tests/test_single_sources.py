"""The single-source rule (docs/CONTRACTS.md sections 2-4), enforced over the whole tree.

Three scans, each over every Python and shell file git knows about (tracked or new, not ignored):

  * env      no HUNTRESS_* / CSCTF_* environment variable is read, set or cleared anywhere except
             ctf/env.py (which maps the legacy spellings) and its own contract test;
  * workdir  no module resolves the per-event workdir itself: nothing reads $CTF_WORKDIR (or a
             legacy spelling of it) except ctf/paths.py, nothing builds `<repo>/challenges` or
             `<repo>/workspace` from its own location, and no shell script defaults $CTF_WORKDIR;
  * flags    no flag or proof regex literal exists outside ctf/flagfmt.py (and its contract test).

Each detector is first checked against synthetic offenders and look-alikes, so a scan that finds
nothing is known to be able to find something.
"""
from __future__ import annotations

import ast
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from ctf import paths

REPO = paths.repo_root()

# Old prefixes, spelled so this file's own constants never match the scans it runs.
OLD_PREFIXES = ("HUNT" + "RESS_", "CS" + "CTF_")
_OLD_NAME = re.compile(r"^(?:%s)[A-Z0-9_]*$" % "|".join(OLD_PREFIXES))
WORKDIR_NAMES = {"CTF_WORKDIR", "HUNT" + "RESS_WORKDIR", "CS" + "CTF_WORKDIR", "HUNT" + "RESS_CHALLENGES"}

# ctf/env.py maps the legacy spellings; the two contract tests prove that mapping still works.
ENV_EXEMPT = {"ctf/env.py", "tests/test_contracts_env_paths.py", "tests/test_contracts_event.py"}
WORKDIR_EXEMPT = {"ctf/paths.py", "ctf/env.py"}
FLAG_EXEMPT = {"ctf/flagfmt.py", "tests/test_contracts_flagfmt.py"}

# A string constant that holds a flag regex but is data, not a pattern the code uses. Keep this short;
# every entry says why.
FLAG_DATA_LITERALS = {
    # A synthetic challenge description that STATES its answer format as /.../; the test checks that
    # the engine reads the stated format out of challenge text (stated formats are challenge data).
    ("tests/test_adapt_propose-widen.py", "Submit the token matching /HTB"),
    ("tests/test_adapt_propose-widen.py", "a token matching /HTB"),
    # Tests a module that is not in this tree (docs/writeups/organizer/assemble.py, unit B-098); the
    # file fails collection until it lands. Its per-event "flag_regex" override contradicts
    # docs/CONTRACTS.md section 4 and is recorded in docs/build-log/B-001a.md for B-098 to drop.
    ("tests/test_writeup_organizer_assemble.py", "flag\\" + "{[^}]*\\}"),
    # The assembler itself, tracked since R-12 byte-identical to the hand-merged copy. The literal splits
    # an event.json flag_format "PREFIX{...}" into its prefix (it parses the event's stated format, it
    # does not match flags in data); porting the assembler onto ctf.flagfmt is B-098's.
    ("docs/writeups/organizer/assemble.py", "([A-Za-z0-9_\\-]+)\\" + "{"),
    # A synthetic event profile's proof pattern, written to event.toml by the scaffold's TOML writer
    # round-trip test (an event profile is where proof formats live, docs/CONTRACTS.md section 4).
    ("tests/test_event_scaffold.py", "proof_" + "[0-9a-f]{4}"),
    # A synthetic question's own stated answer pattern (the pattern= field of a question, challenge data);
    # the test checks the reader returns nothing plain whether a question states a pattern or not.
    ("tests/test_tk_day27_dlog.py", "flag\\" + "{[a-z_]+\\}"),
}


# ------------------------------------------------------------------------------------- the file set

def tree_files() -> list[str]:
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("git is not on PATH: the single-source scan lists files with git ls-files")
    out = subprocess.run([git, "-C", str(REPO), "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
                         capture_output=True, check=True).stdout.decode("utf-8", "surrogateescape")
    return sorted({p for p in out.split("\0") if p and (REPO / p).is_file()})


def python_files(files):
    return [f for f in files if f.endswith(".py")]


def shell_files(files):
    out = []
    for f in files:
        if f.endswith((".sh", ".bash", ".zsh")):
            out.append(f)
        elif "." not in Path(f).name and not f.startswith("tests/fixtures/"):
            try:
                head = (REPO / f).read_bytes()[:64]
            except OSError:
                continue
            if head.startswith(b"#!") and re.match(rb"#![^\n]*\b(?:ba|z|da)?sh\b", head):
                out.append(f)
    return out


def _parse(rel: str, src: str | None = None):
    text = src if src is not None else (REPO / rel).read_text(encoding="utf-8", errors="surrogateescape")
    try:
        return ast.parse(text)
    except SyntaxError:
        return None


# --------------------------------------------------------------------------------- AST helpers

def _dotted(node) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return _dotted(node.value) + "." + node.attr
    if isinstance(node, ast.Call):
        return _dotted(node.func) + "()"
    if isinstance(node, ast.Subscript):
        return _dotted(node.value) + "[]"
    return "?"


def _is_environ(node) -> bool:
    """os.environ, environ, self.environ, ... (a mapping of the process environment)."""
    return _dotted(node).split(".")[-1] == "environ"


def _bindings(tree) -> dict[str, list]:
    """Every expression a plain name is bound to anywhere in the module: NAME = <expr>, and each
    element of a literal sequence a for-loop or comprehension iterates (`for n in ("A", "B")`).
    Coarse (no scopes), which errs towards finding more."""
    out: dict[str, list] = {}

    def bind(target, values):
        if isinstance(target, ast.Name):
            out.setdefault(target.id, []).extend(values)

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                bind(t, [node.value])
        elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)) and node.value is not None:
            bind(node.target, [node.value])
        elif isinstance(node, (ast.For, ast.comprehension)):
            if isinstance(node.iter, (ast.Tuple, ast.List, ast.Set)):
                bind(node.target, list(node.iter.elts))
    return out


def _names_of(node, binds, depth=0) -> list[str]:
    """The environment-variable names an expression can spell: a constant, a name bound to one, or the
    literal head of an f-string or a "+" concatenation (f"HUNTRESS_WEB_{x}" -> "HUNTRESS_WEB_")."""
    if depth > 4 or node is None:
        return []
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, ast.Name):
        return [n for v in binds.get(node.id, ()) for n in _names_of(v, binds, depth + 1)]
    if isinstance(node, ast.JoinedStr) and node.values and isinstance(node.values[0], ast.Constant):
        return [str(node.values[0].value)]
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _names_of(node.left, binds, depth + 1)
    return []


_GETTERS = {"get": "read", "pop": "write", "setdefault": "write", "__getitem__": "read",
            "__contains__": "read", "__setitem__": "write", "__delitem__": "write"}
_FUNCS = {"getenv": "read", "getenvb": "read", "putenv": "write", "unsetenv": "write",
          "setenv": "write", "delenv": "write"}
_CTF_ENV_FUNCS = {"get", "get_bool", "get_int", "require"}
_ENV_KWARGS = {"env", "environ", "extra_env", "environment"}


def _direct_env_args(node):
    """(argument expression, kind) pairs for one AST node that touches the environment directly."""
    if isinstance(node, ast.Call):
        f = node.func
        fname = f.attr if isinstance(f, ast.Attribute) else (f.id if isinstance(f, ast.Name) else "")
        if isinstance(f, ast.Attribute) and _is_environ(f.value) and fname in _GETTERS and node.args:
            yield node.args[0], _GETTERS[fname]
        elif fname in _FUNCS and node.args:
            yield node.args[0], _FUNCS[fname]
        elif (isinstance(f, ast.Attribute) and fname in _CTF_ENV_FUNCS and node.args
              and _dotted(f.value).split(".")[-1] in ("env", "ctf_env", "_env", "ctfenv")):
            yield node.args[0], "read"
        elif (fname == "update" and isinstance(f, ast.Attribute) and _is_environ(f.value)) or \
                (fname == "dict" and node.args and _is_environ(node.args[0])):
            for kw in node.keywords:
                if kw.arg:
                    yield ast.Constant(kw.arg), "write"
            for a in node.args:
                if isinstance(a, ast.Dict):
                    for k in a.keys:
                        if k is not None:
                            yield k, "write"
        for kw in node.keywords:                      # subprocess.run(..., env={"NAME": ...}), helper(env={...})
            if kw.arg in _ENV_KWARGS and isinstance(kw.value, ast.Dict):
                for k in kw.value.keys:
                    if k is not None:
                        yield k, "write"
    elif isinstance(node, ast.Subscript) and _is_environ(node.value):
        yield node.slice, ("write" if isinstance(node.ctx, (ast.Store, ast.Del)) else "read")
    elif isinstance(node, ast.Compare) and any(isinstance(o, (ast.In, ast.NotIn)) for o in node.ops):
        if any(_is_environ(c) for c in node.comparators):
            yield node.left, "read"
    elif isinstance(node, ast.Dict):
        # {**os.environ, "NAME": ...}: an environment handed to a child process
        if any(k is None and _is_environ(v) for k, v in zip(node.keys, node.values)):
            for k in node.keys:
                if k is not None:
                    yield k, "write"


def _walk_with_functions(tree):
    """Every node once, with the tuple of FunctionDefs enclosing it (iterative: no recursion limit)."""
    todo = [(tree, ())]
    while todo:
        node, stack = todo.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            stack = stack + (node,)
        yield node, stack
        todo.extend((child, stack) for child in ast.iter_child_nodes(node))


def _kwargs_key_names(fn) -> set[str]:
    """Names bound to the keys of fn's **kwargs (`for k, v in kwargs.items()`)."""
    if not fn.args.kwarg:
        return set()
    kwname, out = fn.args.kwarg.arg, set()
    for sub in ast.walk(fn):
        if isinstance(sub, (ast.For, ast.comprehension)):
            it = sub.iter
            if (isinstance(it, ast.Call) and isinstance(it.func, ast.Attribute) and it.func.attr in ("items", "keys")
                    and isinstance(it.func.value, ast.Name) and it.func.value.id == kwname):
                tgt = sub.target.elts[0] if isinstance(sub.target, ast.Tuple) else sub.target
                if isinstance(tgt, ast.Name):
                    out.add(tgt.id)
    return out


_ENV_CACHE: dict[int, tuple] = {}


def env_uses(tree) -> list[tuple[int, str, str]]:
    """(line, name, kind) for every environment access in a module, kind "read" or "write": direct
    (os.environ, os.getenv, ctf.env, monkeypatch.setenv/delenv, env={...} handed to a call) and one
    step indirect (a call to a function of this module that hands a parameter, or its **kwargs keys, to
    the environment). Cached per parsed tree (the env and workdir scans share it)."""
    hit = _ENV_CACHE.get(id(tree))
    if hit is not None and hit[0] is tree:
        return hit[1]
    binds = _bindings(tree)
    direct, calls = [], []
    helpers: dict[str, list] = {}                 # fn name -> [pos {index: kind}, kws {name: kind}, kwkind]
    kwkeys: dict[int, set] = {}
    for node, stack in _walk_with_functions(tree):
        if isinstance(node, ast.Call):
            calls.append(node)
        for arg, kind in _direct_env_args(node):
            direct.append((node, arg, kind))
            if not isinstance(arg, ast.Name):
                continue
            for fn in reversed(stack):
                params = [a.arg for a in fn.args.posonlyargs + fn.args.args]
                h = helpers.setdefault(fn.name, [{}, {}, None])
                if arg.id in params:
                    h[0][params.index(arg.id)] = kind
                    h[1][arg.id] = kind
                    break
                if id(fn) not in kwkeys:
                    kwkeys[id(fn)] = _kwargs_key_names(fn)
                if arg.id in kwkeys[id(fn)]:
                    h[2] = kind
                    break
    helpers = {k: v for k, v in helpers.items() if v[0] or v[2]}
    out = []

    def add(node, arg, kind):
        for name in _names_of(arg, binds):
            out.append((node.lineno, name, kind))

    for node, arg, kind in direct:
        add(node, arg, kind)
    for node in calls:
        f = node.func
        fname = f.attr if isinstance(f, ast.Attribute) else (f.id if isinstance(f, ast.Name) else "")
        if fname not in helpers:
            continue
        pos, kws, kwkind = helpers[fname]
        offset = 1 if isinstance(f, ast.Attribute) else 0      # a method: self takes position 0
        for i, a in enumerate(node.args):
            for j in {i, i + offset}:
                if j in pos:
                    add(node, a, pos[j])
        for kw in node.keywords:
            if kw.arg in kws:
                add(node, kw.value, kws[kw.arg])
            elif kw.arg and kwkind:
                out.append((node.lineno, kw.arg, kwkind))
    _ENV_CACHE[id(tree)] = (tree, out)
    return out


# --------------------------------------------------------------------------------- the detectors

def old_env_offences(rel: str, tree) -> list[str]:
    return [f"{rel}:{ln}: {kind} of legacy environment variable {name}"
            for ln, name, kind in env_uses(tree) if _OLD_NAME.match(name)]


_ROOTISH = {"ROOT", "REPO", "HERE", "BASE", "_REPO", "REPO_ROOT", "SOLVERS", "TOOLS", "_ROOT"}
_WORK_DIRS = {"challenges", "workspace"}


def _derives_from_checkout(node) -> bool:
    """True when an expression is built from this file's location (or a constant derived from it)."""
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and (sub.id == "__file__" or sub.id in _ROOTISH):
            return True
        if isinstance(sub, ast.Attribute) and sub.attr in ("parent", "parents"):
            return True
        if isinstance(sub, ast.Call) and _dotted(sub.func).split(".")[-1] in ("_repo_root", "repo_root", "getcwd", "cwd"):
            return True
    return False


def workdir_offences(rel: str, tree) -> list[str]:
    out = [f"{rel}:{ln}: reads ${name} (use ctf.paths.workdir())"
           for ln, name, kind in env_uses(tree) if kind == "read" and name in WORKDIR_NAMES]
    for node in ast.walk(tree):
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            r = node.right
            if isinstance(r, ast.Constant) and r.value in _WORK_DIRS and _derives_from_checkout(node.left):
                out.append(f"{rel}:{node.lineno}: builds <checkout>/{r.value} (use ctf.paths.workdir())")
        elif isinstance(node, ast.Call) and _dotted(node.func).endswith("path.join"):
            if (any(isinstance(a, ast.Constant) and a.value in _WORK_DIRS for a in node.args[1:])
                    and node.args and _derives_from_checkout(node.args[0])):
                out.append(f"{rel}:{node.lineno}: joins <checkout>/challenges (use ctf.paths.workdir())")
    return out


# A flag regex: a prefix element, an escaped open brace, a body class/dot with a quantifier, an escaped
# close brace. The prefix element is a literal word (CSCTF, flag), an alternation of words
# ((?:CSCTF|CTF), (?i:flag)), a letter class with a quantifier ([A-Za-z0-9_]{2,}, \w+), or a group of one.
_P_WORD = r"[A-Za-z][A-Za-z0-9_]+\??"
_P_ALT = r"\((?:\?i?:)?(?:\(\?:)?[A-Za-z0-9_|?]+\)\)?\??"
_P_CLASS = r"(?:\[[^\]]*(?:a-z|A-Z|\\w)[^\]]*\]|\\w)(?:\{\d*,?\d*\}|[+*])"
_P_GROUP = r"\((?:\?:)?(?:\[[^\]]*\](?:\{\d*,?\d*\}|[+*])?)+\)"
_BODY = r"(?:\((?:\?:)?)?(?:(?:\[[^\]]*\]|\.|\\[sSwWd])(?:\{\d*,?\d*\}|[+*])?\??)+\)?(?:\\\}|\})"
FLAG_LITERAL = re.compile(r"(?:%s|%s|%s|%s)\\\{%s" % (_P_ALT, _P_GROUP, _P_CLASS, _P_WORD, _BODY))
PROOF_LITERAL = re.compile(r"proof_(?:\[[^\]]+\]|\\w|\.)")


def _string_value(node) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
        v = node.value
        return v.decode("latin-1") if isinstance(v, bytes) else v
    if isinstance(node, ast.JoinedStr):
        return "".join(str(v.value) if isinstance(v, ast.Constant) else "X" for v in node.values)
    return None


def _docstring_ids(tree) -> set[int]:
    ids = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Expr) and isinstance(node.value, (ast.Constant, ast.JoinedStr)):
            ids.add(id(node.value))
            if isinstance(node.value, ast.JoinedStr):
                ids.update(id(v) for v in node.value.values)
    return ids


_STATED_KEYS = {"pattern", "regex"}


def _stated_format_ids(tree) -> set[int]:
    """In a test, a challenge question's stated answer format is fixture data: a string passed as a
    `pattern=`/`regex=` keyword (q("...", pattern=r"flag\\{...\\}")) or held under a "pattern"/"regex"
    key of a dict literal ({"kind": "exact_text", "pattern": ...}). Engines read such a format out of
    the challenge; it is not the code's own flag regex."""
    ids = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            ids.update(id(kw.value) for kw in node.keywords if kw.arg in _STATED_KEYS)
        elif isinstance(node, ast.Dict):
            ids.update(id(v) for k, v in zip(node.keys, node.values)
                       if isinstance(k, ast.Constant) and k.value in _STATED_KEYS)
    return ids


def flag_offences(rel: str, tree) -> list[str]:
    skip = _docstring_ids(tree)
    if rel.startswith("tests/"):
        skip |= _stated_format_ids(tree)
    out = []
    inner = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr):
            inner.update(id(v) for v in node.values)
    for node in ast.walk(tree):
        if id(node) in skip or id(node) in inner:
            continue
        s = _string_value(node)
        if not s or ("\\{" not in s and "proof_" not in s):     # cheap prefilter
            continue
        if any(rel == f and s.startswith(head) for f, head in FLAG_DATA_LITERALS):
            continue
        if FLAG_LITERAL.search(s) or PROOF_LITERAL.search(s):
            out.append(f"{rel}:{node.lineno}: flag/proof regex literal {s[:80]!r} (use ctf.flagfmt)")
    return out


_SH_OLD = re.compile(r"\$\{?(?:%s)[A-Z0-9_]+|\b(?:export\s+)?(?:%s)[A-Z0-9_]+=" % ("|".join(OLD_PREFIXES),
                                                                                  "|".join(OLD_PREFIXES)))
_SH_WORKDIR_DEFAULT = re.compile(r"\$\{CTF_WORKDIR:?[-=]")


def shell_offences(rel: str, text: str) -> list[str]:
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        code = line.split("#", 1)[0] if not line.lstrip().startswith("#!") else ""
        if _SH_OLD.search(code):
            out.append(f"{rel}:{i}: legacy environment variable in shell code")
        if _SH_WORKDIR_DEFAULT.search(code):
            out.append(f"{rel}:{i}: shell default for $CTF_WORKDIR (use `python -m ctf workdir`)")
    return out


# ------------------------------------------------------------------------- detectors find offenders

def _src(*lines):
    return "\n".join(lines) + "\n"


H = OLD_PREFIXES[0]
C = OLD_PREFIXES[1]
BR_O, BR_C = "\\" + "{", "\\" + "}"


@pytest.mark.parametrize("code", [
    f'import os\nx = os.environ.get("{H}TESTING")',
    f'import os\nx = os.getenv("{C}TOKEN", "")',
    f'import os\nx = os.environ["{H}GM_URL"]',
    f'import os\nx = "{C}KINDS" in os.environ',
    f'import os\nNAME = "{H}HIDE"\nx = os.environ.get(NAME)',
    f'import os\nx = os.environ.get(f"{H}WEB_{{name}}")',
    f'import os\nos.environ["{H}TESTING"] = "1"',
    f'import os\nos.environ.setdefault("{C}TESTING", "1")',
    f'import os, subprocess\nsubprocess.run(["x"], env={{**os.environ, "{H}HIDE": "census"}})',
    f'def t(monkeypatch):\n    monkeypatch.setenv("{H}GM_URL", "x")',
    f'def t(monkeypatch):\n    monkeypatch.delenv("{C}TOKEN", raising=False)',
    # one step indirect: a helper of the module hands its parameter to the environment
    f'import os\ndef _limit(name, d):\n    return os.environ.get(name) or d\nX = _limit("{C}SANDBOX_CPUS", "2")',
    f'import os\nclass K:\n    def on(self, var):\n        return os.environ.get(var)\nK().on("{H}WEB_CSRF")',
    f'def _load(mp, **kw):\n    for k, v in kw.items():\n        mp.setenv(k, v)\n_load(None, {C}SANDBOX_MEMORY="8g")',
    f'def t(monkeypatch):\n    for name in ("{H}GM_URL", "CTF_X"):\n        monkeypatch.delenv(name, raising=False)',
    f'import os\nok = any(os.environ.get(n) == "off" for n in ("{H}BINARY_FORMS", "CTF_KINDS"))',
    f'def t(run):\n    run(site, env={{"{H}WEB_CLASS_GRAPHQL": "off"}})',
    f'import os\ndef f(name):\n    env = "{C}WEB_" + name.upper()\n    return os.environ.get(env)',
])
def test_env_detector_finds_legacy_names(code):
    assert old_env_offences("x.py", ast.parse(code))


@pytest.mark.parametrize("code", [
    'import os\nx = os.environ.get("CTF_TESTING")',
    f'MARK = "{C}SSTI_Z"\npayload = MARK + "x"',             # a payload marker, not an environment name
    f'print("set {H}X instead")',
])
def test_env_detector_ignores_canonical_names_and_markers(code):
    assert old_env_offences("x.py", ast.parse(code)) == []


@pytest.mark.parametrize("code", [
    'import os\nw = os.environ.get("CTF_WORKDIR")',
    'import os\nw = os.getenv("CTF_WORKDIR", "/tmp/x")',
    f'import os\nw = os.environ.get("{H}CHALLENGES")',
    'from ctf import env\nw = env.get("CTF_WORKDIR")',
    'from pathlib import Path\nHERE = Path(__file__).resolve().parent\nw = HERE.parents[1] / "challenges"',
    'from pathlib import Path\nw = Path(__file__).resolve().parent.parent / "workspace"',
    'import os\nREPO = "."\nw = os.path.join(REPO, "challenges")',
])
def test_workdir_detector_finds_resolvers(code):
    assert workdir_offences("x.py", ast.parse(code))


@pytest.mark.parametrize("code", [
    'import os\nos.environ["CTF_WORKDIR"] = "/tmp/w"',            # setting it (a test) is not resolving it
    'def t(monkeypatch, tmp_path):\n    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))',
    'def t(tmp_path):\n    d = tmp_path / "challenges"',
    'from ctf import paths\nw = paths.workdir() / "challenges"',
    'rec = {}\nrec["challenges"] = []',
])
def test_workdir_detector_ignores_non_resolvers(code):
    assert workdir_offences("x.py", ast.parse(code)) == []


_FLAG_SAMPLES = [
    "CSCTF" + BR_O + "[^}\\n]{1,256}" + BR_C,
    "(?:CSCTF|csctf|chronos|CTF|flag)" + BR_O + "[^}\\n]{1,256}" + BR_C,
    "(?i:(?:csctf|flag))" + BR_O + "[^{}]{1,256}" + BR_C,
    "(CS)?CTF" + BR_O + "[^}]{1,120}" + BR_C,
    "\\bC?S?CTF" + BR_O + "[^}]{0,200}" + BR_C,
    "[A-Za-z0-9_]{2,}" + BR_O + "[^}]{1,80}" + BR_C,
    "\\w{2,12}" + BR_O + "(.+)" + BR_C,
    "(?<![A-Za-z0-9_])([A-Za-z][A-Za-z0-9_]{1,15})" + BR_O + "([^{}\\s][^{}\\n]{0,198})" + BR_C,
    "^flag" + BR_O + "[0-9a-f]{32}" + BR_C + "$",
    "PINK" + BR_O + "[^}\\n]{1,256}" + BR_C,
    "(?<![A-Za-z0-9_])proof_" + "[0-9a-f]{32}",
]


@pytest.mark.parametrize("pattern", _FLAG_SAMPLES)
@pytest.mark.parametrize("form", ["r'{}'", "rb'{}'", "re.compile(r'{}')"])
def test_flag_detector_finds_regex_literals(pattern, form):
    code = "import re\nX = " + form.format(pattern.replace("'", "\\'"))
    assert flag_offences("x.py", ast.parse(code)), code


def test_flag_detector_finds_fstring_patterns():
    code ='import re\nP = "CSCTF"\nX = re.compile(rf"(?:{P})\\{{[^}}\\n]{{1,256}}\\}}")'
    assert flag_offences("x.py", ast.parse(code))


@pytest.mark.parametrize("pattern", [
    "\\$" + BR_O + "[^}]+" + BR_C,                            # shell variable
    BR_O + BR_O + ".*?" + BR_C + BR_C,                        # template expression
    "[ \\t]*" + BR_O + "([^{}$]+)" + BR_C,                     # Tcl word
    "^(.*/)" + BR_O + "(.*)" + BR_C + "$",                     # brace expansion
    "new(?:string)?\\[\\]" + BR_O + "<L>" + BR_C,              # C# array literal
    "invoke-static\\s+" + BR_O + "([^}]*)" + BR_C,             # smali
])
def test_flag_detector_ignores_other_brace_regexes(pattern):
    code = "import re\nX = re.compile(r'" + pattern + "')"
    assert flag_offences("x.py", ast.parse(code)) == []


def test_flag_detector_ignores_docstrings():
    code = 'def f():\n    r"""Matches CSCTF' + BR_O + '[^}]+' + BR_C + ' and proof' + '_[0-9a-f]{32}."""\n    return 1\n'
    assert flag_offences("x.py", ast.parse(code)) == []


def test_stated_answer_format_is_data_only_in_tests():
    """q(..., pattern=r"flag{...}") in a test is a challenge's stated format (fixture data); the same
    literal in engine code is the code's own flag regex and is refused."""
    lit = "flag" + BR_O + "[a-z_]+" + BR_C
    for code in (f"x = q('Decrypt it.', pattern=r'{lit}')",
                 f"FMT = {{'kind': 'exact_text', 'pattern': r'{lit}'}}"):
        tree = ast.parse(code)
        assert flag_offences("tests/test_x.py", tree) == []
        assert flag_offences("solvers/toolkits/x.py", tree)
    assert flag_offences("tests/test_x.py", ast.parse(f"FLAG_RE = r'{lit}'"))


def test_shell_detector():
    assert shell_offences("x.sh", f'echo "${H}GM_URL"\n')
    assert shell_offences("x.sh", f'export {C}TOKEN=abc\n')
    assert shell_offences("x.sh", 'w="${CTF_WORKDIR:-/tmp/ctfws}"\n')
    assert shell_offences("x.sh", 'w="$CTF_WORKDIR"\n# the old $' + H + 'X is gone\n') == []


# ------------------------------------------------------------------------------- the tree is clean

# The tree scans parse every Python file once (module-scoped fixture, about 20 s in all): tagged slow.
@pytest.fixture(scope="module")
def tree():
    files = tree_files()
    assert len(files) > 500, f"git listed only {len(files)} files under {REPO}"
    parsed = {}
    for rel in python_files(files):
        t = _parse(rel)
        if t is not None:
            parsed[rel] = t
    return files, parsed


@pytest.mark.slow
def test_every_python_file_parses(tree):
    files, parsed = tree
    bad = [f for f in python_files(files) if f not in parsed and not f.startswith("tests/fixtures/")]
    assert not bad, f"unparseable Python files escape the scan: {bad}"


@pytest.mark.slow
def test_no_legacy_env_names_outside_ctf_env(tree):
    _, parsed = tree
    found = [o for rel, t in parsed.items() if rel not in ENV_EXEMPT for o in old_env_offences(rel, t)]
    assert not found, "legacy HUNTRESS_/CSCTF_ environment names (use ctf.env with the CTF_ name):\n" + "\n".join(found)


@pytest.mark.slow
def test_no_workdir_resolution_outside_ctf_paths(tree):
    _, parsed = tree
    found = [o for rel, t in parsed.items() if rel not in WORKDIR_EXEMPT for o in workdir_offences(rel, t)]
    assert not found, "workdir resolved outside ctf/paths.py:\n" + "\n".join(found)


@pytest.mark.slow
def test_no_flag_regex_outside_flagfmt(tree):
    _, parsed = tree
    found = [o for rel, t in parsed.items() if rel not in FLAG_EXEMPT for o in flag_offences(rel, t)]
    assert not found, "flag/proof regex literals outside ctf/flagfmt.py:\n" + "\n".join(found)


@pytest.mark.slow
def test_shell_scripts_use_canonical_env_and_no_workdir_default(tree):
    files, _ = tree
    found = []
    for rel in shell_files(files):
        found += shell_offences(rel, (REPO / rel).read_text(encoding="utf-8", errors="replace"))
    assert not found, "\n".join(found)
