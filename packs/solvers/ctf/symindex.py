"""Symbol index (B-199): every module's classes, functions and constants with their line ranges.

Agents re-read huge single files (proof_hunt.py and codec_search.py are 7,000 lines) in 150-line slices
to find one function. This index answers "what is in this file, where is NAME, and who imports it"
without reading the file, so the next read is `ctf read PATH --symbol NAME`: just that definition.

Built on the regression gate's static graph (ctf.gate.impact): the same `ast` parse (never import or
run), the same import resolution and the same content-hash cache (ctf.gate.inventory). The per-file
symbol table is an Inventory keyed by repo-relative path and recomputed only when the file's content
hash changes, so a second `ctf symbols` call re-parses nothing.

    from ctf import symindex
    syms = symindex.parse_symbols(text)            # {"symbols": [[kind, name, start, end, sig, doc]], "error"}
    symindex.symbols_of(text)                      # [Symbol] (parse errors raise SymbolError)
    symindex.lookup(symbols, "Cls.method")         # [Symbol]: exact qualified name, else last-part matches
    idx = symindex.SymbolIndex(root, state_dir)    # the whole tree, cached under state_dir
    idx.resolve("ctf.cli.read") / idx.resolve("ctf/cli/read.py")   # -> "ctf/cli/read.py"
    idx.symbols(rel); idx.imports(rel); idx.importers(rel); idx.find("NAME")
    idx.outline(rel) -> str                        # what `ctf symbols PATH` prints

A symbol is a top-level `def`/`async def`/`class`, a method or nested class of a class (any depth of
classes, never the inside of a function), or a module-level UPPER_CASE constant. Its range starts at
its first decorator and ends at its last line, so `ctf read --symbol` shows all of it.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

from .gate import GateError
from .gate import config as _gate_config
from .gate import impact as _impact
from .gate.inventory import Inventory

__all__ = ["SYM_VERSION", "SYMBOLS_FILE", "SymbolError", "Symbol", "parse_symbols", "symbols_of",
           "lookup", "SymbolIndex", "format_symbol"]

SYM_VERSION = "symbols-1"
SYMBOLS_FILE = "symbols.json"     # beside the gate's deps.json / hashes.json in the state folder
SIG_CHARS = 120                   # a signature longer than this is shortened (with an ellipsis)
DOC_CHARS = 100                   # the first docstring line, at most this long


class SymbolError(RuntimeError):
    """A target that is not an indexed Python file, an ambiguous module name, or source that does not
    parse. The message names which."""


@dataclass(frozen=True)
class Symbol:
    kind: str          # "def" | "async def" | "class" | "const"
    name: str          # qualified within the module: "func", "Cls", "Cls.method", "Cls.Inner.m"
    start: int         # first line (1-based), its first decorator included
    end: int           # last line, inclusive
    signature: str     # "(a, b=1) -> int" for a def, "(Base, Mixin)" for a class, "" for a const
    doc: str           # the first line of the docstring ("" when none)

    @property
    def lines(self) -> int:
        return self.end - self.start + 1

    @property
    def short(self) -> str:
        return self.name.rsplit(".", 1)[-1]


def _clip(s: str, n: int) -> str:
    s = " ".join(s.split())
    return s if len(s) <= n else s[: n - 1].rstrip() + "…"


def _doc(node) -> str:
    d = ast.get_docstring(node, clean=True) or ""
    return _clip(d.strip().split("\n", 1)[0], DOC_CHARS) if d.strip() else ""


def _start(node) -> int:
    return min([node.lineno] + [d.lineno for d in getattr(node, "decorator_list", [])])


def _sig(node) -> str:
    try:
        if isinstance(node, ast.ClassDef):
            bases = [ast.unparse(b) for b in node.bases] + [ast.unparse(k) for k in node.keywords]
            return _clip(f"({', '.join(bases)})", SIG_CHARS) if bases else ""
        s = f"({ast.unparse(node.args)})"
        if node.returns is not None:
            s += f" -> {ast.unparse(node.returns)}"
        return _clip(s, SIG_CHARS)
    except (ValueError, TypeError, AttributeError, RecursionError):   # pragma: no cover - odd ast
        return ""


def _const_names(node) -> list[str]:
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    out = []
    for t in targets:
        for n in ([t] if isinstance(t, ast.Name) else (t.elts if isinstance(t, ast.Tuple) else [])):
            if isinstance(n, ast.Name) and n.id.isupper() and not n.id.startswith("__"):
                out.append(n.id)
    return out


def _walk(body, prefix: str, out: list, top: bool) -> None:
    for node in body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            kind = ("class" if isinstance(node, ast.ClassDef) else
                    "async def" if isinstance(node, ast.AsyncFunctionDef) else "def")
            name = prefix + node.name
            out.append([kind, name, _start(node), node.end_lineno or node.lineno, _sig(node), _doc(node)])
            if isinstance(node, ast.ClassDef):
                _walk(node.body, name + ".", out, top=False)
        elif top and isinstance(node, (ast.Assign, ast.AnnAssign)):
            for nm in _const_names(node):
                out.append(["const", nm, node.lineno, node.end_lineno or node.lineno, "", ""])


def parse_symbols(text: str) -> dict:
    """The symbol table of one Python source, as plain JSON-able data (what the inventory stores):
    {"symbols": [[kind, name, start, end, signature, doc], ...], "error": ""}, in source order. Source that
    does not parse gives no symbols and the error named."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError) as e:
        return {"symbols": [], "error": f"{type(e).__name__}: {e}"}
    out: list = []
    _walk(tree.body, "", out, top=True)
    return {"symbols": out, "error": ""}


def _to_symbols(rows) -> list[Symbol]:
    return [Symbol(*r) for r in rows]


def symbols_of(text: str) -> list[Symbol]:
    """[Symbol] of one source. SymbolError when it does not parse (never an empty 'no symbols')."""
    got = parse_symbols(text)
    if got["error"]:
        raise SymbolError(f"not parseable Python: {got['error']}")
    return _to_symbols(got["symbols"])


def lookup(symbols: list[Symbol], name: str) -> list[Symbol]:
    """The symbols NAME means: an exact qualified-name match (`Cls.method`), else every symbol whose
    last part is NAME (`method` finds each class's `method`). Empty when none."""
    exact = [s for s in symbols if s.name == name]
    if exact:
        return exact
    tail = name.rsplit(".", 1)[-1]
    if "." in name:     # a dotted name that matched nothing exactly: suffix match on the qualified name
        return [s for s in symbols if s.name.endswith("." + name)]
    return [s for s in symbols if s.short == tail]


def format_symbol(s: Symbol, *, indent: bool = True) -> str:
    """One outline line: `L120-188  def name(sig)  # doc`, nested names indented by depth."""
    pad = "  " * s.name.count(".") if indent else ""
    label = s.short if indent else s.name
    kw = "" if s.kind == "const" else s.kind + " "
    doc = f"  # {s.doc}" if s.doc else ""
    return f"{pad}L{s.start}-{s.end}  {kw}{label}{s.signature}{doc}"


class SymbolIndex:
    """Every Python file of a checkout with its symbol table, its resolved imports and its importers.

    `state_dir` holds the caches (the gate's hashes.json and deps.json, and symbols.json); pass the
    gate's state folder (ctf.paths.gate_state) to share them with the gate. `files` is the checkout's
    file list (repo-relative); None lists it with git (ctf.gate.impact.list_files). `cfg` is the gate
    config (import roots); None loads <root>/tests/gate.toml (GateError, named, when it is missing)."""

    def __init__(self, root: Path, state_dir: Path, *, cfg: _gate_config.GateConfig | None = None,
                 files: list[str] | None = None):
        self.root = Path(root).resolve()
        cfg = _gate_config.load(self.root) if cfg is None else cfg
        self.graph = _impact.Graph(self.root, cfg, Path(state_dir), files=files)
        self.cfg = cfg
        py = {f: self.graph.sha(f) for f in self.graph.files if f.endswith(".py")}
        py = {f: h for f, h in py.items() if h is not None}
        self.inventory = Inventory(Path(state_dir) / SYMBOLS_FILE, SYM_VERSION)
        self.inventory.refresh(py, self._parse)
        self.inventory.save()
        self.py_files = sorted(py)

    @property
    def stats(self):
        return self.inventory.stats

    def _parse(self, rel: str) -> dict:
        try:
            text = (self.root / rel).read_text(encoding="utf-8", errors="surrogateescape")
        except OSError as e:
            return {"symbols": [], "error": f"unreadable: {e}"}
        return parse_symbols(text)

    # ------------------------------------------------------------------ targets

    def resolve(self, target: str, *, cwd: Path | None = None) -> str:
        """The repo-relative .py file `target` names: a path (absolute, relative to `cwd`, or relative to
        the root) or a dotted module (`ctf.cli.read`, resolved against the gate's import roots).
        SymbolError when it names no indexed file, or (a module) more than one."""
        cand = Path(target).expanduser()
        for p in ([cand] if cand.is_absolute() else [Path(cwd or Path.cwd()) / cand, self.root / cand]):
            try:
                rel = p.resolve().relative_to(self.root).as_posix()
            except ValueError:
                continue
            if rel in self.inventory:
                return rel
            if p.is_file():
                raise SymbolError(f"{target}: not a Python file this index covers (only tracked or "
                                  f"untracked-not-ignored .py files of {self.root.name})")
        if "/" in target or target.endswith(".py"):
            raise SymbolError(f"{target}: no such Python file in the index")
        roots = list(dict.fromkeys(["", *self.cfg.roots]))
        hits = []
        for r in roots:
            files = self.graph._module_files(target, [r])
            stem = ((r + "/") if r else "") + target.replace(".", "/")
            hits += [f for f in files if f in (stem + ".py", stem + "/__init__.py")]
        hits = list(dict.fromkeys(hits))
        if not hits:
            raise SymbolError(f"{target}: no module of that name under the import roots "
                              f"({', '.join(repr(r) for r in roots)})")
        if len(hits) > 1:
            raise SymbolError(f"{target}: ambiguous, it names {', '.join(hits)}; pass the path")
        return hits[0]

    def symbols(self, rel: str) -> list[Symbol]:
        if rel not in self.inventory:
            raise SymbolError(f"{rel}: not an indexed Python file")
        return _to_symbols(self.inventory.get(rel)["symbols"])

    def error(self, rel: str) -> str:
        return self.inventory.get(rel)["error"] if rel in self.inventory else ""

    # ------------------------------------------------------------------ the graph

    def imports(self, rel: str) -> list[str]:
        """Repo files `rel` imports or names (the gate graph's direct deps), package __init__ files left out."""
        return sorted(d for d in self.graph.node(rel).deps if not d.endswith("__init__.py"))

    def importers(self, rel: str) -> list[str]:
        """Repo .py files whose direct deps include `rel`."""
        return sorted(f for f in self.py_files if f != rel and rel in self.graph.node(f).deps)

    def find(self, name: str) -> list[tuple[str, Symbol]]:
        """Every (file, symbol) NAME means across the tree (see lookup), files in path order."""
        out = []
        for rel in self.py_files:
            out += [(rel, s) for s in lookup(self.symbols(rel), name)]
        return out

    def outline(self, rel: str, *, users: bool = True, max_list: int = 12) -> str:
        """What `ctf symbols PATH` prints: the file, its imports and importers (each list capped at
        `max_list`, with the count of the rest named), then every symbol with its line range."""
        syms = self.symbols(rel)
        try:
            n_lines = len((self.root / rel).read_text(encoding="utf-8", errors="replace").splitlines())
        except OSError:
            n_lines = 0
        out = [f"{rel}: {n_lines} lines, {len(syms)} symbols"]
        err = self.error(rel)
        if err:
            out.append(f"  parse error: {err}")

        def listing(label: str, items: list[str]) -> None:
            more = f" (+{len(items) - max_list} more)" if len(items) > max_list else ""
            out.append(f"{label} ({len(items)}): {', '.join(items[:max_list]) or '-'}{more}")

        listing("imports", self.imports(rel))
        if users:
            listing("imported by", self.importers(rel))
        out += [format_symbol(s) for s in syms]
        out.append(f"[ctf: read one with `python -m ctf read {rel} --symbol NAME`]")
        return "\n".join(out)
